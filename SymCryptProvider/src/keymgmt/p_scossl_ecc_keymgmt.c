//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_base.h"
#include "p_scossl_ecc_keymgmt.h"

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_ECC_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

typedef struct
{
    OSSL_LIB_CTX *libctx;
    PCSYMCRYPT_ECURVE curve;
} SCOSSL_ECC_KEYGEN_CTX;

// ScOSSL only supports named curves
static const OSSL_PARAM p_scossl_ecc_keygen_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecc_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_END};

// Key Context Management
//
// Key import uses keymgmt_new to allocate an empty key object
// first, then passes that reference to keymgmt_import. Since
// the size of the SYMCRYPT_ECKEY depends on parameters that aren't
// known until import, no key is actually allocated here.

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_ECC_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_ECC_KEY_CTX));
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->libctx = provctx->libctx;
    keyCtx->includePublic = 1;

    return keyCtx;
}

static void p_scossl_ecc_keymgmt_free_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

    OPENSSL_free(keyCtx);
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_dup_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbData = NULL;
    PBYTE pbPrivateKey = NULL;
    PBYTE pbPublicKey = NULL;
    SIZE_T cbData = 0;
    SIZE_T cbPublicKey = 0;
    SIZE_T cbPrivateKey = 0;
    SCOSSL_STATUS success = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SCOSSL_ECC_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEY_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->libctx = keyCtx->libctx;

        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        {
            copyCtx->curve = keyCtx->curve;
        }
        else
        {
            copyCtx->curve = NULL;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && keyCtx->initialized)
        {
            if (copyCtx->curve == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
                goto cleanup;
            }

            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
                SymCryptEckeyHasPrivateKey(keyCtx->key))
            {
                cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);
            }

            if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            {
                cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
            }

            cbData = cbPrivateKey + cbPublicKey;
            if ((pbData = OPENSSL_secure_malloc(cbData)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            pbPrivateKey = cbPrivateKey != 0 ? pbData : NULL;
            pbPublicKey = cbPublicKey != 0 ? pbData + cbPrivateKey : NULL;

            scError = SymCryptEckeyGetValue(
                keyCtx->key,
                pbPrivateKey, cbPrivateKey,
                pbPublicKey, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                0);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            if ((copyCtx->key = SymCryptEckeyAllocate(keyCtx->curve)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            // Default ECDH only. If the key is used for ECDSA then we call SymCryptEckeyExtendKeyUsage
            scError = SymCryptEckeySetValue(
                pbPrivateKey, cbPrivateKey,
                pbPublicKey, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                copyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            copyCtx->initialized = 1;
            copyCtx->includePublic = keyCtx->includePublic;
        }
        else
        {
            copyCtx->key = NULL;
            copyCtx->initialized = 0;
            copyCtx->includePublic = 1;
        }
    }

    success = SCOSSL_SUCCESS;

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_secure_clear_free(pbData, cbData);
    }

    if (!success)
    {
        p_scossl_ecc_keymgmt_free_ctx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_ecc_keygen_set_params(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        EC_GROUP *ecGroup = EC_GROUP_new_from_params(params, genCtx->libctx, NULL);
        genCtx->curve = scossl_ecc_group_to_symcrypt_curve(ecGroup);
        EC_GROUP_free(ecGroup);

        if (genCtx->curve == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_ecc_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provctx)
{
    return p_scossl_ecc_keygen_settable_param_types;
}

static void p_scossl_ecc_keygen_cleanup(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx)
{
    OPENSSL_free(genCtx);
}

static SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                       _In_ const OSSL_PARAM params[])
{
    SCOSSL_ECC_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEYGEN_CTX));
    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genCtx->libctx = provctx->libctx;

    if (!p_scossl_ecc_keygen_set_params(genCtx, params))
    {
        p_scossl_ecc_keygen_cleanup(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keygen(_In_ SCOSSL_ECC_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SCOSSL_ECC_KEY_CTX *keyCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEY_CTX));
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->libctx = genCtx->libctx;
    keyCtx->curve = genCtx->curve;

    keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve);
    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // Default ECDH only. If the key is used for ECDSA then we call SymCryptEckeyExtendKeyUsage
    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    keyCtx->initialized = TRUE;

cleanup:
    if (!keyCtx->initialized)
    {
        p_scossl_ecc_keymgmt_free_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_get_params(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_uint32(p, scossl_ecdsa_size(keyCtx->curve)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptEcurveBitsizeofGroupOrder(keyCtx->curve)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptEcurveBitsizeofGroupOrder(keyCtx->curve) / 2))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        SYMCRYPT_ERROR scError = SymCryptEckeyGetValue(
            keyCtx->key,
            NULL, 0,
            p->data, p->return_size,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    // SCOSSL only allows named curves, so these is never true
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS)) != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }


    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH)) != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_ecc_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_ecc_keymgmt_gettable_param_types;
}

static BOOL p_scossl_ecc_keymgmt_has(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    BOOL hasSelection = TRUE;

    if ((selection & SCOSSL_ECC_POSSIBLE_SELECTIONS) == 0)
    {
        return TRUE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        hasSelection = hasSelection && keyCtx->initialized;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        hasSelection = hasSelection && SymCryptEckeyHasPrivateKey(keyCtx->key);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        hasSelection = hasSelection &&
                       (keyCtx->key != NULL && keyCtx->curve != NULL);
    }
    // OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS always considered available

    return TRUE;
}

static BOOL p_scossl_ecc_keymgmt_match(_In_ SCOSSL_ECC_KEY_CTX *keyCtx1, _In_ SCOSSL_ECC_KEY_CTX *keyCtx2,
                                       int selection)
{
    BOOL ret = FALSE;
    PBYTE pbPrivateKey1 = NULL;
    PBYTE pbPrivateKey2 = NULL;
    PBYTE pbPublicKey1 = NULL;
    PBYTE pbPublicKey2 = NULL;
    SIZE_T cbPrivateKey = 0;
    SIZE_T cbPublicKey = 0;

    if (!keyCtx1->initialized || !keyCtx2->initialized)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        !SymCryptEcurveIsSame(keyCtx1->curve, keyCtx2->curve))
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx1->key);
        if (cbPrivateKey != SymCryptEckeySizeofPrivateKey(keyCtx2->key))
        {
            goto cleanup;
        }


        if ((pbPrivateKey1 = OPENSSL_secure_malloc(cbPrivateKey)) == NULL ||
            (pbPrivateKey2 = OPENSSL_secure_malloc(cbPrivateKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx1->key, SYMCRYPT_ECPOINT_FORMAT_XY);
        if (cbPublicKey != SymCryptEckeySizeofPublicKey(keyCtx2->key, SYMCRYPT_ECPOINT_FORMAT_XY))
        {
            goto cleanup;
        }

        if ((pbPublicKey1 = OPENSSL_malloc(cbPublicKey)) == NULL ||
            (pbPublicKey2 = OPENSSL_malloc(cbPublicKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if ((cbPrivateKey | cbPublicKey) == 0)
    {
        ret = TRUE;
        goto cleanup;
    }

    if (SymCryptEckeyGetValue(
            keyCtx1->key,
            pbPrivateKey1, cbPrivateKey,
            pbPublicKey1, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0) != SYMCRYPT_NO_ERROR ||
        SymCryptEckeyGetValue(
            keyCtx2->key,
            pbPrivateKey2, cbPrivateKey,
            pbPublicKey2, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0) != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    ret = (memcmp(pbPrivateKey1, pbPrivateKey2, cbPrivateKey) == 0) &&
          (memcmp(pbPublicKey1, pbPublicKey2, cbPublicKey) == 0);

cleanup:
    OPENSSL_free(pbPublicKey1);
    OPENSSL_free(pbPublicKey2);
    OPENSSL_secure_clear_free(pbPrivateKey1, cbPrivateKey);
    OPENSSL_secure_clear_free(pbPrivateKey2, cbPrivateKey);

    return ret;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_ecc_keymgmt_impexp_types(int selection)
{
    int idx = 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        idx += 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        idx += 2;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        idx += 4;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        idx += 8;
    }
    return p_scossl_ecc_keymgmt_impexp_param_types[idx];
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    EC_GROUP *ecGroup = NULL;
    BIGNUM *bnPrivateKey = NULL;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    BN_CTX *bnCtx = NULL;
    EC_POINT *ecPoint = NULL;
    const OSSL_PARAM *p;

    // Domain parameters (curve) are required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        goto cleanup;
    }

    ecGroup = EC_GROUP_new_from_params(params, keyCtx->libctx, NULL);
    keyCtx->curve = scossl_ecc_group_to_symcrypt_curve(ecGroup);
    if (keyCtx->curve == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto cleanup;
    }

    // Other parameters
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC)) != NULL &&
            !OSSL_PARAM_get_int(p, &keyCtx->includePublic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    // Keypair
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve))== NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL)
        {
            PCBYTE encodedPoint;
            SIZE_T encodedLen;
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&encodedPoint, &encodedLen))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            if (((ecPoint = EC_POINT_new(ecGroup))    == NULL) ||
                ((bnCtx = BN_CTX_new_ex(keyCtx->libctx))      == NULL) ||
                ((pbPublicKey = OPENSSL_malloc(cbPublicKey))  == NULL))
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (!EC_POINT_oct2point(ecGroup, ecPoint, encodedPoint, encodedLen, bnCtx) ||
                !scossl_ec_point_to_pubkey(ecPoint, ecGroup, bnCtx, pbPublicKey, cbPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if ((bnPrivateKey = BN_secure_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
            BN_set_flags(bnPrivateKey, BN_FLG_CONSTTIME);

            if (!OSSL_PARAM_get_BN(p, &bnPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);
            if ((pbPrivateKey = OPENSSL_secure_malloc(cbPrivateKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if ((SIZE_T)BN_bn2binpad(bnPrivateKey, pbPrivateKey, cbPrivateKey) != cbPrivateKey)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        scError = SymCryptEckeySetValue(
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            SYMCRYPT_FLAG_ECKEY_ECDH,
            keyCtx->key);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        keyCtx->initialized = TRUE;
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    if (pbPrivateKey != NULL)
    {
        OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    }
    EC_GROUP_free(ecGroup);
    BN_clear_free(bnPrivateKey);
    OPENSSL_free(pbPublicKey);
    EC_POINT_free(ecPoint);
    BN_CTX_free(bnCtx);

    return ret;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                                 _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *bnPrivateKey = NULL;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    OSSL_PARAM *params = NULL;
    const char *curveName;


    // Domain parameters (curve) are required for export
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        goto cleanup;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // Curve is assumed to be a valid named curve if it was loaded by SCOSSL
    if ((curveName = scossl_ecc_get_curve_name(keyCtx->curve)) == NULL ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curveName, strlen(curveName)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);
            if ((pbPrivateKey = OPENSSL_secure_malloc(cbPrivateKey)) == NULL ||
                (bnPrivateKey = BN_secure_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
            BN_set_flags(bnPrivateKey, BN_FLG_CONSTTIME);
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
            if ((pbPublicKey = OPENSSL_malloc(cbPublicKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
        }

        scError = SymCryptEckeyGetValue(
            keyCtx->key,
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            if (BN_bin2bn(pbPrivateKey, cbPrivateKey, bnPrivateKey) == NULL ||
                !OSSL_PARAM_BLD_push_BN_pad(bld, OSSL_PKEY_PARAM_PRIV_KEY, bnPrivateKey, cbPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
            !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbPublicKey, cbPublicKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        if (!OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, keyCtx->includePublic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (!OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    ret = param_cb(params, cbarg);

cleanup:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    OPENSSL_free(pbPublicKey);

    return ret;
}

static const char *p_scossl_ecc_keymgmt_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return NULL;
}

const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_ecc_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_ecc_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_ecc_keymgmt_free_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_ecc_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_ecc_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_ecc_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_ecc_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_ecc_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_ecc_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_ecc_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_ecc_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))p_scossl_ecc_keymgmt_query_operation_name},
    {0, NULL}};

#ifdef __cplusplus
}
#endif