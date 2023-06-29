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
    EC_GROUP *ecGroup;
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
    SCOSSL_COMMON_ALIGNED_ALLOC(keyCtx, OPENSSL_zalloc, SCOSSL_ECC_KEY_CTX);
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->libctx = provctx->libctx;

    return keyCtx;
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_dup_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copyCtx, OPENSSL_malloc, SCOSSL_ECC_KEY_CTX);
    if (copyCtx == NULL)
    {
        return NULL;
    }

    if (keyCtx->initialized)
    {
        if (keyCtx->ecGroup == NULL)
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_ECC_CONTEXT_EX, ERR_R_INTERNAL_ERROR,
                "ECC key inititalized but group not set"); 
        }
        copyCtx->ecGroup = keyCtx->ecGroup;
        copyCtx->key = SymCryptEckeyAllocate(scossl_ecc_group_to_symcrypt_curve(copyCtx->ecGroup));
        SymCryptEckeyCopy(keyCtx->key, copyCtx->key);
    }
    else
    {
        copyCtx->initialized = 0;
        copyCtx->key = NULL;
        copyCtx->ecGroup = NULL;
    }

    copyCtx->libctx = keyCtx->libctx;

    return copyCtx;
}

static void p_scossl_ecc_keymgmt_free_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

    EC_GROUP_free(keyCtx->ecGroup);    
    OPENSSL_free(keyCtx);
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_ecc_keygen_set_params(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx, const _In_ OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL)
    {
        genCtx->ecGroup = EC_GROUP_new_from_params(params, genCtx->libctx, NULL);
        if (genCtx->ecGroup == NULL)
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
    if (genCtx != NULL) 
    {
        EC_GROUP_free(genCtx->ecGroup);
    }
    OPENSSL_free(genCtx);
}

static SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                       const _In_ OSSL_PARAM params[])
{
    SCOSSL_COMMON_ALIGNED_ALLOC(genCtx, OPENSSL_malloc, SCOSSL_ECC_KEYGEN_CTX);
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
    PCSYMCRYPT_ECURVE pCurve = NULL;

    SCOSSL_COMMON_ALIGNED_ALLOC(keyCtx, OPENSSL_malloc, SCOSSL_ECC_KEY_CTX);
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->libctx = genCtx->libctx;
    keyCtx->ecGroup = genCtx->ecGroup;
    genCtx->ecGroup = NULL;

    pCurve = scossl_ecc_group_to_symcrypt_curve(keyCtx->ecGroup);
    if (pCurve == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto cleanup; 
    }

    keyCtx->key = SymCryptEckeyAllocate(pCurve);
    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // We don't know whether this key will be used for ECDSA or ECDH
    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

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
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL &&
        !OSSL_PARAM_set_uint32(p, 2 * SymCryptEcurveSizeofScalarMultiplier(keyCtx->key->pCurve)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptEcurveBitsizeofGroupOrder(keyCtx->key->pCurve)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptEcurveBitsizeofGroupOrder(keyCtx->key->pCurve) / 2))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL)
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
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS);
    if (p != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL &&
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
                       (keyCtx->key != NULL && keyCtx->key->pCurve != NULL);
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
        !SymCryptEcurveIsSame(keyCtx1->key->pCurve, keyCtx2->key->pCurve))
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

static SCOSSL_STATUS p_scossl_ecc_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, const _In_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    PSYMCRYPT_ECURVE pCurve;
    BIGNUM *bnPrivateKey = NULL;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    const OSSL_PARAM *p;

    fprintf(stdout, "import!");
    // Domain parameters (curve) are required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL)
    {
        keyCtx->ecGroup = EC_GROUP_new_from_params(params, keyCtx->libctx, NULL);
        if (keyCtx->ecGroup == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return SCOSSL_FAILURE;
        }      
    }

    pCurve = scossl_ecc_group_to_symcrypt_curve(keyCtx->ecGroup);
    if (pCurve == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto cleanup; 
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL)
        {
            cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
            if (!OSSL_PARAM_get_octet_string(p, (void **)&pbPublicKey, 0, &cbPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL)
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
                return SCOSSL_FAILURE;
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

        keyCtx->key = SymCryptEckeyAllocate(pCurve);
        if (keyCtx->key == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        scError = SymCryptEckeySetValue(
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0,
            keyCtx->key);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
        if (p != NULL &&
            !OSSL_PARAM_get_int(p, keyCtx->includePublic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    if (!ret)
    {
        p_scossl_ecc_keymgmt_free_ctx(keyCtx);
    }
    BN_clear_free(bnPrivateKey);
    OPENSSL_secure_clear_free(pbPrivateKey, cbPublicKey);
    OPENSSL_free(pbPublicKey);

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
    curveName = OSSL_EC_curve_nid2name(EC_GROUP_get_curve_name(keyCtx->ecGroup));
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curveName, strlen(curveName)))
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
    {0, NULL}};

#ifdef __cplusplus
}
#endif