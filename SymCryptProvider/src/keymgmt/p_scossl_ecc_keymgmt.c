//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_ecc_keymgmt.h"

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_X25519_MAX_SIZE (32)
#define SCOSSL_ECC_DEFAULT_DIGEST SN_sha256
#define SCOSSL_ECC_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

typedef struct
{
    OSSL_LIB_CTX *libctx;
    PCSYMCRYPT_ECURVE curve;
    BOOL isX25519;
    point_conversion_form_t conversionFormat;
} SCOSSL_ECC_KEYGEN_CTX;

// ScOSSL only supports named curves
static const OSSL_PARAM p_scossl_ecc_keygen_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecc_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecc_keymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_x25519_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

// We don't need to support setting the group for X25519 import/export
// Note: OpenSSL passes the private key for X25519 as an octet string
// instead of a BN in the general ECC case.
static const OSSL_PARAM p_scossl_x25519_keymgmt_impexp_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_ITEM p_scossl_ecc_keymgmt_conversion_formats[] = {
    {POINT_CONVERSION_COMPRESSED,   OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED},
    {POINT_CONVERSION_UNCOMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED},
    {POINT_CONVERSION_HYBRID,       OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID}};

static SCOSSL_STATUS p_scossl_ecc_keymgmt_get_private_key_bn(_In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                                             _Out_ BIGNUM **pbnPrivateKey, _Out_opt_ SIZE_T *pcbPrivateKey);

static const char* p_scossl_ecc_keymgmt_conversion_id_to_name(point_conversion_form_t conversionFormat);
static point_conversion_form_t p_scossl_ecc_keymgmt_conversion_name_to_id(_In_ const char* conversionFormatName);

// Key Context Management
//
// Key import uses keymgmt_new to allocate an empty key object
// first, then passes that reference to keymgmt_import. Since
// the size of the SYMCRYPT_ECKEY depends on parameters that aren't
// known until import, no key is actually allocated here.

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return p_scossl_ecc_new_ctx(provctx);
}

static SCOSSL_ECC_KEY_CTX *p_scossl_x25519_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_ECC_KEY_CTX *keyCtx = p_scossl_ecc_new_ctx(provctx);
    if (keyCtx != NULL)
    {
        keyCtx->curve = scossl_ecc_get_x25519_curve();
        keyCtx->isX25519 = TRUE;
    }

    return keyCtx;
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
        PCSYMCRYPT_ECURVE pCurve = scossl_ecc_group_to_symcrypt_curve(ecGroup);
        EC_GROUP_free(ecGroup);

        if (pCurve == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return SCOSSL_FAILURE;
        }

        genCtx->curve = pCurve;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING)) != NULL)
    {
        const char* encoding;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &encoding))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (OPENSSL_strcasecmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)) != NULL)
    {
        const char* conversionFormatName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &conversionFormatName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((genCtx->conversionFormat = p_scossl_ecc_keymgmt_conversion_name_to_id(conversionFormatName)) == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

// Caller expects to be able to set the group name. We just ensure that it's X25519
static SCOSSL_STATUS p_scossl_x25519_keygen_set_params(ossl_unused void *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    char *groupName = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        if (!OSSL_PARAM_get_utf8_string(p, &groupName, 0) ||
            strcmp(groupName, SN_X25519) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(groupName);
    return ret;
}

static const OSSL_PARAM *p_scossl_ecc_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provctx)
{
    return p_scossl_ecc_keygen_settable_param_types;
}

static void p_scossl_ecc_keygen_cleanup(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx)
{
    OPENSSL_free(genCtx);
}

static SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_common_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                              _In_ const OSSL_PARAM params[], BOOL isX25519)
{
    SCOSSL_ECC_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEYGEN_CTX));
    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genCtx->libctx = provctx->libctx;
    genCtx->isX25519 = isX25519;
    genCtx->conversionFormat = POINT_CONVERSION_UNCOMPRESSED;

    if (!p_scossl_ecc_keygen_set_params(genCtx, params))
    {
        OPENSSL_free(genCtx);
        return NULL;
    }

    return genCtx;
}

static SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                       _In_ const OSSL_PARAM params[])
{
    return p_scossl_ecc_common_keygen_init(provctx, selection, params, FALSE);
}

static SCOSSL_ECC_KEYGEN_CTX *p_scossl_x25519_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                          _In_ const OSSL_PARAM params[])
{
    SCOSSL_ECC_KEYGEN_CTX *genCtx = p_scossl_ecc_common_keygen_init(provctx, selection, params, TRUE);
    // Always set curve to X25519
    if (genCtx != NULL)
    {
        genCtx->curve = scossl_ecc_get_x25519_curve();
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_ecc_keygen_set_template(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx, SCOSSL_ECC_KEY_CTX *tmplCtx)
{
    if (tmplCtx == NULL || tmplCtx->curve == NULL)
    {
        return SCOSSL_FAILURE;
    }

    genCtx->curve = tmplCtx->curve;
    return SCOSSL_SUCCESS;
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keygen(_In_ SCOSSL_ECC_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_ECC_KEY_CTX *keyCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEY_CTX));
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->libctx = genCtx->libctx;
    keyCtx->curve = genCtx->curve;
    keyCtx->isX25519 = genCtx->isX25519;
    keyCtx->conversionFormat = genCtx->conversionFormat;
    keyCtx->key = NULL;

    if (p_scossl_ecc_gen(keyCtx) != SCOSSL_SUCCESS)
    {
        p_scossl_ecc_free_ctx(keyCtx);
        return NULL;
    }

    return keyCtx;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_get_pubkey_point(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE pbPublicKey = NULL;
    SIZE_T cbPublicKey;
    BIGNUM *bnPubX = NULL;
    BIGNUM *bnPubY = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    OSSL_PARAM *paramPubX = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
    OSSL_PARAM *paramPubY = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);

    if (paramPubX == NULL &&
        paramPubY == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

    if ((pbPublicKey = OPENSSL_malloc(cbPublicKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptEckeyGetValue(
        keyCtx->key,
        NULL, 0,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0 );
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
        goto cleanup;
    }

    if (paramPubX != NULL)
    {
        if ((bnPubX = BN_bin2bn(pbPublicKey, cbPublicKey/2, NULL)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!OSSL_PARAM_set_BN(paramPubX, bnPubX))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPubY != NULL)
    {
        if ((bnPubY = BN_bin2bn(pbPublicKey + (cbPublicKey/2), cbPublicKey/2, NULL)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!OSSL_PARAM_set_BN(paramPubY, bnPubY))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbPublicKey);
    BN_free(bnPubX);
    BN_free(bnPubY);

    return ret;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_get_params(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE pbEncodedKey = NULL;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    BIGNUM *bnPrivateKey = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_uint32(p, p_scossl_ecc_get_max_result_size(keyCtx, FALSE)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
         (keyCtx->curve == NULL ||
          !OSSL_PARAM_set_int(p, SymCryptEcurveBitsizeofGroupOrder(keyCtx->curve))))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
         (keyCtx->curve == NULL ||
          !OSSL_PARAM_set_int(p, scossl_ecc_get_curve_security_bits(keyCtx->curve))))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        SIZE_T cbEncodedKey;
        if (!p_scossl_ecc_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pbEncodedKey, &cbEncodedKey) ||
            !OSSL_PARAM_set_octet_string(p, pbEncodedKey, cbEncodedKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *curveName;

        if ((curveName = scossl_ecc_get_curve_name(keyCtx->curve)) == NULL ||
            !OSSL_PARAM_set_utf8_string(p, curveName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_ENCODING)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_EC_ENCODING_GROUP))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL)
    {
        SIZE_T cbEncodedKey;
        if (!p_scossl_ecc_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pbEncodedKey, &cbEncodedKey) ||
            !OSSL_PARAM_set_octet_string(p, pbEncodedKey, cbEncodedKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL &&
        keyCtx->initialized &&
        SymCryptEckeyHasPrivateKey(keyCtx->key))
    {
        if (keyCtx->isX25519)
        {
            if (!p_scossl_ecc_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, &pbPrivateKey, &cbPrivateKey) ||
                !OSSL_PARAM_set_octet_string(p, pbPrivateKey, cbPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }
        else if (!p_scossl_ecc_keymgmt_get_private_key_bn(keyCtx, &bnPrivateKey, NULL) ||
                 !OSSL_PARAM_set_BN(p, bnPrivateKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    // General ECDH only
    if (!keyCtx->isX25519)
    {
        if (!p_scossl_ecc_keymgmt_get_pubkey_point(keyCtx, params))
        {
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL &&
            !OSSL_PARAM_set_utf8_string(p, SCOSSL_ECC_DEFAULT_DIGEST))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        // SCOSSL only allows named curves, so these is never true
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS)) != NULL &&
            !OSSL_PARAM_set_int(p, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH)) != NULL &&
            !OSSL_PARAM_set_int(p, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)) != NULL)
        {
            const char* conversionFormatName;
            if ((conversionFormatName = p_scossl_ecc_keymgmt_conversion_id_to_name(keyCtx->conversionFormat)) == 0)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
                return SCOSSL_FAILURE;
            }

            if (!OSSL_PARAM_set_utf8_string(p, conversionFormatName))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return SCOSSL_FAILURE;
            }
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbEncodedKey);
    OPENSSL_clear_free(pbPrivateKey, cbPrivateKey);
    BN_clear_free(bnPrivateKey);

    return ret;
}

static const OSSL_PARAM *p_scossl_ecc_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_ecc_keymgmt_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_x25519_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_x25519_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_set_params(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    EC_GROUP *ecGroup = NULL;
    PBYTE  encodedPoint = NULL;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    BN_CTX *bnCtx = NULL;
    EC_POINT *ecPoint = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_NUMBER_FORMAT numFormat = keyCtx->isX25519 ? SYMCRYPT_NUMBER_FORMAT_LSB_FIRST : SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    SYMCRYPT_ECPOINT_FORMAT pointFormat = keyCtx->isX25519 ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        SIZE_T encodedLen;
        SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

        if (keyCtx->key == NULL &&
            (keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

#ifdef KEYSINUSE_ENABLED
        // Reset keysinuse in case new key material is overwriting existing
        p_scossl_ecc_reset_keysinuse(keyCtx);
#endif

        if (keyCtx->isX25519)
        {
            if (!OSSL_PARAM_get_octet_string(p, (void **)&pbPublicKey, 0, &cbPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }
        else
        {
            if (!OSSL_PARAM_get_octet_string(p, (void **)&encodedPoint, 0, &encodedLen))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
            if (((ecGroup = scossl_ecc_symcrypt_curve_to_ecc_group(keyCtx->curve)) == NULL) ||
                ((ecPoint = EC_POINT_new(ecGroup)) == NULL) ||
                ((bnCtx = BN_CTX_new_ex(keyCtx->libctx))  == NULL) ||
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

        scError = SymCryptEckeySetValue(
            NULL, 0,
            pbPublicKey, cbPublicKey,
            numFormat,
            pointFormat,
            SYMCRYPT_FLAG_ECKEY_ECDH,
            keyCtx->key);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeySetValue failed", scError);
            goto cleanup;
        }

        keyCtx->initialized = TRUE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING)) != NULL)
    {
        const char* encoding;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &encoding))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (OPENSSL_strcasecmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }
    }

    if (!keyCtx->isX25519)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)) != NULL)
        {
            const char* conversionFormatName;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &conversionFormatName))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            if ((keyCtx->conversionFormat = p_scossl_ecc_keymgmt_conversion_name_to_id(conversionFormatName)) == 0)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
                return SCOSSL_FAILURE;
            }
        }
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    OPENSSL_free(encodedPoint);
    OPENSSL_free(pbPublicKey);
    EC_GROUP_free(ecGroup);
    EC_POINT_free(ecPoint);
    BN_CTX_free(bnCtx);

    return ret;
}

static const OSSL_PARAM *p_scossl_ecc_keymgmt_settable_params(ossl_unused void *provctx)
{
    return p_scossl_ecc_keymgmt_settable_param_types;
}

static BOOL p_scossl_ecc_keymgmt_has(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    BOOL hasSelection = TRUE;

    if (keyCtx == NULL)
    {
        return FALSE;
    }

    if ((selection & SCOSSL_ECC_POSSIBLE_SELECTIONS) != 0)
    {
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
            hasSelection = hasSelection && (keyCtx->curve != NULL);
        }
    }
    // OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS always considered available

    return hasSelection;
}

// Key checking is handled by SymCrypt, and the curves are valid named curves. This function
// just needs to check whether the data indicated by selection has been set.
static SCOSSL_STATUS p_scossl_ecc_keymgmt_validate(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, ossl_unused int checktype)
{
    SCOSSL_STATUS success = SCOSSL_SUCCESS;

    if (!p_scossl_ecc_keymgmt_has(keyCtx, selection))
    {
        return SCOSSL_FAILURE;
    }

    return success;
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
    SYMCRYPT_ERROR scError;
    SYMCRYPT_ECPOINT_FORMAT pointFormat = keyCtx1->isX25519 ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;

    if (keyCtx1->initialized != keyCtx2->initialized ||
        keyCtx1->isX25519 != keyCtx2->isX25519)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        !SymCryptEcurveIsSame(keyCtx1->curve, keyCtx2->curve))
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && keyCtx1->initialized)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx1->key, pointFormat);
            if (cbPublicKey != SymCryptEckeySizeofPublicKey(keyCtx2->key, pointFormat))
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
        // Private key only needs to be checked if public key is not
        else if (SymCryptEckeyHasPrivateKey(keyCtx1->key) && SymCryptEckeyHasPrivateKey(keyCtx2->key))
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
        // Private key comparison, but one key doesn't have a private key
        else
        {
            ret = FALSE;
            goto cleanup;
        }

        if ((cbPrivateKey | cbPublicKey) == 0)
        {
            ret = TRUE;
            goto cleanup;
        }

        scError = SymCryptEckeyGetValue(
            keyCtx1->key,
            pbPrivateKey1, cbPrivateKey,
            pbPublicKey1, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pointFormat,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
            goto cleanup;
        }

        scError = SymCryptEckeyGetValue(
            keyCtx2->key,
            pbPrivateKey2, cbPrivateKey,
            pbPublicKey2, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pointFormat,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
            goto cleanup;
        }

        ret = (memcmp(pbPrivateKey1, pbPrivateKey2, cbPrivateKey) == 0) &&
              (memcmp(pbPublicKey1, pbPublicKey2, cbPublicKey) == 0);
    }
    else
    {
        ret = TRUE;
    }

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
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    EC_GROUP *ecGroup = NULL;
    PCSYMCRYPT_ECURVE pCurve;
    PCBYTE pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    BIGNUM *bnPrivateKey = NULL;
    const OSSL_PARAM *p;

    // Domain parameters (curve) are required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        goto cleanup;
    }

    // Only allow named curves
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING)) != NULL)
    {
        const char* encoding;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &encoding))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (OPENSSL_strcasecmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    ecGroup = EC_GROUP_new_from_params(params, keyCtx->libctx, NULL);
    pCurve = scossl_ecc_group_to_symcrypt_curve(ecGroup);

    if (pCurve == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto cleanup;
    }

    keyCtx->curve = pCurve;

    // Other parameters
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC)) != NULL &&
            !OSSL_PARAM_get_int(p, &keyCtx->includePublic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)) != NULL)
        {
            const char* conversionFormatName;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &conversionFormatName))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            if ((keyCtx->conversionFormat = p_scossl_ecc_keymgmt_conversion_name_to_id(conversionFormatName)) == 0)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
                goto cleanup;
            }
        }
    }

    // Keypair
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL &&
            !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbPublicKey, &cbPublicKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
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

            cbPrivateKey = p_scossl_ecc_get_encoded_key_size(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
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

        ret = p_scossl_ecc_set_encoded_key(
            keyCtx,
            pbPublicKey, cbPublicKey,
            pbPrivateKey, cbPrivateKey);
        if (ret != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

#ifdef KEYSINUSE_ENABLED
        keyCtx->isImported = TRUE;
#endif
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    BN_clear_free(bnPrivateKey);
    EC_GROUP_free(ecGroup);

    return ret;
}

static SCOSSL_STATUS p_scossl_ecc_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                                 _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *bnPrivateKey = NULL;
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
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_EC_ENCODING_GROUP, strlen(OSSL_PKEY_EC_ENCODING_GROUP)) ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curveName, strlen(curveName)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            if (!p_scossl_ecc_keymgmt_get_private_key_bn(keyCtx, &bnPrivateKey, &cbPrivateKey) ||
                !OSSL_PARAM_BLD_push_BN_pad(bld, OSSL_PKEY_PARAM_PRIV_KEY, bnPrivateKey, cbPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            if (!p_scossl_ecc_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pbPublicKey, &cbPublicKey) ||
                !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbPublicKey, cbPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    {
        const char* conversionFormatName;

        if ((conversionFormatName = p_scossl_ecc_keymgmt_conversion_id_to_name(keyCtx->conversionFormat)) == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 0) ||
            !OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, keyCtx->includePublic) ||
            !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, conversionFormatName, strlen(conversionFormatName)))
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
    BN_clear_free(bnPrivateKey);
    OPENSSL_free(pbPublicKey);

    return ret;
}

static const OSSL_PARAM *p_scossl_x25519_keymgmt_impexp_types(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 ? NULL : p_scossl_x25519_keymgmt_impexp_param_types;
}

static SCOSSL_STATUS p_scossl_x25519_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    const OSSL_PARAM *p;

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

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string(p, (void **)&pbPublicKey, 0, &cbPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string(p, (void **)&pbPrivateKey, 0, &cbPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            // Preserve original bits for export
            keyCtx->modifiedPrivateBits = pbPrivateKey[0] & 0x07;
            keyCtx->modifiedPrivateBits |= pbPrivateKey[cbPrivateKey-1] & 0xc0;

            pbPrivateKey[0] &= 0xf8;
            pbPrivateKey[cbPrivateKey-1] &= 0x7f;
            pbPrivateKey[cbPrivateKey-1] |= 0x40;
        }

        scError = SymCryptEckeySetValue(
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_X,
            SYMCRYPT_FLAG_ECKEY_ECDH,
            keyCtx->key);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeySetValue failed", scError);
            goto cleanup;
        }

        keyCtx->initialized = TRUE;
    }

    ret = SCOSSL_SUCCESS;
cleanup:

    OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    OPENSSL_free(pbPublicKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_x25519_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                                    _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM_BLD *bld = NULL;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    OSSL_PARAM *params = NULL;

    // Caller must request keypair for export
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);
        if ((pbPrivateKey = OPENSSL_secure_malloc(cbPrivateKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
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
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_X,
        0);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
        goto cleanup;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        pbPrivateKey[0] = (keyCtx->modifiedPrivateBits & 0x07) | (pbPrivateKey[0] & 0xf8);
        pbPrivateKey[cbPrivateKey-1] = (keyCtx->modifiedPrivateBits & 0xc0) | (pbPrivateKey[cbPrivateKey-1] & 0x3f);

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, pbPrivateKey, cbPrivateKey))
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
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_ecc_free_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_ecc_dup_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_ecc_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_ecc_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_ecc_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_ecc_keygen_set_template},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_ecc_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_ecc_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))p_scossl_ecc_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_ecc_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_ecc_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_ecc_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))p_scossl_ecc_keymgmt_query_operation_name},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_x25519_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_x25519_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_ecc_free_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_ecc_dup_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_x25519_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_ecc_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_x25519_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_ecc_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_x25519_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_ecc_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))p_scossl_ecc_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_ecc_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_x25519_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_x25519_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_x25519_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_x25519_keymgmt_export},
    {0, NULL}};

//
// Helpers
//

// General ECC case exports private key as a BIGNUM, while x25519 exports as an octet string
_Use_decl_annotations_
static SCOSSL_STATUS p_scossl_ecc_keymgmt_get_private_key_bn(SCOSSL_ECC_KEY_CTX *keyCtx,
                                                             BIGNUM **pbnPrivateKey, SIZE_T *pcbPrivateKey)
{
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    BIGNUM *bnPrivateKey = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (!p_scossl_ecc_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, &pbPrivateKey, &cbPrivateKey))
    {
        goto cleanup;
    }

    if ((bnPrivateKey = BN_secure_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    BN_set_flags(bnPrivateKey, BN_FLG_CONSTTIME);

    if((BN_bin2bn(pbPrivateKey, cbPrivateKey, bnPrivateKey)) == NULL)
    {
        goto cleanup;
    }

    *pbnPrivateKey = bnPrivateKey;

    if (pcbPrivateKey != NULL)
    {
        *pcbPrivateKey = cbPrivateKey;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        BN_clear_free(bnPrivateKey);
    }
    OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);

    return ret;
}

_Use_decl_annotations_
static const char* p_scossl_ecc_keymgmt_conversion_id_to_name(point_conversion_form_t conversionFormat)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_ecc_keymgmt_conversion_formats) / sizeof(OSSL_ITEM); i++)
    {
        if (p_scossl_ecc_keymgmt_conversion_formats[i].id == conversionFormat)
        {
            return p_scossl_ecc_keymgmt_conversion_formats[i].ptr;
        }
    }

    return NULL;
}

_Use_decl_annotations_
static point_conversion_form_t p_scossl_ecc_keymgmt_conversion_name_to_id(const char* conversionFormatName)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_ecc_keymgmt_conversion_formats) / sizeof(OSSL_ITEM); i++)
    {
        if (OPENSSL_strcasecmp(p_scossl_ecc_keymgmt_conversion_formats[i].ptr, conversionFormatName) == 0)
        {
            return p_scossl_ecc_keymgmt_conversion_formats[i].id;
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif