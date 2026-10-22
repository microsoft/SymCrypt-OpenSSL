//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mldsa_keymgmt.h"

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    BOOL isComposite;

    SCOSSL_MLDSA_PARAMS mldsaParams;

    BYTE abSeed[SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE];
    SIZE_T cbSeed;
} SCOSSL_MLDSA_KEYGEN_CTX;

static const SCOSSL_MLDSA_KEY_FORMATS p_scossl_mldsa_formats = {
    .null = SYMCRYPT_MLDSAKEY_FORMAT_NULL,
    .privateSeed = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
    .privateKey = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
    .publicKey = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY};

static const SCOSSL_MLDSA_KEY_FORMATS p_scossl_composite_mldsa_formats = {
    .null = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL,
    .privateSeed = SCOSSL_MLDSAKEY_FORMAT_UNSUPPORTED,
    .privateKey = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
    .publicKey = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY};

// Standalone ML-DSA keymgmt parameters
static const OSSL_PARAM p_scossl_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_impexp_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

// Composite ML-DSA keymgmt parameters.
// Largely the same as standalone ML-DSA keymgmt parameters, but without private seed support
static const OSSL_PARAM p_scossl_composite_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_composite_mldsa_keymgmt_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_composite_mldsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_composite_mldsa_impexp_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

static int p_scossl_mldsa_get_bits(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx);
static int p_scossl_mldsa_get_security_bits(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx);
static SIZE_T p_scossl_mldsa_get_max_size(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx);

static void p_scossl_mldsa_key_free(BOOL isComposite, _Inout_ PSCOSSL_MLDSA_KEY key)
{
    if (key == NULL)
        return;

    if (isComposite)
    {
        SymCryptCompositeMlDsakeyFree(key);
    }
    else
    {
        SymCryptMlDsakeyFree(key);
    }
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));

    if (keyCtx != NULL)
    {
        keyCtx->formats = isComposite ? &p_scossl_composite_mldsa_formats : &p_scossl_mldsa_formats;
        keyCtx->isComposite = isComposite;
        keyCtx->mldsaParams = mldsaParams;
        keyCtx->format = keyCtx->formats->null;
    }

    return keyCtx;
}

_Use_decl_annotations_
void p_scossl_mldsa_keymgmt_free_key_ctx(SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    p_scossl_mldsa_key_free(keyCtx->isComposite, keyCtx->key);

    OPENSSL_free(keyCtx);
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_MLDSAKEY_FORMAT format;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLDSA_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));

    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    copyCtx->formats = keyCtx->formats;
    copyCtx->isComposite = keyCtx->isComposite;
    copyCtx->mldsaParams = keyCtx->mldsaParams;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 &&
        keyCtx->key != NULL)
    {
        format = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
            keyCtx->format :
            keyCtx->formats->publicKey;

        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, format, &pbKey, &cbKey) != SCOSSL_SUCCESS ||
            p_scossl_mldsa_keymgmt_set_encoded_key(copyCtx, format, pbKey, cbKey) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mldsa_keymgmt_free_key_ctx(copyCtx);
        copyCtx = NULL;
    }

    OPENSSL_secure_clear_free(pbKey, cbKey);

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (!genCtx->isComposite &&
        (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL)
    {
        PBYTE pbSeed = genCtx->abSeed;
        SIZE_T cbSeed = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbSeed, SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE, &cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbSeed != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE)
        {
            genCtx->cbSeed = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return SCOSSL_FAILURE;
        }

        genCtx->cbSeed = cbSeed;
    }

    return SCOSSL_SUCCESS;
}

static void p_scossl_mldsa_keygen_cleanup(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx)
{
    OPENSSL_secure_clear_free(genCtx, sizeof(SCOSSL_MLDSA_KEYGEN_CTX));
}

static SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(_In_ const OSSL_PARAM params[], BOOL isComposite,
                                                           SCOSSL_MLDSA_PARAMS mldsaParams)
{
    SCOSSL_MLDSA_KEYGEN_CTX *genCtx = OPENSSL_secure_zalloc(sizeof(SCOSSL_MLDSA_KEYGEN_CTX));

    if (genCtx != NULL)
    {
        genCtx->isComposite = isComposite;
        genCtx->mldsaParams = mldsaParams;

        if (p_scossl_mldsa_keygen_set_params(genCtx, params) != SCOSSL_SUCCESS)
        {
            p_scossl_mldsa_keygen_cleanup(genCtx);
            return NULL;
        }
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_keygen_set_template(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLDSA_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL || tmplCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (genCtx->isComposite != tmplCtx->isComposite ||
        genCtx->mldsaParams != tmplCtx->mldsaParams)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keygen(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx,
                                                   ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto cleanup;
    }

    keyCtx = p_scossl_mldsa_keymgmt_new_ctx(genCtx->mldsaParams, genCtx->isComposite);
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    keyCtx->key = genCtx->isComposite ?
            (PSCOSSL_MLDSA_KEY)SymCryptCompositeMlDsakeyAllocate(genCtx->mldsaParams) :
            (PSCOSSL_MLDSA_KEY)SymCryptMlDsakeyAllocate(genCtx->mldsaParams);
    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (genCtx->isComposite)
    {
        scError = SymCryptCompositeMlDsakeyGenerate(keyCtx->key, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptCompositeMlDsakeyGenerate failed", scError);
            goto cleanup;
        }

        keyCtx->format = keyCtx->formats->privateKey;
    }
    else
    {
        if (genCtx->cbSeed != 0)
        {
            scError = SymCryptMlDsakeySetValue(
                genCtx->abSeed, genCtx->cbSeed,
                SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
                keyCtx->key);

            OPENSSL_cleanse(genCtx->abSeed, genCtx->cbSeed);
            genCtx->cbSeed = 0;

            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeySetValue failed", scError);
                goto cleanup;
            }
        }
        else
        {
            scError = SymCryptMlDsakeyGenerate(keyCtx->key, 0);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeyGenerate failed", scError);
                goto cleanup;
            }
        }

        keyCtx->format = keyCtx->formats->privateSeed;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_load(_In_ const void *reference, size_t reference_size)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;

    if (reference_size == sizeof(keyCtx))
    {
        keyCtx = *(SCOSSL_MLDSA_KEY_CTX **)reference;
        *(SCOSSL_MLDSA_KEY_CTX **)reference = NULL;
    }

    return keyCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(ossl_unused SCOSSL_MLDSA_KEY_CTX *keyCtx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_key_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE pbPubKey = NULL;
    SIZE_T cbPubKey = 0;
    PBYTE pbPrivKey = NULL;
    SIZE_T cbPrivKey = 0;
    PBYTE pbSeed = NULL;
    SIZE_T cbSeed = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *paramEncodedKey = NULL;
    OSSL_PARAM *paramPubKey = NULL;
    OSSL_PARAM *paramPrivKey = NULL;
    OSSL_PARAM *paramPrivateSeed = NULL;

    if (keyCtx->key != NULL)
    {
        paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);

        if (p_scossl_mldsa_keymgmt_has(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

            if (keyCtx->format == keyCtx->formats->privateSeed)
            {
                paramPrivateSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
            }
        }
    }

    if (paramEncodedKey != NULL || paramPubKey != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->publicKey, &pbPubKey, &cbPubKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get encoded public key");
            goto cleanup;
        }

        if (paramEncodedKey != NULL &&
            !OSSL_PARAM_set_octet_string(paramEncodedKey, pbPubKey, cbPubKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if (paramPubKey != NULL &&
            !OSSL_PARAM_set_octet_string(paramPubKey, pbPubKey, cbPubKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrivKey != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->privateKey, &pbPrivKey, &cbPrivKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get encoded private key");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivKey, pbPrivKey, cbPrivKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrivateSeed != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->privateSeed, &pbSeed, &cbSeed) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get private seed");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivateSeed, pbSeed, cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_free(pbPubKey);
    OPENSSL_secure_clear_free(pbPrivKey, cbPrivKey);
    OPENSSL_secure_clear_free(pbSeed, cbSeed);

    return ret;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mldsa_get_bits(keyCtx)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mldsa_get_security_bits(keyCtx)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbSignature = p_scossl_mldsa_get_max_size(keyCtx);

        if (cbSignature == 0)
        {
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_size_t(p, cbSignature))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ""))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mldsa_keymgmt_get_key_params(keyCtx, params);
}

_Use_decl_annotations_
BOOL p_scossl_mldsa_keymgmt_has(const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    if (keyCtx == NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
        keyCtx->key == NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        keyCtx->format != keyCtx->formats->privateKey &&
        keyCtx->format != keyCtx->formats->privateSeed)
    {
        return FALSE;
    }

    return TRUE;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_validate(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection,
                                                     ossl_unused int checktype)
{
    return p_scossl_mldsa_keymgmt_has(keyCtx, selection) ? SCOSSL_SUCCESS : SCOSSL_FAILURE;
}

static BOOL p_scossl_mldsa_keymgmt_match(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx1, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx2,
                                         int selection)
{
    PBYTE pbKey1 = NULL;
    PBYTE pbKey2 = NULL;
    SIZE_T cbKey1 = 0;
    SIZE_T cbKey2 = 0;
    BOOL ret = FALSE;

    if (keyCtx1 == NULL ||
        keyCtx2 == NULL ||
        keyCtx1->isComposite != keyCtx2->isComposite ||
        keyCtx1->mldsaParams != keyCtx2->mldsaParams)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (keyCtx1->key != NULL && keyCtx2->key != NULL)
        {
            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx1, keyCtx1->formats->publicKey, &pbKey1, &cbKey1) != SCOSSL_SUCCESS ||
                p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx2, keyCtx2->formats->publicKey, &pbKey2, &cbKey2) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (cbKey1 != cbKey2 ||
                memcmp(pbKey1, pbKey2, cbKey1) != 0)
            {
                goto cleanup;
            }
        }
        // No match in the case where only one key is set.
        else if ((keyCtx1->key == NULL) != (keyCtx2->key == NULL))
        {
            goto cleanup;
        }
    }

    ret = TRUE;

cleanup:
    OPENSSL_secure_free(pbKey1);
    OPENSSL_secure_free(pbKey2);

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, const OSSL_PARAM params[])
{
    PCBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_MLDSAKEY_FORMAT format;
    const OSSL_PARAM *p;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (!keyCtx->isComposite &&
            (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            format = keyCtx->formats->privateSeed;
        }
        else if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            format = keyCtx->formats->privateKey;
        }
    }

    // Only try public key import if private key was not available
    if (pbKey == NULL)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL &&
            !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        format = keyCtx->formats->publicKey;
    }

    if (pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mldsa_keymgmt_set_encoded_key(keyCtx, format, pbKey, cbKey);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_export(SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection,
                                            OSSL_CALLBACK *param_cb, void *cbarg)
{
    PBYTE pbPubKey = NULL;
    SIZE_T cbPubKey = 0;
    PBYTE pbSeed = NULL;
    SIZE_T cbSeed = 0;
    PBYTE pbPrivKey = NULL;
    SIZE_T cbPrivKey = 0;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        goto cleanup;
    }

    if ((bld = OSSL_PARAM_BLD_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->publicKey, &pbPubKey, &cbPubKey) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbPubKey, cbPubKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        p_scossl_mldsa_keymgmt_has(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        if (keyCtx->format == keyCtx->formats->privateSeed)
        {
            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->privateSeed, &pbSeed, &cbSeed) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_ML_DSA_SEED, pbSeed, cbSeed))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }

        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->formats->privateKey, &pbPrivKey, &cbPrivKey) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, pbPrivKey, cbPrivKey))
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
    OPENSSL_secure_free(pbPubKey);
    OPENSSL_secure_clear_free(pbSeed, cbSeed);
    OPENSSL_secure_clear_free(pbPrivKey, cbPrivKey);

    return ret;
}

//
// Helper functions
//

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key_size(const SCOSSL_MLDSA_KEY_CTX *keyCtx, SCOSSL_MLDSAKEY_FORMAT format,
                                                          SIZE_T *pcbKey)
{
    SYMCRYPT_ERROR scError = keyCtx->isComposite ?
        SymCryptCompositeMlDsaSizeofKeyFormatFromParams(keyCtx->mldsaParams, format, pcbKey) :
        SymCryptMlDsaSizeofKeyFormatFromParams(keyCtx->mldsaParams, format, pcbKey);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofKeyFormatFromParams failed", scError);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// On entry a non-NULL *ppbKey selects the caller's buffer of *pcbKey bytes, and NULL requests
// allocation. Only an allocated buffer is freed on failure; the caller's is left owned by the caller.
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(const SCOSSL_MLDSA_KEY_CTX *keyCtx, SCOSSL_MLDSAKEY_FORMAT format,
                                                     PBYTE *ppbKey, SIZE_T *pcbKey)
{
    PBYTE pbKey = NULL;
    PBYTE pbAlloc = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (format == keyCtx->formats->null)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (format == keyCtx->formats->privateSeed)
    {
        if (keyCtx->format != keyCtx->formats->privateSeed)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
            goto cleanup;
        }
    }
    else if (format == keyCtx->formats->privateKey &&
             !p_scossl_mldsa_keymgmt_has(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        goto cleanup;
    }

    if (p_scossl_mldsa_keymgmt_get_encoded_key_size(keyCtx, format, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if (*ppbKey != NULL)
    {
        if (*pcbKey < cbKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        pbKey = *ppbKey;
    }
    // Always using OPENSSL_secure_malloc so caller doesn't have to worry about
    // calling separate free functions for public and private keys.
    else if ((pbAlloc = OPENSSL_secure_malloc(cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    else
    {
        pbKey = pbAlloc;
    }

    scError = keyCtx->isComposite ?
        SymCryptCompositeMlDsakeyGetValue(keyCtx->key, pbKey, cbKey, format, 0) :
        SymCryptMlDsakeyGetValue(keyCtx->key, pbKey, cbKey, format, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeyGetValue failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

    *ppbKey = pbKey;
    *pcbKey = cbKey;

    pbAlloc = NULL;

cleanup:
    if (ret != SCOSSL_SUCCESS && pbKey != NULL)
    {
        OPENSSL_cleanse(pbKey, cbKey);
    }

    OPENSSL_secure_free(pbAlloc);

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(SCOSSL_MLDSA_KEY_CTX *keyCtx, SCOSSL_MLDSAKEY_FORMAT format,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    PSCOSSL_MLDSA_KEY key = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    key = keyCtx->isComposite ?
        (PSCOSSL_MLDSA_KEY)SymCryptCompositeMlDsakeyAllocate(keyCtx->mldsaParams) :
        (PSCOSSL_MLDSA_KEY)SymCryptMlDsakeyAllocate(keyCtx->mldsaParams);
    if (key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = keyCtx->isComposite ?
        SymCryptCompositeMlDsakeySetValue(pbKey, cbKey, format, 0, key) :
        SymCryptMlDsakeySetValue(pbKey, cbKey, format, 0, key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeySetValue failed", scError);
        goto cleanup;
    }

    p_scossl_mldsa_key_free(keyCtx->isComposite, keyCtx->key);

    keyCtx->key = key;
    keyCtx->format = format;
    key = NULL;

    ret = SCOSSL_SUCCESS;

cleanup:
    p_scossl_mldsa_key_free(keyCtx->isComposite, key);

    return ret;
}

static int p_scossl_mldsa_get_bits(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    if (keyCtx->isComposite)
    {
        switch (keyCtx->mldsaParams)
        {
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256:
                return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256 * 8;
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512:
                return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512 * 8;
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512:
                return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512 * 8;
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512:
                return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512 * 8;
            default:
                break;
        }
    }
    else
    {
        switch (keyCtx->mldsaParams)
        {
            case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
                return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44 * 8;
            case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
                return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65 * 8;
            case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
                return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87 * 8;
            default:
                break;
        }
    }

    return 0;
}

static int p_scossl_mldsa_get_security_bits(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    if (keyCtx->isComposite)
    {
        switch (keyCtx->mldsaParams)
        {
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256:
                return 128;
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512:
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512:
                return 192;
            case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512:
                return 256;
            default:
                break;
        }
    }
    else
    {
        switch (keyCtx->mldsaParams)
        {
            case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
                return 128;
            case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
                return 192;
            case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
                return 256;
            default:
                break;
        }
    }

    return 0;
}

static SIZE_T p_scossl_mldsa_get_max_size(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    SIZE_T cbSignature;
    SYMCRYPT_ERROR scError;

    if (keyCtx->isComposite)
    {
        scError = SymCryptCompositeMlDsaSizeofSignatureFromParams(keyCtx->mldsaParams, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptCompositeMlDsaSizeofSignatureFromParams failed", scError);
            return 0;
        }
    }
    else
    {
        scError = SymCryptMlDsaSizeofSignatureFromParams(keyCtx->mldsaParams, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofSignatureFromParams failed", scError);
            return 0;
        }
    }

    return cbSignature;
}

#define IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(alg, isComposite, symcryptParams, paramPrefix)                     \
    static SCOSSL_MLDSA_KEY_CTX                                                                           \
    *p_scossl_##alg##_keymgmt_new_ctx(ossl_unused SCOSSL_PROVCTX *provCtx)                                \
    {                                                                                                     \
        return p_scossl_mldsa_keymgmt_new_ctx(symcryptParams, isComposite);                               \
    }                                                                                                     \
                                                                                                          \
    static SCOSSL_MLDSA_KEYGEN_CTX                                                                        \
    *p_scossl_##alg##_keygen_init(ossl_unused SCOSSL_PROVCTX *provCtx,                                    \
                                  ossl_unused int selection,                                              \
                                  _In_ const OSSL_PARAM params[])                                         \
    {                                                                                                     \
        return p_scossl_mldsa_keygen_init(params, isComposite, symcryptParams);                           \
    }                                                                                                     \
                                                                                                          \
    static const OSSL_PARAM *p_scossl_##alg##_keygen_settable_params(ossl_unused void *provCtx)           \
    {                                                                                                     \
        return paramPrefix##_keygen_settable_param_types;                                                 \
    }                                                                                                     \
                                                                                                          \
    static const OSSL_PARAM *p_scossl_##alg##_keymgmt_settable_params(ossl_unused void *provCtx)          \
    {                                                                                                     \
        return paramPrefix##_keymgmt_settable_param_types;                                                \
    }                                                                                                     \
                                                                                                          \
    static const OSSL_PARAM *p_scossl_##alg##_keymgmt_gettable_params(ossl_unused void *provCtx)          \
    {                                                                                                     \
        return paramPrefix##_keymgmt_gettable_param_types;                                                \
    }                                                                                                     \
                                                                                                          \
    static const OSSL_PARAM *p_scossl_##alg##_keymgmt_impexp_types(ossl_unused int selection)             \
    {                                                                                                     \
        return paramPrefix##_impexp_types;                                                                \
    }                                                                                                     \
                                                                                                          \
    const OSSL_DISPATCH p_scossl_##alg##_keymgmt_functions[] = {                                          \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_##alg##_keymgmt_new_ctx},                        \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mldsa_keymgmt_dup_key_ctx},                      \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                    \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_set_params},             \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_##alg##_keygen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mldsa_keygen_cleanup},                   \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_##alg##_keygen_init},                       \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mldsa_keygen_set_template},         \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mldsa_keygen},                                   \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mldsa_keymgmt_load},                            \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_##alg##_keymgmt_settable_params},    \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_set_params},                \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_##alg##_keymgmt_gettable_params},    \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_get_params},                \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mldsa_keymgmt_has},                              \
        {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))p_scossl_mldsa_keymgmt_validate},                    \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mldsa_keymgmt_match},                          \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_##alg##_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_##alg##_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mldsa_keymgmt_import},                        \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mldsa_keymgmt_export},                        \
        {0, NULL}};

IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa44, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA44, p_scossl_mldsa)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa65, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA65, p_scossl_mldsa)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa87, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA87, p_scossl_mldsa)

IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa44_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa65_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa65_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa87_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512, p_scossl_composite_mldsa)

#ifdef __cplusplus
}
#endif