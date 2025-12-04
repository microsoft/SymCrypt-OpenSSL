//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "signature/p_scossl_mldsa_signature.h"

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLDSA_PRIVATE_SEED_LENGTH 64

typedef struct
{
    SYMCRYPT_MLDSA_PARAMS mldsaParams;
    BYTE pbSeed[SCOSSL_MLDSA_PRIVATE_SEED_LENGTH];
    SIZE_T cbSeed;
} SCOSSL_MLDSA_KEYGEN_CTX;

static const OSSL_PARAM p_scossl_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
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

SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, SYMCRYPT_MLDSAKEY_FORMAT format,
                                                     _Out_writes_bytes_(*pcbKey) PBYTE *ppbKey, _Out_ SIZE_T *pcbKey);

SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, SYMCRYPT_MLDSAKEY_FORMAT format,
                                                     _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);

int p_scossl_mldsa_get_bits(SYMCRYPT_MLDSA_PARAMS mldsaParams);
int p_scossl_mldsa_get_security_bits(SYMCRYPT_MLDSA_PARAMS mlkdsaarams);

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(_In_ SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));
    
    if (keyCtx != NULL)
    {
        keyCtx->mldsaParams = mldsaParams;
    }
    
    return keyCtx;
}

static void p_scossl_mldsa_keymgmt_free_key_ctx(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    if (keyCtx->key != NULL)
    {
        SymCryptMlDsakeyFree(keyCtx->key);
    }

    OPENSSL_free(keyCtx);
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_MLDSAKEY_FORMAT format = SYMCRYPT_MLDSAKEY_FORMAT_NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLDSA_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));

    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    copyCtx->mldsaParams = keyCtx->mldsaParams;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 &&
        keyCtx->key != NULL)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
            keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY)
        {
            format = keyCtx->format;
        }
        else 
        {
            format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
        }

        status = p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, format, &pbKey, &cbKey);
        if (status != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        status = p_scossl_mldsa_keymgmt_set_encoded_key(copyCtx, format, pbKey, cbKey);
        if (status != SCOSSL_SUCCESS)
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

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    PBYTE pbSeed = genCtx->pbSeed;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL &&
        !OSSL_PARAM_get_octet_string(p, (void **)&pbSeed, SCOSSL_MLDSA_PRIVATE_SEED_LENGTH, &genCtx->cbSeed))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mldsa_keygen_settable_params(_In_ ossl_unused void *provCtx)
{
    return p_scossl_mldsa_keygen_settable_param_types;
}

static void p_scossl_mldsa_keygen_cleanup(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx)
{
    OPENSSL_secure_clear_free(genCtx, sizeof(SCOSSL_MLDSA_KEYGEN_CTX));
}

static SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(_In_ const OSSL_PARAM params[], 
                                                           _In_ SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    SCOSSL_MLDSA_KEYGEN_CTX *genCtx = OPENSSL_secure_zalloc(sizeof(SCOSSL_MLDSA_KEYGEN_CTX));
    
    if (genCtx != NULL)
    {
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
    
    if (genCtx->mldsaParams != tmplCtx->mldsaParams)
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

    if ((keyCtx = p_scossl_mldsa_keymgmt_new_ctx(genCtx->mldsaParams)) == NULL ||
        (keyCtx->key = SymCryptMlDsakeyAllocate(genCtx->mldsaParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    
    if (genCtx->cbSeed != 0)
    {
        scError = SymCryptMlDsakeySetValue(
            genCtx->pbSeed,
            genCtx->cbSeed,
            SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
            0,
            keyCtx->key);
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

    keyCtx->format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;

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

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_settable_params(ossl_unused void *provctx)
{
    return p_scossl_mldsa_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(ossl_unused SCOSSL_MLDSA_KEY_CTX *keyCtx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_mldsa_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_key_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *paramEncodedKey = NULL;
    OSSL_PARAM *paramPubKey = NULL;
    OSSL_PARAM *paramPrivKey = NULL;
    OSSL_PARAM *paramPrivateSeed = NULL;

    if (keyCtx->key != NULL)
    {
        paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);

        if (keyCtx->format == SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
            paramPrivateSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        }
        else if (keyCtx->format == SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }
    }

    
    if (paramEncodedKey != NULL || paramPubKey != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get encoded public key");
            goto cleanup;
        }

        if (paramEncodedKey != NULL &&
            !OSSL_PARAM_set_octet_string(paramEncodedKey, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if (paramPubKey != NULL &&
            !OSSL_PARAM_set_octet_string(paramPubKey, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrivKey != NULL)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);

        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get encoded private key");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivKey, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrivateSeed != NULL)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);

        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get private seed");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivateSeed, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mldsa_get_bits(keyCtx->mldsaParams)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mldsa_get_security_bits(keyCtx->mldsaParams)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbSignature;

        scError = SymCryptMlDsaSizeofSignatureFromParams(keyCtx->mldsaParams, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofSignatureFromParams failed", scError);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_size_t(p, cbSignature))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    return p_scossl_mldsa_keymgmt_get_key_params(keyCtx, params);
}

static BOOL p_scossl_mldsa_keymgmt_has(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
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
        keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED &&
        keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL p_scossl_mldsa_keymgmt_match(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx1, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx2,
                                         int selection)
{
    PBYTE pbKey1 = NULL;
    PBYTE pbKey2 = NULL;
    SIZE_T cbKey1 = 0;
    SIZE_T cbKey2 = 0;
    BOOL ret = FALSE;
    SYMCRYPT_MLDSAKEY_FORMAT format;

    if (keyCtx1 == NULL || 
        keyCtx2 == NULL ||
        keyCtx1->mldsaParams != keyCtx2->mldsaParams)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (keyCtx1->key != NULL && keyCtx2->key != NULL)
        {
            if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            {
                format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
            }
            else if (keyCtx1->format != SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY &&
                     keyCtx2->format != SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY)
            {
                format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
            }
            else
            {
                goto cleanup;
            }

            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx1, format, &pbKey1, &cbKey1) != SCOSSL_SUCCESS ||
                p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx2, format, &pbKey2, &cbKey2) != SCOSSL_SUCCESS)
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
        else if (keyCtx1->key != NULL || keyCtx2->key != NULL)
        {
            goto cleanup;
        }
    }

    ret = TRUE;

cleanup:
    OPENSSL_secure_clear_free(pbKey1, cbKey1);
    OPENSSL_secure_clear_free(pbKey2, cbKey2);

    return ret;
}

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_impexp_types(ossl_unused int selection)
{
    return p_scossl_mldsa_impexp_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    PCBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_MLDSAKEY_FORMAT format;
    const OSSL_PARAM *p;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if (keyCtx->key != NULL)
    {
        SymCryptMlDsakeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
        }
        else if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
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

        format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    }

    if (pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_mldsa_keymgmt_set_encoded_key(keyCtx, format, pbKey, cbKey) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_export(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection,
                                                   _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
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
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        switch (keyCtx->format)
        {
        case SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED:
            // Reset pbKey in case it was used for public key export
            OPENSSL_secure_free(pbKey);
            pbKey = NULL;

            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &pbKey, &cbKey) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_ML_DSA_SEED, pbKey, cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }

            __attribute__ ((fallthrough));
        case SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY:
            OPENSSL_secure_clear_free(pbKey, cbKey);
            pbKey = NULL;

            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, pbKey, cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }

            break;
        default:
            break;
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
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

#define IMPLEMENT_SCOSSL_MLDSA(bits)                                                                    \
    static SCOSSL_MLDSA_KEY_CTX                                                                         \
    *p_scossl_mldsa_##bits##_keymgmt_new_ctx(ossl_unused SCOSSL_PROVCTX *provCtx)                       \
    {                                                                                                   \
        return p_scossl_mldsa_keymgmt_new_ctx(SYMCRYPT_MLDSA_PARAMS_MLDSA##bits);                       \
    }                                                                                                   \
                                                                                                        \
    static SCOSSL_MLDSA_KEYGEN_CTX                                                                      \
    *p_scossl_mldsa_##bits##_keygen_init(ossl_unused SCOSSL_PROVCTX *provCtx,                           \
                                         ossl_unused int selection,                                     \
                                         _In_ const OSSL_PARAM params[])                                \
    {                                                                                                   \
        return p_scossl_mldsa_keygen_init(params, SYMCRYPT_MLDSA_PARAMS_MLDSA##bits);                   \
    }                                                                                                   \
                                                                                                        \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_keymgmt_functions[] = {                                  \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_mldsa_##bits##_keymgmt_new_ctx},               \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mldsa_keymgmt_dup_key_ctx},                    \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                  \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mldsa_keygen_cleanup},                 \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_mldsa_##bits##_keygen_init},              \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mldsa_keygen_set_template},       \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mldsa_keygen},                                 \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mldsa_keymgmt_load},                          \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_settable_params},    \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_set_params},              \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_gettable_params},    \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_get_params},              \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mldsa_keymgmt_has},                            \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mldsa_keymgmt_match},                        \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mldsa_keymgmt_import},                      \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mldsa_keymgmt_export},                      \
        {0, NULL}};

IMPLEMENT_SCOSSL_MLDSA(44)
IMPLEMENT_SCOSSL_MLDSA(65)
IMPLEMENT_SCOSSL_MLDSA(87)

//
// Helper functions
//
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(const SCOSSL_MLDSA_KEY_CTX *keyCtx, SYMCRYPT_MLDSAKEY_FORMAT format,
                                                     PBYTE *ppbKey, SIZE_T *pcbKey)
{
    BOOL allocatedKey = FALSE;
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    switch (format)
    {
    case SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED:
        if (keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
            goto cleanup;
        }
        break;
    case SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY:
        if (keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED ||
            keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }
        break;
    case SYMCRYPT_MLDSAKEY_FORMAT_NULL:
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    default:
        break;
    }

    scError = SymCryptMlDsaSizeofKeyFormatFromParams(keyCtx->mldsaParams, format, &cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofKeyFormatFromParams failed", scError);
        goto cleanup;
    }

    if (*ppbKey == NULL)
    {
        // Always using OPENSSL_secure_malloc so caller doesn't have to worry about
        // calling separate free functions for public and private keys.
        if ((pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
        allocatedKey = TRUE;
    }
    else
    {
        if (*pcbKey < cbKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        pbKey = *ppbKey;
    }

    scError = SymCryptMlDsakeyGetValue(keyCtx->key, pbKey, cbKey, format, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeyGetValue failed", scError);
        goto cleanup;
    }

    if (allocatedKey)
    {
        *ppbKey = pbKey;
    }
    *pcbKey = cbKey;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS && allocatedKey)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);
    }
    
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(SCOSSL_MLDSA_KEY_CTX *keyCtx, SYMCRYPT_MLDSAKEY_FORMAT format,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL &&
        (keyCtx->key = SymCryptMlDsakeyAllocate(keyCtx->mldsaParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlDsakeySetValue(pbKey, cbKey, format, 0, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsakeySetValue failed", scError);
        goto cleanup;
    }

    keyCtx->format = format;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS)
    {
        if (keyCtx->key != NULL)
        {
            SymCryptMlDsakeyFree(keyCtx->key);
            keyCtx->key = NULL;
        }
        keyCtx->format = SYMCRYPT_MLDSAKEY_FORMAT_NULL;
    }

    return ret;
}

int p_scossl_mldsa_get_bits(SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    switch (mldsaParams)
    {
        case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
            return 1312;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
            return 1952;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
            return 2592;
        default:
            break;   
    }

    return 0;
}

int p_scossl_mldsa_get_security_bits(SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    switch (mldsaParams)
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

    return 0;
}

#ifdef __cplusplus
}
#endif