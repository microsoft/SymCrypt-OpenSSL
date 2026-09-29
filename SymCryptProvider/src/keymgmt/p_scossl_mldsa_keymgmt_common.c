//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "signature/p_scossl_mldsa_common.h"

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

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

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(const SCOSSL_MLDSA_BACKEND *backend, int params)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));

    if (keyCtx != NULL)
    {
        keyCtx->backend = backend;
        keyCtx->params = params;
        keyCtx->format = backend->formatNull;
    }

    return keyCtx;
}

_Use_decl_annotations_
void p_scossl_mldsa_keymgmt_free_key_ctx(SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    if (keyCtx->key != NULL)
    {
        keyCtx->backend->keyFree(keyCtx->key);
    }

    OPENSSL_free(keyCtx);
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    int format = keyCtx->backend->formatNull;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLDSA_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEY_CTX));

    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    copyCtx->backend = keyCtx->backend;
    copyCtx->params = keyCtx->params;
    copyCtx->format = keyCtx->backend->formatNull;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 &&
        keyCtx->key != NULL)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
            keyCtx->format != keyCtx->backend->formatPublicKey)
        {
            format = keyCtx->format;
        }
        else
        {
            format = keyCtx->backend->formatPublicKey;
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

    OPENSSL_secure_clear_free(pbKey, cbKey);

    return copyCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(SCOSSL_MLDSA_KEYGEN_CTX *genCtx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    // Only families that support the private seed format accept key generation parameters.
    if (!genCtx->backend->supportsSeed)
    {
        return SCOSSL_SUCCESS;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL)
    {
        PBYTE pbSeed = genCtx->abSeed;
        SIZE_T cbSeed = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbSeed, genCtx->backend->cbPrivateSeed, &cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbSeed != genCtx->backend->cbPrivateSeed)
        {
            genCtx->cbSeed = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return SCOSSL_FAILURE;
        }

        genCtx->cbSeed = cbSeed;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
const OSSL_PARAM *p_scossl_mldsa_keygen_settable_params(SCOSSL_MLDSA_KEYGEN_CTX *genCtx, ossl_unused void *provCtx)
{
    return genCtx->backend->keygenSettableParams;
}

_Use_decl_annotations_
void p_scossl_mldsa_keygen_cleanup(SCOSSL_MLDSA_KEYGEN_CTX *genCtx)
{
    if (genCtx == NULL)
        return;

    // The seed is sensitive, so families that support it allocate the context in
    // secure memory and must clear it before freeing.
    if (genCtx->backend->supportsSeed)
    {
        OPENSSL_secure_clear_free(genCtx, sizeof(SCOSSL_MLDSA_KEYGEN_CTX));
    }
    else
    {
        OPENSSL_free(genCtx);
    }
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(const OSSL_PARAM params[], const SCOSSL_MLDSA_BACKEND *backend, int mldsaParams)
{
    SCOSSL_MLDSA_KEYGEN_CTX *genCtx = backend->supportsSeed ?
        OPENSSL_secure_zalloc(sizeof(SCOSSL_MLDSA_KEYGEN_CTX)) :
        OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_KEYGEN_CTX));

    if (genCtx != NULL)
    {
        genCtx->backend = backend;
        genCtx->params = mldsaParams;

        if (p_scossl_mldsa_keygen_set_params(genCtx, params) != SCOSSL_SUCCESS)
        {
            p_scossl_mldsa_keygen_cleanup(genCtx);
            return NULL;
        }
    }

    return genCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keygen_set_template(SCOSSL_MLDSA_KEYGEN_CTX *genCtx, SCOSSL_MLDSA_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL || tmplCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (genCtx->params != tmplCtx->params)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keygen(SCOSSL_MLDSA_KEYGEN_CTX *genCtx,
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

    if ((keyCtx = p_scossl_mldsa_keymgmt_new_ctx(genCtx->backend, genCtx->params)) == NULL ||
        (keyCtx->key = genCtx->backend->keyAllocate(genCtx->params)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (genCtx->backend->supportsSeed && genCtx->cbSeed != 0)
    {
        scError = genCtx->backend->keySetValue(
            genCtx->abSeed,
            genCtx->cbSeed,
            genCtx->backend->formatPrivateSeed,
            0,
            keyCtx->key);

        OPENSSL_cleanse(genCtx->abSeed, genCtx->cbSeed);
        genCtx->cbSeed = 0;

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("keySetValue failed", scError);
            goto cleanup;
        }
    }
    else
    {
        scError = genCtx->backend->keyGenerate(keyCtx->key, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("keyGenerate failed", scError);
            goto cleanup;
        }
    }

    keyCtx->format = genCtx->backend->generatedFormat;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_load(const void *reference, size_t reference_size)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;

    if (reference_size == sizeof(keyCtx))
    {
        keyCtx = *(SCOSSL_MLDSA_KEY_CTX **)reference;
        *(SCOSSL_MLDSA_KEY_CTX **)reference = NULL;
    }

    return keyCtx;
}

_Use_decl_annotations_
const OSSL_PARAM *p_scossl_mldsa_keymgmt_settable_params(ossl_unused void *provctx)
{
    return p_scossl_mldsa_keymgmt_settable_param_types;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(ossl_unused SCOSSL_MLDSA_KEY_CTX *keyCtx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
const OSSL_PARAM *p_scossl_mldsa_keymgmt_gettable_params(ossl_unused void *provctx)
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

        if (keyCtx->backend->supportsSeed &&
            keyCtx->format == keyCtx->backend->formatPrivateSeed)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
            paramPrivateSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        }
        else if (keyCtx->format == keyCtx->backend->formatPrivateKey)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }
    }

    if (paramEncodedKey != NULL || paramPubKey != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPublicKey, &pbKey, &cbKey) != SCOSSL_SUCCESS)
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

        OPENSSL_secure_free(pbKey);
        pbKey = NULL;
        cbKey = 0;
    }

    if (paramPrivKey != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPrivateKey, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get encoded private key");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivKey, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        OPENSSL_secure_clear_free(pbKey, cbKey);
        pbKey = NULL;
        cbKey = 0;
    }

    if (paramPrivateSeed != NULL)
    {
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPrivateSeed, &pbKey, &cbKey) != SCOSSL_SUCCESS)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get private seed");
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivateSeed, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        OPENSSL_secure_clear_free(pbKey, cbKey);
        pbKey = NULL;
        cbKey = 0;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(SCOSSL_MLDSA_KEY_CTX *keyCtx, OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, keyCtx->backend->getBits(keyCtx->params)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, keyCtx->backend->getSecurityBits(keyCtx->params)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbSignature;

        scError = keyCtx->backend->sizeofSignature(keyCtx->params, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("sizeofSignature failed", scError);
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
        keyCtx->format != keyCtx->backend->formatPrivateSeed &&
        keyCtx->format != keyCtx->backend->formatPrivateKey)
    {
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
BOOL p_scossl_mldsa_keymgmt_match(const SCOSSL_MLDSA_KEY_CTX *keyCtx1, const SCOSSL_MLDSA_KEY_CTX *keyCtx2,
                                  int selection)
{
    PBYTE pbKey1 = NULL;
    PBYTE pbKey2 = NULL;
    SIZE_T cbKey1 = 0;
    SIZE_T cbKey2 = 0;
    BOOL ret = FALSE;

    if (keyCtx1 == NULL ||
        keyCtx2 == NULL ||
        keyCtx1->backend != keyCtx2->backend ||
        keyCtx1->params != keyCtx2->params)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (keyCtx1->key != NULL && keyCtx2->key != NULL)
        {
            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx1, keyCtx1->backend->formatPublicKey, &pbKey1, &cbKey1) != SCOSSL_SUCCESS ||
                p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx2, keyCtx2->backend->formatPublicKey, &pbKey2, &cbKey2) != SCOSSL_SUCCESS)
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
const OSSL_PARAM *p_scossl_mldsa_keymgmt_impexp_types(ossl_unused int selection)
{
    return p_scossl_mldsa_impexp_types;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, const OSSL_PARAM params[])
{
    PCBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    int format;
    const OSSL_PARAM *p;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if (keyCtx->key != NULL)
    {
        keyCtx->backend->keyFree(keyCtx->key);
        keyCtx->key = NULL;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (keyCtx->backend->supportsSeed &&
            (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            format = keyCtx->backend->formatPrivateSeed;
        }
        else if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            format = keyCtx->backend->formatPrivateKey;
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

        format = keyCtx->backend->formatPublicKey;
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
        if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPublicKey, &pbPubKey, &cbPubKey) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbPubKey, cbPubKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        // Export the seed alongside the private key when the key was created from
        // one and the family supports it.
        if (keyCtx->backend->supportsSeed &&
            keyCtx->format == keyCtx->backend->formatPrivateSeed)
        {
            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPrivateSeed, &pbSeed, &cbSeed) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_ML_DSA_SEED, pbSeed, cbSeed))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }

        if (keyCtx->format == keyCtx->backend->formatPrivateSeed ||
            keyCtx->format == keyCtx->backend->formatPrivateKey)
        {
            if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->backend->formatPrivateKey, &pbPrivKey, &cbPrivKey) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, pbPrivKey, cbPrivKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
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
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(const SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     PBYTE *ppbKey, SIZE_T *pcbKey)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (keyCtx->backend->supportsSeed && format == keyCtx->backend->formatPrivateSeed)
    {
        if (keyCtx->format != keyCtx->backend->formatPrivateSeed)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
            goto cleanup;
        }
    }
    else if (format == keyCtx->backend->formatPrivateKey)
    {
        if (keyCtx->format != keyCtx->backend->formatPrivateSeed &&
            keyCtx->format != keyCtx->backend->formatPrivateKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }
    }
    else if (format == keyCtx->backend->formatNull)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    scError = keyCtx->backend->sizeofKeyFormat(keyCtx->params, format, &cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("sizeofKeyFormat failed", scError);
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
    else if ((pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = keyCtx->backend->keyGetValue(keyCtx->key, pbKey, cbKey, format, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("keyGetValue failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

    *ppbKey = pbKey;
    *pcbKey = cbKey;

    pbKey = NULL;

cleanup:
    if (*ppbKey == NULL)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL &&
        (keyCtx->key = keyCtx->backend->keyAllocate(keyCtx->params)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = keyCtx->backend->keySetValue(pbKey, cbKey, format, 0, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("keySetValue failed", scError);
        goto cleanup;
    }

    keyCtx->format = format;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS)
    {
        if (keyCtx->key != NULL)
        {
            keyCtx->backend->keyFree(keyCtx->key);
            keyCtx->key = NULL;
        }
        keyCtx->format = keyCtx->backend->formatNull;
    }

    return ret;
}

#ifdef __cplusplus
}
#endif
