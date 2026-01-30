//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mlkem_keymgmt.h"

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLKEM_PRIVATE_SEED_LENGTH 64

// This structure should always be allocated using OPENSSL_secure_malloc
// since it may contain the private seed.
typedef struct {
    SCOSSL_PROVCTX *provCtx;

    SYMCRYPT_MLKEM_PARAMS mlkemParams;

    BYTE abSeed[SCOSSL_MLKEM_PRIVATE_SEED_LENGTH];
    SIZE_T cbSeed;
} SCOSSL_MLKEM_KEYGEN_CTX;

#define SCOSSL_MLKEM_PKEY_PARAMETER_TYPES                                           \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),                     \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                      \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),           \

static const OSSL_PARAM p_scossl_mlkem_keygen_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_impexp_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx, SYMCRYPT_MLKEM_PARAMS mlkemParams)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (keyCtx != NULL)
    {
        keyCtx->provCtx = provCtx;
        keyCtx->mlkemParams = mlkemParams;
    }

    return keyCtx;
}

void p_scossl_mlkem_keymgmt_free_key_ctx(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    if (keyCtx->key != NULL)
    {
        SymCryptMlKemkeyFree(keyCtx->key);
    }
    OPENSSL_free(keyCtx);
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_MLKEMKEY_FORMAT format = SYMCRYPT_MLKEMKEY_FORMAT_NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->provCtx = keyCtx->provCtx;
        copyCtx->mlkemParams = keyCtx->mlkemParams;

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 &&
            keyCtx->key != NULL)
        {
            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
                keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY)
            {
                format = keyCtx->format;
            }
            else
            {
                format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
            }

            scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, format, &cbKey);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
                goto cleanup;
            }

            if ((copyCtx->key = SymCryptMlKemkeyAllocate(copyCtx->mlkemParams)) == NULL ||
                (pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbKey, cbKey, format, 0);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGetValue failed", scError);
                goto cleanup;
            }

            scError = SymCryptMlKemkeySetValue(pbKey, cbKey, format, 0, copyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeySetValue failed", scError);
                goto cleanup;
            }

            copyCtx->format = format;
        }
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(copyCtx);
        copyCtx = NULL;
    }

    OPENSSL_secure_clear_free(pbKey, cbKey);

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_params(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED)) != NULL)
    {
        PBYTE pbSeed = genCtx->abSeed;
        SIZE_T cbSeed;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbSeed, SCOSSL_MLKEM_PRIVATE_SEED_LENGTH, &cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbSeed != SCOSSL_MLKEM_PRIVATE_SEED_LENGTH)
        {
            genCtx->cbSeed = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return SCOSSL_FAILURE;
        }

        genCtx->cbSeed = cbSeed;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mlkem_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keygen_settable_param_types;
}

static void p_scossl_mlkem_keygen_cleanup(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx)
{
    OPENSSL_secure_clear_free(genCtx, sizeof(SCOSSL_MLKEM_KEYGEN_CTX));
}

static SCOSSL_MLKEM_KEYGEN_CTX *p_scossl_mlkem_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,
                                                           _In_ const OSSL_PARAM params[],
                                                           SYMCRYPT_MLKEM_PARAMS mlkemParams)
{
    SCOSSL_MLKEM_KEYGEN_CTX *genCtx = OPENSSL_secure_zalloc(sizeof(SCOSSL_MLKEM_KEYGEN_CTX));

    if (genCtx != NULL)
    {
        genCtx->provCtx = provCtx;
        genCtx->mlkemParams = mlkemParams;
        if (p_scossl_mlkem_keygen_set_params(genCtx, params) != SCOSSL_SUCCESS)
        {
            p_scossl_mlkem_keygen_cleanup(genCtx);
            genCtx = NULL;
        }
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_template(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLKEM_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL || tmplCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (tmplCtx->mlkemParams != genCtx->mlkemParams)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen(_In_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx,
                                                   ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto cleanup;
    }

    if ((keyCtx = p_scossl_mlkem_keymgmt_new_ctx(genCtx->provCtx, genCtx->mlkemParams)) == NULL ||
        (keyCtx->key = SymCryptMlKemkeyAllocate(genCtx->mlkemParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (genCtx->cbSeed != 0)
    {
        scError = SymCryptMlKemkeySetValue(
            genCtx->abSeed,
            genCtx->cbSeed,
            SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
            0,
            keyCtx->key);

        OPENSSL_cleanse(genCtx->abSeed, genCtx->cbSeed);
        genCtx->cbSeed = 0;

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeySetValue failed", scError);
            goto cleanup;
        }
    }
    else
    {
        scError = SymCryptMlKemkeyGenerate(keyCtx->key, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGenerate failed", scError);
            goto cleanup;
        }
    }

    keyCtx->provCtx = genCtx->provCtx;
    keyCtx->mlkemParams = genCtx->mlkemParams;
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static const SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_load(const void *reference, size_t reference_size)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;

    if (reference_size == sizeof(keyCtx))
    {
        keyCtx = *(SCOSSL_MLKEM_KEY_CTX **)reference;
        *(SCOSSL_MLKEM_KEY_CTX **)reference = NULL;
    }

    return keyCtx;
}

static const OSSL_PARAM *p_scossl_mlkem_keymgmt_settable_params(ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_params(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        PCBYTE pbKey;
        SIZE_T cbKey;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, pbKey, cbKey) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mlkem_keymgmt_gettable_params(ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_key_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_STATUS status;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *paramEncodedKey = NULL;
    OSSL_PARAM *paramPubKey = NULL;
    OSSL_PARAM *paramPrivKey = NULL;
    OSSL_PARAM *paramPrivateSeed = NULL;

    if (keyCtx->key != NULL)
    {
        paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);

        if (keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
            paramPrivateSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
        }
        else if (keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }

        if (paramEncodedKey != NULL || paramPubKey != NULL)
        {
            status = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                &pbKey, &cbKey);
            if (status != SCOSSL_SUCCESS)
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
            status = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
                &pbKey, &cbKey);
            if (status != SCOSSL_SUCCESS)
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
            status = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
                &pbKey, &cbKey);
            if (status != SCOSSL_SUCCESS)
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
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mlkem_get_bits(keyCtx->mlkemParams)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mlkem_get_security_bits(keyCtx->mlkemParams)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbCiphertext;

        scError = SymCryptMlKemSizeofCiphertextFromParams(keyCtx->mlkemParams, &cbCiphertext);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_size_t(p, cbCiphertext))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return p_scossl_mlkem_keymgmt_get_key_params(keyCtx, params);
}

static BOOL p_scossl_mlkem_keymgmt_has(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection)
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
        keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED &&
        keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL p_scossl_mlkem_keymgmt_match(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx1, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx2,
                                         int selection)
{
    PBYTE pbKey1 = NULL;
    PBYTE pbKey2 = NULL;
    SIZE_T cbKey1 = 0;
    SIZE_T cbKey2 = 0;
    BOOL ret = FALSE;
    SCOSSL_STATUS success;

    if (keyCtx1 == NULL ||
        keyCtx2 == NULL ||
        keyCtx1->mlkemParams != keyCtx2->mlkemParams)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (keyCtx1->key != NULL && keyCtx2->key != NULL)
        {
            success = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx1,
                SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                &pbKey1, &cbKey1);
            if (!success)
            {
                goto cleanup;
            }

            success = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx2,
                SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                &pbKey2, &cbKey2);
            if (!success)
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

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_mlkem_keymgmt_impexp_types(ossl_unused int selection)
{
    return p_scossl_mlkem_impexp_types;
}

SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    PCBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_MLKEMKEY_FORMAT format;
    const OSSL_PARAM *p;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if (keyCtx->key != NULL)
    {
        SymCryptMlKemkeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
        }
        else if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
        }
    }

    // Only try encapsulation key import if private key was not available
    if (pbKey == NULL)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL &&
            !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    }

    if (pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, format, pbKey, cbKey) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
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
        ret = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx,
            SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
            &pbKey, &cbKey);

        if (ret != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        OPENSSL_secure_free(pbKey);
        pbKey = NULL;
        cbKey = 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        switch (keyCtx->format)
        {
        case SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED:
            ret = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx,
                SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
                &pbKey, &cbKey);

            if (ret != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_ML_KEM_SEED, pbKey, cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }

            OPENSSL_secure_clear_free(pbKey, cbKey);
            pbKey = NULL;
            cbKey = 0;
            /* fall through */
        case SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY:
            ret = p_scossl_mlkem_keymgmt_get_encoded_key(
                keyCtx,
                SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
                &pbKey, &cbKey);

            if (ret != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, pbKey, cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }

            OPENSSL_secure_clear_free(pbKey, cbKey);
            pbKey = NULL;
            cbKey = 0;
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

#define IMPLEMENT_SCOSSL_MLKEM(bits)                                                                    \
    static SCOSSL_MLKEM_KEY_CTX                                                                         \
    *p_scossl_mlkem_##bits##_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx)                              \
    {                                                                                                   \
        return p_scossl_mlkem_keymgmt_new_ctx(provCtx, SYMCRYPT_MLKEM_PARAMS_MLKEM##bits);              \
    }                                                                                                   \
                                                                                                        \
    static SCOSSL_MLKEM_KEYGEN_CTX                                                                      \
    *p_scossl_mlkem_##bits##_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,       \
                                         _In_ const OSSL_PARAM params[])                                \
    {                                                                                                   \
        return p_scossl_mlkem_keygen_init(provCtx, selection, params,                                   \
            SYMCRYPT_MLKEM_PARAMS_MLKEM##bits);                                                         \
    }                                                                                                   \
                                                                                                        \
    const OSSL_DISPATCH p_scossl_mlkem##bits##_keymgmt_functions[] = {                                  \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_mlkem_##bits##_keymgmt_new_ctx},               \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mlkem_keymgmt_dup_key_ctx},                    \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},                  \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mlkem_keygen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keygen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mlkem_keygen_cleanup},                 \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_mlkem_##bits##_keygen_init},              \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mlkem_keygen_set_template},       \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mlkem_keygen},                                 \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mlkem_keymgmt_load},                          \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_settable_params},    \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_set_params},              \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_gettable_params},    \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_get_params},              \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mlkem_keymgmt_has},                            \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mlkem_keymgmt_match},                        \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mlkem_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mlkem_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mlkem_keymgmt_import},                      \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mlkem_keymgmt_export},                      \
        {0, NULL}};

IMPLEMENT_SCOSSL_MLKEM(512)
IMPLEMENT_SCOSSL_MLKEM(768)
IMPLEMENT_SCOSSL_MLKEM(1024)

//
// Helper functions
//
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_encoded_key(const SCOSSL_MLKEM_KEY_CTX *keyCtx, SYMCRYPT_MLKEMKEY_FORMAT format,
                                                     PBYTE *ppbKey, SIZE_T *pcbKey)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    switch (format)
    {
    case SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED:
        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
            goto cleanup;
        }
        break;
    case SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY:
        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED &&
            keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }
        break;
    case SYMCRYPT_MLKEMKEY_FORMAT_NULL:
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    default:
        break;
    }

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, format, &cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
        goto cleanup;
    }

    // Always using OPENSSL_secure_malloc so caller doesn't have to worry about
    // calling separate free functions for encapsulation and decapsulation keys
    if ((pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbKey, cbKey, format, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGetValue failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

    *ppbKey = pbKey;
    *pcbKey = cbKey;

cleanup:
    if (ret != SCOSSL_SUCCESS)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);
    }

    return ret;
}

// Sets the key in keyCtx to the encoded key bytes in pbKey. The key type is indicated by selection.
// If this is a private key, and the ML-KEM portion is 64 bytes, then the ML-KEM portion is
// decoded as a private seed. If keyCtx->key is NULL, then a new key is allocated. Otherwise,
// the existing key data in keyCtx->key is overwritten by the new data.
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_encoded_key(SCOSSL_MLKEM_KEY_CTX *keyCtx, SYMCRYPT_MLKEMKEY_FORMAT format,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL &&
        (keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->mlkemParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeySetValue(pbKey, cbKey, format, 0, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeySetValue failed", scError);
        goto cleanup;
    }

    keyCtx->format = format;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS)
    {
        SymCryptMlKemkeyFree(keyCtx->key);
        keyCtx->key = NULL;
        keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_NULL;
    }

    return ret;
}

#ifdef __cplusplus
}
#endif