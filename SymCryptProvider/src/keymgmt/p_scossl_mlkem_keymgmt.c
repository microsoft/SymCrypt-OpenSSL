//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kem/p_scossl_mlkem.h"

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLKEM_PARAM_NAME_512 "mlkem512"
#define SCOSSL_MLKEM_PARAM_NAME_768 "mlkem768"
#define SCOSSL_MLKEM_PARAM_NAME_1024 "mlkem1024"

typedef struct {
    SYMCRYPT_MLKEM_PARAMS params;
} SCOSSL_MLKEM_KEYGEN_CTX;

#define SCOSSL_MLKEM_PKEY_PARAMETER_TYPES                                 \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0), \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),            \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),

static const OSSL_PARAM p_scossl_mlkem_keygen_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    SCOSSL_MLKEM_PKEY_PARAMETER_TYPES
    OSSL_PARAM_END};

// Import/export types
static const OSSL_PARAM p_scossl_mlkem_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_pkey_types[] = {
    SCOSSL_MLKEM_PKEY_PARAMETER_TYPES
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_all_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    SCOSSL_MLKEM_PKEY_PARAMETER_TYPES
    OSSL_PARAM_END};

static const OSSL_PARAM *p_scossl_mlkem_impexp_types[] = {
    NULL,
    p_scossl_mlkem_param_types,
    p_scossl_mlkem_pkey_types,
    p_scossl_mlkem_all_types};

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_key_bytes(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                          SYMCRYPT_MLKEMKEY_FORMAT format,
                                                          _Out_writes_bytes_(*cbKey) PBYTE *ppbKey, _Out_ SIZE_T *pcbKey);

static SYMCRYPT_MLKEM_PARAMS p_scossl_mlkem_keymgmt_params_from_name(_In_ const char *name);
static const char * p_scossl_mlkem_keymgmt_params_to_name(_In_ const SYMCRYPT_MLKEM_PARAMS name);
static int p_scossl_mlkem_keymgmt_get_security_bits(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx);

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(ossl_unused void *provCtx)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));;
}

static void p_scossl_mlkem_keymgmt_free_key_ctx(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx)
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
    SYMCRYPT_MLKEMKEY_FORMAT format;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (copyCtx != NULL)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        {
            copyCtx->params = keyCtx->params;
        }
        else
        {
            copyCtx->params = SYMCRYPT_MLKEM_PARAMS_NULL;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && keyCtx->key != NULL)
        {
            if (copyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
                goto cleanup;
            }

            if ((copyCtx->key = SymCryptMlKemkeyAllocate(copyCtx->params)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            {
                format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
            }
            else
            {
                format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
            }

            ret = p_scossl_mlkem_keymgmt_get_key_bytes(
                keyCtx,
                format,
                &pbKey, &cbKey);

            if (ret != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            scError = SymCryptMlKemkeySetValue(
                pbKey, cbKey,
                format,
                0,
                copyCtx->key);

            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            copyCtx->format = format;
        }
        else
        {
            copyCtx->key = NULL;
            copyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_NULL;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:

    if (ret != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(copyCtx);
        copyCtx = NULL;
    }

    OPENSSL_secure_clear_free(pbKey, cbKey);

    return copyCtx;
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_mlkem_keygen_set_params(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *name;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &name))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((genCtx->params = p_scossl_mlkem_keymgmt_params_from_name(name)) == SYMCRYPT_MLKEM_PARAMS_NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;;
}

static const OSSL_PARAM *p_scossl_mlkem_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keygen_settable_param_types;
}

static void p_scossl_mlkem_keygen_cleanup(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx)
{
    OPENSSL_free(genCtx);
}

static SCOSSL_MLKEM_KEYGEN_CTX *p_scossl_mlkem_keygen_init(ossl_unused void *provCtx, ossl_unused int selection,
                                                           _In_ const OSSL_PARAM params[])
{
    SCOSSL_MLKEM_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEYGEN_CTX));

    if (genCtx != NULL)
    {
        genCtx->params = SYMCRYPT_MLKEM_PARAMS_MLKEM768;

        if (p_scossl_mlkem_keygen_set_params(genCtx, params) != SCOSSL_SUCCESS)
        {
            OPENSSL_free(genCtx);
            return NULL;
        }
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_template(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLKEM_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL ||
        tmplCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (tmplCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    genCtx->params = tmplCtx->params;

    return SCOSSL_SUCCESS;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen(_In_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    BOOL success = FALSE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_MLKEM_KEY_CTX *keyCtx;

    if ((keyCtx = p_scossl_mlkem_keymgmt_new_ctx(NULL)) == NULL ||
        (keyCtx->key = SymCryptMlKemkeyAllocate(genCtx->params)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeyGenerate(keyCtx->key, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    keyCtx->params = genCtx->params;
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;

    success = TRUE;

cleanup:
    if (!success)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static const OSSL_PARAM *p_scossl_mlkem_keymgmt_settable_params(ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        PCBYTE pbKey;
        SIZE_T cbKey;

        if (keyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->key != NULL)
        {
            SymCryptMlKemkeyFree(keyCtx->key);
        }

        if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->params)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptMlKemkeySetValue(
            pbKey, cbKey,
            SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
            0,
            keyCtx->key);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SymCryptMlKemkeyFree(keyCtx->key);
            keyCtx->key = NULL;
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }

        keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
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
    OSSL_PARAM *paramEncodedKey;
    OSSL_PARAM *paramPubKey;
    OSSL_PARAM *paramPrivKey;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (keyCtx->key == NULL &&
        (paramEncodedKey != NULL ||
         paramPubKey != NULL ||
         paramPrivKey != NULL))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (paramEncodedKey != NULL || paramPubKey != NULL)
    {
        scError = p_scossl_mlkem_keymgmt_get_key_bytes(
            keyCtx,
            SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
            &pbKey, &cbKey);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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
        // Reset pbKey in case it was used for encapsulation key
        OPENSSL_secure_clear_free(pbKey, cbKey);

        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        scError = p_scossl_mlkem_keymgmt_get_key_bytes(
            keyCtx,
            SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
            &pbKey, &cbKey);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivKey, pbKey, cbKey))
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

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    OSSL_PARAM *p;

    if (keyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mlkem_keymgmt_get_security_bits(keyCtx)))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbSize;
        SYMCRYPT_MLKEMKEY_FORMAT format = keyCtx->format;

        // Default to larger size if key data is not set (and therefore format is unknown)
        if (format == SYMCRYPT_MLKEMKEY_FORMAT_NULL)
        {
            format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
        }

        scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->params, format, &cbSize);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_size_t(p, cbSize))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, p_scossl_mlkem_keymgmt_params_to_name(keyCtx->params)))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mlkem_keymgmt_get_key_params(keyCtx, params);
}


static BOOL p_scossl_mlkem_keymgmt_has(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection)
{
    if (keyCtx == NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 &&
        keyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
        keyCtx->key == NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
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

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 &&
        keyCtx1->params != keyCtx2->params)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
    {
        if (keyCtx1->key != NULL || keyCtx2->key != NULL)
        {
            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            {
                // Both keys must be decapsulation keys to compare
                if (keyCtx1->format != keyCtx2->format)
                {
                    goto cleanup;
                }

                // Reset pbKeys in case they was used for encapsulation key compare
                OPENSSL_secure_clear_free(pbKey1, cbKey1);
                OPENSSL_secure_clear_free(pbKey2, cbKey2);

                success = p_scossl_mlkem_keymgmt_get_key_bytes(
                    keyCtx1,
                    SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
                    &pbKey1, &cbKey1);
                if (!success)
                {
                    goto cleanup;
                }

                success = p_scossl_mlkem_keymgmt_get_key_bytes(
                    keyCtx2,
                    SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
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

            if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            {
                success = p_scossl_mlkem_keymgmt_get_key_bytes(
                    keyCtx1,
                    SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                    &pbKey1, &cbKey1);
                if (!success)
                {
                    goto cleanup;
                }

                success = p_scossl_mlkem_keymgmt_get_key_bytes(
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
        }
    }

    ret = TRUE;

cleanup:
    OPENSSL_secure_clear_free(pbKey1, cbKey1);
    OPENSSL_secure_clear_free(pbKey2, cbKey2);

    return ret;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_mlkem_keymgmt_impexp_types(int selection)
{
    int idx = 0;
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
    {
        idx += 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        idx += 2;
    }

    return p_scossl_mlkem_impexp_types[idx];
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PCBYTE pbKey;
    SIZE_T cbKey;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    // Domain parameters are required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *name;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &name))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((keyCtx->params = p_scossl_mlkem_keymgmt_params_from_name(name)) == SYMCRYPT_MLKEM_PARAMS_NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (keyCtx->key != NULL)
        {
            SymCryptMlKemkeyFree(keyCtx->key);
            keyCtx->key = NULL;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
            (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
        }
        else
        {
            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) == NULL &&
                (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
        }

        if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->params)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptMlKemkeySetValue(
            pbKey, cbKey,
            keyCtx->format,
            0,
            keyCtx->key);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SymCryptMlKemkeyFree(keyCtx->key);
            keyCtx->key = NULL;
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                   _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    const char *mlkemParamsName;
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Domain parameters are required for export
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        goto cleanup;
    }

    if (keyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 &&
        keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    if ((bld = OSSL_PARAM_BLD_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    mlkemParamsName = p_scossl_mlkem_keymgmt_params_to_name(keyCtx->params);
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, mlkemParamsName, sizeof(mlkemParamsName)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        ret = p_scossl_mlkem_keymgmt_get_key_bytes(
            keyCtx,
            SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
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
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        // Reset pbKey in case it was used for encapsulation key export
        OPENSSL_secure_clear_free(pbKey, cbKey);

        ret = p_scossl_mlkem_keymgmt_get_key_bytes(
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
    }

    ret = param_cb(params, cbarg);

cleanup:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

const OSSL_DISPATCH p_scossl_mlkem_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_mlkem_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mlkem_keymgmt_dup_key_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mlkem_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mlkem_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_mlkem_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mlkem_keygen_set_template},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mlkem_keygen},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mlkem_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mlkem_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mlkem_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mlkem_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mlkem_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mlkem_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mlkem_keymgmt_export},
    {0, NULL}};

//
// Helper functions
//

_Use_decl_annotations_
static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_key_bytes(const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                          SYMCRYPT_MLKEMKEY_FORMAT format,
                                                          PBYTE *ppbKey, SIZE_T *pcbKey)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL || keyCtx->params == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->params, format, &cbKey);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
static SYMCRYPT_MLKEM_PARAMS p_scossl_mlkem_keymgmt_params_from_name(const char *name)
{
    if (OPENSSL_strcasecmp(name, SCOSSL_MLKEM_PARAM_NAME_512) == 0)
    {
        return SYMCRYPT_MLKEM_PARAMS_MLKEM512;
    }
    else if (OPENSSL_strcasecmp(name, SCOSSL_MLKEM_PARAM_NAME_768) == 0)
    {
        return SYMCRYPT_MLKEM_PARAMS_MLKEM512;
    }
    else if (OPENSSL_strcasecmp(name, SCOSSL_MLKEM_PARAM_NAME_1024) == 0)
    {
        return SYMCRYPT_MLKEM_PARAMS_MLKEM512;
    }

    return SYMCRYPT_MLKEM_PARAMS_NULL;
}

_Use_decl_annotations_
static const char *p_scossl_mlkem_keymgmt_params_to_name(const SYMCRYPT_MLKEM_PARAMS params)
{
    switch (params)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        return SCOSSL_MLKEM_PARAM_NAME_512;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        return SCOSSL_MLKEM_PARAM_NAME_768;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        return SCOSSL_MLKEM_PARAM_NAME_1024;\
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        break;
    }

    return "";
}

_Use_decl_annotations_
static int p_scossl_mlkem_keymgmt_get_security_bits(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    switch(keyCtx->params)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        return 128;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        return 192;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        return 256;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        break;
    }

    return 0;
}


#ifdef __cplusplus
}
#endif