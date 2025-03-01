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

typedef struct {
    SCOSSL_PROVCTX *provCtx;

    const SCOSSL_MLKEM_GROUP_INFO *groupInfo;
} SCOSSL_MLKEM_KEYGEN_CTX;

#define SCOSSL_MLKEM_PKEY_PARAMETER_TYPES                                           \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),           \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                      \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),                     \

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

static int p_scossl_mlkem_keymgmt_get_security_bits(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx);

SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (keyCtx != NULL)
    {
        keyCtx->provCtx = provCtx;
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

    p_scossl_ecc_free_ctx(keyCtx->classicKeyCtx);
    OPENSSL_free(keyCtx);
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->provCtx = keyCtx->provCtx;

        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        {
            copyCtx->groupInfo = keyCtx->groupInfo;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        {
            if (keyCtx->key != NULL)
            {
                if (copyCtx->groupInfo == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
                    goto cleanup;
                }

                scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->groupInfo->mlkemParams, keyCtx->format, &cbKey);
                if (scError != SYMCRYPT_NO_ERROR)
                {
                    SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
                    goto cleanup;
                }

                if ((copyCtx->key = SymCryptMlKemkeyAllocate(copyCtx->groupInfo->mlkemParams)) == NULL ||
                    (pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    goto cleanup;
                }

                scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbKey, cbKey, keyCtx->format, 0);
                if (scError != SYMCRYPT_NO_ERROR)
                {
                    SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGetValue failed", scError);
                    goto cleanup;
                }

                scError = SymCryptMlKemkeySetValue(pbKey, cbKey, keyCtx->format, 0, copyCtx->key);
                if (scError != SYMCRYPT_NO_ERROR)
                {
                    SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeySetValue failed", scError);
                    goto cleanup;
                }

                copyCtx->format = keyCtx->format;
            }

            if (keyCtx->classicKeyCtx != NULL)
            {
                copyCtx->classicKeyCtx = p_scossl_ecc_dup_ctx(keyCtx->classicKeyCtx, selection);
            }
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
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *groupName;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &groupName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((genCtx->groupInfo = p_scossl_mlkem_get_group_info(groupName)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
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

static SCOSSL_MLKEM_KEYGEN_CTX *p_scossl_mlkem_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,
                                                        _In_ const OSSL_PARAM params[])
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEYGEN_CTX *genCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEYGEN_CTX));

    if (genCtx != NULL)
    {
        genCtx->provCtx = provCtx;
        status = p_scossl_mlkem_keygen_set_params(genCtx, params);

        if (status == SCOSSL_SUCCESS && genCtx->groupInfo == NULL)
        {
            genCtx->groupInfo = p_scossl_mlkem_get_group_info(SCOSSL_SN_MLKEM768);
        }
    }

    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keygen_cleanup(genCtx);
        genCtx = NULL;
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

    if (tmplCtx->groupInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    genCtx->groupInfo = tmplCtx->groupInfo;

    return SCOSSL_SUCCESS;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen(_In_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((keyCtx = p_scossl_mlkem_keymgmt_new_ctx(genCtx->provCtx)) == NULL ||
        (keyCtx->key = SymCryptMlKemkeyAllocate(genCtx->groupInfo->mlkemParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeyGenerate(keyCtx->key, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGenerate failed", scError);
        goto cleanup;
    }

    if (genCtx->groupInfo->classicGroupName != NULL)
    {
        if ((keyCtx->classicKeyCtx = p_scossl_ecc_new_ctx(keyCtx->provCtx)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (p_scossl_ecc_set_group(keyCtx->classicKeyCtx, genCtx->groupInfo->classicGroupName) != SCOSSL_SUCCESS ||
            p_scossl_ecc_gen(keyCtx->classicKeyCtx) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    keyCtx->provCtx = genCtx->provCtx;
    keyCtx->groupInfo = genCtx->groupInfo;
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        if (keyCtx != NULL)
        {
            p_scossl_ecc_free_ctx(keyCtx->classicKeyCtx);
        }

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

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
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

        if (p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pbKey, cbKey) != SCOSSL_SUCCESS)
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
    OSSL_PARAM *paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    OSSL_PARAM *paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    OSSL_PARAM *paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

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
        status = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
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
    }

    if (paramPrivKey != NULL)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);

        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        status = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
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

    if (keyCtx->groupInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_mlkem_keymgmt_get_security_bits(keyCtx)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        SIZE_T cbMax;
        SYMCRYPT_MLKEMKEY_FORMAT format = keyCtx->format;

        // Default to larger size if key data is not set (and therefore format is unknown)
        if (format == SYMCRYPT_MLKEMKEY_FORMAT_NULL)
        {
            format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
        }

        scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->groupInfo->mlkemParams, format, &cbMax);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->classicKeyCtx != NULL)
        {
            cbMax += p_scossl_ecc_get_max_size(keyCtx->classicKeyCtx, TRUE);
        }

        if (!OSSL_PARAM_set_size_t(p, cbMax))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, keyCtx->groupInfo->snGroupName != NULL ? keyCtx->groupInfo->snGroupName : ""))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
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
        keyCtx->groupInfo == NULL)
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

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 &&
        keyCtx1->groupInfo != keyCtx2->groupInfo)
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

                success = p_scossl_mlkem_keymgmt_get_encoded_key(
                    keyCtx1,
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    &pbKey1, &cbKey1);
                if (!success)
                {
                    goto cleanup;
                }

                success = p_scossl_mlkem_keymgmt_get_encoded_key(
                    keyCtx2,
                    OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
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
                success = p_scossl_mlkem_keymgmt_get_encoded_key(
                    keyCtx1,
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                    &pbKey1, &cbKey1);
                if (!success)
                {
                    goto cleanup;
                }

                success = p_scossl_mlkem_keymgmt_get_encoded_key(
                    keyCtx2,
                    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
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

SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PCBYTE pbKey;
    SIZE_T cbKey;

    // Domain parameters are required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *groupName;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &groupName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((keyCtx->groupInfo = p_scossl_mlkem_get_group_info(groupName)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->classicKeyCtx != NULL &&
            keyCtx->groupInfo->classicGroupName != NULL &&
            p_scossl_ecc_set_group(keyCtx->classicKeyCtx, keyCtx->groupInfo->classicGroupName) != SCOSSL_SUCCESS)
        {
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
        }

        if (p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, selection, pbKey, cbKey) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
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

    if (keyCtx->groupInfo == NULL)
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

    mlkemParamsName = keyCtx->groupInfo->snGroupName != NULL ? keyCtx->groupInfo->snGroupName : "";
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, mlkemParamsName, strlen(mlkemParamsName)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        ret = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
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

        ret = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
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
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mlkem_keymgmt_load},
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
SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_encoded_key(const SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                     PBYTE *ppbKey, SIZE_T *pcbKey)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    PBYTE pbMlKemKey = NULL;
    SIZE_T cbMlKemKey = 0;
    PBYTE pbClassicKey = NULL;
    SIZE_T cbClassicKey = 0;
    SYMCRYPT_MLKEMKEY_FORMAT format;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL || keyCtx->groupInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_NULL ||
            keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            return SCOSSL_FAILURE;
        }

        format = keyCtx->format;
    }
    else
    {
        format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    }

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->groupInfo->mlkemParams, format, &cbMlKemKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL &&
        (cbClassicKey = p_scossl_ecc_get_encoded_key_size(keyCtx->classicKeyCtx, selection)) == 0)
    {
        goto cleanup;
    }

    cbKey = cbMlKemKey + cbClassicKey;

    // Always using OPENSSL_secure_malloc so caller doesn't have to worry about
    // calling separate free functions for encapsulation and decapsulation keys
    if ((pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL &&
        keyCtx->classicKeyCtx->isX25519)
    {
        pbMlKemKey = pbKey;
        pbClassicKey = pbKey + cbMlKemKey;
    }
    else
    {
        pbClassicKey = pbKey;
        pbMlKemKey = pbKey + cbClassicKey;
    }

    scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbMlKemKey, cbMlKemKey, format, 0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeyGetValue failed", scError);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL &&
        p_scossl_ecc_get_encoded_key(keyCtx->classicKeyCtx, selection, &pbClassicKey, &cbClassicKey) != SCOSSL_SUCCESS)
    {
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
SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_encoded_key(SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    PCBYTE pbMlKemKey = NULL;
    SIZE_T cbMlKemKey = 0;
    PCBYTE pbClassicKey = NULL;
    SIZE_T cbClassicKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->groupInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    if (keyCtx->key == NULL &&
        (keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->groupInfo->mlkemParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (keyCtx->groupInfo->classicGroupName != NULL)
    {
        if (keyCtx->classicKeyCtx == NULL &&
            (keyCtx->classicKeyCtx = p_scossl_ecc_new_ctx(keyCtx->provCtx)) == NULL)
        {
            goto cleanup;
        }

        if (p_scossl_ecc_set_group(keyCtx->classicKeyCtx, keyCtx->groupInfo->classicGroupName) != SCOSSL_SUCCESS ||
            (cbClassicKey = p_scossl_ecc_get_encoded_key_size(keyCtx->classicKeyCtx, selection)) == 0)
        {
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        keyCtx->format = cbKey - cbClassicKey == 64 ? SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED : SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    }
    else
    {
        keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    }

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->groupInfo->mlkemParams, keyCtx->format, &cbMlKemKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofKeyFormatFromParams failed", scError);
        goto cleanup;
    }

    if (cbKey != cbClassicKey + cbMlKemKey)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL &&
        keyCtx->classicKeyCtx->isX25519)
    {
        pbMlKemKey = pbKey;
        pbClassicKey = pbKey + cbMlKemKey;
    }
    else
    {
        pbClassicKey = pbKey;
        pbMlKemKey = pbKey + cbClassicKey;
    }

    scError = SymCryptMlKemkeySetValue(pbMlKemKey, cbMlKemKey, keyCtx->format, 0, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemkeySetValue failed", scError);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            ret = p_scossl_ecc_set_encoded_key(keyCtx->classicKeyCtx, NULL, 0, pbClassicKey, cbClassicKey);
        }
        else
        {
            ret = p_scossl_ecc_set_encoded_key(keyCtx->classicKeyCtx, pbClassicKey, cbClassicKey, NULL, 0);
        }

        if (ret != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

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

_Use_decl_annotations_
static int p_scossl_mlkem_keymgmt_get_security_bits(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    if (keyCtx->groupInfo != NULL)
    {
        switch(keyCtx->groupInfo->mlkemParams)
        {
        case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
            return 128;
        case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
            return 192;
        case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
            return 256;
        default:
            break;
        }
    }

    ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
    return 0;
}

#ifdef __cplusplus
}
#endif