//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "kem/p_scossl_mlkem.h"
#include "keymgmt/p_scossl_mlkem_keymgmt.h"
#include "keymgmt/p_scossl_ecc_keymgmt.h"

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLKEM_PKEY_PARAMETER_TYPES                                           \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),           \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                      \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),                     \
    OSSL_PARAM_octet_string(SCOSSL_PKEY_PARAM_CLASSIC_ENCODED_PUBLIC_KEY, NULL, 0), \
    OSSL_PARAM_octet_string(SCOSSL_PKEY_PARAM_CLASSIC_PUB_KEY, NULL, 0),            \
    OSSL_PARAM_octet_string(SCOSSL_PKEY_PARAM_CLASSIC_PRIV_KEY, NULL, 0),           \

static const OSSL_PARAM p_scossl_mlkem_keygen_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(SCOSSL_PKEY_PARAM_CLASSIC_ENCODED_PUBLIC_KEY, NULL, 0),
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

static const SCOSSL_MLKEM_CLASSIC_KEYMGMT_FNS p_scossl_ecc_classic_keymgmt = {
    (OSSL_FUNC_keymgmt_gen_cleanup_fn *)        p_scossl_ecc_keygen_cleanup,
    (OSSL_FUNC_keymgmt_gen_init_fn *)           p_scossl_ecc_keygen_init,
    (OSSL_FUNC_keymgmt_gen_set_template_fn *)   p_scossl_ecc_keygen_set_template,
    (OSSL_FUNC_keymgmt_gen_fn *)                p_scossl_ecc_keygen,
    (OSSL_FUNC_keymgmt_new_fn *)                p_scossl_ecc_keymgmt_new_ctx,
    (OSSL_FUNC_keymgmt_free_fn *)               p_scossl_ecc_keymgmt_free_ctx,
    (OSSL_FUNC_keymgmt_dup_fn *)                p_scossl_ecc_keymgmt_dup_ctx,
    (OSSL_FUNC_keymgmt_get_params_fn *)         p_scossl_ecc_keymgmt_get_params,
    (OSSL_FUNC_keymgmt_set_params_fn *)         p_scossl_ecc_keymgmt_set_params,
    (OSSL_FUNC_keymgmt_has_fn *)                p_scossl_ecc_keymgmt_has,
    (OSSL_FUNC_keymgmt_match_fn *)              p_scossl_ecc_keymgmt_match,
    (OSSL_FUNC_keymgmt_import_fn *)             p_scossl_ecc_keymgmt_import,
    (OSSL_FUNC_keymgmt_export_fn *)             p_scossl_ecc_keymgmt_export,
    (OSSL_FUNC_keymgmt_validate_fn *)           p_scossl_ecc_keymgmt_validate};

static const SCOSSL_MLKEM_CLASSIC_KEYMGMT_FNS p_scossl_x25519_classic_keymgmt = {
    (OSSL_FUNC_keymgmt_gen_cleanup_fn *)        p_scossl_ecc_keygen_cleanup,
    (OSSL_FUNC_keymgmt_gen_init_fn *)           p_scossl_x25519_keygen_init,
    (OSSL_FUNC_keymgmt_gen_set_template_fn *)   p_scossl_ecc_keygen_set_template,
    (OSSL_FUNC_keymgmt_gen_fn *)                p_scossl_ecc_keygen,
    (OSSL_FUNC_keymgmt_new_fn *)                p_scossl_x25519_keymgmt_new_ctx,
    (OSSL_FUNC_keymgmt_free_fn *)               p_scossl_ecc_keymgmt_free_ctx,
    (OSSL_FUNC_keymgmt_dup_fn *)                p_scossl_ecc_keymgmt_dup_ctx,
    (OSSL_FUNC_keymgmt_get_params_fn *)         p_scossl_ecc_keymgmt_get_params,
    (OSSL_FUNC_keymgmt_set_params_fn *)         p_scossl_ecc_keymgmt_set_params,
    (OSSL_FUNC_keymgmt_has_fn *)                p_scossl_ecc_keymgmt_has,
    (OSSL_FUNC_keymgmt_match_fn *)              p_scossl_ecc_keymgmt_match,
    (OSSL_FUNC_keymgmt_import_fn *)             p_scossl_x25519_keymgmt_import,
    (OSSL_FUNC_keymgmt_export_fn *)             p_scossl_x25519_keymgmt_export,
    (OSSL_FUNC_keymgmt_validate_fn *)           p_scossl_ecc_keymgmt_validate};

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_group(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _In_ const char *groupName);
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

    if (keyCtx->classicKeyCtx != NULL)
    {
        keyCtx->classicKeymgmt->free(keyCtx->classicKeyCtx);
    }

    OPENSSL_free(keyCtx);
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->provCtx = keyCtx->provCtx;
        copyCtx->classicKeymgmt = keyCtx->classicKeymgmt;

        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        {
            copyCtx->groupName = keyCtx->groupName;
            copyCtx->mlkemParams = keyCtx->mlkemParams;
            copyCtx->classicGroupName = keyCtx->classicGroupName;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && keyCtx->key != NULL)
        {
            if (copyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
                goto cleanup;
            }

            scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, keyCtx->format, &cbKey);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            if ((copyCtx->key = SymCryptMlKemkeyAllocate(copyCtx->mlkemParams)) == NULL ||
                (pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbKey, cbKey, keyCtx->format, 0);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            scError = SymCryptMlKemkeySetValue(pbKey, cbKey, keyCtx->format, 0, copyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            copyCtx->format = keyCtx->format;
        }

        if (keyCtx->classicKeyCtx != NULL)
        {
            copyCtx->classicKeyCtx = keyCtx->classicKeymgmt->dup(keyCtx->classicKeyCtx, selection);
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

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_params(_Inout_ SCOSSL_MLKEM_KEY_CTX *genCtx, _In_ const OSSL_PARAM params[])
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

        if (p_scossl_mlkem_keymgmt_set_group(genCtx, groupName) != SCOSSL_SUCCESS)
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

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,
                                                        _In_ const OSSL_PARAM params[])
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLKEM_KEY_CTX *genCtx = p_scossl_mlkem_keymgmt_new_ctx(provCtx);

    if (genCtx != NULL)
    {
        status = p_scossl_mlkem_keygen_set_params(genCtx, params);

        if (status == SCOSSL_SUCCESS && genCtx->groupName == NULL)
        {
            status = p_scossl_mlkem_keymgmt_set_group(genCtx, SCOSSL_SN_MLKEM768);
        }
    }

    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_template(_Inout_ SCOSSL_MLKEM_KEY_CTX *genCtx, _In_ SCOSSL_MLKEM_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL ||
        tmplCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (tmplCtx->groupName == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_mlkem_keymgmt_set_group(genCtx, tmplCtx->groupName) != SCOSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen(_In_ SCOSSL_MLKEM_KEY_CTX *genCtx, _In_ OSSL_CALLBACK *cb, _In_ void *cbarg)
{
    PVOID classicKeygenCtx = NULL;
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if ((keyCtx = p_scossl_mlkem_keymgmt_dup_key_ctx(genCtx, OSSL_KEYMGMT_SELECT_ALL)) == NULL ||
        (keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->mlkemParams)) == NULL)
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

    if (keyCtx->classicGroupName != NULL)
    {
        OSSL_PARAM classicParams[2] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)keyCtx->classicGroupName, strlen(keyCtx->classicGroupName)),
            OSSL_PARAM_END};

        classicKeygenCtx = keyCtx->classicKeymgmt->genInit(keyCtx->provCtx, 0, classicParams);
        if (classicKeygenCtx == NULL)
        {
            goto cleanup;
        }

        keyCtx->classicKeyCtx = keyCtx->classicKeymgmt->gen(classicKeygenCtx, cb, cbarg);
        if (keyCtx->classicKeyCtx == NULL)
        {
            goto cleanup;
        }
    }

    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mlkem_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    if (classicKeygenCtx != NULL)
    {
        genCtx->classicKeymgmt->genCleanup(classicKeygenCtx);
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
    PBYTE pbMlKemKey = NULL;
    SIZE_T cbMlKemKey = 0;
    PBYTE pbClassicKey = NULL;
    SIZE_T cbClassicKey = 0;
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    OSSL_PARAM *paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    OSSL_PARAM *paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    OSSL_PARAM classic_params[2] = { OSSL_PARAM_END };

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
        scError = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            &pbMlKemKey, &cbMlKemKey);

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
        OPENSSL_secure_clear_free(pbMlKemKey, cbMlKemKey);
        OPENSSL_secure_clear_free(pbClassicKey, cbClassicKey);
        OPENSSL_secure_clear_free(pbKey, cbKey);

        if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        scError = p_scossl_mlkem_keymgmt_get_encoded_key(
            keyCtx,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            &pbKey, &cbKey);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (keyCtx->classicKeyCtx != NULL)
        {
            classic_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, &pbClassicKey, cbClassicKey);
            if (keyCtx->classicKeymgmt->getParams(keyCtx->classicKeyCtx, classic_params) != SCOSSL_SUCCESS)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                goto cleanup;
            }

            cbKey = cbMlKemKey + cbClassicKey;
            if ((pbKey = OPENSSL_malloc(cbKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(pbKey, pbClassicKey, cbClassicKey);
            memcpy(pbKey + cbClassicKey, pbMlKemKey, cbMlKemKey);
        }
        else
        {
            pbKey = pbMlKemKey;
            cbKey = cbMlKemKey;
            pbMlKemKey = NULL;
            cbMlKemKey = 0;
        }

        if (!OSSL_PARAM_set_octet_string(paramPrivKey, pbKey, cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbMlKemKey, cbMlKemKey);
    OPENSSL_secure_clear_free(pbClassicKey, cbClassicKey);
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_params(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    OSSL_PARAM *p;
    OSSL_PARAM classicParams[2] = { OSSL_PARAM_END };

    if (keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
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
        SIZE_T cbClassicMax;
        SIZE_T cbMax;
        SYMCRYPT_MLKEMKEY_FORMAT format = keyCtx->format;

        // Default to larger size if key data is not set (and therefore format is unknown)
        if (format == SYMCRYPT_MLKEMKEY_FORMAT_NULL)
        {
            format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
        }

        scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, format, &cbMax);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->classicKeyCtx != NULL)
        {
            classicParams[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_MAX_SIZE, &cbClassicMax);
            if (keyCtx->classicKeymgmt->getParams(keyCtx->classicKeyCtx, classicParams) != SCOSSL_SUCCESS)
            {
                return SCOSSL_FAILURE;
            }

            cbMax += cbClassicMax;
        }

        if (!OSSL_PARAM_set_size_t(p, cbMax))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, keyCtx->groupName != NULL ? keyCtx->groupName : ""))
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
        keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
        keyCtx->key == NULL)
    {
        return FALSE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
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
        keyCtx1->mlkemParams != keyCtx2->mlkemParams)
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
    const char *classicGroupName = NULL;

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

        if (p_scossl_mlkem_keymgmt_set_group(keyCtx, keyCtx->groupName) != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }

        if (classicGroupName != NULL)
        {
            OSSL_PARAM classicParams[2] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)classicGroupName, strlen(classicGroupName)),
                OSSL_PARAM_END};

            if (keyCtx->classicKeymgmt->import(keyCtx->classicKeyCtx, selection, classicParams) != SCOSSL_SUCCESS)
            {
                return SCOSSL_FAILURE;
            }
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

    if (keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
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

    mlkemParamsName = keyCtx->groupName != NULL ? keyCtx->groupName : "";
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
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},
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

    if (keyCtx->key == NULL || keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
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

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, format, &cbMlKemKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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

    pbClassicKey = pbKey;
    pbMlKemKey = pbKey + cbClassicKey;

    if (keyCtx->classicKeyCtx != NULL &&
        p_scossl_ecc_get_encoded_key(keyCtx->classicKeyCtx, selection, &pbClassicKey, &cbClassicKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    scError = SymCryptMlKemkeyGetValue(keyCtx->key, pbMlKemKey, cbMlKemKey, format, 0);
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
SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_encoded_key(SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                     PCBYTE pbKey, SIZE_T cbKey)
{
    PCBYTE pbMlKemKey = NULL;
    SIZE_T cbMlKemKey = 0;
    PCBYTE pbClassicKey = NULL;
    SIZE_T cbClassicKey = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL || keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    if (keyCtx->classicKeyCtx != NULL &&
        (cbClassicKey = p_scossl_ecc_get_encoded_key_size(keyCtx->classicKeyCtx, selection)) == 0)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        keyCtx->format = cbKey - cbClassicKey == 64 ? SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED : SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    }
    else
    {
        keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    }

    scError = SymCryptMlKemSizeofKeyFormatFromParams(keyCtx->mlkemParams, keyCtx->format, &cbMlKemKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (cbKey != cbClassicKey + cbMlKemKey)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        goto cleanup;
    }

    pbClassicKey = pbKey;
    pbMlKemKey = pbKey + cbClassicKey;

    if (keyCtx->classicKeyCtx != NULL)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            ret = p_scossl_ecc_set_encoded_key(keyCtx->classicKeyCtx, selection, NULL, 0, pbClassicKey, cbClassicKey);
        }
        else
        {
            ret = p_scossl_ecc_set_encoded_key(keyCtx->classicKeyCtx, selection, pbClassicKey, cbClassicKey, NULL, 0);
        }

        if (ret != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    scError = SymCryptMlKemkeySetValue(pbMlKemKey, cbMlKemKey, keyCtx->format, 0, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
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
static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_group(SCOSSL_MLKEM_KEY_CTX *keyCtx, const char *groupName)
{
    if (OPENSSL_strcasecmp(groupName, SCOSSL_SN_MLKEM512) == 0)
    {
        keyCtx->mlkemParams = SYMCRYPT_MLKEM_PARAMS_MLKEM512;
        keyCtx->classicKeymgmt = NULL;
        keyCtx->classicGroupName = NULL;
    }
    else if (OPENSSL_strcasecmp(groupName, SCOSSL_SN_MLKEM768) == 0)
    {
        keyCtx->mlkemParams = SYMCRYPT_MLKEM_PARAMS_MLKEM768;
        keyCtx->classicKeymgmt = NULL;
        keyCtx->classicGroupName = NULL;
    }
    else if (OPENSSL_strcasecmp(groupName, SCOSSL_SN_MLKEM1024) == 0)
    {
        keyCtx->mlkemParams = SYMCRYPT_MLKEM_PARAMS_MLKEM1024;
        keyCtx->classicKeymgmt = NULL;
        keyCtx->classicGroupName = NULL;
    }
    else if (OPENSSL_strcasecmp(groupName, SCOSSL_SN_P256_MLKEM768) == 0)
    {
        keyCtx->mlkemParams =  SYMCRYPT_MLKEM_PARAMS_MLKEM768;
        keyCtx->classicKeymgmt = &p_scossl_ecc_classic_keymgmt;
        keyCtx->classicGroupName = SN_X9_62_prime256v1;
    }
    else if (OPENSSL_strcasecmp(groupName, SCOSSL_SN_X25519_MLKEM768) == 0)
    {
        keyCtx->mlkemParams =  SYMCRYPT_MLKEM_PARAMS_MLKEM768;
        keyCtx->classicKeymgmt = &p_scossl_x25519_classic_keymgmt;
        keyCtx->classicGroupName = SN_X25519;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
static int p_scossl_mlkem_keymgmt_get_security_bits(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    switch(keyCtx->mlkemParams)
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