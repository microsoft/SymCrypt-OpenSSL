//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "p_scossl_generic_skeymgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_aes_skeymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_skeygen_settable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_END};

static SCOSSL_SKEY *p_scossl_aes_skeymgmt_import(_In_ SCOSSL_PROVCTX *provctx, int selection, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PCBYTE pcbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_SKEY *skey = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
    {
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pcbKey, &cbKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if (pcbKey == NULL || cbKey == 0 ||
        (cbKey != 16 && cbKey != 24 && cbKey != 32))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        goto cleanup;
    }

    skey = p_scossl_generic_skeymgmt_new(provctx->libctx);
    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    skey->pbKey = OPENSSL_secure_malloc(cbKey);
    if (skey->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    skey->type = SCOSSL_SKEY_TYPE_AES;
    skey->cbKey = cbKey;
    memcpy(skey->pbKey, pcbKey, cbKey);

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_generic_skeymgmt_free(skey);
        skey = NULL;
    }

    return skey;
}

static SCOSSL_STATUS p_scossl_aes_skeymgmt_export(_In_ SCOSSL_SKEY *skey, int selection,
                                                  _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    if (skey->type != SCOSSL_SKEY_TYPE_AES)
    {
        return SCOSSL_FAILURE;
    }

    return p_scossl_generic_skeymgmt_export(skey, selection, param_cb, cbarg);
}

static SCOSSL_SKEY *p_scossl_aes_skeygen_generate(_In_ SCOSSL_PROVCTX *provctx, _In_ const OSSL_PARAM params[])
{
   const OSSL_PARAM *p;
    SIZE_T cbKey = 0;
    SCOSSL_SKEY *skey = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if (!OSSL_PARAM_get_size_t(p, &cbKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if (cbKey == 0 ||
        (cbKey != 16 && cbKey != 24 && cbKey != 32))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        goto cleanup;
    }

    skey = p_scossl_generic_skeymgmt_new(provctx->libctx);
    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    skey->pbKey = OPENSSL_secure_malloc(cbKey);
    if (skey->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    skey->type = SCOSSL_SKEY_TYPE_AES;
    skey->cbKey = cbKey;
    SymCryptRandom(skey->pbKey, cbKey);

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_generic_skeymgmt_free(skey);
        skey = NULL;
    }

    return skey;
}

static const OSSL_PARAM *p_scossl_aes_skeymgmt_imp_settable_params(ossl_unused void *provctx)
{
    return p_scossl_aes_skeymgmt_settable_param_types;
}

static const OSSL_PARAM *p_scossl_aes_skeygen_settable_params(ossl_unused void *provctx)
{
    return p_scossl_aes_skeygen_settable_param_types;
}

const OSSL_DISPATCH p_scossl_aes_skeymgmt_functions[] = {
    {OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))p_scossl_generic_skeymgmt_free},
    {OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))p_scossl_aes_skeymgmt_import},
    {OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))p_scossl_aes_skeymgmt_export},
    {OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void))p_scossl_aes_skeygen_generate},
    {OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS, (void (*)(void))p_scossl_aes_skeymgmt_imp_settable_params},
    {OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_aes_skeygen_settable_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif
