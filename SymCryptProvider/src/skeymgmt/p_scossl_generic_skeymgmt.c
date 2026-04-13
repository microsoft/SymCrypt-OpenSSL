//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "p_scossl_generic_skeymgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_generic_skeymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_generic_skeygen_settable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_END};

_Use_decl_annotations_
SCOSSL_SKEY *p_scossl_generic_skeymgmt_new(OSSL_LIB_CTX *libctx)
{
    SCOSSL_SKEY *skey = OPENSSL_zalloc(sizeof(SCOSSL_SKEY));
    if (skey != NULL)
    {
        skey->libctx = libctx;
        skey->type = SCOSSL_SKEY_TYPE_GENERIC;
    }

    return skey;
}

_Use_decl_annotations_
void p_scossl_generic_skeymgmt_free(SCOSSL_SKEY *skey)
{
    if (skey == NULL)
        return;

    OPENSSL_secure_clear_free(skey->pbKey, skey->cbKey);
    OPENSSL_free(skey);
}

SCOSSL_SKEY *p_scossl_generic_skeymgmt_import(_In_ SCOSSL_PROVCTX *provctx, int selection, _In_ const OSSL_PARAM params[])
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

    skey = p_scossl_generic_skeymgmt_new(provctx->libctx);
    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (cbKey > 0)
    {
        skey->pbKey = OPENSSL_secure_malloc(cbKey);
        if (skey->pbKey == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
        memcpy(skey->pbKey, pcbKey, cbKey);
    }

    skey->cbKey = cbKey;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_generic_skeymgmt_free(skey);
        skey = NULL;
    }

    return skey;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_generic_skeymgmt_export(SCOSSL_SKEY *skey, int selection,
                                               OSSL_CALLBACK *param_cb, void *cbarg)
{
    OSSL_PARAM params[2];

    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
    {
        return SCOSSL_FAILURE;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, skey->cbKey > 0 ? skey->pbKey : "", skey->cbKey);
    params[1] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

SCOSSL_SKEY *p_scossl_generic_skeygen_generate(_In_ SCOSSL_PROVCTX *provctx, _In_ const OSSL_PARAM params[])
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

    skey = p_scossl_generic_skeymgmt_new(provctx->libctx);
    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (cbKey > 0)
    {
        skey->pbKey = OPENSSL_secure_malloc(cbKey);
        if (skey->pbKey == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
        SymCryptRandom(skey->pbKey, cbKey);
    }

    skey->cbKey = cbKey;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_generic_skeymgmt_free(skey);
        skey = NULL;
    }

    return skey;
}

static const OSSL_PARAM *p_scossl_generic_skeymgmt_settable_params(ossl_unused void *provctx)
{
    return p_scossl_generic_skeymgmt_settable_param_types;
}

static const OSSL_PARAM *p_scossl_generic_skeygen_settable_params(ossl_unused void *provctx)
{
    return p_scossl_generic_skeygen_settable_param_types;
}

const OSSL_DISPATCH p_scossl_generic_skeymgmt_functions[] = {
    {OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))p_scossl_generic_skeymgmt_free},
    {OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))p_scossl_generic_skeymgmt_import},
    {OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))p_scossl_generic_skeymgmt_export},
    {OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void))p_scossl_generic_skeygen_generate},
    {OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS, (void (*)(void))p_scossl_generic_skeymgmt_settable_params},
    {OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_generic_skeygen_settable_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif