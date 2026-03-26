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

static void *p_scossl_aes_skeymgmt_import(_In_ SCOSSL_PROVCTX *provctx, int selection,
                                          _In_ const OSSL_PARAM params[])
{
    SCOSSL_SKEY *skey = p_scossl_generic_skeymgmt_import(provctx, selection, params);

    if (skey != NULL)
    {
        skey->type = SCOSSL_SKEY_TYPE_AES;

        if (skey->cbKey != 16 && skey->cbKey != 24 && skey->cbKey != 32)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            p_scossl_generic_skeymgmt_free(skey);
            skey = NULL;
        }
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
    SCOSSL_SKEY *skey = p_scossl_generic_skeygen_generate(provctx, params);

    if (skey != NULL)
    {
        skey->type = SCOSSL_SKEY_TYPE_AES;

        if (skey->cbKey != 16 && skey->cbKey != 24 && skey->cbKey != 32)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            p_scossl_generic_skeymgmt_free(skey);
            skey = NULL;
        }
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
