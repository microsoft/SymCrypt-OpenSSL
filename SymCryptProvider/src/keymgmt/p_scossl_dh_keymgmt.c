//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{

} SCOSSL_DH_KEYGEN_CTX;

typedef struct
{

} SCOSSL_DH_KEY_CTX;

static const OSSL_PARAM p_scossl_dh_keygen_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_keymgmt_impexp_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_DH_KEY_CTX *p_scossl_dh_keymgmt_new_ctx(ossl_unused void *provctx)
{
    SCOSSL_DH_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_DH_KEY_CTX));
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return keyCtx;
}

static SCOSSL_DH_KEY_CTX *p_scossl_dh_keymgmt_dup_ctx(_In_ const SCOSSL_DH_KEY_CTX *keyCtx)
{
    SCOSSL_DH_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_KEY_CTX));
    if (copyCtx == NULL)
    {
        return NULL;
    }

    return copyCtx;
}

static void p_scossl_dh_keymgmt_free_ctx(_In_ SCOSSL_DH_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    OPENSSL_free(keyCtx);
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_dh_keygen_set_params(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx, const _In_ OSSL_PARAM params[])
{
   return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_dh_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provctx)
{
    return p_scossl_dh_keygen_settable_param_types;
}

static void p_scossl_dh_keygen_cleanup(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx)
{
    if (genCtx == NULL)
        return;

    OPENSSL_free(genCtx);
}

static SCOSSL_DH_KEYGEN_CTX *p_scossl_dh_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                       const _In_ OSSL_PARAM params[])
{
    return NULL;
}

static SCOSSL_DH_KEY_CTX *p_scossl_dh_keygen(_In_ SCOSSL_DH_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    return NULL;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_get_params(_In_ SCOSSL_DH_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_dh_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_dh_keymgmt_gettable_param_types;
}

static BOOL p_scossl_dh_keymgmt_has(_In_ SCOSSL_DH_KEY_CTX *keyCtx, int selection)
{
    return FALSE;
}

static BOOL p_scossl_dh_keymgmt_match(_In_ SCOSSL_DH_KEY_CTX *keyCtx1, _In_ SCOSSL_DH_KEY_CTX *keyCtx2,
                                       int selection)
{
    return SCOSSL_FAILURE;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_dh_keymgmt_impexp_types(int selection)
{
    return p_scossl_dh_keymgmt_impexp_param_types;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_import(_Inout_ SCOSSL_DH_KEY_CTX *keyCtx, int selection, const _In_ OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_export(_In_ SCOSSL_DH_KEY_CTX *keyCtx, int selection,
                                                 _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    return SCOSSL_FAILURE;
}

static const char *p_scossl_dh_keymgmt_query_operation_name(int operation_id)
{
    return NULL;
}

const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_dh_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_dh_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_dh_keymgmt_free_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_dh_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_dh_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_dh_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_dh_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_dh_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_dh_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_dh_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_dh_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))p_scossl_dh_keymgmt_query_operation_name},
    {0, NULL}};

#ifdef __cplusplus
}
#endif