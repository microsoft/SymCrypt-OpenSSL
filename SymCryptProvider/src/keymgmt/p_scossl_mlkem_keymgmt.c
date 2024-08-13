//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kem/p_scossl_mlkem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {

} SCOSSL_MLKEM_KEYGEN_CTX;

static const OSSL_PARAM p_scossl_mlkem_keymgmt_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_keygen_settable_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(ossl_unused void *provCtx)
{
    SCOSSL_MLKEM_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));
    if (ctx != NULL)
    {

    }

    return ctx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLKEM_KEY_CTX *ctx, ossl_unused int selection)
{
    SCOSSL_MLKEM_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_KEY_CTX));

    if (copyCtx != NULL)
    {

    }

    return copyCtx;
}

static void p_scossl_mlkem_keymgmt_free_key_ctx(_In_ SCOSSL_MLKEM_KEY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_mlkem_keygen_set_params(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_mlkem_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keygen_settable_param_types;
}

static void p_scossl_mlkem_keygen_cleanup(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx)
{
    if (genCtx == NULL)
        return;

    OPENSSL_free(genCtx);
}

static SCOSSL_MLKEM_KEYGEN_CTX *p_scossl_mlkem_keygen_init(ossl_unused void *provCtx, int selection,
                                                           _In_ const OSSL_PARAM params[])
{
    SCOSSL_MLKEM_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEYGEN_CTX));

    if (genCtx != NULL)
    {

    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_keygen_set_template(_Inout_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLKEM_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL ||
        tmplCtx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_FAILURE;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keygen(_In_ SCOSSL_MLKEM_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_MLKEM_KEY_CTX *ctx;

    if ((ctx = p_scossl_mlkem_keymgmt_new_ctx(NULL)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ctx;
}

static const OSSL_PARAM *p_scossl_mlkem_keymgmt_settable_params(ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_params(_In_ SCOSSL_MLKEM_KEY_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mlkem_keymgmt_gettable_params(ossl_unused void *provCtx)
{
    return p_scossl_mlkem_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_params(_In_ SCOSSL_MLKEM_KEY_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}


static BOOL p_scossl_mlkem_keymgmt_has(_In_ SCOSSL_MLKEM_KEY_CTX *ctx, int selection)
{
    BOOL ret = TRUE;

    if (ctx == NULL)
    {
        return FALSE;
    }

    return ret;
}

static BOOL p_scossl_mlkem_keymgmt_match(_In_ SCOSSL_MLKEM_KEY_CTX *ctx1, _In_ SCOSSL_MLKEM_KEY_CTX *ctx2,
                                         int selection)
{
    BOOL ret = FALSE;

    return ret;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_mlkem_keymgmt_impexp_types(int selection)
{
    return NULL;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *ctx, int selection, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    return ret;
}

static SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *ctx, int selection,
                                                _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    SCOSSL_STATUS ret = SCOSSL_FAILURE;

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

#ifdef __cplusplus
}
#endif