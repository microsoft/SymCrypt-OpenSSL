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

} SCOSSL_DH_CTX;

static const OSSL_PARAM p_scossl_dh_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(ossl_unused void *ctx, const ossl_unused OSSL_PARAM params[]);

static SCOSSL_DH_CTX *p_scossl_dh_newctx(ossl_unused void *provctx)
{
    SCOSSL_DH_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_DH_CTX));
    if (ctx != NULL)
    {

    }

    return ctx;
}

static void p_scossl_dh_freectx(_In_ SCOSSL_DH_CTX *ctx)
{
    OPENSSL_free(ctx);
}

static SCOSSL_DH_CTX *p_scossl_dh_dupctx(_In_ SCOSSL_DH_CTX *ctx)
{
    SCOSSL_DH_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_CTX));
    if (copyCtx != NULL)
    {
        copyCtx->libctx = ctx->libctx;
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->peerKeyCtx = ctx->peerKeyCtx;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_dh_init(_In_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                      ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_dh_set_peer(_Inout_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *peerKeyCtx)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_dh_derive(_In_ SCOSSL_DH_CTX *ctx,
                                        _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                        size_t outlen)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_dh_get_ctx_params(ossl_unused void *ctx, ossl_unused OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_dh_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_dh_ctx_param_types;
}

const OSSL_DISPATCH p_scossl_dh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_dh_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_dh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_dh_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_dh_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_dh_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_dh_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_dh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_dh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif