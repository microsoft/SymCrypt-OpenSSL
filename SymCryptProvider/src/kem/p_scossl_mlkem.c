//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kem/p_scossl_mlkem.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
} SCOSSL_MLKEM_CTX;

static const OSSL_PARAM p_scossl_mlkem_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mlkem_gettable_param_types[] = {
    OSSL_PARAM_END};

/* Context management */
SCOSSL_MLKEM_CTX *p_scossl_mlkem_newctx(ossl_unused void *provctx)
{
    SCOSSL_MLKEM_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_CTX));

    if (ctx != NULL)
    {

    }

    return ctx;
}

void p_scossl_mlkem_freectx(SCOSSL_MLKEM_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

SCOSSL_MLKEM_CTX *p_scossl_mlkem_dupctx(SCOSSL_MLKEM_CTX *ctx)
{
    SCOSSL_MLKEM_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->keyCtx = ctx->keyCtx;
    }

    return copyCtx;
}

//
// Encapsulation
//
SCOSSL_STATUS p_scossl_mlkem_encapsulate_init(SCOSSL_MLKEM_CTX *ctx, SCOSSL_MLKEM_KEY_CTX *keyCtx, const char *name,
                                              const OSSL_PARAM params[])
{
    if (ctx == NULL || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (keyCtx == NULL || !keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;

    return SCOSSL_FAILURE;
}

SCOSSL_STATUS p_scossl_mlkem_encapsulate(SCOSSL_MLKEM_CTX *ctx, unsigned char *out, size_t *outlen,
                                         unsigned char *secret, size_t *secretlen)
{
    return SCOSSL_FAILURE;
}

//
// Decapsulation
//
SCOSSL_STATUS p_scossl_mlkem_decapsulate_init(SCOSSL_MLKEM_CTX *ctx, SCOSSL_MLKEM_KEY_CTX *keyCtx, const char *name)
{
    if (ctx == NULL || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (keyCtx == NULL || !keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;

    return SCOSSL_FAILURE;
}

SCOSSL_STATUS p_scossl_mlkem_decapsulate(SCOSSL_MLKEM_CTX *ctx, unsigned char *out, size_t *outlen,
                                         const unsigned char *in, size_t inlen)
{
    return SCOSSL_FAILURE;
}

//
// Parameters
//
SCOSSL_STATUS p_scossl_mlkem_set_ctx_params(SCOSSL_MLKEM_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_mlkem_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_mlkem_settable_param_types;
}

SCOSSL_STATUS p_scossl_mlkem_get_ctx_params(SCOSSL_MLKEM_CTX *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_mlkem_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_mlkem_gettable_param_types;
}

const OSSL_DISPATCH p_scossl_mlkem_functions[] = {
    {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p_scossl_mlkem_newctx},
    {OSSL_FUNC_KEM_FREECTX, (void (*)(void))p_scossl_mlkem_freectx},
    {OSSL_FUNC_KEM_DUPCTX, (void (*)(void))p_scossl_mlkem_dupctx},
    {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_encapsulate_init},
    {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p_scossl_mlkem_encapsulate},
    {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_decapsulate_init},
    {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p_scossl_mlkem_decapsulate},
    {OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_set_ctx_params},
    {OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_settable_ctx_params},
    {OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_get_ctx_params},
    {OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_gettable_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif