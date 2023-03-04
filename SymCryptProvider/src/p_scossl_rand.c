//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/proverr.h>
#include <openssl/types.h>

#include "scossl_helpers.h"

#define SYMCRYPT_DRGB_STRENGTH 256
#define SYMCRYPT_DRGB_MAX_REQUEST_SIZE (1 << 16)

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    void *parent;
    OSSL_FUNC_rand_enable_locking_fn *parent_enable_locking;
    OSSL_FUNC_rand_lock_fn *parent_lock;
    OSSL_FUNC_rand_unlock_fn *parent_unlock;
} SCOSSL_RAND_CTX;


static SCOSSL_RAND_CTX *p_scossl_rand_newctx(void *provctx,
                                                void *parent,
                                                const OSSL_DISPATCH *parent_calls)
{
    SCOSSL_RAND_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_RAND_CTX));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }

    ctx->parent = parent;
    if (parent_calls != NULL)
    {
        while (parent_calls->function_id != 0)
        {
            switch (parent_calls->function_id)
            {
            case OSSL_FUNC_RAND_ENABLE_LOCKING:
                ctx->parent_enable_locking = OSSL_FUNC_rand_enable_locking(parent_calls);
                break;
            case OSSL_FUNC_RAND_LOCK:
                ctx->parent_lock = OSSL_FUNC_rand_lock(parent_calls);
                break;
            case OSSL_FUNC_RAND_UNLOCK:
                ctx->parent_unlock = OSSL_FUNC_rand_unlock(parent_calls);
                break;
            }
            parent_calls++;
        }
    }

    return ctx;
}

static void p_scossl_rand_freectx(SCOSSL_RAND_CTX *ctx)
{
    OPENSSL_free(ctx);
}

// RNG state is internally managed by SymCrypt. This function is
// required, but does not actually instantiate SymCrypt's RNG state
static SCOSSL_STATUS p_scossl_rand_instantiate(SCOSSL_RAND_CTX *ctx,
                                                unsigned int strength,
                                                int prediction_resistance,
                                                const unsigned char *addin, size_t addin_len,
                                                const OSSL_PARAM params[])
{
    if (addin_len > 0)
    {
        SymCryptProvideEntropy(addin, addin_len);
    }

    return SCOSSL_SUCCESS;
}

// RNG state is internally managed by SymCrypt. This function is
// required, but does not actually uninstantiate SymCrypt's RNG state.
// RNG is uninstantiated on SymCrypt unload
SCOSSL_STATUS p_scossl_rand_uninstantiate(SCOSSL_RAND_CTX *ctx)
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rand_generate(SCOSSL_RAND_CTX *ctx,
                                            unsigned char *out, size_t outlen,
                                            unsigned int strength,
                                            int prediction_resistance,
                                            const unsigned char *addin, size_t addin_len)
{
    SymCryptRandom(out, outlen);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rand_reseed(SCOSSL_RAND_CTX *ctx,
                                            int prediction_resistance,
                                            const unsigned char *ent, size_t ent_len,
                                            const unsigned char *addin, size_t addin_len)
{
    SymCryptProvideEntropy(addin, addin_len);
    return SCOSSL_SUCCESS;
}

// SymCrypt internally mangages locking, so the provider does not need
// to. These functions are required though, and should still lock the parent
static SCOSSL_STATUS p_scossl_rand_enable_locking(SCOSSL_RAND_CTX *ctx)
{
    if (ctx->parent != NULL &&
        ctx->parent_enable_locking != NULL &&
        !ctx->parent_enable_locking(ctx->parent))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rand_lock(SCOSSL_RAND_CTX *ctx)
{
    return SCOSSL_SUCCESS;
}

static void p_scossl_rand_unlock(SCOSSL_RAND_CTX *ctx)
{
}

static const OSSL_PARAM *p_scossl_rand_gettable_ctx_params(SCOSSL_RAND_CTX *ctx, void *provctx)
{
    static const OSSL_PARAM gettable_ctx_param_types[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END};

    return gettable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_rand_get_ctx_params(SCOSSL_RAND_CTX *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    // State managed by symcrypt module
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, SYMCRYPT_DRGB_STRENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SYMCRYPT_DRGB_MAX_REQUEST_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_rand_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))p_scossl_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))p_scossl_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))p_scossl_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))p_scossl_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))p_scossl_rand_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))p_scossl_rand_reseed},
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))p_scossl_rand_enable_locking},
    // {OSSL_FUNC_RAND_LOCK, (void (*)(void))p_scossl_rand_lock},
    // {OSSL_FUNC_RAND_UNLOCK, (void (*)(void))p_scossl_rand_unlock},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))p_scossl_rand_get_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif