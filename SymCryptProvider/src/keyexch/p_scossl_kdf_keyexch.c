//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Before OpenSSL 3, HKDF and TLS1-PRF were available through the EVP_PKEY API.
// In OpenSSL 3, these are available through the EVP_KDF API, which uses the
// provider kdf interface. Some callers may still be using the EVP_PKEY API
// for HKDF and TLS1-PRF. These implementations below provide HKDF and TLS1-PRF
// for the EVP_PKEY API.

#include "kdf/p_scossl_hkdf.h"
#include "kdf/p_scossl_tls1prf.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_FUNC_kdf_newctx_fn                 *newCtx;
    OSSL_FUNC_kdf_freectx_fn                *freeCtx;
    OSSL_FUNC_kdf_dupctx_fn                 *dupCtx;
    OSSL_FUNC_kdf_derive_fn                 *derive;
    OSSL_FUNC_kdf_gettable_ctx_params_fn    *gettableCtxParams;
    OSSL_FUNC_kdf_settable_ctx_params_fn    *settableCtxParams;
    OSSL_FUNC_kdf_get_ctx_params_fn         *getCtxParams;
    OSSL_FUNC_kdf_set_ctx_params_fn         *setCtxParams;
} SCOSSL_KDF_FNS;

const SCOSSL_KDF_FNS hkdfKdfFunctions = {
    (OSSL_FUNC_kdf_newctx_fn *)                 p_scossl_hkdf_newctx,
    (OSSL_FUNC_kdf_freectx_fn *)                p_scossl_hkdf_freectx,
    (OSSL_FUNC_kdf_dupctx_fn *)                 p_scossl_hkdf_dupctx,
    (OSSL_FUNC_kdf_derive_fn *)                 p_scossl_hkdf_derive,
    (OSSL_FUNC_kdf_gettable_ctx_params_fn *)    p_scossl_hkdf_gettable_ctx_params,
    (OSSL_FUNC_kdf_settable_ctx_params_fn *)    p_scossl_hkdf_settable_ctx_params,
    (OSSL_FUNC_kdf_get_ctx_params_fn *)         p_scossl_hkdf_get_ctx_params,
    (OSSL_FUNC_kdf_set_ctx_params_fn *)         p_scossl_hkdf_set_ctx_params};

const SCOSSL_KDF_FNS tls1PrfKdfFunctions = {
    (OSSL_FUNC_kdf_newctx_fn *)                 p_scossl_tls1prf_newctx,
    (OSSL_FUNC_kdf_freectx_fn *)                p_scossl_tls1prf_freectx,
    (OSSL_FUNC_kdf_dupctx_fn *)                 p_scossl_tls1prf_dupctx,
    (OSSL_FUNC_kdf_derive_fn *)                 p_scossl_tls1prf_derive,
    (OSSL_FUNC_kdf_gettable_ctx_params_fn *)    p_scossl_tls1prf_gettable_ctx_params,
    (OSSL_FUNC_kdf_settable_ctx_params_fn *)    p_scossl_tls1prf_settable_ctx_params,
    (OSSL_FUNC_kdf_get_ctx_params_fn *)         p_scossl_tls1prf_get_ctx_params,
    (OSSL_FUNC_kdf_set_ctx_params_fn *)         p_scossl_tls1prf_set_ctx_params};

typedef struct
{
    PVOID kdfCtx;
    const SCOSSL_KDF_FNS *kdfFns;
} SCOSSL_KDF_KEYEXCH_CTX;

static SCOSSL_KDF_KEYEXCH_CTX *p_scossl_kdf_keyexch_newctx(_In_ SCOSSL_PROVCTX *provctx,
                                                           _In_ const SCOSSL_KDF_FNS *kdfFns)
{
    SCOSSL_KDF_KEYEXCH_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_KDF_KEYEXCH_CTX));

    if (ctx != NULL)
    {
        ctx->kdfFns = kdfFns;

        if ((ctx->kdfCtx = ctx->kdfFns->newCtx(provctx)) == NULL)
        {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

static SCOSSL_KDF_KEYEXCH_CTX *p_scossl_hkdf_keyexch_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return p_scossl_kdf_keyexch_newctx(provctx, &hkdfKdfFunctions);
}

static SCOSSL_KDF_KEYEXCH_CTX *p_scossl_tls1prf_keyexch_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return p_scossl_kdf_keyexch_newctx(provctx, &tls1PrfKdfFunctions);
}

static void p_scossl_kdf_keyexch_freectx(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ctx->kdfFns->freeCtx(ctx->kdfCtx);
    OPENSSL_free(ctx);
}

static SCOSSL_KDF_KEYEXCH_CTX *p_scossl_kdf_keyexch_dupctx(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx)
{
    SCOSSL_KDF_KEYEXCH_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_KDF_KEYEXCH_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->kdfFns = ctx->kdfFns;

        if ((copyCtx->kdfCtx = copyCtx->kdfFns->dupCtx(ctx->kdfCtx)) == NULL)
        {
            OPENSSL_free(copyCtx);
            copyCtx = NULL;
        }
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_kdf_keyexch_init(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx, ossl_unused void *provKey,
                                               _In_ const OSSL_PARAM params[])
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return ctx->kdfFns->setCtxParams(ctx->kdfCtx, params);
}

static SCOSSL_STATUS p_scossl_kdf_keyexch_derive(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx,
                                                 _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                                 size_t outlen)
{
    SIZE_T cbKdfResult;
    OSSL_PARAM kdfParams[2] = {
        OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &cbKdfResult),
        OSSL_PARAM_END};

    if (ctx->kdfFns->getCtxParams(ctx->kdfCtx, kdfParams) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    if (secret == NULL)
    {
        *secretlen = cbKdfResult;
        return SCOSSL_SUCCESS;
    }

    if (cbKdfResult != SIZE_MAX)
    {
        if (outlen < cbKdfResult)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        outlen = cbKdfResult;
    }

    if (ctx->kdfFns->derive(ctx->kdfCtx, secret, outlen, NULL) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    *secretlen = outlen;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kdf_keyexch_set_ctx_params(_Inout_ SCOSSL_KDF_KEYEXCH_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    return ctx->kdfFns->setCtxParams(ctx->kdfCtx, params);
}

static const OSSL_PARAM *p_scossl_kdf_keyexch_ctx_settable_params(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx, _In_ SCOSSL_PROVCTX *provctx)
{
    return ctx->kdfFns->settableCtxParams(ctx->kdfCtx, provctx);
}

static SCOSSL_STATUS p_scossl_kdf_keyexch_get_ctx_params(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    return ctx->kdfFns->getCtxParams(ctx->kdfCtx, params);
}

static const OSSL_PARAM *p_scossl_kdf_keyexch_ctx_gettable_params(_In_ SCOSSL_KDF_KEYEXCH_CTX *ctx, _In_ SCOSSL_PROVCTX *provctx)
{
    return ctx->kdfFns->gettableCtxParams(ctx->kdfCtx, provctx);
}

const OSSL_DISPATCH p_scossl_hkdf_keyexch_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_hkdf_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_kdf_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_kdf_keyexch_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_kdf_keyexch_init},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_kdf_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_ctx_settable_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_ctx_gettable_params},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_tls1prf_keyexch_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_tls1prf_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_kdf_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_kdf_keyexch_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_kdf_keyexch_init},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_kdf_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_ctx_settable_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kdf_keyexch_ctx_gettable_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif