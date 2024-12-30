//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "digests/p_scossl_digest_common.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_shake_settable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_shake_set_ctx_params(_Inout_ SCOSSL_DIGEST_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &ctx->xofLen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_shake_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_shake_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_shake_init(_Inout_ SCOSSL_DIGEST_CTX *ctx, ossl_unused const OSSL_PARAM params[])
{
    SymCryptHashInit(ctx->pHash, ctx->pState);
    ctx->xofLen = SymCryptHashResultSize(ctx->pHash);

    return p_scossl_shake_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_shake_extract(_Inout_ SCOSSL_DIGEST_CTX *ctx,
                                            PSYMCRYPT_HASH_EXTRACT extractFunc, BOOLEAN wipeState,
                                            _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    if (outlen < ctx->xofLen)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    extractFunc(ctx->pState, out, ctx->xofLen, wipeState);
    *outl = ctx->xofLen;

    return SCOSSL_SUCCESS;
}

#ifdef OSSL_FUNC_DIGEST_SQUEEZE
#define SCOSSL_DIGEST_SHAKE_SQUEEZE(bits) \
    {OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))p_scossl_shake_##bits##_squeeze},
#else
#define SCOSSL_DIGEST_SHAKE_SQUEEZE(bits)
#endif

#define IMPLEMENT_SCOSSL_SHAKE(bits)                                                                \
    static SCOSSL_STATUS p_scossl_shake_##bits##_final(                                             \
        _In_ SCOSSL_DIGEST_CTX *ctx,                                                                \
        _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)            \
    {                                                                                               \
        return p_scossl_shake_extract(ctx,                                                          \
            (PSYMCRYPT_HASH_EXTRACT)SymCryptShake##bits##Extract,                                   \
            TRUE,                                                                                   \
            out, outl, outlen);                                                                     \
    }                                                                                               \
                                                                                                    \
    static SCOSSL_STATUS p_scossl_shake_##bits##_squeeze(                                           \
        _In_ SCOSSL_DIGEST_CTX *ctx,                                                                \
        _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)            \
    {                                                                                               \
        return p_scossl_shake_extract(ctx,                                                          \
            (PSYMCRYPT_HASH_EXTRACT)SymCryptShake##bits##Extract,                                   \
            FALSE,                                                                                  \
            out, outl, outlen);                                                                     \
    }                                                                                               \
                                                                                                    \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(Shake##bits##Hash, shake_##bits, SCOSSL_DIGEST_FLAG_XOF)         \
        {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))p_scossl_shake_set_ctx_params},           \
        {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_shake_settable_ctx_params}, \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_shake_init},                               \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_shake_##bits##_final},                    \
        SCOSSL_DIGEST_SHAKE_SQUEEZE(bits)                                                           \
        SCOSSL_DIGEST_FUNCTIONS_END

//SHAKE
IMPLEMENT_SCOSSL_SHAKE(128)
IMPLEMENT_SCOSSL_SHAKE(256)

#ifdef __cplusplus
}
#endif