//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct 
{
    PSYMCRYPT_HASH pHash;
    PVOID pState;
} SCOSSL_DIGEST_CTX;

static const OSSL_PARAM p_scossl_digest_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static SCOSSL_DIGEST_CTX *p_scossl_digest_dupctx(_In_ SCOSSL_DIGEST_CTX *ctx)
{
    SCOSSL_DIGEST_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DIGEST_CTX));
    if (copyCtx != NULL)
    {
        copyCtx->pHash = ctx->pHash;
        SCOSSL_COMMON_ALIGNED_ALLOC_EX(pStateTmp, OPENSSL_malloc, PVOID, SymCryptHashStateSize(ctx->pHash));

        if (pStateTmp == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }

        SymCryptHashStateCopy(ctx->pHash, ctx->pState, pStateTmp);
        copyCtx->pState = pStateTmp;
    }

    return copyCtx;
}

static void p_scossl_digest_freectx(_Inout_ SCOSSL_DIGEST_CTX *ctx)
{
    if (ctx == NULL)
        return;

    SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->pState, OPENSSL_clear_free, SymCryptHashStateSize(ctx->pHash));
    OPENSSL_free(ctx);
}

static SCOSSL_STATUS p_scossl_digest_init(_Inout_ SCOSSL_DIGEST_CTX *ctx, ossl_unused const OSSL_PARAM params[])
{
    SymCryptHashInit(ctx->pHash, ctx->pState);
    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_digest_gettable_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_digest_param_types;
}

SCOSSL_STATUS p_scossl_digest_get_params(_Inout_ OSSL_PARAM params[], size_t size, size_t blocksize)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, blocksize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_update(_Inout_ SCOSSL_DIGEST_CTX *ctx,
                                            _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SymCryptHashAppend(ctx->pHash, ctx->pState, in, inl);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_final(_Inout_ SCOSSL_DIGEST_CTX *ctx,
                                           _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsz)
{
    SIZE_T cbResult = SymCryptHashResultSize(ctx->pHash);

    if (outsz < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    SymCryptHashResult(ctx->pHash, ctx->pState, out, cbResult);
    *outl = cbResult;

    return SCOSSL_SUCCESS;
}

static void p_scossl_digest_digest(PSYMCRYPT_HASH pHash,
                                   _In_reads_bytes_(inl) const unsigned char *in, size_t inl,
                                   _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsz)
{
    SIZE_T cbResult = SymCryptHashResultSize(pHash);

    if (outsz < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    SymCryptHash(pHash, in, inl, out, cbResult);
    *outl = cbResult;
}

#define SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name)                               \
    static SCOSSL_DIGEST_CTX *p_scossl_##alg##_newctx(ossl_unused void *prov_ctx)        \
    {                                                                                    \
        SCOSSL_DIGEST_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_DIGEST_CTX));              \
        if (ctx != NULL)                                                                 \
        {                                                                                \
            ctx->pHash = SymCrypt##alg##Algorithm;                                       \
            SCOSSL_COMMON_ALIGNED_ALLOC_EX(                                              \
                pStateTmp,                                                               \
                OPENSSL_malloc,                                                          \
                PVOID,                                                                   \
                SymCryptHashStateSize(ctx->pHash));                                      \
                                                                                         \
            if (pStateTmp == NULL)                                                       \
            {                                                                            \
                OPENSSL_free(ctx);                                                       \
                return NULL;                                                             \
            }                                                                            \
                                                                                         \
            ctx->pState = pStateTmp;                                                     \
        }                                                                                \
        return ctx;                                                                      \
    }                                                                                    \
                                                                                         \
    static SCOSSL_STATUS p_scossl_##alg##_digest(                                        \
        ossl_unused void *prov_ctx,                                                      \
        _In_reads_bytes_(inl) const unsigned char *in, size_t inl,                       \
        _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsz)  \
    {                                                                                    \
        p_scossl_digest_digest(SymCrypt##alg##Algorithm, in, in, out, outl, outsz);      \
                                                                                         \
        return SCOSSL_SUCCESS;                                                           \
    }                                                                                    \
                                                                                         \
    static SCOSSL_STATUS p_scossl_##alg##_get_params(_Inout_ OSSL_PARAM params[])        \
    {                                                                                    \
        return p_scossl_digest_get_params(params,                                        \
            SymCryptHashResultSize(SymCrypt##alg##Algorithm),                            \
            SymCryptHashInputBlockSize(SymCrypt##alg##Algorithm));                       \
    }                                                                                    \
                                                                                         \
    const OSSL_DISPATCH p_scossl_##dispatch_name##_functions[] = {                       \
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))p_scossl_##alg##_newctx},                  \
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))p_scossl_digest_dupctx},                   \
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))p_scossl_digest_freectx},                 \
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))p_scossl_##alg##_get_params},          \
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))p_scossl_digest_gettable_params}, \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_digest_init},                       \
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))p_scossl_digest_update},                   \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_digest_final},                     \
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))p_scossl_digest_digest},

#define IMPLEMENT_SCOSSL_DIGEST_GENERIC(alg, dispatch_name) \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name)      \
    {0, NULL}};

#define IMPLEMENT_SCOSSL_DIGEST_SHAKE(bits) \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(Shake##bits##Hash, shake_##bits) \
    {0, NULL}};

// MD5 and SHA1, supported for compatability
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Md5, md5)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha1, sha1)

// SHA2
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha256, sha256)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha384, sha384)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha512, sha512)

//SHA3
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_256, sha3_256)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_384, sha3_384)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_512, sha3_512)

//SHAKE
IMPLEMENT_SCOSSL_DIGEST_SHAKE(128)
IMPLEMENT_SCOSSL_DIGEST_SHAKE(256)

#ifdef __cplusplus
}
#endif