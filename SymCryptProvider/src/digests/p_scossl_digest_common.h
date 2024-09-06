//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_DIGEST_FLAG_XOF 0x1
#define SCOSSL_DIGEST_FLAG_ALGID_ABSENT 0x2

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_HASH_EXTRACT) (PVOID pState, PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe);

typedef struct
{
    PCSYMCRYPT_HASH pHash;
    PVOID pState;

    SIZE_T xofLen;
} SCOSSL_DIGEST_CTX;

SCOSSL_DIGEST_CTX *p_scossl_digest_dupctx(_In_ SCOSSL_DIGEST_CTX *ctx);
void p_scossl_digest_freectx(_Inout_ SCOSSL_DIGEST_CTX *ctx);

SCOSSL_STATUS p_scossl_digest_update(_Inout_ SCOSSL_DIGEST_CTX *ctx,
                                     _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
SCOSSL_STATUS p_scossl_digest_digest(_In_ PCSYMCRYPT_HASH pHash,
                                     _In_reads_bytes_(inl) const unsigned char *in, size_t inl,
                                     _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen);

SCOSSL_STATUS p_scossl_digest_get_params(_Inout_ OSSL_PARAM params[], size_t size, size_t blocksize, UINT32 flags);
const OSSL_PARAM *p_scossl_digest_gettable_params(ossl_unused void *ctx, ossl_unused void *provctx);

#define SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name, flags)                            \
    static SCOSSL_DIGEST_CTX *p_scossl_##dispatch_name##_newctx(ossl_unused void *prov_ctx)  \
    {                                                                                        \
        SCOSSL_DIGEST_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_DIGEST_CTX));                  \
                                                                                             \
        if (ctx != NULL)                                                                     \
        {                                                                                    \
            SCOSSL_COMMON_ALIGNED_ALLOC_EX(                                                  \
                pStateTmp,                                                                   \
                OPENSSL_malloc,                                                              \
                PVOID,                                                                       \
                SymCryptHashStateSize(ctx->pHash));                                          \
            if (pStateTmp == NULL)                                                           \
            {                                                                                \
                OPENSSL_free(ctx);                                                           \
                return NULL;                                                                 \
            }                                                                                \
                                                                                             \
            ctx->pState = pStateTmp;                                                         \
            ctx->pHash = SymCrypt##alg##Algorithm;                                           \
        }                                                                                    \
                                                                                             \
        return ctx;                                                                          \
    }                                                                                        \
                                                                                             \
    static SCOSSL_STATUS p_scossl_##dispatch_name##_digest(                                  \
        ossl_unused void *prov_ctx,                                                          \
        _In_reads_bytes_(inl) const unsigned char *in, size_t inl,                           \
        _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)     \
    {                                                                                        \
        return p_scossl_digest_digest(SymCrypt##alg##Algorithm, in, inl, out, outl, outlen); \
    }                                                                                        \
                                                                                             \
    static SCOSSL_STATUS p_scossl_##dispatch_name##_get_params(_Inout_ OSSL_PARAM params[])  \
    {                                                                                        \
        return p_scossl_digest_get_params(                                                   \
            params,                                                                          \
            SymCryptHashResultSize(SymCrypt##alg##Algorithm),                                \
            SymCryptHashInputBlockSize(SymCrypt##alg##Algorithm),                            \
            flags);                                                                          \
    }                                                                                        \
                                                                                             \
    const OSSL_DISPATCH p_scossl_##dispatch_name##_functions[] = {                           \
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))p_scossl_##dispatch_name##_newctx},            \
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))p_scossl_digest_freectx},                     \
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))p_scossl_digest_dupctx},                       \
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))p_scossl_##dispatch_name##_get_params},    \
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))p_scossl_digest_gettable_params},     \
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))p_scossl_digest_update},                       \
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))p_scossl_##dispatch_name##_digest},

#define SCOSSL_DIGEST_FUNCTIONS_END \
    {0, NULL}};

#ifdef __cplusplus
}
#endif