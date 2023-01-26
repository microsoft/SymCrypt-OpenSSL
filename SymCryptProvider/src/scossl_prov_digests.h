//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// lowercase, CamelCase, and UPPERCASE must be provided to reconcile differences
// between OpenSSL and SymCrypt APIs and macro definitions
#define IMPLEMENT_SCOSSL_DIGEST(lcalg, CcAlg, UCALG)                                 \
    static void *scossl_##lcalg##_newctx(_Inout_ void *prov_ctx)                     \
    {                                                                                \
        return OPENSSL_malloc(sizeof(SYMCRYPT_##UCALG##_STATE));                     \
    }                                                                                \
    static void scossl_##lcalg##_freectx(_Inout_ SYMCRYPT_##UCALG##_STATE *dctx)     \
    {                                                                                \
        OPENSSL_clear_free(dctx, sizeof(SYMCRYPT_##UCALG##_STATE));                  \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_init(                                      \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                      \
        _In_ const OSSL_PARAM params[])                                              \
    {                                                                                \
        SymCrypt##CcAlg##Init(dctx);                                                 \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_update(                                    \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                      \
        _In_reads_bytes_(inl) const unsigned char *in,                               \
        size_t inl)                                                                  \
    {                                                                                \
        SymCrypt##CcAlg##Append(dctx, in, inl);                                      \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_final(                                     \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                      \
        _Out_writes_(SYMCRYPT_##UCALG##_RESULT_SIZE) unsigned char *out,             \
        _Out_ size_t *outl,                                                          \
        size_t outsz)                                                                \
    {                                                                                \
        if (outsz < SYMCRYPT_##UCALG##_RESULT_SIZE)                                  \
            return 0;                                                                \
                                                                                     \
        SymCrypt##CcAlg##Result(dctx, out);                                          \
        *outl = SYMCRYPT_##UCALG##_RESULT_SIZE;                                      \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_get_params(_Inout_ OSSL_PARAM params[])    \
    {                                                                                \
        return scossl_digest_get_params_generic(params,                              \
                                                SYMCRYPT_##UCALG##_INPUT_BLOCK_SIZE, \
                                                SYMCRYPT_##UCALG##_RESULT_SIZE);     \
    }                                                                                \
                                                                                     \
    const OSSL_DISPATCH scossl_##lcalg##_functions[] = {                             \
        {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))scossl_##lcalg##_newctx},          \
        {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))scossl_##lcalg##_freectx},        \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))scossl_##lcalg##_init},              \
        {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))scossl_##lcalg##_update},          \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))scossl_##lcalg##_final},            \
        {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))scossl_##lcalg##_get_params},  \
        {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))scossl_digest_gettable_params_generic}};

const OSSL_PARAM *scossl_digest_gettable_params_generic(_Inout_ void *dctx, _In_ void *provctx);
SCOSSL_STATUS scossl_digest_get_params_generic(_Inout_ OSSL_PARAM params[], size_t blocksize, size_t size);

#ifdef __cplusplus
}
#endif