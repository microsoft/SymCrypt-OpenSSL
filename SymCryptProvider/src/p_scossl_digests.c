//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_digest_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

const OSSL_PARAM *p_scossl_digest_gettable_params(ossl_unused void *dctx, ossl_unused void *provctx)
{
    return p_scossl_digest_param_types;
}

SCOSSL_STATUS p_scossl_digest_get_params(_Inout_ OSSL_PARAM params[], size_t blocksize, size_t size)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blocksize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

// lowercase, CamelCase, and UPPERCASE must be provided to reconcile differences
// between OpenSSL and SymCrypt APIs and macro definitions
#define IMPLEMENT_SCOSSL_DIGEST(lcalg, CcAlg, UCALG)                                  \
    static void *p_scossl_##lcalg##_newctx(ossl_unused void *prov_ctx)                \
    {                                                                                 \
        return OPENSSL_malloc(sizeof(SYMCRYPT_##UCALG##_STATE));                      \
    }                                                                                 \
    static void *p_scossl_##lcalg##_dupctx(_In_ SYMCRYPT_##UCALG##_STATE *dctx)       \
    {                                                                                 \
        SYMCRYPT_##UCALG##_STATE *copy_ctx =                                          \
            OPENSSL_malloc(sizeof(SYMCRYPT_##UCALG##_STATE));                         \
                                                                                      \
        if (copy_ctx != NULL)                                                         \
            SymCrypt##CcAlg##StateCopy(copy_ctx, dctx);                               \
                                                                                      \
        return copy_ctx;                                                              \
    }                                                                                 \
    static void p_scossl_##lcalg##_freectx(_Inout_ SYMCRYPT_##UCALG##_STATE *dctx)    \
    {                                                                                 \
        OPENSSL_clear_free(dctx, sizeof(SYMCRYPT_##UCALG##_STATE));                   \
    }                                                                                 \
    static SCOSSL_STATUS p_scossl_##lcalg##_init(                                     \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                       \
        ossl_unused const OSSL_PARAM params[])                                        \
    {                                                                                 \
        SymCrypt##CcAlg##Init(dctx);                                                  \
        return SCOSSL_SUCCESS;                                                        \
    }                                                                                 \
    static SCOSSL_STATUS p_scossl_##lcalg##_update(                                   \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                       \
        _In_reads_bytes_(inl) const unsigned char *in,                                \
        size_t inl)                                                                   \
    {                                                                                 \
        SymCrypt##CcAlg##Append(dctx, in, inl);                                       \
        return SCOSSL_SUCCESS;                                                        \
    }                                                                                 \
    static SCOSSL_STATUS p_scossl_##lcalg##_final(                                    \
        _Inout_ SYMCRYPT_##UCALG##_STATE *dctx,                                       \
        _Out_writes_bytes_(SYMCRYPT_##UCALG##_RESULT_SIZE) unsigned char *out,        \
        _Out_ size_t *outl, size_t outsz)                                             \
    {                                                                                 \
        if (outsz < SYMCRYPT_##UCALG##_RESULT_SIZE)                                   \
        {                                                                             \
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);                  \
            return SCOSSL_FAILURE;                                                    \
        }                                                                             \
                                                                                      \
        SymCrypt##CcAlg##Result(dctx, out);                                           \
        *outl = SYMCRYPT_##UCALG##_RESULT_SIZE;                                       \
        return SCOSSL_SUCCESS;                                                        \
    }                                                                                 \
    static SCOSSL_STATUS p_scossl_##lcalg##_digest(                                   \
        ossl_unused void *provctx,                                                    \
        _In_ const unsigned char *in, size_t inl,                                     \
        _Out_writes_bytes_(SYMCRYPT_##UCALG##_RESULT_SIZE) unsigned char *out,        \
        _Out_ size_t *outl, size_t outsz)                                             \
    {                                                                                 \
        if (outsz < SYMCRYPT_##UCALG##_RESULT_SIZE)                                   \
        {                                                                             \
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);                  \
            return SCOSSL_FAILURE;                                                    \
        }                                                                             \
                                                                                      \
        SymCrypt##CcAlg(in, inl, out);                                                \
        *outl = SYMCRYPT_##UCALG##_RESULT_SIZE;                                       \
        return SCOSSL_SUCCESS;                                                        \
    }                                                                                 \
    static SCOSSL_STATUS p_scossl_##lcalg##_get_params(_Inout_ OSSL_PARAM params[])   \
    {                                                                                 \
        return p_scossl_digest_get_params(params,                                     \
                                          SYMCRYPT_##UCALG##_INPUT_BLOCK_SIZE,        \
                                          SYMCRYPT_##UCALG##_RESULT_SIZE);            \
    }                                                                                 \
                                                                                      \
    const OSSL_DISPATCH p_scossl_##lcalg##_functions[] = {                            \
        {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))p_scossl_##lcalg##_newctx},         \
        {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))p_scossl_##lcalg##_dupctx},         \
        {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))p_scossl_##lcalg##_freectx},       \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_##lcalg##_init},             \
        {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))p_scossl_##lcalg##_update},         \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_##lcalg##_final},           \
        {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))p_scossl_##lcalg##_digest},         \
        {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))p_scossl_##lcalg##_get_params}, \
        {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))p_scossl_digest_gettable_params}};

IMPLEMENT_SCOSSL_DIGEST(md5, Md5, MD5)
IMPLEMENT_SCOSSL_DIGEST(sha1, Sha1, SHA1)
IMPLEMENT_SCOSSL_DIGEST(sha256, Sha256, SHA256)
IMPLEMENT_SCOSSL_DIGEST(sha384, Sha384, SHA384)
IMPLEMENT_SCOSSL_DIGEST(sha512, Sha512, SHA512)
IMPLEMENT_SCOSSL_DIGEST(sha3_256, Sha3_256, SHA3_256)
IMPLEMENT_SCOSSL_DIGEST(sha3_384, Sha3_384, SHA3_384)
IMPLEMENT_SCOSSL_DIGEST(sha3_512, Sha3_512, SHA3_512)

#ifdef __cplusplus
}
#endif