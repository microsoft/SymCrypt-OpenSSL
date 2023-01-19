#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "scossl_helpers.h"

// lowercase, CamelCase, and UPPERCASE must be provided to reconcile differences
// between OpenSSL and SymCrypt APIs and macro definitions
#define IMPLEMENT_SCOSSL_DIGEST(lcalg, CcAlg, UCALG)                                 \
    static void *scossl_##lcalg##_newctx(void *prov_ctx)                             \
    {                                                                                \
        return OPENSSL_malloc(sizeof(SYMCRYPT_##UCALG##_STATE));                     \
    }                                                                                \
    static void scossl_##lcalg##_freectx(SYMCRYPT_##UCALG##_STATE *dctx)             \
    {                                                                                \
        OPENSSL_clear_free(dctx, sizeof(SYMCRYPT_##UCALG##_STATE));                  \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_init(                                      \
        SYMCRYPT_##UCALG##_STATE *dctx,                                              \
        const OSSL_PARAM params[])                                                   \
    {                                                                                \
        SymCrypt##CcAlg##Init(dctx);                                                 \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_update(                                    \
        SYMCRYPT_##UCALG##_STATE *dctx,                                              \
        const unsigned char *in, size_t inl)                                         \
    {                                                                                \
        SymCrypt##CcAlg##Append(dctx, in, inl);                                      \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_final(                                     \
        SYMCRYPT_##UCALG##_STATE *dctx,                                              \
        unsigned char *out, size_t *outl,                                            \
        size_t outsz)                                                                \
    {                                                                                \
        if (outsz < SYMCRYPT_##UCALG##_RESULT_SIZE)                                  \
            return 0;                                                                \
        SymCrypt##CcAlg##Result(dctx, out);                                          \
        *outl = SYMCRYPT_##UCALG##_RESULT_SIZE;                                      \
        return SCOSSL_SUCCESS;                                                       \
    }                                                                                \
    static SCOSSL_STATUS scossl_##lcalg##_get_params(OSSL_PARAM params[])            \
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

const OSSL_PARAM *scossl_digest_gettable_params_generic(void *dctx, void *provctx);
SCOSSL_STATUS scossl_digest_get_params_generic(OSSL_PARAM params[], size_t blocksize, size_t size);