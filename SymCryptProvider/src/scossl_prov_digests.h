#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "scossl_helpers.h"

#define IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(alg, CTX, blocksize, size)                                          \
    static void *scossl_prov_##alg##_newctx(void *prov_ctx)                                                   \
    {                                                                                                         \
        return OPENSSL_malloc(sizeof(CTX));                                                                   \
    }                                                                                                         \
    static void scossl_prov_##alg##_freectx(CTX *dctx)                                                        \
    {                                                                                                         \
        OPENSSL_clear_free(dctx, sizeof(CTX));                                                                \
    }                                                                                                         \
    static SCOSSL_STATUS scossl_prov_##alg##_init(CTX *dctx, const OSSL_PARAM params[])                       \
    {                                                                                                         \
        SymCrypt##alg##Init(dctx);                                                                            \
        return SCOSSL_SUCCESS;                                                                                \
    }                                                                                                         \
    static SCOSSL_STATUS scossl_prov_##alg##_update(CTX *dctx, const unsigned char *in, size_t inl)           \
    {                                                                                                         \
        SymCrypt##alg##Append(dctx, in, inl);                                                                 \
        return SCOSSL_SUCCESS;                                                                                \
    }                                                                                                         \
    static SCOSSL_STATUS scossl_prov_##alg##_final(CTX *dctx, unsigned char *out, size_t *outl, size_t outsz) \
    {                                                                                                         \
        if (outsz < size)                                                                                     \
            return 0;                                                                                         \
        SymCrypt##alg##Result(dctx, out);                                                                     \
        *outl = size;                                                                                         \
        return SCOSSL_SUCCESS;                                                                                \
    }                                                                                                         \
    static SCOSSL_STATUS scossl_prov_##alg##_get_params(OSSL_PARAM params[])                                  \
    {                                                                                                         \
        return scossl_prov_digest_get_params_common(params, blocksize, size);                                 \
    }                                                                                                         \
                                                                                                              \
    const OSSL_DISPATCH scossl_prov_##alg##_functions[] = {                                                   \
        {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))scossl_prov_##alg##_newctx},                                \
        {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))scossl_prov_##alg##_freectx},                              \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))scossl_prov_##alg##_init},                                    \
        {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))scossl_prov_##alg##_update},                                \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))scossl_prov_##alg##_final},                                  \
        {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))scossl_prov_##alg##_get_params},                        \
        {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))scossl_prov_digest_gettable_params}};

const OSSL_PARAM *scossl_prov_digest_gettable_params(void *dctx, void *provctx);
SCOSSL_STATUS scossl_prov_digest_get_params_common(OSSL_PARAM params[], size_t blocksize, size_t size);