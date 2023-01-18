#include <openssl/core_dispatch.h>

#define IMPLEMENT_SCOSSL_KDF_FUNCTIONS(alg)                                                               \
    const OSSL_DISPATCH scossl_prov_##alg##_kdf_functions = {                                             \
        {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))scossl_prov_##alg##_kdf_new},                              \
        {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))scossl_prov_##alg##_kdf_dup},                              \
        {OSSL_FUNC_KDF_FREECTX, (void (*)(void))scossl_prov_##alg##_kdf_free},                            \
        {OSSL_FUNC_KDF_RESET, (void (*)(void))scossl_prov_##alg##_kdf_reset},                             \
        {OSSL_FUNC_KDF_DERIVE, (void (*)(void))scossl_prov_##alg##_kdf_derive},                           \
        {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_kdf_settable_ctx_params}, \
        {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_kdf_set_ctx_params},           \
        {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_kdf_gettable_ctx_params}, \
        {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_kdf_get_ctx_params},           \
        {0, NULL}};
