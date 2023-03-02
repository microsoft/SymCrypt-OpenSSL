//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prototype definition, subject to change
#define IMPLEMENT_SCOSSL_KDF_FUNCTIONS(alg)                                                               \
    const OSSL_DISPATCH p_scossl_##alg##_kdf_functions = {                                             \
        {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_##alg##_kdf_new},                              \
        {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_##alg##_kdf_dup},                              \
        {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_##alg##_kdf_free},                            \
        {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_##alg##_kdf_reset},                             \
        {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_##alg##_kdf_derive},                           \
        {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_kdf_settable_ctx_params}, \
        {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_kdf_set_ctx_params},           \
        {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_kdf_gettable_ctx_params}, \
        {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_kdf_get_ctx_params},           \
        {0, NULL}};

#ifdef __cplusplus
}
#endif