//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prototype definition, subject to change
#define IMPLEMENT_SCOSSL_KEYEXCH_FUNCTIONS(alg)                                                                   \
    const OSSL_DISPATCH p_scossl_##alg##_keyexch_functions = {                                                 \
        {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_##alg##_keyexch_newctx},                           \
        {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_##alg##_keyexch_init},                               \
        {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_##alg##_keyexch_derive},                           \
        {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_##alg##_keyexch_set_peer},                       \
        {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_##alg##_keyexch_freectx},                         \
        {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_##alg##_keyexch_dupctx},                           \
        {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_keyexch_set_ctx_params},           \
        {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_keyexch_settable_ctx_params}, \
        {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_keyexch_get_ctx_params},           \
        {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_keyexch_gettable_ctx_params}, \
        {0, NULL}};

#ifdef __cplusplus
}
#endif