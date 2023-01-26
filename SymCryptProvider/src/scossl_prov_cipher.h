//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prototype definition, subject to change
#define IMPLEMENT_SCOSSL_CIPHER_FUNCTIONS(alg, bits, mode)                                                \
    const OSSL_DISPATCH scossl_prov_##alg##kbits##mode##_functions[] = {                                  \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))scossl_prov_##alg##kbits##mode##_newctx},               \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))scossl_prov_##alg##kbits##mode##_dupctx},               \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))scossl_prov_##alg##_##mode##_freectx},                 \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))scossl_prov_##alg##mode##_encrypt_init},          \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))scossl_prov_##alg##mode##_decrypt_init},          \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))scossl_prov_##alg##mode##_update},                      \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))scossl_prov_##alg##mode##_final},                        \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))scossl_prov_##alg##mode##_cipher},                      \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))scossl_prov_##alg##_##kbits##_##mode##_get_params}, \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))scossl_prov_##mode##_get_ctx_params},           \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))scossl_prov_##mode##_set_ctx_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))scossl_prov_cipher_gettable_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_cipher_gettable_ctx_params},   \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_cipher_settable_ctx_params},   \
        {0, NULL}};

#ifdef __cplusplus
}
#endif