//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(kbits, ivlen, lcmode, UCMODE)                                       \
    SCOSSL_CIPHER_##UCMODE##_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx()                                 \
    {                                                                                                        \
        SCOSSL_CIPHER_##UCMODE##_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_CIPHER_##UCMODE##_CTX));            \
        if (ctx != NULL)                                                                                     \
        {                                                                                                    \
            scossl_aes_##lcmode##_init_ctx(ctx, kbits >> 3, NULL);                                           \
        }                                                                                                    \
                                                                                                             \
        return ctx;                                                                                          \
    }                                                                                                        \
    SCOSSL_STATUS p_scossl_aes_##kbits##_##lcmode##_get_params(_Inout_ OSSL_PARAM params[])                  \
    {                                                                                                        \
        return p_scossl_aes_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, kbits >> 3,                 \
                                               ivlen, 1, SCOSSL_FLAG_AEAD | SCOSSL_FLAG_CUSTOM_IV);          \
    }                                                                                                        \
                                                                                                             \
    const OSSL_DISPATCH p_scossl_aes##kbits####lcmode##_functions[] = {                                      \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_newctx},                 \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_##lcmode##_dupctx},                           \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_##lcmode##_freectx},                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_##lcmode##_encrypt_init},               \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_##lcmode##_decrypt_init},               \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_##lcmode##_cipher},                           \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_##lcmode##_final},                             \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_##lcmode##_cipher},                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_get_params},         \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_##lcmode##_get_ctx_params},           \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_##lcmode##_set_ctx_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_params},            \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_##lcmode##_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_##lcmode##_settable_ctx_params}, \
        {0, NULL}};

#ifdef __cplusplus
}
#endif