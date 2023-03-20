//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "scossl_helpers.h"

#define SCOSSL_XTS_IV_LENGTH 8

#define IMPLEMENT_SCOSSL_AES_XTS_CIPHER(kbits)                                                        \
    SCOSSL_AES_XTS_CTX *p_scossl_aes_##kbits##_xts_newctx()                                           \
    {                                                                                                 \
        return p_scossl_aes_xtx_newctx_internal(kbits >> 3);                                          \
    }                                                                                                 \
    SCOSSL_STATUS p_scossl_aes_##kbits##_xts_get_params(_Inout_ OSSL_PARAM params[])                  \
    {                                                                                                 \
        return p_scossl_aes_generic_get_params(params, EVP_CIPH_XTS_MODE, kbits >> 3,                 \
                                               SCOSSL_XTS_IV_LENGTH, 1, SCOSSL_FLAG_CUSTOM_IV);       \
    }                                                                                                 \
                                                                                                      \
    const OSSL_DISPATCH p_scossl_aes##kbits##xts_functions[] = {                                      \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_xts_newctx},                 \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_xts_dupctx},                           \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_xts_freectx},                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_xts_encrypt_init},               \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_xts_decrypt_init},               \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_xts_update},                           \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_xts_final},                             \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_xts_cipher},                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_xts_get_params},         \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_xts_get_ctx_params},           \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_xts_set_ctx_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_params},     \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_xts_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_xts_settable_ctx_params}, \
        {0, NULL}};
