//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_aes_gcm_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_gcm_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_ccm_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_ccm_settable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_STATUS p_scossl_aes_gcm_set_ctx_params(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_aes_ccm_set_ctx_params(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, _In_ const OSSL_PARAM params[]);

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