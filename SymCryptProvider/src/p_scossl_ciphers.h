//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_FLAG_AEAD 0x01
#define SCOSSL_FLAG_CUSTOM_IV 0x02

typedef SCOSSL_STATUS(scossl_cipher_fn)(SYMCRYPT_AES_EXPANDED_KEY *key, PBYTE pbChainingValue,
                                        int encrypt, unsigned char *out, size_t *outl,
                                        const unsigned char *in, size_t inl);

typedef struct
{
    SYMCRYPT_AES_EXPANDED_KEY key;
    size_t keylen;

    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];
    BYTE pbChainingValue[SYMCRYPT_AES_BLOCK_SIZE];
    int encrypt;
    int pad;

    // Buffer for partial blocks resulting from update calls
    unsigned char buf[SYMCRYPT_AES_BLOCK_SIZE];
    size_t cbBuf;

    scossl_cipher_fn *cipher;
} SCOSSL_AES_CTX;

static const OSSL_PARAM p_scossl_cipher_param_types[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cipher_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cipher_settable_ctx_param_types[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END};

// Prototype definition, subject to change
#define IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(kbits, ivlen, lcmode, UCMODE, flags)                   \
SCOSSL_AES_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx()                                       \
{                                                                                                \
    SCOSSL_AES_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_AES_CTX));                                \
    if (ctx != NULL)                                                                             \
    {                                                                                            \
        ctx->keylen = kbits >> 3;                                                                \
        ctx->pad = 1;                                                                            \
        ctx->cipher = &scossl_aes_##lcmode##_cipher;                                             \
    }                                                                                            \
                                                                                                    \
    return ctx;                                                                                  \
}                                                                                                \
SCOSSL_STATUS p_scossl_aes_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])                  \
{                                                                                                \
    return p_scossl_cipher_get_params(params, EVP_CIPH_##UCMODE##_MODE, kbits >> 3, ivlen, flags);      \
}                                                                                                \
                                                                                                    \
const OSSL_DISPATCH p_scossl_aes##kbits##lcmode##_functions[] = {                                \
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_newctx},         \
    {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_dupctx},                              \
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_freectx},                            \
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_encrypt_init},                  \
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_decrypt_init},                  \
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_update},                              \
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_final},                                \
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_cipher},                              \
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_get_params}, \
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_get_ctx_params},              \
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_set_ctx_params},              \
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_cipher_gettable_params},         \
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cipher_gettable_ctx_params}, \
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cipher_settable_ctx_params}, \
    {0, NULL}};

const OSSL_PARAM *p_scossl_cipher_gettable_params(void *provctx);
const OSSL_PARAM *p_scossl_cipher_gettable_ctx_params(void *cctx, void *provctx);
const OSSL_PARAM *p_scossl_cipher_settable_ctx_params(void *cctx, void *provctx);
SCOSSL_STATUS p_scossl_cipher_get_params(_Inout_ OSSL_PARAM params[], unsigned int mode, size_t kbits, size_t ivlen, unsigned int flags);
SCOSSL_STATUS p_scossl_aes_get_ctx_params(SCOSSL_AES_CTX *ctx, OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_aes_set_ctx_params(SCOSSL_AES_CTX *ctx, const OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif