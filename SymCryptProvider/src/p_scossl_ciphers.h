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

typedef SCOSSL_STATUS(scossl_cipher_fn)(_In_ SYMCRYPT_AES_EXPANDED_KEY *key, BOOL encrypt,
                                        _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE) PBYTE pbChainingValue,
                                        _Out_writes_bytes_(*outl) unsigned char *out, _Out_opt_ size_t *outl,
                                        _In_reads_bytes_(inl) const unsigned char *in, size_t inl);

typedef struct
{
    SYMCRYPT_AES_EXPANDED_KEY key;
    SIZE_T keylen;

    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];
    BYTE pbChainingValue[SYMCRYPT_AES_BLOCK_SIZE];
    BOOL encrypt;
    BOOL pad;

    // Provider is responsible for buffering
    // incomplete blocks in update calls
    BYTE buf[SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T cbBuf;

    scossl_cipher_fn *cipher;
} SCOSSL_AES_CTX;

static const OSSL_PARAM p_scossl_aes_generic_param_types[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_generic_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_generic_settable_ctx_param_types[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END};

const OSSL_PARAM *p_scossl_aes_generic_gettable_params(void *provctx);
SCOSSL_STATUS p_scossl_aes_generic_get_params(_Inout_ OSSL_PARAM params[],
                                              unsigned int mode,
                                              size_t keylen,
                                              size_t ivlen,
                                              size_t block_size,
                                              unsigned int flags);

SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(_Inout_ SCOSSL_AES_CTX *ctx, _In_ const OSSL_PARAM params[]);

#define IMPLEMENT_SCOSSL_AES_CIPHER(kbits, ivlen, lcmode, UCMODE, flags)                                  \
    SCOSSL_AES_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx()                                            \
    {                                                                                                     \
        SCOSSL_AES_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_AES_CTX));                                     \
        if (ctx != NULL)                                                                                  \
        {                                                                                                 \
            ctx->keylen = kbits >> 3;                                                                     \
            ctx->pad = 1;                                                                                 \
            ctx->cipher = &scossl_aes_##lcmode##_cipher;                                                  \
        }                                                                                                 \
                                                                                                          \
        return ctx;                                                                                       \
    }                                                                                                     \
    SCOSSL_STATUS p_scossl_aes_##kbits##_##lcmode##_get_params(_Inout_ OSSL_PARAM params[])               \
    {                                                                                                     \
        return p_scossl_aes_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, kbits >> 3,              \
                                               ivlen, SYMCRYPT_AES_BLOCK_SIZE, flags);                    \
    }                                                                                                     \
                                                                                                          \
    const OSSL_DISPATCH p_scossl_aes##kbits##lcmode##_functions[] = {                                     \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_newctx},              \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_generic_dupctx},                           \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_generic_freectx},                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_generic_encrypt_init},               \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_generic_decrypt_init},               \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_generic_update},                           \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_generic_final},                             \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_generic_cipher},                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_get_params},      \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_get_ctx_params},           \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_set_ctx_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_params},         \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_settable_ctx_params}, \
        {0, NULL}};

#ifdef __cplusplus
}
#endif