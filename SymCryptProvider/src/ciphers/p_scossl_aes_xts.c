//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"
#include "p_scossl_aes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_XTS_TWEAK_LENGTH 16

typedef struct
{
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
    SIZE_T keylen;

    BYTE tweak[SCOSSL_XTS_TWEAK_LENGTH];

    BOOL encrypt;
} SCOSSL_AES_XTS_CTX;

static const OSSL_PARAM p_scossl_aes_xts_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_xts_settable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_aes_xts_set_ctx_params(_Inout_ SCOSSL_AES_XTS_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_AES_XTS_CTX *p_scossl_aes_xts_newctx_internal(size_t keylen)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(ctx, OPENSSL_malloc, SCOSSL_AES_XTS_CTX);
    if (ctx != NULL)    
    {
        ctx->keylen = keylen;
    }
    return ctx;
}

static SCOSSL_AES_XTS_CTX *p_scossl_aes_xts_dupctx(SCOSSL_AES_XTS_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copy_ctx, OPENSSL_malloc, SCOSSL_AES_XTS_CTX);
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_AES_XTS_CTX));

        SymCryptXtsAesKeyCopy(&ctx->key, &copy_ctx->key);
    }

    return copy_ctx;
}

static void p_scossl_aes_xts_freectx(SCOSSL_AES_XTS_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_FREE(ctx, OPENSSL_clear_free, SCOSSL_AES_XTS_CTX);
}

static SCOSSL_STATUS p_scossl_aes_xts_init_internal(_Inout_ SCOSSL_AES_XTS_CTX *ctx, INT32 encrypt,
                                                    _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                    _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                    _In_ const OSSL_PARAM params[])
{
    ctx->encrypt = encrypt;

    if (key != NULL)
    {
        if (keylen != ctx->keylen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return SCOSSL_FAILURE;
        }
        SYMCRYPT_ERROR scError = SymCryptXtsAesExpandKeyEx(&ctx->key, key, keylen, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    if (iv != NULL)
    {
        if (ivlen != SCOSSL_XTS_TWEAK_LENGTH)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->tweak, iv, SCOSSL_XTS_TWEAK_LENGTH);
    }

    return p_scossl_aes_xts_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_aes_xts_encrypt_init(_Inout_ SCOSSL_AES_XTS_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_xts_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_xts_decrypt_init(_Inout_ SCOSSL_AES_XTS_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_xts_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}


static SCOSSL_STATUS p_scossl_aes_xts_cipher(SCOSSL_AES_XTS_CTX *ctx,
                                             _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                             _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if( inl < SYMCRYPT_AES_BLOCK_SIZE )
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return SCOSSL_FAILURE;
    }

    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    // The EVP API for exposing AES-XTS expects one call per data unit - so we pass inl
    // to both cbDataUnit and cbData.

    if(ctx->encrypt)
    {
        SymCryptXtsAesEncryptWith128bTweak(
            &ctx->key,
            inl,
            &ctx->tweak[0],
            in,
            out,
            inl);
    }
    else
    {
        SymCryptXtsAesDecryptWith128bTweak(
            &ctx->key,
            inl,
            &ctx->tweak[0],
            in,
            out,
            inl);
    }

    *outl = inl;
    
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_xts_update(_Inout_ SCOSSL_AES_XTS_CTX *ctx,
                                             _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                             _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return p_scossl_aes_xts_cipher(ctx, out, outl, outsize, in, inl);
}

static SCOSSL_STATUS p_scossl_aes_xts_final(ossl_unused SCOSSL_AES_XTS_CTX *ctx,
                                            ossl_unused unsigned char *out, _Out_ size_t *outl, ossl_unused size_t outsize)
{
    *outl = 0;

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_aes_xts_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_xts_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_aes_xts_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_xts_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_aes_xts_get_ctx_params(_In_ SCOSSL_AES_XTS_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SCOSSL_XTS_TWEAK_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->tweak, SCOSSL_XTS_TWEAK_LENGTH) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->tweak, SCOSSL_XTS_TWEAK_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->tweak, SCOSSL_XTS_TWEAK_LENGTH) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->tweak, SCOSSL_XTS_TWEAK_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_xts_set_ctx_params(_Inout_ SCOSSL_AES_XTS_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL)
    {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
        if (keylen != ctx->keylen)
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_AES_XTS_CIPHER(kbits)                                                        \
    SCOSSL_AES_XTS_CTX *p_scossl_aes_##kbits##_xts_newctx()                                           \
    {                                                                                                 \
        return p_scossl_aes_xts_newctx_internal(2 * (kbits >> 3));                                    \
    }                                                                                                 \
    SCOSSL_STATUS p_scossl_aes_##kbits##_xts_get_params(_Inout_ OSSL_PARAM params[])                  \
    {                                                                                                 \
        return p_scossl_aes_generic_get_params(params, EVP_CIPH_XTS_MODE, kbits >> 3,                 \
                                               SCOSSL_XTS_TWEAK_LENGTH, 1, SCOSSL_FLAG_CUSTOM_IV);    \
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

IMPLEMENT_SCOSSL_AES_XTS_CIPHER(128)
IMPLEMENT_SCOSSL_AES_XTS_CIPHER(256)

#ifdef __cplusplus
}
#endif