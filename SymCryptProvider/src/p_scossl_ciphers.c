//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_ciphers.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

// Populates remaining space in the buffer
static size_t p_scossl_aes_generic_fill_buffer(_Inout_updates_bytes_(*cbBuf) unsigned char *buf, _Inout_ size_t *cbBuf,
                                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    size_t cbBufRemaining = SYMCRYPT_AES_BLOCK_SIZE - *cbBuf;
    if (inl < cbBufRemaining)
    {
        cbBufRemaining = inl;
    }
    memcpy(buf + *cbBuf, in, cbBufRemaining);

    // Advance in
    *cbBuf += cbBufRemaining;
    in += cbBufRemaining;
    return cbBufRemaining;
}

static SCOSSL_STATUS p_scossl_aes_generic_buffer_trailing_data(_Inout_updates_bytes_(inl) unsigned char *buf, _Inout_ size_t *cbBuf,
                                                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (inl > SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }

    memcpy(buf, in, inl);
    *cbBuf += inl;

    return SCOSSL_SUCCESS;
}

void p_scossl_aes_generic_freectx(SCOSSL_AES_CTX *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_AES_CTX));
}

SCOSSL_AES_CTX *p_scossl_aes_generic_dupctx(SCOSSL_AES_CTX *ctx)
{
    SCOSSL_AES_CTX *copy_ctx = OPENSSL_malloc(sizeof(SCOSSL_AES_CTX));
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_AES_CTX));
        SymCryptAesKeyCopy(&ctx->key, &copy_ctx->key);
    }
    return copy_ctx;
}

SCOSSL_STATUS p_scossl_aes_generic_init_internal(SCOSSL_AES_CTX *ctx, BOOL encrypt,
                                                 const unsigned char *key, size_t keylen,
                                                 const unsigned char *iv, size_t ivlen,
                                                 const OSSL_PARAM params[])
{
    ctx->encrypt = encrypt;

    if (key != NULL)
    {
        SYMCRYPT_ERROR scError = SymCryptAesExpandKey(&ctx->key, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    if (iv != NULL)
    {
        if (ivlen != SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->iv, iv, SYMCRYPT_AES_BLOCK_SIZE);
        memcpy(ctx->pbChainingValue, iv, SYMCRYPT_AES_BLOCK_SIZE);
    }

    return p_scossl_aes_generic_set_ctx_params(ctx, params);
}

SCOSSL_STATUS p_scossl_aes_generic_encrypt_init(SCOSSL_AES_CTX *ctx,
                                                const unsigned char *key, size_t keylen,
                                                const unsigned char *iv, size_t ivlen,
                                                const OSSL_PARAM params[])
{
    return p_scossl_aes_generic_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

SCOSSL_STATUS p_scossl_aes_generic_decrypt_init(SCOSSL_AES_CTX *ctx,
                                                const unsigned char *key, size_t keylen,
                                                const unsigned char *iv, size_t ivlen,
                                                const OSSL_PARAM params[])
{
    return p_scossl_aes_generic_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}

SCOSSL_STATUS p_scossl_aes_generic_update(SCOSSL_AES_CTX *ctx,
                                          unsigned char *out, size_t *outl, size_t outsize,
                                          const unsigned char *in, size_t inl)
{
    size_t outl_int = 0;
    size_t cBlocksRemaining = 0;

    // Data from previous update in buffer. Try to fill buffer and
    // encrypt/decrypt before moving to remaining data.
    if (ctx->cbBuf > 0)
    {
        inl -= p_scossl_aes_generic_fill_buffer(ctx->buf, &ctx->cbBuf, in, inl);
    }

    // First encrypt the buffer if it is filled
    if (ctx->cbBuf == SYMCRYPT_AES_BLOCK_SIZE)
    {
        if (outsize < SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        if (!ctx->cipher(&ctx->key, ctx->encrypt, ctx->pbChainingValue, out, NULL, ctx->buf, ctx->cbBuf))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        out += SYMCRYPT_AES_BLOCK_SIZE;
        outl_int += SYMCRYPT_AES_BLOCK_SIZE;
        ctx->cbBuf = 0;
    }

    cBlocksRemaining = inl / SYMCRYPT_AES_BLOCK_SIZE;

    // in still contains whole blocks, encrypt available blocks
    if (cBlocksRemaining > 0)
    {
        outl_int += cBlocksRemaining * SYMCRYPT_AES_BLOCK_SIZE;
        if (outsize < outl_int)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        if (!ctx->cipher(&ctx->key, ctx->encrypt, ctx->pbChainingValue, out, NULL, in, cBlocksRemaining * SYMCRYPT_AES_BLOCK_SIZE))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        ctx->cbBuf = 0;

        in += cBlocksRemaining * SYMCRYPT_AES_BLOCK_SIZE;
        inl -= cBlocksRemaining * SYMCRYPT_AES_BLOCK_SIZE;
    }

    // Buffer any remaining data
    if (inl > 0 &&
        !p_scossl_aes_generic_buffer_trailing_data(ctx->buf, &ctx->cbBuf, in, inl))
    {
        return SCOSSL_FAILURE;
    }

    *outl = outl_int;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_generic_final(SCOSSL_AES_CTX *ctx,
                                         unsigned char *out, size_t *outl, size_t outsize)
{
    if (ctx->encrypt)
    {
        if (outsize < SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        // Pad
        if (ctx->pad)
        {
            size_t pcbResult;
            SymCryptPaddingPkcs7Add(
                SYMCRYPT_AES_BLOCK_SIZE,
                ctx->buf,
                ctx->cbBuf,
                ctx->buf,
                SYMCRYPT_AES_BLOCK_SIZE,
                &pcbResult);

            if (pcbResult != SYMCRYPT_AES_BLOCK_SIZE)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return SCOSSL_FAILURE;
            }
        }
        else if (ctx->cbBuf == 0)
        {
            *outl = 0;
            return SCOSSL_SUCCESS;
        }
        else if (ctx->cbBuf != SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return SCOSSL_FAILURE;
        }

        // Encrypt
        if (!ctx->cipher(&ctx->key, ctx->encrypt, ctx->pbChainingValue, out, outl, ctx->buf, ctx->cbBuf))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }
        ctx->cbBuf = 0;

        return SCOSSL_SUCCESS;
    }

    if (ctx->cbBuf == 0 && !ctx->pad)
    {
        *outl = 0;
        return SCOSSL_SUCCESS;
    }
    else if (ctx->cbBuf != SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return SCOSSL_FAILURE;
    }

    unsigned char out_int[SYMCRYPT_AES_BLOCK_SIZE];
    size_t outl_int;

    // Decrypt
    if (!ctx->cipher(&ctx->key, ctx->encrypt, ctx->pbChainingValue, out_int, &outl_int, ctx->buf, ctx->cbBuf))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }
    ctx->cbBuf = 0;

    if (ctx->pad)
    {
        SymCryptPaddingPkcs7Remove(
            SYMCRYPT_AES_BLOCK_SIZE,
            out_int,
            outl_int,
            out_int,
            SYMCRYPT_AES_BLOCK_SIZE,
            &outl_int);
    }

    if (outsize < outl_int)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    memcpy(out, out_int, outl_int);
    *outl = outl_int;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_generic_cipher(SCOSSL_AES_CTX *ctx,
                                          unsigned char *out, size_t *outl, size_t outsize,
                                          const unsigned char *in, size_t inl)
{
    return ctx->cipher(&ctx->key, ctx->encrypt, ctx->pbChainingValue, out, outl, in, inl);
}

const OSSL_PARAM *p_scossl_aes_generic_gettable_params(void *provctx)
{
    return p_scossl_aes_generic_param_types;
}

const OSSL_PARAM *p_scossl_aes_generic_gettable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_aes_generic_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_aes_generic_settable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_aes_generic_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_aes_generic_get_params(_Inout_ OSSL_PARAM params[],
                                              unsigned int mode,
                                              size_t keylen,
                                              size_t ivlen,
                                              size_t block_size,
                                              unsigned int flags)
{

    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block_size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_AEAD))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_CUSTOM_IV))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_generic_get_ctx_params(SCOSSL_AES_CTX *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(SCOSSL_AES_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL)
    {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_cbc_cipher(_In_ SYMCRYPT_AES_EXPANDED_KEY *key, BOOL encrypt,
                                           _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE) PBYTE pbChainingValue,
                                           _Out_writes_bytes_(*outl) unsigned char *out, _Out_opt_ size_t *outl,
                                           _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (outl != NULL)
    {
        *outl = inl;
    }

    if (encrypt)
    {
        SymCryptAesCbcEncrypt(key, pbChainingValue, in, out, inl);
    }
    else
    {
        SymCryptAesCbcDecrypt(key, pbChainingValue, in, out, inl);
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_ecb_cipher(_In_ SYMCRYPT_AES_EXPANDED_KEY *key, BOOL encrypt,
                                           _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE) PBYTE pbChainingValue,
                                           _Out_writes_bytes_(*outl) unsigned char *out, _Out_opt_ size_t *outl,
                                           _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{

    if (outl != NULL)
    {
        *outl = inl;
    }

    if (encrypt)
    {
        SymCryptAesEcbEncrypt(key, in, out, inl);
    }
    else
    {
        SymCryptAesEcbDecrypt(key, in, out, inl);
    }

    return SCOSSL_SUCCESS;
}

IMPLEMENT_SCOSSL_AES_CIPHER(128, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(192, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(256, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)

IMPLEMENT_SCOSSL_AES_CIPHER(128, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(192, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(256, 0, ecb, ECB, 0)

// extern const OSSL_DISPATCH p_scossl_aes256xts_functions[]; IMPLEMENT_cipher
// extern const OSSL_DISPATCH p_scossl_aes128xts_functions[]; IMPLEMENT_cipher

#ifdef __cplusplus
}
#endif