#include "p_scossl_ciphers.h"

#include <openssl/proverr.h>

void fill_buffer(_Inout_updates_bytes_(*cbBuf) unsigned char *buf, _Inout_ size_t *cbBuf,
                 _In_reads_bytes_(*inl) const unsigned char *in, size_t *inl)
{
    size_t cbBufFill = SYMCRYPT_AES_BLOCK_SIZE - *cbBuf;
    if (*inl < cbBufFill)
    {
        cbBufFill = *inl;
    }
    memcpy(buf + *cbBuf, in, cbBufFill);

    // Advance in
    *cbBuf += cbBufFill;
    in += cbBufFill;
    *inl -= cbBufFill;
}

SCOSSL_STATUS buffer_trailing_data(_Inout_updates_bytes_(*inl) unsigned char *buf, _Inout_ size_t *cbBuf,
                                   _In_reads_bytes_(*inl) const unsigned char *in, _Inout_ size_t *inl)
{
    if (*inl > SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }

    memcpy(buf, in, *inl);
    *cbBuf += *inl;

    return SCOSSL_SUCCESS;
}

void p_scossl_aes_freectx(SCOSSL_AES_CTX *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_AES_CTX));
}

SCOSSL_AES_CTX *p_scossl_aes_dupctx(SCOSSL_AES_CTX *ctx)
{
    SCOSSL_AES_CTX *copy_ctx = OPENSSL_malloc(sizeof(SCOSSL_AES_CTX));
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_AES_CTX));
        SymCryptAesKeyCopy(&ctx->key, &copy_ctx->key);
    }
    return copy_ctx;
}

SCOSSL_STATUS p_scossl_aes_init_internal(SCOSSL_AES_CTX *ctx,
                                         const unsigned char *key, size_t keylen,
                                         const unsigned char *iv, size_t ivlen,
                                         const OSSL_PARAM params[])
{
    if (key != NULL)
    {
        SYMCRYPT_ERROR scError = SymCryptAesExpandKey(&ctx->key, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_AES_CCM_CIPHER, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptAesExpandKey failed", scError);
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

    return p_scossl_aes_set_ctx_params(ctx, params);
}

SCOSSL_STATUS p_scossl_aes_encrypt_init(SCOSSL_AES_CTX *ctx,
                                        const unsigned char *key, size_t keylen,
                                        const unsigned char *iv, size_t ivlen,
                                        const OSSL_PARAM params[])
{
    ctx->encrypt = 1;
    

    return p_scossl_aes_init_internal(ctx, key, keylen, iv, ivlen, params);
}

SCOSSL_STATUS p_scossl_aes_decrypt_init(SCOSSL_AES_CTX *ctx,
                                        const unsigned char *key, size_t keylen,
                                        const unsigned char *iv, size_t ivlen,
                                        const OSSL_PARAM params[])
{
    ctx->encrypt = 0;
    

    return p_scossl_aes_init_internal(ctx, key, keylen, iv, ivlen, params);
}

SCOSSL_STATUS p_scossl_aes_update(SCOSSL_AES_CTX *ctx,
                                  unsigned char *out, size_t *outl, size_t outsize,
                                  const unsigned char *in, size_t inl)
{
    size_t outl_int = 0;
    size_t cBlocksRemaining = 0;

    // Data from previous update in buffer. Try to fill buffer and
    // encrypt/decrypt before moving to remaining data.
    if (ctx->cbBuf > 0)
    {
        fill_buffer(ctx->buf, &ctx->cbBuf, in, &inl);
    }

    // First encrypt the buffer if it is filled
    if (ctx->cbBuf == SYMCRYPT_AES_BLOCK_SIZE)
    {
        if (outsize < SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        if (!ctx->cipher(&ctx->key, ctx->pbChainingValue, ctx->encrypt, out, NULL, ctx->buf, ctx->cbBuf))
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

        if (!ctx->cipher(&ctx->key, ctx->pbChainingValue, ctx->encrypt, out, NULL, in, cBlocksRemaining * SYMCRYPT_AES_BLOCK_SIZE))
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
        !buffer_trailing_data(ctx->buf, &ctx->cbBuf, in, &inl))
    {
        return SCOSSL_FAILURE;
    }

    *outl = outl_int;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_final(SCOSSL_AES_CTX *ctx,
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
        if (!ctx->cipher(&ctx->key, ctx->pbChainingValue, ctx->encrypt, out, outl, ctx->buf, ctx->cbBuf))
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
    if (!ctx->cipher(&ctx->key, ctx->pbChainingValue, ctx->encrypt, out_int, &outl_int, ctx->buf, ctx->cbBuf))
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

SCOSSL_STATUS p_scossl_aes_cipher(SCOSSL_AES_CTX *ctx,
                                  unsigned char *out, size_t *outl, size_t outsize,
                                  const unsigned char *in, size_t inl)
{
    return ctx->cipher(&ctx->key, ctx->pbChainingValue, ctx->encrypt, out, outl, in, inl);
}

/* Cipher parameter descriptors */
const OSSL_PARAM *p_scossl_cipher_gettable_params(void *provctx)
{
    return p_scossl_cipher_param_types;
}

/* Cipher operation parameter descriptors */
const OSSL_PARAM *p_scossl_cipher_gettable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_cipher_gettable_ctx_param_types;
}
const OSSL_PARAM *p_scossl_cipher_settable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_cipher_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_cipher_get_params(_Inout_ OSSL_PARAM params[], unsigned int mode, size_t keylen, size_t ivlen, unsigned int flags)
{
    
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen << 3))
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
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_BLOCK_SIZE))
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

/* Cipher operation parameters */
SCOSSL_STATUS p_scossl_aes_get_ctx_params(SCOSSL_AES_CTX *ctx, OSSL_PARAM params[])
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

SCOSSL_STATUS p_scossl_aes_set_ctx_params(SCOSSL_AES_CTX *ctx, const OSSL_PARAM params[])
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

static SCOSSL_STATUS scossl_aes_cbc_cipher(_In_ SYMCRYPT_AES_EXPANDED_KEY *key,
                                           _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE) PBYTE pbChainingValue,
                                           int encrypt,
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

static SCOSSL_STATUS scossl_aes_ecb_cipher(_In_ SYMCRYPT_AES_EXPANDED_KEY *key,
                                           _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE) PBYTE pbChainingValue,
                                           int encrypt,
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

IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(128, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(192, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(256, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)

IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(128, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(192, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER_FUNCTIONS(256, 0, ecb, ECB, 0)

// extern const OSSL_DISPATCH p_scossl_aes128gcm_functions[]; IMPLEMENT_aead_cipher, static IV length
// extern const OSSL_DISPATCH p_scossl_aes192gcm_functions[]; IMPLEMENT_aead_cipher, static IV length
// extern const OSSL_DISPATCH p_scossl_aes256gcm_functions[]; IMPLEMENT_aead_cipher, static IV length

// extern const OSSL_DISPATCH p_scossl_aes128ccm_functions[]; IMPLEMENT_aead_cipher, settable IV
// extern const OSSL_DISPATCH p_scossl_aes192ccm_functions[]; IMPLEMENT_aead_cipher, settable IV
// extern const OSSL_DISPATCH p_scossl_aes256ccm_functions[]; IMPLEMENT_aead_cipher, settable IV

// extern const OSSL_DISPATCH p_scossl_aes256xts_functions[]; IMPLEMENT_cipher
// extern const OSSL_DISPATCH p_scossl_aes128xts_functions[]; IMPLEMENT_cipher