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

typedef struct
{
    SYMCRYPT_AES_EXPANDED_KEY key;
    SIZE_T keylen;

    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];
    BYTE pbChainingValue[SYMCRYPT_AES_BLOCK_SIZE];
    INT32 encrypt;
    INT32 pad;

    // Provider is responsible for buffering
    // incomplete blocks in update calls
    BYTE buf[SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T cbBuf;

    OSSL_FUNC_cipher_cipher_fn *cipher;
} SCOSSL_AES_CTX;

static SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(_Inout_ SCOSSL_AES_CTX *ctx, _In_ const OSSL_PARAM params[]);

static void p_scossl_aes_generic_freectx(SCOSSL_AES_CTX *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_AES_CTX));
}

static SCOSSL_AES_CTX *p_scossl_aes_generic_dupctx(SCOSSL_AES_CTX *ctx)
{
    SCOSSL_AES_CTX *copy_ctx = OPENSSL_malloc(sizeof(SCOSSL_AES_CTX));
    if (copy_ctx != NULL)
    { 
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_AES_CTX));
        SymCryptAesKeyCopy(&ctx->key, &copy_ctx->key);
    }
    return copy_ctx;
}

static SCOSSL_STATUS p_scossl_aes_generic_init_internal(_Inout_ SCOSSL_AES_CTX *ctx, INT32 encrypt,
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

static SCOSSL_STATUS p_scossl_aes_generic_encrypt_init(_Inout_ SCOSSL_AES_CTX *ctx,
                                                       _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                       _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                       _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_generic_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_generic_decrypt_init(_Inout_ SCOSSL_AES_CTX *ctx,
                                                       _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                       _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                       _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_generic_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_generic_update(_Inout_ SCOSSL_AES_CTX *ctx,
                                                 _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                                 _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    size_t outl_int = 0;
    size_t cbBytesInFullBlocks = 0;

    // Data from previous update in buffer. Try to fill buffer and
    // encrypt/decrypt before moving to remaining data.
    if (ctx->cbBuf > 0)
    {
        size_t cbBufRemaining = SYMCRYPT_AES_BLOCK_SIZE - ctx->cbBuf;
        if (inl < cbBufRemaining)
        {
            cbBufRemaining = inl;
        }
        memcpy(ctx->buf + ctx->cbBuf, in, cbBufRemaining);

        // Advance in
        ctx->cbBuf += cbBufRemaining;
        in += cbBufRemaining;
        inl -= cbBufRemaining;
    }

    // First encrypt the buffer if it is filled. If we're decrypting
    // with padding, then keep the last block in the buffer for the
    // call to cipher_final
    if (ctx->cbBuf == SYMCRYPT_AES_BLOCK_SIZE &&
        (ctx->encrypt || !ctx->pad || inl > 0))
    {
        if (!ctx->cipher(ctx, out, NULL, outsize, ctx->buf, ctx->cbBuf))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        out += SYMCRYPT_AES_BLOCK_SIZE;
        outl_int += SYMCRYPT_AES_BLOCK_SIZE;
        ctx->cbBuf = 0;
    }

    // Get the remaining number of whole blocks in inl
    cbBytesInFullBlocks = inl & ~(SYMCRYPT_AES_BLOCK_SIZE-1);

    // Decrypt with padding. Ensure the last block is buffered
    // for the call to cipher_final so padding is removed
    if (!ctx->encrypt && ctx->pad && cbBytesInFullBlocks * SYMCRYPT_AES_BLOCK_SIZE == inl)
    {
        cbBytesInFullBlocks--;
    }   

    // in still contains whole blocks, encrypt available blocks
    if (cbBytesInFullBlocks > 0)
    {
        outl_int += cbBytesInFullBlocks;
        // Need to verify outsize here is not smaller than the 
        // result of the entire update operation
        if (outsize < outl_int)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        if (!ctx->cipher(ctx, out, NULL, outsize, in, cbBytesInFullBlocks))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        in += cbBytesInFullBlocks;
        inl -= cbBytesInFullBlocks;
    }

    // Buffer any remaining data
    if (inl > 0)
    {
        // Ensure trailing remaining data is 
        // - less than one block for encryption or unpadded decryption
        // - less than or equal to one block for padded decryption
        if (inl > SYMCRYPT_AES_BLOCK_SIZE ||
            (inl == SYMCRYPT_AES_BLOCK_SIZE && (ctx->encrypt || !ctx->pad)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }
        memcpy(ctx->buf, in, inl);
        ctx->cbBuf += inl;
    }
    
    // Buffer must have some data in it for padded decryption
    if (!ctx->encrypt && ctx->pad && ctx->cbBuf == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }
    *outl = outl_int;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_final(_Inout_ SCOSSL_AES_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize)
{
    unsigned char out_int[SYMCRYPT_AES_BLOCK_SIZE];
    size_t outl_int;

    // The return value of SymCryptPaddingPkcs7Remove must be mapped in a
    // side-channel safe way with SymCryptMapUint32. For all other failure
    // cases scError is just set to 1 so it maps to SCOSSL_FAILURE
    SYMCRYPT_ERROR scError = 1;
    SYMCRYPT_UINT32_MAP scErrorMap[1] = {
        {SYMCRYPT_NO_ERROR, SCOSSL_SUCCESS}};

    // Encrypt final
    if (ctx->encrypt)
    {
        // Pad
        if (ctx->pad && ctx->cbBuf < SYMCRYPT_AES_BLOCK_SIZE)
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
                goto cleanup;
            }
        }
        else if (ctx->cbBuf == 0)
        {
            *outl = 0;
            scError = SYMCRYPT_NO_ERROR;
            goto cleanup;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            goto cleanup;
        }

        if (!ctx->cipher(ctx, out, outl, outsize, ctx->buf, ctx->cbBuf))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            goto cleanup;
        }

        scError = SYMCRYPT_NO_ERROR;
        goto cleanup;
    }

    // Decrypt final
    if (!ctx->pad && ctx->cbBuf == 0)
    {
        *outl = 0;
        scError = SYMCRYPT_NO_ERROR;
        goto cleanup;
    }
    else if (ctx->cbBuf != SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        goto cleanup;
    }

    if (!ctx->cipher(ctx, out_int, &outl_int, SYMCRYPT_AES_BLOCK_SIZE, ctx->buf, ctx->cbBuf))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        goto cleanup;
    }

    if (ctx->pad)
    {
        scError = SymCryptPaddingPkcs7Remove(
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
        goto cleanup;
    }

    memcpy(out, out_int, outl_int);
    *outl = outl_int;

cleanup:
    ctx->cbBuf = 0;

    SymCryptWipeKnownSize(out_int, SYMCRYPT_AES_BLOCK_SIZE);
    SymCryptWipeKnownSize(ctx->buf, SYMCRYPT_AES_BLOCK_SIZE);

    // Return SCOSSL_FAILURE for any code that isn't SYMCRYPT_NO_ERROR
    return SymCryptMapUint32(scError, SCOSSL_FAILURE, scErrorMap, 1) ;
}

static SCOSSL_STATUS p_scossl_aes_generic_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                                 _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                                 _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return ctx->cipher(ctx, out, outl, outsize, in, inl);
}

const OSSL_PARAM *p_scossl_aes_generic_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_aes_generic_param_types;
}

static const OSSL_PARAM *p_scossl_aes_generic_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_generic_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_aes_generic_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
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
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block_size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_AEAD ? 1 : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_CUSTOM_IV ? 1 : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_get_ctx_params(_In_ SCOSSL_AES_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(_Inout_ SCOSSL_AES_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL)
    {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
        ctx->pad = pad ? 1 : 0;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_cbc_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                           _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                           _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    if (outl != NULL)
    {
        *outl = inl;
    }

    if (ctx->encrypt)
    {
        SymCryptAesCbcEncrypt(&ctx->key, ctx->pbChainingValue, in, out, inl);
    }
    else
    {
        SymCryptAesCbcDecrypt(&ctx->key, ctx->pbChainingValue, in, out, inl);
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_ecb_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                           _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                           _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    if (outl != NULL)
    {
        *outl = inl;
    }

    if (ctx->encrypt)
    {
        SymCryptAesEcbEncrypt(&ctx->key, in, out, inl);
    }
    else
    {
        SymCryptAesEcbDecrypt(&ctx->key, in, out, inl);
    }

    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_AES_CIPHER(kbits, ivlen, lcmode, UCMODE, flags)                                  \
    SCOSSL_AES_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx()                                            \
    {                                                                                                     \
        SCOSSL_AES_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_AES_CTX));                                     \
        if (ctx != NULL)                                                                                  \
        {                                                                                                 \
            ctx->keylen = kbits >> 3;                                                                     \
            ctx->pad = 1;                                                                                 \
            ctx->cipher = (OSSL_FUNC_cipher_cipher_fn*)&scossl_aes_##lcmode##_cipher;                     \
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

IMPLEMENT_SCOSSL_AES_CIPHER(128, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(192, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(256, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, 0)

IMPLEMENT_SCOSSL_AES_CIPHER(128, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(192, 0, ecb, ECB, 0)
IMPLEMENT_SCOSSL_AES_CIPHER(256, 0, ecb, ECB, 0)

#ifdef __cplusplus
}
#endif