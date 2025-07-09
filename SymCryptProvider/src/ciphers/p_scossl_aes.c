//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/prov_ssl.h>

#include "scossl_helpers.h"
#include "p_scossl_base.h"
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
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_generic_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_generic_settable_ctx_param_types[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
    OSSL_PARAM_END};

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

    OSSL_LIB_CTX *libctx;
    UINT tlsVersion;
    PBYTE tlsMac;
    SIZE_T tlsMacSize;

    OSSL_FUNC_cipher_cipher_fn *cipher;
} SCOSSL_AES_CTX;

static SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(_Inout_ SCOSSL_AES_CTX *ctx, _In_ const OSSL_PARAM params[]);

static void p_scossl_aes_generic_freectx(SCOSSL_AES_CTX *ctx)
{
    OPENSSL_free(ctx->tlsMac);
    SCOSSL_COMMON_ALIGNED_FREE(ctx, OPENSSL_clear_free, SCOSSL_AES_CTX);
}

static SCOSSL_AES_CTX *p_scossl_aes_generic_dupctx(SCOSSL_AES_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copyCtx, OPENSSL_malloc, SCOSSL_AES_CTX);
    if (copyCtx != NULL)
    {
        *copyCtx = *ctx;

        if (ctx->tlsMac != NULL &&
            (copyCtx->tlsMac = OPENSSL_memdup(ctx->tlsMac, ctx->tlsMacSize)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            p_scossl_aes_generic_freectx(copyCtx);
            return NULL;
        }

        SymCryptAesKeyCopy(&ctx->key, &copyCtx->key);
    }
    return copyCtx;
}

static SCOSSL_STATUS p_scossl_aes_generic_init_internal(_Inout_ SCOSSL_AES_CTX *ctx, BOOL encrypt,
                                                        _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                        _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                        _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;

    ctx->encrypt = encrypt;
    ctx->cbBuf = 0;

    if (key != NULL)
    {
        if (keylen != ctx->keylen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptAesExpandKey(&ctx->key, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptAesExpandKey failed", scError);
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
    return p_scossl_aes_generic_init_internal(ctx, TRUE, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_generic_decrypt_init(_Inout_ SCOSSL_AES_CTX *ctx,
                                                       _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                       _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                       _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_generic_init_internal(ctx, FALSE, key, keylen, iv, ivlen, params);
}

#define SYMCRYPT_OPENSSL_MASK8_SELECT( _mask, _a, _b ) (SYMCRYPT_FORCE_READ8(&_mask) & _a) | (~(SYMCRYPT_FORCE_READ8(&_mask)) & _b)

// Verifies the TLS padding from the end of record, extracts the MAC from the end of
// the unpadded record, and saves the result to ctx->tlsMac.
//
// The MAC will later be fetched through p_scossl_aes_generic_get_ctx_params
// This function is adapted from ssl3_cbc_copy_mac in ssl/record/tls_pad.c, and 
// SymCryptTlsCbcHmacVerifyCore from SymCrypt, and runs in constant time w.r.t
// the values in pbData. In case of bad padding, a random MAC is assigned instead
static SCOSSL_STATUS p_scossl_aes_tls_remove_padding_and_copy_mac(
    _Inout_ SCOSSL_AES_CTX *ctx,
    _In_reads_bytes_(*pcbData) unsigned char *pbData,
    _Inout_ SIZE_T *pcbData)
{
    SIZE_T cbDataOrig = *pcbData;
    unsigned const char * pbTail = pbData;
    UINT32 cbTail = (UINT32)cbDataOrig;
    UINT32 u32;
    UINT32 cbPad;
    UINT32 maxPadLength;

    // MAC rotation is performed in place
    BYTE rotatedMacBuf[64 + EVP_MAX_MD_SIZE];
    PBYTE rotatedMac;
    BYTE randMac[EVP_MAX_MD_SIZE];
    BYTE paddingStatus = 0; // 0x00 for valid padding, 0xff for bad padding

    UINT32 macEnd; // index in pbTail
    UINT32 macStart; // index in pbTail
    UINT32 inMac = 0;

    UINT32 rotateOffset = 0;
    UINT32 i, j;

    OPENSSL_free(ctx->tlsMac);
    ctx->tlsMac = NULL;

    // Check that we have enough data for a valid record.
    // We need one MAC value plus one padding_length byte
    if (cbDataOrig < ctx->tlsMacSize + 1)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }

    // Generate random bytes in case of bad padding
    if (RAND_bytes_ex(ctx->libctx, randMac, ctx->tlsMacSize, 0) <= 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((ctx->tlsMac = OPENSSL_malloc(ctx->tlsMacSize)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }

    // We only care about the tail of the input buffer, which we can index with UINT32 indices
    // The if() is safe as both cbData and u32 are public values.
    u32 = ctx->tlsMacSize + 255 + 1;
    if( cbDataOrig > u32 )
    {
        pbTail += cbDataOrig - u32;
        cbTail = u32;
    }

    // Pick up the padding_length. Note that this is the value we have to keep secret from
    // side-channel attacks.
    cbPad = pbTail[cbTail - 1]; // cbPad in range [0,255]

    // Bound the padding length to cbTail - tlsMacSize
    // This doesn't reveal data as we treat all cbPad values the same, but it makes our
    // further computations easier
    maxPadLength = (UINT32)cbTail - ctx->tlsMacSize;    // We checked this is >= 0
    u32 = SYMCRYPT_MASK32_LT( maxPadLength, cbPad );    // mask: maxPadLength < cbPad
    cbPad = cbPad + ((maxPadLength - cbPad) & u32);
    paddingStatus |= (BYTE)u32; // validation fails if the padding would overlap with the MAC

    macEnd = (cbTail - 1) - cbPad;
    macStart = macEnd - ctx->tlsMacSize;

    rotatedMac = rotatedMacBuf + ((0 - (SIZE_T)rotatedMacBuf) & 0x3f);
    
    // Find and extract MAC, and verify padding
    memset(rotatedMac, 0, ctx->tlsMacSize);
    for (i = 0, j = 0; i < cbTail-1; i++)
    {
        UINT32 macStarted = SYMCRYPT_MASK32_EQ(i, macStart);
        UINT32 macNotEnded = SYMCRYPT_MASK32_LT(i, macEnd);
        BYTE recordByte = pbTail[i];

        inMac = (inMac | macStarted) & macNotEnded;
        rotateOffset |= j & macStarted;
        rotatedMac[j++] |= recordByte & inMac;
        j &= SYMCRYPT_MASK32_LT(j, ctx->tlsMacSize);

        paddingStatus |= (BYTE)((~SYMCRYPT_MASK32_EQ(recordByte, cbPad)) & (~macNotEnded));
    }

    // MAC rotation
    for (i = 0; i < ctx->tlsMacSize; i++)
    {
        BYTE macByte = 0;
        for (j = 0; j < ctx->tlsMacSize; j++) {
            UINT32 match = SYMCRYPT_MASK32_EQ(j, (rotateOffset + i) % ctx->tlsMacSize);
            macByte |= rotatedMac[j] & match;
        }
        ctx->tlsMac[i] = SYMCRYPT_OPENSSL_MASK8_SELECT(paddingStatus, randMac[i], macByte);
    }

    *pcbData -= (1 + cbPad + ctx->tlsMacSize);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_tls_add_padding(const unsigned char *in, size_t inl, unsigned char *out, size_t outsize, size_t *outlen)
{
    // TLS padding with 1-16 bytes, each with value (cbPad-1)
    SIZE_T cbPad = SYMCRYPT_AES_BLOCK_SIZE - (inl & (SYMCRYPT_AES_BLOCK_SIZE-1));

    if (inl + cbPad > outsize)
    {
        return SCOSSL_FAILURE; // Buffer too small
    }

    if (in != out)
    {
        memmove(out, in, inl);
    }

    memset(out + inl, (unsigned char)(cbPad - 1), cbPad);
    *outlen = inl + cbPad;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_block_update(_Inout_ SCOSSL_AES_CTX *ctx,
                                                       _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                                       _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SIZE_T cbInFullBlocks = 0;
    *outl = 0;

    if (inl == 0)
    {
        return SCOSSL_SUCCESS;
    }

    if (ctx->tlsVersion > 0)
    {
        // Each update call corresponds to a TLS record and is individually padded
        if (in == NULL ||
            in != out ||
            outsize < inl ||
            !ctx->pad)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        if (ctx->encrypt)
        {
            // in == out
            p_scossl_aes_tls_add_padding(
                in, inl,
                out, outsize, &inl);
        }

        if (inl % SYMCRYPT_AES_BLOCK_SIZE != 0 ||
            !ctx->cipher(ctx, out, outl, outsize, in, inl))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return SCOSSL_FAILURE;
        }

        // Need to remove TLS padding and MAC in constant time
        if (!ctx->encrypt)
        {
            switch (ctx->tlsVersion)
            {
            // Need to remove explicit IV in addition to TLS padding and MAC
            case TLS1_2_VERSION:
            case DTLS1_2_VERSION:
            case TLS1_1_VERSION:
            case DTLS1_VERSION:
            case DTLS1_BAD_VER:
                out += SYMCRYPT_AES_BLOCK_SIZE;
                *outl -= SYMCRYPT_AES_BLOCK_SIZE;
                __attribute__ ((fallthrough));
            case TLS1_VERSION:
                return p_scossl_aes_tls_remove_padding_and_copy_mac(ctx, out, outl);
                break;
            default:
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return SCOSSL_FAILURE;
            }
        }

        // Return SCOSSL_FAILURE for any code that isn't SYMCRYPT_NO_ERROR
        return SCOSSL_SUCCESS;
    }

    // Data from previous update in buffer. Try to fill buffer and
    // encrypt/decrypt before moving to remaining data.
    if (ctx->cbBuf > 0)
    {
        // The buffer may already be full for padded decrypt
        if (ctx->cbBuf < SYMCRYPT_AES_BLOCK_SIZE)
        {
            SIZE_T cbBufRemaining = SYMCRYPT_AES_BLOCK_SIZE - ctx->cbBuf;
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

        // Encrypt/decrypt the buffer it it's full. If we're decrypting
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
            *outl += SYMCRYPT_AES_BLOCK_SIZE;
            outsize -= SYMCRYPT_AES_BLOCK_SIZE;
            ctx->cbBuf = 0;

            SymCryptWipeKnownSize(ctx->buf, SYMCRYPT_AES_BLOCK_SIZE);
        }
    }

    // Get the remaining number of whole blocks in inl
    cbInFullBlocks = inl & ~(SYMCRYPT_AES_BLOCK_SIZE-1);

    // Decrypt with padding. Ensure the last block is buffered
    // for the call to cipher_final so padding is removed
    if (!ctx->encrypt &&
        ctx->pad &&
        cbInFullBlocks > 0 &&
        cbInFullBlocks == inl)
    {
        cbInFullBlocks -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    // in still contains whole blocks, encrypt available blocks
    if (cbInFullBlocks > 0)
    {
        if (!ctx->cipher(ctx, out, NULL, outsize, in, cbInFullBlocks))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        in += cbInFullBlocks;
        inl -= cbInFullBlocks;
        *outl += cbInFullBlocks;
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

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_stream_update(_Inout_ SCOSSL_AES_CTX *ctx,
                                                        _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                                        _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (inl == 0)
    {
        *outl = 0;
        return SCOSSL_SUCCESS;
    }

    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    if (!ctx->cipher(ctx, out, outl, outsize, in, inl))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }

    if (!ctx->encrypt &&
        ctx->tlsVersion > 0 &&
        ctx->tlsMacSize > 0)
    {
        if (ctx->tlsMacSize > *outl)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return SCOSSL_FAILURE;
        }

        ctx->tlsMac = out + (*outl - ctx->tlsMacSize);
        *outl -= ctx->tlsMacSize;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_block_final(_Inout_ SCOSSL_AES_CTX *ctx,
                                                      _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize)
{
    if (ctx->tlsVersion > 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    // Unpadded case
    if (!ctx->pad)
    {
        if (ctx->cbBuf != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return SCOSSL_FAILURE;
        }

        *outl = 0;
        return SCOSSL_SUCCESS;
    }

    if (outsize < SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    // The return value of SymCryptPaddingPkcs7Remove must be mapped in a
    // side-channel safe way with SymCryptMapUint32. For all other failure
    // cases scError is just set to 1 so it maps to SCOSSL_FAILURE
    SYMCRYPT_ERROR scError = 1;
    SYMCRYPT_UINT32_MAP scErrorMap[1] = {
        {SYMCRYPT_NO_ERROR, SCOSSL_SUCCESS}};

    // Add padding for encrypt
    if (ctx->encrypt)
    {
        if (ctx->cbBuf >= SYMCRYPT_AES_BLOCK_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            goto cleanup;
        }

        SymCryptPaddingPkcs7Add(
            SYMCRYPT_AES_BLOCK_SIZE,
            ctx->buf, ctx->cbBuf,
            ctx->buf, SYMCRYPT_AES_BLOCK_SIZE,
            &ctx->cbBuf);
    }

    if (ctx->cbBuf != SYMCRYPT_AES_BLOCK_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        goto cleanup;
    }

    if (!ctx->cipher(ctx, out, outl, SYMCRYPT_AES_BLOCK_SIZE, ctx->buf, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        goto cleanup;
    }

    // Remove padding for decrypt. The results of this operation should
    // not be checked, rather mapped to error/success in a side-channel
    // safe way.
    if (!ctx->encrypt)
    {
        scError = SymCryptPaddingPkcs7Remove(
            SYMCRYPT_AES_BLOCK_SIZE,
            out, SYMCRYPT_AES_BLOCK_SIZE,
            out, SYMCRYPT_AES_BLOCK_SIZE,
            outl);
    }
    else
    {
        scError = SYMCRYPT_NO_ERROR;
    }

cleanup:
    ctx->cbBuf = 0;
    SymCryptWipeKnownSize(ctx->buf, SYMCRYPT_AES_BLOCK_SIZE);

    // Return SCOSSL_FAILURE for any code that isn't SYMCRYPT_NO_ERROR
    return SymCryptMapUint32(scError, SCOSSL_FAILURE, scErrorMap, 1);
}

static SCOSSL_STATUS p_scossl_aes_generic_stream_final(ossl_unused SCOSSL_AES_CTX *ctx,
                                                       ossl_unused unsigned char *out, ossl_unused size_t *outl, ossl_unused size_t outsize)
{
    *outl = 0;
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                                 _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                                 _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (!ctx->cipher(ctx, out, outl, outsize, in, inl))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
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

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL &&
        !OSSL_PARAM_set_uint(p, mode))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ivlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, block_size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL &&
        !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_AEAD ? 1 : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) != NULL &&
        !OSSL_PARAM_set_int(p, flags & SCOSSL_FLAG_CUSTOM_IV ? 1 : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS)) != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK)) != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY)) != NULL &&
        !OSSL_PARAM_set_int(p, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_get_ctx_params(_In_ SCOSSL_AES_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV)) != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV)) != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC)) != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, ctx->tlsMac, ctx->tlsMacSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_generic_set_ctx_params(_Inout_ SCOSSL_AES_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING)) != NULL)
    {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
        ctx->pad = pad != 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION)) != NULL)
    {
        UINT tlsVersion;
        if (!OSSL_PARAM_get_uint(p, &tlsVersion))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (tlsVersion == SSL3_VERSION)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }

        ctx->tlsVersion = tlsVersion;
    }


    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE)) != NULL)
    {
        SIZE_T tlsMacSize;

        if (!OSSL_PARAM_get_size_t(p, &tlsMacSize))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (ctx->tlsMacSize > EVP_MAX_MD_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            return SCOSSL_FAILURE;
        }

        ctx->tlsMacSize = tlsMacSize;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_cbc_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                           _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_opt_ size_t *outl, size_t outsize,
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
                                           _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_opt_ size_t *outl, size_t outsize,
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

static SCOSSL_STATUS p_scossl_aes_cfb_cipher_internal(_Inout_ SCOSSL_AES_CTX *ctx, SIZE_T cbShift,
                                                      _Inout_updates_(SYMCRYPT_AES_BLOCKSIZE) PBYTE pbChainingValue,
                                                      _Out_writes_bytes_(*outl) unsigned char *out, _Out_opt_ size_t *outl, size_t outsize,
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
        SymCryptCfbEncrypt(SymCryptAesBlockCipher, cbShift, &ctx->key, pbChainingValue, in, out, inl);
    }
    else
    {
        SymCryptCfbDecrypt(SymCryptAesBlockCipher, cbShift, &ctx->key, pbChainingValue, in, out, inl);
    }

    return SCOSSL_SUCCESS;
}

// AES-CFB requires some special buffering logic due to implementation
// differences between OpenSSL and SymCrypt. SymCrypt will only encrypt
// in multiples of the shift size, but OpenSSL expects the entirety of
// inl to be encrypted in each update call. e.g. if inl is 36, SymCrypt
// will only encrypt 32 bytes, but OpenSSL expects 36 bytes to be encrypted.
// To handle this, any remaining data is buffered, and the previous chaining
// value is saved for the next call. If any data is in the buffer from a
// previous call, the remaining space in the buffer is filled and
// encrypted/decrypted with the previous chaining value before continuing.
static SCOSSL_STATUS scossl_aes_cfb_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                           _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_opt_ size_t *outl, size_t outsize,
                                           _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    BYTE pbPartialBufOut[SYMCRYPT_AES_BLOCK_SIZE];
    BYTE pbChainingValueLast[SYMCRYPT_AES_BLOCK_SIZE];
    SIZE_T cbBufRemaining;
    SIZE_T cbInFullBlocks;
    SIZE_T cbInRemaining;

    if (outl != NULL)
    {
        *outl = inl;
    }

    if (ctx->cbBuf > 0)
    {
        // Last update call was a partial block. Fill buffer and perform cipher
        // with previous chaining value before continuing.
        cbBufRemaining = SYMCRYPT_MIN(SYMCRYPT_AES_BLOCK_SIZE - ctx->cbBuf, inl);

        // Save the chaining value for the next call in case ctx->cbBuf + inl < cbBufRemaining
        memcpy(pbChainingValueLast, ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE);
        memcpy(ctx->buf + ctx->cbBuf, in, cbBufRemaining);

        if (p_scossl_aes_cfb_cipher_internal(
                ctx,
                SYMCRYPT_AES_BLOCK_SIZE,
                ctx->pbChainingValue,
                pbPartialBufOut, NULL, SYMCRYPT_AES_BLOCK_SIZE,
                ctx->buf, SYMCRYPT_AES_BLOCK_SIZE) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }

        memcpy(out, pbPartialBufOut + ctx->cbBuf, cbBufRemaining);

        // Advance pointers and counters
        out += cbBufRemaining;
        outsize -= cbBufRemaining;

        in += cbBufRemaining;
        inl -= cbBufRemaining;

        ctx->cbBuf += cbBufRemaining;
        if (ctx->cbBuf == SYMCRYPT_AES_BLOCK_SIZE)
        {
            ctx->cbBuf = 0;
            SymCryptWipeKnownSize(ctx->buf, SYMCRYPT_AES_BLOCK_SIZE);
        }
        else
        {
            memcpy(ctx->pbChainingValue, pbChainingValueLast, SYMCRYPT_AES_BLOCK_SIZE);
        }
    }

    cbInFullBlocks = inl & ~(SYMCRYPT_AES_BLOCK_SIZE-1);
    cbInRemaining = inl - cbInFullBlocks;

    if (cbInFullBlocks > 0)
    {
        if (ctx->cbBuf != 0)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Unexpected partial block in buffer");
            return SCOSSL_FAILURE;
        }

        if (p_scossl_aes_cfb_cipher_internal(
                ctx,
                SYMCRYPT_AES_BLOCK_SIZE,
                ctx->pbChainingValue,
                out, NULL, outsize,
                in, cbInFullBlocks) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }
    }

    if (cbInRemaining > 0)
    {
        // Encrypt any extra bytes and save the chaining value for the next call
        memcpy(pbChainingValueLast, ctx->pbChainingValue, SYMCRYPT_AES_BLOCK_SIZE);

        memcpy(ctx->buf, in + cbInFullBlocks, cbInRemaining);
        ctx->cbBuf = cbInRemaining;

        out += cbInFullBlocks;
        outsize -= cbInFullBlocks;

        if (p_scossl_aes_cfb_cipher_internal(
            ctx,
            SYMCRYPT_AES_BLOCK_SIZE,
            ctx->pbChainingValue,
            pbPartialBufOut, NULL, SYMCRYPT_AES_BLOCK_SIZE,
            ctx->buf, SYMCRYPT_AES_BLOCK_SIZE) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }

        memcpy(out, pbPartialBufOut, ctx->cbBuf);

        // Since this was a partial block, the next update call will fill the buffer
        // and encrypt/decrypt with the same chaining value
        memcpy(ctx->pbChainingValue, pbChainingValueLast, SYMCRYPT_AES_BLOCK_SIZE);
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_cfb8_cipher(_Inout_ SCOSSL_AES_CTX *ctx,
                                            _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                            _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return p_scossl_aes_cfb_cipher_internal(ctx, 1, ctx->pbChainingValue, out, outl, outsize, in, inl);
}

#define IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(kbits, ivlen, lcmode, UCMODE, type, blocksize)                \
    SCOSSL_AES_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx(_In_ SCOSSL_PROVCTX *provctx)                \
    {                                                                                                     \
        SCOSSL_COMMON_ALIGNED_ALLOC(ctx, OPENSSL_malloc, SCOSSL_AES_CTX);                                 \
        if (ctx != NULL)                                                                                  \
        {                                                                                                 \
            ctx->keylen = kbits >> 3;                                                                     \
            ctx->pad = TRUE;                                                                              \
            ctx->cipher = (OSSL_FUNC_cipher_cipher_fn *)&scossl_aes_##lcmode##_cipher;                    \
            ctx->libctx = provctx->libctx;                                                                \
            ctx->tlsMac = NULL;                                                                           \
            ctx->tlsMacSize = 0;                                                                          \
            ctx->tlsVersion = 0;                                                                          \
        }                                                                                                 \
                                                                                                          \
        return ctx;                                                                                       \
    }                                                                                                     \
    SCOSSL_STATUS p_scossl_aes_##kbits##_##lcmode##_get_params(_Inout_ OSSL_PARAM params[])               \
    {                                                                                                     \
        return p_scossl_aes_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, kbits >> 3,              \
                                               ivlen, blocksize, 0);                                      \
    }                                                                                                     \
                                                                                                          \
    const OSSL_DISPATCH p_scossl_aes##kbits##lcmode##_functions[] = {                                     \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_newctx},              \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_generic_dupctx},                           \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_generic_freectx},                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_generic_encrypt_init},               \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_generic_decrypt_init},               \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_generic_##type##_update},                  \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_generic_##type##_final},                    \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_generic_cipher},                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_##lcmode##_get_params},      \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_get_ctx_params},           \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_set_ctx_params},           \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_params},         \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_aes_generic_settable_ctx_params}, \
        {0, NULL}};

IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(128, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, block, SYMCRYPT_AES_BLOCK_SIZE)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(192, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, block, SYMCRYPT_AES_BLOCK_SIZE)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(256, SYMCRYPT_AES_BLOCK_SIZE, cbc, CBC, block, SYMCRYPT_AES_BLOCK_SIZE)

IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(128, 0, ecb, ECB, block, SYMCRYPT_AES_BLOCK_SIZE)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(192, 0, ecb, ECB, block, SYMCRYPT_AES_BLOCK_SIZE)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(256, 0, ecb, ECB, block, SYMCRYPT_AES_BLOCK_SIZE)

IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(128, SYMCRYPT_AES_BLOCK_SIZE, cfb, CFB, stream, 1)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(192, SYMCRYPT_AES_BLOCK_SIZE, cfb, CFB, stream, 1)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(256, SYMCRYPT_AES_BLOCK_SIZE, cfb, CFB, stream, 1)

IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(128, SYMCRYPT_AES_BLOCK_SIZE, cfb8, CFB, stream, 1)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(192, SYMCRYPT_AES_BLOCK_SIZE, cfb8, CFB, stream, 1)
IMPLEMENT_SCOSSL_AES_GENERIC_CIPHER(256, SYMCRYPT_AES_BLOCK_SIZE, cfb8, CFB, stream, 1)

#ifdef __cplusplus
}
#endif