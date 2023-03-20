//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_aes.h"
#include "p_scossl_aes_xts.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
    SIZE_T keylen;

    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];

    BOOL encrypt;
} SCOSSL_AES_XTS_CTX;

static const OSSL_PARAM p_scossl_aes_xts_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_aes_xts_settable_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_aes_xts_set_ctx_params(_Inout_ SCOSSL_AES_XTS_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_AES_XTS_CTX *p_scossl_aes_xtx_newctx_internal(size_t keylen)
{
    SCOSSL_AES_XTS_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_AES_XTS_CTX));
    if (ctx != NULL)
    {
        ctx->keylen = keylen;
    }
    return ctx;
}

static SCOSSL_AES_XTS_CTX *p_scossl_aes_xts_dupctx(SCOSSL_AES_XTS_CTX *ctx)
{
    SCOSSL_AES_XTS_CTX *copy_ctx = OPENSSL_zalloc(sizeof(SCOSSL_AES_XTS_CTX));
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_AES_XTS_CTX));
    }
    return copy_ctx;
}

static void p_scossl_aes_xts_freectx(SCOSSL_AES_XTS_CTX *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_AES_XTS_CTX));
}

static SCOSSL_STATUS p_scossl_aes_xts_init_internal(_Inout_ SCOSSL_AES_XTS_CTX *ctx, BOOL encrypt,
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
        SYMCRYPT_ERROR scError = SymCryptXtsAesExpandKey(&ctx->key, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    if (iv != NULL)
    {
        if (ivlen != SCOSSL_XTS_IV_LENGTH)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->iv, iv, SCOSSL_XTS_IV_LENGTH);
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
    if( (inl % SYMCRYPT_AES_BLOCK_SIZE) != 0 )
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return SCOSSL_FAILURE;
    }

    // It appears that the EVP API for exposing AES-XTS does not allow definition of the size of
    // a data unit. My understanding is that callers are expected to make a single call through
    // the EVP interface per data unit - so we pass inl to both cbDataUnit and cbData.

    if(ctx->encrypt)
    {
        SymCryptXtsAesEncrypt(
            &ctx->key,
            inl,
            *(UINT64 *) ctx->iv,
            in,
            out,
            inl);
    }
    else
    {
        SymCryptXtsAesDecrypt(
            &ctx->key,
            inl,
            *(UINT64 *) ctx->iv,
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
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }    

    return p_scossl_aes_xts_cipher(ctx, out, outl, outsize, in, inl);
}

static SCOSSL_STATUS p_scossl_aes_xts_final(_Inout_ SCOSSL_AES_XTS_CTX *ctx,
                                            _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize)
{
    *outl = 0;

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_aes_xts_gettable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_aes_xts_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_aes_xts_settable_ctx_params(void *cctx, void *provctx)
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
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SCOSSL_XTS_IV_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, SCOSSL_XTS_IV_LENGTH) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, SCOSSL_XTS_IV_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, SCOSSL_XTS_IV_LENGTH) &&
        !OSSL_PARAM_set_octet_string(p, &ctx->iv, SCOSSL_XTS_IV_LENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_xts_set_ctx_params(_Inout_ SCOSSL_AES_XTS_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    // const OSSL_PARAM *p = NULL;

    return SCOSSL_SUCCESS;
}

IMPLEMENT_SCOSSL_AES_XTS_CIPHER(128)
IMPLEMENT_SCOSSL_AES_XTS_CIPHER(256)

#ifdef __cplusplus
}
#endif