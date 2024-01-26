//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_aes_aead.h"
#include "p_scossl_aes.h"

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_aes_gcm_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
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
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
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

static SCOSSL_STATUS p_scossl_aes_gcm_set_ctx_params(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, _In_ const OSSL_PARAM params[]);
static SCOSSL_STATUS p_scossl_aes_ccm_set_ctx_params(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, _In_ const OSSL_PARAM params[]);

/*
 * AES-GCM Implementation
 */
static SCOSSL_CIPHER_GCM_CTX *p_scossl_aes_gcm_dupctx(_In_ SCOSSL_CIPHER_GCM_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copy_ctx, OPENSSL_malloc, SCOSSL_CIPHER_GCM_CTX);
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_CIPHER_GCM_CTX));

        if (ctx->operationInProgress)
        {
            SymCryptGcmStateCopy(&ctx->state, &copy_ctx->key, &copy_ctx->state);
        }
        SymCryptGcmKeyCopy(&ctx->key, &copy_ctx->key);
    }
    return copy_ctx;
}

static void p_scossl_aes_gcm_freectx(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_FREE(ctx, OPENSSL_clear_free, SCOSSL_CIPHER_GCM_CTX);
}

static SCOSSL_STATUS p_scossl_aes_gcm_init_internal(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                                    _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                    _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                    _In_ const OSSL_PARAM params[])
{
    if (key && keylen != ctx->keylen)
    {
        return SCOSSL_FAILURE;
    }

    ctx->encrypt = encrypt;

    return scossl_aes_gcm_init_key(ctx, key, keylen, iv, ivlen) &&
           p_scossl_aes_gcm_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_encrypt_init(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_gcm_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_decrypt_init(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_gcm_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_final(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                            _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, ossl_unused size_t outsize)
{
    return scossl_aes_gcm_cipher(ctx, ctx->encrypt, out, outl, NULL, 0);
}

static SCOSSL_STATUS p_scossl_aes_gcm_cipher(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                             _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                             _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    return scossl_aes_gcm_cipher(ctx, ctx->encrypt, out, outl, in, inl);
}

static const OSSL_PARAM *p_scossl_aes_gcm_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_gcm_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_aes_gcm_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_gcm_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_aes_gcm_get_ctx_params(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->taglen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tlsAadSet ? EVP_GCM_TLS_TAG_LEN : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL)
    {
        if (p->data_size < ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL)
    {
        if (p->data_size < ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_size < ctx->taglen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->tag, ctx->taglen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if (p != NULL &&
        (p->data == NULL ||
         p->data_type != OSSL_PARAM_OCTET_STRING ||
         !scossl_aes_gcm_iv_gen(ctx, p->data, p->data_size)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_gcm_set_ctx_params(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_gcm_set_aead_tag(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_gcm_set_tls1_aad(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_gcm_set_iv_fixed(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_gcm_set_iv_inv(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

/*
 * AES-CCM Implementation
 */
static SCOSSL_CIPHER_CCM_CTX *p_scossl_aes_ccm_dupctx(_In_ SCOSSL_CIPHER_CCM_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copy_ctx, OPENSSL_malloc, SCOSSL_CIPHER_CCM_CTX);
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_CIPHER_CCM_CTX));
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        // make sure the copy_ctx uses its copy of the expanded key TODO: implement SymCryptCcmStateCopy
        SymCryptAesKeyCopy(&ctx->key, &copy_ctx->key);
        copy_ctx->state = ctx->state;
        copy_ctx->state.pExpandedKey = &copy_ctx->key;
    }
    return copy_ctx;
}

static void p_scossl_aes_ccm_freectx(_Inout_  SCOSSL_CIPHER_CCM_CTX *ctx)
{
    SCOSSL_COMMON_ALIGNED_FREE(ctx, OPENSSL_clear_free, SCOSSL_CIPHER_CCM_CTX);
}

static SCOSSL_STATUS p_scossl_aes_ccm_init_internal(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                                    _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                    _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                    _In_ const OSSL_PARAM params[])
{
    if (key && keylen != ctx->keylen)
    {
        return SCOSSL_FAILURE;
    }

    ctx->encrypt = encrypt;

    return scossl_aes_ccm_init_key(ctx, key, keylen, iv, ivlen) &&
           p_scossl_aes_ccm_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_aes_ccm_encrypt_init(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_ccm_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_ccm_decrypt_init(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                                                   _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                                   _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen,
                                                   _In_ const OSSL_PARAM params[])
{
    return p_scossl_aes_ccm_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_ccm_final(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                                            _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, ossl_unused size_t outsize)
{
    return scossl_aes_ccm_cipher(ctx, ctx->encrypt, out, outl, NULL, 0);
}

static SCOSSL_STATUS p_scossl_aes_ccm_cipher(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                                             _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outsize,
                                             _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    return scossl_aes_ccm_cipher(ctx, ctx->encrypt, out, outl, in, inl);
}

static const OSSL_PARAM *p_scossl_aes_ccm_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_ccm_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_aes_ccm_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return p_scossl_aes_ccm_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_aes_ccm_get_ctx_params(_In_ SCOSSL_CIPHER_CCM_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->taglen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tlsAadSet ? ctx->taglen : 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL)
    {
        if (p->data_size < ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL)
    {
        if (p->data_size < ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_size < ctx->taglen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_string(p, &ctx->tag, ctx->taglen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_aes_ccm_set_ctx_params(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL)
    {
        size_t ivlen;

        if (!OSSL_PARAM_get_size_t(p, &ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_ccm_set_iv_len(ctx, ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_ccm_set_aead_tag(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_ccm_set_tls1_aad(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_aes_ccm_set_iv_fixed(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(kbits, ivlen, lcmode, UCMODE)                                       \
    SCOSSL_CIPHER_##UCMODE##_CTX *p_scossl_aes_##kbits##_##lcmode##_newctx()                                 \
    {                                                                                                        \
        SCOSSL_COMMON_ALIGNED_ALLOC(ctx, OPENSSL_malloc, SCOSSL_CIPHER_##UCMODE##_CTX);                      \
        if (ctx != NULL)                                                                                     \
        {                                                                                                    \
            ctx->keylen = kbits >> 3;                                                                        \
            scossl_aes_##lcmode##_init_ctx(ctx, NULL);                                                       \
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
    const OSSL_DISPATCH p_scossl_aes##kbits##lcmode##_functions[] = {                                        \
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

IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(128, SCOSSL_GCM_IV_LENGTH, gcm, GCM)
IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(192, SCOSSL_GCM_IV_LENGTH, gcm, GCM)
IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(256, SCOSSL_GCM_IV_LENGTH, gcm, GCM)

IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(128, SCOSSL_CCM_MIN_IV_LENGTH, ccm, CCM)
IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(192, SCOSSL_CCM_MIN_IV_LENGTH, ccm, CCM)
IMPLEMENT_SCOSSL_AES_AEAD_CIPHER(256, SCOSSL_CCM_MIN_IV_LENGTH, ccm, CCM)

#ifdef __cplusplus
}
#endif