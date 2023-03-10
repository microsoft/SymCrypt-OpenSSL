#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_ciphers.h"
#include "p_scossl_ciphers.h"

static const OSSL_PARAM p_scossl_cipher_aes_gcm_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cipher_aes_gcm_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_STATUS p_scossl_aes_gcm_get_ctx_params(SCOSSL_CIPHER_GCM_CTX *ctx, OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_aes_gcm_set_ctx_params(SCOSSL_CIPHER_GCM_CTX *ctx, const OSSL_PARAM params[]);

SCOSSL_CIPHER_GCM_CTX *p_scossl_aes_gcm_dupctx(SCOSSL_CIPHER_GCM_CTX *ctx)
{
    SCOSSL_CIPHER_GCM_CTX *copy_ctx = OPENSSL_malloc(sizeof(SCOSSL_CIPHER_GCM_CTX));
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

void p_scossl_aes_gcm_freectx(SCOSSL_CIPHER_GCM_CTX *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_CIPHER_GCM_CTX));
}

static SCOSSL_STATUS p_scossl_aes_gcm_init_internal(SCOSSL_CIPHER_GCM_CTX *ctx, BOOL encrypt,
                                                    const unsigned char *key, size_t keylen,
                                                    const unsigned char *iv, size_t ivlen,
                                                    const OSSL_PARAM params[])
{
    ctx->encrypt = encrypt;

    if (!scossl_cipher_gcm_init_key(ctx, key, keylen, iv, ivlen))
    {
        return SCOSSL_FAILURE;
    }

    return p_scossl_aes_gcm_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_encrypt_init(SCOSSL_CIPHER_GCM_CTX *ctx,
                                                   const unsigned char *key, size_t keylen,
                                                   const unsigned char *iv, size_t ivlen,
                                                   const OSSL_PARAM params[])
{
    return p_scossl_aes_gcm_init_internal(ctx, 1, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_decrypt_init(SCOSSL_CIPHER_GCM_CTX *ctx,
                                                   const unsigned char *key, size_t keylen,
                                                   const unsigned char *iv, size_t ivlen,
                                                   const OSSL_PARAM params[])
{
    return p_scossl_aes_gcm_init_internal(ctx, 0, key, keylen, iv, ivlen, params);
}

static SCOSSL_STATUS p_scossl_aes_gcm_final(SCOSSL_CIPHER_GCM_CTX *ctx,
                                            unsigned char *out, size_t *outl, size_t outsize)
{
    return scossl_aes_gcm_cipher(ctx, ctx->encrypt, out, outl, NULL, 0);
}

static SCOSSL_STATUS p_scossl_aes_gcm_cipher(SCOSSL_CIPHER_GCM_CTX *ctx,
                                             unsigned char *out, size_t *outl, size_t outsize,
                                             const unsigned char *in, size_t inl)
{
    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    return scossl_aes_gcm_cipher(ctx, ctx->encrypt, out, outl, in, inl);
}

const OSSL_PARAM *p_scossl_cipher_aes_gcm_gettable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_cipher_aes_gcm_gettable_ctx_param_types;
}
const OSSL_PARAM *p_scossl_cipher_aes_gcm_settable_ctx_params(void *cctx, void *provctx)
{
    return p_scossl_cipher_aes_gcm_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_aes_gcm_get_ctx_params(SCOSSL_CIPHER_GCM_CTX *ctx, OSSL_PARAM params[])
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
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL)
    {
        if (p->data_size < ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        if (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen))
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
        if (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen))
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
        if (!OSSL_PARAM_set_octet_ptr(p, &ctx->tag, ctx->taglen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->tag, ctx->taglen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if (p != NULL &&
        (p->data == NULL ||
         p->data_type != OSSL_PARAM_OCTET_STRING ||
         !scossl_cipher_gcm_iv_gen(ctx, p->data, p->data_size)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }


return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_aes_gcm_set_ctx_params(SCOSSL_CIPHER_GCM_CTX *ctx, const OSSL_PARAM params[])
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

        if (!scossl_cipher_gcm_set_aead_tag(ctx, ctx->encrypt, p->data, p->data_size))
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

        if (!scossl_cipher_gcm_set_tls1_aad(ctx, ctx->encrypt, p->data, p->data_size))
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

        if (!scossl_cipher_gcm_set_iv_fixed(ctx, ctx->encrypt, p->data, p->data_size))
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

        if (!scossl_cipher_gcm_set_iv_inv(ctx, ctx->encrypt, p->data, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_AES_GCM_FUNCTIONS(kbits, flags)                                             \
    SCOSSL_CIPHER_GCM_CTX *p_scossl_aes_##kbits##_gcm_newctx()                                       \
    {                                                                                                \
        SCOSSL_CIPHER_GCM_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_CIPHER_GCM_CTX));                  \
        if (ctx != NULL)                                                                             \
        {                                                                                            \
            scossl_cipher_gcm_init_ctx(ctx, kbits >> 3, NULL);                                       \
        }                                                                                            \
                                                                                                     \
        return ctx;                                                                                  \
    }                                                                                                \
    SCOSSL_STATUS p_scossl_aes_##kbits##_gcm_get_params(OSSL_PARAM params[])                         \
    {                                                                                                \
        return p_scossl_cipher_get_params(params, EVP_CIPH_GCM_MODE, kbits >> 3,                     \
                                          SCOSSL_GCM_IV_LENGTH, 1, flags);                           \
    }                                                                                                \
                                                                                                     \
    const OSSL_DISPATCH p_scossl_aes##kbits##gcm_functions[] = {                                     \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_scossl_aes_##kbits##_gcm_newctx},                \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))p_scossl_aes_gcm_dupctx},                          \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_scossl_aes_gcm_freectx},                        \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_aes_gcm_encrypt_init},              \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_aes_gcm_decrypt_init},              \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p_scossl_aes_gcm_cipher},                          \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p_scossl_aes_gcm_final},                            \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p_scossl_aes_gcm_cipher},                          \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_scossl_aes_##kbits##_gcm_get_params},        \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_aes_gcm_get_ctx_params},          \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_aes_gcm_set_ctx_params},          \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p_scossl_cipher_gettable_params},         \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cipher_aes_gcm_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cipher_aes_gcm_settable_ctx_params}, \
        {0, NULL}};

IMPLEMENT_SCOSSL_AES_GCM_FUNCTIONS(128, SCOSSL_FLAG_AEAD | SCOSSL_FLAG_CUSTOM_IV)
IMPLEMENT_SCOSSL_AES_GCM_FUNCTIONS(192, SCOSSL_FLAG_AEAD | SCOSSL_FLAG_CUSTOM_IV)
IMPLEMENT_SCOSSL_AES_GCM_FUNCTIONS(256, SCOSSL_FLAG_AEAD | SCOSSL_FLAG_CUSTOM_IV)