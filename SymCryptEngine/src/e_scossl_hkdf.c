//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hkdf.h"
#include "e_scossl_hkdf.h"

#include <openssl/hmac.h>

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hkdf_init(EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_CTX *e_scossl_hkdf_context;
    if ((e_scossl_hkdf_context = scossl_hkdf_newctx()) == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_INIT, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL");
        return SCOSSL_FAILURE;
    }
    EVP_PKEY_CTX_set_data(ctx, e_scossl_hkdf_context);
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
void e_scossl_hkdf_cleanup(EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_CTX *e_scossl_hkdf_context = NULL;

    e_scossl_hkdf_context = (SCOSSL_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (e_scossl_hkdf_context == NULL)
        return;

    scossl_hkdf_freectx(e_scossl_hkdf_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SCOSSL_HKDF_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    switch (type) {
    case EVP_PKEY_CTRL_HKDF_MD:
        if (p2 == NULL)
            return SCOSSL_FAILURE;
        e_scossl_hkdf_context->md = p2;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_MODE:
        e_scossl_hkdf_context->mode = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_SALT:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (e_scossl_hkdf_context->pbSalt != NULL)
            OPENSSL_clear_free(e_scossl_hkdf_context->pbSalt, e_scossl_hkdf_context->cbSalt);
        e_scossl_hkdf_context->pbSalt = OPENSSL_memdup(p2, p1);
        if (e_scossl_hkdf_context->pbSalt == NULL)
            return SCOSSL_FAILURE;
        e_scossl_hkdf_context->cbSalt = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_KEY:
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (e_scossl_hkdf_context->pbKey != NULL)
            OPENSSL_clear_free(e_scossl_hkdf_context->pbKey, e_scossl_hkdf_context->cbKey);
        e_scossl_hkdf_context->pbKey = OPENSSL_memdup(p2, p1);
        if (e_scossl_hkdf_context->pbKey == NULL)
            return SCOSSL_FAILURE;
        e_scossl_hkdf_context->cbKey  = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_INFO:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        return scossl_hkdf_append_info(e_scossl_hkdf_context, p2, p1);
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support ctrl type (%d)", type);
        return SCOSSL_UNSUPPORTED;
    }
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hkdf_derive_init(EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    return scossl_hkdf_reset(e_scossl_hkdf_context);
}

//
// Default OpenSSL fallback functions
//
static unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len)
{
    unsigned int tmp_len;

    if (!HMAC(evp_md, salt, salt_len, key, key_len, prk, &tmp_len))
        return NULL;

    *prk_len = tmp_len;
    return prk;
}

static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    unsigned char *ret = NULL;

    unsigned int i;

    unsigned char prev[EVP_MAX_MD_SIZE];

    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);

    size_t n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return NULL;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return NULL;

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;

        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmac, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmac, info, info_len))
            goto err;

        if (!HMAC_Update(hmac, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmac, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = okm;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}

static unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned char *ret;
    size_t prk_len;

    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, &prk_len))
        return NULL;

    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hkdf_derive(EVP_PKEY_CTX *ctx,
                                   unsigned char *key, size_t *keylen)
{
    SCOSSL_HKDF_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);

    if (e_scossl_hkdf_context->md == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                         "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (e_scossl_hkdf_context->pbKey == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                         "Missing Key");
        return SCOSSL_FAILURE;
    }

    if (scossl_is_md_supported(EVP_MD_type(e_scossl_hkdf_context->md)))
    {
        if (e_scossl_hkdf_context->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY && key == NULL)
        {
            *keylen = EVP_MD_size(e_scossl_hkdf_context->md);
            return SCOSSL_SUCCESS;
        }

        return scossl_hkdf_derive(e_scossl_hkdf_context, key, *keylen);
    }

    SCOSSL_LOG_INFO(SCOSSL_ERR_F_HKDF_DERIVE, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                    "SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(e_scossl_hkdf_context->md));

    switch (e_scossl_hkdf_context->mode)
    {
    case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
        return HKDF(
            e_scossl_hkdf_context->md,
            e_scossl_hkdf_context->pbSalt, e_scossl_hkdf_context->cbSalt,
            e_scossl_hkdf_context->pbKey, e_scossl_hkdf_context->cbKey,
            e_scossl_hkdf_context->info, e_scossl_hkdf_context->cbInfo,
            key, *keylen) != NULL;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        return HKDF_Extract(
            e_scossl_hkdf_context->md,
            e_scossl_hkdf_context->pbSalt, e_scossl_hkdf_context->cbSalt,
            e_scossl_hkdf_context->pbKey, e_scossl_hkdf_context->cbKey,
            key, keylen) != NULL;
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        return HKDF_Expand(
            e_scossl_hkdf_context->md,
            e_scossl_hkdf_context->pbKey, e_scossl_hkdf_context->cbKey,
            e_scossl_hkdf_context->info, e_scossl_hkdf_context->cbInfo,
            key, *keylen) != NULL;
    }

    return SCOSSL_FAILURE;
}

#ifdef __cplusplus
}
#endif
