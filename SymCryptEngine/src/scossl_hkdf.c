//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hkdf.h"
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_MAXBUF 1024
typedef struct {
    int mode;
    const EVP_MD *md;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char info[HKDF_MAXBUF];
    size_t info_len;
} SCOSSL_HKDF_PKEY_CTX;


SCOSSL_STATUS scossl_hkdf_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *scossl_hkdf_context;
    if ((scossl_hkdf_context = OPENSSL_zalloc(sizeof(*scossl_hkdf_context))) == NULL) {
        SCOSSL_LOG_ERROR("Memory Allocation Error");
        return SCOSSL_FAILURE;
    }
    EVP_PKEY_CTX_set_data(ctx, scossl_hkdf_context);
    return SCOSSL_SUCCESS;
}

void scossl_hkdf_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *scossl_hkdf_context = NULL;

    scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (scossl_hkdf_context == NULL) {
        return;
    }
    OPENSSL_clear_free(scossl_hkdf_context->salt, scossl_hkdf_context->salt_len);
    OPENSSL_clear_free(scossl_hkdf_context->key, scossl_hkdf_context->key_len);
    OPENSSL_cleanse(scossl_hkdf_context->info, scossl_hkdf_context->info_len);
    OPENSSL_free(scossl_hkdf_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

SCOSSL_STATUS scossl_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SCOSSL_HKDF_PKEY_CTX *scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    switch (type) {
    case EVP_PKEY_CTRL_HKDF_MD:
        if (p2 == NULL)
            return SCOSSL_FAILURE;
        scossl_hkdf_context->md = p2;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_MODE:
        scossl_hkdf_context->mode = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_SALT:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (scossl_hkdf_context->salt != NULL)
            OPENSSL_clear_free(scossl_hkdf_context->salt, scossl_hkdf_context->salt_len);
        scossl_hkdf_context->salt = OPENSSL_memdup(p2, p1);
        if (scossl_hkdf_context->salt == NULL)
            return SCOSSL_FAILURE;
        scossl_hkdf_context->salt_len = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_KEY:
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (scossl_hkdf_context->key != NULL)
            OPENSSL_clear_free(scossl_hkdf_context->key, scossl_hkdf_context->key_len);
        scossl_hkdf_context->key = OPENSSL_memdup(p2, p1);
        if (scossl_hkdf_context->key == NULL)
            return SCOSSL_FAILURE;
        scossl_hkdf_context->key_len  = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_INFO:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        if (p1 < 0 || p1 > (int)(HKDF_MAXBUF - scossl_hkdf_context->info_len))
            return SCOSSL_FAILURE;
        memcpy(scossl_hkdf_context->info + scossl_hkdf_context->info_len, p2, p1);
        scossl_hkdf_context->info_len += p1;
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR("SymCrypt Engine does not support ctrl type (%d)", type);
        return SCOSSL_UNSUPPORTED;
    }
}

SCOSSL_STATUS scossl_hkdf_derive_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_clear_free(scossl_hkdf_context->key, scossl_hkdf_context->key_len);
    OPENSSL_clear_free(scossl_hkdf_context->salt, scossl_hkdf_context->salt_len);
    OPENSSL_cleanse(scossl_hkdf_context->info, scossl_hkdf_context->info_len);
    memset(scossl_hkdf_context, 0, sizeof(*scossl_hkdf_context));
    return SCOSSL_SUCCESS;
}

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

static PCSYMCRYPT_MAC scossl_get_symcrypt_mac_algorithm( _In_ const EVP_MD *evp_md )
{
    int type = EVP_MD_type(evp_md);

    if (type == NID_sha1)
        return SymCryptHmacSha1Algorithm;
    if (type == NID_sha256)
        return SymCryptHmacSha256Algorithm;
    if (type == NID_sha384)
        return SymCryptHmacSha384Algorithm;
    if (type == NID_sha512)
        return SymCryptHmacSha512Algorithm;
    // if (type == NID_AES_CMC)
    //     return SymCryptAesCmacAlgorithm;
    SCOSSL_LOG_ERROR("SymCrypt engine does not support Mac algorithm %d", type);
    return NULL;
}

SCOSSL_STATUS scossl_hkdf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                    _Out_ size_t *keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_HKDF_PKEY_CTX *scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_MAC scossl_mac_algo = NULL;
    // SYMCRYPT_HKDF_EXPANDED_KEY  scExpandedKey;

    if (scossl_hkdf_context->md == NULL) {
        SCOSSL_LOG_ERROR("Missing Digest");
        return SCOSSL_FAILURE;
    }
    scossl_mac_algo = scossl_get_symcrypt_mac_algorithm(scossl_hkdf_context->md);
    if (scossl_hkdf_context->key == NULL) {
        SCOSSL_LOG_ERROR("Missing Key");
        return SCOSSL_FAILURE;
    }

    switch (scossl_hkdf_context->mode) {
    case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
        if( scossl_mac_algo != NULL )
        {
            scError = SymCryptHkdf(
                scossl_mac_algo,
                scossl_hkdf_context->key,
                scossl_hkdf_context->key_len,
                scossl_hkdf_context->salt,
                scossl_hkdf_context->salt_len,
                scossl_hkdf_context->info,
                scossl_hkdf_context->info_len,
                key,
                *keylen);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            SCOSSL_LOG_INFO("SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(scossl_hkdf_context->md));

            return HKDF(
                scossl_hkdf_context->md,
                scossl_hkdf_context->salt,
                scossl_hkdf_context->salt_len,
                scossl_hkdf_context->key,
                scossl_hkdf_context->key_len,
                scossl_hkdf_context->info,
                scossl_hkdf_context->info_len,
                key, *keylen) != NULL;
        }
        return SCOSSL_SUCCESS;
    case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
        if (key == NULL) {
            *keylen = EVP_MD_size(scossl_hkdf_context->md);
            return SCOSSL_SUCCESS;
        }
        // SymCryptError = SymCryptHkdfExpandKey(
        //     &scExpandedKey,
        //     scossl_mac_algo,
        //     scossl_hkdf_context->key,
        //     scossl_hkdf_context->key_len,
        //     scossl_hkdf_context->salt,
        //     scossl_hkdf_context->salt_len);
        // if (SymCryptError != SYMCRYPT_NO_ERROR)
        // {
        //     SCOSSL_LOG_SYMCRYPT_DEBUG("SymCryptHkdfExpandKey failed", scError);
        //     return SCOSSL_FAILURE;
        // }

        // // TODO:
        // // Extract expanded key output and copy it to key[keylen]
        // return SCOSSL_SUCCESS;

        return HKDF_Extract(
                scossl_hkdf_context->md,
                scossl_hkdf_context->salt,
                scossl_hkdf_context->salt_len,
                scossl_hkdf_context->key,
                scossl_hkdf_context->key_len,
                key, keylen) != NULL;
    case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:

        // // TODO:
        // // Populate scExpandedKey

        // SymCryptError = SymCryptHkdfDerive(
        //                     &scExpandedKey,
        //                     scossl_hkdf_context->info,
        //                     scossl_hkdf_context->info_len,
        //                     key,
        //                     *keylen);
        // if (SymCryptError != SYMCRYPT_NO_ERROR)
        // {
        //     SCOSSL_LOG_SYMCRYPT_DEBUG("SymCryptHkdfExpandKey failed", scError);
        //     return SCOSSL_FAILURE;
        // }
        // return SCOSSL_SUCCESS;
        return HKDF_Expand(
                scossl_hkdf_context->md,
                scossl_hkdf_context->key,
                scossl_hkdf_context->key_len,
                scossl_hkdf_context->info,
                scossl_hkdf_context->info_len,
                key, *keylen) != NULL;
    default:
        return SCOSSL_FAILURE;
    }
}

#ifdef __cplusplus
}
#endif
