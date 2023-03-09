//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl_hkdf.h"
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


SCOSSL_STATUS e_scossl_hkdf_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *e_scossl_hkdf_context;
    if ((e_scossl_hkdf_context = OPENSSL_zalloc(sizeof(*e_scossl_hkdf_context))) == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_INIT, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL");
        return SCOSSL_FAILURE;
    }
    EVP_PKEY_CTX_set_data(ctx, e_scossl_hkdf_context);
    return SCOSSL_SUCCESS;
}

void e_scossl_hkdf_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *e_scossl_hkdf_context = NULL;

    e_scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (e_scossl_hkdf_context == NULL) {
        return;
    }
    OPENSSL_clear_free(e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len);
    OPENSSL_clear_free(e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len);
    OPENSSL_cleanse(e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len);
    OPENSSL_free(e_scossl_hkdf_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

SCOSSL_STATUS e_scossl_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SCOSSL_HKDF_PKEY_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
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
        if (e_scossl_hkdf_context->salt != NULL)
            OPENSSL_clear_free(e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len);
        e_scossl_hkdf_context->salt = OPENSSL_memdup(p2, p1);
        if (e_scossl_hkdf_context->salt == NULL)
            return SCOSSL_FAILURE;
        e_scossl_hkdf_context->salt_len = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_KEY:
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (e_scossl_hkdf_context->key != NULL)
            OPENSSL_clear_free(e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len);
        e_scossl_hkdf_context->key = OPENSSL_memdup(p2, p1);
        if (e_scossl_hkdf_context->key == NULL)
            return SCOSSL_FAILURE;
        e_scossl_hkdf_context->key_len  = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_HKDF_INFO:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        if (p1 < 0 || p1 > (int)(HKDF_MAXBUF - e_scossl_hkdf_context->info_len))
            return SCOSSL_FAILURE;
        memcpy(e_scossl_hkdf_context->info + e_scossl_hkdf_context->info_len, p2, p1);
        e_scossl_hkdf_context->info_len += p1;
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support ctrl type (%d)", type);
        return SCOSSL_UNSUPPORTED;
    }
}

SCOSSL_STATUS e_scossl_hkdf_derive_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HKDF_PKEY_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_clear_free(e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len);
    OPENSSL_clear_free(e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len);
    OPENSSL_cleanse(e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len);
    memset(e_scossl_hkdf_context, 0, sizeof(*e_scossl_hkdf_context));
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

static PCSYMCRYPT_MAC e_scossl_get_symcrypt_mac_algorithm( _In_ const EVP_MD *evp_md )
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
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support Mac algorithm %d", type);
    return NULL;
}

SCOSSL_STATUS e_scossl_hkdf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                    _Inout_ size_t *keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_HKDF_PKEY_CTX *e_scossl_hkdf_context = (SCOSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_MAC e_scossl_mac_algo = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY  scExpandedKey;

    if (e_scossl_hkdf_context->md == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }
    e_scossl_mac_algo = e_scossl_get_symcrypt_mac_algorithm(e_scossl_hkdf_context->md);
    if (e_scossl_hkdf_context->key == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Key");
        return SCOSSL_FAILURE;
    }

    switch (e_scossl_hkdf_context->mode) {
    case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
        if( e_scossl_mac_algo != NULL )
        {
            scError = SymCryptHkdf(
                e_scossl_mac_algo,
                e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len,
                e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len,
                e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len,
                key, *keylen);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_HKDF_DERIVE, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                "SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(e_scossl_hkdf_context->md));

            return HKDF(
                e_scossl_hkdf_context->md,
                e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len,
                e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len,
                e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len,
                key, *keylen) != NULL;
        }
        return SCOSSL_SUCCESS;
    case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
        if (key == NULL) {
            *keylen = EVP_MD_size(e_scossl_hkdf_context->md);
            return SCOSSL_SUCCESS;
        }

        if( e_scossl_mac_algo != NULL )
        {
            scError = SymCryptHkdfExtractPrk(
                e_scossl_mac_algo,
                e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len,
                e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len,
                key, *keylen );
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_HKDF_DERIVE, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                "SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(e_scossl_hkdf_context->md));

            return HKDF_Extract(
                    e_scossl_hkdf_context->md,
                    e_scossl_hkdf_context->salt, e_scossl_hkdf_context->salt_len,
                    e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len,
                    key, keylen) != NULL;
        }
        return SCOSSL_SUCCESS;
    case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
        if( e_scossl_mac_algo != NULL )
        {
            scError = SymCryptHkdfPrkExpandKey(
                &scExpandedKey,
                e_scossl_mac_algo,
                e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len );
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }

            scError = SymCryptHkdfDerive(
                &scExpandedKey,
                e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len,
                key,
                *keylen);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_HKDF_DERIVE, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                "SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(e_scossl_hkdf_context->md));

            return HKDF_Expand(
                    e_scossl_hkdf_context->md,
                    e_scossl_hkdf_context->key, e_scossl_hkdf_context->key_len,
                    e_scossl_hkdf_context->info, e_scossl_hkdf_context->info_len,
                    key, *keylen) != NULL;
        }
        return SCOSSL_SUCCESS;
    default:
        return SCOSSL_FAILURE;
    }
}

#ifdef __cplusplus
}
#endif
