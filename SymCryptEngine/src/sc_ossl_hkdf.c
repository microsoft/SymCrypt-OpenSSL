//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_hkdf.h"
#include "sc_ossl_helpers.h"
#include <openssl/hmac.h>
#include <symcrypt.h>
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
} SC_OSSL_HKDF_PKEY_CTX;


SCOSSL_STATUS sc_ossl_hkdf_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SC_OSSL_HKDF_PKEY_CTX *sc_ossl_hkdf_context;
    if ((sc_ossl_hkdf_context = OPENSSL_zalloc(sizeof(*sc_ossl_hkdf_context))) == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    EVP_PKEY_CTX_set_data(ctx, sc_ossl_hkdf_context);
    return 1;
}

void sc_ossl_hkdf_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SC_OSSL_HKDF_PKEY_CTX *sc_ossl_hkdf_context = NULL;

    sc_ossl_hkdf_context = (SC_OSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (sc_ossl_hkdf_context == NULL) {
        return;
    }
    OPENSSL_clear_free(sc_ossl_hkdf_context->salt, sc_ossl_hkdf_context->salt_len);
    OPENSSL_clear_free(sc_ossl_hkdf_context->key, sc_ossl_hkdf_context->key_len);
    OPENSSL_cleanse(sc_ossl_hkdf_context->info, sc_ossl_hkdf_context->info_len);
    OPENSSL_free(sc_ossl_hkdf_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

SCOSSL_STATUS sc_ossl_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SC_OSSL_HKDF_PKEY_CTX *sc_ossl_hkdf_context = (SC_OSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    switch (type) {
    case EVP_PKEY_CTRL_HKDF_MD:
        if (p2 == NULL)
            return 0;
        sc_ossl_hkdf_context->md = p2;
        return 1;
    case EVP_PKEY_CTRL_HKDF_MODE:
        sc_ossl_hkdf_context->mode = p1;
        return 1;
    case EVP_PKEY_CTRL_HKDF_SALT:
        if (p1 == 0 || p2 == NULL)
            return 1;
        if (p1 < 0)
            return 0;
        if (sc_ossl_hkdf_context->salt != NULL)
            OPENSSL_clear_free(sc_ossl_hkdf_context->salt, sc_ossl_hkdf_context->salt_len);
        sc_ossl_hkdf_context->salt = OPENSSL_memdup(p2, p1);
        if (sc_ossl_hkdf_context->salt == NULL)
            return 0;
        sc_ossl_hkdf_context->salt_len = p1;
        return 1;
    case EVP_PKEY_CTRL_HKDF_KEY:
        if (p1 < 0)
            return 0;
        if (sc_ossl_hkdf_context->key != NULL)
            OPENSSL_clear_free(sc_ossl_hkdf_context->key, sc_ossl_hkdf_context->key_len);
        sc_ossl_hkdf_context->key = OPENSSL_memdup(p2, p1);
        if (sc_ossl_hkdf_context->key == NULL)
            return 0;
        sc_ossl_hkdf_context->key_len  = p1;
        return 1;
    case EVP_PKEY_CTRL_HKDF_INFO:
        if (p1 == 0 || p2 == NULL)
            return 1;
        if (p1 < 0 || p1 > (int)(HKDF_MAXBUF - sc_ossl_hkdf_context->info_len))
            return 0;
        memcpy(sc_ossl_hkdf_context->info + sc_ossl_hkdf_context->info_len, p2, p1);
        sc_ossl_hkdf_context->info_len += p1;
        return 1;
    default:
        SC_OSSL_LOG_ERROR("SymCrypt Engine does not support ctrl type (%d)", type);
        return -2;
    }
}

SCOSSL_STATUS sc_ossl_hkdf_derive_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SC_OSSL_HKDF_PKEY_CTX *sc_ossl_hkdf_context = (SC_OSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_clear_free(sc_ossl_hkdf_context->key, sc_ossl_hkdf_context->key_len);
    OPENSSL_clear_free(sc_ossl_hkdf_context->salt, sc_ossl_hkdf_context->salt_len);
    OPENSSL_cleanse(sc_ossl_hkdf_context->info, sc_ossl_hkdf_context->info_len);
    memset(sc_ossl_hkdf_context, 0, sizeof(*sc_ossl_hkdf_context));
    return 1;
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

PCSYMCRYPT_MAC
SymCryptMacAlgorithm(
    _In_ const EVP_MD *evp_md)
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
    return NULL;
}

SCOSSL_STATUS sc_ossl_hkdf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                    _Out_ size_t *keylen)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SC_OSSL_HKDF_PKEY_CTX *sc_ossl_hkdf_context = (SC_OSSL_HKDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_MAC sc_ossl_mac_algo = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY  scExpandedKey;

    if (sc_ossl_hkdf_context->md == NULL) {
        SC_OSSL_LOG_ERROR("Missing Digest");
        return 0;
    }
    sc_ossl_mac_algo = SymCryptMacAlgorithm(sc_ossl_hkdf_context->md);
    if (sc_ossl_hkdf_context->key == NULL) {
        SC_OSSL_LOG_ERROR("Missing Key");
        return 0;
    }

    switch (sc_ossl_hkdf_context->mode) {
    case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
        if( sc_ossl_mac_algo != NULL )
        {
            SymError = SymCryptHkdf(
                sc_ossl_mac_algo,
                sc_ossl_hkdf_context->key,
                sc_ossl_hkdf_context->key_len,
                sc_ossl_hkdf_context->salt,
                sc_ossl_hkdf_context->salt_len,
                sc_ossl_hkdf_context->info,
                sc_ossl_hkdf_context->info_len,
                key,
                *keylen);
            if (SymError != SYMCRYPT_NO_ERROR)
            {
                return 0;
            }
        }
        else
        {
            SC_OSSL_LOG_INFO("SymCrypt engine does not support Mac algorithm %d - falling back to OpenSSL", EVP_MD_type(sc_ossl_hkdf_context->md));

            return HKDF(
                sc_ossl_hkdf_context->md,
                sc_ossl_hkdf_context->salt,
                sc_ossl_hkdf_context->salt_len,
                sc_ossl_hkdf_context->key,
                sc_ossl_hkdf_context->key_len,
                sc_ossl_hkdf_context->info,
                sc_ossl_hkdf_context->info_len,
                key, *keylen) != NULL;
        }
        return 1;
    case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
        if (key == NULL) {
            *keylen = EVP_MD_size(sc_ossl_hkdf_context->md);
            return 1;
        }
        // SymCryptError = SymCryptHkdfExpandKey(
        //     &scExpandedKey,
        //     sc_ossl_mac_algo,
        //     sc_ossl_hkdf_context->key,
        //     sc_ossl_hkdf_context->key_len,
        //     sc_ossl_hkdf_context->salt,
        //     sc_ossl_hkdf_context->salt_len);
        // if (SymCryptError != SYMCRYPT_NO_ERROR)
        // {
        //     SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptHkdfExpandKey failed", SymError);
        //     return 0;
        // }

        // // TODO:
        // // Extract expanded key output and copy it to key[keylen]
        // return 1;

        return HKDF_Extract(
                sc_ossl_hkdf_context->md,
                sc_ossl_hkdf_context->salt,
                sc_ossl_hkdf_context->salt_len,
                sc_ossl_hkdf_context->key,
                sc_ossl_hkdf_context->key_len,
                key, keylen) != NULL;
    case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:

        // // TODO:
        // // Populate scExpandedKey

        // SymCryptError = SymCryptHkdfDerive(
        //                     &scExpandedKey,
        //                     sc_ossl_hkdf_context->info,
        //                     sc_ossl_hkdf_context->info_len,
        //                     key,
        //                     *keylen);
        // if (SymCryptError != SYMCRYPT_NO_ERROR)
        // {
        //     SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptHkdfExpandKey failed", SymError);
        //     return 0;
        // }
        // return 1;
        return HKDF_Expand(
                sc_ossl_hkdf_context->md,
                sc_ossl_hkdf_context->key,
                sc_ossl_hkdf_context->key_len,
                sc_ossl_hkdf_context->info,
                sc_ossl_hkdf_context->info_len,
                key, *keylen) != NULL;
    default:
        return 0;
    }
}

#ifdef __cplusplus
}
#endif
