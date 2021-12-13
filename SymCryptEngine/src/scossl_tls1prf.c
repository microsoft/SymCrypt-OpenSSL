//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_tls1prf.h"
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS1_PRF_MAXBUF 1024

/* TLS KDF pkey context structure */
typedef struct {
    /* Digest to use for PRF */
    const EVP_MD *md;
    /* Secret value to use for PRF */
    unsigned char *secret;
    size_t secret_length;
    /* Buffer of concatenated seed data */
    unsigned char seed[TLS1_PRF_MAXBUF];
    size_t seed_length;
} SCOSSL_TLS1_PRF_PKEY_CTX;

SCOSSL_STATUS scossl_tls1prf_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_PKEY_CTX *key_context = NULL;
    if ((key_context = OPENSSL_zalloc(sizeof(*key_context))) == NULL) {
        SCOSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    EVP_PKEY_CTX_set_data(ctx, key_context);
    return 1;
}

void scossl_tls1prf_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_PKEY_CTX *key_context = (SCOSSL_TLS1_PRF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (key_context == NULL) {
        return;
    }
    OPENSSL_clear_free(key_context->secret, key_context->secret_length);
    OPENSSL_cleanse(key_context->seed, key_context->seed_length);
    OPENSSL_free(key_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

SCOSSL_STATUS scossl_tls1prf_ctrl(_Inout_ EVP_PKEY_CTX *ctx, int type, int p1, _In_ void *p2)
{
    SCOSSL_TLS1_PRF_PKEY_CTX *key_context = (SCOSSL_TLS1_PRF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);

    switch (type) {
    case EVP_PKEY_CTRL_TLS_MD:
        key_context->md = p2;
        return 1;

    case EVP_PKEY_CTRL_TLS_SECRET:
        if (p1 < 0)
            return 0;
        if (key_context->secret != NULL)
            OPENSSL_clear_free(key_context->secret, key_context->secret_length);
        OPENSSL_cleanse(key_context->seed, key_context->seed_length);
        key_context->seed_length = 0;
        key_context->secret = OPENSSL_memdup(p2, p1);
        if (key_context->secret == NULL)
            return 0;
        key_context->secret_length  = p1;
        return 1;
    case EVP_PKEY_CTRL_TLS_SEED:
        if (p1 == 0 || p2 == NULL)
            return 1;
        if (p1 < 0 || p1 > (int)(TLS1_PRF_MAXBUF - key_context->seed_length))
            return 0;
        memcpy(key_context->seed + key_context->seed_length, p2, p1);
        key_context->seed_length += p1;
        return 1;
    default:
        SCOSSL_LOG_ERROR("SymCrypt Engine does not support ctrl type (%d)", type);
        return -2;
    }
}

SCOSSL_STATUS scossl_tls1prf_derive_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_PKEY_CTX *key_context = (SCOSSL_TLS1_PRF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_clear_free(key_context->secret, key_context->secret_length);
    OPENSSL_cleanse(key_context->seed, key_context->seed_length);
    memset(key_context, 0, sizeof(*key_context));
    return 1;
}

static PCSYMCRYPT_MAC scossl_get_symcrypt_mac_algorithm(
    const EVP_MD *evp_md)
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

SCOSSL_STATUS scossl_tls1prf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                        _Out_ size_t *keylen)
{
    SCOSSL_TLS1_PRF_PKEY_CTX *key_context = (SCOSSL_TLS1_PRF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_MAC scossl_mac_algo = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (key_context->md == NULL) {
        SCOSSL_LOG_ERROR("Missing Digest");
        return 0;
    }

    if (key_context->secret == NULL) {
        SCOSSL_LOG_ERROR("Missing Secret");
        return 0;
    }

    if( EVP_MD_type(key_context->md) == NID_md5_sha1 )
    {
        // Special case to use TlsPrf1_1 to handle md5_sha1
        SCOSSL_LOG_INFO("Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        scError = SymCryptTlsPrf1_1(
            key_context->secret,
            key_context->secret_length,
            NULL,
            0,
            key_context->seed,
            key_context->seed_length,
            key,
            *keylen);
    }
    else
    {
        scossl_mac_algo = scossl_get_symcrypt_mac_algorithm(key_context->md);
        if( scossl_mac_algo == NULL )
        {
            return 0;
        }

        scError = SymCryptTlsPrf1_2(
            scossl_mac_algo,
            key_context->secret,
            key_context->secret_length,
            NULL,
            0,
            key_context->seed,
            key_context->seed_length,
            key,
            *keylen);
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_scError_ERROR("SymCryptTlsPrf1_2 failed", scError);
        return 0;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif