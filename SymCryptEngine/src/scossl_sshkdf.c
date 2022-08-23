//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_sshkdf.h"
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSH_KDF_MAX_DIGEST_SIZE (512 / 8)

/* SSH KDF pkey context structure */
typedef struct {
    /* Hash function to use */
    const EVP_MD *md;
    unsigned char *sharedKey;
    size_t sharedKey_length;
    unsigned char hashValue[SSH_KDF_MAX_DIGEST_SIZE];
    size_t hashValue_length;
    unsigned char sessionId[SSH_KDF_MAX_DIGEST_SIZE];
    size_t sessionId_length;
    unsigned char label;
} SCOSSL_SSH_KDF_PKEY_CTX;

SCOSSL_STATUS scossl_sshkdf_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_SSH_KDF_PKEY_CTX *key_context = NULL;
    if ((key_context = OPENSSL_zalloc(sizeof(*key_context))) == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_INIT, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc return NULL");
        return SCOSSL_FAILURE;
    }
    EVP_PKEY_CTX_set_data(ctx, key_context);
    return SCOSSL_SUCCESS;
}

void scossl_sshkdf_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_SSH_KDF_PKEY_CTX *key_context = (SCOSSL_SSH_KDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (key_context == NULL) {
        return;
    }
    OPENSSL_clear_free(key_context->sharedKey, key_context->sharedKey_length);
    OPENSSL_cleanse(key_context->hashValue, sizeof(key_context->hashValue));
    OPENSSL_cleanse(key_context->sessionId, sizeof(key_context->sessionId));
    OPENSSL_free(key_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

SCOSSL_STATUS scossl_sshkdf_setparam(_Inout_ SCOSSL_SSH_KDF_PKEY_CTX *key_context, int p1, _In_ void *p2, unsigned char *buf, size_t *len)
{
    if (p1 < 0 || p1 > SSH_KDF_MAX_DIGEST_SIZE)
        return SCOSSL_FAILURE;

    if(key_context->md && p1 != EVP_MD_size(key_context->md))
        return SCOSSL_FAILURE;

    OPENSSL_cleanse(buf, *len);
    *len = 0;

    memcpy(buf, p2, p1);
    *len = p1;
    
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS scossl_sshkdf_ctrl(_Inout_ EVP_PKEY_CTX *ctx, int type, int p1, _In_ void *p2)
{
    SCOSSL_SSH_KDF_PKEY_CTX *key_context = (SCOSSL_SSH_KDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);

    switch (type) {
    case EVP_KDF_CTRL_SET_MD:
        key_context->md = p2;
        return SCOSSL_SUCCESS;

    case EVP_KDF_CTRL_SET_KEY:
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (key_context->sharedKey != NULL)
            OPENSSL_clear_free(key_context->sharedKey, key_context->sharedKey_length);
        OPENSSL_cleanse(key_context->hashValue, key_context->hashValue_length);
        key_context->hashValue_length = 0;
        OPENSSL_cleanse(key_context->sessionId, key_context->sessionId_length);
        key_context->sessionId_length = 0;
        key_context->sharedKey = OPENSSL_memdup(p2, p1);
        if (key_context->sharedKey == NULL)
            return SCOSSL_FAILURE;
        key_context->sharedKey_length  = p1;
        return SCOSSL_SUCCESS;        

    case EVP_KDF_CTRL_SET_SSHKDF_XCGHASH:
        return scossl_sshkdf_setparam(key_context, p1, p2, key_context->hashValue, &key_context->hashValue_length);        

    case EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID:
        return scossl_sshkdf_setparam(key_context, p1, p2, key_context->sessionId, &key_context->sessionId_length);        

    case EVP_KDF_CTRL_SET_SSHKDF_TYPE:
        if (!(p1 >= 0x41 && p1 <= 0x46))
            return SCOSSL_FAILURE;
        key_context->label = (unsigned char)p1;
        return SCOSSL_SUCCESS;        

    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support ctrl type (%d)", type);
        return SCOSSL_UNSUPPORTED;
    }
}

SCOSSL_STATUS scossl_sshkdf_derive_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_SSH_KDF_PKEY_CTX *key_context = (SCOSSL_SSH_KDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_clear_free(key_context->sharedKey, key_context->sharedKey_length);
    OPENSSL_cleanse(key_context->hashValue, sizeof(key_context->hashValue));
    OPENSSL_cleanse(key_context->sessionId, sizeof(key_context->sessionId));
    memset(key_context, 0, sizeof(*key_context));
    return SCOSSL_SUCCESS;
}

static PCSYMCRYPT_HASH scossl_get_symcrypt_hash_algorithm(const EVP_MD *evp_md)
{
    int type = EVP_MD_type(evp_md);

    if (type == NID_sha1)
        return SymCryptSha1Algorithm;
    if (type == NID_sha256)
        return SymCryptSha256Algorithm;
    if (type == NID_sha384)
        return SymCryptSha384Algorithm;
    if (type == NID_sha512)
        return SymCryptSha512Algorithm;
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support hash algorithm %d", type);
    return NULL;
}

SCOSSL_STATUS scossl_sshkdf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                        _Inout_ size_t *keylen)
{
    SCOSSL_SSH_KDF_PKEY_CTX *key_context = (SCOSSL_SSH_KDF_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_HASH scossl_hash_alg = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_HASH_STATE state1, state2;

    if (key_context->md == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (key_context->sharedKey == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing SharedKey");
        return SCOSSL_FAILURE;
    }

    scossl_hash_alg = scossl_get_symcrypt_hash_algorithm(key_context->md);
    if( scossl_hash_alg == NULL )
    {
        return SCOSSL_FAILURE;
    }

    scError = SymCryptSshKdf(scossl_hash_alg, &state1, &state2, 
                                key_context->sharedKey, key_context->sharedKey_length,
                                key_context->hashValue, key_context->hashValue_length,
                                key_context->sessionId, key_context->sessionId_length,
                                key_context->label,
                                key, *keylen);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptSshKdf failed", scError);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif