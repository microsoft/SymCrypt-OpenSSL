//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_tls1prf.h"
#include "e_scossl_tls1prf.h"

#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_tls1prf_init(EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_CTX *key_context = NULL;
    if ((key_context = scossl_tls1prf_newctx()) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_TLS1PRF_INIT, ERR_R_MALLOC_FAILURE,
                         "OPENSSL_zalloc return NULL");
        return SCOSSL_FAILURE;
    }
    EVP_PKEY_CTX_set_data(ctx, key_context);
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
void e_scossl_tls1prf_cleanup(EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_CTX *key_context = (SCOSSL_TLS1_PRF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (key_context == NULL)
        return;

    scossl_tls1prf_freectx(key_context);

    EVP_PKEY_CTX_set_data(ctx, NULL);
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_tls1prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SCOSSL_TLS1_PRF_CTX *key_context = (SCOSSL_TLS1_PRF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    PCSYMCRYPT_MAC symcryptMacAlg = NULL;
    BOOL isTlsPrf1_1 = TRUE;

    switch (type)
    {
    case EVP_PKEY_CTRL_TLS_MD:
        // Special case to always allow md5_sha1 for tls1.1 PRF compat
        if (EVP_MD_type(p2) != NID_md5_sha1)
        {
            if ((symcryptMacAlg = scossl_get_symcrypt_mac_algorithm(p2)) == NULL)
                return SCOSSL_FAILURE;
            isTlsPrf1_1 = FALSE;
        }
        key_context->pMac = symcryptMacAlg;
        key_context->isTlsPrf1_1 = isTlsPrf1_1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_TLS_SECRET:
        if (p1 < 0)
            return SCOSSL_FAILURE;
        if (key_context->pbSecret != NULL)
            OPENSSL_clear_free(key_context->pbSecret, key_context->cbSecret);
        OPENSSL_cleanse(key_context->seed, key_context->cbSeed);
        key_context->cbSeed = 0;
        key_context->pbSecret = OPENSSL_memdup(p2, p1);
        if (key_context->pbSecret == NULL)
            return SCOSSL_FAILURE;
        key_context->cbSecret  = p1;
        return SCOSSL_SUCCESS;
    case EVP_PKEY_CTRL_TLS_SEED:
        if (p1 == 0 || p2 == NULL)
            return SCOSSL_SUCCESS;
        return scossl_tls1prf_append_seed(key_context, p2, p1);
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_TLS1PRF_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "SymCrypt Engine does not support ctrl type (%d)", type);
        return SCOSSL_UNSUPPORTED;
    }
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_tls1prf_derive_init(EVP_PKEY_CTX *ctx)
{
    SCOSSL_TLS1_PRF_CTX *key_context = (SCOSSL_TLS1_PRF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    return scossl_tls1prf_reset(key_context);
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_tls1prf_derive(EVP_PKEY_CTX *ctx,
                                      unsigned char *key, size_t *keylen)
{
    SCOSSL_TLS1_PRF_CTX *key_context = (SCOSSL_TLS1_PRF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    return scossl_tls1prf_derive(key_context, key, *keylen);
}

#ifdef __cplusplus
}
#endif