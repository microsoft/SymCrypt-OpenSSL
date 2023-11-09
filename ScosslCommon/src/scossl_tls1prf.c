//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_tls1prf.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_TLS1_PRF_CTX *scossl_tls1prf_newctx()
{
    return OPENSSL_zalloc(sizeof(SCOSSL_TLS1_PRF_CTX));
}

_Use_decl_annotations_
SCOSSL_TLS1_PRF_CTX *scossl_tls1prf_dupctx(SCOSSL_TLS1_PRF_CTX *ctx)
{
    SCOSSL_TLS1_PRF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_TLS1_PRF_CTX));
    if (copyCtx != NULL)
    {
        if (ctx->pbSecret == NULL)
        {
            copyCtx->pbSecret = NULL;
        }
        else if ((copyCtx->pbSecret = OPENSSL_memdup(ctx->pbSecret, ctx->cbSecret)) == NULL)
        {
            scossl_tls1prf_freectx(copyCtx);
            return NULL;
        }

        copyCtx->isTlsPrf1_1 = ctx->isTlsPrf1_1;
        copyCtx->pHmac = ctx->pHmac;
        copyCtx->cbSecret = ctx->cbSecret;
        copyCtx->cbSeed = ctx->cbSeed;
        memcpy(copyCtx->seed, ctx->seed, ctx->cbSeed);
    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_tls1prf_freectx(SCOSSL_TLS1_PRF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_clear_free(ctx->pbSecret, ctx->cbSecret);
    OPENSSL_cleanse(ctx->seed, ctx->cbSeed);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_tls1prf_reset(SCOSSL_TLS1_PRF_CTX *ctx)
{
    OPENSSL_clear_free(ctx->pbSecret, ctx->cbSecret);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_tls1prf_append_seed(SCOSSL_TLS1_PRF_CTX *ctx,
                                         PCBYTE pbSeed, SIZE_T cbSeed)
{
    if (cbSeed + ctx->cbSeed > TLS1_PRF_MAXBUF)
    {
        return SCOSSL_FAILURE;
    }

    memcpy(ctx->seed + ctx->cbSeed, pbSeed, cbSeed);
    ctx->cbSeed += cbSeed;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_tls1prf_derive(SCOSSL_TLS1_PRF_CTX *ctx,
                                    PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx->pbSecret == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_TLS1PRF_DERIVE, ERR_R_INTERNAL_ERROR,
                         "Missing Secret");
        return SCOSSL_FAILURE;
    }

    if (ctx->isTlsPrf1_1)
    {
        // Special case to use TlsPrf1_1 to handle md5_sha1
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_TLS1PRF_DERIVE, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Hmac algorithm MD5+SHA1 which is not FIPS compliant");

        scError = SymCryptTlsPrf1_1(
            ctx->pbSecret, ctx->cbSecret,
            NULL, 0,
            ctx->seed, ctx->cbSeed,
            key, keylen);
    }
    else
    {
        if (ctx->pHmac == NULL)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_TLS1PRF_DERIVE, ERR_R_INTERNAL_ERROR,
                             "Missing Digest");
            return SCOSSL_FAILURE;
        }

        scError = SymCryptTlsPrf1_2(
            ctx->pHmac,
            ctx->pbSecret, ctx->cbSecret,
            NULL, 0,
            ctx->seed, ctx->cbSeed,
            key, keylen);
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_TLS1PRF_DERIVE, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptTlsPrf1_x failed", scError);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif