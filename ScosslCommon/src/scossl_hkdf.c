//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hkdf.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_HKDF_CTX *scossl_hkdf_newctx()
{
    return OPENSSL_zalloc(sizeof(SCOSSL_HKDF_CTX));
}

_Use_decl_annotations_
SCOSSL_HKDF_CTX *scossl_hkdf_dupctx(SCOSSL_HKDF_CTX *ctx)
{
    SCOSSL_HKDF_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_HKDF_CTX));
    if (copyCtx != NULL)
    {
        if (ctx->pbSalt != NULL)
        {
            if ((copyCtx->pbSalt = OPENSSL_memdup(ctx->pbSalt, ctx->cbSalt)) == NULL)
            {
                scossl_hkdf_freectx(copyCtx);
                return NULL;
            }
        }
        if (ctx->pbKey != NULL)
        {
            if ((copyCtx->pbKey = OPENSSL_memdup(ctx->pbKey, ctx->cbKey)) == NULL)
            {
                scossl_hkdf_freectx(copyCtx);
                return NULL;
            }
        }
        if (ctx->pbPrefix != NULL)
        {
            if ((copyCtx->pbPrefix = OPENSSL_memdup(ctx->pbPrefix, ctx->cbPrefix)) == NULL)
            {
                scossl_hkdf_freectx(copyCtx);
                return NULL;
            }
        }
        if (ctx->pbLabel != NULL)
        {
            if ((copyCtx->pbLabel = OPENSSL_memdup(ctx->pbLabel, ctx->cbLabel)) == NULL)
            {
                scossl_hkdf_freectx(copyCtx);
                return NULL;
            }
        }

        if (ctx->pbData != NULL)
        {
            if ((copyCtx->pbData = OPENSSL_memdup(ctx->pbData, ctx->cbData)) == NULL)
            {
                scossl_hkdf_freectx(copyCtx);
                return NULL;
            }
        }

        copyCtx->md = ctx->md;
        copyCtx->mode = ctx->mode;
        copyCtx->cbInfo = ctx->cbInfo;
        memcpy(copyCtx->info, ctx->info, ctx->cbInfo);
        copyCtx->cbSalt = ctx->cbSalt;
        copyCtx->cbKey = ctx->cbKey;
        copyCtx->cbPrefix = ctx->cbPrefix;
        copyCtx->cbLabel = ctx->cbLabel;
        copyCtx->cbData = ctx->cbData;

    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_hkdf_freectx(SCOSSL_HKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;
    scossl_hkdf_reset(ctx);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_reset(SCOSSL_HKDF_CTX *ctx)
{
    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_free(ctx->pbPrefix);
    OPENSSL_free(ctx->pbLabel);
    OPENSSL_clear_free(ctx->pbData, ctx->cbData);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_append_info(SCOSSL_HKDF_CTX *ctx,
                                      PCBYTE pbInfo, SIZE_T cbInfo)
{
    if (cbInfo > HKDF_MAXBUF - ctx->cbInfo)
    {
        return SCOSSL_FAILURE;
    }

    memcpy(ctx->info + ctx->cbInfo, pbInfo, cbInfo);
    ctx->cbInfo += cbInfo;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_derive(SCOSSL_HKDF_CTX *ctx,
                                 PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;

    if (ctx->md == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Key");
        return SCOSSL_FAILURE;
    }

    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL)
    {
        return SCOSSL_FAILURE;
    }

    switch (ctx->mode)
    {
    case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
        scError = SymCryptHkdf(
            symcryptHmacAlg,
            ctx->pbKey, ctx->cbKey,
            ctx->pbSalt, ctx->cbSalt,
            ctx->info, ctx->cbInfo,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        scError = SymCryptHkdfExtractPrk(
            symcryptHmacAlg,
            ctx->pbKey, ctx->cbKey,
            ctx->pbSalt, ctx->cbSalt,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        scError = SymCryptHkdfPrkExpandKey(
            &scExpandedKey,
            symcryptHmacAlg,
            ctx->pbKey, ctx->cbKey);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }

        scError = SymCryptHkdfDerive(
            &scExpandedKey,
            ctx->info, ctx->cbInfo,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Invalid Mode: %d", ctx->mode);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif