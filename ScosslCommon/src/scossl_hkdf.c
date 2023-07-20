//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/kdf.h>

#include "scossl_hkdf.h"

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
BOOL scossl_hkdf_is_md_supported(EVP_MD *md)
{
    int mdnid = EVP_MD_type(md);
    switch (mdnid)
    {
    case NID_sha1:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
    case NID_sha3_256:
    case NID_sha3_384:
    case NID_sha3_512:
        return TRUE;
    }

    return FALSE;
}

static PCSYMCRYPT_MAC scossl_get_symcrypt_mac_algorithm(_In_ const EVP_MD *md)
{
    int type = EVP_MD_type(md);

    switch(type)
    {
    case NID_sha1:
        return SymCryptHmacSha1Algorithm;
    case NID_sha256:
        return SymCryptHmacSha256Algorithm;
    case NID_sha384:
        return SymCryptHmacSha384Algorithm;
    case NID_sha512:
        return SymCryptHmacSha512Algorithm;
    case NID_sha3_256:
        return SymCryptHmacSha3_256Algorithm;
    case NID_sha3_384:
        return SymCryptHmacSha3_384Algorithm;
    case NID_sha3_512:
        return SymCryptHmacSha3_512Algorithm;
    }
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support Mac algorithm %d", type);
    return NULL;
}

SCOSSL_HKDF_CTX *scossl_hkdf_newctx()
{
    SCOSSL_HKDF_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_HKDF_CTX));

    return ctx;
}

_Use_decl_annotations_
SCOSSL_HKDF_CTX *scossl_hkdf_dupctx(SCOSSL_HKDF_CTX *ctx)
{
    SCOSSL_HKDF_CTX *copyCtx = scossl_hkdf_newctx();
    if (copyCtx != NULL)
    {
        if (ctx->md != NULL && !EVP_MD_up_ref(ctx->md))
        {
            // Dont call scossl_hkdf_freectx here since we don't want 
            // to free ctx->md if it's reference count wasn't increased
            OPENSSL_free(copyCtx);
            return NULL;
        }
        copyCtx->md = ctx->md;

        copyCtx->cbSalt = ctx->cbSalt;
        if (ctx->pbSalt != NULL && 
            (copyCtx->pbSalt = OPENSSL_memdup(ctx->pbSalt, ctx->cbSalt)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }

        copyCtx->cbKey = ctx->cbKey;
        if (ctx->pbKey != NULL && 
            (copyCtx->pbKey = OPENSSL_memdup(ctx->pbKey, ctx->cbKey)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }

        copyCtx->mode = ctx->mode;
        copyCtx->cbInfo = ctx->cbInfo;
        memcpy(copyCtx->info, ctx->info, ctx->cbInfo);
    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_hkdf_freectx(SCOSSL_HKDF_CTX *ctx)
{
    EVP_MD_free(ctx->md);
    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_cleanse(ctx->info, ctx->cbInfo);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_reset(SCOSSL_HKDF_CTX *ctx)
{
    EVP_MD_free(ctx->md);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_cleanse(ctx, sizeof(SCOSSL_HKDF_CTX));
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_append_info(SCOSSL_HKDF_CTX *ctx, PCBYTE info, SIZE_T cbInfo)
{
    if (cbInfo + ctx->cbInfo > HKDF_MAXBUF)
    {
        return SCOSSL_FAILURE;
    }

    memcpy(ctx->info + ctx->cbInfo, info, cbInfo);
    ctx->cbInfo += cbInfo;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_derive(SCOSSL_HKDF_CTX *ctx, 
                                 PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptMacAlg = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;

    if (ctx->md == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Key");
        return SCOSSL_FAILURE;
    }

    symcryptMacAlg = scossl_get_symcrypt_mac_algorithm(ctx->md);
    if (symcryptMacAlg == NULL)
    {
        return SCOSSL_FAILURE;
    }

    switch (ctx->mode) {
    case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
        scError = SymCryptHkdf(
            symcryptMacAlg,
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
            symcryptMacAlg,
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
            symcryptMacAlg,
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