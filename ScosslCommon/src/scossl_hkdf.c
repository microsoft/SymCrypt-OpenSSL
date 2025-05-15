//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hkdf.h"


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HASH_SIZE    (256)
#define MAX_INFO_SIZE    (1024)  // need to revist later[megliu]

SCOSSL_HKDF_CTX *scossl_hkdf_newctx()
{
    return OPENSSL_zalloc(sizeof(SCOSSL_HKDF_CTX));
}

_Use_decl_annotations_
SCOSSL_HKDF_CTX *scossl_hkdf_dupctx(SCOSSL_HKDF_CTX *ctx)
{
    SCOSSL_HKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_HKDF_CTX));
    if (copyCtx != NULL)
    {
        if (ctx->pbSalt == NULL)
        {
            copyCtx->pbSalt = NULL;
        }
        else if ((copyCtx->pbSalt = OPENSSL_memdup(ctx->pbSalt, ctx->cbSalt)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }
        copyCtx->cbSalt = ctx->cbSalt;

        if (ctx->pbKey == NULL)
        {
            copyCtx->pbKey = NULL;
        }
        else if ((copyCtx->pbKey = OPENSSL_memdup(ctx->pbKey, ctx->cbKey)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }
        copyCtx->cbKey = ctx->cbKey;

        copyCtx->md = ctx->md;
        copyCtx->mode = ctx->mode;
        copyCtx->cbInfo = ctx->cbInfo;
        memcpy(copyCtx->info, ctx->info, ctx->cbInfo);
    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_hkdf_freectx(SCOSSL_HKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_cleanse(ctx->info, ctx->cbInfo);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_reset(SCOSSL_HKDF_CTX *ctx)
{
    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
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

/*
 * TLS1.3KDF uses slight variations of the above,
 * they need to be present here.
 * Refer to RFC 8446 section 7 for specific details.
 */

 static 
 SCOSSL_STATUS scossl_tls13kdf_generate_secret(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
 {
     
     SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
     PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
     SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;
     BYTE default_zeros[MAX_HASH_SIZE] = {0};
     BYTE hash_empty[MAX_HASH_SIZE];
 
     if (ctx == NULL || ctx->md == NULL)
     {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
             "Missing Digest");
         return SCOSSL_FAILURE;
     }
 
     symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
     if (symcryptHmacAlg == NULL)
     {
         return SCOSSL_FAILURE;
     }
     
     // Handle NULL key (IKM)
     if (ctx->pbKey == NULL) {
         ctx->pbKey = default_zeros;
         ctx->cbKey = keylen;
     }
 
     // Handle NULL salt (prevsecret)
     if (ctx->pbSalt == NULL) {
         ctx->pbSalt = default_zeros;
         ctx->cbSalt = keylen;
     } else {
         // Hash of empty string
         PCSYMCRYPT_HASH scosslHashAlgo = scossl_get_symcrypt_hash_algorithm(ctx->md);
         SIZE_T cbHashSize = SymCryptHashResultSize(scosslHashAlgo);
         SymCryptHash(scosslHashAlgo, NULL, 0, hash_empty, cbHashSize);
 
         // Build info = prefix || label || hash(empty)
         if ((ctx->cbPrefix + ctx->cbLabel + keylen) > MAX_INFO_SIZE)
         {
             SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                             "Total size exceeds maximum info size allowed");
             return SCOSSL_FAILURE;
         }
         
         ctx->cbInfo = 0;
         memset(ctx->info, 0, MAX_INFO_SIZE);
 
         if (!scossl_hkdf_append_info(ctx, ctx->pbPrefix, ctx->cbPrefix) ||
             !scossl_hkdf_append_info(ctx, ctx->pbLabel, ctx->cbLabel) ||
             !scossl_hkdf_append_info(ctx, hash_empty, keylen))
             return SCOSSL_FAILURE;
 
         scError = SymCryptHkdfPrkExpandKey(
             &scExpandedKey,
             symcryptHmacAlg,
             ctx->pbSalt,
             ctx->cbSalt);
         if (scError != SYMCRYPT_NO_ERROR)
             return SCOSSL_FAILURE;
 
         scError = SymCryptHkdfDerive(
                 &scExpandedKey,
                 ctx->info, ctx->cbInfo,
                 key, keylen);
         if (scError != SYMCRYPT_NO_ERROR)
             return SCOSSL_FAILURE;
 
         ctx->pbSalt = key;
         ctx->cbSalt = keylen;
     }
 
     // Final extract
     scError = SymCryptHkdfExtractPrk(
         symcryptHmacAlg,
         ctx->pbKey, ctx->cbKey,
         ctx->pbSalt, ctx->cbSalt,
         key, keylen);
     if (scError != SYMCRYPT_NO_ERROR)
         return SCOSSL_FAILURE;
 
     return SCOSSL_SUCCESS;
 }
 
 static 
 SCOSSL_STATUS scossl_tls13_hkdf_expand(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
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
     /*
      * TLS 1.3 HKDF Label structure:
      *
      * struct {
      *     uint16 length;          // desired length of output keying material
      *     opaque label<7..255>;   // "tls13 " + label
      *     opaque context<0..255>; // usually a hash
      * } HkdfLabel;
     */
     // Reset info buffer
     if ((ctx->cbPrefix + ctx->cbLabel + ctx->cbData) > MAX_INFO_SIZE)
     {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                          "Total size exceeds maximum info size allowed");
         return SCOSSL_FAILURE;
     }
     ctx->cbInfo = 0;
     memset(ctx->info, 0, MAX_INFO_SIZE);
     // Append output length
     if (!scossl_hkdf_append_info(ctx, key, keylen))
         return SCOSSL_FAILURE;
     // Append label: prefix || label
     if (!scossl_hkdf_append_info(ctx, ctx->pbPrefix, ctx->cbPrefix) ||
         !scossl_hkdf_append_info(ctx, ctx->pbLabel, ctx->cbLabel))
         return SCOSSL_FAILURE;
     // Append context (data)
     if (ctx->cbData > 0 &&
         !scossl_hkdf_append_info(ctx, ctx->pbData, ctx->cbData))
         return SCOSSL_FAILURE;
 
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
     return SCOSSL_SUCCESS;
 
 }
 
 _Use_decl_annotations_
 SCOSSL_STATUS scossl_tls13kdf_derive(SCOSSL_HKDF_CTX *ctx,
                                  PBYTE key, SIZE_T keylen)
 {
     SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
 
     if (ctx == NULL)
     {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
             "Ctx is NULL");
         return SCOSSL_FAILURE;
     }
 
     switch (ctx->mode)
     {
     case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
         scError = scossl_tls13kdf_generate_secret(ctx, key, keylen);
         if (scError != SYMCRYPT_NO_ERROR)
         {
             return SCOSSL_FAILURE;
         }
         break;
     case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
         scError = scossl_tls13_hkdf_expand(ctx, key, keylen);
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