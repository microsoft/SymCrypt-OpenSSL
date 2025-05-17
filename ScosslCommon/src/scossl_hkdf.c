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
        
        if (ctx->pbPrefix == NULL)
        {
            copyCtx->pbPrefix = NULL;
        }
        else if ((copyCtx->pbPrefix = OPENSSL_memdup(ctx->pbPrefix, ctx->cbPrefix)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }
        copyCtx->cbPrefix = ctx->cbPrefix;
        
        if (ctx->pbLabel == NULL)
        {
            copyCtx->pbLabel = NULL;
        }
        else if ((copyCtx->pbLabel = OPENSSL_memdup(ctx->pbLabel, ctx->cbLabel)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }
        copyCtx->cbLabel = ctx->cbLabel;

        if (ctx->pbData == NULL)
        {
            copyCtx->pbData = NULL;
        }
        else if ((copyCtx->pbData = OPENSSL_memdup(ctx->pbData, ctx->cbData)) == NULL)
        {
            scossl_hkdf_freectx(copyCtx);
            return NULL;
        }
        copyCtx->cbData = ctx->cbData;

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
    OPENSSL_clear_free(ctx->pbPrefix, ctx->cbPrefix);
    OPENSSL_clear_free(ctx->pbLabel, ctx->cbLabel);
    OPENSSL_clear_free(ctx->pbData, ctx->cbData);
    OPENSSL_cleanse(ctx->info, ctx->cbInfo);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hkdf_reset(SCOSSL_HKDF_CTX *ctx)
{
    OPENSSL_clear_free(ctx->pbSalt, ctx->cbSalt);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_clear_free(ctx->pbPrefix, ctx->cbPrefix);
    OPENSSL_clear_free(ctx->pbLabel, ctx->cbLabel);
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

/*
 * TLS1.3KDF uses slight variations of the above,
 * they need to be present here.
 * Refer to RFC 8446 section 7 for specific details.
 */

 static
 SCOSSL_STATUS scossl_tls13_hkdf_expand(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
 {
     SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
     PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
     SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;
 
     // Validate required inputs
     if (ctx->md == NULL) {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Digest");
         return SCOSSL_FAILURE;
     }
 
     if (ctx->pbKey == NULL) {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Key");
         return SCOSSL_FAILURE;
     }
 
     symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
     if (symcryptHmacAlg == NULL) {
         return SCOSSL_FAILURE;
     }
 
     SIZE_T labelLen = ctx->cbPrefix + ctx->cbLabel;
     if (labelLen > 255)
         return SCOSSL_FAILURE;

     SIZE_T totalLen = 2 + 1 + labelLen + 1 + ctx->cbData;
     // Check total info size
     if (totalLen > MAX_INFO_SIZE) {
         SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                          "Total size exceeds maximum info size allowed");
         return SCOSSL_FAILURE;
     }
 
     // Reset info buffer
     ctx->cbInfo = totalLen;
     memset(ctx->info, 0, totalLen);
 
     printf("\n prefixlen %ld, labellen is %ld, datalen is %ld, totallen is %ld", ctx->cbPrefix, ctx->cbLabel, ctx->cbData, totalLen);
     // Append 2-byte output length
     BYTE outlen_bytes[2] = {
         (BYTE)((keylen >> 8) & 0xFF),
         (BYTE)(keylen & 0xFF)
     };
     if (!scossl_hkdf_append_info(ctx, outlen_bytes, sizeof(outlen_bytes)))
         return SCOSSL_FAILURE;
 
     // Append 1-byte label length and label ("tls13 " + label)
     BYTE labelLenByte = (BYTE)labelLen;
     if (!scossl_hkdf_append_info(ctx, &labelLenByte, 1) ||
         !scossl_hkdf_append_info(ctx, ctx->pbPrefix, ctx->cbPrefix) ||
         !scossl_hkdf_append_info(ctx, ctx->pbLabel, ctx->cbLabel))
         return SCOSSL_FAILURE;
     
     // Append 1-byte context length and context
     BYTE contextLenByte = (BYTE)ctx->cbData;
     if (!scossl_hkdf_append_info(ctx, &contextLenByte, 1) ||
        (ctx->cbData > 0 && !scossl_hkdf_append_info(ctx, ctx->pbData, ctx->cbData)))
         return SCOSSL_FAILURE;
 
     // Expand PRK
     printf("\n call SymCryptHkdfPrkExpandKey\n");
     scError = SymCryptHkdfPrkExpandKey(
         &scExpandedKey,
         symcryptHmacAlg,
         ctx->pbKey, ctx->cbKey);
     if (scError != SYMCRYPT_NO_ERROR)
         return SCOSSL_FAILURE;
     
     printf("\n call SymCryptHkdfDerive\n");
     scError = SymCryptHkdfDerive(
         &scExpandedKey,
         ctx->info, ctx->cbInfo,
         key, keylen);
     if (scError != SYMCRYPT_NO_ERROR)
         return SCOSSL_FAILURE;
 
     return SCOSSL_SUCCESS;
 }
 


static 
SCOSSL_STATUS scossl_tls13kdf_generate_secret(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    static BYTE default_zeros[EVP_MAX_MD_SIZE] = {0};
    BYTE preextractsec[EVP_MAX_MD_SIZE];
    SIZE_T mdlen;

    if (ctx == NULL || ctx->md == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }
    mdlen = EVP_MD_get_size(ctx->md);
    if (mdlen <= 0)
       return SCOSSL_FAILURE;
    
    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL)
    {
        return SCOSSL_FAILURE;
    }
    printf("\n I am here, kenlen is %ld\n", keylen);
    if (key) printf("\n key not NULL\n");
    // Handle NULL key (IKM)
    if (ctx->pbKey == NULL) {
        printf("\n empty pbkey\n");
        ctx->pbKey = default_zeros;
        ctx->cbKey = mdlen;
    }

    // Handle NULL salt (prevsecret)
    if (ctx->pbSalt == NULL) {
       printf("\n empty salt\n");
       ctx->pbSalt = default_zeros;
       ctx->cbSalt = mdlen;
    } else {
       printf("\n empty hash\n");
        
       EVP_MD_CTX *mctx = EVP_MD_CTX_new();
       BYTE hash[EVP_MAX_MD_SIZE];

       /* The pre-extract derive step uses a hash of no messages */
       if (mctx == NULL
               || EVP_DigestInit_ex(mctx, ctx->md, NULL) <= 0
               || EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
           EVP_MD_CTX_free(mctx);
           return 0;
       }
       EVP_MD_CTX_free(mctx);

       /* Generate the pre-extract secret */
       if (!scossl_tls13_hkdf_expand(ctx, key, keylen))
           return SCOSSL_FAILURE;

       ctx->pbSalt = preextractsec;
       ctx->cbSalt = mdlen;
    }

    // Final extract
    printf("\n call SymCryptHkdfExtractPrk\n");
    scError = SymCryptHkdfExtractPrk(
       symcryptHmacAlg,
       ctx->pbKey, ctx->cbKey,
       ctx->pbSalt, ctx->cbSalt,
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