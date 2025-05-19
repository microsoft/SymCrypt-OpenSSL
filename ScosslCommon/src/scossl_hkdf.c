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
 * HKDF-Expand-Label is a TLS 1.3-specific key derivation function defined in RFC 8446, Section 7.1.
 * It wraps the standard HKDF-Expand function with a structured label format to ensure domain separation.
 *
 * The structure of the HkdfLabel is as follows:
 *
 * struct {
 *     uint16 length;             // Desired length of the output keying material (2 bytes, big-endian)
 *     opaque label<7..255>;      // A variable-length label prefixed with "tls13 " followed by a custom label
 *     opaque context<0..255>;    // A variable-length context (e.g., handshake transcript hash)
 * } HkdfLabel;
 *
 */
static 
void print_buffer(const char *label, const BYTE *data, SIZE_T len) 
{
    printf("%s (%zu bytes): ", label, len);
    for (SIZE_T i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}
    
static
SCOSSL_STATUS scossl_tls13_hkdf_expand(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;

    if (ctx->md == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Key");
        return SCOSSL_FAILURE;
    }
    printf("\n---------------------------------------------------------------------------\n");
    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) {
        return SCOSSL_FAILURE;
    }

    SIZE_T labelLen = ctx->cbPrefix + ctx->cbLabel;
    if (labelLen > 255)
        return SCOSSL_FAILURE;

    SIZE_T totalLen = 2 + 1 + labelLen + 1 + ctx->cbData;
    if (totalLen > HKDF_MAXBUF) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                         "Total size exceeds maximum info size allowed");
        return SCOSSL_FAILURE;
    }
    printf("\nPrefix len %ld, labellen %ld, data len %ld, total len %ld", ctx->cbPrefix, ctx->cbLabel, ctx->cbData, totalLen);
    
    int nid = EVP_MD_type(ctx->md);
    const char *alg_name = OBJ_nid2sn(nid);
    printf("\nDigest algorithm: %s (NID: %d)\n", alg_name ? alg_name : "unknown", nid);

    BYTE hkdflabel[HKDF_MAXBUF];
    size_t hkdflabellen = 0;

    // Output length (2 bytes)
    hkdflabel[hkdflabellen++] = (BYTE)((keylen >> 8) & 0xFF);
    hkdflabel[hkdflabellen++] = (BYTE)(keylen & 0xFF);

    // Label length
    hkdflabel[hkdflabellen++] = (BYTE)labelLen;

    // Label = prefix + label
    memcpy(hkdflabel + hkdflabellen, ctx->pbPrefix, ctx->cbPrefix);
    hkdflabellen += ctx->cbPrefix;
    memcpy(hkdflabel + hkdflabellen, ctx->pbLabel, ctx->cbLabel);
    hkdflabellen += ctx->cbLabel;

    // Context length
    hkdflabel[hkdflabellen++] = (BYTE)ctx->cbData;

    // Context
    if (ctx->cbData > 0) {
        memcpy(hkdflabel + hkdflabellen, ctx->pbData, ctx->cbData);
        hkdflabellen += ctx->cbData;
    }

    print_buffer("\nPrefix", ctx->pbPrefix, ctx->cbPrefix);
    print_buffer("Label", ctx->pbLabel, ctx->cbLabel);
    print_buffer("Data", ctx->pbData, ctx->cbData);
    print_buffer("\nKey", ctx->pbKey, ctx->cbKey);
    
    // Expand PRK
    scError = SymCryptHkdfPrkExpandKey(
        &scExpandedKey,
        symcryptHmacAlg,
        ctx->pbKey, ctx->cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
        return SCOSSL_FAILURE;
    
    scError = SymCryptHkdfDerive(
        &scExpandedKey,
        hkdflabel, hkdflabellen,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR)
        return SCOSSL_FAILURE;

    print_buffer("Derived key", key, keylen);
    return SCOSSL_SUCCESS;
}

static
SCOSSL_STATUS scossl_tls13kdf_generate_secret(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    BYTE *default_zeros = NULL;
    BYTE *empty_hash = NULL;
    BYTE *expanded_secret = NULL;
    EVP_MD_CTX *mctx = NULL;
    SIZE_T mdlen;
    BOOL salt_need_reset = FALSE;
    BOOL data_need_reset = FALSE;
    BOOL key_need_reset = FALSE;
    PBYTE saved_key = NULL;
    SIZE_T saved_keylen = 0;


    if (ctx == NULL || ctx->md == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Digest");
        return SCOSSL_FAILURE;
    }

    mdlen = EVP_MD_get_size(ctx->md);
    if (mdlen <= 0)
        return SCOSSL_FAILURE;

    default_zeros = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
    if (default_zeros == NULL)
        return SCOSSL_FAILURE;

    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) {
        scError = SCOSSL_FAILURE;
        goto cleanup;
    }
    printf("\n---------------------------------------------------------------------------\n");
    printf("\nDigest algorithm: %s (NID: %d)\n", OBJ_nid2sn(EVP_MD_type(ctx->md)), EVP_MD_type(ctx->md));
    printf("\nKey length %ld, mdlen %ld\n", keylen, mdlen);
    print_buffer("\nPrefix", ctx->pbPrefix, ctx->cbPrefix);
    print_buffer("Label", ctx->pbLabel, ctx->cbLabel);
    print_buffer("Data", ctx->pbData, ctx->cbData);
    print_buffer("Salt", ctx->pbSalt, ctx->cbSalt);
    print_buffer("\npbKey", ctx->pbKey, ctx->cbKey);

    if (ctx->pbKey == NULL) {
        printf("\n empty pbkey\n");
        ctx->pbKey = default_zeros;
        ctx->cbKey = mdlen;
        key_need_reset = TRUE;
    }

    if (ctx->pbSalt == NULL) {
        printf("\n empty salt\n");
        ctx->pbSalt = default_zeros;
        ctx->cbSalt = mdlen;
        salt_need_reset = TRUE;
    } else {
        printf("\n empty hash\n");
        empty_hash = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
        if (empty_hash == NULL) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL ||
            EVP_DigestInit_ex(mctx, ctx->md, NULL) <= 0 ||
            EVP_DigestFinal_ex(mctx, empty_hash, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        EVP_MD_CTX_free(mctx);

        ctx->pbData = empty_hash;
        ctx->cbData = mdlen;
        data_need_reset = TRUE;
        
        print_buffer("Data(Empty Hash)", ctx->pbData, ctx->cbData);

        expanded_secret = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
        if (expanded_secret == NULL) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        //scossl_tls13_hkdf_expand used pbKey, so save original pbKey and use pbSalt
        saved_key = ctx->pbKey;
        saved_keylen = ctx->cbKey;
        ctx->pbKey = ctx->pbSalt;
        ctx->cbKey = ctx->cbSalt;

        if (SCOSSL_SUCCESS != scossl_tls13_hkdf_expand(ctx, expanded_secret, keylen)) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        //restore pbKey/cbKey
        ctx->pbKey = saved_key;
        ctx->cbKey = saved_keylen;

        print_buffer("Salt(expanded)", expanded_secret, keylen);
        print_buffer("pbKey(restored)", ctx->pbKey, ctx->cbKey);

        scError = SymCryptHkdfExtractPrk(
            symcryptHmacAlg,
            ctx->pbKey, ctx->cbKey,
            expanded_secret, keylen,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        scError = SCOSSL_SUCCESS;
        goto cleanup;
    }

    printf("\n call SymCryptHkdfExtractPrk\n");
    scError = SymCryptHkdfExtractPrk(
        symcryptHmacAlg,
        ctx->pbKey, ctx->cbKey,
        ctx->pbSalt, ctx->cbSalt,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR) {
        scError = SCOSSL_FAILURE;
        goto cleanup;
    }
    print_buffer("PRK", key, keylen);
    scError = SCOSSL_SUCCESS;

cleanup:
    if (salt_need_reset == TRUE) {
        ctx->pbSalt = NULL;
        ctx->cbSalt = 0;
    }
    if (data_need_reset == TRUE) {
        ctx->pbData = NULL;
        ctx->cbData = 0;
    }
    if (key_need_reset == TRUE) {
        ctx->pbKey = NULL;
        ctx->cbKey = 0;
    }
    if (default_zeros != NULL) {
        OPENSSL_free(default_zeros);
        default_zeros = NULL;
    }
    if (empty_hash != NULL) {
        OPENSSL_free(empty_hash);
        empty_hash = NULL;
    }
    if (expanded_secret != NULL) {
        OPENSSL_free(expanded_secret);
        expanded_secret = NULL;
    }

    return scError;  
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
        if (scError != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        scError = scossl_tls13_hkdf_expand(ctx, key, keylen);
        if (scError != SCOSSL_SUCCESS)
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