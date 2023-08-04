//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

PSCOSSL_MAC_ALIGNED_CTX scossl_mac_newctx()
{
    return OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_MAC_CTX));
}

_Use_decl_annotations_
PSCOSSL_MAC_ALIGNED_CTX scossl_mac_dupctx(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_MAC_CTX *ctx, *copyCtx;
    PSCOSSL_MAC_ALIGNED_CTX alignedCopy;

    if ((alignedCopy = scossl_mac_newctx()) == NULL)
    {
        return NULL;
    }

    ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    copyCtx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCopy);

    if (ctx->pbKey != NULL)
    {
        if ((copyCtx->pbKey = OPENSSL_malloc(ctx->cbKey)) == NULL)
        {
            scossl_mac_freectx(copyCtx);
            return NULL;
        }

        memcpy(copyCtx->pbKey, ctx->pbKey, ctx->cbKey);
        copyCtx->cbKey = ctx->cbKey;
    }

    copyCtx->pMac = ctx->pMac;
    copyCtx->keyCopyFunc = ctx->keyCopyFunc;
    copyCtx->stateCopyFunc = ctx->stateCopyFunc;

    ctx->keyCopyFunc(&ctx->expandedKey, &copyCtx->expandedKey);
    ctx->stateCopyFunc(&ctx->macState, &copyCtx->expandedKey, &copyCtx->macState);

    return alignedCopy;
}

_Use_decl_annotations_
void scossl_mac_freectx(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    if (alignedCtx == NULL)
        return;

    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    SCOSSL_COMMON_ALIGNED_FREE(alignedCtx, OPENSSL_clear_free, SCOSSL_MAC_CTX);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_md(PSCOSSL_MAC_ALIGNED_CTX alignedCtx, const EVP_MD *md)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    int type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        ctx->pMac = SymCryptHmacSha1Algorithm;
        ctx->keyCopyFunc = (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha1KeyCopy;
        ctx->stateCopyFunc = (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha1StateCopy;
        return SCOSSL_SUCCESS;
    case NID_sha256:
        ctx->pMac = SymCryptHmacSha256Algorithm;
        ctx->keyCopyFunc = (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha256KeyCopy;
        ctx->stateCopyFunc = (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha256StateCopy;
        return SCOSSL_SUCCESS;
    case NID_sha384:
        ctx->pMac = SymCryptHmacSha384Algorithm;
        ctx->keyCopyFunc = (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha384KeyCopy;
        ctx->stateCopyFunc = (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha384StateCopy;
        return SCOSSL_SUCCESS;
    case NID_sha512:
        ctx->pMac = SymCryptHmacSha512Algorithm;
        ctx->keyCopyFunc = (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha512KeyCopy;
        ctx->stateCopyFunc = (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha512StateCopy;
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "SymCrypt engine does not support hash algorithm for MAC %d", type);
    }

    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_cipher(PSCOSSL_MAC_ALIGNED_CTX alignedCtx, const EVP_CIPHER *cipher)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    switch (EVP_CIPHER_nid(cipher))
    {
    case NID_aes_128_cbc:
        ctx->cbKey = 16;
        break;
    case NID_aes_192_cbc:
        ctx->cbKey = 24;
        break;
    case NID_aes_256_cbc:
        ctx->cbKey = 32;
        break;
    default:
        return SCOSSL_FAILURE;
    }
    ctx->pMac = SymCryptAesCmacAlgorithm;
    ctx->keyCopyFunc = (PSYMCRYPT_MAC_KEY_COPY)SymCryptAesCmacKeyCopy;
    ctx->stateCopyFunc = (PSYMCRYPT_MAC_STATE_COPY)SymCryptAesCmacStateCopy;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_mac_key(PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                                     PCBYTE pbMacKey, SIZE_T cbMacKey)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    PBYTE pbKey;

    if (pbMacKey == NULL ||
        (pbKey = OPENSSL_malloc(cbMacKey)) == NULL)
    {
        return SCOSSL_FAILURE;
    }

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    ctx->pbKey = pbKey;
    ctx->cbKey = cbMacKey;
    memcpy(ctx->pbKey, pbMacKey, cbMacKey);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SIZE_T scossl_mac_get_result_size(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    return ctx->pMac == NULL ? 0 : ctx->pMac->resultSize;
}

_Use_decl_annotations_
SIZE_T scossl_mac_get_block_size(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if(ctx->pMac == SymCryptHmacSha1Algorithm)
    {
        return SYMCRYPT_HMAC_SHA1_INPUT_BLOCK_SIZE;
    }
    else if(ctx->pMac == SymCryptHmacSha256Algorithm)
    {
        return SYMCRYPT_HMAC_SHA256_INPUT_BLOCK_SIZE;
    }
    else if(ctx->pMac == SymCryptHmacSha384Algorithm)
    {
        return SYMCRYPT_HMAC_SHA384_INPUT_BLOCK_SIZE;
    }
    else if(ctx->pMac == SymCryptHmacSha512Algorithm)
    {
        return SYMCRYPT_HMAC_SHA512_INPUT_BLOCK_SIZE;
    }
    else if (ctx->pMac == SymCryptAesCmacAlgorithm)
    {
        return SYMCRYPT_AES_CMAC_INPUT_BLOCK_SIZE;
    }

    return 0;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_init(PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                              PCBYTE pbKey, SIZE_T cbKey)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (pbKey != NULL &&
        ctx->pMac->expandKeyFunc(&ctx->expandedKey, pbKey, cbKey) != SYMCRYPT_NO_ERROR)
    {
        return SCOSSL_FAILURE;
    }

    ctx->pMac->initFunc(&ctx->macState, &ctx->expandedKey);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_update(PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                                PCBYTE pbData, SIZE_T cbData)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    ctx->pMac->appendFunc(&ctx->macState, pbData, cbData);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_final(PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                               PBYTE pbResult, SIZE_T *cbResult, SIZE_T outsize)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (pbResult != NULL)
    {
        if (outsize < ctx->pMac->resultSize)
        {
            return SCOSSL_FAILURE;
        }

        ctx->pMac->resultFunc(&ctx->macState, pbResult);
    }

    *cbResult = ctx->pMac->resultSize;

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif