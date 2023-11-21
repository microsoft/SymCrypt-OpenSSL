//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

static const SCOSSL_MAC_EX SymCryptHmacSha1Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha1KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha1StateCopy,
    SYMCRYPT_HMAC_SHA1_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptHmacSha256Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha256KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha256StateCopy,
    SYMCRYPT_HMAC_SHA256_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptHmacSha384Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha384KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha384StateCopy,
    SYMCRYPT_HMAC_SHA384_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptHmacSha512Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha512KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha512StateCopy,
    SYMCRYPT_HMAC_SHA512_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptAesCmacEx = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptAesCmacKeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptAesCmacStateCopy,
    SYMCRYPT_AES_CMAC_INPUT_BLOCK_SIZE
};

PSCOSSL_MAC_ALIGNED_CTX scossl_mac_newctx()
{
    return OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_MAC_CTX));
}

_Use_decl_annotations_
PSCOSSL_MAC_ALIGNED_CTX scossl_mac_dupctx(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    PSCOSSL_MAC_ALIGNED_CTX alignedCopy;
    SCOSSL_MAC_CTX *ctx, *copyCtx;

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
    if (ctx->pMacEx != NULL)
    {
        copyCtx->pMacEx = ctx->pMacEx;

        ctx->pMacEx->keyCopyFunc(&ctx->expandedKey, &copyCtx->expandedKey);
        ctx->pMacEx->stateCopyFunc(&ctx->macState, &copyCtx->expandedKey, &copyCtx->macState);
    }

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

// HMAC
_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_md(PSCOSSL_MAC_ALIGNED_CTX alignedCtx, const EVP_MD *md)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    int type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        ctx->pMac = SymCryptHmacSha1Algorithm;
        ctx->pMacEx = &SymCryptHmacSha1Ex;
        return SCOSSL_SUCCESS;
    case NID_sha256:
        ctx->pMac = SymCryptHmacSha256Algorithm;
        ctx->pMacEx = &SymCryptHmacSha256Ex;
        return SCOSSL_SUCCESS;
    case NID_sha384:
        ctx->pMac = SymCryptHmacSha384Algorithm;
        ctx->pMacEx = &SymCryptHmacSha384Ex;
        return SCOSSL_SUCCESS;
    case NID_sha512:
        ctx->pMac = SymCryptHmacSha512Algorithm;
        ctx->pMacEx = &SymCryptHmacSha512Ex;
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "SCOSSL does not support hash algorithm for MAC %d", type);
    }

    return SCOSSL_FAILURE;
}

// CMAC
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
    ctx->pMac = SymCryptAesCmacAlgorithm;;
    ctx->pMacEx = &SymCryptAesCmacEx;

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
    return ctx->pMacEx == NULL ? 0 : ctx->pMac->resultSize;
}

_Use_decl_annotations_
SIZE_T scossl_mac_get_block_size(PSCOSSL_MAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_MAC_CTX *ctx = (SCOSSL_MAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    return ctx->pMacEx == NULL ? 0 : ctx->pMacEx->blockSize;
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