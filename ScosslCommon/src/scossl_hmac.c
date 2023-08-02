//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

PSCOSSL_HMAC_ALIGNED_CTX scossl_hmac_newctx()
{
    return OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_HMAC_CTX));
}

#define SCOSSL_COPY_HMAC_KEY_AND_STATE(lcAlg, UcAlg)                 \
    SymCryptHmac##UcAlg##KeyCopy(&ctx->expandedKey.lcAlg##Key,       \
                                 &copyCtx->expandedKey.lcAlg##Key);  \
    SymCryptHmac##UcAlg##StateCopy(&ctx->macState.lcAlg##State,      \
                                   &copyCtx->expandedKey.lcAlg##Key, \
                                   &copyCtx->macState.lcAlg##State);

_Use_decl_annotations_
PSCOSSL_HMAC_ALIGNED_CTX scossl_hmac_dupctx(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_HMAC_CTX *ctx, *copyCtx;
    PSCOSSL_HMAC_ALIGNED_CTX alignedCopy;

    if ((alignedCopy = scossl_hmac_newctx()) == NULL)
    {
        return NULL;
    }

    ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    copyCtx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCopy);

    if (ctx->pbKey != NULL)
    {
        if ((copyCtx->pbKey = OPENSSL_malloc(ctx->cbKey)) == NULL)
        {
            scossl_hmac_freectx(copyCtx);
            return NULL;
        }

        memcpy(copyCtx->pbKey, ctx->pbKey, ctx->cbKey);
        copyCtx->cbKey = ctx->cbKey;
    }

    copyCtx->pMac = ctx->pMac;

    // Copy the expanded key and mac state
    if(ctx->pMac == SymCryptHmacSha1Algorithm)
    {
        SCOSSL_COPY_HMAC_KEY_AND_STATE(sha1, Sha1);
    }
    else if(ctx->pMac == SymCryptHmacSha256Algorithm)
    {
        SCOSSL_COPY_HMAC_KEY_AND_STATE(sha256, Sha256);
    }
    else if(ctx->pMac == SymCryptHmacSha384Algorithm)
    {
        SCOSSL_COPY_HMAC_KEY_AND_STATE(sha384, Sha384);
    }
    else if(ctx->pMac == SymCryptHmacSha512Algorithm)
    {
        SCOSSL_COPY_HMAC_KEY_AND_STATE(sha512, Sha512);
    }

    return alignedCopy;
}

_Use_decl_annotations_
void scossl_hmac_freectx(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx)
{
    if (alignedCtx == NULL)
        return;

    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    SCOSSL_COMMON_ALIGNED_FREE(alignedCtx, OPENSSL_clear_free, SCOSSL_HMAC_CTX);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_set_md(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx, const EVP_MD *md)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    int type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        ctx->pMac = SymCryptHmacSha1Algorithm;
        break;
    case NID_sha256:
        ctx->pMac = SymCryptHmacSha256Algorithm;
        break;
    case NID_sha384:
        ctx->pMac = SymCryptHmacSha384Algorithm;
        break;
    case NID_sha512:
        ctx->pMac = SymCryptHmacSha512Algorithm;
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "SymCrypt engine does not support hash algorithm %d", type);
        ret = SCOSSL_FAILURE;
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_set_mac_key(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx,
                                      PCBYTE pbMacKey, SIZE_T cbMacKey)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
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
SIZE_T scossl_hmac_get_result_size(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    return ctx->pMac == NULL ? 0 : ctx->pMac->resultSize;
}

_Use_decl_annotations_
SIZE_T scossl_hmac_get_block_size(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

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

    return 0;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_init(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx,
                               PCBYTE pbKey, SIZE_T cbKey)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (pbKey != NULL &&
        ctx->pMac->expandKeyFunc(&ctx->expandedKey, pbKey, cbKey) != SYMCRYPT_NO_ERROR)
    {
        return SCOSSL_FAILURE;
    }

    ctx->pMac->initFunc(&ctx->macState, &ctx->expandedKey);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_update(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx,
                                 PCBYTE pbData, SIZE_T cbData)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    ctx->pMac->appendFunc(&ctx->macState, pbData, cbData);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_final(PSCOSSL_HMAC_ALIGNED_CTX alignedCtx,
                                PBYTE pbResult, SIZE_T *cbResult, SIZE_T outsize)
{
    SCOSSL_HMAC_CTX *ctx = (SCOSSL_HMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (pbResult == NULL)
    {
        *cbResult = ctx->pMac->resultSize;
        return SCOSSL_SUCCESS;
    }

    if (outsize < ctx->pMac->resultSize)
    {
        return SCOSSL_FAILURE;
    }

    ctx->pMac->resultFunc(&ctx->macState, pbResult);
    *cbResult = ctx->pMac->resultSize;

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif