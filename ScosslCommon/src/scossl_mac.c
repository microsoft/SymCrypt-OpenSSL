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

static const SCOSSL_MAC_EX SymCryptHmacSha3_256Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha3_256KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha3_256StateCopy,
    SYMCRYPT_HMAC_SHA3_256_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptHmacSha3_384Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha3_384KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha3_384StateCopy,
    SYMCRYPT_HMAC_SHA3_384_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptHmacSha3_512Ex = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptHmacSha3_512KeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptHmacSha3_512StateCopy,
    SYMCRYPT_HMAC_SHA3_512_INPUT_BLOCK_SIZE
};

static const SCOSSL_MAC_EX SymCryptAesCmacEx = {
    (PSYMCRYPT_MAC_KEY_COPY)SymCryptAesCmacKeyCopy,
    (PSYMCRYPT_MAC_STATE_COPY)SymCryptAesCmacStateCopy,
    SYMCRYPT_AES_CMAC_INPUT_BLOCK_SIZE
};

_Use_decl_annotations_
SCOSSL_MAC_CTX *scossl_mac_dupctx(SCOSSL_MAC_CTX *ctx)
{
    SCOSSL_STATUS success = SCOSSL_FAILURE;
    SCOSSL_MAC_CTX *copyCtx = NULL;

    if ((copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_MAC_CTX))) != NULL)
    {
        if (ctx->pbKey != NULL)
        {
            if ((copyCtx->pbKey = OPENSSL_malloc(ctx->cbKey)) == NULL)
            {
                goto cleanup;
            }

            memcpy(copyCtx->pbKey, ctx->pbKey, ctx->cbKey);
            copyCtx->cbKey = ctx->cbKey;
        }

        copyCtx->pMac = ctx->pMac;
        copyCtx->pMacEx = ctx->pMacEx;

        if (ctx->pMacEx != NULL)
        {
            if (ctx->expandedKey != NULL)
            {
                SCOSSL_COMMON_ALIGNED_ALLOC_EX(expandedKey, OPENSSL_malloc, SCOSSL_MAC_EXPANDED_KEY, ctx->pMac->expandedKeySize);
                if (expandedKey == NULL)
                {
                    goto cleanup;
                }

                copyCtx->expandedKey = expandedKey;
                ctx->pMacEx->keyCopyFunc(ctx->expandedKey, copyCtx->expandedKey);
            }

            if (ctx->macState != NULL)
            {
                SCOSSL_COMMON_ALIGNED_ALLOC_EX(macState, OPENSSL_malloc, SCOSSL_MAC_STATE, ctx->pMac->stateSize);
                if (macState == NULL)
                {
                    goto cleanup;
                }

                copyCtx->macState = macState;
                ctx->pMacEx->stateCopyFunc(ctx->macState, ctx->expandedKey, copyCtx->macState);
            }
        }

        copyCtx->mdName = OPENSSL_strdup(ctx->mdName);
        copyCtx->libctx = ctx->libctx;
    }

    success = SCOSSL_SUCCESS;

cleanup:
    if (!success)
    {
        scossl_mac_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_mac_freectx(SCOSSL_MAC_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->expandedKey != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->expandedKey, OPENSSL_clear_free, ctx->pMac->expandedKeySize);
    }

    if (ctx->macState != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->macState, OPENSSL_clear_free, ctx->pMac->stateSize);
    }

    OPENSSL_free(ctx->mdName);
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);

    OPENSSL_free(ctx);
}

// HMAC
_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_hmac_md(SCOSSL_MAC_CTX *ctx, int mdNid)
{
    if (ctx->macState != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->macState, OPENSSL_clear_free, ctx->pMac->stateSize);
        ctx->macState = NULL;
    }

    if (ctx->expandedKey != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->expandedKey, OPENSSL_clear_free, ctx->pMac->expandedKeySize);
        ctx->expandedKey = NULL;
    }

    switch (mdNid)
    {
    case NID_sha1:
        ctx->pMac = SymCryptHmacSha1Algorithm;
        ctx->pMacEx = &SymCryptHmacSha1Ex;
        break;
    case NID_sha256:
        ctx->pMac = SymCryptHmacSha256Algorithm;
        ctx->pMacEx = &SymCryptHmacSha256Ex;
        break;
    case NID_sha384:
        ctx->pMac = SymCryptHmacSha384Algorithm;
        ctx->pMacEx = &SymCryptHmacSha384Ex;
        break;
    case NID_sha512:
        ctx->pMac = SymCryptHmacSha512Algorithm;
        ctx->pMacEx = &SymCryptHmacSha512Ex;
        break;
    case NID_sha3_256:
        ctx->pMac = SymCryptHmacSha3_256Algorithm;
        ctx->pMacEx = &SymCryptHmacSha3_256Ex;
        break;
    case NID_sha3_384:
        ctx->pMac = SymCryptHmacSha3_384Algorithm;
        ctx->pMacEx = &SymCryptHmacSha3_384Ex;
        break;
    case NID_sha3_512:
        ctx->pMac = SymCryptHmacSha3_512Algorithm;
        ctx->pMacEx = &SymCryptHmacSha3_512Ex;
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_MAC_SET_HMAC_MD, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SCOSSL does not support hash algorithm for MAC %d", mdNid);
        return SCOSSL_FAILURE;
    }

    SCOSSL_COMMON_ALIGNED_ALLOC_EX(macState, OPENSSL_malloc, SCOSSL_MAC_STATE, ctx->pMac->stateSize);
    ctx->macState = macState;

    return ctx->macState != NULL;
}

// CMAC
_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_cmac_cipher(SCOSSL_MAC_CTX *ctx, const EVP_CIPHER *cipher)
{
    if (ctx->macState != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->macState, OPENSSL_clear_free, ctx->pMac->stateSize);
        ctx->macState = NULL;
    }

    if (ctx->expandedKey != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->expandedKey, OPENSSL_clear_free, ctx->pMac->expandedKeySize);
        ctx->expandedKey = NULL;
    }

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

    SCOSSL_COMMON_ALIGNED_ALLOC_EX(macState, OPENSSL_malloc, SCOSSL_MAC_STATE, ctx->pMac->stateSize);
    ctx->macState = macState;

    return ctx->macState != NULL;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_set_mac_key(SCOSSL_MAC_CTX *ctx,
                                     PCBYTE pbMacKey, SIZE_T cbMacKey)
{
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
SCOSSL_STATUS scossl_mac_init(SCOSSL_MAC_CTX *ctx,
                              PCBYTE pbKey, SIZE_T cbKey)
{
    SYMCRYPT_ERROR scError;

    if (pbKey != NULL)
    {
        if (ctx->expandedKey == NULL)
        {
            SCOSSL_COMMON_ALIGNED_ALLOC_EX(expandedKey, OPENSSL_malloc, SCOSSL_MAC_EXPANDED_KEY, ctx->pMac->expandedKeySize);
            if (expandedKey == NULL)
            {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_MAC_INIT, ERR_R_INTERNAL_ERROR,
                    "Failed to aligned allocated expanded key");
                return SCOSSL_FAILURE;
            }

            ctx->expandedKey = expandedKey;
        }

        scError = ctx->pMac->expandKeyFunc(ctx->expandedKey, pbKey, cbKey);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_MAC_INIT,
                "SymCryptMacExpandKey failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    ctx->pMac->initFunc(ctx->macState, ctx->expandedKey);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_update(SCOSSL_MAC_CTX *ctx,
                                PCBYTE pbData, SIZE_T cbData)
{
    ctx->pMac->appendFunc(ctx->macState, pbData, cbData);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_mac_final(SCOSSL_MAC_CTX *ctx,
                               PBYTE pbResult, SIZE_T *cbResult, SIZE_T outsize)
{
    if (pbResult != NULL)
    {
        if (outsize < ctx->pMac->resultSize)
        {
            return SCOSSL_FAILURE;
        }

        ctx->pMac->resultFunc(ctx->macState, pbResult);
    }

    *cbResult = ctx->pMac->resultSize;

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif