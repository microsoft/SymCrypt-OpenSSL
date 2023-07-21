//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_sshkdf.h"

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
SCOSSL_SSHKDF_CTX *scossl_sshkdf_newctx()
{
    return OPENSSL_zalloc(sizeof(SCOSSL_SSHKDF_CTX));
}

_Use_decl_annotations_
SCOSSL_SSHKDF_CTX *scossl_sshkdf_dupctx(SCOSSL_SSHKDF_CTX *ctx)
{
    SCOSSL_SSHKDF_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_SSHKDF_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->pHash = ctx->pHash;

        copyCtx->cbKey = ctx->cbKey;
        if (ctx->pbKey != NULL &&
            (copyCtx->pbKey = OPENSSL_memdup(ctx->pbKey, ctx->cbKey)) == NULL)
        {
            scossl_sshkdf_freectx(copyCtx);
            return NULL;
        }

        memcpy(copyCtx->pbHashValue, ctx->pbHashValue, ctx->cbHashValue);
        memcpy(copyCtx->pbSessionId, ctx->pbSessionId, ctx->cbSessionId);
        copyCtx->cbHashValue = ctx->cbHashValue;
        copyCtx->cbSessionId = ctx->cbSessionId;
        copyCtx->label = ctx->label;
    }

    return copyCtx;
}

_Use_decl_annotations_
void scossl_sshkdf_freectx(SCOSSL_SSHKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_cleanse(ctx->pbHashValue, sizeof(ctx->pbHashValue));
    OPENSSL_cleanse(ctx->pbSessionId, sizeof(ctx->pbSessionId));
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_sshkdf_reset(SCOSSL_SSHKDF_CTX *ctx)
{
    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_sshkdf_derive(SCOSSL_SSHKDF_CTX *ctx,
                                   PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError;

    if (!ctx->pHash ||
        ctx->cbHashValue == 0)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (!ctx->pbKey)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Key");
        return SCOSSL_FAILURE;
    }

    if (ctx->cbSessionId == 0)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Session ID");
        return SCOSSL_FAILURE;
    }

    if (ctx->label == 0)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Label");
        return SCOSSL_FAILURE;
    }

    scError = SymCryptSshKdf(ctx->pHash,
                             ctx->pbKey, ctx->cbKey,
                             ctx->pbHashValue, ctx->cbHashValue,
                             ctx->label,
                             ctx->pbSessionId, ctx->cbSessionId,
                             key, keylen);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif