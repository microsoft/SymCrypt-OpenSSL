//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_SRTP_KDF_SALT_SIZE (112 / 8)

#define SCOSSL_KDF_PARAM_SRTP_RATE "rate"
#define SCOSSL_KDF_PARAM_SRTP_INDEX "index"
#define SCOSSL_KDF_PARAM_SRTP_INDEX_WIDTH "index-width"

typedef struct
{
    // pKey is immediately expanded into expandedKey. It is only kept
    // in the context for duplication and initialization checks.
    PBYTE pKey;
    SIZE_T cbKey;
    SYMCRYPT_SRTPKDF_EXPANDED_KEY expandedKey;

    BYTE pbSalt[SCOSSL_SRTP_KDF_SALT_SIZE];
    BOOL isSaltSet;

    UINT32 uKeyDerivationRate;
    UINT64 uIndex;
    UINT32 uIndexWidth;
    BYTE label;
} SCOSSL_PROV_SRTPKDF_CTX;

static const OSSL_PARAM p_scossl_srtpkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_srtpkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_uint(SCOSSL_KDF_PARAM_SRTP_RATE, NULL),
    OSSL_PARAM_uint(SCOSSL_KDF_PARAM_SRTP_INDEX, NULL),
    OSSL_PARAM_uint(SCOSSL_KDF_PARAM_SRTP_INDEX_WIDTH, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_newctx(ossl_unused void *provctx)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));
}

static void p_scossl_srtpkdf_freectx(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_SRTPKDF_EXPANDED_KEY));
    OPENSSL_secure_clear_free(ctx->pKey, ctx->cbKey);
    OPENSSL_free(ctx);
}

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_dupctx(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_PROV_SRTPKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (copyCtx != NULL)
    {
        if (ctx->pKey != NULL)
        {
            if ((copyCtx->pKey = OPENSSL_secure_malloc(ctx->cbKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(copyCtx->pKey, ctx->pKey, ctx->cbKey);
            copyCtx->cbKey = ctx->cbKey;
        }
        else
        {
            copyCtx->pKey = NULL;
            copyCtx->cbKey = 0;
        }

        if (ctx->isSaltSet)
        {
            memcpy(copyCtx->pbSalt, ctx->pbSalt, SCOSSL_SRTP_KDF_SALT_SIZE);
        }

        copyCtx->isSaltSet = ctx->isSaltSet;
        copyCtx->uKeyDerivationRate = ctx->uKeyDerivationRate;
        copyCtx->uIndex = ctx->uIndex;
        copyCtx->uIndexWidth = ctx->uIndexWidth;
        copyCtx->label = ctx->label;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status == SCOSSL_FAILURE)
    {
        p_scossl_srtpkdf_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_srtpkdf_reset(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_SRTPKDF_EXPANDED_KEY));
    OPENSSL_secure_clear_free(ctx->pKey, ctx->cbKey);
    ctx->pKey = NULL;
    ctx->cbKey = 0;
    ctx->isSaltSet = FALSE;
    ctx->uKeyDerivationRate = 0;
    ctx->uIndex = 0;
    ctx->uIndexWidth = 0;
    ctx->label = 0;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_srtpkdf_derive(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx,
                                             _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                             _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;

    if (p_scossl_srtpkdf_set_ctx_params(ctx, params) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->pKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (!ctx->isSaltSet)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return SCOSSL_FAILURE;
    }

    scError = SymCryptSrtpKdfDerive(
        &ctx->expandedKey,
        ctx->pbSalt, SCOSSL_SRTP_KDF_SALT_SIZE,
        ctx->uKeyDerivationRate,
        ctx->uIndex, ctx->uIndexWidth,
        ctx->label,
        key, keylen);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_srtpkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_srtpkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_srtpkdf_get_ctx_params(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_srtpkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_srtpkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_srtpkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_srtpkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_srtpkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_srtpkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif