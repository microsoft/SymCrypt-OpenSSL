//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"
#include "scossl_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_SRTP_KDF_SALT_SIZE (112 / 8)

#define SCOSSL_SRTP_LABEL_NOT_SET (BYTE)-1

typedef struct
{
    BOOL isSrtcp;

    // pbKey is immediately expanded into expandedKey. It is only kept
    // in the context for duplication and initialization checks. This
    // must be cleared when the context is freed.
    PBYTE pbKey;
    SIZE_T cbKey;
    SYMCRYPT_SRTPKDF_EXPANDED_KEY expandedKey;

    BYTE pbSalt[SCOSSL_SRTP_KDF_SALT_SIZE];
    BOOL isSaltSet;

    BYTE label;
    UINT64 uIndex;
    UINT32 uIndexWidth;
    UINT32 uKeyDerivationRate;
} SCOSSL_PROV_SRTPKDF_CTX;

static const OSSL_PARAM p_scossl_srtpkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_srtpkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
    OSSL_PARAM_uint64(SCOSSL_KDF_PARAM_SRTP_INDEX, NULL),
    OSSL_PARAM_uint64(SCOSSL_KDF_PARAM_SRTP_INDEX_WIDTH, NULL),
    OSSL_PARAM_uint32(SCOSSL_KDF_PARAM_SRTP_RATE, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_newctx(ossl_unused void *provctx)
{
    SCOSSL_PROV_SRTPKDF_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (ctx != NULL)
    {
        ctx->label = SCOSSL_SRTP_LABEL_NOT_SET;
    }

    return ctx;
}

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtcpkdf_newctx(ossl_unused void *provctx)
{
    SCOSSL_PROV_SRTPKDF_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (ctx != NULL)
    {
        ctx->label = SCOSSL_SRTP_LABEL_NOT_SET;
        ctx->isSrtcp = TRUE;
    }

    return ctx;
}

static void p_scossl_srtpkdf_freectx(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_SRTPKDF_EXPANDED_KEY));
    OPENSSL_secure_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_free(ctx);
}

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_dupctx(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_PROV_SRTPKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (copyCtx != NULL)
    {
        if (ctx->pbKey != NULL)
        {
            if ((copyCtx->pbKey = OPENSSL_secure_malloc(ctx->cbKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(copyCtx->pbKey, ctx->pbKey, ctx->cbKey);
            copyCtx->cbKey = ctx->cbKey;

            scError = SymCryptSrtpKdfExpandKey(&copyCtx->expandedKey, copyCtx->pbKey, copyCtx->cbKey);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptSrtpKdfExpandKey failed", scError);
                goto cleanup;
            }
        }
        else
        {
            copyCtx->pbKey = NULL;
            copyCtx->cbKey = 0;
        }

        if (ctx->isSaltSet)
        {
            memcpy(copyCtx->pbSalt, ctx->pbSalt, SCOSSL_SRTP_KDF_SALT_SIZE);
        }

        copyCtx->isSrtcp = ctx->isSrtcp;
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
    OPENSSL_secure_clear_free(ctx->pbKey, ctx->cbKey);

    ctx->pbKey = NULL;
    ctx->cbKey = 0;
    ctx->isSaltSet = FALSE;
    ctx->uKeyDerivationRate = 0;
    ctx->uIndex = 0;
    ctx->uIndexWidth = 0;
    ctx->label = SCOSSL_SRTP_LABEL_NOT_SET;

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

    if (ctx->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (!ctx->isSaltSet)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return SCOSSL_FAILURE;
    }

    if (ctx->label == SCOSSL_SRTP_LABEL_NOT_SET)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_TYPE);
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
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptSrtpKdfDerive failed", scError);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_srtpkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_srtpkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_srtpkdf_get_ctx_params(ossl_unused void *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SIZE_MAX))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
    {
        PBYTE pbKey;
        SIZE_T cbKey;
        SYMCRYPT_ERROR scError;

        OPENSSL_secure_clear_free(ctx->pbKey, ctx->cbKey);
        ctx->pbKey = NULL;
        ctx->cbKey = 0;
        SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_SRTPKDF_EXPANDED_KEY));

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbKey, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        switch (cbKey)
        {
            case 16:
            case 24:
            case 32:
                break;
            default:
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return SCOSSL_FAILURE;
        }

        if ((ctx->pbKey = OPENSSL_secure_malloc(cbKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->pbKey, pbKey, cbKey);
        ctx->cbKey = cbKey;

        scError = SymCryptSrtpKdfExpandKey(&ctx->expandedKey, ctx->pbKey, ctx->cbKey);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            OPENSSL_secure_clear_free(ctx->pbKey, ctx->cbKey);
            ctx->pbKey = NULL;
            ctx->cbKey = 0;

            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptSrtpKdfExpandKey failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        PBYTE pbSalt;
        SIZE_T cbSalt;

        ctx->isSaltSet = FALSE;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbSalt, &cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbSalt != SCOSSL_SRTP_KDF_SALT_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->pbSalt, pbSalt, cbSalt);
        ctx->isSaltSet = TRUE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL)) != NULL)
    {
        const char *pbLabel;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &pbLabel))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (OPENSSL_strcasecmp(pbLabel, SCOSSL_SRTP_LABEL_ENCRYPTION) == 0)
        {
            ctx->label = ctx->isSrtcp ?
                SYMCRYPT_SRTCP_ENCRYPTION_KEY :
                SYMCRYPT_SRTP_ENCRYPTION_KEY;
        }
        else if (OPENSSL_strcasecmp(pbLabel, SCOSSL_SRTP_LABEL_AUTHENTICATION) == 0)
        {
            ctx->label = ctx->isSrtcp ?
                SYMCRYPT_SRTCP_AUTHENTICATION_KEY :
                SYMCRYPT_SRTP_AUTHENTICATION_KEY;
        }
        else if (OPENSSL_strcasecmp(pbLabel, SCOSSL_SRTP_LABEL_SALTING) == 0)
        {
            ctx->label = ctx->isSrtcp ?
                SYMCRYPT_SRTCP_SALTING_KEY :
                SYMCRYPT_SRTP_SALTING_KEY;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_KDF_PARAM_SRTP_INDEX)) != NULL &&
        !OSSL_PARAM_get_uint64(p, &ctx->uIndex))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_KDF_PARAM_SRTP_INDEX_WIDTH)) != NULL)
    {
        if (!OSSL_PARAM_get_uint32(p, &ctx->uIndexWidth))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        switch (ctx->uIndexWidth)
        {
            case 0:
            case 32:
            case 48:
                break;
            default:
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
                return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_KDF_PARAM_SRTP_RATE)) != NULL)
    {
        if (!OSSL_PARAM_get_uint32(p, &ctx->uKeyDerivationRate))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if(ctx->uKeyDerivationRate > (1 << 24)  ||
           (ctx->uKeyDerivationRate & (ctx->uKeyDerivationRate - 1)) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return SCOSSL_FAILURE;
        }
    }

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

const OSSL_DISPATCH p_scossl_srtcpkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_srtcpkdf_newctx},
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