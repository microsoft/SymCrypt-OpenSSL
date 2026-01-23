//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants defined SP800-132 that should be checked
// unless the OSSL_KDF_PARAM_PKCS5 parameter gets set
#define SCOSSL_PBKDF2_MIN_KEY_LEN_BITS  (112)
#define SCOSSL_PBKDF2_MIN_ITERATIONS (1000)
#define SCOSSL_PBKDF2_MIN_SALT_LEN   (128 / 8)
#define SCOSSL_PKCS5_DEFAULT_ITER    (2048)

typedef struct {
    OSSL_LIB_CTX *libctx;

    PBYTE pbPassword;
    SIZE_T cbPassword;
    PBYTE pbSalt;
    SIZE_T cbSalt;

    PCSYMCRYPT_MAC pMac;
    SYMCRYPT_PBKDF2_EXPANDED_KEY expandedKey;
    BOOL initialized;

    UINT64 iterationCount;
    BOOL checkMinSizes;
} SCOSSL_PROV_PBKDF2_CTX;

static const OSSL_PARAM p_scossl_pbkdf2_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_pbkdf2_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL),
    OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS5, NULL),
    OSSL_PARAM_END};

SCOSSL_STATUS p_scossl_pbkdf2_set_ctx_params(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx, _In_ const OSSL_PARAM params[]);

SCOSSL_PROV_PBKDF2_CTX *p_scossl_pbkdf2_newctx(SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_PBKDF2_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_PBKDF2_CTX));

    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
        ctx->pMac = SymCryptHmacSha1Algorithm;
        ctx->iterationCount = SCOSSL_PKCS5_DEFAULT_ITER;
        ctx->checkMinSizes = FALSE;
    }

    return ctx;
}

void p_scossl_pbkdf2_freectx(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    if (ctx == NULL)
        return;

    SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_PBKDF2_EXPANDED_KEY));
    OPENSSL_secure_clear_free(ctx->pbPassword, ctx->cbPassword);
    OPENSSL_free(ctx->pbSalt);
    OPENSSL_free(ctx);
}

SCOSSL_PROV_PBKDF2_CTX *p_scossl_pbkdf2_dupctx(_In_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    SCOSSL_PROV_PBKDF2_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_PBKDF2_CTX));
    if (copyCtx != NULL)
    {
        copyCtx->libctx = ctx->libctx;
        copyCtx->pMac = ctx->pMac;
        copyCtx->iterationCount = ctx->iterationCount;
        copyCtx->checkMinSizes = ctx->checkMinSizes;
        copyCtx->initialized = FALSE;

        if (ctx->pbPassword != NULL)
        {
            if ((copyCtx->pbPassword = OPENSSL_secure_malloc(ctx->cbPassword)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(copyCtx->pbPassword, ctx->pbPassword, ctx->cbPassword);
            copyCtx->cbPassword = ctx->cbPassword;
        }

        if (ctx->pbSalt != NULL &&
            (copyCtx->pbSalt = OPENSSL_memdup(ctx->pbSalt, ctx->cbSalt)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
        copyCtx->cbSalt = ctx->cbSalt;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_pbkdf2_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

SCOSSL_STATUS p_scossl_pbkdf2_reset(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    OPENSSL_secure_clear_free(ctx->pbPassword, ctx->cbPassword);
    OPENSSL_free(ctx->pbSalt);
    SymCryptWipeKnownSize(&ctx->expandedKey, sizeof(SYMCRYPT_SRTPKDF_EXPANDED_KEY));

    ctx->pbPassword = NULL;
    ctx->cbPassword = 0;
    ctx->pbSalt = NULL;
    ctx->cbSalt = 0;
    ctx->pMac = SymCryptHmacSha1Algorithm;
    ctx->initialized = FALSE;
    ctx->iterationCount = PKCS5_DEFAULT_ITER;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_pbkdf2_derive(_In_ SCOSSL_PROV_PBKDF2_CTX *ctx,
                                     _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                     _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;

    if (!p_scossl_pbkdf2_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->pMac == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return SCOSSL_FAILURE;
    }

    if (!ctx->initialized)
    {
        scError = SymCryptPbkdf2ExpandKey(&ctx->expandedKey, ctx->pMac, ctx->pbPassword, ctx->cbPassword);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptPbkdf2ExpandKey failed", scError);
            return SCOSSL_FAILURE;
        }

        ctx->initialized = TRUE;
    }

    if (ctx->checkMinSizes)
    {
        if ((keylen * 8) < SCOSSL_PBKDF2_MIN_KEY_LEN_BITS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return SCOSSL_FAILURE;
        }

        if (ctx->cbSalt < SCOSSL_PBKDF2_MIN_SALT_LEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return SCOSSL_FAILURE;
        }

        if (ctx->iterationCount < SCOSSL_PBKDF2_MIN_ITERATIONS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
            return SCOSSL_FAILURE;
        }
    }

    if (keylen > 0)
    {
        scError = SymCryptPbkdf2Derive(
            &ctx->expandedKey,
            ctx->pbSalt, ctx->cbSalt,
            ctx->iterationCount,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptPbkdf2Derive failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_pbkdf2_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_pbkdf2_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_pbkdf2_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_pbkdf2_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_pbkdf2_get_ctx_params(ossl_unused void *ctx, _Inout_ OSSL_PARAM params[])
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

SCOSSL_STATUS p_scossl_pbkdf2_set_ctx_params(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    EVP_MD *md = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5)) != NULL)
    {
        int pkcs5;

        if (!OSSL_PARAM_get_int(p, &pkcs5))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        ctx->checkMinSizes = pkcs5 == 0;
    }


    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD)) != NULL)
    {
        OPENSSL_secure_clear_free(ctx->pbPassword, ctx->cbPassword);
        ctx->pbPassword = NULL;
        ctx->cbPassword = p->data_size;

        if (p->data_size != 0)
        {
            if ((ctx->pbPassword = OPENSSL_secure_malloc(ctx->cbPassword)) == NULL)
            {
                ctx->cbPassword = 0;
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbPassword, ctx->cbPassword, &ctx->cbPassword))
            {
                OPENSSL_secure_clear_free(ctx->pbPassword, ctx->cbPassword);
                ctx->pbPassword = NULL;
                ctx->cbPassword = 0;

                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        ctx->initialized = FALSE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        if (ctx->checkMinSizes && p->data_size < SCOSSL_PBKDF2_MIN_SALT_LEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            goto cleanup;
        }

        OPENSSL_free(ctx->pbSalt);
        ctx->pbSalt = NULL;
        ctx->cbSalt = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbSalt, 0, &ctx->cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        const char *mdName;
        const char *mdProps = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES)) != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((md = EVP_MD_fetch(ctx->libctx, mdName, mdProps)) == NULL ||
            (ctx->pMac = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(md))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }

        ctx->initialized = FALSE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER)) != NULL)
    {
        uint64_t iterationCount;
        uint64_t minIterationCount = ctx->checkMinSizes ? SCOSSL_PBKDF2_MIN_ITERATIONS : 1;

        if (!OSSL_PARAM_get_uint64(p, &iterationCount))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (iterationCount < minIterationCount)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
            goto cleanup;
        }

        ctx->iterationCount = iterationCount;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    EVP_MD_free(md);

    return ret;
}

const OSSL_DISPATCH p_scossl_pbkdf2_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_pbkdf2_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_pbkdf2_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_pbkdf2_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_pbkdf2_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_pbkdf2_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif