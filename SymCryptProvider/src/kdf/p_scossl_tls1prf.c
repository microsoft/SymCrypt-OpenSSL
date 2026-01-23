//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kdf/p_scossl_tls1prf.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_tls1prf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_tls1prf_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_PROV_TLS1_PRF_CTX *p_scossl_tls1prf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_TLS1_PRF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_TLS1_PRF_CTX));
    if (ctx != NULL)
    {
        if ((ctx->tls1prfCtx = scossl_tls1prf_newctx()) == NULL)
        {
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->mdName = NULL;
        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

void p_scossl_tls1prf_freectx(_Inout_ SCOSSL_PROV_TLS1_PRF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->mdName);
    scossl_tls1prf_freectx(ctx->tls1prfCtx);
    OPENSSL_free(ctx);
}

SCOSSL_PROV_TLS1_PRF_CTX *p_scossl_tls1prf_dupctx(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    SCOSSL_PROV_TLS1_PRF_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_TLS1_PRF_CTX));
    if (copyCtx != NULL)
    {
        if ((copyCtx->tls1prfCtx = scossl_tls1prf_dupctx(ctx->tls1prfCtx)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (ctx->mdName != NULL &&
            (copyCtx->mdName = OPENSSL_strdup(ctx->mdName)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        copyCtx->libctx = ctx->libctx;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_tls1prf_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_tls1prf_reset(_Inout_ SCOSSL_PROV_TLS1_PRF_CTX *ctx)
{
    OPENSSL_free(ctx->mdName);
    ctx->mdName = NULL;
    return scossl_tls1prf_reset(ctx->tls1prfCtx);
}

SCOSSL_STATUS p_scossl_tls1prf_derive(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx,
                                      _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                      _In_ const OSSL_PARAM params[])
{
    if (!p_scossl_tls1prf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->tls1prfCtx->cbSeed == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return SCOSSL_FAILURE;
    }

    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return SCOSSL_FAILURE;
    }

    return scossl_tls1prf_derive(ctx->tls1prfCtx, key, keylen);
}

const OSSL_PARAM *p_scossl_tls1prf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls1prf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_tls1prf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls1prf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_tls1prf_get_ctx_params(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SIZE_MAX))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mdName == NULL ? "" : ctx->mdName))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SECRET)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->tls1prfCtx->pbSecret, ctx->tls1prfCtx->cbSecret))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SEED)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->tls1prfCtx->seed, ctx->tls1prfCtx->cbSeed))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_tls1prf_set_ctx_params(_Inout_ SCOSSL_PROV_TLS1_PRF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    EVP_MD *md = NULL;
    char *mdName = NULL;
    PCBYTE pbSeed;
    SIZE_T cbSeed;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
        BOOL isTlsPrf1_1 = FALSE;
        const char *paramMdName, *mdProps;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &paramMdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        // Special case to always allow md5_sha1 for tls1.1 PRF compat
        if (OPENSSL_strcasecmp(paramMdName, SN_md5_sha1) != 0)
        {
            mdProps = NULL;
            p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
            if ((p != NULL &&
                !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps)))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            if ((md = EVP_MD_fetch(ctx->libctx, paramMdName, mdProps)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                goto cleanup;
            }

            mdName = OPENSSL_strdup(EVP_MD_get0_name(md));
            symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(md));

            if (symcryptHmacAlg == NULL)
            {
                goto cleanup;
            }
        }
        else
        {
            mdName = OPENSSL_strdup(SN_md5_sha1);
            isTlsPrf1_1 = TRUE;
        }

        OPENSSL_free(ctx->mdName);
        ctx->mdName = mdName;
        mdName = NULL;
        if (ctx->mdName == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        ctx->tls1prfCtx->pHmac = symcryptHmacAlg;
        ctx->tls1prfCtx->isTlsPrf1_1 = isTlsPrf1_1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL)
    {
        OPENSSL_clear_free(ctx->tls1prfCtx->pbSecret, ctx->tls1prfCtx->cbSecret);
        ctx->tls1prfCtx->pbSecret = NULL;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->tls1prfCtx->pbSecret, 0, &ctx->tls1prfCtx->cbSecret))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    // Parameters may contain multiple seed params that must all be processed
    for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
         p != NULL;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_SEED))
    {
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbSeed, &cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (!scossl_tls1prf_append_seed(ctx->tls1prfCtx, pbSeed, cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    EVP_MD_free(md);
    OPENSSL_free(mdName);

    return ret;
}

const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_tls1prf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_tls1prf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_tls1prf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_tls1prf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_tls1prf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif