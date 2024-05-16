//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hkdf.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Needed for fetching md
    OSSL_LIB_CTX *libctx;

    SCOSSL_HKDF_CTX *hkdfCtx;
} SCOSSL_PROV_HKDF_CTX;

#define HKDF_MODE_EXTRACT_AND_EXPAND "EXTRACT_AND_EXPAND"
#define HKDF_MODE_EXTRACT_ONLY       "EXTRACT_ONLY"
#define HKDF_MODE_EXPAND_ONLY        "EXPAND_ONLY"

static const OSSL_PARAM p_scossl_hkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_hkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_hkdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_HKDF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_HKDF_CTX));
    if (ctx != NULL)
    {
        if ((ctx->hkdfCtx = scossl_hkdf_newctx()) == NULL)
        {
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

static void p_scossl_hkdf_freectx(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    if (ctx != NULL)
    {
        EVP_MD_free(ctx->hkdfCtx->md);
        scossl_hkdf_freectx(ctx->hkdfCtx);
    }

    OPENSSL_free(ctx);
}

static SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_dupctx(_In_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    SCOSSL_PROV_HKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_HKDF_CTX));
    if (copyCtx != NULL)
    {
        if ((copyCtx->hkdfCtx = scossl_hkdf_dupctx(ctx->hkdfCtx)) == NULL ||
            (ctx->hkdfCtx->md != NULL && !EVP_MD_up_ref(ctx->hkdfCtx->md)))
        {
            scossl_hkdf_freectx(copyCtx->hkdfCtx);
            OPENSSL_free(copyCtx);
            return NULL;
        }

        copyCtx->libctx = ctx->libctx;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_hkdf_reset(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    EVP_MD_free(ctx->hkdfCtx->md);
    return scossl_hkdf_reset(ctx->hkdfCtx);
}

static SCOSSL_STATUS p_scossl_hkdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
                                          _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                          _In_ const OSSL_PARAM params[])
{
    if (!p_scossl_hkdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->hkdfCtx->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    return scossl_hkdf_derive(ctx->hkdfCtx, key, keylen);
}

static const OSSL_PARAM *p_scossl_hkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_hkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_hkdf_get_ctx_params(_In_ SCOSSL_PROV_HKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
    {
        SIZE_T cbResult;
        if (ctx->hkdfCtx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
        {
            if (ctx->hkdfCtx->md == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
                return SCOSSL_FAILURE;
            }

            cbResult = EVP_MD_get_size(ctx->hkdfCtx->md);
        }
        else
        {
            cbResult = SIZE_MAX;
        }

        if (!OSSL_PARAM_set_size_t(p, cbResult))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_MODE)) != NULL)
    {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            const char *mode = NULL;
            switch (ctx->hkdfCtx->mode)
            {
            case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
                mode = HKDF_MODE_EXTRACT_AND_EXPAND;
                break;
            case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
                mode = HKDF_MODE_EXTRACT_ONLY;
                break;
            case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
                mode = HKDF_MODE_EXPAND_ONLY;
                break;
            }

            if (mode == NULL ||
                !OSSL_PARAM_set_utf8_string(p, mode))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return SCOSSL_FAILURE;
            }
        }
        else if (!OSSL_PARAM_set_int(p, ctx->hkdfCtx->mode))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->hkdfCtx->md == NULL ? "" : EVP_MD_get0_name(ctx->hkdfCtx->md)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SALT)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->pbSalt, ctx->hkdfCtx->cbSalt))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->pbKey, ctx->hkdfCtx->cbKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_INFO)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->info, ctx->hkdfCtx->cbInfo))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_hkdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    PCBYTE pbInfo;
    SIZE_T cbInfo;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL)
    {
        int mode = -1;
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXTRACT_AND_EXPAND) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            }
            else if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXTRACT_ONLY) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            }
            else if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXPAND_ONLY) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            }
        }
        else if (!OSSL_PARAM_get_int(p, &mode))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (mode < EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND || mode > EVP_KDF_HKDF_MODE_EXPAND_ONLY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return SCOSSL_FAILURE;
        }

        ctx->hkdfCtx->mode = mode;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        const OSSL_PARAM *param_propq;
        const char *mdName, *mdProps;
        EVP_MD *md;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        param_propq = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
        if (param_propq != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        md = EVP_MD_fetch(ctx->libctx, mdName, mdProps);

        if (md == NULL ||
            !scossl_is_md_supported(EVP_MD_type(md)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        EVP_MD_free(ctx->hkdfCtx->md);
        ctx->hkdfCtx->md = md;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        PBYTE pbSalt = NULL;
        SIZE_T cbSalt = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbSalt, 0, &cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbSalt, ctx->hkdfCtx->cbSalt);
        ctx->hkdfCtx->pbSalt = pbSalt;
        ctx->hkdfCtx->cbSalt = cbSalt;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
    {
        PBYTE pbKey = NULL;
        SIZE_T cbKey = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbKey, 0, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbKey, ctx->hkdfCtx->cbKey);
        ctx->hkdfCtx->pbKey = pbKey;
        ctx->hkdfCtx->cbKey = cbKey;
    }

    // Parameters may contain multiple info params that must all be processed
    for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
         p != NULL;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO))
    {
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbInfo, &cbInfo))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_hkdf_append_info(ctx->hkdfCtx, pbInfo, cbInfo))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_hkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_hkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_hkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_hkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_hkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif