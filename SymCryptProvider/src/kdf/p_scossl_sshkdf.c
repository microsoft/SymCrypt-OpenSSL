//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/kdf.h>
#include <openssl/proverr.h>

#include "scossl_sshkdf.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Needed for fetching md
    OSSL_LIB_CTX *libctx;

    // Purely informational
    EVP_MD *md;

    SCOSSL_SSHKDF_CTX *sshkdfCtx;
} SCOSSL_PROV_SSHKDF_CTX;

static const OSSL_PARAM p_scossl_sshkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_sshkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_STATUS p_scossl_sshkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSHKDF_CTX *ctx, _In_ const OSSL_PARAM params[]);

SCOSSL_PROV_SSHKDF_CTX *p_scossl_sshkdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_SSHKDF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SSHKDF_CTX));
    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
        ctx->sshkdfCtx = scossl_sshkdf_newctx();
    }

    return ctx;
}

void p_scossl_sshkdf_freectx(_Inout_ SCOSSL_PROV_SSHKDF_CTX *ctx)
{
    if (ctx != NULL)
    {
        scossl_sshkdf_freectx(ctx->sshkdfCtx);
        EVP_MD_free(ctx->md);
    }

    OPENSSL_free(ctx);
}

SCOSSL_PROV_SSHKDF_CTX *p_scossl_sshkdf_dupctx(_In_ SCOSSL_PROV_SSHKDF_CTX *ctx)
{
    SCOSSL_PROV_SSHKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SSHKDF_CTX));
    if (copyCtx != NULL)
    {
        if ((ctx->md != NULL && !EVP_MD_up_ref(ctx->md)) ||
            (copyCtx->sshkdfCtx = scossl_sshkdf_dupctx(ctx->sshkdfCtx)) == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }
        copyCtx->libctx = ctx->libctx;
        copyCtx->md = ctx->md;
    }

    return copyCtx;
}

SCOSSL_STATUS p_scossl_sshkdf_reset(_Inout_ SCOSSL_PROV_SSHKDF_CTX *ctx)
{
    EVP_MD_free(ctx->md);
    ctx->md = NULL;
    return scossl_sshkdf_reset(ctx->sshkdfCtx);
}

SCOSSL_STATUS p_scossl_sshkdf_derive(_In_ SCOSSL_PROV_SSHKDF_CTX *ctx,
                                     _In_reads_bytes_(keylen) unsigned char *key, size_t keylen,
                                     _In_ const OSSL_PARAM params[])
{
    if (!p_scossl_sshkdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    return scossl_sshkdf_derive(ctx->sshkdfCtx, key, keylen);
}

const OSSL_PARAM *p_scossl_sshkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sshkdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_sshkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sshkdf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_sshkdf_get_ctx_params(_In_ SCOSSL_PROV_SSHKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SIZE_MAX))
    {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL ? "" : EVP_MD_get0_name(ctx->md)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->sshkdfCtx->pbKey, ctx->sshkdfCtx->cbKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SSHKDF_XCGHASH)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->sshkdfCtx->pbHashValue, ctx->sshkdfCtx->cbHashValue))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SSHKDF_SESSION_ID)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->sshkdfCtx->pbSessionId, ctx->sshkdfCtx->cbSessionId))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SSHKDF_TYPE)) != NULL)
    {
        char *pData = p->data;

        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
            p->data_size < 1)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        pData[0] = ctx->sshkdfCtx->label;
        p->return_size = 1;
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_sshkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSHKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

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

        if ((md = EVP_MD_fetch(ctx->libctx, mdName, mdProps)) == NULL ||
            (ctx->sshkdfCtx->pHash = scossl_get_symcrypt_hash_algorithm(md)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        ctx->md = md;
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

        OPENSSL_clear_free(ctx->sshkdfCtx->pbKey, ctx->sshkdfCtx->cbKey);
        ctx->sshkdfCtx->pbKey = pbKey;
        ctx->sshkdfCtx->cbKey = cbKey;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_XCGHASH)) != NULL)
    {
        PCBYTE pbHashValue;
        SIZE_T cbHashValue;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbHashValue, &cbHashValue))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbHashValue > SSH_KDF_MAX_DIGEST_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->sshkdfCtx->pbHashValue, pbHashValue, cbHashValue);
        ctx->sshkdfCtx->cbHashValue = cbHashValue;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_SESSION_ID)) != NULL)
    {
        PCBYTE pbSessionId;
        SIZE_T cbSessionId;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbSessionId, &cbSessionId))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbSessionId > SSH_KDF_MAX_DIGEST_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            return SCOSSL_FAILURE;
        }

        memcpy(ctx->sshkdfCtx->pbSessionId, pbSessionId, cbSessionId);
        ctx->sshkdfCtx->cbSessionId = cbSessionId;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_TYPE)) != NULL)
    {
        const char *type;
        if (p->data_size != 1)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &type))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (type[0] < EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV ||
            type[0] > EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
            return 0;
        }

        ctx->sshkdfCtx->label = type[0];
    }

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_sshkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_sshkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_sshkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_sshkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_sshkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_sshkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sshkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sshkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_sshkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_sshkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif