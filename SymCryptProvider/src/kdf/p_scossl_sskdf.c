//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    OSSL_LIB_CTX *libCtx;

    PBYTE pbSecret;
    SIZE_T cbSecret;
    PBYTE pbSalt;
    SIZE_T cbSalt;
    PBYTE pbInfo;
    SIZE_T cbInfo;
    
    BOOL isSaltExpanded;
    SYMCRYPT_SSKDF_MAC_EXPANDED_SALT expandedSalt;

    EVP_MAC *mac;
    SIZE_T cbKmacResult;

    int mdnid;
    PCSYMCRYPT_HASH pHash;
} SCOSSL_PROV_SSKDF_CTX;

static const OSSL_PARAM p_scossl_sskdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_sskdf_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_MAC_SIZE, NULL),
    OSSL_PARAM_END};


SCOSSL_STATUS p_scossl_sskdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_sskdf_reset(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx);

SCOSSL_PROV_SSKDF_CTX *p_scossl_sskdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_SSKDF_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_SSKDF_CTX));

    if (ctx != NULL)
    {
        ctx->libCtx = provctx->libctx;
    }

    return ctx;
}

void p_scossl_sskdf_freectx(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    p_scossl_sskdf_reset(ctx);
    OPENSSL_free(ctx);
}

SCOSSL_PROV_SSKDF_CTX *p_scossl_sskdf_dupctx(_In_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    SCOSSL_PROV_SSKDF_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_SSKDF_CTX));
    if (copyCtx != NULL)
    {
        if (ctx->pbSecret != NULL)
        {
            if ((copyCtx->pbSecret = OPENSSL_secure_malloc(ctx->cbSecret)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(copyCtx->pbSecret, ctx->pbSecret, ctx->cbSecret);
        }

        if (ctx->pbInfo != NULL &&
            (copyCtx->pbInfo = OPENSSL_memdup(ctx->pbInfo, ctx->cbInfo)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (ctx->pbSalt != NULL &&
            (copyCtx->pbSalt = OPENSSL_memdup(ctx->pbSalt, ctx->cbSalt)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (ctx->mac != NULL && !EVP_MAC_up_ref(ctx->mac))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        copyCtx->libCtx = ctx->libCtx;
        copyCtx->cbSecret = ctx->cbSecret;
        copyCtx->cbSalt = ctx->cbSalt;
        copyCtx->cbInfo = ctx->cbInfo;
        copyCtx->isSaltExpanded = ctx->isSaltExpanded;
        copyCtx->expandedSalt = ctx->expandedSalt;
        copyCtx->mac = ctx->mac;
        copyCtx->cbKmacResult = ctx->cbKmacResult;
        copyCtx->mdnid = ctx->mdnid;
        copyCtx->pHash = ctx->pHash;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_sskdf_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

SCOSSL_STATUS p_scossl_sskdf_reset(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    OPENSSL_secure_clear_free(ctx->pbSecret, ctx->cbSecret);
    OPENSSL_free(ctx->pbSalt);
    OPENSSL_free(ctx->pbInfo);
    EVP_MAC_free(ctx->mac);
    OPENSSL_cleanse(ctx, sizeof(SCOSSL_PROV_SSKDF_CTX));
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_sskdf_derive(_In_ SCOSSL_PROV_SSKDF_CTX *ctx,
                                    _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                    _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;

    if (!p_scossl_sskdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->mac != NULL)
    {
        if (!ctx->isSaltExpanded)
        {   
            PCSYMCRYPT_MAC pcSymCryptMacAlgorithm = NULL;
            if (EVP_MAC_is_a(ctx->mac, OSSL_MAC_NAME_HMAC))
            {
                if (ctx->mdnid == NID_undef)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
                    return SCOSSL_FAILURE;
                }
                
                pcSymCryptMacAlgorithm = scossl_get_symcrypt_hmac_algorithm(ctx->mdnid);
            }
            if (EVP_MAC_is_a(ctx->mac, OSSL_MAC_NAME_KMAC128))
            {
                pcSymCryptMacAlgorithm = SymCryptKmac128Algorithm;
            }
            else if (EVP_MAC_is_a(ctx->mac, OSSL_MAC_NAME_KMAC256))
            {
                pcSymCryptMacAlgorithm = SymCryptKmac256Algorithm;
            }
            
            
            if (pcSymCryptMacAlgorithm == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_MAC_TYPE);
                return SCOSSL_FAILURE;
            }

            scError = SymCryptSskdfMacExpandSalt(
                &ctx->expandedSalt,
                pcSymCryptMacAlgorithm,
                ctx->pbSalt, ctx->cbSalt);
                
            if (scError != SYMCRYPT_NO_ERROR)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                return SCOSSL_FAILURE;
            }

            ctx->isSaltExpanded = TRUE;
        }

        scError = SymCryptSskdfMacDerive(
            &ctx->expandedSalt,
            ctx->cbKmacResult,
            ctx->pbSecret, ctx->cbSecret,
            ctx->pbInfo, ctx->cbInfo,
            key, keylen);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }
    else if (ctx->pHash != NULL)
    {
        scError = SymCryptSskdfHash(
            ctx->pHash,
            ctx->pbSecret, ctx->cbSecret,
            ctx->pbInfo, ctx->cbInfo,
            key, keylen);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_sskdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sskdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_sskdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sskdf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_sskdf_get_ctx_params(_In_ SCOSSL_PROV_SSKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
    {
        SIZE_T cbResult = 0;
        if (EVP_MAC_is_a(ctx->mac, OSSL_MAC_NAME_KMAC128) ||
            EVP_MAC_is_a(ctx->mac, OSSL_MAC_NAME_KMAC256))
        {
            cbResult = SIZE_MAX;
        }
        else if (ctx->pHash != NULL)
        {
            cbResult = SymCryptHashResultSize(ctx->pHash); 
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        }

        if (!OSSL_PARAM_set_size_t(p, cbResult))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_sskdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const char *propq = NULL;
    EVP_MD *md = NULL;
    const OSSL_PARAM *p;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL ||
        // Shared secret may be set by OSSL_KDF_PARAM_KEY instead
        (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) 
    {
        OPENSSL_secure_free(ctx->pbSecret);
        ctx->cbSecret = 0;

        if ((ctx->pbSecret = OPENSSL_secure_malloc(p->data_size)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbSecret, p->data_size, &ctx->cbSecret))
        {
            OPENSSL_secure_free(ctx->pbSecret);
            ctx->pbSecret = NULL;
            ctx->cbSecret = 0;

            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }
    
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        OPENSSL_free(ctx->pbSalt);
        ctx->pbSalt = NULL;
        ctx->cbSalt = 0;
        ctx->isSaltExpanded = FALSE;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbSalt, 0, &ctx->cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL)
    {   
        PBYTE pbCur = NULL;
        SIZE_T cbCur = 0;
        SIZE_T cbInfoMax = 0;

        OPENSSL_free(ctx->pbInfo);
        ctx->cbInfo = 0;

        // Parameters may contain multiple info params that must all be concatenated
        for (;
             p != NULL;
             p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO))
        {
            ctx->cbInfo += p->data_size;
        }

        if ((ctx->pbInfo = OPENSSL_malloc(ctx->cbInfo)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbCur = ctx->pbInfo;
        cbInfoMax = ctx->cbInfo;

        for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
             p != NULL;
             p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO))
        {
            if (!OSSL_PARAM_get_octet_string(p, (void **)&pbCur, cbInfoMax, &cbCur))
            {
                OPENSSL_free(ctx->pbInfo);
                ctx->pbInfo = NULL;
                ctx->cbInfo = 0;

                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            pbCur += cbCur;
            cbInfoMax -= cbCur;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES)) != NULL &&
        !OSSL_PARAM_get_utf8_string_ptr(p, &propq))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        EVP_MD *md;
        const char *mdName;
    
        ctx->pHash = NULL;
        ctx->isSaltExpanded = FALSE;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName) ||
            mdName == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((md = EVP_MD_fetch(ctx->libCtx, mdName, propq)) == NULL ||
            (ctx->mdnid = EVP_MD_type(md)) == NID_undef ||
            (ctx->pHash = scossl_get_symcrypt_hash_algorithm(ctx->mdnid)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC)) != NULL)
    {
        const char *macName;

        EVP_MAC_free(ctx->mac);
        ctx->mac = NULL;
        ctx->isSaltExpanded = FALSE;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &macName) ||
            macName == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((ctx->mac = EVP_MAC_fetch(ctx->libCtx, macName, propq)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC_SIZE)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &ctx->cbKmacResult))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    EVP_MD_free(md);

    return ret;
}

const OSSL_DISPATCH p_scossl_sskdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_sskdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_sskdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_sskdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_sskdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_sskdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif