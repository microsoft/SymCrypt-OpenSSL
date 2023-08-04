//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Needed for fetching cipher
    OSSL_LIB_CTX *libctx;

    PSCOSSL_MAC_ALIGNED_CTX cmacAlignedCtx;
} SCOSSL_PROV_CMAC_CTX;

static const OSSL_PARAM p_scossl_cmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cmac_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_PROV_CMAC_CTX *p_scossl_cmac_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_CMAC_CTX *ctx = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_PROV_CMAC_CTX));
    if (ctx != NULL)
    {
        if ((ctx->cmacAlignedCtx = scossl_mac_newctx()) == NULL)
        {
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

static void p_scossl_cmac_freectx(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx)
{
    if (ctx == NULL)
        return;

    scossl_mac_freectx(ctx->cmacAlignedCtx);
    OPENSSL_free(ctx);

}

static SCOSSL_PROV_CMAC_CTX* p_scossl_cmac_dupctx(_In_ SCOSSL_PROV_CMAC_CTX *ctx)
{
    SCOSSL_PROV_CMAC_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_CMAC_CTX));

    if (copyCtx != NULL)
    {
        if ((copyCtx->cmacAlignedCtx = scossl_mac_dupctx(ctx)) == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }

        copyCtx->libctx = ctx->libctx;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_cmac_init(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        const _In_ OSSL_PARAM params[])
{
    return p_scossl_cmac_set_ctx_params(ctx, params) &&
           scossl_mac_init(ctx->cmacAlignedCtx, key, keylen);

}

static SCOSSL_STATUS p_scossl_cmac_update(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx,
                                          _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return scossl_mac_update(ctx->cmacAlignedCtx, in, inl);
}

static SCOSSL_STATUS p_scossl_cmac_final(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx,
                                         _Out_writes_bytes_opt_(*outl) char *out, _Out_ size_t *outl, size_t outsize)
{
    return scossl_mac_final(ctx->cmacAlignedCtx, (PBYTE) out, outl, outsize);

}

static const OSSL_PARAM *p_scossl_cmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_cmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_cmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_cmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_cmac_get_ctx_params(ossl_unused void *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_CMAC_RESULT_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SYMCRYPT_AES_CMAC_INPUT_BLOCK_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ SCOSSL_PROV_CMAC_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER)) != NULL)
    {
        SCOSSL_STATUS success;
        const OSSL_PARAM *param_propq;
        const char *cipherName, *cipherProps;
        EVP_CIPHER *cipher;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &cipherName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        cipherProps = NULL;
        param_propq = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
        if ((param_propq != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &cipherProps)) ||
            (cipher = EVP_CIPHER_fetch(ctx->libctx, cipherName, cipherProps)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        success = scossl_mac_set_cipher(ctx->cmacAlignedCtx, cipher);
        EVP_CIPHER_free(cipher);

        if (!success)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        PCBYTE pbMacKey;
        SIZE_T cbMacKey;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbMacKey, &cbMacKey) ||
            !scossl_mac_init(ctx->cmacAlignedCtx, pbMacKey, cbMacKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_cmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_cmac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_cmac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_cmac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_cmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_cmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_cmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_cmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_cmac_set_ctx_params},
    {0, NULL}};


#ifdef __cplusplus
}
#endif