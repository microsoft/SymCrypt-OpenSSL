//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_cmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cmac_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_MAC_CTX *p_scossl_cmac_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_MAC_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MAC_CTX));
    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

static SCOSSL_STATUS p_scossl_cmac_init(_Inout_ SCOSSL_MAC_CTX *ctx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        _In_ const OSSL_PARAM params[])
{
    return p_scossl_cmac_set_ctx_params(ctx, params) &&
           scossl_mac_init(ctx, key, keylen);

}

static const OSSL_PARAM *p_scossl_cmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_cmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_cmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_cmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_cmac_get_ctx_params(_In_ SCOSSL_MAC_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->pMac == NULL ? 0 : ctx->pMac->resultSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->pMacEx == NULL ? 0 : ctx->pMacEx->blockSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER)) != NULL)
    {
        SCOSSL_STATUS success;
        const char *cipherName, *cipherProps;
        EVP_CIPHER *cipher;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &cipherName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        cipherProps = NULL;
        p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_PROPERTIES);
        if ((p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &cipherProps)) ||
            (cipher = EVP_CIPHER_fetch(ctx->libctx, cipherName, cipherProps)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        success = scossl_mac_set_cmac_cipher(ctx, cipher);
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
            !scossl_mac_init(ctx, pbMacKey, cbMacKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_cmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_cmac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))scossl_mac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))scossl_mac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_cmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))scossl_mac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))scossl_mac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_cmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_cmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_cmac_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif