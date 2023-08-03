//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Needed for fetching cipher
    OSSL_LIB_CTX *libctx;

    SIZE_T cbKey;

    SYMCRYPT_AES_CMAC_EXPANDED_KEY expandedKey;
    SYMCRYPT_AES_CMAC_STATE macState;
} SCOSSL_CMAC_CTX;

typedef PVOID PSCOSSL_CMAC_ALIGNED_CTX;

static const OSSL_PARAM p_scossl_cmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cmac_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx, const _In_ OSSL_PARAM params[]);

static PSCOSSL_CMAC_ALIGNED_CTX *p_scossl_cmac_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    PSCOSSL_CMAC_ALIGNED_CTX alignedCtx = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_CMAC_CTX));
    if (alignedCtx != NULL)
    {
        SCOSSL_CMAC_CTX *ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

        ctx->libctx = provctx->libctx;
    }

    return alignedCtx;
}

static void p_scossl_cmac_freectx(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx)
{
    if (alignedCtx == NULL)
        return;

    SCOSSL_COMMON_ALIGNED_FREE(alignedCtx, OPENSSL_clear_free, SCOSSL_CMAC_CTX);
}

static PSCOSSL_CMAC_ALIGNED_CTX p_scossl_cmac_dupctx(_In_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_CMAC_CTX *ctx, *copyCtx;
    PSCOSSL_CMAC_ALIGNED_CTX alignedCopy;

    if ((alignedCopy = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_CMAC_CTX))) == NULL)
    {
        return NULL;
    }

    ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    copyCtx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCopy);

    SymCryptAesCmacKeyCopy(&ctx->expandedKey, &copyCtx->expandedKey);
    SymCryptAesCmacStateCopy(&ctx->macState, &copyCtx->expandedKey, &copyCtx->macState);
    copyCtx->cbKey = ctx->cbKey;
    copyCtx->libctx = ctx->libctx;

    return alignedCopy;
}

static SCOSSL_STATUS p_scossl_cmac_init(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        const _In_ OSSL_PARAM params[])
{
    SCOSSL_CMAC_CTX *ctx;

    if (!p_scossl_cmac_set_ctx_params(alignedCtx, params))
    {
        return SCOSSL_FAILURE;
    }

    ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (key != NULL &&
        ((keylen | ctx->cbKey) != keylen ||
         SymCryptAesCmacExpandKey(&ctx->expandedKey, key, keylen) != SYMCRYPT_NO_ERROR))
    {
        return SCOSSL_FAILURE;
    }

    SymCryptAesCmacInit(&ctx->macState, &ctx->expandedKey);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cmac_update(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx,
                                          _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SCOSSL_CMAC_CTX *ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    SymCryptAesCmacAppend(&ctx->macState, in, inl);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cmac_final(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx,
                                         _Out_writes_bytes_opt_(*outl) char *out, _Out_ size_t *outl, size_t outsize)
{
    SCOSSL_CMAC_CTX *ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (out != NULL)
    {
        if (outsize < SYMCRYPT_AES_CMAC_RESULT_SIZE)
        {
            return SCOSSL_FAILURE;
        }

        SymCryptAesCmacResult(&ctx->macState, (PBYTE)out);
    }

    *outl = SYMCRYPT_AES_CMAC_RESULT_SIZE;

    return SCOSSL_SUCCESS;
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

static SCOSSL_STATUS p_scossl_cmac_set_ctx_params(_Inout_ PSCOSSL_CMAC_ALIGNED_CTX alignedCtx, const _In_ OSSL_PARAM params[])
{
    SCOSSL_CMAC_CTX *ctx = (SCOSSL_CMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER)) != NULL)
    {
        const OSSL_PARAM *param_propq;
        const char *cipherName, *cipherProps;
        EVP_CIPHER *cipher;
        SIZE_T cbKey = 0;

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

        switch (EVP_CIPHER_get_nid(cipher))
        {
        case NID_aes_128_cbc:
            cbKey = 16;
            break;
        case NID_aes_192_cbc:
            cbKey = 24;
            break;
        case NID_aes_256_cbc:
            cbKey = 32;
            break;
        }
        EVP_CIPHER_free(cipher);

        if (cbKey == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return SCOSSL_FAILURE;
        }

        ctx->cbKey = cbKey;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        PCBYTE pbMacKey;
        SIZE_T cbMacKey;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbMacKey, &cbMacKey) ||
            (cbMacKey | ctx->cbKey) != cbMacKey ||
            SymCryptAesCmacExpandKey(&ctx->expandedKey, pbMacKey, cbMacKey) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        SymCryptAesCmacInit(&ctx->macState, &ctx->expandedKey);
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