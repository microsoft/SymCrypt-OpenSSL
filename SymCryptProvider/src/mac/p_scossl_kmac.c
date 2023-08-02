//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"


#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KMAC_MAX_OUTPUT_LEN (0xFFFFFF / 8)
#define KMAC_MAX_CUSTOM 512

typedef union
{
    SYMCRYPT_KMAC128_EXPANDED_KEY kmac128Key;
    SYMCRYPT_KMAC256_EXPANDED_KEY kmac256Key;
} SYMCRYPT_KMAC_EXPANDED_KEY;

typedef union
{
    SYMCRYPT_KMAC128_STATE kmac128State;
    SYMCRYPT_KMAC256_STATE kmac256State;
} SYMCRYPT_KMAC_STATE;

typedef SYMCRYPT_ERROR (SYMCRYPT_CALL * PSYMCRYPT_MAC_EXPAND_KEY_EX)
                                        (PVOID pExpandedKey, PCBYTE pbKey, SIZE_T cbKey,
                                         PCBYTE  pbCustomizationString, SIZE_T  cbCustomizationString);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_RESULT_EX) (PVOID pState, PVOID pbResult, SIZE_T cbResult);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_EXTRACT) (PVOID pState, PVOID pbOutput, SIZE_T cbOutput, BOOLEAN bWipe);

typedef struct
{
    SYMCRYPT_KMAC_EXPANDED_KEY expandedKey;
    SYMCRYPT_KMAC_STATE macState;

    PCSYMCRYPT_MAC pMac;

    PSYMCRYPT_MAC_EXPAND_KEY_EX expandKeyExFunc;
    PSYMCRYPT_MAC_RESULT_EX resultExFunc;
    PSYMCRYPT_MAC_EXTRACT extractFunc;

    int xofMode;
    SIZE_T cbOutput;
    BYTE customizationString[KMAC_MAX_CUSTOM];
    SIZE_T cbCustomizationString;
} SCOSSL_KMAC_CTX;

typedef PVOID PSCOSSL_KMAC_ALIGNED_CTX;

static const OSSL_PARAM p_scossl_kmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_kmac_ctx_settable_param_types[] = {
    OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_kmac_set_ctx_params(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx, const _In_ OSSL_PARAM params[]);

static PSCOSSL_KMAC_ALIGNED_CTX *p_scossl_kmac128_newctx(ossl_unused void *provctx)
{
    PSCOSSL_KMAC_ALIGNED_CTX alignedCtx = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_KMAC_CTX));
    if (alignedCtx != NULL)
    {
        SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
        ctx->pMac = SymCryptKmac128Algorithm;
        ctx->expandKeyExFunc = (PSYMCRYPT_MAC_EXPAND_KEY_EX)&SymCryptKmac128ExpandKeyEx;
        ctx->resultExFunc = (PSYMCRYPT_MAC_RESULT_EX)&SymCryptKmac128ResultEx;
        ctx->extractFunc = (PSYMCRYPT_MAC_EXTRACT)&SymCryptKmac128Extract;
        ctx->cbOutput = ctx->pMac->resultSize;
    }
    return alignedCtx;
}

static PSCOSSL_KMAC_ALIGNED_CTX *p_scossl_kmac256_newctx(ossl_unused void *provctx)
{
    PSCOSSL_KMAC_ALIGNED_CTX alignedCtx = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_KMAC_CTX));
    if (alignedCtx != NULL)
    {
        SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
        ctx->pMac = SymCryptKmac256Algorithm;
        ctx->expandKeyExFunc = (PSYMCRYPT_MAC_EXPAND_KEY_EX)&SymCryptKmac256ExpandKeyEx;
        ctx->resultExFunc = (PSYMCRYPT_MAC_RESULT_EX)&SymCryptKmac256ResultEx;
        ctx->extractFunc = (PSYMCRYPT_MAC_EXTRACT)&SymCryptKmac256Extract;
        ctx->cbOutput = ctx->pMac->resultSize;
    }
    return alignedCtx;
}

static void p_scossl_kmac_freectx(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx)
{
    if (alignedCtx == NULL)
        return;

    SCOSSL_COMMON_ALIGNED_FREE(alignedCtx, OPENSSL_clear_free, SCOSSL_KMAC_CTX);
}

static PSCOSSL_KMAC_ALIGNED_CTX p_scossl_kmac_dupctx(_In_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx)
{
    SCOSSL_KMAC_CTX *ctx, *copyCtx;
    PSCOSSL_KMAC_ALIGNED_CTX alignedCopy;

    if ((alignedCopy = OPENSSL_zalloc(SCOSSL_ALIGNED_SIZEOF(SCOSSL_KMAC_CTX))) == NULL)
    {
        return NULL;
    }

    ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    copyCtx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCopy);

    copyCtx->pMac = ctx->pMac;

    if (ctx->pMac == SymCryptKmac128Algorithm)
    {
        SymCryptKmac128KeyCopy(&ctx->expandedKey.kmac128Key,
                               &copyCtx->expandedKey.kmac128Key);
        SymCryptKmac128StateCopy(&ctx->macState.kmac128State,
                                 &copyCtx->macState.kmac128State);
    }
    else if (ctx->pMac == SymCryptKmac256Algorithm)
    {
        SymCryptKmac256KeyCopy(&ctx->expandedKey.kmac256Key,
                               &copyCtx->expandedKey.kmac256Key);
        SymCryptKmac256StateCopy(&ctx->macState.kmac256State,
                                 &copyCtx->macState.kmac256State);
    }

    if (ctx->cbCustomizationString > 0)
    {
        memcpy(copyCtx->customizationString, ctx->customizationString, ctx->cbCustomizationString);
        copyCtx->cbCustomizationString = ctx->cbCustomizationString;
    }

    copyCtx->cbOutput = ctx->cbOutput;
    copyCtx->xofMode = ctx->xofMode;

    return alignedCopy;
}

static SCOSSL_STATUS p_scossl_kmac_init(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        const _In_ OSSL_PARAM params[])
{
    SCOSSL_KMAC_CTX *ctx;

    if (!p_scossl_kmac_set_ctx_params(alignedCtx, params))
    {
        return SCOSSL_FAILURE;
    }

    ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (key != NULL &&
        ctx->expandKeyExFunc(&ctx->expandedKey,
                             key, keylen,
                             ctx->customizationString, ctx->cbCustomizationString) != SYMCRYPT_NO_ERROR)
    {
        return SCOSSL_FAILURE;
    }

    ctx->pMac->initFunc(&ctx->macState, &ctx->expandedKey);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kmac_update(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx,
                                          _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    ctx->pMac->appendFunc(&ctx->macState, in, inl);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kmac_final(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx,
                                         _Out_writes_bytes_(*outl) char *out, _Out_ size_t *outl, size_t outsize)
{
    SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);

    if (outsize < ctx->cbOutput)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->xofMode)
    {
        ctx->extractFunc(&ctx->macState, out, ctx->cbOutput, TRUE);
    }
    else
    {
        ctx->resultExFunc(&ctx->macState, out, ctx->cbOutput);
    }

    *outl = ctx->cbOutput;

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_kmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_kmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_kmac_get_ctx_params(_In_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx, _Inout_ OSSL_PARAM params[])
{
    SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->cbOutput))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL)
    {
        SIZE_T blockSize = 0;
        if (ctx->pMac == SymCryptKmac128Algorithm)
        {
            blockSize = SYMCRYPT_KMAC128_INPUT_BLOCK_SIZE;
        }
        else if (ctx->pMac == SymCryptKmac256Algorithm)
        {
            blockSize = SYMCRYPT_KMAC256_INPUT_BLOCK_SIZE;
        }

        if (blockSize == 0 ||
            !OSSL_PARAM_set_size_t(p, blockSize))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kmac_set_ctx_params(_Inout_ PSCOSSL_KMAC_ALIGNED_CTX alignedCtx, const _In_ OSSL_PARAM params[])
{
    SCOSSL_KMAC_CTX *ctx = (SCOSSL_KMAC_CTX *)SCOSSL_ALIGN_UP(alignedCtx);
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_XOF)) != NULL &&
        !OSSL_PARAM_get_int(p, &ctx->xofMode))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE)) != NULL)
    {
        SIZE_T cbOutput = 0;
        if (!OSSL_PARAM_get_size_t(p, &cbOutput))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
            return SCOSSL_FAILURE;
        }

        if (cbOutput > KMAC_MAX_OUTPUT_LEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        ctx->cbOutput = cbOutput;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        PCBYTE pbMacKey;
        SIZE_T cbMacKey;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbMacKey, &cbMacKey) ||
            ctx->expandKeyExFunc(&ctx->expandedKey,
                                 pbMacKey, cbMacKey,
                                 ctx->customizationString, ctx->cbCustomizationString) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        ctx->pMac->initFunc(&ctx->macState, &ctx->expandedKey);
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM)) != NULL)
    {
        PCBYTE pbCustomizationString;
        SIZE_T cbCustomizationString;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **) &pbCustomizationString, &cbCustomizationString))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (cbCustomizationString > KMAC_MAX_CUSTOM)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
            return 0;
        }

        OPENSSL_cleanse(ctx->customizationString, ctx->cbCustomizationString);
        memcpy(ctx->customizationString, pbCustomizationString, cbCustomizationString);
        ctx->cbCustomizationString = cbCustomizationString;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_kmac128_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_kmac128_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_kmac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_kmac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_kmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_kmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_kmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_set_ctx_params},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_kmac256_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_kmac256_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_kmac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_kmac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_kmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_kmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_kmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif