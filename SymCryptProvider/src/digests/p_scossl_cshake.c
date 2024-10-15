//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_provider.h"
#include "p_scossl_digest_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    SCOSSL_XOF_STATE_INIT = 0,
    SCOSSL_XOF_STATE_UPDATE,
    SCOSSL_XOF_STATE_FINAL,
    SCOSSL_XOF_STATE_SQUEEZE,
} SCOSSL_XOF_STATE;

typedef union
{
    SYMCRYPT_CSHAKE128_STATE cshake128State;
    SYMCRYPT_CSHAKE256_STATE cshake256State;
} SCOSSL_CSHAKE_STATE;

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_CSHAKE_DIGEST) (
    PCBYTE pbFunctionNameString, SIZE_T cbFunctionNameString,
    PCBYTE pbCustomizationString, SIZE_T cbCustomizationString,
    PCBYTE pbData, SIZE_T cbData,
    PBYTE pbResult, SIZE_T cbResult);

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_CSHAKE_INIT) (
    SCOSSL_CSHAKE_STATE *pState,
    PCBYTE pbFunctionNameString, SIZE_T cbFunctionNameString,
    PCBYTE pbCustomizationString, SIZE_T cbCustomizationString);

typedef struct
{
    PSYMCRYPT_CSHAKE_DIGEST digestFunc;
    PSYMCRYPT_CSHAKE_INIT initFunc;
    PSYMCRYPT_HASH_APPEND_FUNC appendFunc;
    PSYMCRYPT_HASH_EXTRACT extractFunc;
    PSYMCRYPT_HASH_STATE_COPY_FUNC stateCopyFunc;

    SIZE_T blockSize;
    SIZE_T resultSize;
} SCOSSL_CSHAKE_HASH;

static const SCOSSL_CSHAKE_HASH SymCryptCShake128Algorithm = {
    SymCryptCShake128,
    (PSYMCRYPT_CSHAKE_INIT)SymCryptCShake128Init,
    (PSYMCRYPT_HASH_APPEND_FUNC)SymCryptCShake128Append,
    (PSYMCRYPT_HASH_EXTRACT)SymCryptCShake128Extract,
    (PSYMCRYPT_HASH_STATE_COPY_FUNC)SymCryptCShake128StateCopy,
    SYMCRYPT_CSHAKE128_INPUT_BLOCK_SIZE,
    SYMCRYPT_CSHAKE128_RESULT_SIZE};

static const SCOSSL_CSHAKE_HASH SymCryptCShake256Algorithm = {
    SymCryptCShake256,
    (PSYMCRYPT_CSHAKE_INIT)SymCryptCShake256Init,
    (PSYMCRYPT_HASH_APPEND_FUNC)SymCryptCShake256Append,
    (PSYMCRYPT_HASH_EXTRACT)SymCryptCShake256Extract,
    (PSYMCRYPT_HASH_STATE_COPY_FUNC)SymCryptCShake256StateCopy,
    SYMCRYPT_CSHAKE256_INPUT_BLOCK_SIZE,
    SYMCRYPT_CSHAKE256_RESULT_SIZE};

typedef struct
{
    const SCOSSL_CSHAKE_HASH *pHash;
    SCOSSL_CSHAKE_STATE state;
    SCOSSL_XOF_STATE xofState;

    PBYTE pbFunctionNameString;
    SIZE_T cbFunctionNameString;
    PBYTE pbCustomizationString;
    SIZE_T cbCustomizationString;

    SIZE_T xofLen;
} SCOSSL_CSHAKE_CTX;

static const OSSL_PARAM p_scossl_cshake_settable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
    OSSL_PARAM_octet_string(SCOSSL_DIGEST_PARAM_FUNCTION_NAME_STRING, NULL, 0),
    OSSL_PARAM_octet_string(SCOSSL_DIGEST_PARAM_CUSTOMIZATION_STRING, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_cshake_settable_ctx_param_types_initialized[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_cshake_set_ctx_params(_Inout_ SCOSSL_CSHAKE_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_CSHAKE_CTX *p_scossl_cshake_newctx(const SCOSSL_CSHAKE_HASH *pHash)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(ctx, OPENSSL_zalloc, SCOSSL_CSHAKE_CTX);

    if (ctx != NULL)
    {
        ctx->pHash = pHash;
        ctx->xofLen = pHash->resultSize;
    }

    return ctx;
}

static SCOSSL_CSHAKE_CTX *p_scossl_cshake_128_newctx()
{
    return p_scossl_cshake_newctx(&SymCryptCShake128Algorithm);
}

static SCOSSL_CSHAKE_CTX *p_scossl_cshake_256_newctx()
{
    return p_scossl_cshake_newctx(&SymCryptCShake256Algorithm);
}

static void p_scossl_cshake_freectx(_Inout_ SCOSSL_CSHAKE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->pbFunctionNameString);
    OPENSSL_free(ctx->pbCustomizationString);
    SCOSSL_COMMON_ALIGNED_FREE(ctx, OPENSSL_clear_free, SCOSSL_CSHAKE_CTX);
}

static SCOSSL_CSHAKE_CTX *p_scossl_cshake_dupctx(_In_ SCOSSL_CSHAKE_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    SCOSSL_COMMON_ALIGNED_ALLOC(copyCtx, OPENSSL_zalloc, SCOSSL_CSHAKE_CTX);

    if (ctx != NULL)
    {
        if (ctx->pbFunctionNameString != NULL)
        {
            copyCtx->pbFunctionNameString = OPENSSL_memdup(ctx->pbFunctionNameString, ctx->cbFunctionNameString);
            if (copyCtx->pbFunctionNameString == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
        }
        else
        {
            copyCtx->pbFunctionNameString = NULL;
        }
        copyCtx->cbFunctionNameString = ctx->cbFunctionNameString;

        if (ctx->pbCustomizationString != NULL)
        {
            copyCtx->pbCustomizationString = OPENSSL_memdup(ctx->pbCustomizationString, ctx->cbCustomizationString);
            if (copyCtx->pbCustomizationString == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
        }
        else
        {
            copyCtx->pbCustomizationString = NULL;
        }
        copyCtx->cbCustomizationString = ctx->cbCustomizationString;

        ctx->pHash->stateCopyFunc(&ctx->state, &copyCtx->state);

        copyCtx->pHash = ctx->pHash;
        copyCtx->xofState = ctx->xofState;
        copyCtx->xofLen = ctx->xofLen;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_cshake_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_cshake_init(_Inout_ SCOSSL_CSHAKE_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    ctx->xofState = SCOSSL_XOF_STATE_INIT;

    return p_scossl_cshake_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_cshake_update(_Inout_ SCOSSL_CSHAKE_CTX *ctx,
                                            _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    if (ctx->xofState == SCOSSL_XOF_STATE_FINAL ||
        ctx->xofState == SCOSSL_XOF_STATE_SQUEEZE)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return SCOSSL_FAILURE;
    }

    // Delay init until first update call, in case function name or customization strings
    // are set by parameter after the init call.
    if (ctx->xofState == SCOSSL_XOF_STATE_INIT)
    {
        ctx->pHash->initFunc(
            &ctx->state,
            ctx->pbFunctionNameString, ctx->cbFunctionNameString,
            ctx->pbCustomizationString, ctx->cbCustomizationString);

        ctx->xofState = SCOSSL_XOF_STATE_UPDATE;
    }

    ctx->pHash->appendFunc(&ctx->state, in, inl);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cshake_extract(_In_ SCOSSL_CSHAKE_CTX *ctx, BOOL wipeState,
                                             _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    if (outlen < ctx->xofLen)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    if (ctx->xofState == SCOSSL_XOF_STATE_FINAL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return SCOSSL_FAILURE;
    }

    // Delay init until first update call, in case function name or customization strings
    // are set by parameter after the init call.
    if (ctx->xofState == SCOSSL_XOF_STATE_INIT)
    {
        ctx->pHash->initFunc(
            &ctx->state,
            ctx->pbFunctionNameString, ctx->cbFunctionNameString,
            ctx->pbCustomizationString, ctx->cbCustomizationString);
    }

    ctx->pHash->extractFunc(&ctx->state, out, ctx->xofLen, wipeState);
    *outl = ctx->xofLen;

    if (wipeState)
    {
        ctx->xofState = SCOSSL_XOF_STATE_FINAL;
    }
    else
    {
        ctx->xofState = SCOSSL_XOF_STATE_SQUEEZE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cshake_final(_In_ SCOSSL_CSHAKE_CTX *ctx,
                                           _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    return p_scossl_cshake_extract(ctx, TRUE, out, outl, outlen);
}

#ifdef OSSL_FUNC_DIGEST_SQUEEZE
static SCOSSL_STATUS p_scossl_cshake_squeeze(_In_ SCOSSL_CSHAKE_CTX *ctx,
                                           _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    return p_scossl_cshake_extract(ctx, FALSE, out, outl, outlen);
}
#endif

static SCOSSL_STATUS p_scossl_cshake_digest(_In_ const SCOSSL_CSHAKE_HASH *pHash,
                                            _In_reads_bytes_(inl) const unsigned char *in, size_t inl,
                                            _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    SIZE_T cbResult = pHash->resultSize;

    if (outlen < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    pHash->digestFunc(
        NULL, 0,
        NULL, 0,
        in, inl,
        out, cbResult);

    *outl = cbResult;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_cshake_128_digest(ossl_unused void *prov_ctx,
                                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl,
                                               _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    return p_scossl_cshake_digest(&SymCryptCShake128Algorithm, in, inl, out, outl, outlen);
}

static SCOSSL_STATUS p_scossl_cshake_256_digest(ossl_unused void *prov_ctx,
                                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl,
                                               _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    return p_scossl_cshake_digest(&SymCryptCShake256Algorithm, in, inl, out, outl, outlen);
}
static SCOSSL_STATUS p_scossl_cshake_128_get_params(_Inout_ OSSL_PARAM params[])
{
    return p_scossl_digest_get_params(params,
        SymCryptCShake128Algorithm.resultSize,
        SymCryptCShake128Algorithm.blockSize,
        SCOSSL_DIGEST_FLAG_XOF);
}

static SCOSSL_STATUS p_scossl_cshake_256_get_params(_Inout_ OSSL_PARAM params[])
{
    return p_scossl_digest_get_params(params,
        SymCryptCShake256Algorithm.resultSize,
        SymCryptCShake256Algorithm.blockSize,
        SCOSSL_DIGEST_FLAG_XOF);
}

static SCOSSL_STATUS p_scossl_cshake_set_ctx_params(_Inout_ SCOSSL_CSHAKE_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_DIGEST_PARAM_FUNCTION_NAME_STRING)) != NULL)
    {
        if (ctx->xofState != SCOSSL_XOF_STATE_INIT)
        {
            return SCOSSL_FAILURE;
        }

        OPENSSL_free(ctx->pbFunctionNameString);
        ctx->pbFunctionNameString = NULL;

        if (p->data != NULL &&
            !OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbFunctionNameString, 0, &ctx->cbFunctionNameString))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_DIGEST_PARAM_CUSTOMIZATION_STRING)) != NULL)
    {
        if (ctx->xofState != SCOSSL_XOF_STATE_INIT)
        {
            return SCOSSL_FAILURE;
        }

        OPENSSL_free(ctx->pbCustomizationString);
        ctx->pbCustomizationString = NULL;

        if (p->data != NULL &&
            !OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbCustomizationString, 0, &ctx->cbCustomizationString))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &ctx->xofLen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_cshake_settable_ctx_params(_In_ SCOSSL_CSHAKE_CTX *ctx, ossl_unused void *provctx)
{
    return ctx->xofState == SCOSSL_XOF_STATE_INIT ? p_scossl_cshake_settable_ctx_param_types : p_scossl_cshake_settable_ctx_param_types_initialized;
}

#ifdef OSSL_FUNC_DIGEST_SQUEEZE
#define SCOSSL_DIGEST_CSHAKE_SQUEEZE \
    {OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))p_scossl_cshake_squeeze},
#else
#define SCOSSL_DIGEST_CSHAKE_SQUEEZE
#endif

const OSSL_DISPATCH p_scossl_cshake_128_functions[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) p_scossl_cshake_128_newctx},
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) p_scossl_cshake_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) p_scossl_cshake_dupctx},
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void)) p_scossl_cshake_init},
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) p_scossl_cshake_update},
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) p_scossl_cshake_final},
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void)) p_scossl_cshake_128_digest},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) p_scossl_cshake_128_get_params},
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void)) p_scossl_digest_gettable_params},
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) p_scossl_cshake_set_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) p_scossl_cshake_settable_ctx_params},
#ifdef OSSL_FUNC_DIGEST_SQUEEZE
    {OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))p_scossl_cshake_squeeze},
#endif
    {0, NULL}};

const OSSL_DISPATCH p_scossl_cshake_256_functions[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) p_scossl_cshake_256_newctx},
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) p_scossl_cshake_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) p_scossl_cshake_dupctx},
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void)) p_scossl_cshake_init},
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) p_scossl_cshake_update},
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) p_scossl_cshake_final},
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void)) p_scossl_cshake_256_digest},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) p_scossl_cshake_256_get_params},
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void)) p_scossl_digest_gettable_params},
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) p_scossl_cshake_set_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) p_scossl_cshake_settable_ctx_params},
#ifdef OSSL_FUNC_DIGEST_SQUEEZE
    {OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))p_scossl_cshake_squeeze},
#endif
    {0, NULL}};

#ifdef __cplusplus
}
#endif