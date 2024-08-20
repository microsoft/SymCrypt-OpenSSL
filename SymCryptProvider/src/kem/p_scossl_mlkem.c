//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kem/p_scossl_mlkem.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYMCRYPT_MLKEM_SECRET_LENGTH 32

typedef struct
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
    int operation;
} SCOSSL_MLKEM_CTX;

static const OSSL_PARAM p_scossl_mlkem_param_types[] = {
    OSSL_PARAM_END};

/* Context management */
static SCOSSL_MLKEM_CTX *p_scossl_mlkem_newctx(ossl_unused void *provctx)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_CTX));
}

static void p_scossl_mlkem_freectx(_Inout_ SCOSSL_MLKEM_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

static SCOSSL_MLKEM_CTX *p_scossl_mlkem_dupctx(_In_ SCOSSL_MLKEM_CTX *ctx)
{
    SCOSSL_MLKEM_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->operation = ctx->operation;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                         int operation)
{
    if (ctx == NULL || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (keyCtx == NULL || keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return SCOSSL_SUCCESS;
}

//
// Encapsulation
//
static SCOSSL_STATUS p_scossl_mlkem_encapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_ENCAPSULATE);
}

static SCOSSL_STATUS p_scossl_mlkem_encapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _Out_writes_bytes_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen)
{
    SIZE_T cbCipherText;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation != EVP_PKEY_OP_ENCAPSULATE)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return SCOSSL_FAILURE;
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->params, &cbCipherText);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    if (out != NULL)
    {
        scError = SymCryptMlKemEncapsulate(ctx->keyCtx->key, secret, SYMCRYPT_MLKEM_SECRET_LENGTH, out, cbCipherText);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }
    else if (outlen == NULL && secretlen != NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    if (outlen != NULL)
    {
        *outlen = cbCipherText;
    }

    if (secretlen != NULL)
    {
        *secretlen = SYMCRYPT_MLKEM_SECRET_LENGTH;
    }

    return SCOSSL_SUCCESS;
}

//
// Decapsulation
//
static SCOSSL_STATUS p_scossl_mlkem_decapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_DECAPSULATE);
}

static SCOSSL_STATUS p_scossl_mlkem_decapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{
    SIZE_T cbCipherText;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation != EVP_PKEY_OP_DECAPSULATE)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return SCOSSL_FAILURE;
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->params, &cbCipherText);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    if (inlen != cbCipherText)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return SCOSSL_FAILURE;
    }

    if (out != NULL)
    {
        scError = SymCryptMlKemDecapsulate(ctx->keyCtx->key, in, inlen, out, SYMCRYPT_MLKEM_SECRET_LENGTH);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }
    else if (outlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    if (outlen != NULL)
    {
        *outlen = SYMCRYPT_MLKEM_SECRET_LENGTH;
    }

    return SCOSSL_SUCCESS;
}

//
// Parameters
//
static const OSSL_PARAM *p_scossl_mlkem_ctx_param_types(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_mlkem_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mlkem_get_ctx_params(ossl_unused void *ctx, ossl_unused OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static const OSSL_DISPATCH p_scossl_mlkem_functions[] = {
    {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p_scossl_mlkem_newctx},
    {OSSL_FUNC_KEM_FREECTX, (void (*)(void))p_scossl_mlkem_freectx},
    {OSSL_FUNC_KEM_DUPCTX, (void (*)(void))p_scossl_mlkem_dupctx},
    {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_encapsulate_init},
    {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p_scossl_mlkem_encapsulate},
    {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_decapsulate_init},
    {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p_scossl_mlkem_decapsulate},
    {OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_set_ctx_params},
    {OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_ctx_param_types},
    {OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_get_ctx_params},
    {OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_ctx_param_types},
    {0, NULL}};

#ifdef __cplusplus
}
#endif