//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;
    SCOSSL_ECC_KEY_CTX *keyCtx;
    SCOSSL_ECC_KEY_CTX *peerKeyCtx;
} SCOSSL_ECDH_CTX;

static const OSSL_PARAM p_scossl_ecdh_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_ecdh_set_ctx_params(_Inout_ SCOSSL_ECDH_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_ECDH_CTX *p_scossl_ecdh_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_ECDH_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_ECDH_CTX));
    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
        ctx->keyCtx = NULL;
        ctx->peerKeyCtx = NULL;
    }

    return ctx;
}

static void p_scossl_ecdh_freectx(_In_ SCOSSL_ECDH_CTX *ctx)
{
    OPENSSL_free(ctx);
}

static SCOSSL_ECDH_CTX *p_scossl_ecdh_dupctx(_In_ SCOSSL_ECDH_CTX *ctx)
{
    SCOSSL_ECDH_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_ECDH_CTX));
    if (copyCtx != NULL)
    {
        copyCtx->libctx = ctx->libctx;
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->peerKeyCtx = ctx->peerKeyCtx;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_ecdh_init(_In_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                        ossl_unused const OSSL_PARAM params[])
{
    if (ctx == NULL || keyCtx == NULL)
    {
        return SCOSSL_FAILURE;
    }
    ctx->keyCtx = keyCtx;

    // No parameters are currently accepted for this interface.
    // Return the result of p_scossl_ecdh_set_ctx_params if this changes.
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_ecdh_set_peer(_Inout_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *peerKeyCtx)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx == NULL || peerKeyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto cleanup;
    }

    if (!SymCryptEcurveIsSame(ctx->keyCtx->curve, peerKeyCtx->curve))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        goto cleanup;
    }

    ctx->peerKeyCtx = peerKeyCtx;
    ret = SCOSSL_SUCCESS;

cleanup:

    return ret;
}

static SCOSSL_STATUS p_scossl_ecdh_derive(_In_ SCOSSL_ECDH_CTX *ctx,
                                          _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                          size_t outlen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx == NULL || secretlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->keyCtx == NULL || ctx->peerKeyCtx == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    *secretlen = SymCryptEckeySizeofPublicKey(ctx->keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    if (secret == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    scError = SymCryptEcDhSecretAgreement(
        ctx->keyCtx->key,
        ctx->peerKeyCtx->key,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        secret,
        outlen);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// This implementation currently does not accept any parameters
static SCOSSL_STATUS p_scossl_ecdh_set_ctx_params(ossl_unused SCOSSL_ECDH_CTX *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_ecdh_get_ctx_params(ossl_unused SCOSSL_ECDH_CTX *ctx, ossl_unused OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_ecdh_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_ecdh_ctx_param_types;
}

const OSSL_DISPATCH p_scossl_ecdh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_ecdh_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_ecdh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_ecdh_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_ecdh_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_ecdh_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_ecdh_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif