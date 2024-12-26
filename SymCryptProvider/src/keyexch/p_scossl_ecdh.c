//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_ecc.h"
#include "p_scossl_base.h"
#include "keyexch/p_scossl_ecdh.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_ecdh_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_ecdh_set_ctx_params(_Inout_ SCOSSL_ECDH_CTX *ctx, _In_ const OSSL_PARAM params[]);

_Use_decl_annotations_
SCOSSL_ECDH_CTX *p_scossl_ecdh_newctx(SCOSSL_PROVCTX *provctx)
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

_Use_decl_annotations_
void p_scossl_ecdh_freectx(SCOSSL_ECDH_CTX *ctx)
{
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_ECDH_CTX *p_scossl_ecdh_dupctx(SCOSSL_ECDH_CTX *ctx)
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

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecdh_init(SCOSSL_ECDH_CTX *ctx, SCOSSL_ECC_KEY_CTX *keyCtx,
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

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecdh_set_peer(SCOSSL_ECDH_CTX *ctx, SCOSSL_ECC_KEY_CTX *peerKeyCtx)
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

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecdh_derive(SCOSSL_ECDH_CTX *ctx,
                                   unsigned char *secret, size_t *secretlen,
                                   size_t outlen)
{
    PBYTE pbSecret = secret;
    PBYTE pbSecretBuf = NULL;
    SIZE_T cbSecretBuf = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_NUMBER_FORMAT numberFormat;

    if (ctx == NULL || secretlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    cbSecretBuf = SymCryptEckeySizeofPublicKey(ctx->keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    if (secret == NULL)
    {
        *secretlen = cbSecretBuf;
        return SCOSSL_SUCCESS;
    }

    if (ctx->keyCtx == NULL || ctx->peerKeyCtx == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    numberFormat = ctx->keyCtx->isX25519 ? SYMCRYPT_NUMBER_FORMAT_LSB_FIRST : SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;

    if (outlen < cbSecretBuf)
    {
       if ((pbSecretBuf = OPENSSL_secure_malloc(cbSecretBuf)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbSecret = pbSecretBuf;
    }

    scError = SymCryptEcDhSecretAgreement(
        ctx->keyCtx->key,
        ctx->peerKeyCtx->key,
        numberFormat,
        0,
        pbSecret,
        cbSecretBuf);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEcDhSecretAgreement failed", scError);
        goto cleanup;
    }

    if (outlen < cbSecretBuf)
    {
        memcpy(secret, pbSecretBuf, outlen);
        *secretlen = outlen;
    }
    else
    {
        *secretlen = cbSecretBuf;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbSecretBuf, cbSecretBuf);

    return ret;
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