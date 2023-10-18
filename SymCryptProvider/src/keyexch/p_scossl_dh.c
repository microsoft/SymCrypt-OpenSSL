//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"
#include "p_scossl_dh.h"

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_PROV_DH_KEY_CTX *provKey;
    SCOSSL_PROV_DH_KEY_CTX *peerProvKey;

    unsigned int pad;
} SCOSSL_DH_CTX;

static const OSSL_PARAM p_scossl_dh_ctx_param_types[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(_Inout_ SCOSSL_DH_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_DH_CTX *p_scossl_dh_newctx(ossl_unused void *provctx)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_DH_CTX));
}

static void p_scossl_dh_freectx(_In_ SCOSSL_DH_CTX *ctx)
{
    OPENSSL_free(ctx);
}

static SCOSSL_DH_CTX *p_scossl_dh_dupctx(_In_ SCOSSL_DH_CTX *ctx)
{
    SCOSSL_DH_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_CTX));
    if (copyCtx != NULL)
    {
        copyCtx->provKey = ctx->provKey;
        copyCtx->peerProvKey = ctx->peerProvKey;
        copyCtx->pad = ctx->pad;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_dh_init(_In_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_PROV_DH_KEY_CTX *provKey,
                                      ossl_unused const OSSL_PARAM params[])
{
    if (ctx == NULL ||
        provKey == NULL)
    {
        return SCOSSL_FAILURE;
    }

    ctx->provKey = provKey;

    return p_scossl_dh_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_dh_set_peer(_Inout_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_PROV_DH_KEY_CTX *peerProvKey)
{
    if (!SymCryptDlgroupIsSame(ctx->provKey->keyCtx->dlkey->pDlgroup, peerProvKey->keyCtx->dlkey->pDlgroup))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return SCOSSL_FAILURE;
    }

    ctx->peerProvKey = peerProvKey;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_dh_derive(_In_ SCOSSL_DH_CTX *ctx,
                                        _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                        size_t outlen)
{
    int cbAgreedSecret;
    size_t npad = 0;
    size_t mask = 1;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx == NULL || secretlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->provKey == NULL || ctx->peerProvKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    cbAgreedSecret = SymCryptDlkeySizeofPublicKey(ctx->provKey->keyCtx->dlkey);

    if (secret != NULL)
    {
        scError = SymCryptDhSecretAgreement(
            ctx->provKey->keyCtx->dlkey,
            ctx->peerProvKey->keyCtx->dlkey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            secret,
            outlen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }

        // Padding removal code from DH_compute_key to ensure
        // consistency between implementations. This is
        // inherently not constant time due to the RFC 5246 (8.1.2)
        // padding style that strips leading zero bytes.
        if (!ctx->pad)
        {
            for (int i = 0; i < cbAgreedSecret; i++)
            {
                mask &= !secret[i];
                npad += mask;
            }

            /* unpad key */
            cbAgreedSecret -= npad;
            /* key-dependent memory access, potentially leaking npad / ret */
            memmove(secret, secret + npad, cbAgreedSecret);
            /* key-dependent memory access, potentially leaking npad / ret */
            memset(secret + cbAgreedSecret, 0, npad);
        }
    }

    *secretlen = cbAgreedSecret;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(_Inout_ SCOSSL_DH_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE)) != NULL)
    {
        const char *kdfType;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &kdfType))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // We don't support other types such as x9.42 for now
        if (kdfType == NULL ||
            kdfType[0] !=-'\0')
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD)) != NULL)
    {
        unsigned int pad;
        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        ctx->pad = pad ? 1 : 0;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_dh_get_ctx_params(_In_ SCOSSL_DH_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ""))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_PAD)) != NULL &&
        !OSSL_PARAM_set_uint(p, ctx->pad))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_dh_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_dh_ctx_param_types;
}

const OSSL_DISPATCH p_scossl_dh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_dh_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_dh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_dh_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_dh_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_dh_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_dh_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_dh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_dh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif