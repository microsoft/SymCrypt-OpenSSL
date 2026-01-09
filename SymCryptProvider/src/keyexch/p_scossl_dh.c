//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_dh.h"

#include <openssl/kdf.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

// Normally, if the output of this key exchange will be fed into
// a KDF, the caller should not set OSSL_EXCHANGE_PARAM_KDF_TYPE,
// create a KDF themselves, and pass the output of this operation
// into the KDF. Due to the way X9.42 was historically implemented,
// the SymCrypt provider needs to do this step for the caller if
// OSSL_EXCHANGE_PARAM_KDF_TYPE is set to OSSL_KDF_NAME_X942KDF_ASN1.
enum scossl_kdf_type {
    SCOSSL_KDF_TYPE_NONE = 0,
    SCOSSL_KDF_TYPE_X9_42};

typedef struct
{
    OSSL_LIB_CTX *libCtx;

    SCOSSL_PROV_DH_KEY_CTX *provKey;
    SCOSSL_PROV_DH_KEY_CTX *peerProvKey;

    UINT pad;

    // X9.42 parameters
    enum scossl_kdf_type kdfType;
    char *kdfMdName;
    char *kdfMdProps;
    char *kdfCekAlg;
    unsigned char *kdfUkm;
    SIZE_T kdfUkmlen;
    SIZE_T kdfOutlen;
} SCOSSL_DH_CTX;

static const OSSL_PARAM p_scossl_dh_ctx_settable_param_types[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_ctx_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(_Inout_ SCOSSL_DH_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_DH_CTX *p_scossl_dh_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_DH_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_DH_CTX));

    if (ctx != NULL)
    {
        ctx->libCtx = provctx->libctx;
    }

    return ctx;
}

static void p_scossl_dh_freectx(_In_ SCOSSL_DH_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->kdfMdName);
    OPENSSL_free(ctx->kdfMdProps);
    OPENSSL_free(ctx->kdfCekAlg);
    OPENSSL_free(ctx->kdfUkm);
    OPENSSL_free(ctx);
}

static SCOSSL_DH_CTX *p_scossl_dh_dupctx(_In_ SCOSSL_DH_CTX *ctx)
{
    SCOSSL_DH_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_CTX));
    if (copyCtx != NULL)
    {
        *copyCtx = *ctx;

        copyCtx->kdfMdName = OPENSSL_strdup(ctx->kdfMdName);
        copyCtx->kdfMdProps = OPENSSL_strdup(ctx->kdfMdProps);
        copyCtx->kdfCekAlg = OPENSSL_strdup(ctx->kdfCekAlg);
        copyCtx->kdfUkm = OPENSSL_memdup(ctx->kdfUkm, ctx->kdfUkmlen);

        if ((ctx->kdfMdName != NULL  && (copyCtx->kdfMdName == NULL)) ||
            (ctx->kdfMdProps != NULL && (copyCtx->kdfMdProps == NULL)) ||
            (ctx->kdfCekAlg != NULL  && (copyCtx->kdfCekAlg == NULL)) ||
            (ctx->kdfUkm != NULL     && (copyCtx->kdfUkm == NULL)))
        {
            p_scossl_dh_freectx(copyCtx);
            copyCtx = NULL;
        }
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_dh_init(_In_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_PROV_DH_KEY_CTX *provKey,
                                      _In_ const OSSL_PARAM params[])
{
    if (ctx == NULL || provKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (provKey->keyCtx == NULL ||!provKey->keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->provKey = provKey;

    return p_scossl_dh_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_dh_set_peer(_Inout_ SCOSSL_DH_CTX *ctx, _In_ SCOSSL_PROV_DH_KEY_CTX *peerProvKey)
{
    if (ctx == NULL || peerProvKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (peerProvKey->keyCtx == NULL || !peerProvKey->keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    if (!SymCryptDlgroupIsSame(
            SymCryptDlkeyGetGroup(ctx->provKey->keyCtx->dlkey),
            SymCryptDlkeyGetGroup(peerProvKey->keyCtx->dlkey)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return SCOSSL_FAILURE;
    }

    ctx->peerProvKey = peerProvKey;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_dh_X9_42_derive(_In_ SCOSSL_DH_CTX *ctx,
                                              _Out_writes_bytes_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                              size_t outlen)
{
    PBYTE pbAgreedSecret = NULL;
    SIZE_T cbAgreedSecret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdfCtx = NULL;
    OSSL_PARAM params[6], *pCur = params;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Perform derivation, and pass result to X9_42 implementation
    if (secret != NULL)
    {
        if (outlen < ctx->kdfOutlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        cbAgreedSecret = SymCryptDlkeySizeofPublicKey(ctx->provKey->keyCtx->dlkey);

        if ((pbAgreedSecret = OPENSSL_secure_malloc(cbAgreedSecret)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        scError = SymCryptDhSecretAgreement(
            ctx->provKey->keyCtx->dlkey,
            ctx->peerProvKey->keyCtx->dlkey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbAgreedSecret,
            cbAgreedSecret);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDhSecretAgreement failed", scError);
            goto cleanup;
        }

        if ((kdf = EVP_KDF_fetch(ctx->libCtx, OSSL_KDF_NAME_X942KDF_ASN1, NULL)) == NULL ||
            (kdfCtx = EVP_KDF_CTX_new(kdf)) == NULL)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to create X9.42 KDF context");
            goto cleanup;
        }

        *pCur++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, ctx->kdfMdName, 0);
        *pCur++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, ctx->kdfMdProps, 0);
        *pCur++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, ctx->kdfCekAlg, 0);
        *pCur++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, pbAgreedSecret, cbAgreedSecret);

        if (ctx->kdfUkm != NULL)
        {
            *pCur++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_UKM, ctx->kdfUkm, ctx->kdfUkmlen);
        }

        *pCur = OSSL_PARAM_construct_end();

        if (!EVP_KDF_derive(kdfCtx, secret, ctx->kdfOutlen, params))
        {
            goto cleanup;
        }
    }

    *secretlen = ctx->kdfOutlen;
    ret = SCOSSL_SUCCESS;
cleanup:
    if (pbAgreedSecret != NULL)
    {
        OPENSSL_clear_free(pbAgreedSecret, cbAgreedSecret);
    }

    EVP_KDF_CTX_free(kdfCtx);
    EVP_KDF_free(kdf);

    return ret;
}

static SCOSSL_STATUS p_scossl_dh_plain_derive(_In_ SCOSSL_DH_CTX *ctx,
                                              _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                              size_t outlen)
{
    SIZE_T cbAgreedSecret;
    SIZE_T npad = 0;
    SIZE_T mask = 1;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    cbAgreedSecret = SymCryptDlkeySizeofPublicKey(ctx->provKey->keyCtx->dlkey);

    if (secret != NULL)
    {
        if (outlen < cbAgreedSecret)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptDhSecretAgreement(
            ctx->provKey->keyCtx->dlkey,
            ctx->peerProvKey->keyCtx->dlkey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            secret,
            cbAgreedSecret);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDhSecretAgreement failed", scError);
            return SCOSSL_FAILURE;
        }

        // Padding removal code from DH_compute_key to ensure
        // consistency between implementations. This is
        // inherently not constant time due to the RFC 5246 (8.1.2)
        // padding style that strips leading zero bytes.
        if (!ctx->pad)
        {
            for (SIZE_T i = 0; i < cbAgreedSecret; i++)
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

static SCOSSL_STATUS p_scossl_dh_derive(_In_ SCOSSL_DH_CTX *ctx,
                                        _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                        size_t outlen)
{
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

    if (ctx->kdfType == SCOSSL_KDF_TYPE_X9_42)
    {
        return p_scossl_dh_X9_42_derive(ctx, secret, secretlen, outlen);
    }

    return p_scossl_dh_plain_derive(ctx, secret, secretlen, outlen);
}

static SCOSSL_STATUS p_scossl_dh_set_ctx_params(_Inout_ SCOSSL_DH_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const char *mdName = NULL;
    const char *mdProps = NULL;
    EVP_MD *md = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD)) != NULL)
    {
        unsigned int pad;
        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        ctx->pad = pad ? 1 : 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE)) != NULL)
    {
        const char *kdfType;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &kdfType) ||
            kdfType == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (kdfType[0] =='\0')
        {
            ctx->kdfType = SCOSSL_KDF_TYPE_NONE;
        }
        else if (strcmp(kdfType, OSSL_KDF_NAME_X942KDF_ASN1) == 0)
        {
            ctx->kdfType = SCOSSL_KDF_TYPE_X9_42;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST)) != NULL)
    {
        if (!OSSL_PARAM_get_utf8_string(p, &mdName, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS)) != NULL)
        {
            if (!OSSL_PARAM_get_utf8_string(p, &mdProps, 0))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        OPENSSL_free(ctx->kdfMdName);
        OPENSSL_free(ctx->kdfMdProps);
        ctx->kdfMdName = NULL;
        ctx->kdfMdProps = NULL;

        if ((md = EVP_MD_fetch(ctx->libCtx, mdName, mdProps)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }

        if (EVP_MD_xof(md))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED);
            goto cleanup;
        }

        ctx->kdfMdName = mdName;
        ctx->kdfMdProps = mdProps;
        mdName = NULL;
        mdProps = NULL;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG)) != NULL)
    {
        OPENSSL_free(ctx->kdfCekAlg);
        ctx->kdfCekAlg = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &ctx->kdfCekAlg, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM)) != NULL)
    {
        OPENSSL_free(ctx->kdfUkm);
        ctx->kdfUkm = NULL;
        ctx->kdfUkmlen = 0;

        if (p->data != 0 &&
            p->data_size != 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)(&ctx->kdfUkm), 0, &ctx->kdfUkmlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &ctx->kdfOutlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(mdName);
    OPENSSL_free(mdProps);
    EVP_MD_free(md);

    return ret;
}

static const OSSL_PARAM *p_scossl_dh_ctx_settable_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_dh_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_dh_get_ctx_params(_In_ SCOSSL_DH_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_PAD)) != NULL &&
        !OSSL_PARAM_set_uint(p, ctx->pad))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE)) != NULL)
    {
        const char *kdfType = "";
        if (ctx->kdfType == SCOSSL_KDF_TYPE_X9_42)
        {
            kdfType = OSSL_KDF_NAME_X942KDF_ASN1;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdfType))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->kdfMdName == NULL ? "" : ctx->kdfMdName))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CEK_ALG)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->kdfCekAlg == NULL ? "" : ctx->kdfCekAlg))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM)) != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, ctx->kdfUkm, ctx->kdfUkmlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->kdfOutlen))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_dh_ctx_gettable_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_dh_ctx_gettable_param_types;
}

const OSSL_DISPATCH p_scossl_dh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_dh_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_dh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_dh_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_dh_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_dh_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_dh_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_dh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_settable_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_dh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_dh_ctx_gettable_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif