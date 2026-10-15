//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mldsa.h"
#include "keymgmt/p_scossl_mldsa_keymgmt.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLDSA_MSG_ENCODING_PURE 1

static SCOSSL_MLDSA_ALG_INFO p_scossl_mldsa_algs[] = {
    {NID_undef, SCOSSL_OID_MLDSA44, SCOSSL_SN_MLDSA44, SCOSSL_LN_MLDSA44, SYMCRYPT_MLDSA_PARAMS_MLDSA44, FALSE},
    {NID_undef, SCOSSL_OID_MLDSA65, SCOSSL_SN_MLDSA65, SCOSSL_LN_MLDSA65, SYMCRYPT_MLDSA_PARAMS_MLDSA65, FALSE},
    {NID_undef, SCOSSL_OID_MLDSA87, SCOSSL_SN_MLDSA87, SCOSSL_LN_MLDSA87, SYMCRYPT_MLDSA_PARAMS_MLDSA87, FALSE},
    {NID_undef, SCOSSL_OID_MLDSA44_ECDSA_P256_SHA256, SCOSSL_SN_MLDSA44_ECDSA_P256_SHA256, SCOSSL_LN_MLDSA44_ECDSA_P256_SHA256, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256, TRUE},
    {NID_undef, SCOSSL_OID_MLDSA65_ECDSA_P256_SHA512, SCOSSL_SN_MLDSA65_ECDSA_P256_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P256_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512, TRUE},
    {NID_undef, SCOSSL_OID_MLDSA65_ECDSA_P384_SHA512, SCOSSL_SN_MLDSA65_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P384_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512, TRUE},
    {NID_undef, SCOSSL_OID_MLDSA87_ECDSA_P384_SHA512, SCOSSL_SN_MLDSA87_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA87_ECDSA_P384_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512, TRUE}};

typedef struct
{
    BOOL isComposite;

    SCOSSL_MLDSA_PARAMS mldsaParams;
    SCOSSL_MLDSA_KEY_CTX *keyCtx;
    int operation;

    BYTE abContext[SCOSSL_MLDSA_CONTEXT_MAX_LENGTH];
    SIZE_T cbContext;
} SCOSSL_MLDSA_SIGNATURE_CTX;

static const OSSL_PARAM p_scossl_mldsa_ctx_gettable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_composite_mldsa_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const OSSL_PARAM params[]);
static SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_params_to_alg_info(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite);
static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite,
                                               _Out_writes_bytes_(*pcbAlgId) PBYTE *ppbAlgId, _Out_ SIZE_T *pcbAlgId);

static SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_newctx(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite)
{
    SCOSSL_MLDSA_SIGNATURE_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_SIGNATURE_CTX));
    if (ctx != NULL)
    {
        ctx->isComposite = isComposite;
        ctx->mldsaParams = mldsaParams;
    }

    return ctx;
}

static void p_scossl_mldsa_freectx(SCOSSL_MLDSA_SIGNATURE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

static SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_dupctx(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx)
{
    SCOSSL_MLDSA_SIGNATURE_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLDSA_SIGNATURE_CTX));
    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    copyCtx->isComposite = ctx->isComposite;
    copyCtx->mldsaParams = ctx->mldsaParams;
    copyCtx->keyCtx = ctx->keyCtx;
    copyCtx->operation = ctx->operation;
    copyCtx->cbContext = ctx->cbContext;
    memcpy(copyCtx->abContext, ctx->abContext, ctx->cbContext);

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_signverify_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                    _In_ const OSSL_PARAM params[], int operation)
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->keyCtx == NULL &&
        (keyCtx == NULL || keyCtx->key == NULL))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (keyCtx != NULL)
    {
        if (operation == EVP_PKEY_OP_SIGN &&
            !p_scossl_mldsa_keymgmt_has(keyCtx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->isComposite != ctx->isComposite ||
            keyCtx->mldsaParams != ctx->mldsaParams)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return SCOSSL_FAILURE;
        }
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return p_scossl_mldsa_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_mldsa_sign_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                              _In_ const OSSL_PARAM params[])
{
    return p_scossl_mldsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGN);
}

static SCOSSL_STATUS p_scossl_mldsa_sign(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                         _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                         _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    SIZE_T cbSignature;
    SIZE_T cbResult;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation != EVP_PKEY_OP_SIGN)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return SCOSSL_FAILURE;
    }

    if (ctx->isComposite)
    {
        scError = SymCryptCompositeMlDsaSizeofSignatureFromParams(ctx->mldsaParams, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptCompositeMlDsaSizeofSignatureFromParams failed", scError);
            return SCOSSL_FAILURE;
        }
    }
    else
    {
        scError = SymCryptMlDsaSizeofSignatureFromParams(ctx->mldsaParams, &cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofSignatureFromParams failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    if (sig != NULL)
    {
        if (sigsize < cbSignature)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        if (ctx->isComposite)
        {
            scError = SymCryptCompositeMlDsaSign(
                ctx->keyCtx->key,
                tbs, tbslen,
                ctx->abContext, ctx->cbContext,
                0,
                sig, cbSignature, &cbResult);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptCompositeMlDsaSign failed", scError);
                return SCOSSL_FAILURE;
            }

            cbSignature = cbResult;
        }
        else
        {
            scError = SymCryptMlDsaSign(
                ctx->keyCtx->key,
                tbs, tbslen,
                ctx->abContext, ctx->cbContext,
                0,
                sig, cbSignature);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSign failed", scError);
                return SCOSSL_FAILURE;
            }
        }
    }

    if (siglen != NULL)
    {
        *siglen = cbSignature;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mldsa_verify_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                _In_ const OSSL_PARAM params[])
{
    return p_scossl_mldsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

static SCOSSL_STATUS p_scossl_mldsa_verify(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                           _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                           _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation != EVP_PKEY_OP_VERIFY)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return SCOSSL_FAILURE;
    }

    if (ctx->isComposite)
    {
        scError = SymCryptCompositeMlDsaVerify(
            ctx->keyCtx->key,
            tbs, tbslen,
            ctx->abContext, ctx->cbContext,
            sig, siglen,
            0);
    }
    else
    {
        scError = SymCryptMlDsaVerify(
            ctx->keyCtx->key,
            tbs, tbslen,
            ctx->abContext, ctx->cbContext,
            sig, siglen,
            0);
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaVerify returned unexpected error", scError);
        }

        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mldsa_digest_signverify_init(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const char *mdname,
                                                           _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[],
                                                           int operation)
{
    if (mdname != NULL && mdname[0] != '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return SCOSSL_FAILURE;
    }

    if (keyCtx == NULL &&
        ctx != NULL &&
        ctx->keyCtx != NULL)
    {
        ctx->operation = operation;
        return p_scossl_mldsa_set_ctx_params(ctx, params);
    }

    return p_scossl_mldsa_signverify_init(ctx, keyCtx, params, operation);
}

static SCOSSL_STATUS p_scossl_mldsa_digest_sign_init(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const char *mdname,
                                                     _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_mldsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_SIGN);
}

static SCOSSL_STATUS p_scossl_mldsa_digest_verify_init(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const char *mdname,
                                                       _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_mldsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

static SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)) != NULL)
    {
        PVOID pbContext = ctx->abContext;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbContext, SCOSSL_MLDSA_CONTEXT_MAX_LENGTH, &ctx->cbContext))
        {
            ctx->cbContext = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    // Unsupported parameters, check value matches default
    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC)) != NULL)
    {
        int deterministic;
        if (!OSSL_PARAM_get_int(p, &deterministic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (deterministic != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU)) != NULL)
    {
        int mu;
        if (!OSSL_PARAM_get_int(p, &mu))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (mu != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if (!ctx->isComposite)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING)) != NULL)
        {
            int messageEncoding;
            if (!OSSL_PARAM_get_int(p, &messageEncoding))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            if (messageEncoding != SCOSSL_MLDSA_MSG_ENCODING_PURE)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                return SCOSSL_FAILURE;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY)) != NULL &&
            p->data_size != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mldsa_gettable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    return p_scossl_mldsa_ctx_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_get_ctx_params(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (params == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)) != NULL)
    {
        PBYTE pbAid = NULL;
        SIZE_T cbAid;

        if (p_scossl_mldsa_get_alg_id(ctx->mldsaParams, ctx->isComposite, &pbAid, &cbAid) != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_octet_string(p, pbAid, cbAid))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            OPENSSL_free(pbAid);
            return SCOSSL_FAILURE;
        }

        OPENSSL_free(pbAid);
    }

    return SCOSSL_SUCCESS;
}

#define SCOSSL_MLDSA_SIGNATURE_FNS(alg, isComposite, symcryptParams, paramPrefix)                        \
    static SCOSSL_MLDSA_SIGNATURE_CTX                                                                    \
    *p_scossl_##alg##_newctx(ossl_unused SCOSSL_PROVCTX *provctx, ossl_unused const char *propq)         \
    {                                                                                                    \
        return p_scossl_mldsa_newctx(symcryptParams, isComposite);                                       \
    }                                                                                                    \
                                                                                                         \
    static const OSSL_PARAM                                                                              \
    *p_scossl_##alg##_settable_ctx_params(ossl_unused SCOSSL_MLDSA_SIGNATURE_CTX *ctx,                   \
                                          ossl_unused void *provctx)                                     \
    {                                                                                                    \
        return paramPrefix##_ctx_settable_param_types;                                                   \
    }                                                                                                    \
                                                                                                         \
    const OSSL_DISPATCH p_scossl_##alg##_signature_functions[] = {                                       \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_##alg##_newctx},                           \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_mldsa_dupctx},                             \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_mldsa_freectx},                           \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_mldsa_sign_init},                       \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_mldsa_sign},                                 \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_verify_init},                   \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                             \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_mldsa_digest_sign_init},         \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))p_scossl_mldsa_sign},                          \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_digest_verify_init},     \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                      \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_get_ctx_params},             \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_gettable_ctx_params},   \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_set_ctx_params},             \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_settable_ctx_params}, \

#define SCOSSL_MLDSA_SIGN_MESSAGE_FNS                                                       \
    {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_sign_init},      \
    {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_verify_init},

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
    #define IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(alg, isComposite, symcryptParams, paramPrefix) \
        SCOSSL_MLDSA_SIGNATURE_FNS(alg, isComposite, symcryptParams, paramPrefix)           \
        SCOSSL_MLDSA_SIGN_MESSAGE_FNS                                                       \
        {0, NULL}};
#else
    #define IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(alg, isComposite, symcryptParams, paramPrefix) \
        SCOSSL_MLDSA_SIGNATURE_FNS(alg, isComposite, symcryptParams, paramPrefix)           \
        {0, NULL}};
#endif

IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa44, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA44, p_scossl_mldsa)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa65, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA65, p_scossl_mldsa)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa87, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA87, p_scossl_mldsa)

IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa44_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa65_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa65_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512, p_scossl_composite_mldsa)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa87_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512, p_scossl_composite_mldsa)

//
// Helper functions
//

_Use_decl_annotations_
static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite,
                                               PBYTE *ppbAlgId, SIZE_T *pcbAlgId)
{
    SCOSSL_MLDSA_ALG_INFO *algInfo;
    ASN1_OBJECT *aobj = NULL;
    X509_ALGOR *x509Alg = NULL;
    PBYTE pbAlgId = NULL;
    int cbAid;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ppbAlgId == NULL || pcbAlgId == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    *ppbAlgId = NULL;

    if ((algInfo = p_scossl_mldsa_params_to_alg_info(mldsaParams, isComposite)) == NULL)
    {
        return SCOSSL_FAILURE;
    }

    if ((x509Alg = X509_ALGOR_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    aobj = OBJ_txt2obj(algInfo->oid, 1);
    if (aobj == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "OBJ_txt2obj failed");
        goto cleanup;
    }

    if (!X509_ALGOR_set0(x509Alg, aobj, V_ASN1_UNDEF, NULL))
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "X509_ALGOR_set0 failed");
        goto cleanup;
    }
    aobj = NULL; // X509_ALGOR_set0 takes ownership on success

    if ((cbAid = i2d_X509_ALGOR(x509Alg, &pbAlgId)) < 0)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "i2d_X509_ALGOR failed");
        goto cleanup;
    }

    *ppbAlgId = pbAlgId;
    pbAlgId = NULL;
    *pcbAlgId = (SIZE_T)cbAid;

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbAlgId);
    X509_ALGOR_free(x509Alg);
    ASN1_OBJECT_free(aobj);

    return ret;
}

static SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_params_to_alg_info(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO); i++)
    {
        if (p_scossl_mldsa_algs[i].mldsaParams == mldsaParams &&
            p_scossl_mldsa_algs[i].isComposite == isComposite)
        {
            return &p_scossl_mldsa_algs[i];
        }
    }

    return NULL;
}

_Use_decl_annotations_
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(int nid)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO); i++)
    {
        if (p_scossl_mldsa_algs[i].nid == nid)
        {
            return &p_scossl_mldsa_algs[i];
        }
    }

    return NULL;
}

int p_scossl_mldsa_params_to_nid(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite)
{
    SCOSSL_MLDSA_ALG_INFO *algInfo = p_scossl_mldsa_params_to_alg_info(mldsaParams, isComposite);

    return algInfo == NULL ? NID_undef : algInfo->nid;
}

SCOSSL_STATUS p_scossl_mldsa_register_algorithms()
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO); i++)
    {
        // Don't double register MLDSA algorithms. Standalone ML-DSA should already
        // be registered on OpenSSL 3.5+
        p_scossl_mldsa_algs[i].nid = OBJ_sn2nid(p_scossl_mldsa_algs[i].snGroupName);
        if (p_scossl_mldsa_algs[i].nid == NID_undef)
        {
            p_scossl_mldsa_algs[i].nid = OBJ_create(p_scossl_mldsa_algs[i].oid, p_scossl_mldsa_algs[i].snGroupName, p_scossl_mldsa_algs[i].lnGroupName);
            if (p_scossl_mldsa_algs[i].nid == NID_undef)
            {
                return SCOSSL_FAILURE;
            }
        }
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif