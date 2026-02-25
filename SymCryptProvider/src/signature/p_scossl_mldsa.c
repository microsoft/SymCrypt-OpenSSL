//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mldsa.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLDSA_MSG_ENCODING_PURE 1

static SCOSSL_MLDSA_ALG_INFO p_scossl_mldsa_algs[] = {
    {NID_undef, SCOSSL_OID_MLDSA44, SCOSSL_SN_MLDSA44, SCOSSL_LN_MLDSA44, SYMCRYPT_MLDSA_PARAMS_MLDSA44},
    {NID_undef, SCOSSL_OID_MLDSA65, SCOSSL_SN_MLDSA65, SCOSSL_LN_MLDSA65, SYMCRYPT_MLDSA_PARAMS_MLDSA65},
    {NID_undef, SCOSSL_OID_MLDSA87, SCOSSL_SN_MLDSA87, SCOSSL_LN_MLDSA87, SYMCRYPT_MLDSA_PARAMS_MLDSA87}};

typedef struct
{
    SYMCRYPT_MLDSA_PARAMS mldsaParams;
    SCOSSL_MLDSA_KEY_CTX *keyCtx;
    int operation;

    BYTE pbContext[SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH];
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

static SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(SYMCRYPT_MLDSA_PARAMS mldsaParams,
                                               _Out_writes_bytes_(cbAlgId) PBYTE *ppbAlgId, _Out_ SIZE_T *pcbAlgId);

static SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_newctx(_In_ SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    SCOSSL_MLDSA_SIGNATURE_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_SIGNATURE_CTX));
    if (ctx != NULL)
    {
        ctx->mldsaParams = mldsaParams;
    }

    return ctx;
}

static void p_scossl_mldsa_freectx(SCOSSL_MLDSA_SIGNATURE_CTX *ctx)
{
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

    copyCtx->mldsaParams = ctx->mldsaParams;
    copyCtx->keyCtx = ctx->keyCtx;
    copyCtx->operation = ctx->operation;
    copyCtx->cbContext = ctx->cbContext;
    memcpy(copyCtx->pbContext, ctx->pbContext, ctx->cbContext);

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mldsa_signverify_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                    _In_ const OSSL_PARAM params[], int operation)
{
    if (keyCtx == NULL || keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (operation == EVP_PKEY_OP_SIGN &&
        keyCtx->format == SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return SCOSSL_FAILURE;
    }

    if (keyCtx->mldsaParams != ctx->mldsaParams)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        return SCOSSL_FAILURE;
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

    scError = SymCryptMlDsaSizeofSignatureFromParams(ctx->mldsaParams, &cbSignature);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSizeofSignatureFromParams failed", scError);
        return SCOSSL_FAILURE;
    }

    if (sig != NULL)
    {
        if (sigsize < cbSignature)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptMlDsaSign(
            ctx->keyCtx->key,
            tbs, tbslen,
            ctx->pbContext, ctx->cbContext,
            0,
            sig, cbSignature);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlDsaSign failed", scError);
            return SCOSSL_FAILURE;
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

    scError = SymCryptMlDsaVerify(
        ctx->keyCtx->key,
        tbs, tbslen,
        ctx->pbContext, ctx->cbContext,
        sig, siglen,
        0);
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

    if (keyCtx == NULL && ctx->keyCtx != NULL)
    {
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

static const OSSL_PARAM *p_scossl_mldsa_settable_ctx_params(ossl_unused SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                                            ossl_unused void *provctx)
{
    return p_scossl_mldsa_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)) != NULL)
    {
        PVOID pbContext = ctx->pbContext;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbContext, sizeof(ctx->pbContext), &ctx->cbContext))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    // Unsupported parameters, check value matches default
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

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY)) != NULL &&
        p->data_size != 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
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

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        p->return_size = 0;

        if (p_scossl_mldsa_get_alg_id(ctx->mldsaParams, (PBYTE *)&p->data, &p->return_size) != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

#define SCOSSL_MLDSA_FNS(bits)                                                                          \
    static SCOSSL_MLDSA_SIGNATURE_CTX                                                                   \
    *p_scossl_mldsa##bits##_newctx(ossl_unused SCOSSL_PROVCTX *provctx, ossl_unused const char *propq)  \
    {                                                                                                   \
        return p_scossl_mldsa_newctx(SYMCRYPT_MLDSA_PARAMS_MLDSA##bits);                                \
    }                                                                                                   \
                                                                                                        \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_signature_functions[] = {                                \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_mldsa##bits##_newctx},                    \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_mldsa_dupctx},                            \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_mldsa_freectx},                          \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_mldsa_sign_init},                      \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_mldsa_sign},                                \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_verify_init},                  \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                            \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_mldsa_digest_sign_init},        \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))p_scossl_mldsa_sign},                         \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_digest_verify_init},    \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                     \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_get_ctx_params},            \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_gettable_ctx_params},  \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_set_ctx_params},            \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_settable_ctx_params},  \

#define SCOSSL_MLDSA_SIGN_MESSAGE_FNS                                                       \
    {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_sign_init},      \
    {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_verify_init},

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
    #define IMPLEMENT_SCOSSL_MLDSA(bits)    \
        SCOSSL_MLDSA_FNS(bits)              \
        SCOSSL_MLDSA_SIGN_MESSAGE_FNS       \
        {0, NULL}};
#else
    #define IMPLEMENT_SCOSSL_MLDSA(bits)    \
        SCOSSL_MLDSA_FNS(bits)              \
        {0, NULL}};
#endif

IMPLEMENT_SCOSSL_MLDSA(44)
IMPLEMENT_SCOSSL_MLDSA(65)
IMPLEMENT_SCOSSL_MLDSA(87)

//
// Helper functions
//

_Use_decl_annotations_
static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(SYMCRYPT_MLDSA_PARAMS mldsaParams,
                                               PBYTE *ppbAlgId, SIZE_T *pcbAlgId)
{
    ASN1_OBJECT *aobj = NULL;
    X509_ALGOR *x509Alg = NULL;
    int cbAid;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ppbAlgId == NULL ||
        pcbAlgId == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    const char *oid = NULL;
    switch (mldsaParams)
    {
    case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
        oid = SCOSSL_OID_MLDSA44;
        break;
    case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
        oid = SCOSSL_OID_MLDSA65;
        break;
    case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
        oid = SCOSSL_OID_MLDSA87;
        break;
    default:
        return SCOSSL_FAILURE;
    }

    if ((x509Alg = X509_ALGOR_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    aobj = OBJ_txt2obj(oid, 1);
    if (aobj == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "OBJ_txt2obj failed");
        goto cleanup;
    }

    X509_ALGOR_set0(x509Alg, aobj, V_ASN1_UNDEF, NULL);
    aobj = NULL; // X509_ALGOR_set0 takes ownership

    if ((cbAid = i2d_X509_ALGOR(x509Alg, ppbAlgId)) < 0)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "i2d_X509_ALGOR failed");
        goto cleanup;
    }

    *pcbAlgId = (SIZE_T)cbAid;

    ret = SCOSSL_SUCCESS;

cleanup:
    X509_ALGOR_free(x509Alg);
    ASN1_OBJECT_free(aobj);

    return ret;
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

int p_scossl_mldsa_params_to_nid(SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO); i++)
    {
        if (p_scossl_mldsa_algs[i].mldsaParams == mldsaParams)
        {
            return p_scossl_mldsa_algs[i].nid;
        }
    }

    return NID_undef;
}

SCOSSL_STATUS p_scossl_mldsa_register_algorithms()
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO); i++)
    {
        // Don't double register MLDSA algorithms. These should already be registered on
        // OpenSSL 3.5+
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