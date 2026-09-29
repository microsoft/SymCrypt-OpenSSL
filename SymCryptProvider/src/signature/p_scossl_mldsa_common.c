//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mldsa_common.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_mldsa_ctx_gettable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(_In_ const SCOSSL_MLDSA_BACKEND *backend, int params,
                                               _Out_writes_bytes_(*pcbAlgId) PBYTE *ppbAlgId, _Out_ SIZE_T *pcbAlgId);

_Use_decl_annotations_
SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_newctx(const SCOSSL_MLDSA_BACKEND *backend, int params)
{
    SCOSSL_MLDSA_SIGNATURE_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLDSA_SIGNATURE_CTX));
    if (ctx != NULL)
    {
        ctx->backend = backend;
        ctx->params = params;
    }

    return ctx;
}

_Use_decl_annotations_
void p_scossl_mldsa_freectx(SCOSSL_MLDSA_SIGNATURE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_dupctx(SCOSSL_MLDSA_SIGNATURE_CTX *ctx)
{
    SCOSSL_MLDSA_SIGNATURE_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLDSA_SIGNATURE_CTX));
    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    copyCtx->backend = ctx->backend;
    copyCtx->params = ctx->params;
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
            keyCtx->format != ctx->backend->formatPrivateKey &&
            keyCtx->format != ctx->backend->formatPrivateSeed)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->backend != ctx->backend ||
            keyCtx->params != ctx->params)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return SCOSSL_FAILURE;
        }
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return p_scossl_mldsa_set_ctx_params(ctx, params);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_sign_init(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, SCOSSL_MLDSA_KEY_CTX *keyCtx, const OSSL_PARAM params[])
{
    return p_scossl_mldsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGN);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_sign(SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                  unsigned char *sig, size_t *siglen, size_t sigsize,
                                  const unsigned char *tbs, size_t tbslen)
{
    SIZE_T cbSignatureMax;
    SIZE_T cbResult = 0;
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

    scError = ctx->backend->sizeofSignature(ctx->params, &cbSignatureMax);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("sizeofSignature failed", scError);
        return SCOSSL_FAILURE;
    }

    // The actual signature may be smaller than the maximum for some families
    // (e.g. Composite-ML-DSA due to variations in Ecdsa-Sig-Value encoding), so
    // query the maximum size when sig is NULL and report the exact number of
    // bytes written otherwise.
    if (sig == NULL)
    {
        *siglen = cbSignatureMax;
        return SCOSSL_SUCCESS;
    }

    if (sigsize < cbSignatureMax)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    scError = ctx->backend->sign(
        ctx->keyCtx->key,
        tbs, tbslen,
        ctx->abContext, ctx->cbContext,
        0,
        sig, cbSignatureMax,
        &cbResult);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("sign failed", scError);
        return SCOSSL_FAILURE;
    }

    *siglen = cbResult;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_verify_init(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, SCOSSL_MLDSA_KEY_CTX *keyCtx, const OSSL_PARAM params[])
{
    return p_scossl_mldsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_verify(SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                    const unsigned char *sig, size_t siglen,
                                    const unsigned char *tbs, size_t tbslen)
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

    scError = ctx->backend->verify(
        ctx->keyCtx->key,
        tbs, tbslen,
        ctx->abContext, ctx->cbContext,
        sig, siglen,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("verify returned unexpected error", scError);
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

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_digest_sign_init(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, const char *mdname,
                                              SCOSSL_MLDSA_KEY_CTX *keyCtx, const OSSL_PARAM params[])
{
    return p_scossl_mldsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_SIGN);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_digest_verify_init(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, const char *mdname,
                                                SCOSSL_MLDSA_KEY_CTX *keyCtx, const OSSL_PARAM params[])
{
    return p_scossl_mldsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

_Use_decl_annotations_
const OSSL_PARAM *p_scossl_mldsa_settable_ctx_params(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, ossl_unused void *provctx)
{
    return ctx->backend->sigSettableCtxParams;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)) != NULL)
    {
        PVOID pbContext = ctx->abContext;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbContext, sizeof(ctx->abContext), &ctx->cbContext))
        {
            ctx->cbContext = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    // Some families (e.g. "pure" ML-DSA) expose additional parameters that are
    // not supported yet; delegate their validation to the backend.
    if (ctx->backend->validateExtraSigCtxParams != NULL)
    {
        return ctx->backend->validateExtraSigCtxParams(params);
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
const OSSL_PARAM *p_scossl_mldsa_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_mldsa_ctx_gettable_param_types;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_get_ctx_params(SCOSSL_MLDSA_SIGNATURE_CTX *ctx, OSSL_PARAM params[])
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

        if (p_scossl_mldsa_get_alg_id(ctx->backend, ctx->params, &pbAid, &cbAid) != SCOSSL_SUCCESS)
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

//
// Helper functions
//

_Use_decl_annotations_
static SCOSSL_STATUS p_scossl_mldsa_get_alg_id(const SCOSSL_MLDSA_BACKEND *backend, int params,
                                               PBYTE *ppbAlgId, SIZE_T *pcbAlgId)
{
    ASN1_OBJECT *aobj = NULL;
    X509_ALGOR *x509Alg = NULL;
    PBYTE pbAlgId = NULL;
    int cbAid;
    const char *oid = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ppbAlgId == NULL || pcbAlgId == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    *ppbAlgId = NULL;

    for (SIZE_T i = 0; i < backend->cAlgInfos; i++)
    {
        if (backend->algInfos[i].params == params)
        {
            oid = backend->algInfos[i].oid;
            break;
        }
    }

    if (oid == NULL)
    {
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

_Use_decl_annotations_
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(const SCOSSL_MLDSA_BACKEND *backend, int nid)
{
    for (SIZE_T i = 0; i < backend->cAlgInfos; i++)
    {
        if (backend->algInfos[i].nid == nid)
        {
            return &backend->algInfos[i];
        }
    }

    return NULL;
}

_Use_decl_annotations_
int p_scossl_mldsa_params_to_nid(const SCOSSL_MLDSA_BACKEND *backend, int params)
{
    for (SIZE_T i = 0; i < backend->cAlgInfos; i++)
    {
        if (backend->algInfos[i].params == params)
        {
            return backend->algInfos[i].nid;
        }
    }

    return NID_undef;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_mldsa_register_backend(const SCOSSL_MLDSA_BACKEND *backend)
{
    for (SIZE_T i = 0; i < backend->cAlgInfos; i++)
    {
        // Don't double register algorithms. Some (e.g. "pure" ML-DSA on OpenSSL
        // 3.5+) are already registered; others (e.g. Composite-ML-DSA) must be
        // created if they have not already been registered.
        backend->algInfos[i].nid = OBJ_sn2nid(backend->algInfos[i].snGroupName);
        if (backend->algInfos[i].nid == NID_undef)
        {
            backend->algInfos[i].nid = OBJ_create(backend->algInfos[i].oid, backend->algInfos[i].snGroupName, backend->algInfos[i].lnGroupName);
            if (backend->algInfos[i].nid == NID_undef)
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
