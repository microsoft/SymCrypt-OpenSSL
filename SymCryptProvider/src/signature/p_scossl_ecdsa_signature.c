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
    SCOSSL_ECC_KEY_CTX *keyCtx;

    // Needed for fetching md
    OSSL_LIB_CTX *libctx;
    char* propq;

    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    SIZE_T mdSize;
    BOOL allowMdUpdates;
} SCOSSL_ECDSA_CTX;

static const OSSL_PARAM p_scossl_ecdsa_ctx_gettable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecdsa_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_END};

// Digest cannot be set during digest sign update
static const OSSL_PARAM p_scossl_ecdsa_ctx_settable_param_types_no_digest[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_ecdsa_set_ctx_params(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_ECDSA_CTX *p_scossl_ecdsa_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const char *propq)
{
    SCOSSL_ECDSA_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_ECDSA_CTX));
    if (ctx != NULL)
    {
        if (propq != NULL && ((ctx->propq = OPENSSL_strdup(propq)) == NULL))
        {
            OPENSSL_free(ctx);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }

        ctx->libctx = provctx->libctx;
        ctx->allowMdUpdates = TRUE;
    }

    return ctx;
}

static void p_scossl_ecdsa_freectx(SCOSSL_ECDSA_CTX *ctx)
{
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx);
}

static SCOSSL_ECDSA_CTX *p_scossl_ecdsa_dupctx(_In_ SCOSSL_ECDSA_CTX *ctx)
{
    SCOSSL_ECDSA_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_ECDSA_CTX));
    if (copyCtx != NULL)
    {
        if ((ctx->propq != NULL && ((copyCtx->propq = OPENSSL_strdup(ctx->propq)) == NULL)) ||
            (ctx->mdctx != NULL && ((copyCtx->mdctx = EVP_MD_CTX_dup((const EVP_MD_CTX *)ctx->mdctx)) == NULL)) ||
            (ctx->md    != NULL && !EVP_MD_up_ref(ctx->md)))
        {
            p_scossl_ecdsa_freectx(copyCtx);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            copyCtx = NULL;
        }

        copyCtx->libctx = ctx->libctx;
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->md = ctx->md;
        ctx->mdSize = ctx->mdSize;
        copyCtx->allowMdUpdates = ctx->allowMdUpdates;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_ecdsa_signverify_init(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                                    _In_ const OSSL_PARAM params[])
{
    if (ctx == NULL ||
        (keyCtx == NULL && ctx->keyCtx == NULL))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (keyCtx != NULL)
    {
        if (!keyCtx->initialized)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return SCOSSL_FAILURE;
        }

        ctx->keyCtx = keyCtx;
    }

    return p_scossl_ecdsa_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_ecdsa_sign_init(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                              _In_ const OSSL_PARAM params[])
{
    return p_scossl_ecdsa_signverify_init(ctx, keyCtx, params);
}

static SCOSSL_STATUS p_scossl_ecdsa_verify_init(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                                _In_ const OSSL_PARAM params[])
{
    return p_scossl_ecdsa_signverify_init(ctx, keyCtx, params);
}

static SCOSSL_STATUS p_scossl_ecdsa_sign(_In_ SCOSSL_ECDSA_CTX *ctx,
                                         _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                         _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    SIZE_T cbResult;

    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (siglen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    cbResult = scossl_ecdsa_size(ctx->keyCtx->curve);
    if (sig == NULL)
    {
        *siglen = cbResult;
        return SCOSSL_SUCCESS;
    }

    if (sigsize < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    if (ctx->mdSize != 0 && tbslen != ctx->mdSize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        return SCOSSL_FAILURE;
    }

    return scossl_ecdsa_sign(ctx->keyCtx->key, ctx->keyCtx->curve, tbs, tbslen, sig, (unsigned int *)siglen);
}

static SCOSSL_STATUS p_scossl_ecdsa_verify(_In_ SCOSSL_ECDSA_CTX *ctx,
                                           _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                           _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    return scossl_ecdsa_verify(ctx->keyCtx->key, ctx->keyCtx->curve, tbs, tbslen, sig, siglen);
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_signverify_init(_In_ SCOSSL_ECDSA_CTX *ctx, _In_ const char *mdname,
                                                           _In_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[], ossl_unused int operation)
{
    if (!p_scossl_ecdsa_signverify_init(ctx, keyCtx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (mdname != NULL &&
        (mdname[0] == '\0' || ctx->md == NULL || !EVP_MD_is_a(ctx->md, mdname)))
    {
        // Different digest specified than what was previously set by parameters.
        EVP_MD_free(ctx->md);

        ctx->md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
    }

    if (ctx->mdctx == NULL &&
        ((ctx->mdctx = EVP_MD_CTX_new()) == NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
    {
        EVP_MD_CTX_free(ctx->mdctx);
        ctx->mdctx = NULL;
        return SCOSSL_FAILURE;
    }

    ctx->allowMdUpdates = FALSE;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_sign_init(_In_ SCOSSL_ECDSA_CTX *ctx, _In_ const char *mdname,
                                                     _In_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_ecdsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_SIGN);
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_verify_init(_In_ SCOSSL_ECDSA_CTX *ctx, _In_ const char *mdname,
                                                       _In_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_ecdsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_signverify_update(_In_ SCOSSL_ECDSA_CTX *ctx,
                                                             _In_reads_bytes_(datalen) const unsigned char *data, size_t datalen)
{
    if (ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_sign_final(_In_ SCOSSL_ECDSA_CTX *ctx,
                                                      _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize)
{
    BYTE digest[EVP_MAX_MD_SIZE];
    UINT cbDigest = 0;

    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    if (sig != NULL)
    {
        ctx->allowMdUpdates = TRUE;

        if (!EVP_DigestFinal(ctx->mdctx, digest, &cbDigest))
        {
            return SCOSSL_FAILURE;
        }
    }

    return p_scossl_ecdsa_sign(ctx, sig, siglen, sigsize, digest, cbDigest);
}

static SCOSSL_STATUS p_scossl_ecdsa_digest_verify_final(_In_ SCOSSL_ECDSA_CTX *ctx,
                                                        _In_reads_bytes_(siglen) unsigned char *sig, size_t siglen)
{
    BYTE digest[EVP_MAX_MD_SIZE];
    UINT cbDigest = 0;

    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    ctx->allowMdUpdates = TRUE;

    return EVP_DigestFinal(ctx->mdctx, digest, &cbDigest) &&
           p_scossl_ecdsa_verify(ctx, sig, siglen, digest, cbDigest);
}

static const OSSL_PARAM *p_scossl_ecdsa_settable_ctx_params(_In_ SCOSSL_ECDSA_CTX *ctx,
                                                            ossl_unused void *provctx)
{
    return ctx->allowMdUpdates ? p_scossl_ecdsa_ctx_settable_param_types : p_scossl_ecdsa_ctx_settable_param_types_no_digest;
}

static SCOSSL_STATUS p_scossl_ecdsa_set_ctx_params(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const OSSL_PARAM *param_propq;
    const char *mdname, *mdprops;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL)
    {
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdprops = NULL;
        if ((param_propq = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES)) != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdprops))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        ctx->md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        if (ctx->md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        ctx->mdSize = EVP_MD_get_size(ctx->md);
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &ctx->mdSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_ecdsa_gettable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    return p_scossl_ecdsa_ctx_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_ecdsa_get_ctx_params(_In_ SCOSSL_ECDSA_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    if (params == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    OSSL_PARAM *p;
    X509_ALGOR *x509Alg = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL ? "" : EVP_MD_get0_name(ctx->md)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->mdSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)) != NULL)
    {
        int cbAid;
        int algNid = NID_undef;

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;

        }

        p->return_size = 0;

        if (ctx->md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            goto cleanup;
        }

        if ((x509Alg = X509_ALGOR_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        switch (EVP_MD_nid(ctx->md))
        {
        case NID_sha1:
            algNid = NID_ecdsa_with_SHA1;
            break;
        case NID_sha256:
            algNid = NID_ecdsa_with_SHA256;
            break;
        case NID_sha384:
            algNid = NID_ecdsa_with_SHA384;
            break;
        case NID_sha512:
            algNid = NID_ecdsa_with_SHA512;
            break;
        case NID_sha3_256:
            algNid = NID_ecdsa_with_SHA3_256;
            break;
        case NID_sha3_384:
            algNid = NID_ecdsa_with_SHA3_384;
            break;
        case NID_sha3_512:
            algNid = NID_ecdsa_with_SHA3_512;
            break;
        }

        if (algNid == NID_undef ||
            !X509_ALGOR_set0(x509Alg, OBJ_nid2obj(algNid), V_ASN1_UNDEF, NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if ((cbAid = i2d_X509_ALGOR(x509Alg, (unsigned char**)&p->data)) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        p->return_size = (SIZE_T)cbAid;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    X509_ALGOR_free(x509Alg);

    return ret;
}

static const OSSL_PARAM *p_scossl_ecdsa_gettable_ctx_md_params(_In_ SCOSSL_ECDSA_CTX *ctx)
{
    if (ctx->md == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static SCOSSL_STATUS p_scossl_ecdsa_get_ctx_md_params(_In_ SCOSSL_ECDSA_CTX *ctx, _Inout_ OSSL_PARAM *params)
{
    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *p_scossl_ecdsa_settable_ctx_md_params(_In_ SCOSSL_ECDSA_CTX *ctx)
{
    if (ctx->md == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_settable_ctx_params(ctx->md);
}

static SCOSSL_STATUS p_scossl_ecdsa_set_ctx_md_params(_In_ SCOSSL_ECDSA_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

const OSSL_DISPATCH p_scossl_ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_ecdsa_newctx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_ecdsa_dupctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_ecdsa_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_ecdsa_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_ecdsa_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_ecdsa_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_ecdsa_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_ecdsa_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))p_scossl_ecdsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))p_scossl_ecdsa_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_ecdsa_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))p_scossl_ecdsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))p_scossl_ecdsa_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_ecdsa_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdsa_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_ecdsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdsa_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))p_scossl_ecdsa_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_ecdsa_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))p_scossl_ecdsa_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_ecdsa_settable_ctx_md_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif
