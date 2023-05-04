//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include "scossl_rsa.h"
#include "p_scossl_base.h"

# define OSSL_MAX_NAME_SIZE 50

typedef struct
{
    OSSL_LIB_CTX *libctx;
    char* propq;

    SCOSSL_RSA_KEY_CTX *kctx;

    // 
    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    int mdnid;
    BOOL allowMdUpdates;
} SCOSSL_RSA_SIGN_CTX;

static const OSSL_ITEM p_scossl_rsa_supported_mds[] = {
    {NID_sha1, OSSL_DIGEST_NAME_SHA1},
    {NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
    {NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
    {NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
    {NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
    {NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224},
    {NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256},
    {NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384},
    {NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512}};

static const OSSL_PARAM p_scossl_rsa_sig_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    // OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_sig_ctx_param_types_no_digest[] = {
    // OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_rsa_set_ctx_params(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[]);
static SCOSSL_STATUS p_scossl_rsa_set_md(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname);

static SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const char *propq)
{
    SCOSSL_RSA_SIGN_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_SIGN_CTX));
    if (ctx == NULL ||
        (propq != NULL && ((ctx->propq = OPENSSL_strdup(propq)) == NULL)))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }

    ctx->libctx = provctx->libctx;
    ctx->allowMdUpdates = TRUE;
    return ctx;
}

static void p_scossl_rsa_freectx(SCOSSL_RSA_SIGN_CTX *ctx)
{
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->propq);
    OPENSSL_clear_free(ctx, sizeof(SCOSSL_RSA_SIGN_CTX));
}

static SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_dupctx(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    SCOSSL_RSA_SIGN_CTX *copy_ctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_SIGN_CTX));
    if (copy_ctx != NULL)
    {
        copy_ctx->libctx = ctx->libctx;
        copy_ctx->kctx = ctx->kctx;
        copy_ctx->mdnid = ctx->mdnid;

        if ((ctx->propq != NULL && ((copy_ctx->propq = OPENSSL_strdup(ctx->propq)) == NULL)) ||
            ((copy_ctx->mdctx = EVP_MD_CTX_dup((const EVP_MD_CTX *)ctx->mdctx)) == NULL) ||
            ((copy_ctx->md = EVP_MD_CTX_get1_md(copy_ctx->mdctx)) == NULL))
        {
            p_scossl_rsa_freectx(copy_ctx);
            copy_ctx = NULL;
        }
    }

    return copy_ctx;
}

static SCOSSL_STATUS p_scossl_rsa_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_RSA_KEY_CTX *kctx,
                                                  _In_ const OSSL_PARAM params[])
{
    if (ctx == NULL || 
        (kctx == NULL && ctx->kctx == NULL) ||
        !kctx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (kctx != NULL)
    {
        ctx->kctx = kctx;
    }

    return p_scossl_rsa_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_rsa_sign(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                       _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                       _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    UINT32 cbModulus = SymCryptRsakeySizeofModulus(ctx->kctx->key);

    if (sig == NULL)
    {
        *siglen = cbModulus;
        return SCOSSL_SUCCESS;
    }

    if (sigsize < cbModulus)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    return scossl_rsa_sign(ctx->kctx, ctx->mdnid, tbs, tbslen, sig, siglen);
}

static SCOSSL_STATUS p_scossl_rsa_verify(_In_ SCOSSL_RSA_SIGN_CTX *ctx, 
                                         _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                         _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    return scossl_rsa_verify(ctx->kctx, ctx->mdnid, tbs, tbslen, sig, siglen);
}

static SCOSSL_STATUS p_scossl_rsa_digest_signverify_init(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname,
                                                         _In_ SCOSSL_RSA_KEY_CTX *kctx, _In_ const OSSL_PARAM params[])
{
    if (!p_scossl_rsa_signverify_init(ctx, kctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (mdname != NULL &&
        (mdname[0] == '\0' || !EVP_MD_is_a(ctx->md, mdname)) &&
        !p_scossl_rsa_set_md(ctx, mdname))
    {
        return SCOSSL_FAILURE;
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

static SCOSSL_STATUS p_scossl_rsa_digest_signverify_update(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                           _In_reads_bytes_(datalen) const unsigned char *data, size_t datalen)
{
    if (ctx == NULL || ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static SCOSSL_STATUS p_scossl_rsa_digest_sign_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                    _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize)
{
    BYTE digest[EVP_MAX_MD_SIZE];
    UINT cbDigest = 0;

    if (ctx == NULL || 
        ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    ctx->allowMdUpdates = TRUE;

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    return (sig == NULL || EVP_DigestFinal(ctx->mdctx, digest, &cbDigest)) &&
           p_scossl_rsa_sign(ctx, sig, siglen, sigsize, digest, cbDigest);
}

static SCOSSL_STATUS p_scossl_rsa_digest_verify_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                      _In_reads_bytes_(siglen) unsigned char *sig, size_t siglen)
{
    BYTE digest[EVP_MAX_MD_SIZE];
    UINT cbDigest = 0;
    
    if (ctx == NULL || 
        ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    ctx->allowMdUpdates = TRUE;

    return EVP_DigestFinal(ctx->mdctx, digest, &cbDigest) &&
           p_scossl_rsa_verify(ctx, sig, siglen, digest, cbDigest);
}

static const OSSL_PARAM *p_scossl_rsa_settable_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                          ossl_unused void *provctx)
{
    return ctx->allowMdUpdates ? 
        p_scossl_rsa_sig_ctx_param_types : 
        p_scossl_rsa_sig_ctx_param_types_no_digest;
}

static SCOSSL_STATUS p_scossl_rsa_set_ctx_params(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    char mdname[OSSL_MAX_NAME_SIZE];

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    { 
        char *pmdname = mdname;

        if(!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname))) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!p_scossl_rsa_set_md(ctx, mdname))
        {
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rsa_gettable_ctx_params(ossl_unused void *vprsactx,
                                                          ossl_unused void *provctx)
{
    return p_scossl_rsa_sig_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_rsa_get_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    if (params == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, EVP_MD_name(ctx->md))) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rsa_gettable_ctx_md_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    if (ctx->md == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static SCOSSL_STATUS p_scossl_rsa_get_ctx_md_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _Inout_ OSSL_PARAM *params)
{
    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *p_scossl_rsa_settable_ctx_md_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    if (ctx->md == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_settable_ctx_params(ctx->md);
}

static SCOSSL_STATUS p_scossl_rsa_set_ctx_md_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    if (ctx->mdctx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

const OSSL_DISPATCH p_scossl_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_rsa_newctx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_rsa_dupctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_rsa_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_rsa_signverify_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_rsa_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_rsa_signverify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_rsa_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_rsa_digest_signverify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))p_scossl_rsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))p_scossl_rsa_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_rsa_digest_signverify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))p_scossl_rsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))p_scossl_rsa_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_settable_ctx_md_params},
    {0, NULL}};

//
// Helper functions
//

int p_scossl_rsa_get_supported_md_nid(_In_ const EVP_MD *md)
{
    for (size_t i = 0; i < sizeof(p_scossl_rsa_supported_mds)/sizeof(OSSL_ITEM); i++)
    {
        if (EVP_MD_is_a(md, p_scossl_rsa_supported_mds[i].ptr))
        {
            return p_scossl_rsa_supported_mds[i].id;
        }
    }

    return NID_undef;
}

SCOSSL_STATUS p_scossl_rsa_set_md(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname)
{
    if (mdname == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if (!ctx->allowMdUpdates)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
        return SCOSSL_FAILURE;
    }

    if ((ctx->md = EVP_MD_fetch(ctx->libctx, mdname, ctx->propq)) == NULL ||
        (ctx->mdnid = p_scossl_rsa_get_supported_md_nid(ctx->md)) == NID_undef)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return SCOSSL_FAILURE;
    }

    
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;

    return SCOSSL_SUCCESS;
}