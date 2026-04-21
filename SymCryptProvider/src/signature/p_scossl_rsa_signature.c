//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include "scossl_rsa.h"
#include "p_scossl_rsa.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_PROV_RSA_KEY_CTX *keyCtx;
    UINT8 padding;
    int operation;

    // Needed for fetching md
    OSSL_LIB_CTX *libctx;
    char* propq;

    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    const OSSL_ITEM *mdInfo; // Informational, must match md if set
    BOOL allowMdUpdates;

    // PSS params
    BOOL pssRestricted;
    const OSSL_ITEM *mgf1MdInfo; // Informational, must match md if set
    int cbSalt;
    int cbSaltMin;

    // Sigalg state tracking
    BOOL isSigalg;
    BOOL allowUpdate;
    BOOL allowFinal;
    BOOL allowOneshot;

    // Sigalg verify message support
    PBYTE pbSignature;
    SIZE_T cbSignature;
} SCOSSL_RSA_SIGN_CTX;

#define SCOSSL_RSA_SIGNATURE_GETTABLE_PARAMS                        \
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),   \
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0), \
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),

#define SCOSSL_RSA_PSS_SIGNATURE_GETTABLE_PARAMS                       \
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0), \
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0), \
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),

#define SCOSSL_RSA_PSS_SIGNATURE_SETTABLE_PARAMS \
    SCOSSL_RSA_PSS_SIGNATURE_GETTABLE_PARAMS     \
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),

static const OSSL_PARAM p_scossl_rsa_sig_ctx_gettable_param_types[] = {
    SCOSSL_RSA_SIGNATURE_GETTABLE_PARAMS
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_pss_sig_ctx_gettable_param_types[] = {
    SCOSSL_RSA_SIGNATURE_GETTABLE_PARAMS
    SCOSSL_RSA_PSS_SIGNATURE_GETTABLE_PARAMS
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_sigalg_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
    OSSL_PARAM_END};

// Padding may not be set at the time of querying settable params, so PSS params
// are always accepted. The provider will check the padding before attempting
// to set the PSS parameters
static const OSSL_PARAM p_scossl_rsa_sig_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    SCOSSL_RSA_PSS_SIGNATURE_SETTABLE_PARAMS
    OSSL_PARAM_END};

// Digest cannot be set during digest sign update
static const OSSL_PARAM p_scossl_rsa_sig_ctx_settable_param_types_no_digest[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    SCOSSL_RSA_PSS_SIGNATURE_SETTABLE_PARAMS
    OSSL_PARAM_END};

static OSSL_ITEM p_scossl_rsa_sign_padding_modes[] = {
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
    {RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS},
    {0, NULL}};

static SCOSSL_STATUS p_scossl_rsa_set_ctx_params(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const char *propq)
{
    SCOSSL_RSA_SIGN_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_SIGN_CTX));
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
        ctx->padding = RSA_PKCS1_PADDING;
        ctx->cbSaltMin = -1;
    }

    return ctx;
}

static void p_scossl_rsa_freectx(SCOSSL_RSA_SIGN_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx->pbSignature);
    OPENSSL_free(ctx);
}

static SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_dupctx(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    SCOSSL_RSA_SIGN_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_SIGN_CTX));
    if (copyCtx != NULL)
    {
        if ((ctx->propq != NULL && ((copyCtx->propq = OPENSSL_strdup(ctx->propq)) == NULL)) ||
            (ctx->mdctx != NULL && ((copyCtx->mdctx = EVP_MD_CTX_dup((const EVP_MD_CTX *)ctx->mdctx)) == NULL)) ||
            (ctx->md    != NULL && !EVP_MD_up_ref(ctx->md)))
        {
            p_scossl_rsa_freectx(copyCtx);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            copyCtx = NULL;
        }

        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->padding = ctx->padding;
        copyCtx->operation = ctx->operation;
        copyCtx->libctx = ctx->libctx;
        copyCtx->md = ctx->md;
        copyCtx->cbSalt = ctx->cbSalt;
        copyCtx->mdInfo = ctx->mdInfo;
        copyCtx->allowMdUpdates = ctx->allowMdUpdates;
        copyCtx->pssRestricted = ctx->pssRestricted;
        copyCtx->mgf1MdInfo = ctx->mgf1MdInfo;
        copyCtx->cbSaltMin = ctx->cbSaltMin;
        copyCtx->isSigalg = ctx->isSigalg;
        copyCtx->allowUpdate = ctx->allowUpdate;
        copyCtx->allowFinal = ctx->allowFinal;
        copyCtx->allowOneshot = ctx->allowOneshot;
        copyCtx->cbSignature = ctx->cbSignature;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_rsa_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                                  _In_ const OSSL_PARAM params[], int operation)
{
    if (ctx == NULL ||
        (keyCtx == NULL && ctx->keyCtx == NULL))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    ctx->cbSalt = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    ctx->cbSaltMin = -1;
    ctx->operation = operation;
    ctx->allowMdUpdates = TRUE;
    ctx->allowUpdate = TRUE;
    ctx->allowFinal = TRUE;
    ctx->allowOneshot = TRUE;
    ctx->isSigalg = FALSE;
    ctx->pssRestricted = FALSE;

    OPENSSL_free(ctx->pbSignature);
    ctx->pbSignature = NULL;
    ctx->cbSignature = 0;

    if (keyCtx != NULL)
    {
        if (!keyCtx->initialized)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return SCOSSL_FAILURE;
        }

        if (keyCtx->pssRestrictions != NULL)
        {
            EVP_MD *md = NULL;
            // ScOSSL does not support distinct MD and MGF1 MD
            if (keyCtx->pssRestrictions->mdInfo != keyCtx->pssRestrictions->mgf1MdInfo ||
                (md = EVP_MD_fetch(ctx->libctx, keyCtx->pssRestrictions->mdInfo->ptr, NULL)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return SCOSSL_FAILURE;
            }

            int cbSaltMax = scossl_rsa_pss_get_salt_max(keyCtx->key, EVP_MD_get_size(md));
            if (keyCtx->pssRestrictions->cbSaltMin < 0 ||
                keyCtx->pssRestrictions->cbSaltMin > cbSaltMax)
            {
                EVP_MD_free(md);
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                return SCOSSL_FAILURE;
            }

            ctx->md = md;
            ctx->mdInfo = keyCtx->pssRestrictions->mdInfo;
            ctx->mgf1MdInfo = keyCtx->pssRestrictions->mgf1MdInfo;
            ctx->cbSalt = keyCtx->pssRestrictions->cbSaltMin;
            ctx->cbSaltMin = keyCtx->pssRestrictions->cbSaltMin;
            ctx->pssRestricted = TRUE;
        }

        ctx->keyCtx = keyCtx;
        ctx->padding = keyCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;

#ifdef KEYSINUSE_ENABLED
        if (keysinuse_is_running() &&
            (operation == EVP_PKEY_OP_SIGN || operation == EVP_PKEY_OP_SIGNMSG))
        {
            p_scossl_rsa_init_keysinuse(keyCtx);
        }
#endif
    }

    return p_scossl_rsa_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_rsa_sign_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                            _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGN);
}

static SCOSSL_STATUS p_scossl_rsa_verify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                              _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

static SCOSSL_STATUS p_scossl_rsa_sign_internal(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                                _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    int mdnid = ctx->mdInfo == NULL ? NID_undef : ctx->mdInfo->id;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (sig != NULL && sigsize < SymCryptRsakeySizeofModulus(ctx->keyCtx->key))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto err;
    }

    switch (ctx->padding)
    {
    case RSA_PKCS1_PADDING:
        ret = scossl_rsa_pkcs1_sign(ctx->keyCtx->key, mdnid, tbs, tbslen, sig, siglen);
        break;
    case RSA_PKCS1_PSS_PADDING:
        if (mdnid == NID_undef)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            goto err;
        }

        ret = scossl_rsapss_sign(ctx->keyCtx->key, mdnid, ctx->cbSalt, tbs, tbslen, sig, siglen);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
        goto err;
    }

#ifdef KEYSINUSE_ENABLED
    if (ret && sig != NULL)
    {
        keysinuse_on_use(ctx->keyCtx->keysinuseCtx, KEYSINUSE_SIGN);
    }
#endif

err:
    return ret;
}

static SCOSSL_STATUS p_scossl_rsa_verify_internal(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                  _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                                  _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    int mdnid = ctx->mdInfo == NULL ? NID_undef : ctx->mdInfo->id;

    if (ctx == NULL || ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    switch (ctx->padding)
    {
    case RSA_PKCS1_PADDING:
        return scossl_rsa_pkcs1_verify(ctx->keyCtx->key, mdnid, tbs, tbslen, sig, siglen);
    case RSA_PKCS1_PSS_PADDING:
        if (mdnid == NID_undef)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            return SCOSSL_FAILURE;
        }

        return scossl_rsapss_verify(ctx->keyCtx->key, mdnid, ctx->cbSalt, tbs, tbslen, sig, siglen);
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
    }

    return SCOSSL_FAILURE;
}
static SCOSSL_STATUS p_scossl_rsa_digest_signverify_init(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname,
                                                         _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[], int operation)
{
    if (!p_scossl_rsa_signverify_init(ctx, keyCtx, params, operation))
    {
        return SCOSSL_FAILURE;
    }

    // Different digest specified than what was previously set by paramters.
    if (mdname != NULL &&
        (mdname[0] == '\0' || ctx->md == NULL || !EVP_MD_is_a(ctx->md, mdname)))
    {
        if (ctx->pssRestricted)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
            return SCOSSL_FAILURE;
        }

        EVP_MD *md = NULL;
        const OSSL_ITEM *mdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, ctx->padding, mdname, NULL, &md);

        if (mdInfo == NULL ||
            (ctx->mgf1MdInfo != NULL && mdInfo->id != ctx->mgf1MdInfo->id))
        {
            EVP_MD_free(md);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        EVP_MD_free(ctx->md);
        ctx->md = md;
        ctx->mdInfo = mdInfo;
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

static SCOSSL_STATUS p_scossl_rsa_digest_sign_init(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname,
                                                   _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_SIGN);
}

static SCOSSL_STATUS p_scossl_rsa_digest_verify_init(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const char *mdname,
                                                     _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_digest_signverify_init(ctx, mdname, keyCtx, params, EVP_PKEY_OP_VERIFY);
}

static SCOSSL_STATUS p_scossl_rsa_digest_signverify_update(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                           _In_reads_bytes_(datalen) const unsigned char *data, size_t datalen)
{
    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->isSigalg)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowUpdate)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    ctx->allowOneshot = FALSE;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static SCOSSL_STATUS p_scossl_rsa_digest_sign_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                    _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    BYTE digest[EVP_MAX_MD_SIZE];
    unsigned int cbDigest = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->isSigalg)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowFinal)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FINAL_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    if (sig != NULL)
    {
        if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &cbDigest))
        {
            return SCOSSL_FAILURE;
        }

        ctx->allowUpdate = FALSE;
        ctx->allowFinal = FALSE;
        ctx->allowOneshot = FALSE;
    }

    ret = p_scossl_rsa_sign_internal(ctx, sig, siglen, sigsize, digest, cbDigest);

    ctx->allowMdUpdates = TRUE;

    return ret;
}

static SCOSSL_STATUS p_scossl_rsa_digest_verify_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                      _In_reads_bytes_(siglen) unsigned char *sig, size_t siglen)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    BYTE digest[EVP_MAX_MD_SIZE];
    unsigned int cbDigest = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->isSigalg)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowFinal)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FINAL_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &cbDigest))
    {
        return SCOSSL_FAILURE;
    }

    ctx->allowUpdate = FALSE;
    ctx->allowFinal = FALSE;
    ctx->allowOneshot = FALSE;

    ret = p_scossl_rsa_verify_internal(ctx, sig, siglen, digest, cbDigest);

    ctx->allowMdUpdates = TRUE;

    return ret;
}

static const OSSL_PARAM *p_scossl_rsa_settable_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                          ossl_unused void *provctx)
{
    if (ctx != NULL && !ctx->allowMdUpdates)
    {
        return p_scossl_rsa_sig_ctx_settable_param_types_no_digest;
    }

    return p_scossl_rsa_sig_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_rsa_set_ctx_params(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const char *mdName, *mdProps;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL)
    {
        EVP_MD *md = NULL;
        const OSSL_ITEM *mdInfo;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES)) != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // ScOSSL does not support distinct MD and MGF1 MD
        mdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, ctx->padding, mdName, mdProps, &md);
        if (mdInfo == NULL ||
            (ctx->mgf1MdInfo != NULL && mdInfo->id != ctx->mgf1MdInfo->id))
        {
            EVP_MD_free(md);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        if (ctx->pssRestricted)
        {
            // MD already set. Only need to check whether this matches
            EVP_MD_free(md);
            if (mdInfo->id != ctx->mdInfo->id)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            EVP_MD_free(ctx->md);
            ctx->md = md;
            ctx->mdInfo = mdInfo;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL)
    {
        // Padding mode may be passed as legacy NID or string, and is
        // checked against the padding modes the ScOSSL provider supports
        int i = 0;
        unsigned int padding;

        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_uint(p, &padding))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            while (p_scossl_rsa_sign_padding_modes[i].id != 0 &&
                   padding != p_scossl_rsa_sign_padding_modes[i].id)
            {
                i++;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            while (p_scossl_rsa_sign_padding_modes[i].id != 0 &&
                   OPENSSL_strcasecmp(p->data, p_scossl_rsa_sign_padding_modes[i].ptr) != 0)
            {
                i++;
            }
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        padding = p_scossl_rsa_sign_padding_modes[i].id;

        if (padding == 0 ||
            (ctx->keyCtx != NULL &&
             ctx->keyCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS &&
             padding != RSA_PKCS1_PSS_PADDING))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return SCOSSL_FAILURE;
        }

        // MD5+SHA1 is only allowed for RSA_PKCS1_PADDING
        if (padding != RSA_PKCS1_PADDING &&
            ctx->mdInfo != NULL &&
            ctx->mdInfo->id == NID_md5_sha1)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
            return SCOSSL_FAILURE;
        }

        ctx->padding = padding;
    }

    //
    // PSS paramaters
    //
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN)) != NULL)
    {
        // PSS padding must be set before setting PSS parameters
        if (ctx->padding != RSA_PKCS1_PSS_PADDING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }

        int cbSalt;
        // Padding mode may be passed as legacy NID or string
        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(p, &cbSalt))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
            {
                cbSalt = RSA_PSS_SALTLEN_DIGEST;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
            {
                // Sign: Maximized salt length
                // Verify: Autorecovered salt length
                cbSalt = RSA_PSS_SALTLEN_AUTO;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
            {
                cbSalt = RSA_PSS_SALTLEN_MAX;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
            {
                // Sign: Smaller of digest length or maximized salt length
                // Verify: Autorecovered salt length
                cbSalt = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
            }
            else
            {
                cbSalt = atoi(p->data);
            }
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
        if (cbSalt < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return SCOSSL_FAILURE;
        }

        if (ctx->pssRestricted)
        {
            switch (cbSalt)
            {
            case RSA_PSS_SALTLEN_AUTO:
            case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                if (ctx->operation == EVP_PKEY_OP_VERIFY ||
                    ctx->operation == EVP_PKEY_OP_VERIFYMSG)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                    return SCOSSL_FAILURE;
                }
                break;
            case RSA_PSS_SALTLEN_DIGEST:
                if (EVP_MD_get_size(ctx->md) < ctx->cbSaltMin)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                    return SCOSSL_FAILURE;
                }
                break;
            default:
                if (cbSalt >= 0 && cbSalt < ctx->cbSaltMin)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                    return SCOSSL_FAILURE;
                }
            }
        }

        ctx->cbSalt = cbSalt;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST)) != NULL)
    {
        // PSS padding must be set before setting PSS parameters
        if (ctx->padding != RSA_PKCS1_PSS_PADDING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return SCOSSL_FAILURE;
        }

        EVP_MD *md = NULL;
        const OSSL_ITEM *mgf1MdInfo;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES)) != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // ScOSSL does not support distinct MD and MGF1 MD
        mgf1MdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, ctx->padding, mdName, mdProps, &md);
        if (mgf1MdInfo == NULL ||
            (ctx->mdInfo != NULL && mgf1MdInfo->id != ctx->mdInfo->id))
        {
            EVP_MD_free(md);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        if (ctx->pssRestricted)
        {
            // MD already set. Only need to check whether this matches
            EVP_MD_free(md);
            if (mgf1MdInfo->id != ctx->mgf1MdInfo->id)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            EVP_MD_free(ctx->md);
            ctx->md = md;
            ctx->mgf1MdInfo = mgf1MdInfo;
            ctx->mdInfo = mgf1MdInfo;
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rsa_sigalg_settable_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, ossl_unused void *provctx)
{
    if (ctx != NULL && ctx->operation == EVP_PKEY_OP_VERIFYMSG)
    {
        return p_scossl_rsa_sigalg_ctx_settable_param_types;
    }

    return NULL;
}

static SCOSSL_STATUS p_scossl_rsa_sigalg_set_ctx_params(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return SCOSSL_FAILURE;

    if (ctx->operation == EVP_PKEY_OP_VERIFYMSG)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE)) != NULL)
        {
            OPENSSL_free(ctx->pbSignature);
            ctx->pbSignature = NULL;
            ctx->cbSignature = 0;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pbSignature, 0, &ctx->cbSignature))
            {
                return SCOSSL_FAILURE;
            }
        }
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rsa_gettable_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX  *ctx,
                                                          ossl_unused void *provctx)
{
    return ctx->padding == RSA_PKCS1_PSS_PADDING ? p_scossl_rsa_pss_sig_ctx_gettable_param_types : p_scossl_rsa_sig_ctx_gettable_param_types;
}

static ASN1_STRING *p_scossl_rsa_pss_params_to_asn1_sequence(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    SCOSSL_RSA_PSS_RESTRICTIONS defaultRestrictions;
    RSA_PSS_PARAMS *pssParams = NULL;
    ASN1_STRING *mgf1MdStr = NULL;
    ASN1_STRING *pssParamSeq = NULL;
    int cbSalt;
    int cbSaltMax;
    int cbHash;

    if ((pssParams = RSA_PSS_PARAMS_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    p_scossl_rsa_pss_restrictions_get_defaults(&defaultRestrictions);

    // mgf1md must equal md for symcrypt
    // If this changes, the mgf1md must be checked independently
    if (ctx->mdInfo->id != defaultRestrictions.mdInfo->id)
    {
        if ((pssParams->hashAlgorithm = X509_ALGOR_new()) == NULL ||
            (pssParams->maskGenAlgorithm = X509_ALGOR_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        X509_ALGOR_set_md(pssParams->hashAlgorithm, ctx->md);

        if (ASN1_item_pack(pssParams->hashAlgorithm, ASN1_ITEM_rptr(X509_ALGOR), &mgf1MdStr) == NULL ||
            !X509_ALGOR_set0(pssParams->maskGenAlgorithm, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, mgf1MdStr))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    cbSalt = ctx->cbSalt;

    // Determine actual salt value if some auto detect value is set
    if (cbSalt < 0)
    {
        if (ctx->keyCtx == NULL ||
            !ctx->keyCtx->initialized)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            goto cleanup;
        }

        cbHash = scossl_get_expected_hash_length(ctx->mdInfo->id);
        cbSaltMax = scossl_rsa_pss_get_salt_max(ctx->keyCtx->key, cbHash);

        switch(cbSalt)
        {
        case RSA_PSS_SALTLEN_DIGEST:
            cbSalt = cbHash;
            break;
        case RSA_PSS_SALTLEN_MAX:
        case RSA_PSS_SALTLEN_AUTO:
            cbSalt = cbSaltMax;
            break;
        case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
            cbSalt = cbSaltMax < (int)cbHash ? cbSaltMax : (int)cbHash;
            break;
        }

        if (cbSalt < 0)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Invalid salt length in key context");
            goto cleanup;
        }
    }

    if (cbSalt != defaultRestrictions.cbSaltMin)
    {
        if ((pssParams->saltLength = ASN1_INTEGER_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!ASN1_INTEGER_set(pssParams->saltLength, cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    pssParamSeq = ASN1_item_pack(pssParams, ASN1_ITEM_rptr(RSA_PSS_PARAMS), NULL);

cleanup:
    RSA_PSS_PARAMS_free(pssParams);

    return pssParamSeq;
}

static SCOSSL_STATUS p_scossl_rsa_get_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    if (params == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    OSSL_PARAM *p;
    ASN1_STRING *pval = NULL;
    X509_ALGOR *x509Alg = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mdInfo == NULL ? "" : ctx->mdInfo->ptr))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL)
    {
        int i = 0;

        // Padding mode may be retrieved as legacy NID or string
        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->padding))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            while (p_scossl_rsa_sign_padding_modes[i].id != 0 &&
                   ctx->padding != p_scossl_rsa_sign_padding_modes[i].id)
            {
                i++;
            }

            if (!OSSL_PARAM_set_utf8_string(p, p_scossl_rsa_sign_padding_modes[i].ptr))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }


    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)) != NULL) {
        int cbAid;
        int algNid = NID_undef;
        int ptype = V_ASN1_NULL;
        void *pval = NULL;

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        p->return_size = 0;

        if (ctx->mdInfo == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            goto cleanup;
        }

        if ((x509Alg = X509_ALGOR_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (ctx->padding == RSA_PKCS1_PADDING)
        {
            switch (ctx->mdInfo->id)
            {
            case NID_sha1:
                algNid = NID_sha1WithRSAEncryption;
                break;
            case NID_sha224:
                algNid = NID_sha224WithRSAEncryption;
                break;
            case NID_sha256:
                algNid = NID_sha256WithRSAEncryption;
                break;
            case NID_sha384:
                algNid = NID_sha384WithRSAEncryption;
                break;
            case NID_sha512:
                algNid = NID_sha512WithRSAEncryption;
                break;
            case NID_sha512_224:
                algNid = NID_sha512_224WithRSAEncryption;
                break;
            case NID_sha512_256:
                algNid = NID_sha512_256WithRSAEncryption;
                break;
            case NID_sha3_224:
                algNid = NID_RSA_SHA3_224;
                break;
            case NID_sha3_256:
                algNid = NID_RSA_SHA3_256;
                break;
            case NID_sha3_384:
                algNid = NID_RSA_SHA3_384;
                break;
            case NID_sha3_512:
                algNid = NID_RSA_SHA3_512;
                break;
            }
        }
        else if (ctx->padding == RSA_PKCS1_PSS_PADDING)
        {
            algNid = NID_rsassaPss;

            ptype = V_ASN1_SEQUENCE;
            if ((pval = p_scossl_rsa_pss_params_to_asn1_sequence(ctx)) == NULL)
            {
                goto cleanup;
            }
        }


        if (algNid == NID_undef ||
            !X509_ALGOR_set0(x509Alg, OBJ_nid2obj(algNid), ptype, pval))
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

    //
    // PSS paramaters
    //
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN)) != NULL)
    {
        const char* saltLenText = NULL;
        int len;

        // Padding mode may be accepted as legacy NID or string
        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->cbSalt))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            switch (ctx->cbSalt)
            {
                case RSA_PSS_SALTLEN_DIGEST:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
                    break;
                case RSA_PSS_SALTLEN_AUTO:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
                    break;
                case RSA_PSS_SALTLEN_MAX:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
                    break;
                case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX;
                    break;
                default:
                    len = BIO_snprintf(p->data, p->data_size, "%d",
                                           ctx->cbSalt);
                    if (len <= 0)
                        goto cleanup;
                    p->return_size = len;
            }

            if (saltLenText != NULL &&
                !OSSL_PARAM_set_utf8_string(p, saltLenText))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }

            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mgf1MdInfo == NULL ? "" : ctx->mgf1MdInfo->ptr))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    ASN1_STRING_free(pval);
    X509_ALGOR_free(x509Alg);

    return ret;
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

static SCOSSL_STATUS p_scossl_rsa_sigalg_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                                         _In_ const OSSL_PARAM params[], int operation,
                                                         _In_ const char *mdname)
{
    EVP_MD *md = NULL;

    if (!p_scossl_rsa_signverify_init(ctx, keyCtx, params, operation))
    {
        return SCOSSL_FAILURE;
    }

    // Sigalgs are not supported for PSS keys
    if (ctx->padding == RSA_PKCS1_PSS_PADDING)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return SCOSSL_FAILURE;
    }

    const OSSL_ITEM *mdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, RSA_PKCS1_PADDING, mdname, NULL, &md);
    if (mdInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return SCOSSL_FAILURE;
    }

    EVP_MD_free(ctx->md);
    ctx->md = md;
    ctx->mdInfo = mdInfo;
    ctx->padding = RSA_PKCS1_PADDING;
    ctx->allowMdUpdates = FALSE;
    ctx->isSigalg = TRUE;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rsa_sigalg_message_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                                                 _In_ const OSSL_PARAM params[], int operation,
                                                                 _In_ const char *mdname)
{
    if (!p_scossl_rsa_sigalg_signverify_init(ctx, keyCtx, params, operation, mdname))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->mdctx == NULL)
    {
        if ((ctx->mdctx = EVP_MD_CTX_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }
    }

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
    {
        EVP_MD_CTX_free(ctx->mdctx);
        ctx->mdctx = NULL;
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rsa_sigalg_signverify_message_update(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                                   _In_reads_bytes_(datalen) const unsigned char *data,
                                                                   size_t datalen)
{
    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowUpdate)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    ctx->allowOneshot = 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static SCOSSL_STATUS p_scossl_rsa_sigalg_sign_message_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                            _Out_writes_bytes_opt_(*siglen) unsigned char *sig,
                                                            _Out_ size_t *siglen, size_t sigsize)
{
    BYTE abDigest[EVP_MAX_MD_SIZE];
    unsigned int cbDigest = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowFinal)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FINAL_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    if (sig != NULL)
    {
        if (!EVP_DigestFinal_ex(ctx->mdctx, abDigest, &cbDigest))
        {
            return SCOSSL_FAILURE;
        }

        ctx->allowUpdate = FALSE;
        ctx->allowFinal = FALSE;
        ctx->allowOneshot = FALSE;
    }

    return p_scossl_rsa_sign_internal(ctx, sig, siglen, sigsize, abDigest, cbDigest);
}

static int p_scossl_rsa_sigalg_verify_message_final(_In_ SCOSSL_RSA_SIGN_CTX *ctx)
{
    BYTE abDigest[EVP_MAX_MD_SIZE];
    unsigned int cbDigest = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowFinal)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FINAL_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    if (!EVP_DigestFinal_ex(ctx->mdctx, abDigest, &cbDigest))
    {
        return SCOSSL_FAILURE;
    }

    ctx->allowUpdate = FALSE;
    ctx->allowFinal = FALSE;
    ctx->allowOneshot = FALSE;

    return p_scossl_rsa_verify_internal(ctx, ctx->pbSignature, ctx->cbSignature, abDigest, cbDigest);
}

static SCOSSL_STATUS p_scossl_rsa_sign(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                       _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                       _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowOneshot)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ONESHOT_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation == EVP_PKEY_OP_SIGNMSG)
    {
        if (sig == NULL)
        {
            return p_scossl_rsa_sigalg_sign_message_final(ctx, sig, siglen, sigsize);
        }

        return p_scossl_rsa_sigalg_signverify_message_update(ctx, tbs, tbslen) &&
               p_scossl_rsa_sigalg_sign_message_final(ctx, sig, siglen, sigsize);
    }

    return p_scossl_rsa_sign_internal(ctx, sig, siglen, sigsize, tbs, tbslen);
}

// Dispatch-facing verify function.
// If verifying a message, digests tbs and verifies the result.
// Otherwise, verifies tbs directly as a pre-computed digest.
static SCOSSL_STATUS p_scossl_rsa_verify(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                         _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                         _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (!ctx->allowOneshot)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ONESHOT_CALL_OUT_OF_ORDER);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation == EVP_PKEY_OP_VERIFYMSG)
    {
        OPENSSL_free(ctx->pbSignature);
        ctx->cbSignature = 0;
        if ((ctx->pbSignature = OPENSSL_memdup(sig, siglen)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }
        ctx->cbSignature = siglen;

        return p_scossl_rsa_sigalg_signverify_message_update(ctx, tbs, tbslen) &&
               p_scossl_rsa_sigalg_verify_message_final(ctx);
    }

    return p_scossl_rsa_verify_internal(ctx, sig, siglen, tbs, tbslen);
}

const OSSL_DISPATCH p_scossl_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_rsa_newctx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_rsa_dupctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_rsa_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_rsa_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_rsa_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_rsa_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_rsa_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_rsa_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))p_scossl_rsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))p_scossl_rsa_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_rsa_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))p_scossl_rsa_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))p_scossl_rsa_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_rsa_settable_ctx_md_params},
    {0, NULL}};

static const char **p_scossl_rsa_sigalg_query_key_types(void)
{
    static const char *keyTypes[] = { "RSA", NULL };
    return keyTypes;
}

#define IMPLEMENT_SCOSSL_RSA_SIGALG(md, MD)                                                                         \
    static SCOSSL_STATUS p_scossl_rsa_##md##_sign_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx,                            \
                                                       _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,                        \
                                                       _In_ const OSSL_PARAM params[])                              \
    {                                                                                                               \
        return p_scossl_rsa_sigalg_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGN, MD);                      \
    }                                                                                                               \
                                                                                                                    \
    static SCOSSL_STATUS p_scossl_rsa_##md##_verify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx,                          \
                                                         _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,                      \
                                                         _In_ const OSSL_PARAM params[])                            \
    {                                                                                                               \
        return p_scossl_rsa_sigalg_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFY, MD);                    \
    }                                                                                                               \
                                                                                                                    \
    static SCOSSL_STATUS p_scossl_rsa_##md##_sign_message_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx,                    \
                                                               _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,                \
                                                               _In_ const OSSL_PARAM params[])                      \
    {                                                                                                               \
        return p_scossl_rsa_sigalg_message_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGNMSG, MD);           \
    }                                                                                                               \
                                                                                                                    \
    static SCOSSL_STATUS p_scossl_rsa_##md##_verify_message_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx,                  \
                                                                 _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,              \
                                                                 _In_ const OSSL_PARAM params[])                    \
    {                                                                                                               \
        return p_scossl_rsa_sigalg_message_signverify_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFYMSG, MD);         \
    }                                                                                                               \
                                                                                                                    \
    const OSSL_DISPATCH p_scossl_rsa_##md##_signature_functions[] = {                                               \
        {OSSL_FUNC_SIGNATURE_NEWCTX,               (void (*)(void))p_scossl_rsa_newctx},                            \
        {OSSL_FUNC_SIGNATURE_DUPCTX,               (void (*)(void))p_scossl_rsa_dupctx},                            \
        {OSSL_FUNC_SIGNATURE_FREECTX,              (void (*)(void))p_scossl_rsa_freectx},                           \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT,            (void (*)(void))p_scossl_rsa_##md##_sign_init},                  \
        {OSSL_FUNC_SIGNATURE_SIGN,                 (void (*)(void))p_scossl_rsa_sign},                              \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,    (void (*)(void))p_scossl_rsa_##md##_sign_message_init},          \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,  (void (*)(void))p_scossl_rsa_sigalg_signverify_message_update},  \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,   (void (*)(void))p_scossl_rsa_sigalg_sign_message_final},         \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT,          (void (*)(void))p_scossl_rsa_##md##_verify_init},                \
        {OSSL_FUNC_SIGNATURE_VERIFY,               (void (*)(void))p_scossl_rsa_verify},                            \
        {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,  (void (*)(void))p_scossl_rsa_##md##_verify_message_init},        \
        {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,(void (*)(void))p_scossl_rsa_sigalg_signverify_message_update},  \
        {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, (void (*)(void))p_scossl_rsa_sigalg_verify_message_final},       \
        {OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,      (void (*)(void))p_scossl_rsa_sigalg_query_key_types},            \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,       (void (*)(void))p_scossl_rsa_get_ctx_params},                    \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,  (void (*)(void))p_scossl_rsa_gettable_ctx_params},               \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,       (void (*)(void))p_scossl_rsa_sigalg_set_ctx_params},             \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,  (void (*)(void))p_scossl_rsa_sigalg_settable_ctx_params},        \
        {0, NULL}};

IMPLEMENT_SCOSSL_RSA_SIGALG(sha1,       OSSL_DIGEST_NAME_SHA1)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha224,     OSSL_DIGEST_NAME_SHA2_224)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha256,     OSSL_DIGEST_NAME_SHA2_256)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha384,     OSSL_DIGEST_NAME_SHA2_384)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha512,     OSSL_DIGEST_NAME_SHA2_512)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha512_224, OSSL_DIGEST_NAME_SHA2_512_224)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha512_256, OSSL_DIGEST_NAME_SHA2_512_256)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha3_224,   OSSL_DIGEST_NAME_SHA3_224)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha3_256,   OSSL_DIGEST_NAME_SHA3_256)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha3_384,   OSSL_DIGEST_NAME_SHA3_384)
IMPLEMENT_SCOSSL_RSA_SIGALG(sha3_512,   OSSL_DIGEST_NAME_SHA3_512)

#ifdef __cplusplus
}
#endif