//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include "p_scossl_rsa_signature.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_RSA_MAX_SIGNATURE_LEN (SYMCRYPT_RSAKEY_MAX_BITSIZE_MODULUS / 8)

static const OSSL_PARAM p_scossl_rsa_sigalg_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_rsa_sigalg_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                                         _In_ const OSSL_PARAM params[], int operation,
                                                         _In_ const char *mdname)
{
    EVP_MD *md = NULL;
    const OSSL_ITEM *mdInfo = NULL;

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

    mdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, RSA_PKCS1_PADDING, mdname, NULL, &md);
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

static SCOSSL_STATUS p_scossl_rsa_sigalg_signverify_message_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
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
                                                                   _In_reads_bytes_(inlen) const unsigned char *in,
                                                                   size_t inlen)
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

    ctx->allowOneshot = FALSE;

    return EVP_DigestUpdate(ctx->mdctx, in, inlen);
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
\
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

static SCOSSL_STATUS p_scossl_rsa_sigalg_sign(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                              _Out_writes_bytes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                              _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
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

        if (p_scossl_rsa_sigalg_signverify_message_update(ctx, tbs, tbslen) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }

        return p_scossl_rsa_sigalg_sign_message_final(ctx, sig, siglen, sigsize);
    }

    return p_scossl_rsa_sign_internal(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static SCOSSL_STATUS p_scossl_rsa_sigalg_verify(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                                _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                                _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
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

        if (siglen == 0 ||
            siglen > SCOSSL_RSA_MAX_SIGNATURE_LEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE);
            return SCOSSL_FAILURE;
        }

        if ((ctx->pbSignature = OPENSSL_memdup(sig, siglen)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }
        ctx->cbSignature = siglen;

        if (p_scossl_rsa_sigalg_signverify_message_update(ctx, tbs, tbslen) != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }

        return p_scossl_rsa_sigalg_verify_message_final(ctx);
    }

    return p_scossl_rsa_verify_internal(ctx, sig, siglen, tbs, tbslen);
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
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (ctx->operation == EVP_PKEY_OP_VERIFYMSG)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE)) != NULL)
        {
            PCBYTE pcbSignature = NULL;
            SIZE_T cbSignature = 0;

            OPENSSL_free(ctx->pbSignature);
            ctx->pbSignature = NULL;
            ctx->cbSignature = 0;

            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pcbSignature, &cbSignature))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            if (cbSignature == 0 ||
                cbSignature > SCOSSL_RSA_MAX_SIGNATURE_LEN)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE);
                return SCOSSL_FAILURE;
            }

            if ((ctx->pbSignature = OPENSSL_memdup(pcbSignature, cbSignature)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return SCOSSL_FAILURE;
            }
            ctx->cbSignature = cbSignature;
        }
    }

    return SCOSSL_SUCCESS;
}

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
        return p_scossl_rsa_sigalg_signverify_message_init(ctx, keyCtx, params, EVP_PKEY_OP_SIGNMSG, MD);           \
    }                                                                                                               \
                                                                                                                    \
    static SCOSSL_STATUS p_scossl_rsa_##md##_verify_message_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx,                  \
                                                                 _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,              \
                                                                 _In_ const OSSL_PARAM params[])                    \
    {                                                                                                               \
        return p_scossl_rsa_sigalg_signverify_message_init(ctx, keyCtx, params, EVP_PKEY_OP_VERIFYMSG, MD);         \
    }                                                                                                               \
                                                                                                                    \
    const OSSL_DISPATCH p_scossl_rsa_##md##_signature_functions[] = {                                               \
        {OSSL_FUNC_SIGNATURE_NEWCTX,               (void (*)(void))p_scossl_rsa_newctx},                            \
        {OSSL_FUNC_SIGNATURE_DUPCTX,               (void (*)(void))p_scossl_rsa_dupctx},                            \
        {OSSL_FUNC_SIGNATURE_FREECTX,              (void (*)(void))p_scossl_rsa_freectx},                           \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT,            (void (*)(void))p_scossl_rsa_##md##_sign_init},                  \
        {OSSL_FUNC_SIGNATURE_SIGN,                 (void (*)(void))p_scossl_rsa_sigalg_sign},                       \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,    (void (*)(void))p_scossl_rsa_##md##_sign_message_init},          \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,  (void (*)(void))p_scossl_rsa_sigalg_signverify_message_update},  \
        {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,   (void (*)(void))p_scossl_rsa_sigalg_sign_message_final},         \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT,          (void (*)(void))p_scossl_rsa_##md##_verify_init},                \
        {OSSL_FUNC_SIGNATURE_VERIFY,               (void (*)(void))p_scossl_rsa_sigalg_verify},                     \
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
