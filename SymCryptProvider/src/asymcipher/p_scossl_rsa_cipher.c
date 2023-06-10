//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_rsa.h"
#include "p_scossl_base.h"
#include "p_scossl_rsa.h"

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_DEFAULT_OAEP_DIGEST OSSL_DIGEST_NAME_SHA1

typedef struct
{
    OSSL_LIB_CTX *libctx;

    SCOSSL_RSA_KEY_CTX *keyCtx;
    UINT padding;

    // OAEP Parameters
    const OSSL_ITEM *oaepMdInfo;
    const OSSL_ITEM *mgf1MdInfo; // Informational, must match oaepMdInfo if set
    PBYTE pbLabel;
    SIZE_T cbLabel;
} SCOSSL_RSA_CIPHER_CTX;

static const OSSL_PARAM p_scossl_rsa_cipher_gettable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_cipher_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_END};

static OSSL_ITEM p_scossl_rsa_cipher_padding_modes[] = {
    {RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE},
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
    {RSA_PKCS1_OAEP_PADDING, OSSL_PKEY_RSA_PAD_MODE_OAEP},
    {0, NULL}};

SCOSSL_STATUS p_scossl_rsa_cipher_set_ctx_params(_Inout_ SCOSSL_RSA_CIPHER_CTX *ctx, const _In_ OSSL_PARAM params[]);

/* Context management */
SCOSSL_RSA_CIPHER_CTX *p_scossl_rsa_cipher_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_RSA_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_CIPHER_CTX));
    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

void p_scossl_rsa_cipher_freectx(_Inout_ SCOSSL_RSA_CIPHER_CTX *ctx)
{
    if (ctx != NULL)
    {
        OPENSSL_free(ctx->pbLabel);
    }
    OPENSSL_free(ctx);
}

SCOSSL_RSA_CIPHER_CTX *p_scossl_rsa_cipher_dupctx(_Inout_ SCOSSL_RSA_CIPHER_CTX *ctx)
{
    SCOSSL_RSA_CIPHER_CTX *copy_ctx = OPENSSL_malloc(sizeof(SCOSSL_RSA_CIPHER_CTX));
    if (copy_ctx != NULL)
    {
        memcpy(copy_ctx, ctx, sizeof(SCOSSL_RSA_CIPHER_CTX));
    }

    return copy_ctx;
}

SCOSSL_STATUS p_scossl_rsa_cipher_init(_Inout_ SCOSSL_RSA_CIPHER_CTX *ctx, _In_ SCOSSL_RSA_KEY_CTX *keyCtx,
                                       const _In_ OSSL_PARAM params[])
{
    ctx->keyCtx = keyCtx;
    ctx->padding = RSA_PKCS1_PADDING;

    return p_scossl_rsa_cipher_set_ctx_params(ctx, params);
}

SCOSSL_STATUS p_scossl_rsa_cipher_encrypt(_In_ SCOSSL_RSA_CIPHER_CTX *ctx,
                                          _Out_writes_bytes_(*outlen) unsigned char *out, _Out_ size_t *outlen, size_t outsize,
                                          _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{
    INT32 cbResult;
    SCOSSL_STATUS ret;

    // Default to SHA1 for OAEP. Update md in context so this is
    // reflected in getparam
    if (ctx->oaepMdInfo == NULL)
    {
        ctx->oaepMdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, SCOSSL_DEFAULT_OAEP_DIGEST, NULL, NULL);

        if (ctx->oaepMdInfo == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    ret = scossl_rsa_encrypt(ctx->keyCtx, ctx->padding, ctx->oaepMdInfo->id,
                             ctx->pbLabel, ctx->cbLabel,
                             in, inlen,
                             out, &cbResult, outsize);
    *outlen = ret ? (SIZE_T)cbResult : 0;

    return ret;
}

SCOSSL_STATUS p_scossl_rsa_cipher_decrypt(_In_ SCOSSL_RSA_CIPHER_CTX *ctx,
                                          _Out_writes_bytes_(*outlen) unsigned char *out, _Out_ size_t *outlen, size_t outsize,
                                          _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{
    INT32 cbResult;
    SCOSSL_STATUS ret;

    // Default to SHA1 for OAEP. Update md in context so this is
    // reflected in getparam
    if (ctx->oaepMdInfo == NULL)
    {
        ctx->oaepMdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, SCOSSL_DEFAULT_OAEP_DIGEST, NULL, NULL);
        if (ctx->oaepMdInfo == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }
    }

    ret = scossl_rsa_decrypt(ctx->keyCtx, ctx->padding, ctx->oaepMdInfo->id,
                             ctx->pbLabel, ctx->cbLabel,
                             in, inlen,
                             out, &cbResult, outsize);
    *outlen = ret ? (SIZE_T)cbResult : 0;

    return ret;
}

/* Asymmetric Cipher parameters */
SCOSSL_STATUS p_scossl_rsa_cipher_get_ctx_params(_In_ SCOSSL_RSA_CIPHER_CTX *ctx, _Out_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        // Padding mode may be retrieved as legacy NID or string
        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->padding))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            int i = 0;
            while (p_scossl_rsa_cipher_padding_modes[i].id != 0 &&
                   ctx->padding != p_scossl_rsa_cipher_padding_modes[i].id)
            {
                i++;
            }

            if (!OSSL_PARAM_set_utf8_string(p, p_scossl_rsa_cipher_padding_modes[i].ptr))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->oaepMdInfo == NULL ? "" : ctx->oaepMdInfo->ptr))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mgf1MdInfo == NULL ? "" : ctx->mgf1MdInfo->ptr))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_rsa_cipher_gettable_ctx_params(ossl_unused void *provctx)
{
    return p_scossl_rsa_cipher_gettable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_rsa_cipher_set_ctx_params(_Inout_ SCOSSL_RSA_CIPHER_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const OSSL_PARAM *param_propq;
    const char *mdName, *mdProps;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        // Padding mode may be passed as legacy NID or string, and is
        // checked against the padding modes the ScOSSL provider supports
        int i = 0;
        UINT padding;

        switch (p->data_type)
        {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_uint(p, &padding))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }

            while (p_scossl_rsa_cipher_padding_modes[i].id != 0 &&
                   padding != p_scossl_rsa_cipher_padding_modes[i].id)
            {
                i++;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            while (p_scossl_rsa_cipher_padding_modes[i].id != 0 &&
                   OPENSSL_strcasecmp(p->data, p_scossl_rsa_cipher_padding_modes[i].ptr) != 0)
            {
                i++;
            }
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        padding = p_scossl_rsa_cipher_padding_modes[i].id;

        if (padding == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return SCOSSL_FAILURE;
        }

        ctx->padding = padding;
    }

    //
    // OAEP parameters
    //
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL)
    {
        const OSSL_ITEM *oaepMdInfo;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        param_propq = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (param_propq != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // ScOSSL does not support distinct MD and MGF1 MD
        oaepMdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, mdName, mdProps, NULL);
        if (oaepMdInfo == NULL ||
            (ctx->mgf1MdInfo != NULL && oaepMdInfo->id != ctx->mgf1MdInfo->id))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        ctx->oaepMdInfo = oaepMdInfo;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const OSSL_ITEM *mgf1MdInfo;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        param_propq = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (param_propq != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // ScOSSL does not support distinct MD and MGF1 MD
        mgf1MdInfo = p_scossl_rsa_get_supported_md(ctx->libctx, mdName, mdProps, NULL);
        if (mgf1MdInfo == NULL ||
            (ctx->oaepMdInfo != NULL && mgf1MdInfo->id != ctx->oaepMdInfo->id))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return SCOSSL_FAILURE;
        }

        ctx->mgf1MdInfo = mgf1MdInfo;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL)
    {
        void *pbLabel = NULL;
        size_t cbLabel;
        if (!OSSL_PARAM_get_octet_string(p, &pbLabel, 0, &cbLabel))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_free(ctx->pbLabel);
        ctx->pbLabel = (PBYTE)pbLabel;
        ctx->cbLabel = cbLabel;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_rsa_cipher_settable_ctx_params(ossl_unused void *provctx)
{
    return p_scossl_rsa_cipher_settable_ctx_param_types;
}

const OSSL_DISPATCH p_scossl_rsa_cipher_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))p_scossl_rsa_cipher_newctx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))p_scossl_rsa_cipher_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))p_scossl_rsa_cipher_freectx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))p_scossl_rsa_cipher_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))p_scossl_rsa_cipher_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))p_scossl_rsa_cipher_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))p_scossl_rsa_cipher_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_cipher_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_cipher_gettable_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))p_scossl_rsa_cipher_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rsa_cipher_settable_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif