//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "kdf/p_scossl_hkdf.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_MODE_EXTRACT_AND_EXPAND "EXTRACT_AND_EXPAND"
#define HKDF_MODE_EXTRACT_ONLY       "EXTRACT_ONLY"
#define HKDF_MODE_EXPAND_ONLY        "EXPAND_ONLY"

#define HKDF_COMMON_SETTABLES                                       \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),     \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),           \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0)

static const OSSL_PARAM p_scossl_hkdf_gettable_ctx_param_types[] = {
    HKDF_COMMON_SETTABLES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_hkdf_settable_ctx_param_types[] = {
    HKDF_COMMON_SETTABLES,
    OSSL_PARAM_END};

/*
 * TLS1.3KDF uses slight variations of the above,
 * they need to be present here.
 * Refer to RFC 8446 section 7 for specific details.
 */
static const OSSL_PARAM p_scossl_tls13kdf_settable_ctx_param_types[] = {
    HKDF_COMMON_SETTABLES,
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
    OSSL_PARAM_END};

SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_HKDF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_HKDF_CTX));
    if (ctx != NULL)
    {
        if ((ctx->hkdfCtx = scossl_hkdf_newctx()) == NULL)
        {
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

void p_scossl_hkdf_freectx(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    if (ctx != NULL)
    {
        EVP_MD_free(ctx->hkdfCtx->md);
        scossl_hkdf_freectx(ctx->hkdfCtx);
    }

    OPENSSL_free(ctx);
}

SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_dupctx(_In_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    SCOSSL_PROV_HKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_HKDF_CTX));
    if (copyCtx != NULL)
    {
        if ((copyCtx->hkdfCtx = scossl_hkdf_dupctx(ctx->hkdfCtx)) == NULL ||
            (ctx->hkdfCtx->md != NULL && !EVP_MD_up_ref(ctx->hkdfCtx->md)))
        {
            scossl_hkdf_freectx(copyCtx->hkdfCtx);
            OPENSSL_free(copyCtx);
            return NULL;
        }

        copyCtx->libctx = ctx->libctx;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_hkdf_reset(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx)
{
    EVP_MD_free(ctx->hkdfCtx->md);
    return scossl_hkdf_reset(ctx->hkdfCtx);
}

const OSSL_PARAM *p_scossl_hkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_hkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_settable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_tls13kdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls13kdf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_hkdf_get_ctx_params(_In_ SCOSSL_PROV_HKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
    {
        SIZE_T cbResult;
        if (ctx->hkdfCtx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
        {
            if (ctx->hkdfCtx->md == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
                return SCOSSL_FAILURE;
            }

            cbResult = EVP_MD_get_size(ctx->hkdfCtx->md);
        }
        else
        {
            cbResult = SIZE_MAX;
        }

        if (!OSSL_PARAM_set_size_t(p, cbResult))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_MODE)) != NULL)
    {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            const char *mode = NULL;
            switch (ctx->hkdfCtx->mode)
            {
            case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
                mode = HKDF_MODE_EXTRACT_AND_EXPAND;
                break;
            case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
                mode = HKDF_MODE_EXTRACT_ONLY;
                break;
            case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
                mode = HKDF_MODE_EXPAND_ONLY;
                break;
            }

            if (mode == NULL ||
                !OSSL_PARAM_set_utf8_string(p, mode))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return SCOSSL_FAILURE;
            }
        }
        else if (!OSSL_PARAM_set_int(p, ctx->hkdfCtx->mode))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->hkdfCtx->md == NULL ? "" : EVP_MD_get0_name(ctx->hkdfCtx->md)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SALT)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->pbSalt, ctx->hkdfCtx->cbSalt))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->pbKey, ctx->hkdfCtx->cbKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_INFO)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->hkdfCtx->info, ctx->hkdfCtx->cbInfo))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_hkdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    PCBYTE pbInfo;
    SIZE_T cbInfo;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL)
    {
        int mode = -1;
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXTRACT_AND_EXPAND) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            }
            else if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXTRACT_ONLY) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            }
            else if (OPENSSL_strcasecmp(p->data, HKDF_MODE_EXPAND_ONLY) == 0)
            {
                mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            }
        }
        else if (!OSSL_PARAM_get_int(p, &mode))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (mode < EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND || mode > EVP_KDF_HKDF_MODE_EXPAND_ONLY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return SCOSSL_FAILURE;
        }

        ctx->hkdfCtx->mode = mode;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        const OSSL_PARAM *param_propq;
        const char *mdName, *mdProps;
        EVP_MD *md;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        mdProps = NULL;
        param_propq = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
        if (param_propq != NULL &&
            !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        md = EVP_MD_fetch(ctx->libctx, mdName, mdProps);

        if (md == NULL ||
            !scossl_is_md_supported(EVP_MD_type(md)))
        {
            EVP_MD_free(md);
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        EVP_MD_free(ctx->hkdfCtx->md);
        ctx->hkdfCtx->md = md;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        PBYTE pbSalt = NULL;
        SIZE_T cbSalt = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbSalt, 0, &cbSalt))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbSalt, ctx->hkdfCtx->cbSalt);
        ctx->hkdfCtx->pbSalt = pbSalt;
        ctx->hkdfCtx->cbSalt = cbSalt;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
    {
        PBYTE pbKey = NULL;
        SIZE_T cbKey = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbKey, 0, &cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbKey, ctx->hkdfCtx->cbKey);
        ctx->hkdfCtx->pbKey = pbKey;
        ctx->hkdfCtx->cbKey = cbKey;
    }

    // Parameters may contain multiple info params that must all be processed
    for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
         p != NULL;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO))
    {
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbInfo, &cbInfo))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (!scossl_hkdf_append_info(ctx->hkdfCtx, pbInfo, cbInfo))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static
SCOSSL_STATUS p_scossl_tls13kdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (!p_scossl_hkdf_set_ctx_params(ctx, params))
        return SCOSSL_FAILURE;

    if (ctx->hkdfCtx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX)) != NULL)
    {
        OPENSSL_free(ctx->hkdfCtx->pbPrefix);
        ctx->hkdfCtx->pbPrefix = NULL;
        ctx->hkdfCtx->cbPrefix = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->hkdfCtx->pbPrefix, 0, &ctx->hkdfCtx->cbPrefix))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL)) != NULL)
    {
        OPENSSL_free(ctx->hkdfCtx->pbLabel);
        ctx->hkdfCtx->pbLabel = NULL;
        ctx->hkdfCtx->cbLabel = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->hkdfCtx->pbLabel, 0, &ctx->hkdfCtx->cbLabel))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA)) != NULL)
    {
        OPENSSL_clear_free(ctx->hkdfCtx->pbData, ctx->hkdfCtx->cbData);
        ctx->hkdfCtx->pbData = NULL;
        ctx->hkdfCtx->cbData = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->hkdfCtx->pbData, 0, &ctx->hkdfCtx->cbData))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_hkdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
                                   _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                   _In_ const OSSL_PARAM params[])
{
    if (!p_scossl_hkdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->hkdfCtx->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return SCOSSL_FAILURE;
    }

    return scossl_hkdf_derive(ctx->hkdfCtx, key, keylen);
}

/*
 * HKDF-Expand-Label is a TLS 1.3-specific key derivation function defined in RFC 8446, Section 7.1.
 * It wraps the standard HKDF-Expand function with a structured label format to ensure domain separation.
 *
 * The structure of the HkdfLabel is as follows:
 *
 * struct {
 *     uint16 length;             // Desired length of the output keying material (2 bytes, big-endian)
 *     opaque label<7..255>;      // A variable-length label prefixed with "tls13 " followed by a custom label
 *     opaque context<0..255>;    // A variable-length context (e.g., handshake transcript hash)
 * } HkdfLabel;
 *
 */
static
SCOSSL_STATUS p_scossl_tls13_hkdf_expand(_In_ SCOSSL_HKDF_CTX *ctx, 
                                         _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;
    SIZE_T labelLen = 0;
    SIZE_T totalLen = 0;
        
    BYTE hkdflabel[HKDF_MAXBUF];
    SIZE_T hkdflabellen = 0;
    
    if (ctx->md == NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) 
    {
        return SCOSSL_FAILURE;
    }

    labelLen = ctx->cbPrefix + ctx->cbLabel;
    
    // Ensure this value does not exceed 0xFF, as only the least-significant byte is copied into hkdflabel.
    // If the value exceeds 0xFF, it will overflow and corrupt the label encoding.
    if (labelLen > 0xFF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return SCOSSL_FAILURE;
    }
    
    // 2 bytes for output length, 1 byte for label length, and 1 byte for context length
    totalLen = 2 + 1 + labelLen + 1 + ctx->cbData;
    if (totalLen > HKDF_MAXBUF) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return SCOSSL_FAILURE;
    }

    // Output length (2 bytes) in big endian format
    SYMCRYPT_STORE_MSBFIRST16(&hkdflabel[hkdflabellen], keylen);
    hkdflabellen += 2;

    // Label length
    hkdflabel[hkdflabellen++] = (BYTE)labelLen;

    // Label = prefix + label
    memcpy(hkdflabel + hkdflabellen, ctx->pbPrefix, ctx->cbPrefix);
    hkdflabellen += ctx->cbPrefix;
    memcpy(hkdflabel + hkdflabellen, ctx->pbLabel, ctx->cbLabel);
    hkdflabellen += ctx->cbLabel;
    
    if (ctx->cbData > 0xFF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        return SCOSSL_FAILURE;
    }
    // Context length
    hkdflabel[hkdflabellen++] = (BYTE)ctx->cbData;

    // Context
    if (ctx->cbData > 0) 
    {
        memcpy(hkdflabel + hkdflabellen, ctx->pbData, ctx->cbData);
        hkdflabellen += ctx->cbData;
    }

    // Expand PRK
    scError = SymCryptHkdfPrkExpandKey(
        &scExpandedKey,
        symcryptHmacAlg,
        ctx->pbKey, ctx->cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptHkdfPrkExpandKey failed", scError);
        return SCOSSL_FAILURE;
    }
    scError = SymCryptHkdfDerive(
        &scExpandedKey,
        hkdflabel, hkdflabellen,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptHkdfDerive failed", scError);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

static
SCOSSL_STATUS p_scossl_tls13kdf_generate_secret(_In_ SCOSSL_HKDF_CTX *ctx, 
                                                _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    BYTE *default_zeros = NULL;
    BYTE empty_hash[EVP_MAX_MD_SIZE]; 
    BYTE expanded_secret[EVP_MAX_MD_SIZE];
    SCOSSL_HKDF_CTX *dupCtx;
    SIZE_T mdlen = 0;
    PBYTE pbSavedKey;
    SIZE_T cbSavedKey = 0;
    
    if (ctx == NULL || ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return SCOSSL_FAILURE;
    }
    
    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) 
    {
        return SCOSSL_FAILURE;
    }
 
    mdlen = EVP_MD_get_size(ctx->md);
    if (mdlen <= 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        return SCOSSL_FAILURE;
    }

    // duplicate a ctx to use as pass-in parameter for Symcrypt
    if ((dupCtx = OPENSSL_memdup(ctx, sizeof(*ctx))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }
    
    default_zeros = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
    if (default_zeros == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
   
    if (dupCtx->pbKey == NULL) 
    {
        dupCtx->pbKey = default_zeros;
        dupCtx->cbKey = mdlen;
    }

    if (dupCtx->pbSalt == NULL) 
    {
        dupCtx->pbSalt = default_zeros;
        dupCtx->cbSalt = mdlen;
    }
    else
    {
        // get empty hash value
        unsigned int tmplen = 0;
        if (!EVP_Digest(NULL, 0, empty_hash, &tmplen, dupCtx->md, NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        dupCtx->pbData = empty_hash;
        dupCtx->cbData = tmplen;

        //scossl_tls13_hkdf_expand uses pbKey, so set it as pbSalt
        pbSavedKey = dupCtx->pbKey;
        cbSavedKey = dupCtx->cbKey;
        dupCtx->pbKey = dupCtx->pbSalt;
        dupCtx->cbKey = dupCtx->cbSalt;

        if (SCOSSL_SUCCESS != p_scossl_tls13_hkdf_expand(dupCtx, expanded_secret, keylen)) 
        {
            goto cleanup;
        }
        //restore pbKey/cbKey
        dupCtx->pbKey = pbSavedKey;
        dupCtx->cbKey = cbSavedKey;

        dupCtx->pbSalt = expanded_secret;
        dupCtx->cbSalt = keylen;
    }

    scError = SymCryptHkdfExtractPrk(
        symcryptHmacAlg,
        dupCtx->pbKey, dupCtx->cbKey,
        dupCtx->pbSalt, dupCtx->cbSalt,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR) 
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptHkdfExtractPrk failed", scError);
        goto cleanup;
    }
    status = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(dupCtx);
    OPENSSL_free(default_zeros);
    return status;
}

static
SCOSSL_STATUS p_scossl_tls13kdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
                                       _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                       _In_ const OSSL_PARAM params[])
{
    if (ctx == NULL || ctx->hkdfCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }
    
    if (!p_scossl_tls13kdf_set_ctx_params(ctx, params))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return SCOSSL_FAILURE;
    }

    switch (ctx->hkdfCtx->mode)
    {
        case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
            return p_scossl_tls13kdf_generate_secret(ctx->hkdfCtx, key, keylen);
        case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
            return p_scossl_tls13_hkdf_expand(ctx->hkdfCtx, key, keylen);
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
    }
}

const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_hkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_hkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_hkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_hkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_hkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_set_ctx_params},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_tls13kdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_hkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_hkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_hkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_hkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_tls13kdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_hkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif