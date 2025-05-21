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

static const OSSL_PARAM p_scossl_hkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_hkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
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
        return 0;
    }

    return scossl_hkdf_derive(ctx->hkdfCtx, key, keylen);
}

const OSSL_PARAM *p_scossl_hkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_hkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hkdf_settable_ctx_param_types;
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

/*
 * TLS1.3KDF uses slight variations of the above,
 * they need to be present here.
 * Refer to RFC 8446 section 7 for specific details.
 */


#define HKDF_COMMON_SETTABLES                                       \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),     \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),           \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0)

/*
* Gettable context parameters that are common across HKDF and the TLS KDF.
*   OSSL_KDF_PARAM_KEY is not gettable because it is a secret value.
*/
#define HKDF_COMMON_GETTABLES                                       \
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),                   \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
    OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),          \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0)

static const OSSL_PARAM p_scossl_tls13kdf_gettable_ctx_param_types[] = {
    HKDF_COMMON_GETTABLES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_tls13kdf_settable_ctx_param_types[] = {
    HKDF_COMMON_SETTABLES,
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
    OSSL_PARAM_END};

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
SCOSSL_STATUS p_scossl_tls13_hkdf_expand(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    SYMCRYPT_HKDF_EXPANDED_KEY scExpandedKey;

    if (ctx->md == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Digest");
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Key");
        return SCOSSL_FAILURE;
    }

    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) {
        return SCOSSL_FAILURE;
    }

    SIZE_T labelLen = ctx->cbPrefix + ctx->cbLabel;
    if (labelLen > 255)
        return SCOSSL_FAILURE;

    SIZE_T totalLen = 2 + 1 + labelLen + 1 + ctx->cbData;
    if (totalLen > HKDF_MAXBUF) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
                         "Total size exceeds maximum buffer size allowed");
        return SCOSSL_FAILURE;
    }

    BYTE hkdflabel[HKDF_MAXBUF];
    size_t hkdflabellen = 0;

    // Output length (2 bytes) in big endian format
    hkdflabel[hkdflabellen++] = (BYTE)((keylen >> 8) & 0xFF); //high byte
    hkdflabel[hkdflabellen++] = (BYTE)(keylen & 0xFF);  //low byte

    // Label length
    hkdflabel[hkdflabellen++] = (BYTE)labelLen;

    // Label = prefix + label
    memcpy(hkdflabel + hkdflabellen, ctx->pbPrefix, ctx->cbPrefix);
    hkdflabellen += ctx->cbPrefix;
    memcpy(hkdflabel + hkdflabellen, ctx->pbLabel, ctx->cbLabel);
    hkdflabellen += ctx->cbLabel;

    // Context length
    hkdflabel[hkdflabellen++] = (BYTE)ctx->cbData;

    // Context
    if (ctx->cbData > 0) {
        memcpy(hkdflabel + hkdflabellen, ctx->pbData, ctx->cbData);
        hkdflabellen += ctx->cbData;
    }

    // Expand PRK
    scError = SymCryptHkdfPrkExpandKey(
        &scExpandedKey,
        symcryptHmacAlg,
        ctx->pbKey, ctx->cbKey);
    if (scError != SYMCRYPT_NO_ERROR)
        return SCOSSL_FAILURE;

    scError = SymCryptHkdfDerive(
        &scExpandedKey,
        hkdflabel, hkdflabellen,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR)
        return SCOSSL_FAILURE;

    return SCOSSL_SUCCESS;
}

static
SCOSSL_STATUS p_scossl_tls13kdf_generate_secret(SCOSSL_HKDF_CTX *ctx, PBYTE key, SIZE_T keylen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_MAC symcryptHmacAlg = NULL;
    BYTE *default_zeros = NULL;
    BYTE *empty_hash = NULL;
    BYTE *expanded_secret = NULL;
    EVP_MD_CTX *mctx = NULL;
    SIZE_T mdlen;
    BOOL salt_need_reset = FALSE;
    BOOL data_need_reset = FALSE;
    BOOL key_need_reset = FALSE;
    PBYTE saved_key = NULL;
    SIZE_T saved_keylen = 0;


    if (ctx == NULL || ctx->md == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR, "Missing Digest");
        return SCOSSL_FAILURE;
    }

    mdlen = EVP_MD_get_size(ctx->md);
    if (mdlen <= 0)
        return SCOSSL_FAILURE;

    default_zeros = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
    if (default_zeros == NULL)
        return SCOSSL_FAILURE;

    symcryptHmacAlg = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(ctx->md));
    if (symcryptHmacAlg == NULL) {
        scError = SCOSSL_FAILURE;
        goto cleanup;
    }

    if (ctx->pbKey == NULL) {
        ctx->pbKey = default_zeros;
        ctx->cbKey = mdlen;
        key_need_reset = TRUE;
    }

    if (ctx->pbSalt == NULL) {
        ctx->pbSalt = default_zeros;
        ctx->cbSalt = mdlen;
        salt_need_reset = TRUE;
    } else {
        empty_hash = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
        if (empty_hash == NULL) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL ||
            EVP_DigestInit_ex(mctx, ctx->md, NULL) <= 0 ||
            EVP_DigestFinal_ex(mctx, empty_hash, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        EVP_MD_CTX_free(mctx);

        ctx->pbData = empty_hash;
        ctx->cbData = mdlen;
        data_need_reset = TRUE;

        expanded_secret = OPENSSL_zalloc(EVP_MAX_MD_SIZE);
        if (expanded_secret == NULL) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        //scossl_tls13_hkdf_expand uses pbKey, so save original pbKey and set it as pbSalt
        saved_key = ctx->pbKey;
        saved_keylen = ctx->cbKey;
        ctx->pbKey = ctx->pbSalt;
        ctx->cbKey = ctx->cbSalt;

        if (SCOSSL_SUCCESS != p_scossl_tls13_hkdf_expand(ctx, expanded_secret, keylen)) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        //restore pbKey/cbKey
        ctx->pbKey = saved_key;
        ctx->cbKey = saved_keylen;

        scError = SymCryptHkdfExtractPrk(
            symcryptHmacAlg,
            ctx->pbKey, ctx->cbKey,
            expanded_secret, keylen,
            key, keylen);
        if (scError != SYMCRYPT_NO_ERROR) {
            scError = SCOSSL_FAILURE;
            goto cleanup;
        }
        scError = SCOSSL_SUCCESS;
        goto cleanup;
    }

    scError = SymCryptHkdfExtractPrk(
        symcryptHmacAlg,
        ctx->pbKey, ctx->cbKey,
        ctx->pbSalt, ctx->cbSalt,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR) {
        scError = SCOSSL_FAILURE;
        goto cleanup;
    }

    scError = SCOSSL_SUCCESS;

cleanup:
    // restore original values
    if (salt_need_reset == TRUE) {
        ctx->pbSalt = NULL;
        ctx->cbSalt = 0;
    }
    if (data_need_reset == TRUE) {
        ctx->pbData = NULL;
        ctx->cbData = 0;
    }
    if (key_need_reset == TRUE) {
        ctx->pbKey = NULL;
        ctx->cbKey = 0;
    }
    if (default_zeros != NULL) {
        OPENSSL_free(default_zeros);
        default_zeros = NULL;
    }
    if (empty_hash != NULL) {
        OPENSSL_free(empty_hash);
        empty_hash = NULL;
    }
    if (expanded_secret != NULL) {
        OPENSSL_free(expanded_secret);
        expanded_secret = NULL;
    }

    return scError;
}


SCOSSL_STATUS p_scossl_tls13kdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
                                _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx == NULL || ctx->hkdfCtx == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Ctx/hkdfCtx is NULL");
        return SCOSSL_FAILURE;
    }
    
    if (!p_scossl_tls13kdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }
    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }


    switch (ctx->hkdfCtx->mode)
    {
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        scError = p_scossl_tls13kdf_generate_secret(ctx->hkdfCtx, key, keylen);
        if (scError != SCOSSL_SUCCESS)
        {
            return SCOSSL_FAILURE;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        scError = p_scossl_tls13_hkdf_expand(ctx->hkdfCtx, key, keylen);
        if (scError != SCOSSL_SUCCESS)
        {
           return SCOSSL_FAILURE;
        }
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Invalid Mode: %d", ctx->hkdfCtx->mode);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
   
}




const OSSL_PARAM *p_scossl_tls13kdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls13kdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_tls13kdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls13kdf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_tls13kdf_get_ctx_params(_In_ SCOSSL_PROV_HKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    if (!p_scossl_hkdf_get_ctx_params(ctx, params))
        return SCOSSL_FAILURE;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_tls13kdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (!p_scossl_hkdf_set_ctx_params(ctx, params))
        return SCOSSL_FAILURE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX)) != NULL)
    {
        PBYTE pbPrefix = NULL;
        SIZE_T cbPrefix = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbPrefix, 0, &cbPrefix))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbPrefix, ctx->hkdfCtx->cbPrefix);
        ctx->hkdfCtx->pbPrefix = pbPrefix;
        ctx->hkdfCtx->cbPrefix = cbPrefix;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL)) != NULL)
    {
        PBYTE pbLabel = NULL;
        SIZE_T cbLabel = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbLabel, 0, &cbLabel))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbLabel, ctx->hkdfCtx->cbLabel);
        ctx->hkdfCtx->pbLabel = pbLabel;
        ctx->hkdfCtx->cbLabel = cbLabel;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA)) != NULL)
    {
        PBYTE pbData = NULL;
        SIZE_T cbData = 0;

        if (p->data_size > 0 &&
            !OSSL_PARAM_get_octet_string(p, (void **)&pbData, 0, &cbData))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        OPENSSL_clear_free(ctx->hkdfCtx->pbData, ctx->hkdfCtx->cbData);
        ctx->hkdfCtx->pbData= pbData;
        ctx->hkdfCtx->cbData = cbData;
    }
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_tls13kdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_hkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_hkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_hkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_hkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_tls13kdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_tls13kdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif