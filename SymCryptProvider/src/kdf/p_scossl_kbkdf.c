//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "mac/p_scossl_kmac.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MAC_TYPE_HMAC (1)
#define SCOSSL_MAC_TYPE_CMAC (2)
#define SCOSSL_MAC_TYPE_KMAC (3)

#define OSSL_KDF_PARAM_KBKDF_LABEL OSSL_KDF_PARAM_SALT
#define OSSL_KDF_PARAM_KBKDF_CONTEXT OSSL_KDF_PARAM_INFO

typedef struct
{
    OSSL_LIB_CTX *libCtx;

    PBYTE pbKey;
    SIZE_T cbKey;
    PBYTE pbContext;
    SIZE_T cbContext;
    PBYTE pbLabel;
    SIZE_T cbLabel;
    PCSYMCRYPT_MAC pMac;

    UINT macType;
    SIZE_T cbCmacKey;
    const SCOSSL_KMAC_EXTENSIONS *pMacEx;
} SCOSSL_PROV_KBKDF_CTX;

static const OSSL_PARAM p_scossl_kbkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_kbkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KBKDF_CONTEXT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KBKDF_LABEL, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
    // Below parameters aren't configurable. The provider will reject anything that
    // does not match the fixed behavior of SymCrypt.
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, NULL),
    OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, NULL),
#if OPENSSL_VERSION_MAJOR >= 3 && OPENSSL_VERSION_MINOR > 0
    OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_R, NULL),
#endif
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_kbkdf_set_ctx_params(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_PROV_KBKDF_CTX *p_scossl_kbkdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_KBKDF_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_KBKDF_CTX));
    if (ctx != NULL)
    {
        ctx->libCtx = provctx->libctx;
    }

    return ctx;
}

static void p_scossl_kbkdf_freectx(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_clear_free(ctx->pbLabel, ctx->cbLabel);
    OPENSSL_clear_free(ctx->pbContext, ctx->cbContext);
    OPENSSL_free(ctx);
}

static SCOSSL_PROV_KBKDF_CTX *p_scossl_kbkdf_dupctx(_In_ SCOSSL_PROV_KBKDF_CTX *ctx)
{
    SCOSSL_PROV_KBKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_KBKDF_CTX));
    if (copyCtx != NULL)
    {
        *copyCtx = *ctx;

        copyCtx->pbKey = OPENSSL_memdup(ctx->pbKey, ctx->cbKey);
        copyCtx->pbLabel = OPENSSL_memdup(ctx->pbLabel, ctx->cbLabel);
        copyCtx->pbContext = OPENSSL_memdup(ctx->pbContext, ctx->cbContext);

        if ((ctx->pbKey != NULL     && copyCtx->pbKey == NULL) ||
            (ctx->pbLabel != NULL   && copyCtx->pbLabel == NULL) ||
            (ctx->pbContext != NULL && copyCtx->pbContext == NULL))
        {
            p_scossl_kbkdf_freectx(copyCtx);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_kbkdf_reset(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx)
{
    OSSL_LIB_CTX *libCtx = ctx->libCtx;

    OPENSSL_clear_free(ctx->pbKey, ctx->cbKey);
    OPENSSL_clear_free(ctx->pbLabel, ctx->cbLabel);
    OPENSSL_clear_free(ctx->pbContext, ctx->cbContext);
    OPENSSL_cleanse(ctx, sizeof(SCOSSL_PROV_KBKDF_CTX));

    ctx->libCtx = libCtx;

    return SCOSSL_SUCCESS;
}

// KMAC KBKDF is a special case. Pass the context as the input and label as the customization string.
static SCOSSL_STATUS p_scossl_kbkdf_kmac_derive(_In_ SCOSSL_PROV_KBKDF_CTX *ctx,
                                                _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen)
{
    SCOSSL_KMAC_EXPANDED_KEY expandedKey;
    SCOSSL_KMAC_STATE macState;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->pMacEx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MAC);
        goto cleanup;
    }

    if (ctx->pbLabel != NULL)
    {
        scError = ctx->pMacEx->expandKeyExFunc(&expandedKey, ctx->pbKey, ctx->cbKey, ctx->pbLabel, ctx->cbLabel);
    }
    else
    {
        scError = ctx->pMac->expandKeyFunc(&expandedKey, ctx->pbKey, ctx->cbKey);
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_PROV_KBKDF_KMAC_DERIVE, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptKmacXXXExpandKey failed", scError);
        goto cleanup;
    }

    ctx->pMac->initFunc(&macState, &expandedKey);
    ctx->pMac->appendFunc(&macState, ctx->pbContext, ctx->cbContext);
    ctx->pMacEx->resultExFunc(&macState, key, keylen);

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_cleanse(&expandedKey, sizeof(SCOSSL_KMAC_EXPANDED_KEY));
    OPENSSL_cleanse(&macState, sizeof(SCOSSL_KMAC_STATE));

    return ret;
}

static SCOSSL_STATUS p_scossl_kbkdf_derive(_In_ SCOSSL_PROV_KBKDF_CTX *ctx,
                                           _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                           _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (!p_scossl_kbkdf_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->pMac == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MAC);
        return SCOSSL_FAILURE;
    }

    if (ctx->pbKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    if (keylen == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return SCOSSL_FAILURE;
    }

    if (ctx->macType == SCOSSL_MAC_TYPE_KMAC)
    {
        return p_scossl_kbkdf_kmac_derive(ctx, key, keylen);
    }

    scError = SymCryptSp800_108(
        ctx->pMac,
        ctx->pbKey, ctx->cbKey,
        ctx->pbLabel, ctx->cbLabel,
        ctx->pbContext, ctx->cbContext,
        key, keylen);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_PROV_KBKDF_KMAC_DERIVE, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptSp800_108 failed", scError);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_kbkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kbkdf_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_kbkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kbkdf_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_kbkdf_get_ctx_params(ossl_unused void *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, SIZE_MAX))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kbkdf_get_octet_string(_In_ const OSSL_PARAM *p, _Out_writes_bytes_(*cbData) PBYTE *ppbData, _Out_ SIZE_T *pcbData)
{
    if (p->data == NULL || p->data_size == 0)
    {
        return SCOSSL_SUCCESS;
    }

    OPENSSL_clear_free(*ppbData, *pcbData);

    *ppbData = NULL;
    return OSSL_PARAM_get_octet_string(p, (void **) ppbData, 0, pcbData);
}

static SCOSSL_STATUS p_scossl_kbkdf_set_ctx_params(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    const char *propq = NULL;
    EVP_MD *md = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_MAC *mac = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
    {
        if (!p_scossl_kbkdf_get_octet_string(p, &ctx->pbKey, &ctx->cbKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        // Check that key size matches expected if cmac is initialized
        if (ctx->cbCmacKey != 0 &&
            ctx->cbKey != ctx->cbCmacKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_CONTEXT)) != NULL &&
        !p_scossl_kbkdf_get_octet_string(p, &ctx->pbContext, &ctx->cbContext))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_LABEL)) != NULL &&
        !p_scossl_kbkdf_get_octet_string(p, &ctx->pbLabel, &ctx->cbLabel))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES)) != NULL &&
        !OSSL_PARAM_get_utf8_string_ptr(p, &propq))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC)) != NULL)
    {
        const char *macName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &macName) ||
            macName == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((mac = EVP_MAC_fetch(ctx->libCtx, macName, propq)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            goto cleanup;
        }

        if (EVP_MAC_is_a(mac, SN_hmac))
        {
            // Need digest to determine appropriate PCSYMCRYPT_MAC
            ctx->macType = SCOSSL_MAC_TYPE_HMAC;
            ctx->pMac = NULL;
            ctx->pMacEx = NULL;
        }
        else if (EVP_MAC_is_a(mac, SN_cmac))
        {
            ctx->macType = SCOSSL_MAC_TYPE_CMAC;
            ctx->pMac = SymCryptAesCmacAlgorithm;
            ctx->pMacEx = NULL;
        }
        else if (EVP_MAC_is_a(mac, SN_kmac128))
        {
            ctx->macType = SCOSSL_MAC_TYPE_KMAC;
            ctx->pMac = SymCryptKmac128Algorithm;
            ctx->pMacEx = &SymCryptKmac128AlgorithmEx;
        }
        else if (EVP_MAC_is_a(mac, SN_kmac256))
        {
            ctx->macType = SCOSSL_MAC_TYPE_KMAC;
            ctx->pMac = SymCryptKmac256Algorithm;
            ctx->pMacEx = &SymCryptKmac256AlgorithmEx;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            goto cleanup;
        }

        ctx->cbCmacKey = 0;
    }

    // Digest only relevant for HMAC
    if (ctx->macType == SCOSSL_MAC_TYPE_HMAC &&
        (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL)
    {
        const char *mdName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName) ||
            mdName == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((md = EVP_MD_fetch(ctx->libCtx, mdName, propq)) == NULL ||
            (ctx->pMac = scossl_get_symcrypt_hmac_algorithm(EVP_MD_type(md))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }
    }

    // Cipher only relevant for CMAC
    if (ctx->macType == SCOSSL_MAC_TYPE_CMAC &&
        (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CIPHER)) != NULL)
    {
        const char *cipherName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &cipherName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((cipher = EVP_CIPHER_fetch(ctx->libCtx, cipherName, propq)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }

        switch(EVP_CIPHER_type(cipher))
        {
        case NID_aes_128_cbc:
            ctx->cbCmacKey = 16;
            break;
        case NID_aes_192_cbc:
            ctx->cbCmacKey = 24;
            break;
        case NID_aes_256_cbc:
            ctx->cbCmacKey = 32;
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            goto cleanup;
        }

        if (ctx->pbKey != NULL &&
            ctx->cbKey != ctx->cbCmacKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto cleanup;
        }
    }

    // Fixed parameters. Anything that doesn't match the fixed behavior of SymCrypt will be rejected.

    // SymCrypt only supports counter mode.
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL)
    {
        const char *mode;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mode) ||
            mode == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (OPENSSL_strcasecmp(mode, "counter") != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            goto cleanup;
        }
    }

    // SymCrypt does not omit L or separator
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L)) != NULL)
    {
        int useL;

        if (!OSSL_PARAM_get_int(p, &useL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (useL == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR)) != NULL)
    {
        int useSeparator;

        if (!OSSL_PARAM_get_int(p, &useSeparator))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (useSeparator == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }
    }

#if OPENSSL_VERSION_MAJOR >= 3 && OPENSSL_VERSION_MINOR > 0
    // SymCrypt always uses a 32-bit counter size
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_R)) != NULL)
    {
        int r;

        if (!OSSL_PARAM_get_int(p, &r))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (r != 32)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }
    }
#endif

    ret = SCOSSL_SUCCESS;

cleanup:
    EVP_MAC_free(mac);
    EVP_MD_free(md);
    EVP_CIPHER_free(cipher);
    return ret;
}

const OSSL_DISPATCH p_scossl_kbkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_kbkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_kbkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_kbkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_kbkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_kbkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif