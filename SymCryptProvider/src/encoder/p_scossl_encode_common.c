//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_bio.h"
#include "encoder/p_scossl_encode_common.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_TO_TEXT_PRINT_WIDTH 15

static const OSSL_PARAM p_scossl_encode_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END};

_Use_decl_annotations_
SCOSSL_ENCODE_CTX *p_scossl_encode_newctx(SCOSSL_PROVCTX *provctx,
                                          int selection,
                                          SCOSSL_ENCODE_OUT_FORMAT outFormat,
                                          PSCOSSL_ENCODE_INTERNAL_FN encodeInternal)
{
    SCOSSL_ENCODE_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_ENCODE_CTX));

    if (ctx != NULL)
    {
        ctx->provctx = provctx;
        ctx->selection = selection;
        ctx->outFormat = outFormat;
        ctx->encodeInternal = encodeInternal;
   }

    return ctx;
}

_Use_decl_annotations_
void p_scossl_encode_freectx(SCOSSL_ENCODE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_encode_set_ctx_params(SCOSSL_ENCODE_CTX *ctx, const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = ctx->provctx != NULL ? ctx->provctx->libctx : NULL;
    const char *cipherName = NULL;
    const char *propQ = NULL;
    const OSSL_PARAM *paramCipher = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    const OSSL_PARAM *paramProperties = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);

    if (paramCipher != NULL)
    {
        if (!OSSL_PARAM_get_utf8_string_ptr(paramCipher, &cipherName) ||
            (paramProperties != NULL && !OSSL_PARAM_get_utf8_string_ptr(paramProperties, &propQ)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        EVP_CIPHER_free(ctx->cipher);

        if (cipherName != NULL)
        {
            if ((ctx->cipher = EVP_CIPHER_fetch(libctx, cipherName, propQ)) == NULL)
            {
                ctx->cipherIntent = FALSE;
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return SCOSSL_FAILURE;
            }
            ctx->cipherIntent = TRUE;

        }
        else
        {
            ctx->cipher = NULL;
        }

        ctx->cipherIntent = ctx->cipher != NULL;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_encode_settable_ctx_params(ossl_unused void *provctx)
{
    return p_scossl_encode_settable_param_types;
}

BOOL p_scossl_encode_does_selection(int supportedSelection, int selection)
{
    if (selection == 0)
    {
        return TRUE;
    }

    // Supporting private key implies supporting public key.
    // Both imply supporting key parameters

    return ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && (supportedSelection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) ||
           ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && (supportedSelection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)   ||
           ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 && (supportedSelection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_encode(SCOSSL_ENCODE_CTX *ctx, OSSL_CORE_BIO *out,
                              const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                              const OSSL_PARAM keyAbstract[],
                              int selection,
                              OSSL_PASSPHRASE_CALLBACK *passphraseCb, void *passphraseCbArgs)
{
    BIO *bio = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto cleanup;
    }

    if (ctx->encodeInternal == NULL ||
        keyAbstract != NULL ||
        (ctx->outFormat != SCOSSL_ENCODE_TEXT && ((selection & ctx->selection) == 0)))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if ((bio = p_scossl_bio_new_from_core_bio(ctx->provctx, out)) != NULL)
    {
        ret = ctx->encodeInternal(
            ctx, bio,
            keyCtx,
            selection,
            passphraseCb, passphraseCbArgs,
            ctx->outFormat == SCOSSL_ENCODE_PEM);
    }

cleanup:
    BIO_free(bio);

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_encode_write_key_bytes(PCBYTE pbKey, SIZE_T cbKey, BIO *out)
{
    for(SIZE_T i = 0; i < cbKey; i++)
    {
        if (i % KEY_TO_TEXT_PRINT_WIDTH == 0)
        {
            if (BIO_printf(out, "\n    ") <= 0)
            {
                return SCOSSL_FAILURE;
            }
        }

        if (BIO_printf(out, "%02x%s", pbKey[i], (i < cbKey - 1) ? ":" : "") <= 0)
        {
            return SCOSSL_FAILURE;
        }
    }

    if (BIO_printf(out, "\n") <= 0)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}


#ifdef __cplusplus
}
#endif