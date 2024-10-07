//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_bio.h"
#include "kem/p_scossl_mlkem.h"

#include <openssl/asn1t.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    X509_ALGOR algorithm;
    ASN1_BIT_STRING *subjectPublicKey;
} SUBJECT_PUBKEY_INFO;

typedef struct
{
    const char *dataType;
    const OSSL_DISPATCH *keymgmtFns;
    int selection;

    SYMCRYPT_MLKEM_PARAMS mlkemParams;
} SCOSSL_KEYTYPE_DESC;

typedef struct
{
    SCOSSL_PROVCTX *provctx;

    const SCOSSL_KEYTYPE_DESC *desc;

    OSSL_FUNC_keymgmt_free_fn *keymgmt_free;
    OSSL_FUNC_keymgmt_export_fn *keymgmt_export;
} SCOSSL_DER_TO_KEY_CTX;

ASN1_NDEF_SEQUENCE(SUBJECT_PUBKEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_PUBKEY_INFO, algorithm, X509_ALGOR),
        ASN1_SIMPLE(SUBJECT_PUBKEY_INFO, subjectPublicKey, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SUBJECT_PUBKEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(SUBJECT_PUBKEY_INFO)

static const OSSL_PARAM p_scossl_der_to_key_settable_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_DER_TO_KEY_CTX *p_scossl_der_to_key_newctx(SCOSSL_PROVCTX *provctx, const SCOSSL_KEYTYPE_DESC *desc)
{
    SCOSSL_DER_TO_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_DER_TO_KEY_CTX));

    if (ctx != NULL)
    {
        ctx->desc = desc;
        ctx->provctx = provctx;

        for (const OSSL_DISPATCH *fn = desc->keymgmtFns; fn->function_id != 0; fn++)
        {
            switch (fn->function_id)
            {
            case OSSL_FUNC_KEYMGMT_FREE:
                ctx->keymgmt_free = (OSSL_FUNC_keymgmt_free_fn *)fn->function;
                break;
            case OSSL_FUNC_KEYMGMT_EXPORT:
                ctx->keymgmt_export = (OSSL_FUNC_keymgmt_export_fn *)fn->function;
                break;
            }
        }
   }

    return ctx;
}

static void p_scossl_der_to_key_freectx(_Inout_ SCOSSL_DER_TO_KEY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

static const OSSL_PARAM *p_scossl_der_to_key_settable_ctx_params(ossl_unused void *ctx)
{
    return p_scossl_der_to_key_settable_param_types;
}

static SCOSSL_STATUS p_scossl_der_to_key_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static BOOL p_scossl_der_to_key_does_selection(_In_ SCOSSL_KEYTYPE_DESC *desc, int selection)
{
    if (selection == 0)
    {
        return TRUE;
    }

    // Supporting private key implies supporting public key.
    // Both imply supporting key parameters

    return ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && (desc->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) ||
           ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && (desc->selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)   ||
           ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 && (desc->selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0);
}


static SCOSSL_MLKEM_KEY_CTX *p_scossl_d2i_mlkem_PKCS8(_In_ const SCOSSL_KEYTYPE_DESC *desc, _In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const unsigned char *pbKey = NULL;
    int cbKey;
    ASN1_OCTET_STRING *p8Data = NULL;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_MLKEMKEY_FORMAT decodeFormat = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(NULL, &pbKey, &cbKey, NULL, p8Info) ||
        (p8Data = d2i_ASN1_OCTET_STRING(NULL, &pbKey, cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_DECODE_ERROR);
        goto cleanup;
    }

    pbKey = ASN1_STRING_get0_data(p8Data);
    cbKey = ASN1_STRING_length(p8Data);

    if (cbKey == 64)
    {
        decodeFormat = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    }

    if ((keyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEY_CTX))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    keyCtx->params = desc->mlkemParams;
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;

    if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->params)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeySetValue(
        pbKey, cbKey,
        decodeFormat,
        0,
        keyCtx->key);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SymCryptMlKemkeyFree(keyCtx->key);
        keyCtx->key = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        OPENSSL_free(keyCtx);
        keyCtx = NULL;
    }

    ASN1_OCTET_STRING_free(p8Data);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_d2i_mlkem_PUBKEY(_In_ const SCOSSL_KEYTYPE_DESC *desc, _In_ BIO *bio)
{
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if ((subjPubKeyInfo = OPENSSL_zalloc(sizeof(SUBJECT_PUBKEY_INFO))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (ASN1_item_d2i_bio(ASN1_ITEM_rptr(SUBJECT_PUBKEY_INFO), bio, (ASN1_VALUE **)&subjPubKeyInfo) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_DECODE_ERROR);
        goto cleanup;
    }

    if ((keyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEY_CTX))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    keyCtx->params = desc->mlkemParams;
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;

    if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->params)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptMlKemkeySetValue(
        subjPubKeyInfo->subjectPublicKey->data,
        subjPubKeyInfo->subjectPublicKey->length,
        keyCtx->format,
        0,
        keyCtx->key);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SymCryptMlKemkeyFree(keyCtx->key);
        keyCtx->key = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        OPENSSL_free(keyCtx);
        keyCtx = NULL;
    }

    OPENSSL_free(subjPubKeyInfo);

    return keyCtx;
}

// This function should return SCOSSL_SUCCESS if it successfully decodes something,
// or decodes nothing at all. Another decoder may be able to decode the data into something.
// This function should only return SCOSSL_FAILURE if the data could be decoded, but further
// validation of the data failed in a way that another decoder could not handle.
static SCOSSL_STATUS p_scossl_der_to_key_decode(_In_ SCOSSL_DER_TO_KEY_CTX *ctx, _In_ OSSL_CORE_BIO *in,
                                                int selection,
                                                _In_ OSSL_CALLBACK *dataCb, _In_ void *dataCbArg,
                                                ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArg)
{
    BIO *bio = NULL;
    SCOSSL_MLKEM_KEY_CTX *pKey = NULL;
    OSSL_PARAM cbParams[4];
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;

    if (selection == 0)
    {
        selection = ctx->desc->selection;
    }
    else if ((selection & ctx->desc->selection) == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }

    if ((bio = p_scossl_bio_new_from_core_bio(ctx->provctx, in)) == NULL)
    {
        goto callback;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        pKey = p_scossl_d2i_mlkem_PKCS8(ctx->desc, bio);
        if (!BIO_reset(bio))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto callback;
        }
    }

    if (pKey == NULL && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        pKey = p_scossl_d2i_mlkem_PUBKEY(ctx->desc, bio);
    }

callback:

    if (pKey != NULL)
    {
        int objectType = OSSL_OBJECT_PKEY;

        cbParams[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objectType);
        cbParams[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)ctx->desc->dataType, 0);
        cbParams[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pKey, sizeof(pKey));
        cbParams[3] = OSSL_PARAM_construct_end();

        ret = dataCb(cbParams, dataCbArg);
    }

    BIO_free(bio);
    ctx->keymgmt_free(pKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_der_to_key_export_object(_In_ SCOSSL_DER_TO_KEY_CTX *ctx,
                                                       _In_reads_bytes_(cbObjRef) const void *pbObjRef, _In_ size_t cbObjRef,
                                                       _In_ OSSL_CALLBACK *exportCb, _In_ void *exportCbArg)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = *(SCOSSL_MLKEM_KEY_CTX **)pbObjRef;

    if (cbObjRef != sizeof(SCOSSL_MLKEM_KEY_CTX *) || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    return ctx->keymgmt_export(keyCtx, ctx->desc->selection, exportCb, exportCbArg);
}

#define SCOSSL_MAKE_MLKEM_DECODER(paramSet, decoderType, selectionType)                                       \
    static SCOSSL_KEYTYPE_DESC p_scossl_mlkem##paramSet##_##decoderType##_desc = {                            \
        "MLKEM",                                                                                              \
        p_scossl_mlkem_keymgmt_functions,                                                                     \
        selectionType,                                                                                        \
        SYMCRYPT_MLKEM_PARAMS_MLKEM##paramSet};                                                               \
                                                                                                              \
    static SCOSSL_DER_TO_KEY_CTX *                                                                            \
    p_scossl_der_to_mlkem##paramSet##_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                    \
    {                                                                                                         \
        return p_scossl_der_to_key_newctx(                                                                    \
            provctx,                                                                                          \
            &p_scossl_mlkem##paramSet##_##decoderType##_desc);                                                \
    }                                                                                                         \
                                                                                                              \
    static BOOL                                                                                               \
    p_scossl_der_to_mlkem##paramSet##_##decoderType##_does_selection(                                         \
        ossl_unused void *provctx,                                                                            \
        int selection)                                                                                        \
    {                                                                                                         \
        return p_scossl_der_to_key_does_selection(                                                            \
            &p_scossl_mlkem##paramSet##_##decoderType##_desc,                                                 \
            selection);                                                                                       \
    }                                                                                                         \
                                                                                                              \
    const OSSL_DISPATCH p_scossl_der_to_mlkem##paramSet##_##decoderType##_functions[] = {                     \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_mlkem##paramSet##_##decoderType##_newctx}, \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_der_to_key_freectx},                             \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_der_to_key_set_ctx_params},               \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_der_to_key_settable_ctx_params},     \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))                                                   \
            p_scossl_der_to_mlkem##paramSet##_##decoderType##_does_selection},                                \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_der_to_key_decode},                               \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_key_export_object},                 \
        {0, NULL}};


extern const OSSL_DISPATCH p_scossl_mlkem_keymgmt_functions[];

SCOSSL_MAKE_MLKEM_DECODER(512, PrivateKeyInfo, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
SCOSSL_MAKE_MLKEM_DECODER(512, SubjectPublicKeyInfo, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
SCOSSL_MAKE_MLKEM_DECODER(768, PrivateKeyInfo, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
SCOSSL_MAKE_MLKEM_DECODER(768, SubjectPublicKeyInfo, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
SCOSSL_MAKE_MLKEM_DECODER(1024, PrivateKeyInfo, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
SCOSSL_MAKE_MLKEM_DECODER(1024, SubjectPublicKeyInfo, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

#ifdef __cplusplus
}
#endif