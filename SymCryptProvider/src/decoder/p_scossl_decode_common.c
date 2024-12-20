//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_bio.h"
#include "decoder/p_scossl_decode_common.h"

#include <openssl/asn1t.h>
#include <openssl/core_object.h>

#ifdef __cplusplus
extern "C" {
#endif

ASN1_NDEF_SEQUENCE(SUBJECT_PUBKEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_PUBKEY_INFO, algorithm, X509_ALGOR),
        ASN1_SIMPLE(SUBJECT_PUBKEY_INFO, subjectPublicKey, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SUBJECT_PUBKEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(SUBJECT_PUBKEY_INFO)

const OSSL_PARAM p_scossl_der_to_key_settable_param_types[] = {
    OSSL_PARAM_END};

_Use_decl_annotations_
SCOSSL_DECODE_CTX *p_scossl_decode_newctx(SCOSSL_PROVCTX *provctx, const SCOSSL_DECODE_KEYTYPE_DESC *desc)
{
    SCOSSL_DECODE_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_DECODE_CTX));

    if (ctx != NULL)
    {
        ctx->provctx = provctx;
        ctx->desc = desc;
    }

    return ctx;
}

_Use_decl_annotations_
void p_scossl_decode_freectx(SCOSSL_DECODE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

const OSSL_PARAM *p_scossl_decode_settable_ctx_params(ossl_unused void *ctx)
{
    return p_scossl_der_to_key_settable_param_types;
}

SCOSSL_STATUS p_scossl_decode_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
BOOL p_scossl_decode_does_selection(SCOSSL_DECODE_KEYTYPE_DESC *desc, int selection)
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

// This function should return SCOSSL_SUCCESS if it successfully decodes something,
// or decodes nothing at all. Another decoder may be able to decode the data into something.
// This function should only return SCOSSL_FAILURE if the data could be decoded, but further
// validation of the data failed in a way that another decoder could not handle.
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_decode(SCOSSL_DECODE_CTX *ctx, OSSL_CORE_BIO *in, int selection,
                              OSSL_CALLBACK *dataCb, void *dataCbArg,
                              ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArg)
{
    BIO *bio = NULL;
    PVOID *keyCtx = NULL;
    OSSL_PARAM cbParams[4];
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;

    if (selection == 0)
    {
        selection = ctx->desc->selection;
    }

    if ((selection & ctx->desc->selection) != 0 &&
        (bio = p_scossl_bio_new_from_core_bio(ctx->provctx, in)) != NULL)
    {
        keyCtx = ctx->desc->decodeInternal(ctx, bio);
    }

    if (keyCtx != NULL)
    {
        int objectType = OSSL_OBJECT_PKEY;

        cbParams[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objectType);
        cbParams[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)ctx->desc->dataType, 0);
        cbParams[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &keyCtx, sizeof(keyCtx));
        cbParams[3] = OSSL_PARAM_construct_end();

        ret = dataCb(cbParams, dataCbArg);
    }

    BIO_free(bio);
    ctx->desc->freeKeyCtx(keyCtx);

    return ret;
}

const ASN1_ITEM *p_scossl_decode_get_pubkey_asn1_item()
{
    return ASN1_ITEM_rptr(SUBJECT_PUBKEY_INFO);
}

#ifdef __cplusplus
}
#endif