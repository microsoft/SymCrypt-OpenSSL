//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "keymgmt/p_scossl_mlkem_keymgmt.h"

#include <openssl/core_object.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_decode_key_bytes(_In_ SCOSSL_DECODE_CTX *ctx, _In_ const ASN1_OBJECT *algorithm,
                                                             SYMCRYPT_MLKEM_PARAMS mlkemParams, SYMCRYPT_MLKEMKEY_FORMAT format,
                                                             _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLKEM_GROUP_INFO *groupInfo = NULL;

    if (pbKey == NULL || cbKey == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((groupInfo = p_scossl_mlkem_get_group_info_by_nid(OBJ_obj2nid(algorithm))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if (mlkemParams != groupInfo->mlkemParams)
    {
        goto cleanup;
    }

    if ((keyCtx = p_scossl_mlkem_keymgmt_new_ctx(ctx->provctx, mlkemParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    status = p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, format, pbKey, cbKey);

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        OPENSSL_free(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_PrivateKeyInfo_to_mlkem(_In_ SCOSSL_DECODE_CTX *ctx, SYMCRYPT_MLKEM_PARAMS mlkemParams, _In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const ASN1_OBJECT *algorithm;
    const unsigned char *pbKey;
    int cbKey;
    ASN1_OCTET_STRING *p8Data = NULL;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(&algorithm, &pbKey, &cbKey, NULL, p8Info) ||
        d2i_ASN1_OCTET_STRING(&p8Data, &pbKey, cbKey) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    format = cbKey == 64 ? SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED : SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;

    keyCtx = p_scossl_mlkem_decode_key_bytes(ctx, algorithm,
                                             mlkemParams, format,
                                             ASN1_STRING_get0_data(p8Data), ASN1_STRING_length(p8Data));

cleanup:
    ASN1_OCTET_STRING_free(p8Data);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mlkem(_In_ SCOSSL_DECODE_CTX *ctx, SYMCRYPT_MLKEM_PARAMS mlkemParams, _In_ BIO *bio)
{
    OSSL_LIB_CTX *libCtx = ctx->provctx == NULL ? NULL : ctx->provctx->libctx;
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo = NULL;
    const ASN1_OBJECT *algorithm;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;

    if ((subjPubKeyInfo = OPENSSL_zalloc(sizeof(SUBJECT_PUBKEY_INFO))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (ASN1_item_d2i_bio_ex(p_scossl_decode_subject_pubkey_asn1_item(), bio, (ASN1_VALUE **)&subjPubKeyInfo, libCtx, NULL) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    X509_ALGOR_get0(&algorithm, NULL, NULL, subjPubKeyInfo->x509Alg);

    keyCtx = p_scossl_mlkem_decode_key_bytes(ctx, algorithm,
                                             mlkemParams, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                                             ASN1_STRING_get0_data(subjPubKeyInfo->subjectPublicKey), ASN1_STRING_length(subjPubKeyInfo->subjectPublicKey));

cleanup:
    OPENSSL_free(subjPubKeyInfo);

    return keyCtx;
}

static SCOSSL_STATUS p_scossl_der_to_mlkem_export_object(_In_ SCOSSL_DECODE_CTX *ctx,
                                                         _In_reads_bytes_(cbObjRef) const void *pbObjRef, _In_ size_t cbObjRef,
                                                         _In_ OSSL_CALLBACK *exportCb, _In_ void *exportCbArg)
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = *(SCOSSL_MLKEM_KEY_CTX **)pbObjRef;

    if (cbObjRef != sizeof(SCOSSL_MLKEM_KEY_CTX *) || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mlkem_keymgmt_export(keyCtx, ctx->desc->selection, exportCb, exportCbArg);
}

#define SCOSSL_MAKE_MLKEM_DECODER(decoderType, bits)                                                        \
    static SCOSSL_MLKEM_KEY_CTX                                                                             \
    *p_scossl_##decoderType##_to_mlkem##bits(_In_ SCOSSL_DECODE_CTX *ctx,                                   \
                                             _In_ BIO *bio)                                                 \
    {                                                                                                       \
        return p_scossl_##decoderType##_to_mlkem(ctx, SYMCRYPT_MLKEM_PARAMS_MLKEM##bits, bio);              \
    }                                                                                                       \
                                                                                                            \
    static const SCOSSL_DECODE_KEYTYPE_DESC p_scossl_mlkem##bits##_##decoderType##_desc = {                 \
        "ML-KEM-"#bits,                                                                                     \
        select_##decoderType,                                                                               \
        (PSCOSSL_DECODE_INTERNAL_FN)p_scossl_##decoderType##_to_mlkem##bits,                                \
        (OSSL_FUNC_keymgmt_free_fn *)p_scossl_mlkem_keymgmt_free_key_ctx};                                  \
                                                                                                            \
    static SCOSSL_DECODE_CTX *                                                                              \
    p_scossl_der_to_mlkem##bits##_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                      \
    {                                                                                                       \
        return p_scossl_decode_newctx(                                                                      \
            provctx,                                                                                        \
            &p_scossl_mlkem##bits##_##decoderType##_desc);                                                  \
    }                                                                                                       \
                                                                                                            \
    static BOOL                                                                                             \
    p_scossl_der_to_mlkem##bits##_##decoderType##_does_selection(                                           \
        ossl_unused void *provctx,                                                                          \
        int selection)                                                                                      \
    {                                                                                                       \
        return p_scossl_decode_does_selection(                                                              \
            &p_scossl_mlkem##bits##_##decoderType##_desc,                                                   \
            selection);                                                                                     \
    }                                                                                                       \
                                                                                                            \
    const OSSL_DISPATCH p_scossl_der_to_mlkem##bits##_##decoderType##_functions[] = {                       \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_mlkem##bits##_##decoderType##_newctx},   \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_decode_freectx},                               \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_decode_set_ctx_params},                 \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_decode_settable_ctx_params},       \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))                                                 \
            p_scossl_der_to_mlkem##bits##_##decoderType##_does_selection},                                  \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_decode},                                        \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_mlkem_export_object},             \
        {0, NULL}};

SCOSSL_MAKE_MLKEM_DECODER(PrivateKeyInfo, 512);
SCOSSL_MAKE_MLKEM_DECODER(SubjectPublicKeyInfo, 512);
SCOSSL_MAKE_MLKEM_DECODER(PrivateKeyInfo, 768);
SCOSSL_MAKE_MLKEM_DECODER(SubjectPublicKeyInfo, 768);
SCOSSL_MAKE_MLKEM_DECODER(PrivateKeyInfo, 1024);
SCOSSL_MAKE_MLKEM_DECODER(SubjectPublicKeyInfo, 1024);

#ifdef __cplusplus
}
#endif