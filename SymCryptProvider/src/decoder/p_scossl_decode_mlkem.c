//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "keymgmt/p_scossl_mlkem_keymgmt.h"

#include <openssl/asn1t.h>
#include <openssl/core_object.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

// Private key CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET STRING,
//                      both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } } (RFC 9935)
typedef struct {
    ASN1_OCTET_STRING *seed;
    ASN1_OCTET_STRING *expandedKey;
} SCOSSL_MLKEM_PRIVATE_KEY_BOTH;

typedef struct {
    int type;
    union {
        ASN1_OCTET_STRING *seed;
        ASN1_OCTET_STRING *expandedKey;
        SCOSSL_MLKEM_PRIVATE_KEY_BOTH *both;
    } value;
} SCOSSL_MLKEM_PRIVATE_KEY;

#define SCOSSL_MLKEM_PRIVATE_KEY_TYPE_SEED         0
#define SCOSSL_MLKEM_PRIVATE_KEY_TYPE_EXPANDED_KEY 1
#define SCOSSL_MLKEM_PRIVATE_KEY_TYPE_BOTH         2

ASN1_SEQUENCE(SCOSSL_MLKEM_PRIVATE_KEY_BOTH) = {
    ASN1_SIMPLE(SCOSSL_MLKEM_PRIVATE_KEY_BOTH, seed, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SCOSSL_MLKEM_PRIVATE_KEY_BOTH, expandedKey, ASN1_OCTET_STRING)
} static_ASN1_SEQUENCE_END(SCOSSL_MLKEM_PRIVATE_KEY_BOTH)

ASN1_CHOICE(SCOSSL_MLKEM_PRIVATE_KEY) = {
    ASN1_IMP(SCOSSL_MLKEM_PRIVATE_KEY, value.seed, ASN1_OCTET_STRING, 0),
    ASN1_SIMPLE(SCOSSL_MLKEM_PRIVATE_KEY, value.expandedKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SCOSSL_MLKEM_PRIVATE_KEY, value.both, SCOSSL_MLKEM_PRIVATE_KEY_BOTH)
} static_ASN1_CHOICE_END(SCOSSL_MLKEM_PRIVATE_KEY)

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
    const X509_ALGOR *algorithmIdentifier;
    int paramType;
    const unsigned char *pbKey;
    const unsigned char *pbEnd;
    int cbKey;
    SCOSSL_MLKEM_PRIVATE_KEY *p8Data = NULL;
    ASN1_OCTET_STRING *seed = NULL;
    ASN1_OCTET_STRING *expandedKey = NULL;
    ASN1_OCTET_STRING *privateKey;
    PBYTE pbExpanded = NULL;
    SIZE_T cbExpanded = 0;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(&algorithm, &pbKey, &cbKey, &algorithmIdentifier, p8Info))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    // AlgorithmIdentifier parameters must be absent (RFC 9935)
    X509_ALGOR_get0(NULL, &paramType, NULL, algorithmIdentifier);
    if (paramType != V_ASN1_UNDEF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    if (cbKey <= 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    pbEnd = pbKey + cbKey;
    if ((p8Data = (SCOSSL_MLKEM_PRIVATE_KEY *)ASN1_item_d2i(NULL, &pbKey, cbKey, ASN1_ITEM_rptr(SCOSSL_MLKEM_PRIVATE_KEY))) == NULL ||
        pbKey != pbEnd)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    switch (p8Data->type)
    {
    case SCOSSL_MLKEM_PRIVATE_KEY_TYPE_SEED:
        seed = p8Data->value.seed;
        break;
    case SCOSSL_MLKEM_PRIVATE_KEY_TYPE_EXPANDED_KEY:
        expandedKey = p8Data->value.expandedKey;
        break;
    case SCOSSL_MLKEM_PRIVATE_KEY_TYPE_BOTH:
        seed = p8Data->value.both->seed;
        expandedKey = p8Data->value.both->expandedKey;
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    // Retain the seed when present
    privateKey = seed != NULL ? seed : expandedKey;
    format = seed != NULL ? SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED : SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    keyCtx = p_scossl_mlkem_decode_key_bytes(ctx, algorithm,
                                             mlkemParams, format,
                                             ASN1_STRING_get0_data(privateKey), ASN1_STRING_length(privateKey));

    if (keyCtx == NULL)
    {
        goto cleanup;
    }

    // Both seed and expanded key are present. The expanded key
    // must match the one derived from the seed.
    if (p8Data->type == SCOSSL_MLKEM_PRIVATE_KEY_TYPE_BOTH)
    {
        if (!p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &pbExpanded, &cbExpanded))
        {
            p_scossl_mlkem_keymgmt_free_key_ctx(keyCtx);
            keyCtx = NULL;
            goto cleanup;
        }

        if (cbExpanded != (SIZE_T)ASN1_STRING_length(expandedKey) ||
            CRYPTO_memcmp(pbExpanded, ASN1_STRING_get0_data(expandedKey), cbExpanded) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            p_scossl_mlkem_keymgmt_free_key_ctx(keyCtx);
            keyCtx = NULL;
        }
    }

cleanup:
    if (seed != NULL)
    {
        OPENSSL_cleanse(seed->data, seed->length);
    }
    if (expandedKey != NULL)
    {
        OPENSSL_cleanse(expandedKey->data, expandedKey->length);
    }
    ASN1_item_free((ASN1_VALUE *)p8Data, ASN1_ITEM_rptr(SCOSSL_MLKEM_PRIVATE_KEY));
    OPENSSL_secure_clear_free(pbExpanded, cbExpanded);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mlkem(_In_ SCOSSL_DECODE_CTX *ctx, SYMCRYPT_MLKEM_PARAMS mlkemParams, _In_ BIO *bio)
{
    OSSL_LIB_CTX *libCtx = ctx->provctx == NULL ? NULL : ctx->provctx->libctx;
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo = NULL;
    const ASN1_OBJECT *algorithm;
    int paramType;
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

    X509_ALGOR_get0(&algorithm, &paramType, NULL, subjPubKeyInfo->x509Alg);

    // AlgorithmIdentifier parameters must be absent (RFC 9935)
    if (paramType != V_ASN1_UNDEF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    keyCtx = p_scossl_mlkem_decode_key_bytes(ctx, algorithm,
                                             mlkemParams, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
                                             ASN1_STRING_get0_data(subjPubKeyInfo->subjectPublicKey), ASN1_STRING_length(subjPubKeyInfo->subjectPublicKey));

cleanup:
    ASN1_item_free((ASN1_VALUE *)subjPubKeyInfo, p_scossl_decode_subject_pubkey_asn1_item());

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