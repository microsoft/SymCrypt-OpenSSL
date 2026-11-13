//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "keymgmt/p_scossl_mldsa_keymgmt.h"

#include <openssl/asn1.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_decode_key_bytes(_In_ const ASN1_OBJECT *algorithm,
                                                             SYMCRYPT_MLDSA_PARAMS mldsaParams, SYMCRYPT_MLDSAKEY_FORMAT format,
                                                             _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    SCOSSL_MLDSA_ALG_INFO *algInfo = NULL;

    if (pbKey == NULL || cbKey == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((algInfo = p_scossl_mldsa_get_alg_info_by_nid(OBJ_obj2nid(algorithm))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if (mldsaParams != algInfo->mldsaParams)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        goto cleanup;
    }

    if ((keyCtx = p_scossl_mldsa_keymgmt_new_ctx(mldsaParams)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    status = p_scossl_mldsa_keymgmt_set_encoded_key(keyCtx, format, pbKey, cbKey);

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_PrivateKeyInfo_to_mldsa(ossl_unused SCOSSL_DECODE_CTX *ctx, SYMCRYPT_MLDSA_PARAMS mldsaParams, _In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const ASN1_OBJECT *algorithm;
    const unsigned char *pbKey;
    const unsigned char *pbKeyCursor;
    int cbKey;
    const unsigned char *pbEncodedKey = NULL;
    int cbEncodedKey = 0;
    ASN1_OCTET_STRING *p8Data = NULL;
    STACK_OF(ASN1_TYPE) *p8Both = NULL;
    ASN1_TYPE *p8Seed = NULL;
    ASN1_TYPE *p8ExpandedKey = NULL;
    PBYTE pbDerivedExpandedKey = NULL;
    SIZE_T cbDerivedExpandedKey = 0;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_MLDSAKEY_FORMAT format;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(&algorithm, &pbKey, &cbKey, NULL, p8Info) ||
        cbKey <= 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    if (pbKey[0] == V_ASN1_CONTEXT_SPECIFIC)
    {
        if (cbKey != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE + 2 ||
            pbKey[1] != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            goto cleanup;
        }

        format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
        pbEncodedKey = pbKey + 2;
        cbEncodedKey = SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE;
    }
    else if (pbKey[0] == V_ASN1_OCTET_STRING)
    {
        pbKeyCursor = pbKey;
        if (d2i_ASN1_OCTET_STRING(&p8Data, &pbKeyCursor, cbKey) == NULL ||
            pbKeyCursor != pbKey + cbKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            goto cleanup;
        }

        cbEncodedKey = ASN1_STRING_length(p8Data);
        pbEncodedKey = ASN1_STRING_get0_data(p8Data);

        // Accept the seed encoding emitted by older SCOSSL versions.
        format = cbEncodedKey == SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE
            ? SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED
            : SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    }
    else if (pbKey[0] == (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE))
    {
        pbKeyCursor = pbKey;
        if ((p8Both = d2i_ASN1_SEQUENCE_ANY(NULL, &pbKeyCursor, cbKey)) == NULL ||
            pbKeyCursor != pbKey + cbKey ||
            sk_ASN1_TYPE_num(p8Both) != 2)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            goto cleanup;
        }

        p8Seed = sk_ASN1_TYPE_value(p8Both, 0);
        p8ExpandedKey = sk_ASN1_TYPE_value(p8Both, 1);
        if (p8Seed == NULL ||
            p8ExpandedKey == NULL ||
            p8Seed->type != V_ASN1_OCTET_STRING ||
            p8ExpandedKey->type != V_ASN1_OCTET_STRING ||
            ASN1_STRING_length(p8Seed->value.octet_string) != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            goto cleanup;
        }

        keyCtx = p_scossl_mldsa_decode_key_bytes(
            algorithm, mldsaParams, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
            ASN1_STRING_get0_data(p8Seed->value.octet_string),
            ASN1_STRING_length(p8Seed->value.octet_string));
        if (keyCtx == NULL)
        {
            goto cleanup;
        }

        if (p_scossl_mldsa_keymgmt_get_encoded_key(
                keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
                &pbDerivedExpandedKey, &cbDerivedExpandedKey) != SCOSSL_SUCCESS ||
            cbDerivedExpandedKey != (SIZE_T)ASN1_STRING_length(p8ExpandedKey->value.octet_string) ||
            CRYPTO_memcmp(
                pbDerivedExpandedKey,
                ASN1_STRING_get0_data(p8ExpandedKey->value.octet_string),
                cbDerivedExpandedKey) != 0)
        {
            p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
            keyCtx = NULL;
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        }

        goto cleanup;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    keyCtx = p_scossl_mldsa_decode_key_bytes(algorithm,
                                             mldsaParams, format,
                                             pbEncodedKey, cbEncodedKey);

cleanup:
    OPENSSL_secure_clear_free(pbDerivedExpandedKey, cbDerivedExpandedKey);
    sk_ASN1_TYPE_pop_free(p8Both, ASN1_TYPE_free);
    ASN1_OCTET_STRING_free(p8Data);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mldsa(_In_ SCOSSL_DECODE_CTX *ctx, SYMCRYPT_MLDSA_PARAMS mldsaParams, _In_ BIO *bio)
{
    OSSL_LIB_CTX *libCtx = ctx->provctx == NULL ? NULL : ctx->provctx->libctx;
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo = NULL;
    const ASN1_OBJECT *algorithm;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;

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

    keyCtx = p_scossl_mldsa_decode_key_bytes(algorithm,
                                             mldsaParams, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                                             ASN1_STRING_get0_data(subjPubKeyInfo->subjectPublicKey), ASN1_STRING_length(subjPubKeyInfo->subjectPublicKey));

cleanup:
    ASN1_item_free((ASN1_VALUE *)subjPubKeyInfo, p_scossl_decode_subject_pubkey_asn1_item());

    return keyCtx;
}

static SCOSSL_STATUS p_scossl_der_to_mldsa_export_object(_In_ SCOSSL_DECODE_CTX *ctx,
                                                         _In_reads_bytes_(cbObjRef) const void *pbObjRef, _In_ size_t cbObjRef,
                                                         _In_ OSSL_CALLBACK *exportCb, _In_ void *exportCbArg)
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = *(SCOSSL_MLDSA_KEY_CTX **)pbObjRef;

    if (cbObjRef != sizeof(SCOSSL_MLDSA_KEY_CTX *) || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mldsa_keymgmt_export(keyCtx, ctx->desc->selection, exportCb, exportCbArg);
}

#define SCOSSL_MAKE_MLDSA_DECODER(decoderType, paramSet)                                                        \
    static SCOSSL_MLDSA_KEY_CTX                                                                             \
    *p_scossl_##decoderType##_to_mldsa##paramSet(_In_ SCOSSL_DECODE_CTX *ctx,  _In_ BIO *bio)                   \
    {                                                                                                       \
        return p_scossl_##decoderType##_to_mldsa(ctx, SYMCRYPT_MLDSA_PARAMS_MLDSA##paramSet, bio);              \
    }                                                                                                       \
                                                                                                            \
    static const SCOSSL_DECODE_KEYTYPE_DESC p_scossl_mldsa##paramSet##_##decoderType##_desc = {                 \
        "ML-DSA-"#paramSet,                                                                                     \
        select_##decoderType,                                                                               \
        (PSCOSSL_DECODE_INTERNAL_FN)p_scossl_##decoderType##_to_mldsa##paramSet,                                \
        (OSSL_FUNC_keymgmt_free_fn *)p_scossl_mldsa_keymgmt_free_key_ctx};                                  \
                                                                                                            \
    static SCOSSL_DECODE_CTX *                                                                              \
    p_scossl_der_to_mldsa##paramSet##_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                      \
    {                                                                                                       \
        return p_scossl_decode_newctx(provctx, &p_scossl_mldsa##paramSet##_##decoderType##_desc);               \
    }                                                                                                       \
                                                                                                            \
    static BOOL                                                                                             \
    p_scossl_der_to_mldsa##paramSet##_##decoderType##_does_selection(ossl_unused void *provctx,                 \
                                                                 int selection)                             \
    {                                                                                                       \
        return p_scossl_decode_does_selection( &p_scossl_mldsa##paramSet##_##decoderType##_desc, selection);    \
    }                                                                                                       \
                                                                                                            \
    const OSSL_DISPATCH p_scossl_der_to_mldsa##paramSet##_##decoderType##_functions[] = {                       \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_mldsa##paramSet##_##decoderType##_newctx},   \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_decode_freectx},                               \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_decode_set_ctx_params},                 \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_decode_settable_ctx_params},       \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))                                                 \
            p_scossl_der_to_mldsa##paramSet##_##decoderType##_does_selection},                                  \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_decode},                                        \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_mldsa_export_object},             \
        {0, NULL}};

SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, 44);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, 44);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, 65);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, 65);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, 87);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, 87);

#ifdef __cplusplus
}
#endif