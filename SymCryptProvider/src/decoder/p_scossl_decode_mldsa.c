//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "keymgmt/p_scossl_mldsa_keymgmt.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_decode_key_bytes(BOOL isComposite, _In_ const ASN1_OBJECT *algorithm,
                                                             SCOSSL_MLDSA_PARAMS mldsaParams, SCOSSL_MLDSAKEY_FORMAT format,
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

    if ((algInfo = p_scossl_mldsa_get_alg_info_by_nid(OBJ_obj2nid(algorithm))) == NULL ||
        algInfo->isComposite != isComposite)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if (mldsaParams != algInfo->mldsaParams)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        goto cleanup;
    }

    if ((keyCtx = p_scossl_mldsa_keymgmt_new_ctx(mldsaParams, isComposite)) == NULL)
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

// Parses the ML-DSA-PrivateKey CHOICE (RFC 9881):
//   seed        [0] IMPLICIT OCTET STRING (SIZE (32))
//   expandedKey OCTET STRING
//   both        SEQUENCE { seed OCTET STRING (SIZE (32)), expandedKey OCTET STRING }
// Returned pointers reference pbDer. *ppbSeed and *ppbExpanded
// are set to NULL if the respective component is not present.
static SCOSSL_STATUS p_scossl_mldsa_parse_private_key(_In_reads_bytes_(cbDer) PCBYTE pbDer, SIZE_T cbDer,
                                                      _Out_ PCBYTE *ppbSeed,
                                                      _Out_ PCBYTE *ppbExpanded, _Out_ SIZE_T *pcbExpanded)
{
    const unsigned char *pbCur = pbDer;
    const unsigned char *pbEnd = pbDer + cbDer;
    long cbContent;
    int tag;
    int xclass;
    int ret;

    *ppbSeed = NULL;
    *ppbExpanded = NULL;
    *pcbExpanded = 0;

    ret = ASN1_get_object(&pbCur, &cbContent, &tag, &xclass, (long)cbDer);
    if ((ret & 0x80) != 0 || ret == (V_ASN1_CONSTRUCTED | 1) ||
        pbCur + cbContent != pbEnd)
    {
        return SCOSSL_FAILURE;
    }

    if (xclass == V_ASN1_CONTEXT_SPECIFIC && tag == 0 && ret == 0)
    {
        if (cbContent != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE)
        {
            return SCOSSL_FAILURE;
        }

        *ppbSeed = pbCur;
    }
    else if (xclass == V_ASN1_UNIVERSAL && tag == V_ASN1_OCTET_STRING && ret == 0)
    {
        *ppbExpanded = pbCur;
        *pcbExpanded = (SIZE_T)cbContent;
    }
    else if (xclass == V_ASN1_UNIVERSAL && tag == V_ASN1_SEQUENCE && ret == V_ASN1_CONSTRUCTED)
    {
        ret = ASN1_get_object(&pbCur, &cbContent, &tag, &xclass, (long)(pbEnd - pbCur));
        if (ret != 0 || xclass != V_ASN1_UNIVERSAL || tag != V_ASN1_OCTET_STRING ||
            cbContent != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE)
        {
            return SCOSSL_FAILURE;
        }

        *ppbSeed = pbCur;
        pbCur += cbContent;

        ret = ASN1_get_object(&pbCur, &cbContent, &tag, &xclass, (long)(pbEnd - pbCur));
        if (ret != 0 || xclass != V_ASN1_UNIVERSAL || tag != V_ASN1_OCTET_STRING ||
            pbCur + cbContent != pbEnd)
        {
            *ppbSeed = NULL;
            return SCOSSL_FAILURE;
        }

        *ppbExpanded = pbCur;
        *pcbExpanded = (SIZE_T)cbContent;
    }
    else
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// Checks that the expanded private key matches the key derived from the seed
static SCOSSL_STATUS p_scossl_mldsa_check_expanded_key(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                       _In_reads_bytes_(cbExpanded) PCBYTE pbExpanded, SIZE_T cbExpanded)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if (cbKey != cbExpanded ||
        CRYPTO_memcmp(pbKey, pbExpanded, cbKey) != 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return status;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_PrivateKeyInfo_to_mldsa(ossl_unused SCOSSL_DECODE_CTX *ctx, BOOL isComposite, SCOSSL_MLDSA_PARAMS mldsaParams, _In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const ASN1_OBJECT *algorithm;
    const X509_ALGOR *algorithmIdentifier;
    int paramType;
    const unsigned char *pbKey;
    int cbKey;
    PCBYTE pbSeed = NULL;
    PCBYTE pbExpanded = NULL;
    SIZE_T cbExpanded = 0;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    SCOSSL_MLDSAKEY_FORMAT format;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(&algorithm, &pbKey, &cbKey, &algorithmIdentifier, p8Info))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    // AlgorithmIdentifier parameters must be absent (RFC 9881, draft-ietf-lamps-pq-composite-sigs)
    X509_ALGOR_get0(NULL, &paramType, NULL, algorithmIdentifier);
    if (paramType != V_ASN1_UNDEF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    // Composite private keys are placed directly in the PKCS#8 privateKey
    // OCTET STRING without further encoding (draft-ietf-lamps-pq-composite-sigs)
    if (isComposite)
    {
        keyCtx = p_scossl_mldsa_decode_key_bytes(isComposite, algorithm,
                                                 mldsaParams, SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
                                                 pbKey, cbKey);
        goto cleanup;
    }

    if (cbKey <= 0 ||
        p_scossl_mldsa_parse_private_key(pbKey, (SIZE_T)cbKey, &pbSeed, &pbExpanded, &cbExpanded) != SCOSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    // Prefer the seed when present
    if (pbSeed != NULL)
    {
        format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
        keyCtx = p_scossl_mldsa_decode_key_bytes(isComposite, algorithm,
                                                 mldsaParams, format,
                                                 pbSeed, SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE);

        if (keyCtx != NULL && pbExpanded != NULL &&
            p_scossl_mldsa_check_expanded_key(keyCtx, pbExpanded, cbExpanded) != SCOSSL_SUCCESS)
        {
            p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
            keyCtx = NULL;
        }
    }
    else
    {
        format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
        keyCtx = p_scossl_mldsa_decode_key_bytes(isComposite, algorithm,
                                                 mldsaParams, format,
                                                 pbExpanded, cbExpanded);
    }

cleanup:
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mldsa(_In_ SCOSSL_DECODE_CTX *ctx, BOOL isComposite, SCOSSL_MLDSA_PARAMS mldsaParams, _In_ BIO *bio)
{
    OSSL_LIB_CTX *libCtx = ctx->provctx == NULL ? NULL : ctx->provctx->libctx;
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo = NULL;
    const ASN1_OBJECT *algorithm;
    int paramType;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    SCOSSL_MLDSAKEY_FORMAT format = isComposite ? SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY : SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;

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

    // AlgorithmIdentifier parameters must be absent (RFC 9881, draft-ietf-lamps-pq-composite-sigs)
    if (paramType != V_ASN1_UNDEF)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    keyCtx = p_scossl_mldsa_decode_key_bytes(isComposite, algorithm,
                                             mldsaParams, format,
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

#define SCOSSL_MAKE_MLDSA_DECODER(decoderType, paramSet, isComposite, symcryptParams, lnName)                             \
    static SCOSSL_MLDSA_KEY_CTX *                                                                                         \
    p_scossl_##decoderType##_to_##paramSet(_In_ SCOSSL_DECODE_CTX *ctx, _In_ BIO *bio)                                    \
    {                                                                                                                     \
        return p_scossl_##decoderType##_to_mldsa(ctx, isComposite, symcryptParams, bio);                                  \
    }                                                                                                                     \
                                                                                                                          \
    static const SCOSSL_DECODE_KEYTYPE_DESC p_scossl_##paramSet##_##decoderType##_desc = {                                \
        lnName,                                                                                                           \
        select_##decoderType,                                                                                             \
        (PSCOSSL_DECODE_INTERNAL_FN)p_scossl_##decoderType##_to_##paramSet,                                               \
        (OSSL_FUNC_keymgmt_free_fn *)p_scossl_mldsa_keymgmt_free_key_ctx};                                                \
                                                                                                                          \
    static SCOSSL_DECODE_CTX *                                                                                            \
    p_scossl_der_to_##paramSet##_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                                     \
    {                                                                                                                     \
        return p_scossl_decode_newctx(provctx, &p_scossl_##paramSet##_##decoderType##_desc);                              \
    }                                                                                                                     \
                                                                                                                          \
    static BOOL                                                                                                           \
    p_scossl_der_to_##paramSet##_##decoderType##_does_selection(ossl_unused void *provctx, int selection)                 \
    {                                                                                                                     \
        return p_scossl_decode_does_selection(&p_scossl_##paramSet##_##decoderType##_desc, selection);                    \
    }                                                                                                                     \
                                                                                                                          \
    const OSSL_DISPATCH p_scossl_der_to_##paramSet##_##decoderType##_functions[] = {                                      \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_##paramSet##_##decoderType##_newctx},                  \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_decode_freectx},                                             \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_decode_set_ctx_params},                               \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_decode_settable_ctx_params},                     \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void)) p_scossl_der_to_##paramSet##_##decoderType##_does_selection}, \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_decode},                                                      \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_mldsa_export_object},                           \
        {0, NULL}};

SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, mldsa44, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, mldsa65, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, mldsa87, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa44, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa65, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa87, FALSE, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87);

SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, composite_mldsa44_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256, SCOSSL_LN_MLDSA44_ECDSA_P256_SHA256);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, composite_mldsa65_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P256_SHA512);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, composite_mldsa65_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P384_SHA512);
SCOSSL_MAKE_MLDSA_DECODER(PrivateKeyInfo, composite_mldsa87_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA87_ECDSA_P384_SHA512);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, composite_mldsa44_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256, SCOSSL_LN_MLDSA44_ECDSA_P256_SHA256);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, composite_mldsa65_ecdsa_p256, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P256_SHA512);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, composite_mldsa65_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P384_SHA512);
SCOSSL_MAKE_MLDSA_DECODER(SubjectPublicKeyInfo, composite_mldsa87_ecdsa_p384, TRUE, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA87_ECDSA_P384_SHA512);

#ifdef __cplusplus
}
#endif