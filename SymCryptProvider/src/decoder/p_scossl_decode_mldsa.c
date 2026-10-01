//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "signature/p_scossl_mldsa.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_decode_key_bytes(_In_ const SCOSSL_MLDSA_BACKEND *backend,
                                                             _In_ const ASN1_OBJECT *algorithm,
                                                             int params, int format,
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

    if ((algInfo = p_scossl_mldsa_get_alg_info_by_nid(backend, OBJ_obj2nid(algorithm))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if (params != algInfo->params)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        goto cleanup;
    }

    if ((keyCtx = p_scossl_mldsa_keymgmt_new_ctx(backend, params)) == NULL)
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

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_PrivateKeyInfo_to_mldsa(PVOID vctx, const SCOSSL_MLDSA_BACKEND *backend, int params, BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const ASN1_OBJECT *algorithm;
    const unsigned char *pbKey;
    int cbKey;
    ASN1_OCTET_STRING *p8Data = NULL;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = NULL;
    int format;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(&algorithm, &pbKey, &cbKey, NULL, p8Info) ||
        d2i_ASN1_OCTET_STRING(&p8Data, &pbKey, cbKey) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto cleanup;
    }

    cbKey = ASN1_STRING_length(p8Data);

    // ML-DSA private keys may be encoded either as a raw private key or as the
    // 32-byte private seed. Composite-ML-DSA has no seed format, so its keys are
    // always the raw private key.
    format = (backend->supportsSeed && (SIZE_T)cbKey == backend->cbPrivateSeed) ?
        backend->formatPrivateSeed : backend->formatPrivateKey;

    keyCtx = p_scossl_mldsa_decode_key_bytes(backend, algorithm,
                                             params, format,
                                             ASN1_STRING_get0_data(p8Data), ASN1_STRING_length(p8Data));

cleanup:
    ASN1_OCTET_STRING_free(p8Data);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

_Use_decl_annotations_
SCOSSL_MLDSA_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mldsa(PVOID vctx, const SCOSSL_MLDSA_BACKEND *backend, int params, BIO *bio)
{
    SCOSSL_DECODE_CTX *ctx = (SCOSSL_DECODE_CTX *)vctx;
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

    keyCtx = p_scossl_mldsa_decode_key_bytes(backend, algorithm,
                                             params, backend->formatPublicKey,
                                             ASN1_STRING_get0_data(subjPubKeyInfo->subjectPublicKey), ASN1_STRING_length(subjPubKeyInfo->subjectPublicKey));

cleanup:
    ASN1_item_free((ASN1_VALUE *)subjPubKeyInfo, p_scossl_decode_subject_pubkey_asn1_item());

    return keyCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_der_to_mldsa_export_object(PVOID vctx,
                                                  const void *pbObjRef, size_t cbObjRef,
                                                  OSSL_CALLBACK *exportCb, void *exportCbArg)
{
    SCOSSL_DECODE_CTX *ctx = (SCOSSL_DECODE_CTX *)vctx;
    SCOSSL_MLDSA_KEY_CTX *keyCtx = *(SCOSSL_MLDSA_KEY_CTX **)pbObjRef;

    if (cbObjRef != sizeof(SCOSSL_MLDSA_KEY_CTX *) || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_FAILURE;
    }

    return p_scossl_mldsa_keymgmt_export(keyCtx, ctx->desc->selection, exportCb, exportCbArg);
}

//
// Per-variant decoder dispatch tables for the pure ML-DSA family. The shared
// core above is also used by the Composite-ML-DSA decoder translation unit.
//
IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87)

#ifdef __cplusplus
}
#endif
