//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "decoder/p_scossl_decode_common.h"
#include "keymgmt/p_scossl_mlkem_keymgmt.h"

#include <openssl/core_object.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int nid;
    const char *name;
    SYMCRYPT_MLKEM_PARAMS keyParams;
} SCOSSL_DECODE_MLKEM_PARAM_MAP;

static SCOSSL_DECODE_MLKEM_PARAM_MAP p_scossl_decode_mlkem_param_maps[] = {
    {-1, SCOSSL_SN_MLKEM512, SYMCRYPT_MLKEM_PARAMS_MLKEM512},
    {-1, SCOSSL_SN_MLKEM768, SYMCRYPT_MLKEM_PARAMS_MLKEM768},
    {-1, SCOSSL_SN_MLKEM1024, SYMCRYPT_MLKEM_PARAMS_MLKEM1024}};

static SYMCRYPT_MLKEM_PARAMS p_scossl_decode_mlkem_get_params(int nid)
{
    for (size_t i = 0; i < sizeof(p_scossl_decode_mlkem_param_maps) / sizeof(SCOSSL_DECODE_MLKEM_PARAM_MAP); i++)
    {
        if (p_scossl_decode_mlkem_param_maps[i].nid == -1)
        {
            p_scossl_decode_mlkem_param_maps[i].nid = OBJ_sn2nid(p_scossl_decode_mlkem_param_maps[i].name);
        }

        if (p_scossl_decode_mlkem_param_maps[i].nid == nid)
        {
            return p_scossl_decode_mlkem_param_maps[i].keyParams;
        }
    }

    return SYMCRYPT_MLKEM_PARAMS_NULL;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_PrivateKeyInfo_to_mlkem(_In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const X509_ALGOR *alg = NULL;
    const unsigned char *pbKey = NULL;
    int cbKey;
    ASN1_OCTET_STRING *p8Data = NULL;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SYMCRYPT_MLKEMKEY_FORMAT decodeFormat = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(NULL, &pbKey, &cbKey, &alg, p8Info) ||
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

    keyCtx->mlkemParams = p_scossl_decode_mlkem_get_params(OBJ_obj2nid(alg->algorithm));
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;

    if (keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->mlkemParams)) == NULL)
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

static SCOSSL_MLKEM_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mlkem(_In_ BIO *bio)
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

    if (ASN1_item_d2i_bio(p_scossl_decode_get_pubkey_asn1_item(), bio, (ASN1_VALUE **)&subjPubKeyInfo) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_DECODE_ERROR);
        goto cleanup;
    }

    if ((keyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEY_CTX))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    keyCtx->mlkemParams = p_scossl_decode_mlkem_get_params(OBJ_obj2nid(subjPubKeyInfo->algorithm->algorithm));
    keyCtx->format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;

    if (keyCtx->mlkemParams == SYMCRYPT_MLKEM_PARAMS_NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    if ((keyCtx->key = SymCryptMlKemkeyAllocate(keyCtx->mlkemParams)) == NULL)
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

#define SCOSSL_MAKE_MLKEM_DECODER(decoderType)                                                                     \
    static SCOSSL_DECODE_KEYTYPE_DESC p_scossl_mlkem_##decoderType##_desc = {                                      \
        "MLKEM",                                                                                                   \
        select_##decoderType,                                                                                      \
        (PSCOSSL_DECODE_INTERNAL_FN)p_scossl_##decoderType##_to_mlkem,                                             \
        (OSSL_FUNC_keymgmt_free_fn *)p_scossl_mlkem_keymgmt_free_key_ctx};                                         \
                                                                                                                   \
    static SCOSSL_DECODE_CTX *                                                                                     \
    p_scossl_der_to_mlkem_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                                     \
    {                                                                                                              \
        return p_scossl_decode_newctx(                                                                             \
            provctx,                                                                                               \
            &p_scossl_mlkem_##decoderType##_desc);                                                                 \
    }                                                                                                              \
                                                                                                                   \
    static BOOL                                                                                                    \
    p_scossl_der_to_mlkem_##decoderType##_does_selection(                                                          \
        ossl_unused void *provctx,                                                                                 \
        int selection)                                                                                             \
    {                                                                                                              \
        return p_scossl_decode_does_selection(                                                                     \
            &p_scossl_mlkem_##decoderType##_desc,                                                                  \
            selection);                                                                                            \
    }                                                                                                              \
                                                                                                                   \
    const OSSL_DISPATCH p_scossl_der_to_mlkem_##decoderType##_functions[] = {                                      \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_mlkem_##decoderType##_newctx},                  \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_decode_freectx},                                      \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_decode_settable_ctx_params},              \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_decode_set_ctx_params},                        \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void)) p_scossl_der_to_mlkem_##decoderType##_does_selection}, \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_decode},                                               \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_mlkem_export_object},                    \
        {0, NULL}};


extern const OSSL_DISPATCH p_scossl_mlkem_keymgmt_functions[];

SCOSSL_MAKE_MLKEM_DECODER(PrivateKeyInfo);
SCOSSL_MAKE_MLKEM_DECODER(SubjectPublicKeyInfo);

#ifdef __cplusplus
}
#endif