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
    const char *groupName;
} SCOSSL_DECODE_MLKEM_PARAM_MAP;

static SCOSSL_DECODE_MLKEM_PARAM_MAP p_scossl_decode_mlkem_param_maps[] = {
    {-1, SCOSSL_SN_MLKEM512},
    {-1, SCOSSL_SN_MLKEM768},
    {-1, SCOSSL_SN_MLKEM1024},
    {-1, SCOSSL_SN_P256_MLKEM768},
    {-1, SCOSSL_SN_X25519_MLKEM768}};

static const char *p_scossl_decode_mlkem_obj_to_groupname(const ASN1_OBJECT *obj)
{
    int nid = OBJ_obj2nid(obj);

    if (nid != -1)
    {
        for (size_t i = 0; i < sizeof(p_scossl_decode_mlkem_param_maps) / sizeof(OSSL_ITEM); i++)
        {
            if (p_scossl_decode_mlkem_param_maps[i].nid == -1)
            {
                p_scossl_decode_mlkem_param_maps[i].nid = OBJ_sn2nid(p_scossl_decode_mlkem_param_maps[i].groupName);
            }

            if (p_scossl_decode_mlkem_param_maps[i].nid == nid)
            {
                return p_scossl_decode_mlkem_param_maps[i].groupName;
            }
        }
    }

    return NULL;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_decode_key(_In_ SCOSSL_DECODE_CTX *ctx, _In_ const ASN1_OBJECT *algorithm, int selection,
                                                       _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey)
{
    const char *groupName;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if ((keyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_KEY_CTX))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    keyCtx->provCtx = ctx->provctx;

    groupName = p_scossl_decode_mlkem_obj_to_groupname(algorithm);
    if (groupName == NULL ||
        p_scossl_mlkem_keymgmt_set_group(keyCtx, groupName) != SCOSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        goto cleanup;
    }

    status = p_scossl_mlkem_keymgmt_set_encoded_key(keyCtx, selection, pbKey, cbKey);

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        OPENSSL_free(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_PrivateKeyInfo_to_mlkem(_In_ SCOSSL_DECODE_CTX *ctx, _In_ BIO *bio)
{
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    const X509_ALGOR *alg = NULL;
    const unsigned char *pbKey = NULL;
    int cbKey;
    ASN1_OCTET_STRING *p8Data = NULL;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;

    if (d2i_PKCS8_PRIV_KEY_INFO_bio(bio, &p8Info) == NULL ||
        !PKCS8_pkey_get0(NULL, &pbKey, &cbKey, &alg, p8Info) ||
        (p8Data = d2i_ASN1_OCTET_STRING(NULL, &pbKey, cbKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_DECODE_ERROR);
        goto cleanup;
    }

    keyCtx = p_scossl_mlkem_decode_key(ctx, alg->algorithm, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                       ASN1_STRING_get0_data(p8Data), ASN1_STRING_length(p8Data));

cleanup:
    ASN1_OCTET_STRING_free(p8Data);
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return keyCtx;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mlkem(_In_ SCOSSL_DECODE_CTX *ctx, _In_ BIO *bio)
{
    SUBJECT_PUBKEY_INFO *subjPubKeyInfo;
    SCOSSL_MLKEM_KEY_CTX *keyCtx = NULL;

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

    keyCtx = p_scossl_mlkem_decode_key(ctx, subjPubKeyInfo->algorithm->algorithm, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                       subjPubKeyInfo->subjectPublicKey->data, subjPubKeyInfo->subjectPublicKey->length);

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