//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_encode_common.h"
#include "keymgmt/p_scossl_mldsa_keymgmt.h"

#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static ASN1_OBJECT *p_scossl_encode_mldsa_get_oid(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    int nid = p_scossl_mldsa_params_to_nid(keyCtx->mldsaParams);

    return nid == NID_undef ? NULL : OBJ_nid2obj(nid);
}

static PKCS8_PRIV_KEY_INFO *p_scossl_mldsa_key_to_p8info(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey;
    unsigned char *pbDer = NULL;
    int cbDer;
    ASN1_OCTET_STRING *p8Data = NULL;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    ASN1_OBJECT *p8Obj;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((p8Data = ASN1_OCTET_STRING_new()) == NULL ||
        (p8Info = PKCS8_PRIV_KEY_INFO_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED &&
        keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        goto cleanup;
    }

    if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->format, &pbKey, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if (!ASN1_OCTET_STRING_set(p8Data, pbKey, cbKey) ||
        (cbDer = i2d_ASN1_OCTET_STRING(p8Data, &pbDer)) == 0)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    if ((p8Obj = p_scossl_encode_mldsa_get_oid(keyCtx)) == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "p_scossl_encode_mldsa_get_oid returned NULL");
        goto cleanup;
    }

    if (!PKCS8_pkey_set0(p8Info, p8Obj, 0, V_ASN1_UNDEF, NULL, pbDer, cbDer))
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }
    pbDer = NULL;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        PKCS8_PRIV_KEY_INFO_free(p8Info);
        p8Info = NULL;
    }

    OPENSSL_clear_free(pbDer, cbDer);
    OPENSSL_secure_clear_free(pbKey, cbKey);
    ASN1_OCTET_STRING_free(p8Data);

    return p8Info;
}

static X509_PUBKEY *p_scossl_mldsa_key_to_pubkey(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey;
    X509_PUBKEY *pubKey = NULL;
    ASN1_OBJECT *p8Obj;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((pubKey = X509_PUBKEY_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if ((p8Obj = p_scossl_encode_mldsa_get_oid(keyCtx)) == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "p_scossl_encode_mldsa_get_oid returned NULL");
        goto cleanup;
    }

    if (!X509_PUBKEY_set0_param(pubKey, p8Obj, V_ASN1_UNDEF, NULL, pbKey, cbKey))
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }
    pbKey = NULL;

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        X509_PUBKEY_free(pubKey);
        pubKey = NULL;
    }

    OPENSSL_secure_free(pbKey);

    return pubKey;
}


static SCOSSL_STATUS p_scossl_mldsa_to_EncryptedPrivateKeyInfo(_In_ SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                               _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                               int selection,
                                                               _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs)
{
    OSSL_LIB_CTX *libctx = ctx->provctx == NULL ? NULL : ctx->provctx->libctx;
    int encodeSuccess;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    X509_SIG *p8 = NULL;
    char pbPass[PEM_BUFSIZE];
    SIZE_T cbPass = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (((selection & ctx->desc->selection) == 0))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (ctx->cipher == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        goto cleanup;
    }

    if ((p8Info = p_scossl_mldsa_key_to_p8info(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (!passphraseCb(pbPass, sizeof(pbPass), &cbPass, NULL, passphraseCbArgs))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PASSPHRASE);
        goto cleanup;
    }

    if ((p8 = PKCS8_encrypt_ex(-1, ctx->cipher, pbPass, cbPass, NULL, 0, 0, p8Info, libctx, NULL)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        goto cleanup;
    }

    if (ctx->desc->outFormat == SCOSSL_ENCODE_PEM)
    {
        encodeSuccess = PEM_write_bio_PKCS8(out, p8);
    }
    else
    {
        encodeSuccess = i2d_PKCS8_bio(out, p8);
    }

    if (!encodeSuccess)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_cleanse(pbPass, sizeof(pbPass));
    PKCS8_PRIV_KEY_INFO_free(p8Info);
    X509_SIG_free(p8);

    return ret;
}

static SCOSSL_STATUS p_scossl_mldsa_to_PrivateKeyInfo(_In_ SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                      _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                      int selection,
                                                      _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs)
{
    int encodeSuccess;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (((selection & ctx->desc->selection) == 0))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (ctx->cipher != NULL)
    {
        return p_scossl_mldsa_to_EncryptedPrivateKeyInfo(ctx, out, keyCtx, selection, passphraseCb, passphraseCbArgs);
    }

    if ((p8Info = p_scossl_mldsa_key_to_p8info(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (ctx->desc->outFormat == SCOSSL_ENCODE_PEM)
    {
        encodeSuccess = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8Info);
    }
    else
    {
        encodeSuccess = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8Info);
    }

    if (!encodeSuccess)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    PKCS8_PRIV_KEY_INFO_free(p8Info);

    return ret;
}

static SCOSSL_STATUS p_scossl_mldsa_to_SubjectPublicKeyInfo(_In_ SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                            _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                            int selection,
                                                            ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArgs)
{
    int encodeSuccess;
    X509_PUBKEY *pubKey = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (((selection & ctx->desc->selection) == 0))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if ((pubKey = p_scossl_mldsa_key_to_pubkey(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (ctx->desc->outFormat == SCOSSL_ENCODE_PEM)
    {
        encodeSuccess = PEM_write_bio_X509_PUBKEY(out, pubKey);
    }
    else
    {
        encodeSuccess = i2d_X509_PUBKEY_bio(out, pubKey);
    }

    if (!encodeSuccess)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    X509_PUBKEY_free(pubKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_mldsa_to_text(ossl_unused SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                            _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                            int selection,
                                            ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArgs)
{
    BOOL printedPrivateKey = FALSE;
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    int nid;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED &&
            keyCtx->format != SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        if (!p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, keyCtx->format, &pbKey, &cbKey))
        {
            goto cleanup;
        }

        if (keyCtx->format == SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED)
        {
            if (BIO_printf(out, "MLDSA Private-Key (512 bit private seed encoding):\nprivate-seed") <= 0)
            {
                goto cleanup;
            }
        }
        else if (BIO_printf(out, "MLDSA Private-Key (%ld bit decapsulation key encoding):\nprivate-key", cbKey * 8) <= 0)
        {
            goto cleanup;
        }

        if (p_scossl_encode_write_key_bytes(pbKey, cbKey, out) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        printedPrivateKey = TRUE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);
        pbKey = NULL;
        cbKey = 0;

        if (!p_scossl_mldsa_keymgmt_get_encoded_key(keyCtx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pbKey, &cbKey))
        {
            goto cleanup;
        }

        if ((!printedPrivateKey && BIO_printf(out, "MLDSA Public-Key (%ld bit):\n", cbKey * 8) <= 0) ||
                 BIO_printf(out, "public-key") <= 0)
        {
            goto cleanup;
        }

        if (p_scossl_encode_write_key_bytes(pbKey, cbKey, out) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    nid = p_scossl_mldsa_params_to_nid(keyCtx->mldsaParams);

    if (nid != NID_undef &&
        BIO_printf(out, "ALGORITHM: %s\n", OBJ_nid2ln(nid)) <= 0)
    {
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_encoder_import_object(ossl_unused SCOSSL_ENCODE_CTX *ctx, SYMCRYPT_MLDSA_PARAMS mldsaParams,
                                                                  int selection, _In_ const OSSL_PARAM params[])
{
    SCOSSL_MLDSA_KEY_CTX *keyCtx = p_scossl_mldsa_keymgmt_new_ctx(mldsaParams);

    if (keyCtx != NULL &&
        p_scossl_mldsa_keymgmt_import(keyCtx, selection, params) != SCOSSL_SUCCESS)
    {
        p_scossl_mldsa_keymgmt_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_mldsa_text_desc = {
    0,
    SCOSSL_ENCODE_TEXT,
    (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_text};

static SCOSSL_ENCODE_CTX *p_scossl_mldsa_to_text_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return p_scossl_encode_newctx(provctx, &p_scossl_mldsa_text_desc);
}

#define MAKE_MLDSA_ASN1_ENCODER(encoderType)                                                                        \
    static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_mldsa_##encoderType##_der_desc = {                                   \
        select_##encoderType,                                                                                       \
        SCOSSL_ENCODE_DER,                                                                                          \
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_##encoderType};                                               \
                                                                                                                    \
    static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_mldsa_##encoderType##_pem_desc = {                                   \
        select_##encoderType,                                                                                       \
        SCOSSL_ENCODE_PEM,                                                                                          \
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_##encoderType};                                               \
                                                                                                                    \
    static SCOSSL_ENCODE_CTX *p_scossl_mldsa_to_##encoderType##_der_newctx(_In_ SCOSSL_PROVCTX *provctx)            \
    {                                                                                                               \
        return p_scossl_encode_newctx(provctx, &p_scossl_mldsa_##encoderType##_der_desc);                           \
    }                                                                                                               \
                                                                                                                    \
    static SCOSSL_ENCODE_CTX *p_scossl_mldsa_to_##encoderType##_pem_newctx(_In_ SCOSSL_PROVCTX *provctx)            \
    {                                                                                                               \
        return p_scossl_encode_newctx(provctx, &p_scossl_mldsa_##encoderType##_pem_desc);                           \
    }                                                                                                               \
                                                                                                                    \
    static BOOL p_scossl_der_to_mldsa_##encoderType##_does_selection(ossl_unused void *provctx, int selection)      \
    {                                                                                                               \
        return p_scossl_encode_does_selection(&p_scossl_mldsa_##encoderType##_der_desc, selection);                 \
    }

#define MLDSA_ENCODER_DISPATCH(encoderType, bits)                                                                   \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_to_##encoderType##_der_functions[] = {                               \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mldsa_to_##encoderType##_der_newctx},                   \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                       \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                         \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},               \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_mldsa_##encoderType##_does_selection},   \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                                \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mldsa##bits##_encoder_import_object},            \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                       \
        {0, NULL}};                                                                                                 \
                                                                                                                    \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_to_##encoderType##_pem_functions[] = {                               \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mldsa_to_##encoderType##_pem_newctx},                   \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                       \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                         \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},               \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_mldsa_##encoderType##_does_selection},   \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                                \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mldsa##bits##_encoder_import_object},            \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                       \
        {0, NULL}};

#define MAKE_MLDSA_VARIANT_ENCODER_FUNCTIONS(bits)                                                                  \
    static SCOSSL_MLDSA_KEY_CTX  *p_scossl_mldsa##bits##_encoder_import_object(_In_ SCOSSL_ENCODE_CTX *ctx,         \
                                                                               int selection,                       \
                                                                               _In_ const OSSL_PARAM params[])      \
    {                                                                                                               \
        return p_scossl_mldsa_encoder_import_object(ctx, SYMCRYPT_MLDSA_PARAMS_MLDSA##bits, selection, params);     \
    }                                                                                                               \
                                                                                                                    \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_to_text_functions[] = {                                              \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mldsa_to_text_newctx},                                  \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                       \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                                \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mldsa##bits##_encoder_import_object},            \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                       \
        {0, NULL}};                                                                                                 \
                                                                                                                    \
    MLDSA_ENCODER_DISPATCH(PrivateKeyInfo, bits)                                                                    \
    MLDSA_ENCODER_DISPATCH(EncryptedPrivateKeyInfo, bits)                                                           \
    MLDSA_ENCODER_DISPATCH(SubjectPublicKeyInfo, bits)

MAKE_MLDSA_ASN1_ENCODER(PrivateKeyInfo)
MAKE_MLDSA_ASN1_ENCODER(EncryptedPrivateKeyInfo)
MAKE_MLDSA_ASN1_ENCODER(SubjectPublicKeyInfo)

MAKE_MLDSA_VARIANT_ENCODER_FUNCTIONS(44)
MAKE_MLDSA_VARIANT_ENCODER_FUNCTIONS(65)
MAKE_MLDSA_VARIANT_ENCODER_FUNCTIONS(87)

#ifdef __cplusplus
}
#endif