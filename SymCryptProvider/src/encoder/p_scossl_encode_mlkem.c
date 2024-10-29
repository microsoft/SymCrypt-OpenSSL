//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_names.h"
#include "encoder/p_scossl_encode_common.h"
#include "keymgmt/p_scossl_mlkem_keymgmt.h"

#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const OSSL_DISPATCH p_scossl_mlkem_keymgmt_functions[];

static const char *p_scossl_encode_mlkem_params_to_name(SYMCRYPT_MLKEM_PARAMS params)
{
    switch (params)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        return SCOSSL_SN_MLKEM512;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        return SCOSSL_SN_MLKEM768;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        return SCOSSL_SN_MLKEM1024;
    default:
        break;
    }

    return NULL;
}

static ASN1_OBJECT *p_scossl_encode_get_mlkem_oid(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    int nid = NID_undef;

    switch (keyCtx->params)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        nid = OBJ_sn2nid(SCOSSL_SN_MLKEM512);
        break;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        nid = OBJ_sn2nid(SCOSSL_SN_MLKEM768);
        break;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        nid = OBJ_sn2nid(SCOSSL_SN_MLKEM1024);
        break;
    default:
        break;
    }

    if (nid != NID_undef)
    {
        return OBJ_nid2obj(nid);
    }

    return NULL;
}

static PKCS8_PRIV_KEY_INFO *p_scossl_mlkem_key_to_p8info(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey;
    unsigned char *pbDer = NULL;
    int cbDer;
    ASN1_OCTET_STRING *p8Data = NULL;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    ASN1_OBJECT *p8Obj = NULL;
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

    if (p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, &pbKey, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if (!ASN1_OCTET_STRING_set(p8Data, pbKey, cbKey) ||
        (cbDer = i2d_ASN1_OCTET_STRING(p8Data, &pbDer)) == 0)
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    if ((p8Obj = p_scossl_encode_get_mlkem_oid(keyCtx)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (!PKCS8_pkey_set0(p8Info, p8Obj, 0, V_ASN1_UNDEF, NULL, pbDer, cbDer))
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        PKCS8_PRIV_KEY_INFO_free(p8Info);
        OPENSSL_free(pbDer);
        p8Info = NULL;
    }

    ASN1_OCTET_STRING_free(p8Data);
    ASN1_OBJECT_free(p8Obj);
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return p8Info;
}

static X509_PUBKEY *p_scossl_mlkem_key_to_pubkey(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    PBYTE pbKey = NULL;
    SIZE_T cbKey;
    X509_PUBKEY *pubKey = NULL;
    ASN1_OBJECT *p8Obj = NULL;
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

    if (p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, &pbKey, &cbKey) != SCOSSL_SUCCESS)
    {
        goto cleanup;
    }

    if ((p8Obj = p_scossl_encode_get_mlkem_oid(keyCtx)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (!X509_PUBKEY_set0_param(pubKey, p8Obj, V_ASN1_NULL, NULL, pbKey, cbKey))
    {
        ERR_raise(ERR_LIB_PROV, ASN1_R_ENCODE_ERROR);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        if (pubKey == NULL)
        {
            OPENSSL_secure_free(pbKey);
            ASN1_OBJECT_free(p8Obj);
        }
        X509_PUBKEY_free(pubKey);
        pubKey = NULL;
    }

    return pubKey;
}


static SCOSSL_STATUS p_scossl_mlkem_to_EncryptedPrivateKeyInfo(_In_ SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                               _In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                               ossl_unused int selection,
                                                               _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs,
                                                               BOOL encodeToPem)
{
    int encodeSuccess;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    X509_SIG *p8 = NULL;
    char pbPass[PEM_BUFSIZE];
    SIZE_T cbPass = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->cipher == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        goto cleanup;
    }

    if ((p8Info = p_scossl_mlkem_key_to_p8info(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (!passphraseCb(pbPass, sizeof(pbPass), &cbPass, NULL, passphraseCbArgs))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PASSPHRASE);
        goto cleanup;
    }

    if ((p8 = PKCS8_encrypt_ex(-1, ctx->cipher, pbPass, cbPass, NULL, 0, 0, p8Info, ctx->provctx->libctx, NULL)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        goto cleanup;
    }

    if (encodeToPem)
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

static SCOSSL_STATUS p_scossl_mlkem_to_PrivateKeyInfo(_In_ SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                      _In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                      ossl_unused int selection,
                                                      _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs,
                                                      BOOL encodeToPem)
{
    int encodeSuccess;
    PKCS8_PRIV_KEY_INFO *p8Info = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->cipherIntent)
    {
        return p_scossl_mlkem_to_EncryptedPrivateKeyInfo(ctx, out, keyCtx, selection, passphraseCb, passphraseCbArgs, encodeToPem);
    }

    if ((p8Info = p_scossl_mlkem_key_to_p8info(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (encodeToPem)
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

static SCOSSL_STATUS p_scossl_mlkem_to_SubjectPublicKeyInfo(ossl_unused SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                                            _In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                            ossl_unused int selection,
                                                            ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArgs,
                                                            BOOL encodeToPem)
{
    int encodeSuccess;
    X509_PUBKEY *pubKey = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if ((pubKey = p_scossl_mlkem_key_to_pubkey(keyCtx)) == NULL)
    {
        goto cleanup;
    }

    if (encodeToPem)
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

static SCOSSL_STATUS p_scossl_mlkem_to_text(ossl_unused SCOSSL_ENCODE_CTX *ctx, _Inout_ BIO *out,
                                            _In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                            int selection,
                                            ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArgs,
                                            ossl_unused BOOL encodeToPem)
{
    BOOL printPrivateSeed = FALSE;
    BOOL printDecapsulationKey = FALSE;
    BOOL printEncapsulationKey = FALSE;
    const char *paramName = p_scossl_encode_mlkem_params_to_name(keyCtx->params);
    PBYTE pbKey = NULL;
    SIZE_T cbKey;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key == NULL ||
        paramName == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (keyCtx->format == SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto cleanup;
        }

        printDecapsulationKey = TRUE;
        printEncapsulationKey = TRUE;
    }
    else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        printEncapsulationKey = TRUE;
    }

    if (printDecapsulationKey)
    {
        // Try to get the private seed. Otherwise this key was encoded using the whole decapsulation key.
        if (p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, &pbKey, &cbKey))
        {
            if (BIO_printf(out, "MLKEM Decapsulation-Key (512 bit private seed encoding):\n") <= 0)
            {
                goto cleanup;
            }

            if (BIO_printf(out, "private-seed") <= 0 ||
                p_scossl_encode_write_key_bytes(pbKey, cbKey, out) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            printPrivateSeed = TRUE;
        }

        OPENSSL_secure_clear_free(pbKey, cbKey);
        if (!p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &pbKey, &cbKey))
        {
            goto cleanup;
        }

        if (!printPrivateSeed &&
            BIO_printf(out, "MLKEM Decapsulation-Key (%ld bit decapsulation key encoding):", cbKey * 8) <= 0)
        {
            goto cleanup;
        }

        if (BIO_printf(out, "decapsulation-key") <= 0 ||
            p_scossl_encode_write_key_bytes(pbKey, cbKey, out) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    if (printEncapsulationKey)
    {
        OPENSSL_secure_clear_free(pbKey, cbKey);
        if (!p_scossl_mlkem_keymgmt_get_encoded_key(keyCtx, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, &pbKey, &cbKey))
        {
            goto cleanup;
        }

        if (!printDecapsulationKey && // Implies no private seed
            BIO_printf(out, "MLKEM Encapsulation-Key (%ld bit):", cbKey * 8) <= 0)
        {
            goto cleanup;
        }

        if (BIO_printf(out, "encapsulation-key") <= 0 ||
            p_scossl_encode_write_key_bytes(pbKey, cbKey, out) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    if (BIO_printf(out, "PARAMETER SET: %s\n", paramName) <= 0)
    {
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbKey, cbKey);

    return ret;
}

static SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_encoder_import_object(_In_ SCOSSL_ENCODE_CTX *ctx,
                                                                  int selection, _In_ const OSSL_PARAM params[])
{
    SCOSSL_MLKEM_KEY_CTX *keyCtx = p_scossl_mlkem_keymgmt_new_ctx(ctx->provctx);

    if (keyCtx != NULL)
    {
        p_scossl_mlkem_keymgmt_import(keyCtx, selection, params);
    }

    return keyCtx;
}

#define MAKE_MLKEM_ENCODER(decoderType)                                                                           \
    static SCOSSL_ENCODE_CTX *p_scossl_mlkem_to_##decoderType##_der_newctx(_In_ SCOSSL_PROVCTX *provctx)          \
    {                                                                                                             \
        return p_scossl_encode_newctx(provctx, select_##decoderType,                                              \
            SCOSSL_ENCODE_DER,                                                                                    \
            (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mlkem_to_##decoderType);                                         \
    }                                                                                                             \
                                                                                                                  \
    static SCOSSL_ENCODE_CTX *p_scossl_mlkem_to_##decoderType##_pem_newctx(_In_ SCOSSL_PROVCTX *provctx)          \
    {                                                                                                             \
        return p_scossl_encode_newctx(provctx, select_##decoderType,                                              \
            SCOSSL_ENCODE_PEM,                                                                                    \
            (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mlkem_to_##decoderType);                                         \
    }                                                                                                             \
                                                                                                                  \
    static BOOL p_scossl_der_to_mlkem_##decoderType##_does_selection(ossl_unused void *provctx, int selection)    \
    {                                                                                                             \
        return p_scossl_encode_does_selection(select_##decoderType, selection);                                   \
    }                                                                                                             \
                                                                                                                  \
    const OSSL_DISPATCH p_scossl_mlkem_to_##decoderType##_der_functions[] = {                                     \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mlkem_to_##decoderType##_der_newctx},                 \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                     \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                       \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},             \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_mlkem_##decoderType##_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                              \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mlkem_encoder_import_object},                  \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},                     \
        {0, NULL}};                                                                                               \
                                                                                                                  \
    const OSSL_DISPATCH p_scossl_mlkem_to_##decoderType##_pem_functions[] = {                                     \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mlkem_to_##decoderType##_pem_newctx},                 \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                     \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                       \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},             \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_mlkem_##decoderType##_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                              \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mlkem_encoder_import_object},                  \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},                     \
        {0, NULL}};

MAKE_MLKEM_ENCODER(PrivateKeyInfo)
MAKE_MLKEM_ENCODER(EncryptedPrivateKeyInfo)
MAKE_MLKEM_ENCODER(SubjectPublicKeyInfo)

static SCOSSL_ENCODE_CTX *p_scossl_mlkem_to_text_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return p_scossl_encode_newctx(provctx, 0,
        SCOSSL_ENCODE_TEXT,
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mlkem_to_text);
}

const OSSL_DISPATCH p_scossl_mlkem_to_text_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_mlkem_to_text_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_mlkem_encoder_import_object},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mlkem_keymgmt_free_key_ctx},
    {0, NULL}};

#ifdef __cplusplus
}
#endif