//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"
#include "e_scossl_hmac.h"

#include <openssl/hmac.h>
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_init(EVP_PKEY_CTX *ctx)
{
    SCOSSL_MAC_CTX *e_scossl_hmac_context;

    if ((e_scossl_hmac_context = OPENSSL_zalloc(sizeof(SCOSSL_MAC_CTX))) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HMAC_INIT, ERR_R_MALLOC_FAILURE,
                         "OPENSSL_zalloc returned NULL");
        return SCOSSL_FAILURE;
    }

    EVP_PKEY_CTX_set_data(ctx, e_scossl_hmac_context);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
void e_scossl_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
    SCOSSL_MAC_CTX *e_scossl_hmac_context = EVP_PKEY_CTX_get_data(ctx);
    scossl_mac_freectx(e_scossl_hmac_context);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

// The const modifier on src was added in OpenSSL 3, but is not expected
// in OpenSSL 1.1.1. Building the Engine for OpenSSL 1.1.1 will generate
// an incompatible pointer warning that can be safely ignored.
_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    SCOSSL_MAC_CTX *src_ctx, *dst_ctx;

    if ((src_ctx = EVP_PKEY_CTX_get_data(src)) == NULL)
    {
        return SCOSSL_FAILURE;
    }

    if ((dst_ctx = scossl_mac_dupctx(src_ctx)) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HMAC_INIT, ERR_R_MALLOC_FAILURE,
                         "scossl_hmac_dupctx returned NULL");
        return SCOSSL_FAILURE;
    }

    EVP_PKEY_CTX_set_data(dst, dst_ctx);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EVP_PKEY *pkey;
    ASN1_OCTET_STRING *key;
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_MAC_CTX *e_scossl_hmac_context = EVP_PKEY_CTX_get_data(ctx);

    switch (type)
    {
    case EVP_PKEY_CTRL_MD:
        // Expecting p2 of type EVP_MD* specifying the hash function to be used in HMAC
        if (p2 == NULL) {
            ret = SCOSSL_FAILURE;
            break;
        }
        ret = scossl_mac_set_hmac_md(e_scossl_hmac_context, p2);
        break;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
        // p2 : pointer to the buffer containing the HMAC key, must not be NULL.
        // p1 : length of the key in bytes. p1 = -1 indicates p2 is a null-terminated string.
        ret = scossl_mac_set_mac_key(e_scossl_hmac_context, p2, p1);
        break;
    case EVP_PKEY_CTRL_DIGESTINIT:
        if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL ||
            (key = EVP_PKEY_get0(pkey)) == NULL)
        {
            ret = SCOSSL_FAILURE;
            break;
        }

        ret = scossl_mac_init(e_scossl_hmac_context, key->data, key->length);
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HMAC_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support ctrl type (%d)", type);
        ret =  SCOSSL_UNSUPPORTED;
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_MAC_CTX *e_scossl_hmac_context = EVP_PKEY_CTX_get_data(ctx);
    ASN1_OCTET_STRING *key;

    if (e_scossl_hmac_context->pbKey == NULL)
    {
        ret = SCOSSL_FAILURE;
        goto end;
    }

    if ((key = ASN1_OCTET_STRING_new()) == NULL ||
        !ASN1_OCTET_STRING_set(key, e_scossl_hmac_context->pbKey, e_scossl_hmac_context->cbKey))
    {
        ret = SCOSSL_FAILURE;
        goto end;
    }

    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, key);

end:

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return scossl_mac_update(EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx)), data, count);
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdctx)
{
    EVP_MD_CTX_set_flags(mdctx, EVP_MD_CTX_FLAG_NO_INIT);

    EVP_MD_CTX_set_update_fn(mdctx, e_scossl_hmac_update);

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS e_scossl_hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mdctx)
{
    return scossl_mac_final(EVP_PKEY_CTX_get_data(ctx), sig, siglen, *siglen);
}

#ifdef __cplusplus
}
#endif
