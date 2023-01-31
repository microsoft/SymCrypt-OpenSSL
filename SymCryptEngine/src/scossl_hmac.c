//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hmac.h"
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    SYMCRYPT_MAC_EXPANDED_KEY   expandedKey;
    SYMCRYPT_MAC_STATE          macState;
    PCSYMCRYPT_MAC              mac;
    ASN1_OCTET_STRING           key;
} SCOSSL_HMAC_PKEY_CTX;


static PCSYMCRYPT_MAC e_scossl_get_symcrypt_hmac_algorithm( _In_ const EVP_MD *evp_md )
{
    int type = EVP_MD_type(evp_md);

    if (type == NID_sha1)
        return SymCryptHmacSha1Algorithm;
    if (type == NID_sha256)
        return SymCryptHmacSha256Algorithm;
    if (type == NID_sha384)
        return SymCryptHmacSha384Algorithm;
    if (type == NID_sha512)
        return SymCryptHmacSha512Algorithm;
 
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support hash algorithm %d", type);
    return NULL;
}


SCOSSL_STATUS e_scossl_hmac_init(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context;
    
    if ((e_scossl_hmac_context = OPENSSL_zalloc(sizeof(*e_scossl_hmac_context))) == NULL) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HMAC_INIT, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL");
        return SCOSSL_FAILURE;
    }
    
    EVP_PKEY_CTX_set_data(ctx, e_scossl_hmac_context);

    return SCOSSL_SUCCESS;
}


void e_scossl_hmac_cleanup(_Inout_ EVP_PKEY_CTX *ctx)
{
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context = (SCOSSL_HMAC_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    
    if (!e_scossl_hmac_context) {
        return;
    }

    OPENSSL_clear_free(e_scossl_hmac_context->key.data, e_scossl_hmac_context->key.length);
    OPENSSL_clear_free(e_scossl_hmac_context, sizeof(*e_scossl_hmac_context));

    EVP_PKEY_CTX_set_data(ctx, NULL);
}


SCOSSL_STATUS e_scossl_hmac_copy(_Out_ EVP_PKEY_CTX *dst, _In_ EVP_PKEY_CTX *src)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_HMAC_PKEY_CTX *src_ctx, *dst_ctx;
    ASN1_OCTET_STRING *pkey;

    ret = e_scossl_hmac_init(dst);

    if (ret != SCOSSL_SUCCESS) {
        goto end;
    }

    src_ctx = EVP_PKEY_CTX_get_data(src);

    dst_ctx = EVP_PKEY_CTX_get_data(dst);

    if(!src_ctx || !dst_ctx) {

        ret = SCOSSL_FAILURE;
        goto cleanup;
    }

    if(src_ctx->key.data) {

        pkey = ASN1_OCTET_STRING_dup(&src_ctx->key);

        if(!pkey) {
            ret = SCOSSL_FAILURE;
            goto cleanup;
        }

        dst_ctx->key = *pkey;
    }
    else {

        dst_ctx->key.data = NULL;
        dst_ctx->key.length = 0;
    }

    dst_ctx->mac = src_ctx->mac;

    // Copy the expanded key and mac state
    if(src_ctx->mac == SymCryptHmacSha1Algorithm) {

        SymCryptHmacSha1KeyCopy(&src_ctx->expandedKey.sha1Key, 
                                &dst_ctx->expandedKey.sha1Key);

        SymCryptHmacSha1StateCopy(  &src_ctx->macState.sha1State, 
                                    &dst_ctx->expandedKey.sha1Key, 
                                    &dst_ctx->macState.sha1State);
    }
    else if(src_ctx->mac == SymCryptHmacSha256Algorithm) {

        SymCryptHmacSha256KeyCopy(  &src_ctx->expandedKey.sha256Key, 
                                    &dst_ctx->expandedKey.sha256Key);

        SymCryptHmacSha256StateCopy(&src_ctx->macState.sha256State, 
                                    &dst_ctx->expandedKey.sha256Key, 
                                    &dst_ctx->macState.sha256State);
    }
    else if(src_ctx->mac == SymCryptHmacSha384Algorithm) {

        SymCryptHmacSha384KeyCopy(  &src_ctx->expandedKey.sha384Key, 
                                    &dst_ctx->expandedKey.sha384Key);

        SymCryptHmacSha384StateCopy(&src_ctx->macState.sha384State, 
                                    &dst_ctx->expandedKey.sha384Key, 
                                    &dst_ctx->macState.sha384State);
    }
    else if(src_ctx->mac == SymCryptHmacSha512Algorithm) {

        SymCryptHmacSha512KeyCopy(  &src_ctx->expandedKey.sha512Key, 
                                    &dst_ctx->expandedKey.sha512Key);

        SymCryptHmacSha512StateCopy(&src_ctx->macState.sha512State, 
                                    &dst_ctx->expandedKey.sha512Key, 
                                    &dst_ctx->macState.sha512State);
    }

cleanup:

    if(ret != SCOSSL_SUCCESS) {
        e_scossl_hmac_cleanup(dst);
    }

end:

    return ret;
}


SCOSSL_STATUS e_scossl_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context = (SCOSSL_HMAC_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey;
    ASN1_OCTET_STRING *key;


    switch (type) {

    case EVP_PKEY_CTRL_MD:
        // Expecting p2 of type EVP_MD* specifying the hash function to be used in HMAC
        if (p2 == NULL) {
            ret = SCOSSL_FAILURE;
            break;
        }
        e_scossl_hmac_context->mac = e_scossl_get_symcrypt_hmac_algorithm((const EVP_MD*)p2);
        break;

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        // p2 : pointer to the buffer containing the HMAC key, must not be NULL.
        // p1 : length of the key in bytes. p1 = -1 indicates p2 is a null-terminated string.
        if (p1 < -1 || !p2) {
            ret = SCOSSL_FAILURE;
            break;
        }

        if(e_scossl_hmac_context->key.data) {
            OPENSSL_clear_free(e_scossl_hmac_context->key.data, e_scossl_hmac_context->key.length);
        }

        if(!ASN1_OCTET_STRING_set(&e_scossl_hmac_context->key, p2, p1)) {
            ret = SCOSSL_FAILURE;
            break;
        }
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:

        pkey = EVP_PKEY_CTX_get0_pkey(ctx);

        if(!pkey) {
            ret = SCOSSL_FAILURE;
            break;
        }

        key = EVP_PKEY_get0(pkey);

        if(!key) {
            ret = SCOSSL_FAILURE;
            break;
        }

        if(e_scossl_hmac_context->mac->expandKeyFunc(&e_scossl_hmac_context->expandedKey, 
                                                    key->data,
                                                    key->length) != SYMCRYPT_NO_ERROR) {

            ret = SCOSSL_FAILURE;
            break;
        }
        e_scossl_hmac_context->mac->initFunc(&e_scossl_hmac_context->macState, &e_scossl_hmac_context->expandedKey);
        break;

    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_HMAC_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support ctrl type (%d)", type);
        ret =  SCOSSL_UNSUPPORTED;
    }

    return ret;
}

SCOSSL_STATUS e_scossl_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context = (SCOSSL_HMAC_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    ASN1_OCTET_STRING *key;

    if(!e_scossl_hmac_context->key.data) {
        ret = SCOSSL_FAILURE;
        goto end;
    }

    key =  ASN1_OCTET_STRING_dup(&e_scossl_hmac_context->key);

    if(!key) {
        ret = SCOSSL_FAILURE;
        goto end;
    }

    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, key);
   
end:

    return ret;
}

SCOSSL_STATUS e_scossl_hmac_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context = (SCOSSL_HMAC_PKEY_CTX *)EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx));

    e_scossl_hmac_context->mac->appendFunc(&e_scossl_hmac_context->macState, data, count);

    return SCOSSL_SUCCESS;
}


SCOSSL_STATUS e_scossl_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mdctx)
{
    EVP_MD_CTX_set_flags(mdctx, EVP_MD_CTX_FLAG_NO_INIT);

    EVP_MD_CTX_set_update_fn(mdctx, e_scossl_hmac_update);

    return SCOSSL_SUCCESS;
}


SCOSSL_STATUS e_scossl_hmac_signctx(_Inout_ EVP_PKEY_CTX *ctx, _Out_ unsigned char *sig, _Out_ size_t *siglen, _In_ EVP_MD_CTX *mdctx)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SCOSSL_HMAC_PKEY_CTX *e_scossl_hmac_context = (SCOSSL_HMAC_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);

    if(!sig) {

        *siglen = e_scossl_hmac_context->mac->resultSize;
        goto end;
    }

    if(*siglen < e_scossl_hmac_context->mac->resultSize) {

        ret = SCOSSL_FAILURE;
        goto end;
    }

    e_scossl_hmac_context->mac->resultFunc(&e_scossl_hmac_context->macState, sig);
    
    *siglen = e_scossl_hmac_context->mac->resultSize;

end:

    return ret;
}




#ifdef __cplusplus
}
#endif
