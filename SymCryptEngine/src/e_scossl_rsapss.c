//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl_rsa.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_STATUS e_scossl_rsapss_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY* pkey = NULL;
    const RSA* rsa = NULL;
    SCOSSL_RSA_KEY_CTX *keyCtx = NULL;
    const EVP_MD *messageDigest;
    const EVP_MD *mgf1Digest;
    int type = 0;
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_signature_md(ctx, &messageDigest) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_OPERATION_FAIL,
            "Failed to get messageDigest");
        return SCOSSL_UNSUPPORTED;
    }
    if( EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1Digest) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_OPERATION_FAIL,
            "Failed to get mgf1Digest");
        return SCOSSL_UNSUPPORTED;
    }
    type = EVP_MD_type(messageDigest);

    if( type != EVP_MD_type(mgf1Digest) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "messageDigest and mgf1Digest do not match");
        return SCOSSL_UNSUPPORTED;
    }

    if( ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL) ||
        ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "Failed to get RSA key from ctx");
        return SCOSSL_UNSUPPORTED;
    }

    if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_OPERATION_FAIL,
            "Failed to get cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);
    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        return SCOSSL_FAILURE;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_UNSUPPORTED;
        }
    }

    return scossl_rsapss_sign(keyCtx, type, cbSalt, tbs, tbslen, sig, (SIZE_T*)siglen);
}

SCOSSL_STATUS e_scossl_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY* pkey = NULL;
    const RSA* rsa = NULL;
    SCOSSL_RSA_KEY_CTX *keyCtx = NULL;
    const EVP_MD *messageDigest;
    const EVP_MD *mgf1Digest;
    int type = 0;
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_signature_md(ctx, &messageDigest) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, ERR_R_OPERATION_FAIL,
            "Failed to get messageDigest");
        return SCOSSL_UNSUPPORTED;
    }
    if( EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1Digest) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, ERR_R_OPERATION_FAIL,
            "Failed to get mgf1Digest");
        return SCOSSL_UNSUPPORTED;
    }
    type = EVP_MD_type(messageDigest);

    if( type != EVP_MD_type(mgf1Digest) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "messageDigest and mgf1Digest do not match");
        return SCOSSL_UNSUPPORTED;
    }

    if( ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL) ||
        ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "Failed to get RSA key from ctx");
        return SCOSSL_UNSUPPORTED;
    }

    if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, ERR_R_OPERATION_FAIL,
            "Failed to get cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);
    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        return SCOSSL_FAILURE;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_UNSUPPORTED;
        }
    }

    if( sig == NULL )
    {
        return SCOSSL_FAILURE;
    }

    return scossl_rsapss_verify(keyCtx, type, cbSalt, tbs, tbslen, sig, siglen);
}


#ifdef __cplusplus
}
#endif