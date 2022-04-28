//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_rsa.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

static PCSYMCRYPT_HASH scossl_get_symcrypt_hash_algorithm(int type)
{
    if (type == NID_md5)
        return SymCryptMd5Algorithm;
    if (type == NID_sha1)
        return SymCryptSha1Algorithm;
    if (type == NID_sha256)
        return SymCryptSha256Algorithm;
    if (type == NID_sha384)
        return SymCryptSha384Algorithm;
    if (type == NID_sha512)
        return SymCryptSha512Algorithm;
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support Mac algorithm %d", type);
    return NULL;
}

static size_t scossl_get_expected_tbs_length(int type)
{
    if (type == NID_md5)
        return 16;
    if (type == NID_sha1)
        return 20;
    if (type == NID_sha256)
        return 32;
    if (type == NID_sha384)
        return 48;
    if (type == NID_sha512)
        return 64;
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support Mac algorithm %d", type);
    return -1;
}

SCOSSL_STATUS scossl_rsapss_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    BN_ULONG cbModulus = 0;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    size_t cbResult = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int ret = SCOSSL_FAILURE;
    SCOSSL_RSA_KEY_CONTEXT *keyCtx = NULL;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
    EVP_MD *messageDigest;
    EVP_MD *mgf1Digest;
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

    if( cbSalt == RSA_PSS_SALTLEN_DIGEST )
    {
        cbSalt = EVP_MD_size(messageDigest);
    }
    else if ( (cbSalt == RSA_PSS_SALTLEN_MAX_SIGN) || (cbSalt == RSA_PSS_SALTLEN_MAX) )
    {
        cbSalt = RSA_size(rsa) - EVP_MD_size(messageDigest) - 2;
    }
    
    if ( (cbSalt < 0) || (cbSalt > (RSA_size(rsa) - EVP_MD_size(messageDigest) - 2)) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_PASSED_INVALID_ARGUMENT,
            "Invalid cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);
    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_UNSUPPORTED;
        }
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModulus;
    if( siglen != NULL )
    {
        *siglen = cbResult;
    }
    if( sig == NULL )
    {
        ret = SCOSSL_SUCCESS;
        goto cleanup; // Not error - this can be called with NULL parameter for siglen
    }

    scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(type);
    expectedTbsLength = scossl_get_expected_tbs_length(type);
    if( !scossl_mac_algo || expectedTbsLength == (SIZE_T) -1 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "Unknown type: %d. Size: %d.", type, tbslen);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if( type == NID_md5 )
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
            "Using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if( type == NID_sha1 )
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
            "Using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if( tbslen != expectedTbsLength )
    {
        goto cleanup;
    }

    scError = SymCryptRsaPssSign(
                keyCtx->key,
                tbs,
                tbslen,
                scossl_mac_algo,
                cbSalt,
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                sig,
                siglen != NULL ? (*siglen) : 0,
                &cbResult);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsaPssSign failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    return ret;
}

SCOSSL_STATUS scossl_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    int ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_RSA_KEY_CONTEXT *keyCtx = NULL;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
    EVP_MD *messageDigest;
    EVP_MD *mgf1Digest;
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

    if( cbSalt == RSA_PSS_SALTLEN_DIGEST )
    {
        cbSalt = EVP_MD_size(messageDigest);
    }
    else if ( cbSalt == RSA_PSS_SALTLEN_MAX )
    {
        cbSalt = RSA_size(rsa) - EVP_MD_size(messageDigest) - 2;
    }
    else if ( cbSalt == RSA_PSS_SALTLEN_AUTO )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support RSA_PSS_SALTLEN_AUTO saltlen");
        return SCOSSL_UNSUPPORTED;
    }
    
    if ( (cbSalt < 0) || (cbSalt > (RSA_size(rsa) - EVP_MD_size(messageDigest) - 2)) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, ERR_R_PASSED_INVALID_ARGUMENT,
            "Invalid cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);
    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_UNSUPPORTED;
        }
    }

    if( sig == NULL )
    {
        goto cleanup;
    }

    scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(type);
    expectedTbsLength = scossl_get_expected_tbs_length(type);
    if( !scossl_mac_algo || expectedTbsLength == (SIZE_T) -1 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "Unknown type: %d. Size: %d.", type, tbslen);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if( type == NID_md5 )
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
            "Using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if( type == NID_sha1 )
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
            "Using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if( tbslen != expectedTbsLength )
    {
        goto cleanup;
    }

    scError = SymCryptRsaPssVerify(
                keyCtx->key,
                tbs,
                tbslen,
                sig,
                siglen,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                scossl_mac_algo,
                cbSalt,
                0);

    if( scError != SYMCRYPT_NO_ERROR )
    {
        if( scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptRsaPssVerify returned unexpected error", scError);
        }
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    return ret;
}


#ifdef __cplusplus
}
#endif