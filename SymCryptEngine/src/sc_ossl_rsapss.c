//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_rsa.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

static PCSYMCRYPT_HASH GetSymCryptHashAlgorithm(int type)
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
    SC_OSSL_LOG_ERROR("SymCrypt engine does not support Mac algorithm %d", type);
    return NULL;
}

static size_t GetExpectedTbsLength(int type)
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
    SC_OSSL_LOG_ERROR("SymCrypt engine does not support Mac algorithm %d", type);
    return -1;
}

SCOSSL_STATUS sc_ossl_rsapss_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    BN_ULONG cbModulus = 0;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    int ret = -1;
    // We should have this localKeyCtx kept in some extension to EVP_PKEY_CTX
    // Currently not sure how to achieve this with 1.1.1 APIs (EVP_PKEY_get_ex_data is introduced in OpenSSL 3.0)
    SC_OSSL_RSA_KEY_CONTEXT localKeyCtx;
    PCSYMCRYPT_HASH sc_ossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
    EVP_MD *messageDigest;
    EVP_MD *mgf1Digest;
    int type = 0;
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_signature_md(ctx, &messageDigest) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get messageDigest");
        return -2;
    }
    if( EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1Digest) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get mgf1Digest");
        return -2;
    }
    type = EVP_MD_type(messageDigest);

    if( type != EVP_MD_type(mgf1Digest) )
    {
        SC_OSSL_LOG_ERROR("messageDigest and mgf1Digest do not match");
        return -2;
    }

    if( ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL) ||
        ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) )
    {
        SC_OSSL_LOG_ERROR("Failed to get RSA key from ctx");
        return -2;
    }

    if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get cbSalt");
        return -2;
    }

    if( cbSalt == RSA_PSS_SALTLEN_DIGEST )
    {
        cbSalt = EVP_MD_size(messageDigest);
    }
    else if ( (cbSalt == RSA_PSS_SALTLEN_MAX_SIGN) || (cbSalt == RSA_PSS_SALTLEN_MAX) )
    {
        cbSalt = RSA_size(rsa) - EVP_MD_size(messageDigest) - 2;
    }
    else if ( (cbSalt < 0) || (cbSalt > (RSA_size(rsa) - EVP_MD_size(messageDigest) - 2)) )
    {
        SC_OSSL_LOG_ERROR("Invalid cbSalt");
        return -2;
    }

    if( sc_ossl_initialize_rsa_key(rsa, &localKeyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to initialize localKeyCtx");
        return -2;
    }

    cbModulus = SymCryptRsakeySizeofModulus(localKeyCtx.key);
    cbResult = cbModulus;
    if( siglen != NULL )
    {
        *siglen = cbResult;
    }
    if( sig == NULL )
    {
        ret = 1;
        goto cleanup; // Not error - this can be called with NULL parameter for siglen
    }

    sc_ossl_mac_algo = GetSymCryptHashAlgorithm(type);
    expectedTbsLength = GetExpectedTbsLength(type);
    if( !sc_ossl_mac_algo || expectedTbsLength < 0 )
    {
        SC_OSSL_LOG_ERROR("Unknown type: %d. Size: %d.", type, tbslen);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if( type == NID_md5 )
    {
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if( type == NID_sha1 )
    {
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if( tbslen != expectedTbsLength )
    {
        goto cleanup;
    }

    SymError = SymCryptRsaPssSign(
                localKeyCtx.key,
                tbs,
                tbslen,
                sc_ossl_mac_algo,
                cbSalt,
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                sig,
                siglen != NULL ? (*siglen) : 0,
                &cbResult);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPssSign failed", SymError);
        goto cleanup;
    }

    ret = 1;

cleanup:
    sc_ossl_rsa_free_key_context(&localKeyCtx);
    return ret;
}

SCOSSL_STATUS sc_ossl_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    BN_ULONG cbModulus = 0;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    size_t ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    // We should have this localKeyCtx kept in some extension to EVP_PKEY_CTX
    // Currently not sure how to achieve this with 1.1.1 APIs (EVP_PKEY_get_ex_data is introduced in OpenSSL 3.0)
    SC_OSSL_RSA_KEY_CONTEXT localKeyCtx;
    PCSYMCRYPT_HASH sc_ossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
    EVP_MD *messageDigest;
    EVP_MD *mgf1Digest;
    int type = 0;
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_signature_md(ctx, &messageDigest) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get messageDigest");
        return -2;
    }
    if( EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1Digest) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get mgf1Digest");
        return -2;
    }
    type = EVP_MD_type(messageDigest);

    if( type != EVP_MD_type(mgf1Digest) )
    {
        SC_OSSL_LOG_ERROR("messageDigest and mgf1Digest do not match");
        return -2;
    }

    if( ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL) ||
        ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) )
    {
        SC_OSSL_LOG_ERROR("Failed to get RSA key from ctx");
        return -2;
    }

    if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get cbSalt");
        return -2;
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
        SC_OSSL_LOG_ERROR("SymCrypt Engine does not support RSA_PSS_SALTLEN_AUTO saltlen");
        return -2;
    }
    else if ( (cbSalt < 0) || (cbSalt > (RSA_size(rsa) - EVP_MD_size(messageDigest) - 2)) )
    {
        SC_OSSL_LOG_ERROR("Invalid cbSalt");
        return -2;
    }

    if( sc_ossl_initialize_rsa_key(rsa, &localKeyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to initialize localKeyCtx");
        return -2;
    }

    if( sig == NULL )
    {
        goto cleanup;
    }

    cbModulus = SymCryptRsakeySizeofModulus(localKeyCtx.key);

    sc_ossl_mac_algo = GetSymCryptHashAlgorithm(type);
    expectedTbsLength = GetExpectedTbsLength(type);
    if( !sc_ossl_mac_algo || expectedTbsLength < 0 )
    {
        SC_OSSL_LOG_ERROR("Unknown type: %d. Size: %d.", type, tbslen);
        goto cleanup;
    }
    
    // Log warnings for algorithms that aren't FIPS compliant
    if( type == NID_md5 )
    {
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if( type == NID_sha1 )
    {
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if( tbslen != expectedTbsLength )
    {
        goto cleanup;
    }

    SymError = SymCryptRsaPssVerify(
                localKeyCtx.key,
                tbs,
                tbslen,
                sig,
                siglen,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                sc_ossl_mac_algo,
                cbSalt,
                0);

    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPssverify failed", SymError);
        goto cleanup;
    }

    ret = 1;

cleanup:
    sc_ossl_rsa_free_key_context(&localKeyCtx);
    return ret;
}


#ifdef __cplusplus
}
#endif