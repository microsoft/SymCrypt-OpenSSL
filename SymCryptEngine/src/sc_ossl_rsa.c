//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

int scossl_rsa_idx = -1;

typedef int (*PFN_RSA_meth_pub_enc)(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

typedef int (*PFN_RSA_meth_priv_enc)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

typedef int (*PFN_RSA_meth_pub_dec)(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

typedef int (*PFN_RSA_meth_priv_dec)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

// The minimum PKCS1 padding is 11 bytes
#define SC_OSSL_MIN_PKCS1_PADDING (11)
// The minimum OAEP padding is 2*hashlen + 2, and the minimum hashlen is SHA1 - with 20B hash => minimum 42B of padding
#define SC_OSSL_MIN_OAEP_PADDING (42)

// Hash digest lengths
#define SC_OSSL_MD5_DIGEST_LENGTH (16)
#define SC_OSSL_SHA1_DIGEST_LENGTH (20)
#define SC_OSSL_MD5_SHA1_DIGEST_LENGTH (SC_OSSL_MD5_DIGEST_LENGTH + SC_OSSL_SHA1_DIGEST_LENGTH) //36
#define SC_OSSL_SHA256_DIGEST_LENGTH (32)
#define SC_OSSL_SHA384_DIGEST_LENGTH (48)
#define SC_OSSL_SHA512_DIGEST_LENGTH (64)

SCOSSL_RETURNLENGTH sc_ossl_rsa_pub_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
    int padding)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    BN_ULONG cbModulus = 0;
    SIZE_T cbResult = -1;
    int ret = -1;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_pub_enc pfn_rsa_meth_pub_enc = NULL;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    cbModulus= SymCryptRsakeySizeofModulus(keyCtx->key);

    if( from == NULL )
    {
        goto cleanup;
    }

    switch( padding )
    {
    case RSA_PKCS1_PADDING:
        if( flen > (int) cbModulus - SC_OSSL_MIN_PKCS1_PADDING )
        {
            goto cleanup;
        }
        SymError = SymCryptRsaPkcs1Encrypt(
                       keyCtx->key,
                       from,
                       flen,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       to,
                       cbModulus,
                       &cbResult);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Encrypt failed", SymError);
            goto cleanup;
        }
        break;
    case RSA_PKCS1_OAEP_PADDING:
        if( flen > (int) cbModulus - SC_OSSL_MIN_OAEP_PADDING )
        {
            goto cleanup;
        }
        SymError = SymCryptRsaOaepEncrypt(
                       keyCtx->key,
                       from,
                       flen,
                       SymCryptSha1Algorithm,
                       NULL,
                       0,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       to,
                       cbModulus,
                       &cbResult);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaOaepEncrypt failed", SymError);
            goto cleanup;
        }
        break;
    case RSA_NO_PADDING:
        if( flen != (int) cbModulus )
        {
            goto cleanup;
        }
        SymError = SymCryptRsaRawEncrypt(
                       keyCtx->key,
                       from,
                       flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       0,
                       to,
                       cbModulus);
        cbResult = cbModulus;
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaRawEncrypt failed", SymError);
            goto cleanup;
        }
        break;
    default:
        SC_OSSL_LOG_INFO("Unsupported Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
        if( !pfn_rsa_meth_pub_enc )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_set_pub_enc failed");
            goto cleanup;
        }
        cbResult = pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        break;
    }

    ret = (cbResult <= INT_MAX) ? cbResult : -1;

cleanup:
    return ret;
}

SCOSSL_RETURNLENGTH sc_ossl_rsa_priv_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    BN_ULONG cbModulus = 0;
    SIZE_T cbResult = -1;
    UINT64 err = 0;
    int ret = -1;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = NULL;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    cbModulus= SymCryptRsakeySizeofModulus(keyCtx->key);

    if( from == NULL )
    {
        goto cleanup;
    }
    if( flen > (int) cbModulus )
    {
        goto cleanup;
    }

    switch( padding )
    {
    case RSA_PKCS1_PADDING:
        SymError = SymCryptRsaPkcs1Decrypt(
                       keyCtx->key,
                       from,
                       flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       0,
                       to,
                       cbModulus - SC_OSSL_MIN_PKCS1_PADDING,
                       &cbResult);

        // Constant-time error processing to avoid Bleichenbacher attack

        // Set ret based on SymError and cbResult
        // cbResult > INT_MAX               => err > 0
        err = (UINT64)cbResult >> 31;
        // SymError != SYMCRYPT_NO_ERROR    => err > 0
        err |= (UINT32)(SymError ^ SYMCRYPT_NO_ERROR);
        // if( err > 0 ) { ret = -1; }
        // else          { ret = 0; }
        ret = (0ll - err) >> 32;

        // Set ret to cbResult if ret still 0
        ret |= (UINT32)cbResult;
        goto cleanup;
    case RSA_PKCS1_OAEP_PADDING:
        SymError = SymCryptRsaOaepDecrypt(
                       keyCtx->key,
                       from,
                       flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1Algorithm,
                       NULL,
                       0,
                       0,
                       to,
                       cbModulus - SC_OSSL_MIN_OAEP_PADDING,
                       &cbResult);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaOaepDecrypt failed", SymError);
            goto cleanup;
        }
        break;
    case RSA_NO_PADDING:
        SymError = SymCryptRsaRawDecrypt(
                       keyCtx->key,
                       from,
                       flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       0,
                       to,
                       cbModulus);
        cbResult = cbModulus;
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaRawDecrypt failed", SymError);
            goto cleanup;
        }
        break;
    default:
        SC_OSSL_LOG_INFO("Unsupported Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
        if( !pfn_rsa_meth_priv_dec )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_get_priv_dec failed");
            goto cleanup;
        }
        cbResult = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        break;
    }

    ret = (cbResult <= INT_MAX) ? cbResult : -1;

cleanup:
    return ret;
}

SCOSSL_RETURNLENGTH sc_ossl_rsa_priv_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding)
{
    SC_OSSL_LOG_INFO("RSA private encrypt equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
    const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL(); // Use default implementation
    PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = NULL;

    pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
    if( !pfn_rsa_meth_priv_enc )
    {
        SC_OSSL_LOG_ERROR("RSA_meth_get_priv_enc failed");
        return -1;
    }
    return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
}

SCOSSL_RETURNLENGTH sc_ossl_rsa_pub_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
    int padding)
{
    SC_OSSL_LOG_INFO("RSA public decrypt equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
    const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL(); // Use default implementation
    PFN_RSA_meth_pub_dec pfn_rsa_meth_pub_dec = NULL;

    pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
    if( !pfn_rsa_meth_pub_dec )
    {
        SC_OSSL_LOG_ERROR("RSA_meth_get_pub_dec failed");
        return -1;
    }
    return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
}

SCOSSL_STATUS sc_ossl_rsa_sign(int type, _In_reads_bytes_(m_length) const unsigned char* m, unsigned int m_length,
    _Out_writes_bytes_(siglen) unsigned char* sigret, _Out_ unsigned int* siglen,
    _In_ const RSA* rsa)
{
    BN_ULONG cbModulus = 0;
    SIZE_T cbResult = 0;
    SCOSSL_STATUS ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    if( sigret == NULL || siglen == NULL )
    {
        goto cleanup;
    }

    switch( type )
    {
    case NID_md5_sha1:
        SC_OSSL_LOG_INFO("Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if( m_length != SC_OSSL_MD5_SHA1_DIGEST_LENGTH )
        {
            SC_OSSL_LOG_ERROR("m_length == %d", m_length);
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       NULL,
                       0,
                       SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }
        break;
    case NID_md5:
        SC_OSSL_LOG_INFO("Using Mac algorithm MD5 which is not FIPS compliant");
        if( m_length != SC_OSSL_MD5_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_INFO("Using Mac algorithm SHA1 which is not FIPS compliant");
        if( m_length != SC_OSSL_SHA1_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }
        break;
    case NID_sha256:
        if( m_length != SC_OSSL_SHA256_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }

        break;
    case NID_sha384:
        if( m_length != SC_OSSL_SHA384_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }
        break;
    case NID_sha512:
        if( m_length != SC_OSSL_SHA512_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       cbModulus,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Sign failed", SymError);
            goto cleanup;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown type: %d. Size: %d.", type, m_length);
        goto cleanup;
    }

    *siglen = cbResult;
    ret = 1;

cleanup:
    return ret;
}

SCOSSL_STATUS sc_ossl_rsa_verify(int dtype, _In_reads_bytes_(m_length) const unsigned char* m,
    unsigned int m_length,
    _In_reads_bytes_(siglen) const unsigned char* sigbuf,
    unsigned int siglen, _In_ const RSA* rsa)
{
    BN_ULONG cbModulus = 0;
    SCOSSL_STATUS ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    switch( dtype )
    {
    case NID_md5_sha1:
        SC_OSSL_LOG_INFO("Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if( m_length != SC_OSSL_MD5_SHA1_DIGEST_LENGTH )
        {
            SC_OSSL_LOG_ERROR("m_length == %d", m_length);
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       NULL,
                       0,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    case NID_md5:
        SC_OSSL_LOG_INFO("Using Mac algorithm MD5 which is not FIPS compliant");
        if( m_length != SC_OSSL_MD5_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_INFO("Using Mac algorithm SHA1 which is not FIPS compliant");
        if( m_length != SC_OSSL_SHA1_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    case NID_sha256:
        if( m_length != SC_OSSL_SHA256_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    case NID_sha384:
        if( m_length != SC_OSSL_SHA384_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    case NID_sha512:
        if( m_length != SC_OSSL_SHA512_DIGEST_LENGTH )
        {
            goto cleanup;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            if( SymError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1verify returned unexpected error", SymError);
            }
            goto cleanup;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown dtype: %d. Size: %d.", dtype, m_length);
        goto cleanup;
    }

    ret = 1;

cleanup:
    return ret;
}

SCOSSL_STATUS sc_ossl_rsa_keygen(_Out_ RSA* rsa, int bits, _In_ BIGNUM* e,
    _In_opt_ BN_GENCB* cb)
{
    UINT64  pubExp64;
    PBYTE   pbModulus = NULL;
    SIZE_T  cbModulus = 0;
    PBYTE   ppbPrimes[2] = { 0 };
    SIZE_T  pcbPrimes[2] = { 0 };
    SIZE_T  cbPrime1 = 0;
    SIZE_T  cbPrime2 = 0;
    PBYTE   ppbCrtExponents[2] = { 0 };
    SIZE_T  pcbCrtExponents[2] = { 0 };
    PBYTE   pbCrtCoefficient = NULL;
    SIZE_T  cbCrtCoefficient = 0;
    PBYTE   pbPrivateExponent = NULL;
    SIZE_T  cbPrivateExponent = 0;
    SIZE_T  nPrimes = 2; // Constant for SymCrypt
    PBYTE   pbCurrent = NULL;
    PBYTE   pbData = NULL;
    SIZE_T  cbData = 0;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    int     ret = 0;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);
    BIGNUM *rsa_n = NULL;
    BIGNUM *rsa_e = NULL;
    BIGNUM *rsa_p = NULL;
    BIGNUM *rsa_q = NULL;
    BIGNUM *rsa_d = NULL;
    BIGNUM *rsa_dmp1 = NULL;
    BIGNUM *rsa_dmq1 = NULL;
    BIGNUM *rsa_iqmp = NULL;

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized != 0 )
    {
        sc_ossl_rsa_free_key_context(keyCtx);
    }

    SymcryptRsaParam.version = 1;               // Version of the parameters structure
    SymcryptRsaParam.nBitsOfModulus = bits;     // Number of bits in the modulus
    SymcryptRsaParam.nPrimes = 2;               // Number of primes
    SymcryptRsaParam.nPubExp = 1;               // Number of public exponents
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if( keyCtx->key == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptRsakeyAllocate failed");
        goto cleanup;
    }
    if( BN_bn2binpad(e, (PBYTE) &pubExp64, sizeof(pubExp64)) != sizeof(pubExp64) )
    {
        SC_OSSL_LOG_ERROR("BN_bn2binpad failed - Probably Public Exponent larger than maximum supported size (8 bytes)");
        goto cleanup;
    }
    if( SymCryptLoadMsbFirstUint64((PBYTE) &pubExp64, sizeof(pubExp64), &pubExp64) != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_ERROR("SymCryptLoadMsbFirstUint64 failed");
        goto cleanup;
    }
    SymError = SymCryptRsakeyGenerate(keyCtx->key, &pubExp64, 1, 0);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeyGenerate failed", SymError);
        goto cleanup;
    }

    //
    // Fill rsa structures so that OpenSSL helper functions can import/export the
    // structure to its format.
    // CNG format for reference:
    // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    //
    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbPrime1 = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
    cbPrime2 = SymCryptRsakeySizeofPrime(keyCtx->key, 1);

    cbData =
        cbModulus +     // Modulus[cbModulus] // Big-endian.
        cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
        cbPrime2 +      // Prime2[cbPrime2] // Big-endian.
        cbPrime1 +      // Exponent1[cbPrime1] // Big-endian.
        cbPrime2 +      // Exponent2[cbPrime2] // Big-endian.
        cbPrime1 +      // Coefficient[cbPrime1] // Big-endian.
        cbModulus;      // PrivateExponent[cbModulus] // Big-endian.

    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        goto cleanup;
    }
    pbCurrent = pbData;

    pbModulus = pbCurrent;
    pbCurrent += cbModulus;

    ppbPrimes[0] = pbCurrent;
    pcbPrimes[0] = cbPrime1;
    pbCurrent += cbPrime1;

    ppbPrimes[1] = pbCurrent;
    pcbPrimes[1] = cbPrime2;
    pbCurrent += cbPrime2;

    ppbCrtExponents[0] = pbCurrent;
    pcbCrtExponents[0] = cbPrime1;
    pbCurrent += cbPrime1;

    ppbCrtExponents[1] = pbCurrent;
    pcbCrtExponents[1] = cbPrime2;
    pbCurrent += cbPrime2;

    pbCrtCoefficient = pbCurrent;
    cbCrtCoefficient = cbPrime1;
    pbCurrent += cbPrime1;

    pbPrivateExponent = pbCurrent;
    cbPrivateExponent = cbModulus;

    SymError = SymCryptRsakeyGetValue(
                   keyCtx->key,
                   pbModulus,
                   cbModulus,
                   NULL,
                   0,
                   ppbPrimes,
                   pcbPrimes,
                   nPrimes,
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                   0);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeyGetValue failed", SymError);
        goto cleanup;
    }

    SymError = SymCryptRsakeyGetCrtValue(
                    keyCtx->key,
                    ppbCrtExponents,
                    pcbCrtExponents,
                    nPrimes,
                    pbCrtCoefficient,
                    cbCrtCoefficient,
                    pbPrivateExponent,
                    cbPrivateExponent,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeyGetCrtValue failed", SymError);
        goto cleanup;
    }

    // Set these values
    if( ((rsa_n = BN_new()) == NULL ) ||
        ((rsa_e = BN_dup(e)) == NULL) ||
        ((rsa_p = BN_secure_new()) == NULL) ||
        ((rsa_q = BN_secure_new()) == NULL) ||
        ((rsa_dmp1 = BN_secure_new()) == NULL) ||
        ((rsa_dmq1 = BN_secure_new()) == NULL) ||
        ((rsa_iqmp = BN_secure_new()) == NULL) ||
        ((rsa_d = BN_secure_new()) == NULL))
    {
        SC_OSSL_LOG_ERROR("BN_new returned NULL.");
        goto cleanup;
    }

    if( (BN_bin2bn(pbModulus, cbModulus, rsa_n) == NULL) ||
        (BN_bin2bn(ppbPrimes[0], cbPrime1, rsa_p) == NULL) ||
        (BN_bin2bn(ppbPrimes[1], cbPrime2, rsa_q) == NULL) ||
        (BN_bin2bn(ppbCrtExponents[0], cbPrime1, rsa_dmp1) == NULL) ||
        (BN_bin2bn(ppbCrtExponents[1], cbPrime2, rsa_dmq1) == NULL) ||
        (BN_bin2bn(pbCrtCoefficient, cbPrime1, rsa_iqmp) == NULL) ||
        (BN_bin2bn(pbPrivateExponent, cbPrivateExponent, rsa_d) == NULL) )
    {
        SC_OSSL_LOG_ERROR("BN_bin2bn failed.");
        goto cleanup;
    }

    RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);
    RSA_set0_factors(rsa, rsa_p, rsa_q);
    RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp);

    keyCtx->initialized = 1;
    ret = 1;

cleanup:
    if( ret != 1 )
    {
        sc_ossl_rsa_free_key_context(keyCtx);
        BN_free(rsa_n);
        BN_free(rsa_e);
        BN_clear_free(rsa_p);
        BN_clear_free(rsa_q);
        BN_clear_free(rsa_dmp1);
        BN_clear_free(rsa_dmq1);
        BN_clear_free(rsa_iqmp);
        BN_clear_free(rsa_d);
    }

    if( pbData )
    {
        OPENSSL_clear_free( pbData, cbData );
    }

    return ret;
}

SCOSSL_STATUS sc_ossl_initialize_rsa_key(_In_ RSA* rsa, _Out_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx)
{
    int ret = 0;
    UINT64  pubExp64;
    PBYTE   pbModulus = NULL;
    SIZE_T  cbModulus = 0;
    PBYTE   ppbPrimes[2] = { 0 };
    SIZE_T  pcbPrimes[2] = { 0 };
    SIZE_T  cbPrime1 = 0;
    SIZE_T  cbPrime2 = 0;
    SIZE_T  nPrimes = 0;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    PBYTE   pbData = NULL;
    SIZE_T  cbData = 0;
    PBYTE   pbCurrent = NULL;
    const BIGNUM *rsa_n = NULL;
    const BIGNUM *rsa_e = NULL;
    const BIGNUM *rsa_p = NULL;
    const BIGNUM *rsa_q = NULL;
    cbData =
        cbModulus +     // Modulus[cbModulus] // Big-endian.
        cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
        cbPrime2 +      // Prime2[cbPrime2] // Big-endian.
        cbPrime1 +      // Exponent1[cbPrime1] // Big-endian.
        cbPrime2 +      // Exponent2[cbPrime2] // Big-endian.
        cbPrime1 +      // Coefficient[cbPrime1] // Big-endian.
        cbModulus;      // PrivateExponent[cbModulus] // Big-endian.

    if( RSA_get_version(rsa) != RSA_ASN1_VERSION_DEFAULT )
    {
        // Currently only support normal two-prime RSA with SymCrypt Engine
        SC_OSSL_LOG_ERROR("Unsupported RSA version");
        goto cleanup;
    }

    RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);

    if( rsa_n == NULL || rsa_e == NULL )
    {
        SC_OSSL_LOG_ERROR("Not enough Parameters");
        goto cleanup;
    }
    // Modulus
    cbModulus = BN_num_bytes(rsa_n);
    cbData += cbModulus;
    // Prime1 - May not be present
    if( rsa_p )
    {
        pcbPrimes[0] = BN_num_bytes(rsa_p);
        cbData += pcbPrimes[0];
        nPrimes++;
    }
    // Prime2 - May not be present
    if( rsa_q )
    {
        pcbPrimes[1] = BN_num_bytes(rsa_q);
        cbData += pcbPrimes[1];
        nPrimes++;
    }

    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        goto cleanup;
    }

    pbCurrent = pbData;

    if( BN_bn2binpad(rsa_e, (PBYTE) &pubExp64, sizeof(pubExp64)) != sizeof(pubExp64) )
    {
        SC_OSSL_LOG_ERROR("BN_bn2binpad failed - Probably Public Exponent larger than maximum supported size (8 bytes)");
        goto cleanup;
    }
    if( SymCryptLoadMsbFirstUint64((PBYTE) &pubExp64, sizeof(pubExp64), &pubExp64) != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_ERROR("SymCryptLoadMsbFirstUint64 failed");
        goto cleanup;
    }

    pbModulus = pbCurrent;
    pbCurrent += cbModulus;
    BN_bn2bin(rsa_n, pbModulus);

    if( rsa_p )
    {
        ppbPrimes[0] = pbCurrent;
        pbCurrent += pcbPrimes[0];
        BN_bn2bin(rsa_p, ppbPrimes[0]);
    }
    if( rsa_q )
    {
        ppbPrimes[1] = pbCurrent;
        pbCurrent += pcbPrimes[1];
        BN_bn2bin(rsa_q, ppbPrimes[1]);
    }

    if( nPrimes != 0 && nPrimes != 2 )
    {
        // Currently only support normal two-prime RSA with SymCrypt Engine
        SC_OSSL_LOG_ERROR("Unsupported RSA version");
        goto cleanup;
    }

    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
    SymcryptRsaParam.nPrimes = nPrimes;
    SymcryptRsaParam.nPubExp = 1;
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if( keyCtx->key == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptRsakeyAllocate failed");
        goto cleanup;
    }

    SymError = SymCryptRsakeySetValue(
                   pbModulus,
                   cbModulus,
                   &pubExp64,
                   1,
                   (PCBYTE *)ppbPrimes,
                   (SIZE_T *)pcbPrimes,
                   nPrimes,
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                   0,
                   keyCtx->key);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeySetValue failed", SymError);
        goto cleanup;
    }

    keyCtx->initialized = 1;

    ret = 1;

cleanup:
    if( ret != 1 )
    {
        SC_OSSL_LOG_ERROR("sc_ossl_initialize_rsa_key failed.");
        sc_ossl_rsa_free_key_context(keyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return ret;
}

typedef int (*PFN_RSA_meth_mod_exp) (BIGNUM* r0, const BIGNUM* i, RSA* rsa, BN_CTX* ctx);

SCOSSL_STATUS sc_ossl_rsa_mod_exp(_Out_ BIGNUM* r0, _In_ const BIGNUM* i, _In_ RSA* rsa, _In_ BN_CTX* ctx)
{
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_mod_exp pfn_rsa_meth_mod_exp = RSA_meth_get_mod_exp(ossl_rsa_meth);

    if( !pfn_rsa_meth_mod_exp )
    {
        return 0;
    }
    return pfn_rsa_meth_mod_exp(r0, i, rsa, ctx);
}

typedef int (*PFN_RSA_meth_bn_mod_exp) (
        BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);

SCOSSL_STATUS sc_ossl_rsa_bn_mod_exp(_Out_ BIGNUM* r, _In_ const BIGNUM* a, _In_ const BIGNUM* p,
        _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx)
{
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_bn_mod_exp pfn_rsa_meth_bn_mod_exp = RSA_meth_get_bn_mod_exp(ossl_rsa_meth);
    if( !pfn_rsa_meth_bn_mod_exp )
    {
        SC_OSSL_LOG_ERROR("RSA_meth_get_bn_mod_exp failed");
        return 0;
    }
    return pfn_rsa_meth_bn_mod_exp(r, a, p, m, ctx, m_ctx);
}

SCOSSL_STATUS sc_ossl_rsa_init(_Inout_ RSA *rsa)
{
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if( !keyCtx )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        return 0;
    }

    if( RSA_set_ex_data(rsa, scossl_rsa_idx, keyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("RSA_set_ex_data failed");
        OPENSSL_free(keyCtx);
        return 0;
    }

    return 1;
}

void sc_ossl_rsa_free_key_context(_In_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx)
{
    if( keyCtx->key )
    {
        SymCryptRsakeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }
    keyCtx->initialized = 0;
    return;
}

SCOSSL_STATUS sc_ossl_rsa_finish(_Inout_ RSA *rsa)
{
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, scossl_rsa_idx);
    if( keyCtx )
    {
        if( keyCtx->initialized == 1 )
        {
            sc_ossl_rsa_free_key_context(keyCtx);
        }
        OPENSSL_free(keyCtx);
        RSA_set_ex_data(rsa, scossl_rsa_idx, NULL);
    }
    return 1;
}


#ifdef __cplusplus
}
#endif

