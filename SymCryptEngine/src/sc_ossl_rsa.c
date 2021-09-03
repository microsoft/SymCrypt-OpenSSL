//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_rsa.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

int rsa_sc_ossl_idx = -1;

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

// Public Encryption
// Encrypts flen bytes at from using public key rsa and stores ciphertext in to.
// Same parameters as RSA_public_encrypt
// - flen must not be more than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes, not more than RSA_size(rsa) - 42
//   for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING
// - from and to may overlap
// - padding is ones of RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, or RSA_NO_PADDING
// Returns size of encrypted data (RSA_size(rsa)), or -1 on error
_Success_(return >= 0)
int sc_ossl_rsa_pub_enc(_In_ int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_ unsigned char* to, _In_ RSA* rsa,
    _In_ int padding)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    BN_ULONG cbModulus = 0;
    BN_ULONG cbResult = 0;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_pub_enc pfn_rsa_meth_pub_enc = NULL;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto err;
        }
    }

    cbModulus= SymCryptRsakeySizeofModulus(keyCtx->key);

    if( from == NULL )
    {
        goto err;
    }

    switch( padding )
    {
    case RSA_PKCS1_PADDING:
        if( flen > cbModulus - SC_OSSL_MIN_PKCS1_PADDING )
        {
            goto err;
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
            goto err;
        }
        break;
    case RSA_PKCS1_OAEP_PADDING:
        if( flen > cbModulus - SC_OSSL_MIN_OAEP_PADDING )
        {
            goto err;
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
            goto err;
        }
        break;
    case RSA_NO_PADDING:
        if( flen != cbModulus )
        {
            goto err;
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
            goto err;
        }
        break;
    case RSA_SSLV23_PADDING:
        SC_OSSL_LOG_INFO("RSA_SSLV23_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
        if( !pfn_rsa_meth_pub_enc )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_set_pub_enc failed");
            return -1;
        }
        cbResult = pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        break;
    case RSA_X931_PADDING:
        SC_OSSL_LOG_INFO("RSA_X931_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
        if( !pfn_rsa_meth_pub_enc )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_set_pub_enc failed");
            goto err;
        }
        cbResult = pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        break;
    default:
        SC_OSSL_LOG_INFO("Unknown Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
        if( !pfn_rsa_meth_pub_enc )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_set_pub_enc failed");
            goto err;
        }
        cbResult = pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        break;
    }

CommonReturn:
    return cbResult;
err:
    cbResult = -1;
    goto CommonReturn;
}

// Private Decryption
// Decrypts flen bytes at from using private key rsa and stores plaintext in to.
// Same parameters as RSA_private_decrypt
// - flen should be equal to RSA_size(rsa) but may be smaller, when leading zero bytes are in the ciphertext
// - from and to may overlap
// - padding is the mode used to encrypt the data
// Returns size of recovered plaintext, or -1 on error.
_Success_(return >= 0)
int sc_ossl_rsa_priv_dec(_In_ int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_ unsigned char* to, _In_ RSA* rsa, _In_ int padding)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    BN_ULONG cbModulus = 0;
    BN_ULONG cbResult = 0;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = NULL;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto err;
        }
    }

    cbModulus= SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModulus;

    if( from == NULL )
    {
        goto err;
    }
    if( flen > cbModulus )
    {
        goto err;
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
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsaPkcs1Decrypt failed", SymError);
            goto err;
        }
        break;
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
            goto err;
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
            goto err;
        }
        break;
    case RSA_SSLV23_PADDING:
        SC_OSSL_LOG_INFO("RSA_SSLV23_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
        if( !pfn_rsa_meth_priv_dec )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_get_priv_dec failed");
            goto err;
        }
        cbResult = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        break;
    case RSA_X931_PADDING:
        SC_OSSL_LOG_INFO("RSA_X931_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
        if( !pfn_rsa_meth_priv_dec )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_get_priv_dec failed");
            goto err;
        }
        cbResult = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        break;
    default:
        SC_OSSL_LOG_INFO("Unknown Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
        if( !pfn_rsa_meth_priv_dec )
        {
            SC_OSSL_LOG_ERROR("RSA_meth_get_priv_dec failed");
            goto err;
        }
        cbResult = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        break;
    }

CommonReturn:
    return cbResult;
err:
    cbResult = -1;
    goto CommonReturn;
}

// Private Encryption
// Signs flen bytes at from using private key rsa and stores signature in to.
// Returns size of signature, or -1 on error
_Success_(return >= 0)
int sc_ossl_rsa_priv_enc(_In_ int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_ unsigned char* to, _In_ RSA* rsa, _In_ int padding)
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

// Public Decryption
// Recovers message digest from flen-bytes long signature at from using public key rsa and stores result in to.
// Returns size of recovered message digest, or -1 on error.
_Success_(return >= 0)
int sc_ossl_rsa_pub_dec(_In_ int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_ unsigned char* to, _In_ RSA* rsa,
    _In_ int padding)
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

// Signs the message digest m of size m_len using private key rsa using PKCS1-v1_5 and stores signature in sigret and
// signature size in siglen. Type denotes the message digest algorithm used to generate m.
// Returns 1 on success
SCOSSL_STATUS sc_ossl_rsa_sign(_In_ int type, _In_reads_bytes_(m_length) const unsigned char* m, unsigned int m_length,
    _Out_ unsigned char* sigret, _Out_ unsigned int* siglen,
    _In_ const RSA* rsa)
{
    BN_ULONG cbModulus = 0;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto err;
        }
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModulus;
    if( siglen != NULL )
    {
        *siglen = cbResult;
    }
    if( sigret == NULL )
    {
        goto CommonReturn; // Not error - this can be called with NULL parameter for siglen
    }

    switch( type )
    {
    case NID_md5_sha1:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if( m_length != 36 )
        {
            SC_OSSL_LOG_ERROR("m_length == %d", m_length);
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       NULL,
                       0,
                       SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }
        break;
    case NID_md5:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
        if( m_length != 16 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
        if( m_length != 20 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        if( m_length != 32 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }

        break;
    case NID_sha384:
        if( m_length != 48 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        if( m_length != 64 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModulus ? cbModulus : *siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1Sign failed", SymError);
            goto err;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown type: %d. Size: %d.", type, m_length);
        goto err;
    }

CommonReturn:
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}

// Verifies that the signature sigbuf of size siglen matches a given message digest m of size m_len.
// dtype denotes the message digest algorithm that was used to generate the signature. rsa is the signer's
// public key.
// Returns 1 on successful verification
SCOSSL_STATUS sc_ossl_rsa_verify(_In_ int dtype, _In_reads_bytes_(m_length) const unsigned char* m,
    _In_ unsigned int m_length,
    _In_reads_bytes_(siglen) const unsigned char* sigbuf,
    _In_ unsigned int siglen, _In_ const RSA* rsa)
{
    BN_ULONG cbModulus = 0;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);
    // const RSA_METHOD *ossl_rsa_meth = NULL;
    // PFN_RSA_meth_verify pfn_rsa_meth_verify = NULL;

    if( keyCtx == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if( keyCtx->initialized == 0 )
    {
        if( sc_ossl_initialize_rsa_key((RSA *)rsa, keyCtx) == 0 )
        {
            goto err;
        }
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModulus;
    switch( dtype )
    {
    case NID_md5_sha1:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if( m_length != 36 )
        {
            SC_OSSL_LOG_ERROR("m_length == %d", m_length);
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       NULL,
                       0,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    case NID_md5:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
        if( m_length != 16 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
        if( m_length != 20 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        if( m_length != 32 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    case NID_sha384:
        if( m_length != 48 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        if( m_length != 64 )
        {
            goto err;
        }

        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModulus ? cbModulus : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPkcs1verify failed", SymError);
            goto err;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown dtype: %d. Size: %d.", dtype, m_length);
        goto err;
    }

    cbResult = 1;

CommonReturn:
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}

// Generates a 2-prime RSA key pair and stores it in rsa. Modulus will be of length bits,
// the number of primes to form the modulus will be primes, and the public exponent will be e.
// cb is an optional callback for progress of key generation that is unused in our implementation.
// Returns 1 on success or 0 on error.
SCOSSL_STATUS sc_ossl_rsa_keygen(_Out_ RSA* rsa, _In_ int bits, _In_ BIGNUM* e,
    _In_opt_ BN_GENCB* cb)
{
    UINT64  pubExp64;
    PUINT64 pPubExp64 = &pubExp64;
    BN_ULONG publicExponent = 0;
    PBYTE   pbPublicExp = NULL;
    size_t  cbPublicExp = 0;
    PBYTE   pbModulus = NULL;
    size_t  cbModulus = 0;
    PBYTE   ppbPrimes[2] = { 0 };
    size_t  pcbPrimes[2] = { 0 };
    size_t  cbPrime1 = 0;
    size_t  cbPrime2 = 0;
    PBYTE   ppbCrtExponents[2] = { 0 };
    size_t  pcbCrtExponents[2] = { 0 };
    PBYTE   pbCrtCoefficient = NULL;
    size_t  cbCrtCoefficient = 0;
    PBYTE   pbPrivateExponent = NULL;
    size_t  cbPrivateExponent = 0;
    size_t  nPrimes = 2; // Constant for SymCrypt
    PBYTE   pbCurrent = NULL;
    size_t  cbAllocSize = 0;
    PBYTE   pbFullPrivateKey = NULL;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    int     ret = 0;
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);
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
        goto err;
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
        goto err;
    }
    pubExp64 = BN_get_word(e);
    SymError = SymCryptRsakeyGenerate(keyCtx->key, pPubExp64, 1, 0);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeyAllocate failed", SymError);
        goto err;
    }

    //
    // Fill rsa structures so that OpenSSL helper functions can import/export the
    // structure to its format.
    // CNG format for reference:
    // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    //
    cbPublicExp = SymCryptRsakeySizeofPublicExponent(keyCtx->key, 0);
    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbPrime1 = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
    cbPrime2 = SymCryptRsakeySizeofPrime(keyCtx->key, 1);

    cbAllocSize =
        cbPublicExp +   // PublicExponent[cbPublicExp] // Big-endian.
        cbModulus +     // Modulus[cbModulus] // Big-endian.
        cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
        cbPrime2 +      // Prime2[cbPrime2] // Big-endian.
        cbPrime1 +      // Exponent1[cbPrime1] // Big-endian.
        cbPrime2 +      // Exponent2[cbPrime2] // Big-endian.
        cbPrime1 +      // Coefficient[cbPrime1] // Big-endian.
        cbModulus;      // PrivateExponent[cbModulus] // Big-endian.

    keyCtx->cbData = cbAllocSize;
    keyCtx->data = OPENSSL_zalloc(cbAllocSize);
    if( keyCtx->data == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }
    pbCurrent = keyCtx->data;

    pbPublicExp = pbCurrent;
    pbCurrent += cbPublicExp;

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
                   &pubExp64,
                   1,
                   ppbPrimes,
                   pcbPrimes,
                   nPrimes,
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                   0);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptRsakeyGetValue failed", SymError);
        goto err;
    }

    SymError = SymCryptStoreMsbFirstUint64(pubExp64, pbPublicExp, cbPublicExp);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptStoreMsbFirstUint64 failed", SymError);
        goto err;
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
        goto err;
    }

    // Set these values
    if( ((rsa_n = BN_new()) == NULL ) ||
        ((rsa_e = BN_new()) == NULL) ||
        ((rsa_p = BN_secure_new()) == NULL) ||
        ((rsa_q = BN_secure_new()) == NULL) ||
        ((rsa_dmp1 = BN_secure_new()) == NULL) ||
        ((rsa_dmq1 = BN_secure_new()) == NULL) ||
        ((rsa_iqmp = BN_secure_new()) == NULL) ||
        ((rsa_d = BN_secure_new()) == NULL))
    {
        goto err;
    }

    BN_bin2bn(pbPublicExp, cbPublicExp, rsa_e);
    BN_bin2bn(pbModulus, cbModulus, rsa_n);
    BN_bin2bn(ppbPrimes[0], cbPrime1, rsa_p);
    BN_bin2bn(ppbPrimes[1], cbPrime2, rsa_q);
    BN_bin2bn(ppbCrtExponents[0], cbPrime1, rsa_dmp1);
    BN_bin2bn(ppbCrtExponents[1], cbPrime2, rsa_dmq1);
    BN_bin2bn(pbCrtCoefficient, cbPrime1, rsa_iqmp);
    BN_bin2bn(pbPrivateExponent, cbPrivateExponent, rsa_d);

    RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);
    RSA_set0_factors(rsa, rsa_p, rsa_q);
    RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp);

    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbPublicExp", pbPublicExp, cbPublicExp);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbModulus", pbModulus, cbModulus);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[0]", ppbPrimes[0], cbPrime1);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[1]", ppbPrimes[1], cbPrime2);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[0]", ppbCrtExponents[0], cbPrime1);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[1]", ppbCrtExponents[1], cbPrime2);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbCrtCoefficient", pbCrtCoefficient, cbPrime1);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbPrivateExponent", pbPrivateExponent, cbPrime1);

    SC_OSSL_LOG_BIGNUM_DEBUG("e", rsa_e);
    SC_OSSL_LOG_BIGNUM_DEBUG("n", rsa_n);
    SC_OSSL_LOG_BIGNUM_DEBUG("p", rsa_p);
    SC_OSSL_LOG_BIGNUM_DEBUG("q", rsa_q);
    SC_OSSL_LOG_BIGNUM_DEBUG("dmp1", rsa_dmp1);
    SC_OSSL_LOG_BIGNUM_DEBUG("dmq1", rsa_dmq1);
    SC_OSSL_LOG_BIGNUM_DEBUG("iqmp", rsa_iqmp);
    SC_OSSL_LOG_BIGNUM_DEBUG("d", rsa_d);

    keyCtx->initialized = 1;
    ret = 1;

CommonReturn:
    return ret;

err:
    sc_ossl_rsa_free_key_context(keyCtx);
    ret = 0;
    goto CommonReturn;
}

// Initializes keyCtx from key rsa.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_initialize_rsa_key(_In_ RSA* rsa, _Out_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx)
{
    int ret = 0;
    UINT64  pubExp64;
    PBYTE   pbPublicExp = NULL;
    size_t  cbPublicExp = 0;
    PBYTE   pbModulus = NULL;
    size_t  cbModulus = 0;
    PBYTE   ppbPrimes[2] = { 0 };
    size_t  pcbPrimes[2] = { 0 };
    size_t  cbPrime1 = 0;
    size_t  cbPrime2 = 0;
    PBYTE   ppbCrtExponents[2] = { 0 };
    size_t  pcbCrtExponents[2] = { 0 };
    PBYTE   pbCrtCoefficient = NULL;
    size_t  cbCrtCoefficient = 0;
    PBYTE   pbPrivateExponent = NULL;
    size_t  cbPrivateExponent = 0;
    size_t  nPrimes = 0;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    int     allocSize = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    size_t  cbAllocSize = 0;
    PBYTE   pbCurrent = NULL;
    const BIGNUM *rsa_n = NULL;
    const BIGNUM *rsa_e = NULL;
    const BIGNUM *rsa_p = NULL;
    const BIGNUM *rsa_q = NULL;
    const BIGNUM *rsa_d = NULL;
    const BIGNUM *rsa_dmp1 = NULL;
    const BIGNUM *rsa_dmq1 = NULL;
    const BIGNUM *rsa_iqmp = NULL;

    cbAllocSize =
        cbPublicExp +   // PublicExponent[cbPublicExp] // Big-endian.
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
        goto err;
    }

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);
    RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

    if( rsa_n == NULL || rsa_e == NULL )
    {
        SC_OSSL_LOG_ERROR("Not enough Parameters");
        goto err;
    }
    // PublicExponent
    cbPublicExp = BN_num_bytes(rsa_e);
    cbAllocSize += cbPublicExp;
    // Modulus
    cbModulus = BN_num_bytes(rsa_n);
    cbAllocSize += cbModulus;
    // Prime1 - May not be present
    if( rsa_p )
    {
        pcbPrimes[0] = BN_num_bytes(rsa_p);
        cbAllocSize += pcbPrimes[0];
        nPrimes++;
    }
    // Prime2 - May not be present
    if( rsa_q )
    {
        pcbPrimes[1] = BN_num_bytes(rsa_q);
        cbAllocSize += pcbPrimes[1];
        nPrimes++;
    }
    // Exponent1 - May not be present
    if( rsa_dmp1 )
    {
        pcbCrtExponents[0] = BN_num_bytes(rsa_dmp1);
        cbAllocSize += pcbCrtExponents[0];
    }
    // Exponent2 - May not be present
    if( rsa_dmq1 )
    {
        pcbCrtExponents[1] = BN_num_bytes(rsa_dmq1);
        cbAllocSize += pcbCrtExponents[1];
    }
    // Coefficient - May not be present
    if( rsa_iqmp )
    {
        cbCrtCoefficient = BN_num_bytes(rsa_iqmp);
        cbAllocSize += cbCrtCoefficient;
    }
    // PrivateExponent - May not be present
    if( rsa_d )
    {
        cbPrivateExponent = BN_num_bytes(rsa_d);
        cbAllocSize += cbPrivateExponent;
    }

    keyCtx->cbData = cbAllocSize;
    keyCtx->data = OPENSSL_zalloc(cbAllocSize);
    if( keyCtx->data == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }

    pbCurrent = keyCtx->data;

    pbPublicExp = pbCurrent;
    pbCurrent += cbPublicExp;
    BN_bn2bin(rsa_e, pbPublicExp);

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
    if( rsa_dmp1 )
    {
        ppbCrtExponents[0] = pbCurrent;
        pbCurrent += pcbCrtExponents[0];
        BN_bn2bin(rsa_dmp1, ppbCrtExponents[0]);
    }
    if( rsa_dmq1 )
    {
        ppbCrtExponents[1] = pbCurrent;
        pbCurrent += pcbCrtExponents[1];
        BN_bn2bin(rsa_dmq1, ppbCrtExponents[1]);
    }
    if( rsa_iqmp )
    {
        pbCrtCoefficient = pbCurrent;
        pbCurrent += cbCrtCoefficient;
        BN_bn2bin(rsa_iqmp, pbCrtCoefficient);
    }
    if( rsa_d )
    {
        pbPrivateExponent = pbCurrent;
        pbCurrent += cbPrivateExponent;
        BN_bn2bin(rsa_d, pbPrivateExponent);
    }

    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbPublicExp", pbPublicExp, cbPublicExp);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbModulus", pbModulus, cbModulus);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[0]", ppbPrimes[0], pcbPrimes[0]);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[1]", ppbPrimes[1], pcbPrimes[1]);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[0]", ppbCrtExponents[0], pcbCrtExponents[0]);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[1]", ppbCrtExponents[1], pcbCrtExponents[1]);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbCrtCoefficient", pbCrtCoefficient, cbCrtCoefficient);
    SC_OSSL_LOG_BYTES_DEBUG("SymCrypt pbPrivateExponent", pbPrivateExponent, cbPrivateExponent);

    if( nPrimes != 0 && nPrimes != 2 )
    {
        // Currently only support normal two-prime RSA with SymCrypt Engine
        SC_OSSL_LOG_ERROR("Unsupported RSA version");
        goto err;
    }

    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
    SymcryptRsaParam.nPrimes = nPrimes;
    SymcryptRsaParam.nPubExp = 1;
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if( keyCtx->key == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptRsakeyAllocate failed");
        goto err;
    }

    SymError = SymCryptLoadMsbFirstUint64(pbPublicExp, cbPublicExp, &pubExp64);
    if( SymError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptLoadMsbFirstUint64 failed", SymError);
        goto err;
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
        SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsakeySetValue failed", SymError);
        goto err;
    }

    keyCtx->initialized = 1;

    ret = 1;

CommonReturn:
    return ret;

err:
    SC_OSSL_LOG_ERROR("sc_ossl_initialize_rsa_key failed.");
    sc_ossl_rsa_free_key_context(keyCtx);
    ret = 0;
    goto CommonReturn;
}

typedef int (*PFN_RSA_meth_mod_exp) (BIGNUM* r0, const BIGNUM* i, RSA* rsa, BN_CTX* ctx);

// Used for CRT computations, used by default RSA implementations
// ctx is a temporary BIGNUM variable
// Returns 1 on success, or 0 on error
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

// Used for CRT computations, used by default RSA implementations
// r = a ^ p mod m
// ctx is a temporary BIGNUM variable, while m_ctx is a Montgomery multiplication structure
// Returns 1 on success, or 0 on error
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

// Initializes a new RSA instance.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_rsa_init(_Inout_ RSA *rsa)
{
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if( !keyCtx )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
        return 0;
    }

    if( RSA_set_ex_data(rsa, rsa_sc_ossl_idx, keyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("RSA_set_ex_data failed");
        return 0;
    }

    return 1;
}

// Frees data and key of keyCtx
void sc_ossl_rsa_free_key_context(_In_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx)
{
    if( keyCtx->data )
    {
        OPENSSL_clear_free(keyCtx->data, keyCtx->cbData);
    }
    if( keyCtx->key )
    {
        SymCryptRsakeyFree(keyCtx->key);
    }
    keyCtx->initialized = 0;
    return;
}

// Destroys instance of RSA object. The memory for rsa is not freed by this function.
// Returns 1 on success
SCOSSL_STATUS sc_ossl_rsa_finish(_In_ RSA *rsa)
{
    SC_OSSL_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_sc_ossl_idx);
    if( keyCtx )
    {
        if( keyCtx->initialized == 1 )
        {
            sc_ossl_rsa_free_key_context(keyCtx);
        }
        OPENSSL_free(keyCtx);
        RSA_set_ex_data(rsa, rsa_sc_ossl_idx, NULL);
    }
    return 1;
}


#ifdef __cplusplus
}
#endif

