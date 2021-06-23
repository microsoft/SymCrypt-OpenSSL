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

int sc_ossl_rsapss_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    SC_OSSL_LOG_DEBUG(NULL);
    BN_ULONG cbModuls = 0;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    // We should have this localKeyCtx kept in some extension to EVP_PKEY_CTX
    // Currently not sure how to achieve this with 1.1.1 APIs (EVP_PKEY_get_ex_data is introduced in OpenSSL 3.0)
    SC_OSSL_RSA_KEY_CONTEXT localKeyCtx;
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

    SC_OSSL_LOG_DEBUG("cbSalt= %d", cbSalt);
    if( sc_ossl_initialize_rsa_key(rsa, &localKeyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to initialize localKeyCtx");
        return -2;
    }

    cbModuls = SymCryptRsakeySizeofModulus(localKeyCtx.key);
    cbResult = cbModuls;
    SC_OSSL_LOG_DEBUG("tbslen= %d", tbslen);
    if( siglen != NULL )
    {
        *siglen = cbResult;
    }
    if( sig == NULL )
    {
        SC_OSSL_LOG_DEBUG("sig NOT present");
        goto CommonReturn; // Not error - this can be called with NULL parameter for siglen
    }

    switch( type )
    {
    case NID_md5:
        SC_OSSL_LOG_DEBUG("NID_md5");
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
        if( tbslen != 16 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssSign(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       SymCryptMd5Algorithm,
                       cbSalt,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sig,
                       siglen != NULL ? (*siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssSign failed", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_DEBUG("NID_sha1");
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
        if( tbslen != 20 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssSign(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       SymCryptSha1Algorithm,
                       cbSalt,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sig,
                       siglen != NULL ? (*siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssSign failed", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        SC_OSSL_LOG_DEBUG("NID_sha256");
        if( tbslen != 32 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssSign(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       SymCryptSha256Algorithm,
                       cbSalt,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sig,
                       siglen != NULL ? (*siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssSign failed", SymError);
            goto err;
        }

        break;
    case NID_sha384:
        SC_OSSL_LOG_DEBUG("NID_sha384");
        if( tbslen != 48 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssSign(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       SymCryptSha384Algorithm,
                       cbSalt,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sig,
                       siglen != NULL ? (*siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssSign failed", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        SC_OSSL_LOG_DEBUG("NID_sha512");
        if( tbslen != 64 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssSign(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       SymCryptSha512Algorithm,
                       cbSalt,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sig,
                       siglen != NULL ? (*siglen) : 0,
                       &cbResult);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssSign failed", SymError);
            goto err;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown type: %d. Size: %d.", type, tbslen);
        goto err;
    }

CommonReturn:
    sc_ossl_rsa_free_key_context(&localKeyCtx);
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}

int sc_ossl_rsapss_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    SC_OSSL_LOG_DEBUG(NULL);
    BN_ULONG cbModuls = 0;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    // We should have this localKeyCtx kept in some extension to EVP_PKEY_CTX
    // Currently not sure how to achieve this with 1.1.1 APIs (EVP_PKEY_get_ex_data is introduced in OpenSSL 3.0)
    SC_OSSL_RSA_KEY_CONTEXT localKeyCtx;
    EVP_MD *messageDigest;
    EVP_MD *mgf1Digest;
    int dtype = 0;
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
    dtype = EVP_MD_type(messageDigest);

    if( dtype != EVP_MD_type(mgf1Digest) )
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

    SC_OSSL_LOG_DEBUG("cbSalt= %d", cbSalt);

    if( sc_ossl_initialize_rsa_key(rsa, &localKeyCtx) == 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to initialize localKeyCtx");
        return -2;
    }

    cbModuls = SymCryptRsakeySizeofModulus(localKeyCtx.key);
    cbResult = cbModuls;
    SC_OSSL_LOG_DEBUG("tbslen= %d", tbslen);
    if( sig == NULL )
    {
        SC_OSSL_LOG_DEBUG("sig NOT present");
        goto err;
    }

    cbModuls = SymCryptRsakeySizeofModulus(localKeyCtx.key);
    cbResult = cbModuls;
    switch( dtype )
    {
    case NID_md5:
        SC_OSSL_LOG_DEBUG("NID_md5");
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm MD5 which is not FIPS compliant");
        if( tbslen != 16 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssVerify(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       sig,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptMd5Algorithm,
                       cbSalt,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssverify failed", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SC_OSSL_LOG_DEBUG("NID_sha1");
        SC_OSSL_LOG_INFO("SymCrypt engine warning using Mac algorithm SHA1 which is not FIPS compliant");
        if( tbslen != 20 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssVerify(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       sig,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1Algorithm,
                       cbSalt,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssverify failed", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        SC_OSSL_LOG_DEBUG("NID_sha256");
        if( tbslen != 32 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssVerify(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       sig,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha256Algorithm,
                       cbSalt,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssverify failed", SymError);
            goto err;
        }
        break;
    case NID_sha384:
        SC_OSSL_LOG_DEBUG("NID_sha384");
        if( tbslen != 48 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssVerify(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       sig,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha384Algorithm,
                       cbSalt,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssverify failed", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        SC_OSSL_LOG_DEBUG("NID_sha512");
        if( tbslen != 64 )
        {
            goto err;
        }

        SymError = SymCryptRsaPssVerify(
                       localKeyCtx.key,
                       tbs,
                       tbslen,
                       sig,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha512Algorithm,
                       cbSalt,
                       0);

        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_DEBUG("SymCryptRsaPssverify failed", SymError);
            goto err;
        }
        break;
    default:
        SC_OSSL_LOG_ERROR("Unknown dtype: %d. Size: %d.", dtype, tbslen);
        goto err;
    }

    cbResult = 1;

CommonReturn:
    sc_ossl_rsa_free_key_context(&localKeyCtx);
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}


#ifdef __cplusplus
}
#endif