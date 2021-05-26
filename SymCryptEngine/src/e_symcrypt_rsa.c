//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt_rsa.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SYMCRYPT_RSA_KEY_CONTEXT {
    int initialized;
    unsigned char* data;
    PSYMCRYPT_RSAKEY key;
} SYMCRYPT_RSA_KEY_CONTEXT;

int symcrypt_initialize_rsa_key(RSA* rsa, SYMCRYPT_RSA_KEY_CONTEXT *keyCtx);
void symcrypt_rsa_free_key_context(SYMCRYPT_RSA_KEY_CONTEXT *keyCtx);
int rsa_symcrypt_idx = -1;

#define SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL     1
#define SYMCRYPT_RSA_METHOD_PRIVATE_KEY_CALL    2

typedef int (*PFN_RSA_meth_pub_enc)(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

typedef int (*PFN_RSA_meth_priv_enc)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

int symcrypt_rsa_encrypt(int rsa_method_context, SYMCRYPT_RSA_KEY_CONTEXT *keyCtx, int flen, const unsigned char* from,
    unsigned char* to, RSA* rsa, int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    int ret = 0;
    BN_ULONG cbModuls = 0;
    BN_ULONG cbResult = 0;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_pub_enc pfn_rsa_meth_pub_enc = NULL;
    PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = NULL;

    cbModuls= SymCryptRsakeySizeofModulus(keyCtx->key);
    SYMCRYPT_LOG_DEBUG("from: %X, flen: %d, cbModuls: %ld", from, flen, cbModuls);

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Encrypt");
        SymError = SymCryptRsaPkcs1Encrypt(
                       keyCtx->key,
                       from,
                       flen > cbModuls ? cbModuls : flen,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       to,
                       cbModuls,
                       &cbResult);
        SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_ERROR("SymCryptRsaPkcs1Encrypt failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case RSA_PKCS1_OAEP_PADDING:
        SYMCRYPT_LOG_DEBUG("SymCryptRsaOaepEncrypt");
        SymError = SymCryptRsaOaepEncrypt(
                       keyCtx->key,
                       from,
                       flen > cbModuls ? cbModuls : flen,
                       SymCryptSha1Algorithm,
                       NULL,
                       0,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       to,
                       cbModuls,
                       &cbResult);
        SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_ERROR("SymCryptRsaOaepEncrypt failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case RSA_SSLV23_PADDING:
        SYMCRYPT_LOG_INFO("RSA_SSLV23_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_enc failed");
                return -1;
            }
            return pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_enc failed");
                return -1;
            }
            return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
        }
        break;
    case RSA_X931_PADDING:
        SYMCRYPT_LOG_INFO("RSA_X931_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_enc failed");
                return -1;
            }
            return pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_enc failed");
                return -1;
            }
            return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
        }
        break;
    case RSA_NO_PADDING:
        SYMCRYPT_LOG_INFO("RSA_NO_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_enc failed");
                return -1;
            }
            return pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_enc)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_enc failed");
                return -1;
            }
            return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
        }
        // SYMCRYPT_LOG_DEBUG("SymCryptRsaRawEncrypt");
        // SYMCRYPT_LOG_BYTES_DEBUG("SymCryptRsaRawEncrypt Input", from, flen > cbModuls ? cbModuls : flen);
        // SymError = SymCryptRsaRawEncrypt(
        //                keyCtx->key,
        //                from,
        //                flen > cbModuls ? cbModuls : flen,
        //                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        //                0,
        //                to,
        //                cbModuls);
        // cbResult = cbModuls;
        // SYMCRYPT_LOG_BYTES_DEBUG("SymCryptRsaRawEncrypt Output", to, cbModuls);
        // SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        // if (SymError != SYMCRYPT_NO_ERROR)
        // {
        //     SYMCRYPT_LOG_ERROR("SymCryptRsaRawEncrypt failed. SymError = %ld", SymError);
        //     goto err;
        // }
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unknown Padding: %d", padding);
        goto err;
    }

CommonReturn:
    return cbResult;
err:
    goto CommonReturn;
}

typedef int (*PFN_RSA_meth_pub_dec)(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

typedef int (*PFN_RSA_meth_priv_dec)(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

int symcrypt_rsa_decrypt(int rsa_method_context, SYMCRYPT_RSA_KEY_CONTEXT *keyCtx,
        int flen, const unsigned char* from,
        unsigned char* to, RSA* rsa, int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    BN_ULONG cbModuls = 0;
    BN_ULONG cbResult = 0;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_pub_dec pfn_rsa_meth_pub_dec = NULL;
    PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = NULL;

    SYMCRYPT_LOG_DEBUG("SymCryptRsakeySizeofModulus");
    cbModuls= SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModuls;

    SYMCRYPT_LOG_DEBUG("from: %X, flen: %d, cbModuls: %ld, to: %X", from, flen, cbModuls, to);

    if (from == NULL)
    {
        goto err;
    }

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Decrypt");
        SymError = SymCryptRsaPkcs1Decrypt(
                       keyCtx->key,
                       from,
                       flen > cbModuls ? cbModuls : flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       0,
                       to,
                       flen > cbModuls ? cbModuls : flen,
                       &cbResult);
        SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_ERROR("SymCryptRsaPkcs1Decrypt failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case RSA_PKCS1_OAEP_PADDING:
        SYMCRYPT_LOG_DEBUG("SymCryptRsaOaepDecrypt");
        SymError = SymCryptRsaOaepDecrypt(
                       keyCtx->key,
                       from,
                       flen > cbModuls ? cbModuls : flen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1Algorithm,
                       NULL,
                       0,
                       0,
                       to,
                       flen > cbModuls ? cbModuls : flen,
                       &cbResult);
        SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_ERROR("SymCryptRsaOaepDecrypt failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case RSA_SSLV23_PADDING:
        SYMCRYPT_LOG_INFO("RSA_SSLV23_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_dec failed");
                return -1;
            }
            return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_dec failed");
                return -1;
            }
            return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        }
        break;
    case RSA_X931_PADDING:
        SYMCRYPT_LOG_INFO("RSA_SSLV23_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_dec failed");
                return -1;
            }
            return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_dec failed");
                return -1;
            }
            return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        }
        goto err;
        break;
    case RSA_NO_PADDING:
        SYMCRYPT_LOG_INFO("RSA_NO_PADDING equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if (rsa_method_context == SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL)
        {
            pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_pub_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_set_pub_dec failed");
                return -1;
            }
            return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
        }
        else
        {
            pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
            if (!pfn_rsa_meth_priv_dec)
            {
                SYMCRYPT_LOG_ERROR("RSA_meth_get_priv_dec failed");
                return -1;
            }
            return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        }
        // SYMCRYPT_LOG_DEBUG("SymCryptRsaRawDecrypt");
        // SYMCRYPT_LOG_BYTES_DEBUG("SymCryptRsaRawDecrypt Input", from, flen > cbModuls ? cbModuls : flen);
        // SymError = SymCryptRsaRawDecrypt(
        //                keyCtx->key,
        //                from,
        //                flen > cbModuls ? cbModuls : flen,
        //                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        //                0,
        //                to,
        //                cbModuls);
        // cbResult = cbModuls;
        // SYMCRYPT_LOG_BYTES_DEBUG("SymCryptRsaRawDecrypt Output", to, flen > cbModuls ? cbModuls : flen);
        // SYMCRYPT_LOG_DEBUG("cbResult: %ld", cbResult);
        // if (SymError != SYMCRYPT_NO_ERROR)
        // {
        //     SYMCRYPT_LOG_ERROR("SymCryptRsaRawDecrypt failed. SymError = %ld", SymError);
        //     goto err;
        // }
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unknown Padding: %d", padding);
        goto err;
    }

CommonReturn:
    return cbResult;
err:
    goto CommonReturn;
}

int symcrypt_rsa_priv_enc(int flen, const unsigned char* from,
    unsigned char* to, RSA* rsa, int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }
    ret = symcrypt_rsa_encrypt(SYMCRYPT_RSA_METHOD_PRIVATE_KEY_CALL, keyCtx, flen, from, to, rsa, padding);

CommonReturn:
    return ret;
err:
    goto CommonReturn;
}

int symcrypt_rsa_priv_dec(int flen, const unsigned char* from,
    unsigned char* to, RSA* rsa, int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }
    ret = symcrypt_rsa_decrypt(SYMCRYPT_RSA_METHOD_PRIVATE_KEY_CALL, keyCtx, flen, from, to, rsa, padding);

CommonReturn:
    return ret;
err:
    goto CommonReturn;
}

int symcrypt_rsa_pub_enc(int flen, const unsigned char* from,
    unsigned char* to, RSA* rsa,
    int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }
    ret = symcrypt_rsa_encrypt(SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL, keyCtx, flen, from, to, rsa, padding);

CommonReturn:
    return ret;
err:
    goto CommonReturn;
}


int symcrypt_rsa_pub_dec(int flen, const unsigned char* from,
    unsigned char* to, RSA* rsa,
    int padding)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }
    ret = symcrypt_rsa_decrypt(SYMCRYPT_RSA_METHOD_PUBLIC_KEY_CALL, keyCtx, flen, from, to, rsa, padding);

CommonReturn:
    return ret;
err:
    goto CommonReturn;

}

int symcrypt_rsa_sign(int type, const unsigned char* m,
    unsigned int m_length,
    unsigned char* sigret, unsigned int* siglen,
    const RSA* rsa)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    BN_ULONG cbModuls = 0;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);

    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }

    cbModuls = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModuls;
    SYMCRYPT_LOG_DEBUG("m_length= %d", m_length);
    if (siglen != NULL)
    {
        *siglen = cbResult;
    }
    if(sigret == NULL)
    {
        SYMCRYPT_LOG_DEBUG("sigret NOT present");
        goto err;
    }

    switch (type)
    {
    case NID_md5:
        SYMCRYPT_LOG_DEBUG("NID_md5");
        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModuls ? cbModuls : *siglen) : 0,
                       &cbResult);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Sign failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SYMCRYPT_LOG_DEBUG("NID_sha1");
        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModuls ? cbModuls : *siglen) : 0,
                       &cbResult);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Sign failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        SYMCRYPT_LOG_DEBUG("NID_sha256");
        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModuls ? cbModuls : *siglen) : 0,
                       &cbResult);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Sign failed. SymError = %ld", SymError);
            goto err;
        }

        break;
    case NID_sha384:
        SYMCRYPT_LOG_DEBUG("NID_sha384");
        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModuls ? cbModuls : *siglen) : 0,
                       &cbResult);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Sign failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        SYMCRYPT_LOG_DEBUG("NID_sha512");
        SymError = SymCryptRsaPkcs1Sign(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       sigret,
                       siglen != NULL ? (*siglen > cbModuls ? cbModuls : *siglen) : 0,
                       &cbResult);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1Sign failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    default:
        SYMCRYPT_LOG_DEBUG("Unknown type, %d", type);
        goto err;
    }

CommonReturn:
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}

int symcrypt_rsa_verify(int dtype, const unsigned char* m,
    unsigned int m_length,
    const unsigned char* sigbuf,
    unsigned int siglen, const RSA* rsa)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    BN_ULONG cbModuls = 0;
    size_t cbResult = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);

    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized == 0)
    {
        if (symcrypt_initialize_rsa_key((RSA *)rsa, keyCtx) == 0)
        {
            goto err;
        }
    }

    cbModuls = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbResult = cbModuls;
    switch (dtype)
    {
    case NID_md5:
        SYMCRYPT_LOG_DEBUG("NID_md5");
        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptMd5OidList,
                       SYMCRYPT_MD5_OID_COUNT,
                       0);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1verify failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha1:
        SYMCRYPT_LOG_DEBUG("NID_sha1");
        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha1OidList,
                       SYMCRYPT_SHA1_OID_COUNT,
                       0);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1verify failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha256:
        SYMCRYPT_LOG_DEBUG("NID_sha256");
        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha256OidList,
                       SYMCRYPT_SHA256_OID_COUNT,
                       0);
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1verify failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha384:
        SYMCRYPT_LOG_DEBUG("NID_sha384");
        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha384OidList,
                       SYMCRYPT_SHA384_OID_COUNT,
                       0);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1verify failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    case NID_sha512:
        SYMCRYPT_LOG_DEBUG("NID_sha512");
        SymError = SymCryptRsaPkcs1Verify(
                       keyCtx->key,
                       m,
                       m_length > cbModuls ? cbModuls : m_length,
                       sigbuf,
                       siglen,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       SymCryptSha512OidList,
                       SYMCRYPT_SHA512_OID_COUNT,
                       0);

        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("SymCryptRsaPkcs1verify failed. SymError = %ld", SymError);
            goto err;
        }
        break;
    default:
        SYMCRYPT_LOG_DEBUG("Unknown type, %d", dtype);
        goto err;
    }

    cbResult = 1;

CommonReturn:
    return cbResult;
err:
    cbResult = 0;
    goto CommonReturn;
}

int symcrypt_rsa_keygen(RSA* rsa, int bits, BIGNUM* e,
    BN_GENCB* cb)
{
    SYMCRYPT_LOG_DEBUG(NULL);
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
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    BIGNUM *rsa_n = NULL;
    BIGNUM *rsa_e = NULL;
    BIGNUM *rsa_p = NULL;
    BIGNUM *rsa_q = NULL;
    BIGNUM *rsa_d = NULL;
    BIGNUM *rsa_dmp1 = NULL;
    BIGNUM *rsa_dmq1 = NULL;
    BIGNUM *rsa_iqmp = NULL;

    if(keyCtx == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        goto err;
    }
    if (keyCtx->initialized != 0)
    {
        symcrypt_rsa_free_key_context(keyCtx);
    }

    SymcryptRsaParam.version = 1;               // Version of the parameters structure
    SymcryptRsaParam.nBitsOfModulus = bits;     // Number of bits in the modulus
    SymcryptRsaParam.nPrimes = 2;               // Number of primes
    SymcryptRsaParam.nPubExp = 1;               // Number of public exponents
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if (keyCtx->key == NULL)
    {
        SYMCRYPT_LOG_DEBUG("SymCryptRsakeyAllocate failed");
        goto err;
    }
    SYMCRYPT_LOG_DEBUG("SymCryptRsakeyAllocate completed");
    pubExp64 = BN_get_word(e);
    SymError = SymCryptRsakeyGenerate(keyCtx->key, pPubExp64, 1, 0);
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_ERROR("SymCryptRsakeyAllocate failed. SymError = %d ", SymError);
        goto err;
    }
    SYMCRYPT_LOG_DEBUG("SymCryptRsakeyGenerate completed");

    //
    // Fill rsa structures so that OpenSSL helper functions can import/export the
    // structure to it's format.
    // CNG format for reference:
    // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    //
    cbPublicExp = SymCryptRsakeySizeofPublicExponent(keyCtx->key, 0);
    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    cbPrime1 = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
    cbPrime2 = SymCryptRsakeySizeofPrime(keyCtx->key, 1);
    SYMCRYPT_LOG_DEBUG("cbPublicExp: %ld, cbModulus: %ld, cbPrime1: %ld, cbPrime2: %ld",
        cbPublicExp, cbModulus, cbPrime1, cbPrime2);

    cbAllocSize =
        cbPublicExp +   // PublicExponent[cbPublicExp] // Big-endian.
        cbModulus +     // Modulus[cbModulus] // Big-endian.
        cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
        cbPrime2 +      // Prime2[cbPrime2] // Big-endian.
        cbPrime1 +      // Exponent1[cbPrime1] // Big-endian.
        cbPrime2 +      // Exponent2[cbPrime2] // Big-endian.
        cbPrime1 +      // Coefficient[cbPrime1] // Big-endian.
        cbModulus;      // PrivateExponent[cbModulus] // Big-endian.

    keyCtx->data = OPENSSL_zalloc(cbAllocSize);
    if (keyCtx->data == NULL)
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc failed");
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
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_ERROR("SymCryptRsakeyGetValue failed. SymError = %ld", SymError);
        goto err;
    }

    SymError = SymCryptStoreMsbFirstUint64(pubExp64, pbPublicExp, cbPublicExp);
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_ERROR("SymCryptStoreMsbFirstUint64 failed. SymError = %ld", SymError);
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
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_ERROR("SymCryptRsakeyGetCrtValue failed. SymError = %ld", SymError);
        goto err;
    }

    // Set these values
    if (((rsa_n = BN_new()) == NULL) ||
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

    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPublicExp", pbPublicExp, cbPublicExp);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbModulus", pbModulus, cbModulus);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[0]", ppbPrimes[0], cbPrime1);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[1]", ppbPrimes[1], cbPrime2);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[0]", ppbCrtExponents[0], cbPrime1);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[1]", ppbCrtExponents[1], cbPrime2);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbCrtCoefficient", pbCrtCoefficient, cbPrime1);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPrivateExponent", pbPrivateExponent, cbPrime1);

    SYMCRYPT_LOG_BIGNUM_DEBUG("e", rsa_e);
    SYMCRYPT_LOG_BIGNUM_DEBUG("n", rsa_n);
    SYMCRYPT_LOG_BIGNUM_DEBUG("p", rsa_p);
    SYMCRYPT_LOG_BIGNUM_DEBUG("q", rsa_q);
    SYMCRYPT_LOG_BIGNUM_DEBUG("dmp1", rsa_dmp1);
    SYMCRYPT_LOG_BIGNUM_DEBUG("dmq1", rsa_dmq1);
    SYMCRYPT_LOG_BIGNUM_DEBUG("iqmp", rsa_iqmp);
    SYMCRYPT_LOG_BIGNUM_DEBUG("d", rsa_d);

    keyCtx->initialized = 1;
    SYMCRYPT_LOG_DEBUG("symcrypt_rsa_keygen completed");
    ret = 1;

CommonReturn:
    return ret;

err:
    symcrypt_rsa_free_key_context(keyCtx);
    ret = 0;
    goto CommonReturn;
}

int symcrypt_initialize_rsa_key(RSA* rsa, SYMCRYPT_RSA_KEY_CONTEXT *keyCtx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("RSA Address: %X", rsa);
    SYMCRYPT_LOG_DEBUG("Key Initialized: %X, %d", &keyCtx->initialized, keyCtx->initialized);
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

    if (RSA_get_version(rsa) != RSA_ASN1_VERSION_DEFAULT)
    {
        // Currently only support normal two-prime RSA with SymCrypt Engine
        SYMCRYPT_LOG_ERROR("Unsupported RSA version");
        goto err;
    }

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);
    RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

    if (rsa_n == NULL || rsa_e == NULL)
    {
        SYMCRYPT_LOG_ERROR("Not enough Parameters");
        goto err;
    }
    // PublicExponent
    cbPublicExp = BN_num_bytes(rsa_e);
    cbAllocSize += cbPublicExp;
    // Modulus
    cbModulus = BN_num_bytes(rsa_n);
    cbAllocSize += cbModulus;
    // Prime1 - May not be present
    if (rsa_p)
    {
        pcbPrimes[0] = BN_num_bytes(rsa_p);
        cbAllocSize += pcbPrimes[0];
        nPrimes++;
    }
    // Prime2 - May not be present
    if (rsa_q)
    {
        pcbPrimes[1] = BN_num_bytes(rsa_q);
        cbAllocSize += pcbPrimes[1];
        nPrimes++;
    }
    // Exponent1 - May not be present
    if (rsa_dmp1)
    {
        pcbCrtExponents[0] = BN_num_bytes(rsa_dmp1);
        cbAllocSize += pcbCrtExponents[0];
    }
    // Exponent2 - May not be present
    if (rsa_dmq1)
    {
        pcbCrtExponents[1] = BN_num_bytes(rsa_dmq1);
        cbAllocSize += pcbCrtExponents[1];
    }
    // Coefficient - May not be present
    if (rsa_iqmp)
    {
        cbCrtCoefficient = BN_num_bytes(rsa_iqmp);
        cbAllocSize += cbCrtCoefficient;
    }
    // PrivateExponent - May not be present
    if (rsa_d)
    {
        cbPrivateExponent = BN_num_bytes(rsa_d);
        cbAllocSize += cbPrivateExponent;
    }

    keyCtx->data = OPENSSL_zalloc(cbAllocSize);
    if (keyCtx->data == NULL)
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }

    pbCurrent = keyCtx->data;

    pbPublicExp = pbCurrent;
    pbCurrent += cbPublicExp;
    BN_bn2bin(rsa_e, pbPublicExp);

    pbModulus = pbCurrent;
    pbCurrent += cbModulus;
    BN_bn2bin(rsa_n, pbModulus);

    if (rsa_p)
    {
        ppbPrimes[0] = pbCurrent;
        pbCurrent += pcbPrimes[0];
        BN_bn2bin(rsa_p, ppbPrimes[0]);
    }
    if (rsa_q)
    {
        ppbPrimes[1] = pbCurrent;
        pbCurrent += pcbPrimes[1];
        BN_bn2bin(rsa_q, ppbPrimes[1]);
    }
    if (rsa_dmp1)
    {
        ppbCrtExponents[0] = pbCurrent;
        pbCurrent += pcbCrtExponents[0];
        BN_bn2bin(rsa_dmp1, ppbCrtExponents[0]);
    }
    if (rsa_dmq1)
    {
        ppbCrtExponents[1] = pbCurrent;
        pbCurrent += pcbCrtExponents[1];
        BN_bn2bin(rsa_dmq1, ppbCrtExponents[1]);
    }
    if (rsa_iqmp)
    {
        pbCrtCoefficient = pbCurrent;
        pbCurrent += cbCrtCoefficient;
        BN_bn2bin(rsa_iqmp, pbCrtCoefficient);
    }
    if (rsa_d)
    {
        pbPrivateExponent = pbCurrent;
        pbCurrent += cbPrivateExponent;
        BN_bn2bin(rsa_d, pbPrivateExponent);
    }

    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPublicExp", pbPublicExp, cbPublicExp);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbModulus", pbModulus, cbModulus);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[0]", ppbPrimes[0], pcbPrimes[0]);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbPrimes[1]", ppbPrimes[1], pcbPrimes[1]);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[0]", ppbCrtExponents[0], pcbCrtExponents[0]);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt ppbCrtExponents[1]", ppbCrtExponents[1], pcbCrtExponents[1]);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbCrtCoefficient", pbCrtCoefficient, cbCrtCoefficient);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPrivateExponent", pbPrivateExponent, cbPrivateExponent);

    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
    SymcryptRsaParam.nPrimes = 2;
    SymcryptRsaParam.nPubExp = 1;
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if (keyCtx->key == NULL)
    {
        SYMCRYPT_LOG_ERROR("SymCryptRsakeyAllocate failed");
        goto err;
    }
    SYMCRYPT_LOG_DEBUG("SymCryptRsakeyAllocate completed");

    SymError = SymCryptLoadMsbFirstUint64(pbPublicExp, cbPublicExp, &pubExp64);
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_DEBUG("SymCryptLoadMsbFirstUint64 failed. SymError = %ld", SymError);
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
    if (SymError != SYMCRYPT_NO_ERROR)
    {
        SYMCRYPT_LOG_DEBUG("SymCryptRsakeySetValue failed. SymError = %ld", SymError);
        goto err;
    }

    keyCtx->initialized = 1;

    ret = 1;

CommonReturn:
    return ret;

err:
    SYMCRYPT_LOG_DEBUG("symcrypt_initialize_rsa_key failed.");
    symcrypt_rsa_free_key_context(keyCtx);
    ret = 0;
    goto CommonReturn;
}

typedef int (*PFN_RSA_meth_mod_exp) (BIGNUM* r0, const BIGNUM* i, RSA* rsa,
    BN_CTX* ctx);

int symcrypt_rsa_mod_exp(BIGNUM* r0, const BIGNUM* i, RSA* rsa,
    BN_CTX* ctx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_mod_exp pfn_rsa_meth_mod_exp = RSA_meth_get_mod_exp(ossl_rsa_meth);

    if (!pfn_rsa_meth_mod_exp)
    {
        return 0;
    }
    return pfn_rsa_meth_mod_exp(r0, i, rsa, ctx);
}

typedef int (*PFN_RSA_meth_bn_mod_exp) (BIGNUM* r,
    const BIGNUM* a,
    const BIGNUM* p,
    const BIGNUM* m,
    BN_CTX* ctx,
    BN_MONT_CTX* m_ctx);

int symcrypt_rsa_bn_mod_exp(BIGNUM* r,
    const BIGNUM* a,
    const BIGNUM* p,
    const BIGNUM* m,
    BN_CTX* ctx,
    BN_MONT_CTX* m_ctx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_bn_mod_exp pfn_rsa_meth_bn_mod_exp = RSA_meth_get_bn_mod_exp(ossl_rsa_meth);
    if (!pfn_rsa_meth_bn_mod_exp)
    {
        return 0;
    }
    return pfn_rsa_meth_bn_mod_exp(r, a, p, m, ctx, m_ctx);
}

int symcrypt_rsa_init(RSA *rsa)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if (!keyCtx)
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }
    RSA_set_ex_data(rsa, rsa_symcrypt_idx, keyCtx);

    ret = 1;

CommonReturn:
    return ret;

err:
    ret = 0;
    goto CommonReturn;
}

void symcrypt_rsa_free_key_context(SYMCRYPT_RSA_KEY_CONTEXT *keyCtx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (keyCtx->data)
    {
        OPENSSL_free(keyCtx->data);
    }
    if (keyCtx->key)
    {
        SymCryptRsakeyFree(keyCtx->key);
    }
    keyCtx->initialized = 0;
    return;
}

int symcrypt_rsa_finish(RSA *rsa)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_RSA_KEY_CONTEXT *keyCtx = RSA_get_ex_data(rsa, rsa_symcrypt_idx);
    symcrypt_rsa_free_key_context(keyCtx);
    RSA_set_ex_data(rsa, rsa_symcrypt_idx, NULL);
    return 1;
}


#ifdef __cplusplus
}
#endif

