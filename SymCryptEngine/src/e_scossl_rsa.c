//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl_rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

int e_scossl_rsa_idx = -1;

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

SCOSSL_RETURNLENGTH e_scossl_rsa_pub_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
    int padding)
{
    int ret = -1;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_pub_enc pfn_rsa_meth_pub_enc = NULL;
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    if( from == NULL )
    {
        goto cleanup;
    }

    switch( padding )
    {
    case RSA_PKCS1_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_NO_PADDING:
        scossl_rsa_encrypt(keyCtx, padding, NID_sha1, NULL, 0, from, flen, to, &ret, -1);
        break;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "Unsupported Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
        if( pfn_rsa_meth_pub_enc )
        {
            ret = pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
        }
        break;
    }

cleanup:
    return ret;
}

SCOSSL_RETURNLENGTH e_scossl_rsa_priv_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding)
{
    int ret = -1;
    const RSA_METHOD *ossl_rsa_meth = NULL;
    PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = NULL;
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_PRIV_DEC, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            goto cleanup;
        }
    }

    if( from == NULL )
    {
        goto cleanup;
    }

    switch( padding )
    {
    case RSA_PKCS1_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_NO_PADDING:
        scossl_rsa_decrypt(keyCtx, padding, NID_sha1, NULL, 0, from, flen, to, &ret, -1);
        break;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PRIV_DEC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "Unsupported Padding: %d. Forwarding to OpenSSL. Size: %d.", padding, flen);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
        if( !pfn_rsa_meth_priv_dec )
        {
            ret = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
        }
        break;
    }

cleanup:
    return ret;
}

SCOSSL_RETURNLENGTH e_scossl_rsa_priv_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding)
{
    SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PRIV_ENC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
        "RSA private encrypt equivalent not FIPS certifiable. Forwarding to OpenSSL. Size: %d.", flen);
    const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL(); // Use default implementation
    PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = NULL;

    pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
    if( !pfn_rsa_meth_priv_enc )
    {
        return -1;
    }
    return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
}

SCOSSL_RETURNLENGTH e_scossl_rsa_pub_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
    _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
    int padding)
{
    SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PUB_DEC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
        "RSA public decrypt equivalent not found in SymCrypt. Forwarding to OpenSSL. Size: %d.", flen);
    const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL(); // Use default implementation
    PFN_RSA_meth_pub_dec pfn_rsa_meth_pub_dec = NULL;

    pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
    if( !pfn_rsa_meth_pub_dec )
    {
        return -1;
    }
    return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
}

SCOSSL_STATUS e_scossl_rsa_sign(int type, _In_reads_bytes_(m_length) const unsigned char* m, unsigned int m_length,
    _Out_writes_bytes_(siglen) unsigned char* sigret, _Out_ unsigned int* siglen,
    _In_ const RSA* rsa)
{
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        return SCOSSL_FAILURE;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_FAILURE;
        }
    }

    return scossl_rsa_pkcs1_sign(keyCtx, type, m, m_length, sigret, (SIZE_T*)siglen);
}

SCOSSL_STATUS e_scossl_rsa_verify(int dtype, _In_reads_bytes_(m_length) const unsigned char* m,
    unsigned int m_length,
    _In_reads_bytes_(siglen) const unsigned char* sigbuf,
    unsigned int siglen, _In_ const RSA* rsa)
{
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);

    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        return SCOSSL_FAILURE;
    }
    if( keyCtx->initialized == 0 )
    {
        if( e_scossl_initialize_rsa_key(rsa, keyCtx) == 0 )
        {
            return SCOSSL_FAILURE;
        }
    }

    return scossl_rsa_pkcs1_verify(keyCtx, dtype, m, m_length, sigbuf, siglen);
}

SCOSSL_STATUS e_scossl_rsa_keygen(_Out_ RSA* rsa, int bits, _In_ BIGNUM* e,
    _In_opt_ BN_GENCB* cb)
{
    UINT64  pubExp64;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int ret = SCOSSL_FAILURE;
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);
    SCOSSL_RSA_EXPORT_PARAMS *rsaParams = NULL;

    if( keyCtx == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_MISSING_CTX_DATA,
            "SymCrypt Context Not Found.");
        goto cleanup;
    }
    if( keyCtx->initialized != 0 )
    {
        e_scossl_rsa_free_key_context(keyCtx);
    }

    SymcryptRsaParam.version = 1;               // Version of the parameters structure
    SymcryptRsaParam.nBitsOfModulus = bits;     // Number of bits in the modulus
    SymcryptRsaParam.nPrimes = 2;               // Number of primes
    SymcryptRsaParam.nPubExp = 1;               // Number of public exponents
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if( keyCtx->key == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsakeyAllocate failed");
        goto cleanup;
    }
    if( BN_bn2binpad(e, (PBYTE) &pubExp64, sizeof(pubExp64)) != sizeof(pubExp64) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_OPERATION_FAIL,
            "BN_bn2binpad failed - Probably Public Exponent larger than maximum supported size (8 bytes)");
        goto cleanup;
    }
    if( SymCryptLoadMsbFirstUint64((PBYTE) &pubExp64, sizeof(pubExp64), &pubExp64) != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptLoadMsbFirstUint64 failed");
        goto cleanup;
    }
    scError = SymCryptRsakeyGenerate(keyCtx->key, &pubExp64, 1, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsakeyGenerate failed", scError);
        goto cleanup;
    }

    rsaParams = scossl_rsa_new_export_params(TRUE);
    if (rsaParams == NULL ||
        !scossl_rsa_export_key(keyCtx->key, rsaParams))
    {
        goto cleanup;
    }

    RSA_set0_key(rsa, rsaParams->n, rsaParams->e, rsaParams->privateParams->d);
    RSA_set0_factors(rsa, rsaParams->privateParams->p, rsaParams->privateParams->q);
    RSA_set0_crt_params(rsa, rsaParams->privateParams->dmp1, rsaParams->privateParams->dmq1, rsaParams->privateParams->iqmp);

    keyCtx->initialized = 1;
    ret = SCOSSL_SUCCESS;

cleanup:
    if( ret != SCOSSL_SUCCESS )
    {
        e_scossl_rsa_free_key_context(keyCtx);
    }

    // Only free the set params in failure case,
    // since OpenSSL directly copies the pointers
    scossl_rsa_free_export_params(rsaParams, !ret);

    return ret;
}

SCOSSL_STATUS e_scossl_initialize_rsa_key(_In_ const RSA* rsa, _Out_ SCOSSL_RSA_KEY_CTX *keyCtx)
{
    int ret = SCOSSL_FAILURE;
    UINT64  pubExp64;
    PBYTE   pbModulus = NULL;
    SIZE_T  cbModulus = 0;
    PBYTE   ppbPrimes[2] = { 0 };
    SIZE_T  pcbPrimes[2] = { 0 };
    SIZE_T  cbPrime1 = 0;
    SIZE_T  cbPrime2 = 0;
    SIZE_T  nPrimes = 0;
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
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

    if( RSA_get_version((RSA*) rsa) != RSA_ASN1_VERSION_DEFAULT )
    {
        // Currently only support normal two-prime RSA with SymCrypt Engine
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "Unsupported RSA version");
        goto cleanup;
    }

    RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);

    if( rsa_n == NULL || rsa_e == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, ERR_R_PASSED_NULL_PARAMETER,
            "Not enough Parameters");
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
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc failed");
        goto cleanup;
    }

    pbCurrent = pbData;

    if( BN_bn2binpad(rsa_e, (PBYTE) &pubExp64, sizeof(pubExp64)) != sizeof(pubExp64) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, ERR_R_OPERATION_FAIL,
            "BN_bn2binpad failed - Probably Public Exponent larger than maximum supported size (8 bytes)");
        goto cleanup;
    }
    if( SymCryptLoadMsbFirstUint64((PBYTE) &pubExp64, sizeof(pubExp64), &pubExp64) != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptLoadMsbFirstUint64 failed");
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
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "Unsupported RSA version");
        goto cleanup;
    }

    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
    SymcryptRsaParam.nPrimes = nPrimes;
    SymcryptRsaParam.nPubExp = 1;
    keyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if( keyCtx->key == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsakeyAllocate failed");
        goto cleanup;
    }

    scError = SymCryptRsakeySetValue(
                   pbModulus,
                   cbModulus,
                   &pubExp64,
                   1,
                   (PCBYTE *)ppbPrimes,
                   (SIZE_T *)pcbPrimes,
                   nPrimes,
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                   SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
                   keyCtx->key);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsakeySetValue failed", scError);
        goto cleanup;
    }

    keyCtx->initialized = 1;

    ret = SCOSSL_SUCCESS;

cleanup:
    if( ret != SCOSSL_SUCCESS )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, ERR_R_OPERATION_FAIL,
            "e_scossl_initialize_rsa_key failed.");
        e_scossl_rsa_free_key_context(keyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return ret;
}

typedef int (*PFN_RSA_meth_mod_exp) (BIGNUM* r0, const BIGNUM* i, RSA* rsa, BN_CTX* ctx);

SCOSSL_STATUS e_scossl_rsa_mod_exp(_Out_ BIGNUM* r0, _In_ const BIGNUM* i, _In_ RSA* rsa, _In_ BN_CTX* ctx)
{
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_mod_exp pfn_rsa_meth_mod_exp = RSA_meth_get_mod_exp(ossl_rsa_meth);

    if( !pfn_rsa_meth_mod_exp )
    {
        return SCOSSL_FAILURE;
    }
    return pfn_rsa_meth_mod_exp(r0, i, rsa, ctx);
}

typedef int (*PFN_RSA_meth_bn_mod_exp) (
        BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);

SCOSSL_STATUS e_scossl_rsa_bn_mod_exp(_Out_ BIGNUM* r, _In_ const BIGNUM* a, _In_ const BIGNUM* p,
        _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx)
{
    const RSA_METHOD* ossl_rsa_meth = RSA_PKCS1_OpenSSL();
    PFN_RSA_meth_bn_mod_exp pfn_rsa_meth_bn_mod_exp = RSA_meth_get_bn_mod_exp(ossl_rsa_meth);
    if( !pfn_rsa_meth_bn_mod_exp )
    {
        return SCOSSL_FAILURE;
    }
    return pfn_rsa_meth_bn_mod_exp(r, a, p, m, ctx, m_ctx);
}

SCOSSL_STATUS e_scossl_rsa_init(_Inout_ RSA *rsa)
{
    SCOSSL_RSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if( !keyCtx )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_INIT, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc failed");
        return SCOSSL_FAILURE;
    }

    if( RSA_set_ex_data(rsa, e_scossl_rsa_idx, keyCtx) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_INIT, ERR_R_OPERATION_FAIL,
            "RSA_set_ex_data failed");
        OPENSSL_free(keyCtx);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

void e_scossl_rsa_free_key_context(_In_ SCOSSL_RSA_KEY_CTX *keyCtx)
{
    if( keyCtx->key )
    {
        SymCryptRsakeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }
    keyCtx->initialized = 0;
    return;
}

SCOSSL_STATUS e_scossl_rsa_finish(_Inout_ RSA *rsa)
{
    SCOSSL_RSA_KEY_CTX *keyCtx = RSA_get_ex_data(rsa, e_scossl_rsa_idx);
    if( keyCtx )
    {
        if( keyCtx->initialized == 1 )
        {
            e_scossl_rsa_free_key_context(keyCtx);
        }
        OPENSSL_free(keyCtx);
        RSA_set_ex_data(rsa, e_scossl_rsa_idx, NULL);
    }
    return SCOSSL_SUCCESS;
}


#ifdef __cplusplus
}
#endif

