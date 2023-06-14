//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

// The minimum PKCS1 padding is 11 bytes
#define SCOSSL_MIN_PKCS1_PADDING (11)
// The minimum OAEP padding is 2*hashlen + 2, and the minimum hashlen is SHA1 - with 20B hash => minimum 42B of padding
#define SCOSSL_MIN_OAEP_PADDING  (42)

// Hash digest lengths
#define SCOSSL_MD5_DIGEST_LENGTH      (16)
#define SCOSSL_SHA1_DIGEST_LENGTH     (20)
#define SCOSSL_MD5_SHA1_DIGEST_LENGTH (SCOSSL_MD5_DIGEST_LENGTH + SCOSSL_SHA1_DIGEST_LENGTH) // 36
#define SCOSSL_SHA256_DIGEST_LENGTH   (32)
#define SCOSSL_SHA384_DIGEST_LENGTH   (48)
#define SCOSSL_SHA512_DIGEST_LENGTH   (64)

typedef struct
{
    PCSYMCRYPT_OID pHashOIDs;
    SIZE_T         nOIDCount;
    UINT32         flags;
} SCOSSL_RSA_PKCS1_PARAMS;

static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha1md5_params  = {NULL, 0, SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_md5_params      = {SymCryptMd5OidList, SYMCRYPT_MD5_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha1_params     = {SymCryptSha1OidList, SYMCRYPT_SHA1_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha256_params   = {SymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha384_params   = {SymCryptSha384OidList, SYMCRYPT_SHA384_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha512_params   = {SymCryptSha512OidList, SYMCRYPT_SHA512_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha3_256_params = {SymCryptSha3_256OidList, SYMCRYPT_SHA3_256_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha3_384_params = {SymCryptSha3_384OidList, SYMCRYPT_SHA3_384_OID_COUNT, 0};
static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_sha3_512_params = {SymCryptSha3_512OidList, SYMCRYPT_SHA3_512_OID_COUNT, 0};

static const SCOSSL_RSA_PKCS1_PARAMS *scossl_get_rsa_pkcs1_params(int mdnid)
{
    switch (mdnid)
    {
    case NID_md5_sha1:
        return &scossl_rsa_pkcs1_sha1md5_params;
    case NID_md5:
        return &scossl_rsa_pkcs1_md5_params;
    case NID_sha1:
        return &scossl_rsa_pkcs1_sha1_params;
    case NID_sha256:
        return &scossl_rsa_pkcs1_sha256_params;
    case NID_sha384:
        return &scossl_rsa_pkcs1_sha384_params;
    case NID_sha512:
        return &scossl_rsa_pkcs1_sha512_params;
    case NID_sha3_256:
        return &scossl_rsa_pkcs1_sha3_256_params;
    case NID_sha3_384:
        return &scossl_rsa_pkcs1_sha3_384_params;
    case NID_sha3_512:
        return &scossl_rsa_pkcs1_sha3_512_params;
    }

    return NULL;
}

static PCSYMCRYPT_HASH scossl_get_symcrypt_hash_algorithm(int mdnid)
{
    switch (mdnid)
    {
    case NID_md5:
        return SymCryptMd5Algorithm;
    case NID_sha1:
        return SymCryptSha1Algorithm;
    case NID_sha256:
        return SymCryptSha256Algorithm;
    case NID_sha384:
        return SymCryptSha384Algorithm;
    case NID_sha512:
        return SymCryptSha512Algorithm;
    case NID_sha3_256:
        return SymCryptSha3_256Algorithm;
    case NID_sha3_384:
        return SymCryptSha3_384Algorithm;
    case NID_sha3_512:
        return SymCryptSha3_512Algorithm;
    }
    return NULL;
}

static SIZE_T scossl_get_expected_hash_length(int mdnid)
{
    switch (mdnid)
    {
    case NID_md5:
        return SCOSSL_MD5_DIGEST_LENGTH;
    case NID_sha1:
        return SCOSSL_SHA1_DIGEST_LENGTH;
    case NID_sha256:
    case NID_sha3_256:
        return SCOSSL_SHA256_DIGEST_LENGTH;
    case NID_sha384:
    case NID_sha3_384:
        return SCOSSL_SHA384_DIGEST_LENGTH;
    case NID_sha512:
    case NID_sha3_512:
        return SCOSSL_SHA512_DIGEST_LENGTH;
    }
    return -1;
}

SCOSSL_RSA_KEY_CTX *scossl_rsa_new_key_ctx()
{
    SCOSSL_COMMON_ALIGNED_ALLOC(keyCtx, OPENSSL_zalloc, SCOSSL_RSA_KEY_CTX);
    return keyCtx;
}

_Use_decl_annotations_
SCOSSL_RSA_KEY_CTX *scossl_rsa_dup_key_ctx(const SCOSSL_RSA_KEY_CTX *keyCtx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copy_ctx, OPENSSL_malloc, SCOSSL_RSA_KEY_CTX);
    if (copy_ctx == NULL)
    {
        return NULL;
    }

    if (keyCtx->initialized)
    {
        SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
        UINT32 cbModulus = SymCryptRsakeyModulusBits(keyCtx->key);
        UINT32 nPrimes = SymCryptRsakeyGetNumberOfPrimes(keyCtx->key);

        SymcryptRsaParam.version = 1;
        SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
        SymcryptRsaParam.nPrimes = nPrimes;
        SymcryptRsaParam.nPubExp = 1;
        copy_ctx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
        if (copy_ctx->key == NULL)
        {
            scossl_rsa_free_key_ctx(copy_ctx);
            return NULL;
        }

        // TODO: Enable in SymCrypt
        SymCryptRsakeyCopy((PCSYMCRYPT_RSAKEY)keyCtx->key, copy_ctx->key);
        copy_ctx->initialized = 1;
    }
    else
    {
        copy_ctx->initialized = 0;
        copy_ctx->key = NULL;
    }

    return copy_ctx;
}

_Use_decl_annotations_
void scossl_rsa_free_key_ctx(SCOSSL_RSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key != NULL)
    {
        SymCryptRsakeyFree(keyCtx->key);
    }

    OPENSSL_free(keyCtx);
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_pkcs1_sign(SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid,
                                    PCBYTE pbHashValue, SIZE_T cbHashValue,
                                    PBYTE pbSignature, SIZE_T *pcbSignature)
{
    UINT32 cbModulus = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const SCOSSL_RSA_PKCS1_PARAMS *pkcs1Params;

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    if (pcbSignature == NULL)
    {
        goto cleanup;
    }

    pkcs1Params = scossl_get_rsa_pkcs1_params(mdnid);
    if (pkcs1Params == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %s. Size: %d.", OBJ_nid2sn(mdnid), cbHashValue);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    switch (mdnid)
    {
    case NID_md5_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
        break;
    }

    if (pbSignature != NULL && cbHashValue != scossl_get_expected_hash_length(mdnid))
    {
        goto cleanup;
    }

    scError = SymCryptRsaPkcs1Sign(
        keyCtx->key,
        pbHashValue,
        cbHashValue,
        pkcs1Params->pHashOIDs,
        pkcs1Params->nOIDCount,
        pkcs1Params->flags,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pbSignature,
        cbModulus,
        pcbSignature);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptRsaPkcs1Sign failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_pkcs1_verify(SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid,
                                      PCBYTE pbHashValue, SIZE_T cbHashValue,
                                      PCBYTE pbSignature, SIZE_T pcbSignature)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const SCOSSL_RSA_PKCS1_PARAMS *pkcs1Params;

    pkcs1Params = scossl_get_rsa_pkcs1_params(mdnid);
    if (pkcs1Params == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %s. Size: %d.", OBJ_nid2sn(mdnid), cbHashValue);
        goto cleanup;
    }

    switch (mdnid)
    {
    case NID_md5_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
        break;
    }

    if (cbHashValue != scossl_get_expected_hash_length(mdnid))
    {
        goto cleanup;
    }

    scError = SymCryptRsaPkcs1Verify(
        keyCtx->key,
        pbHashValue,
        cbHashValue,
        pbSignature,
        pcbSignature,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pkcs1Params->pHashOIDs,
        pkcs1Params->nOIDCount,
        0);

    if (scError == SYMCRYPT_NO_ERROR)
    {
        ret = SCOSSL_SUCCESS;
    }
    else if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptRsaPkcs1verify returned unexpected error", scError);
    }

cleanup:
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsapss_sign(SCOSSL_RSA_KEY_CTX *keyCtx, const EVP_MD *md, int cbSalt,
                                 PCBYTE pbHashValue, SIZE_T cbHashValue,
                                 PBYTE pbSignature, SIZE_T *pcbSignature)
{
    SIZE_T cbResult = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int ret = SCOSSL_FAILURE;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    SIZE_T expectedHashLength = -1;
    int cbDigest, cbSaltMax;
    int mdnid;

    cbDigest = EVP_MD_size(md);
    cbSaltMax = ((SymCryptRsakeyModulusBits(keyCtx->key) + 6) / 8) - cbDigest - 2; // ceil((ModulusBits - 1) / 8) - cbDigest - 2

    switch (cbSalt)
    {
    case RSA_PSS_SALTLEN_DIGEST:
        cbSalt = cbDigest;
        break;
    case RSA_PSS_SALTLEN_MAX_SIGN:
    case RSA_PSS_SALTLEN_MAX:
        cbSalt = cbSaltMax;
        break;
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    // Added in 3.1, should only be used in provider. min(cbSaltMax, cbDigest)
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
        cbSalt = cbSaltMax < cbDigest ? cbSaltMax : cbDigest;
#endif
    }

    if (cbSalt < 0 || cbSalt > cbSaltMax)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Invalid cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    cbResult = SymCryptRsakeySizeofModulus(keyCtx->key);
    if (pcbSignature != NULL)
    {
        *pcbSignature = cbResult;
    }
    if (pbSignature == NULL)
    {
        ret = SCOSSL_SUCCESS;
        goto cleanup; // Not error - this can be called with NULL parameter for siglen
    }

    mdnid = EVP_MD_type(md);
    scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(mdnid);
    expectedHashLength = scossl_get_expected_hash_length(mdnid);
    if (!scossl_mac_algo || expectedHashLength == (SIZE_T)-1)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %d. Size: %d.", mdnid, cbHashValue);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == NID_md5)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if (mdnid == NID_sha1)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if (cbHashValue != expectedHashLength)
    {
        goto cleanup;
    }

    scError = SymCryptRsaPssSign(
        keyCtx->key,
        pbHashValue,
        cbHashValue,
        scossl_mac_algo,
        cbSalt,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pbSignature,
        pcbSignature != NULL ? (*pcbSignature) : 0,
        &cbResult);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptRsaPssSign failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsapss_verify(SCOSSL_RSA_KEY_CTX *keyCtx, const EVP_MD *md, int cbSalt,
                                   PCBYTE pbHashValue, SIZE_T cbHashValue,
                                   PCBYTE pbSignature, SIZE_T pcbSignature)
{
    int ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    SIZE_T expectedHashLength = -1;
    int mdnid = 0;
    int cbDigest, cbSaltMax;

    mdnid = EVP_MD_type(md);

    cbDigest = EVP_MD_size(md);
    cbSaltMax = ((SymCryptRsakeyModulusBits(keyCtx->key) + 6) / 8) - cbDigest - 2; // ceil((ModulusBits - 1) / 8) - cbDigest - 2

    switch (cbSalt)
    {
    case RSA_PSS_SALTLEN_DIGEST:
        cbSalt = cbDigest;
        break;
    case RSA_PSS_SALTLEN_MAX:
        cbSalt = cbSaltMax;
        break;
    case RSA_PSS_SALTLEN_AUTO:
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    // Added in 3.1, should only be used in provider. Unsupported auto salt len for verify
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
#endif
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "SymCrypt Engine does not support RSA_PSS_SALTLEN_AUTO saltlen");
        return SCOSSL_UNSUPPORTED;
    }

    if (cbSalt < 0 || cbSalt > cbSaltMax)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Invalid cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    if (pbSignature == NULL)
    {
        goto cleanup;
    }

    scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(mdnid);
    expectedHashLength = scossl_get_expected_hash_length(mdnid);
    if (!scossl_mac_algo || expectedHashLength == (SIZE_T)-1)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %d. Size: %d.", mdnid, cbHashValue);
        goto cleanup;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == NID_md5)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
    }
    else if (mdnid == NID_sha1)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
    }

    if (cbHashValue != expectedHashLength)
    {
        goto cleanup;
    }

    scError = SymCryptRsaPssVerify(
        keyCtx->key,
        pbHashValue,
        cbHashValue,
        pbSignature,
        pcbSignature,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        scossl_mac_algo,
        cbSalt,
        0);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
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

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_encrypt(SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding,
                                 int mdnid, PCBYTE pbLabel, SIZE_T cbLabel, // OAEP-only parameters
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, INT32 *pcbDst, SIZE_T cbDst)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    SIZE_T cbResult = -1;

    if (pbDst == NULL)
    {
        *pcbDst = (INT32)cbModulus;
        goto cleanup;
    }

    if (cbDst == (SIZE_T)-1)
    {
        // cbDst is not caller supplied for engine
        cbDst = cbModulus;
    }
    else if (cbDst < cbModulus)
    {
        goto cleanup;
    }

    *pcbDst = -1;

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        if (cbSrc > cbModulus - SCOSSL_MIN_PKCS1_PADDING)
        {
            goto cleanup;
        }
        scError = SymCryptRsaPkcs1Encrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbDst,
            cbDst,
            &cbResult);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptRsaPkcs1Encrypt failed", scError);
            goto cleanup;
        }
        break;
    case RSA_PKCS1_OAEP_PADDING:
        if (cbSrc > cbModulus - SCOSSL_MIN_OAEP_PADDING)
        {
            goto cleanup;
        }

        PCSYMCRYPT_HASH scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(mdnid);
        if (!scossl_mac_algo)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                             "Unknown type: %d.", mdnid);
            goto cleanup;
        }

        scError = SymCryptRsaOaepEncrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            scossl_mac_algo,
            pbLabel,
            cbLabel,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbDst,
            cbDst,
            &cbResult);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptRsaOaepEncrypt failed", scError);
            goto cleanup;
        }
        break;
    case RSA_NO_PADDING:
        if (cbSrc != cbModulus)
        {
            goto cleanup;
        }
        scError = SymCryptRsaRawEncrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbDst);
        cbResult = cbDst;
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptRsaRawEncrypt failed", scError);
            goto cleanup;
        }
        break;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                        "Unsupported Padding: %d.", padding);
        break;
    }

    *pcbDst = (cbResult <= INT_MAX) ? (INT32)cbResult : -1;

cleanup:
    return *pcbDst >= 0;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_decrypt(SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding,
                                 int mdnid, PCBYTE pbLabel, SIZE_T cbLabel, // OAEP-only parameters
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, INT32 *pcbDst, SIZE_T cbDst)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    UINT32 cbModulus;
    UINT64 err = 0;
    SIZE_T cbResult = -1;

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);

    if (pbDst == NULL)
    {
        *pcbDst = (INT32)cbModulus;
        goto cleanup;
    }

    if (cbDst > INT_MAX)
    {
        // cbDst is not caller supplied for engine
        cbDst = cbModulus;
    }
    else if (cbSrc > cbModulus)
    {
        goto cleanup;
    }

    *pcbDst = -1;

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        scError = SymCryptRsaPkcs1Decrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbModulus - SCOSSL_MIN_PKCS1_PADDING,
            &cbResult);

        // Constant-time error processing to avoid Bleichenbacher attack

        // Set pcbDst based on scError and cbResult
        // cbResult > INT_MAX               => err > 0
        err = (UINT64)cbResult >> 31;
        // scError != SYMCRYPT_NO_ERROR    => err > 0
        err |= (UINT32)(scError ^ SYMCRYPT_NO_ERROR);
        // if( err > 0 ) { ret = -1; }
        // else          { ret = 0; }
        *pcbDst = (0ll - err) >> 32;

        // Set pcbDst to cbResult if pcbDst still 0
        *pcbDst |= (UINT32)cbResult;
        goto cleanup;
    case RSA_PKCS1_OAEP_PADDING:
        scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(mdnid);
        if (!scossl_mac_algo)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                             "Unknown type: %d.", mdnid);
            goto cleanup;
        }

        scError = SymCryptRsaOaepDecrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SymCryptSha1Algorithm,
            pbLabel,
            cbLabel,
            0,
            pbDst,
            cbModulus - SCOSSL_MIN_OAEP_PADDING,
            &cbResult);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_PRIV_DEC, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptRsaOaepDecrypt failed", scError);
            goto cleanup;
        }
        break;
    case RSA_NO_PADDING:
        scError = SymCryptRsaRawDecrypt(
            keyCtx->key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbModulus);
        cbResult = cbModulus;
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_PRIV_DEC, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptRsaRawDecrypt failed", scError);
            goto cleanup;
        }
        break;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_PUB_ENC, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                        "Unsupported Padding: %d.", padding);
        break;
    }

    *pcbDst = (cbResult <= INT_MAX) ? (INT32)cbResult : -1;

cleanup:
    return *pcbDst >= 0;
}

#ifdef __cplusplus
}
#endif