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

static const SCOSSL_RSA_PKCS1_PARAMS scossl_rsa_pkcs1_md5sha1_params  = {NULL, 0, SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1};
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
        return &scossl_rsa_pkcs1_md5sha1_params;
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

SIZE_T scossl_get_expected_hash_length(int mdnid)
{
    switch (mdnid)
    {
    case NID_md5_sha1:
        return SCOSSL_MD5_SHA1_DIGEST_LENGTH;
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

_Use_decl_annotations_
int scossl_rsa_pss_get_salt_max(PSYMCRYPT_RSAKEY key, SIZE_T cbHashValue)
{
    return ((SymCryptRsakeyModulusBits(key) + 6) / 8) - cbHashValue - 2; // ceil((ModulusBits - 1) / 8) - cbDigest - 2
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_pkcs1_sign(PSYMCRYPT_RSAKEY key, int mdnid,
                                    PCBYTE pbHashValue, SIZE_T cbHashValue,
                                    PBYTE pbSignature, SIZE_T *pcbSignature)
{
    UINT32 cbModulus = SymCryptRsakeySizeofModulus(key);
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const SCOSSL_RSA_PKCS1_PARAMS *pkcs1Params;

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
                        "Using hash algorithm MD5+SHA1 which is not FIPS compliant");
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm MD5 which is not FIPS compliant");
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm SHA1 which is not FIPS compliant");
        break;
    }

    if (pbSignature != NULL && cbHashValue != scossl_get_expected_hash_length(mdnid))
    {
        goto cleanup;
    }

    scError = SymCryptRsaPkcs1Sign(
        key,
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
SCOSSL_STATUS scossl_rsa_pkcs1_verify(PSYMCRYPT_RSAKEY key, int mdnid,
                                      PCBYTE pbHashValue, SIZE_T cbHashValue,
                                      PCBYTE pbSignature, SIZE_T pcbSignature)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const SCOSSL_RSA_PKCS1_PARAMS *pkcs1Params = scossl_get_rsa_pkcs1_params(mdnid);

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
                        "Using hash algorithm MD5+SHA1 which is not FIPS compliant");
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm MD5 which is not FIPS compliant");
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm SHA1 which is not FIPS compliant");
        break;
    }

    if (cbHashValue != scossl_get_expected_hash_length(mdnid))
    {
        goto cleanup;
    }

    scError = SymCryptRsaPkcs1Verify(
        key,
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
SCOSSL_STATUS scossl_rsapss_sign(PSYMCRYPT_RSAKEY key, int mdnid, int cbSalt,
                                 PCBYTE pbHashValue, SIZE_T cbHashValue,
                                 PBYTE pbSignature, SIZE_T *pcbSignature)
{
    int ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int cbSaltMax = scossl_rsa_pss_get_salt_max(key, cbHashValue);
    SIZE_T cbResult = 0;
    PCSYMCRYPT_HASH scosslHashAlgo = scossl_get_symcrypt_hash_algorithm(mdnid);
    SIZE_T expectedHashLength = scossl_get_expected_hash_length(mdnid);

    if (scosslHashAlgo == NULL || expectedHashLength == (SIZE_T)-1)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %d. Size: %d.", mdnid, cbHashValue);
        goto cleanup;
    }

    switch (cbSalt)
    {
    case RSA_PSS_SALTLEN_DIGEST:
        cbSalt = expectedHashLength;
        break;
    case RSA_PSS_SALTLEN_MAX_SIGN:
    case RSA_PSS_SALTLEN_MAX:
        cbSalt = cbSaltMax;
        break;
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    // Added in 3.1, smaller of digest length or maximized salt length
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
        cbSalt = cbSaltMax < (int)cbHashValue ? cbSaltMax : (int)cbHashValue;
#endif
    }

    if (cbSalt < 0 || cbSalt > cbSaltMax)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Invalid cbSalt");
        return SCOSSL_UNSUPPORTED;
    }

    cbResult = SymCryptRsakeySizeofModulus(key);
    if (pcbSignature == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, ERR_R_PASSED_NULL_PARAMETER,
                         "pcbSignature is NULL");
        goto cleanup;
    }

    *pcbSignature = cbResult;

    if (pbSignature == NULL)
    {
        ret = SCOSSL_SUCCESS;
        goto cleanup; // Not error - this can be called with NULL parameter for siglen
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == NID_md5)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm MD5 which is not FIPS compliant");
    }
    else if (mdnid == NID_sha1)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm SHA1 which is not FIPS compliant");
    }

    if (cbHashValue != expectedHashLength)
    {
        goto cleanup;
    }

    scError = SymCryptRsaPssSign(
        key,
        pbHashValue,
        cbHashValue,
        scosslHashAlgo,
        cbSalt,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pbSignature,
        *pcbSignature,
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
SCOSSL_STATUS scossl_rsapss_verify(PSYMCRYPT_RSAKEY key, int mdnid, int cbSalt,
                                   PCBYTE pbHashValue, SIZE_T cbHashValue,
                                   PCBYTE pbSignature, SIZE_T pcbSignature)
{
    int ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int cbSaltMax = scossl_rsa_pss_get_salt_max(key, cbHashValue);
    PCSYMCRYPT_HASH scosslHashAlgo = scossl_get_symcrypt_hash_algorithm(mdnid);
    SIZE_T expectedHashLength = scossl_get_expected_hash_length(mdnid);
    UINT32 scFlags = 0;

    if (scosslHashAlgo == NULL || expectedHashLength == (SIZE_T)-1)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_SIGN, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %d. Size: %d.", mdnid, cbHashValue);
        goto cleanup;
    }

    if (cbHashValue != expectedHashLength)
    {
        goto cleanup;
    }

    switch (cbSalt)
    {
    case RSA_PSS_SALTLEN_DIGEST:
        cbSalt = cbHashValue;
        break;
    case RSA_PSS_SALTLEN_MAX:
        cbSalt = cbSaltMax;
        break;
    case RSA_PSS_SALTLEN_AUTO:
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    // Added in 3.1; auto salt len for verify
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
#endif
        scFlags = SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT;
        cbSalt = 0;
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

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == NID_md5)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm MD5 which is not FIPS compliant");
    }
    else if (mdnid == NID_sha1)
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using hash algorithm SHA1 which is not FIPS compliant");
    }

    scError = SymCryptRsaPssVerify(
        key,
        pbHashValue,
        cbHashValue,
        pbSignature,
        pcbSignature,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        scosslHashAlgo,
        cbSalt,
        scFlags);

    if (scError == SYMCRYPT_NO_ERROR)
    {
        ret = SCOSSL_SUCCESS;
    }
    else if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptRsaPssVerify returned unexpected error", scError);
    }

cleanup:
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_encrypt(PSYMCRYPT_RSAKEY key, UINT padding,
                                 int mdnid, PCBYTE pbLabel, SIZE_T cbLabel, // OAEP-only parameters
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, INT32 *pcbDst, SIZE_T cbDst)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 cbModulus = SymCryptRsakeySizeofModulus(key);
    SIZE_T cbResult = -1;

    if (pbDst == NULL)
    {
        ret = SCOSSL_SUCCESS;
        *pcbDst = (INT32)cbModulus;
        goto cleanup;
    }

    if (cbDst == (SIZE_T)-1)
    {
        // cbDst is not caller supplied for engine
        cbDst = cbModulus;
    }

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
        if (cbSrc > cbModulus - SCOSSL_MIN_PKCS1_PADDING)
        {
            goto cleanup;
        }
        scError = SymCryptRsaPkcs1Encrypt(
            key,
            pbSrc,
            cbSrc,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbDst,
            cbModulus,
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

        PCSYMCRYPT_HASH scosslHashAlgo = scossl_get_symcrypt_hash_algorithm(mdnid);
        if (!scosslHashAlgo)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                             "Unknown type: %d.", mdnid);
            goto cleanup;
        }

        scError = SymCryptRsaOaepEncrypt(
            key,
            pbSrc,
            cbSrc,
            scosslHashAlgo,
            pbLabel,
            cbLabel,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbDst,
            cbModulus,
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
            key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbDst,
            cbModulus);
        cbResult = cbModulus;
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

    ret = cbResult <= INT_MAX;
    *pcbDst = ret ? (INT32)cbResult : -1;

cleanup:
    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_decrypt(PSYMCRYPT_RSAKEY key, UINT padding,
                                 int mdnid, PCBYTE pbLabel, SIZE_T cbLabel, // OAEP-only parameters
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, INT32 *pcbDst, SIZE_T cbDst)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH scosslHashAlgo = NULL;
    UINT32 cbModulus;
    UINT64 err = 0;
    SIZE_T cbResult = -1;

    cbModulus = SymCryptRsakeySizeofModulus(key);

    if (pbDst == NULL)
    {
        ret = SCOSSL_SUCCESS;
        *pcbDst = (INT32)cbModulus;
        goto cleanup;
    }

    if (cbDst == (SIZE_T)-1)
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
#ifdef RSA_PKCS1_WITH_TLS_PADDING
    case RSA_PKCS1_WITH_TLS_PADDING:
#endif
        scError = SymCryptRsaPkcs1Decrypt(
            key,
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
        // if( err > 0 ) { pcbDst = -1; }
        // else          { pcbDst = 0; }
        *pcbDst = (0ll - err) >> 32;
        ret = err <= 0;

        // Set pcbDst to cbResult if pcbDst still 0
        *pcbDst |= (UINT32)cbResult;
        goto cleanup;
    case RSA_PKCS1_OAEP_PADDING:
        scosslHashAlgo = scossl_get_symcrypt_hash_algorithm(mdnid);
        if (!scosslHashAlgo)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSAPSS_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                             "Unknown type: %d.", mdnid);
            goto cleanup;
        }

        scError = SymCryptRsaOaepDecrypt(
            key,
            pbSrc,
            cbSrc,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            scosslHashAlgo,
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
            key,
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

    ret = cbResult <= INT_MAX;
    *pcbDst = ret ? (INT32)cbResult : -1;

cleanup:
    return ret;
}

SCOSSL_RSA_EXPORT_PARAMS *scossl_rsa_new_export_params(BOOL includePrivate)
{
    SCOSSL_RSA_EXPORT_PARAMS *rsaParams = OPENSSL_malloc(sizeof(SCOSSL_RSA_EXPORT_PARAMS));

    if(rsaParams == NULL ||
       ((rsaParams->n = BN_new()) == NULL) ||
       ((rsaParams->e = BN_new()) == NULL))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        scossl_rsa_free_export_params(rsaParams, TRUE);
        rsaParams = NULL;
    }
    else if (includePrivate)
    {
        rsaParams->privateParams = OPENSSL_malloc(sizeof(SCOSSL_RSA_PRIVATE_EXPORT_PARAMS));
        if (rsaParams->privateParams == NULL ||
            ((rsaParams->privateParams->p    = BN_secure_new()) == NULL) ||
            ((rsaParams->privateParams->q    = BN_secure_new()) == NULL) ||
            ((rsaParams->privateParams->dmp1 = BN_secure_new()) == NULL) ||
            ((rsaParams->privateParams->dmq1 = BN_secure_new()) == NULL) ||
            ((rsaParams->privateParams->iqmp = BN_secure_new()) == NULL) ||
            ((rsaParams->privateParams->d    = BN_secure_new()) == NULL))
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_MALLOC_FAILURE,
                "BN_new returned NULL.");
            scossl_rsa_free_export_params(rsaParams, TRUE);
            rsaParams = NULL;
        }
    }
    else
    {
        rsaParams->privateParams = NULL;
    }

    return rsaParams;
}

// Contained BNs are not freed in the engine case,
// since OpenSSL just copies the pointer
_Use_decl_annotations_
void scossl_rsa_free_export_params(SCOSSL_RSA_EXPORT_PARAMS *rsaParams, BOOL freeParams)
{
    if (rsaParams != NULL)
    {
        if (freeParams)
        {
            BN_free(rsaParams->n);
            BN_free(rsaParams->e);
        }
        if (rsaParams->privateParams != NULL)
        {
            if (freeParams)
            {
                BN_clear_free(rsaParams->privateParams->p);
                BN_clear_free(rsaParams->privateParams->q);
                BN_clear_free(rsaParams->privateParams->dmp1);
                BN_clear_free(rsaParams->privateParams->dmq1);
                BN_clear_free(rsaParams->privateParams->iqmp);
                BN_clear_free(rsaParams->privateParams->d);
            }
            OPENSSL_free(rsaParams->privateParams);
        }
        OPENSSL_free(rsaParams);
    }
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_export_key(PCSYMCRYPT_RSAKEY key, SCOSSL_RSA_EXPORT_PARAMS *rsaParams)
{
    BOOL    includePrivate = rsaParams->privateParams != NULL;
    UINT64  pubExp64;
    BYTE    pbPubExp64[8];
    PBYTE   pbModulus = NULL;
    SIZE_T  cbModulus = 0;
    PBYTE   ppbPrimes[2] = {0};
    SIZE_T  pcbPrimes[2] = {0};
    SIZE_T  cbPrime1 = 0;
    SIZE_T  cbPrime2 = 0;
    PBYTE   ppbCrtExponents[2] = { 0 };
    SIZE_T  pcbCrtExponents[2] = { 0 };
    PBYTE   pbCrtCoefficient = NULL;
    SIZE_T  cbCrtCoefficient = 0;
    PBYTE   pbPrivateExponent = NULL;
    SIZE_T  cbPrivateExponent = 0;
    SIZE_T  nPrimes = includePrivate ? 2 : 0;
    PBYTE   pbCurrent = NULL;
    PBYTE   pbData = NULL;
    SIZE_T  cbData = 0;
    SCOSSL_STATUS  ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    //
    // Fill rsa structures so that OpenSSL helper functions can import/export the
    // structure to its format.
    // CNG format for reference:
    // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    //
    cbModulus = SymCryptRsakeySizeofModulus(key);
    cbPrime1 = SymCryptRsakeySizeofPrime(key, 0);
    cbPrime2 = SymCryptRsakeySizeofPrime(key, 1);

    cbData = cbModulus; // Modulus[cbModulus] // Big-endian.

    if (includePrivate)
    {
        cbData =
            cbModulus +     // Modulus[cbModulus] // Big-endian.
            cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
            cbPrime2 +      // Prime2[cbPrime2] // Big-endian.
            cbPrime1 +      // Exponent1[cbPrime1] // Big-endian.
            cbPrime2 +      // Exponent2[cbPrime2] // Big-endian.
            cbPrime1 +      // Coefficient[cbPrime1] // Big-endian.
            cbModulus;      // PrivateExponent[cbModulus] // Big-endian.
    }

    pbData = OPENSSL_zalloc(cbData);
    if (pbData == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc failed");
        goto cleanup;
    }
    pbCurrent = pbData;

    pbModulus = pbCurrent;
    pbCurrent += cbModulus;

    if (includePrivate)
    {
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
    }

    scError = SymCryptRsakeyGetValue(
                   key,
                   pbModulus, cbModulus,
                   &pubExp64, 1,
                   ppbPrimes, pcbPrimes, nPrimes,
                   SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
                   0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    // Explicitly convert UINT64 public exponent to little-endian byte array (no-op on little-endian target)
    SYMCRYPT_STORE_LSBFIRST64( pbPubExp64, pubExp64 );

    if (BN_lebin2bn(pbModulus, cbModulus, rsaParams->n) == NULL ||
        BN_lebin2bn(pbPubExp64, 8, rsaParams->e) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_OPERATION_FAIL,
            "BN_bin2bn failed.");
        goto cleanup;
    }

    if (includePrivate)
    {
        scError = SymCryptRsakeyGetCrtValue(
                        key,
                        ppbCrtExponents, pcbCrtExponents, nPrimes,
                        pbCrtCoefficient, cbCrtCoefficient,
                        pbPrivateExponent, cbPrivateExponent,
                        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
                        0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptRsakeyGetCrtValue failed", scError);
            goto cleanup;
        }

        if ((BN_lebin2bn(ppbPrimes[0], cbPrime1, rsaParams->privateParams->p) == NULL) ||
            (BN_lebin2bn(ppbPrimes[1], cbPrime2, rsaParams->privateParams->q) == NULL) ||
            (BN_lebin2bn(ppbCrtExponents[0], cbPrime1, rsaParams->privateParams->dmp1) == NULL) ||
            (BN_lebin2bn(ppbCrtExponents[1], cbPrime2, rsaParams->privateParams->dmq1) == NULL) ||
            (BN_lebin2bn(pbCrtCoefficient, cbPrime1, rsaParams->privateParams->iqmp)   == NULL) ||
            (BN_lebin2bn(pbPrivateExponent, cbPrivateExponent, rsaParams->privateParams->d) == NULL))
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_KEYGEN, ERR_R_OPERATION_FAIL,
                "BN_bin2bn failed.");
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if(pbData)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return ret;
}

#ifdef __cplusplus
}
#endif