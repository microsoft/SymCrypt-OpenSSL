#include "scossl_rsa.h"
#include <openssl/core_names.h>
#include <openssl/proverr.h>

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
    if (type == NID_sha3_256)
        return SymCryptSha3_256Algorithm;
    if (type == NID_sha3_384)
        return SymCryptSha3_384Algorithm;
    if (type == NID_sha3_512)
        return SymCryptSha3_512Algorithm;
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

SCOSSL_RSA_KEY_CTX *scossl_rsa_new_key_ctx()
{
    SCOSSL_RSA_KEY_CTX *kctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_KEY_CTX));
    if (kctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }

    return kctx;
}

_Use_decl_annotations_
    SCOSSL_RSA_KEY_CTX *
    scossl_rsa_dup_key_ctx(const SCOSSL_RSA_KEY_CTX *keyCtx)
{
    SCOSSL_RSA_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_KEY_CTX));
    if (copyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
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
        copyCtx->key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
        if (copyCtx->key == NULL)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_INITIALIZE_RSA_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                             "SymCryptRsakeyAllocate failed");
            scossl_rsa_free_key_ctx(copyCtx);
            return NULL;
        }

        SymCryptRsakeyCopy((PCSYMCRYPT_RSAKEY)keyCtx->key, copyCtx->key);
        copyCtx->initialized = 1;
    }

    return copyCtx;
}

_Use_decl_annotations_ void scossl_rsa_free_key_ctx(SCOSSL_RSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key)
    {
        SymCryptRsakeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }
    keyCtx->initialized = 0;

    OPENSSL_free(keyCtx);
}

_Use_decl_annotations_
    SCOSSL_STATUS
    scossl_rsa_pkcs1_sign(SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid,
                          PCBYTE pbHashValue, SIZE_T cbHashValue,
                          PBYTE pbSignature, SIZE_T *pcbSignature)
{
    UINT32 cbModulus = 0;
    SIZE_T cbResult = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    if (pbSignature == NULL || pcbSignature == NULL)
    {
        goto cleanup;
    }

    switch (mdnid)
    {
    case NID_md5_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_MD5_SHA1_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            NULL,
            0,
            SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_MD5_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptMd5OidList,
            SYMCRYPT_MD5_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_SHA1_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha1OidList,
            SYMCRYPT_SHA1_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha256:
        if (cbHashValue != SCOSSL_SHA256_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha256OidList,
            SYMCRYPT_SHA256_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha384:
        if (cbHashValue != SCOSSL_SHA384_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha384OidList,
            SYMCRYPT_SHA384_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha512:
        if (cbHashValue != SCOSSL_SHA512_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha512OidList,
            SYMCRYPT_SHA512_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha3_256:
        if (cbHashValue != SCOSSL_SHA256_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha3_256OidList,
            SYMCRYPT_SHA3_256_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha3_384:
        if (cbHashValue != SCOSSL_SHA384_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha3_384OidList,
            SYMCRYPT_SHA3_384_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    case NID_sha3_512:
        if (cbHashValue != SCOSSL_SHA512_DIGEST_LENGTH)
        {
            goto cleanup;
        }

        scError = SymCryptRsaPkcs1Sign(
            keyCtx->key,
            pbHashValue,
            cbHashValue,
            SymCryptSha3_512OidList,
            SYMCRYPT_SHA3_512_OID_COUNT,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSignature,
            cbModulus,
            &cbResult);
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %s. Size: %d.", OBJ_nid2sn(mdnid), cbHashValue);
        goto cleanup;
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_RSA_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                  "SymCryptRsaPkcs1Sign failed", scError);
        goto cleanup;
    }

    *pcbSignature = cbResult;
    ret = SCOSSL_SUCCESS;

cleanup:
    return ret;
}

_Use_decl_annotations_
    SCOSSL_STATUS
    scossl_rsa_pkcs1_verify(SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid,
                            PCBYTE pbHashValue, SIZE_T cbHashValue,
                            PCBYTE pbSignature, SIZE_T pcbSignature)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    switch (mdnid)
    {
    case NID_md5_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5+SHA1 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_MD5_SHA1_DIGEST_LENGTH)
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
            NULL,
            0,
            0);
        break;
    case NID_md5:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm MD5 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_MD5_DIGEST_LENGTH)
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
            SymCryptMd5OidList,
            SYMCRYPT_MD5_OID_COUNT,
            0);
        break;
    case NID_sha1:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                        "Using Mac algorithm SHA1 which is not FIPS compliant");
        if (cbHashValue != SCOSSL_SHA1_DIGEST_LENGTH)
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
            SymCryptSha1OidList,
            SYMCRYPT_SHA1_OID_COUNT,
            0);
        break;
    case NID_sha256:
        if (cbHashValue != SCOSSL_SHA256_DIGEST_LENGTH)
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
            SymCryptSha256OidList,
            SYMCRYPT_SHA256_OID_COUNT,
            0);
        break;
    case NID_sha384:
        if (cbHashValue != SCOSSL_SHA384_DIGEST_LENGTH)
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
            SymCryptSha384OidList,
            SYMCRYPT_SHA384_OID_COUNT,
            0);
        break;
    case NID_sha512:
        if (cbHashValue != SCOSSL_SHA512_DIGEST_LENGTH)
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
            SymCryptSha512OidList,
            SYMCRYPT_SHA512_OID_COUNT,
            0);
        break;
    case NID_sha3_256:
        if (cbHashValue != SCOSSL_SHA256_DIGEST_LENGTH)
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
            SymCryptSha3_256OidList,
            SYMCRYPT_SHA3_256_OID_COUNT,
            0);
        break;
    case NID_sha3_384:
        if (cbHashValue != SCOSSL_SHA384_DIGEST_LENGTH)
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
            SymCryptSha3_384OidList,
            SYMCRYPT_SHA3_384_OID_COUNT,
            0);
        break;
    case NID_sha3_512:
        if (cbHashValue != SCOSSL_SHA512_DIGEST_LENGTH)
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
            SymCryptSha3_512OidList,
            SYMCRYPT_SHA3_512_OID_COUNT,
            0);
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_RSA_VERIFY, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                         "Unknown type: %s. Size: %d.", mdnid, cbHashValue);
        goto cleanup;
    }

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
SCOSSL_STATUS
scossl_rsapss_sign(SCOSSL_RSA_KEY_CTX *keyCtx, EVP_MD *md, int cbSalt,
                   PCBYTE pbHashValue, SIZE_T cbHashValue,
                   PBYTE pbSignature, SIZE_T *pcbSignature)
{
    size_t cbResult = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int ret = SCOSSL_FAILURE;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
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
    expectedTbsLength = scossl_get_expected_tbs_length(mdnid);
    if (!scossl_mac_algo || expectedTbsLength == (SIZE_T)-1)
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

    if (cbHashValue != expectedTbsLength)
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
SCOSSL_STATUS scossl_rsapss_verify(SCOSSL_RSA_KEY_CTX *keyCtx, EVP_MD *md, int cbSalt,
                                   PCBYTE pbHashValue, SIZE_T cbHashValue,
                                   PCBYTE pbSignature, SIZE_T pcbSignature)
{
    int ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH scossl_mac_algo = NULL;
    size_t expectedTbsLength = -1;
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
    expectedTbsLength = scossl_get_expected_tbs_length(mdnid);
    if (!scossl_mac_algo || expectedTbsLength == (SIZE_T)-1)
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

    if (cbHashValue != expectedTbsLength)
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
SCOSSL_STATUS scossl_rsa_encrypt(SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding, int mdnid,
                                 PCBYTE pbLabel, SIZE_T cbLabel,
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, SIZE_T *pcbDst, SIZE_T cbDst)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);

    if (pbDst == NULL)
    {
        *pcbDst = cbModulus;
        goto cleanup;
    }

    if (pbSrc == NULL)
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
                       pcbDst);
        if( scError != SYMCRYPT_NO_ERROR )
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
                       SymCryptSha1Algorithm,
                       pbLabel,
                       cbLabel,
                       0,
                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                       pbDst,
                       cbDst,
                       pcbDst);
        if( scError != SYMCRYPT_NO_ERROR )
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
        *pcbDst = cbDst;
        if( scError != SYMCRYPT_NO_ERROR )
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

cleanup:
    return *pcbDst <= INT_MAX;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_decrypt(SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding, int mdnid,
                                 PCBYTE pbLabel, SIZE_T cbLabel,
                                 PCBYTE pbSrc, SIZE_T cbSrc,
                                 PBYTE pbDst, SIZE_T *pcbDst, SIZE_T cbDst)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 cbModulus;
    UINT64 err = 0;
    SIZE_T cbResult = -1;

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);

    if (pbDst == NULL)
    {
        *pcbDst = cbModulus;
        goto cleanup;
    }

    if (pbSrc == NULL ||
        cbDst > cbModulus)
    {
        goto cleanup;
    }

    *pcbDst = -1;

    switch( padding )
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

        // Set ret based on scError and cbResult
        // cbResult > INT_MAX               => err > 0
        err = (UINT64)cbResult >> 31;
        // scError != SYMCRYPT_NO_ERROR    => err > 0
        err |= (UINT32)(scError ^ SYMCRYPT_NO_ERROR);
        // if( err > 0 ) { ret = -1; }
        // else          { ret = 0; }
        *pcbDst = (0ll - err) >> 32;

        // Set ret to cbResult if ret still 0
        *pcbDst |= (UINT32)cbResult;
        goto cleanup;
    case RSA_PKCS1_OAEP_PADDING:
        PCSYMCRYPT_HASH scossl_mac_algo = scossl_get_symcrypt_hash_algorithm(mdnid);
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
        if( scError != SYMCRYPT_NO_ERROR )
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
        if( scError != SYMCRYPT_NO_ERROR )
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

    *pcbDst = (cbResult <= INT_MAX) ? (int) cbResult : -1;

cleanup:
    return *pcbDst <= INT_MAX;
}