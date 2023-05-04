#include "scossl_rsa.h"

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
SCOSSL_RSA_KEY_CTX *scossl_rsa_dup_key_ctx(const SCOSSL_RSA_KEY_CTX *keyCtx)
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

        SymCryptRsakeyCopy((PCSYMCRYPT_RSAKEY) keyCtx->key, copyCtx->key);
        copyCtx->initialized = 1;
    }

    return copyCtx;
}

_Use_decl_annotations_ 
void scossl_rsa_free_key_ctx(SCOSSL_RSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key)
    {
        SymCryptRsakeyFree(keyCtx->key);
        keyCtx->key = NULL;
    }
    keyCtx->initialized = 0;
    return;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_rsa_sign(SCOSSL_RSA_KEY_CTX *keyCtx, int type,
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

    switch (type)
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
                         "Unknown type: %s. Size: %d.", OBJ_nid2sn(type), cbHashValue);
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
SCOSSL_STATUS scossl_rsa_verify(SCOSSL_RSA_KEY_CTX *keyCtx, int type,
                                PCBYTE pbHashValue, SIZE_T cbHashValue,
                                PCBYTE pbSignature, SIZE_T pcbSignature)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    switch (type)
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
                         "Unknown type: %s. Size: %d.", type, cbHashValue);
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