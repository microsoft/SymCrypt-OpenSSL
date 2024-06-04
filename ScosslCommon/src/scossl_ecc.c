//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_secp192r1 (SN_X9_62_prime192v1)
#define SN_secp256r1 (SN_X9_62_prime256v1)

#define NID_secp192r1 (NID_X9_62_prime192v1)
#define NID_secp256r1 (NID_X9_62_prime256v1)

// If r and s are both 0, the DER encoding would be 8 bytes
// (0x30 0x06 0x02 0x01 0x00 0x02 0x01 0x00)
// integers must contain at least 1 octet of content in DER
#define SCOSSL_ECDSA_MIN_DER_SIGNATURE_LEN (8)
// Largest supported curve is P521 => 66 * 2 + 4 (int headers) + 3 (seq header)
#define SCOSSL_ECDSA_MAX_DER_SIGNATURE_LEN (139)
// Smallest supported curve is P192 => 24 * 2 byte SymCrypt signatures
#define SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN (48)

static PSYMCRYPT_ECURVE _hidden_curve_P192 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P224 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P256 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P384 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P521 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_X25519 = NULL;

SCOSSL_STATUS scossl_ecc_init_static()
{
    if( ((_hidden_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0)) == NULL) ||
        ((_hidden_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0)) == NULL) ||
        ((_hidden_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0)) == NULL) ||
        ((_hidden_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0)) == NULL) ||
        ((_hidden_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0)) == NULL) ||
        ((_hidden_curve_X25519 = SymCryptEcurveAllocate(SymCryptEcurveParamsCurve25519, 0)) == NULL))
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

void scossl_ecc_destroy_ecc_curves()
{
    if (_hidden_curve_P192 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_P192);
        _hidden_curve_P192 = NULL;
    }
    if (_hidden_curve_P224 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_P224);
        _hidden_curve_P224 = NULL;
    }
    if (_hidden_curve_P256 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_P256);
        _hidden_curve_P256 = NULL;
    }
    if (_hidden_curve_P384 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_P384);
        _hidden_curve_P384 = NULL;
    }
    if (_hidden_curve_P521 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_P521);
        _hidden_curve_P521 = NULL;
    }
    if (_hidden_curve_X25519 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_X25519);
        _hidden_curve_X25519 = NULL;
    }
}

_Use_decl_annotations_
PCSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(const EC_GROUP *group)
{
    if (group == NULL)
        return NULL;

    int groupNid = EC_GROUP_get_curve_name(group);

    // Only reroute NIST Prime curves to SymCrypt for now
    switch (groupNid)
    {
    case NID_secp192r1:
        return _hidden_curve_P192;
    case NID_secp224r1:
        return _hidden_curve_P224;
    case NID_secp256r1:
        return _hidden_curve_P256;
    case NID_secp384r1:
        return _hidden_curve_P384;
    case NID_secp521r1:
        return _hidden_curve_P521;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_ECC_CONTEXT_EX, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "SCOSSL does not yet support this group (nid %d).", groupNid);
    }

    return NULL;
}

PCSYMCRYPT_ECURVE scossl_ecc_get_x25519_curve()
{
    return _hidden_curve_X25519;
}

_Use_decl_annotations_
EC_GROUP *scossl_ecc_symcrypt_curve_to_ecc_group(PCSYMCRYPT_ECURVE pCurve)
{
    if (pCurve == NULL)
        return NULL;

    if (pCurve == _hidden_curve_P192)
    {
        return EC_GROUP_new_by_curve_name(NID_secp192r1);
    }
    else if (pCurve == _hidden_curve_P224)
    {
        return EC_GROUP_new_by_curve_name(NID_secp224r1);
    }
    else if (pCurve == _hidden_curve_P256)
    {
        return EC_GROUP_new_by_curve_name(NID_secp256r1);
    }
    else if (pCurve == _hidden_curve_P384)
    {
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
    }
    else if (pCurve == _hidden_curve_P521)
    {
        return EC_GROUP_new_by_curve_name(NID_secp521r1);
    }

    return NULL;
}

// Gets the security strength of the algorithm in discrete values as
// specified in "NIST Special Publication 800-57 Part 1 Revision 5"
// This matches the default OpenSSL behavior.
_Use_decl_annotations_
int scossl_ecc_get_curve_security_bits(PCSYMCRYPT_ECURVE curve)
{
    // Security strength is estimated as groupOrderBits / 2. For
    // P192 and x25519, this doesn't match one of the discrete values.
    if (curve == _hidden_curve_P192)
    {
        return 80;
    }
    else if (curve == _hidden_curve_X25519)
    {
        return 128;
    }

    return SymCryptEcurveBitsizeofGroupOrder(curve) / 2;
}


_Use_decl_annotations_
const char *scossl_ecc_get_curve_name(PCSYMCRYPT_ECURVE curve)
{
    const char *ret = NULL;

    if (curve == _hidden_curve_P192)
    {
        ret = SN_secp192r1;
    }
    else if (curve == _hidden_curve_P224)
    {
        ret = SN_secp224r1;
    }
    else if (curve == _hidden_curve_P256)
    {
        ret = SN_secp256r1;
    }
    else if (curve == _hidden_curve_P384)
    {
        ret = SN_secp384r1;
    }
    else if (curve == _hidden_curve_P521)
    {
        ret = SN_secp521r1;
    }
    else if (curve == _hidden_curve_X25519)
    {
        ret = SN_X25519;
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_ec_point_to_pubkey(const EC_POINT* ecPoint, const EC_GROUP *ecGroup, BN_CTX* bnCtx,
                                        PBYTE pbPublicKey, SIZE_T cbPublicKey)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    BIGNUM* ecPubX = NULL;
    BIGNUM* ecPubY = NULL;

    if (((ecPubX = BN_new()) == NULL) ||
        ((ecPubY = BN_new()) == NULL))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(ecGroup, ecPoint, ecPubX, ecPubY, bnCtx))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_POINT_get_affine_coordinates failed.");
        goto cleanup;
    }

    if (((SIZE_T) BN_bn2binpad(ecPubX, pbPublicKey, cbPublicKey/2) != cbPublicKey/2) ||
        ((SIZE_T) BN_bn2binpad(ecPubY, pbPublicKey + (cbPublicKey/2), cbPublicKey/2) != cbPublicKey/2))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_bn2binpad did not write expected number of public key bytes.");
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    BN_free(ecPubX);
    BN_free(ecPubY);

    return ret;
}

static SCOSSL_STATUS scossl_ecdsa_der_check_tag_and_get_value_and_length(_In_reads_bytes_(cbDerField) PCBYTE pbDerField, SIZE_T cbDerField,
                                                                         BYTE expectedTag,
                                                                         _Out_writes_bytes_(pcbContent) PCBYTE *ppbContent, SIZE_T *pcbContent)
{
    PCBYTE pbContent = NULL;
    SIZE_T cbContent = 0;
    int res = SCOSSL_FAILURE;

    // Check for tag
    if (pbDerField[0] != expectedTag)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, ERR_R_PASSED_INVALID_ARGUMENT,
                         "pbDerField[0] != 0x%x", expectedTag);
        goto cleanup;
    }

    // Extract content length and pointer to beginning of content
    cbContent = pbDerField[1];
    pbContent = pbDerField + 2;
    if (cbContent > 0x7f)
    {
        // Only acceptable length with long form has 1 byte length
        if (cbContent == 0x81)
        {
            if (pbDerField[2] > 0x7f)
            {
                cbContent = pbDerField[2];
                pbContent = pbDerField + 3;
            }
            else
            {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, ERR_R_PASSED_INVALID_ARGUMENT,
                                 "Der element length field is not minimal");
                goto cleanup;
            }
        }
        else
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, ERR_R_PASSED_INVALID_ARGUMENT,
                             "Unexpected length field encoding. pbDerField[1] == 0x%x", cbContent);
            goto cleanup;
        }
    }

    if (pbContent + cbContent > pbDerField + cbDerField)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Decoded content length does not fit in derField buffer. pbDerField [0x%lx, 0x%lx), pbContent [0x%lx, 0x%lx)",
                         pbDerField, pbDerField + cbDerField, pbContent, pbContent + cbContent);
        goto cleanup;
    }

    *ppbContent = pbContent;
    *pcbContent = cbContent;

    res = SCOSSL_SUCCESS;

cleanup:
    return res;
}

// Quick hack function to parse precisely the DER encodings which we expect for ECDSA signatures for the NIST prime curves
// Extracts the encoded R and S and places them in a buffer with 2 same-sized big-endian encodings (BER encoding expected by SymCrypt)
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on failure.
static SCOSSL_STATUS scossl_ecdsa_remove_der(_In_reads_bytes_(cbDerSignature) PCBYTE pbDerSignature, SIZE_T cbDerSignature,
                                             _Out_writes_bytes_(cbSymCryptSignature) PBYTE pbSymCryptSignature, SIZE_T cbSymCryptSignature)
{
    PCBYTE pbSeq = NULL;
    SIZE_T cbSeq = 0;
    PCBYTE pbR = NULL;
    SIZE_T cbR = 0;
    PCBYTE pbS = NULL;
    SIZE_T cbS = 0;
    int res = SCOSSL_FAILURE;

    // Check the provided lengths are within reasonable bounds
    if ((cbDerSignature < SCOSSL_ECDSA_MIN_DER_SIGNATURE_LEN) ||
        (cbDerSignature > SCOSSL_ECDSA_MAX_DER_SIGNATURE_LEN) ||
        (cbSymCryptSignature < SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature > SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature % 2 == 1))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Incorrect size: cbDerSignature %d should be in range [%d, %d]\n"
                         "                cbSymCryptSignature %d should be even integer in range [%d, %d]",
                         cbDerSignature, SCOSSL_ECDSA_MIN_DER_SIGNATURE_LEN, SCOSSL_ECDSA_MAX_DER_SIGNATURE_LEN,
                         cbSymCryptSignature, SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN, SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN);
        goto cleanup;
    }

    if (!scossl_ecdsa_der_check_tag_and_get_value_and_length(
            pbDerSignature, cbDerSignature, 0x30, &pbSeq, &cbSeq))
    {
        goto cleanup;
    }

    if (pbSeq + cbSeq != pbDerSignature + cbDerSignature)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Sequence length field (0x%x) does not match cbDerSignature (0x%x)", cbSeq, cbDerSignature);
        SCOSSL_LOG_BYTES_DEBUG(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                               "pbDerSignature", pbDerSignature, cbDerSignature);
        goto cleanup;
    }

    if (!scossl_ecdsa_der_check_tag_and_get_value_and_length(
            pbSeq, cbSeq, 0x02, &pbR, &cbR))
    {
        goto cleanup;
    }

    if (cbR > cbSeq - 3)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "cbR = pbSeq[1] > cbSeq - 3");
        SCOSSL_LOG_BYTES_DEBUG(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                               "pbDerSignature", pbDerSignature, cbDerSignature);
        goto cleanup;
    }

    if (!scossl_ecdsa_der_check_tag_and_get_value_and_length(
            pbR + cbR, (pbSeq + cbSeq) - (pbR + cbR), 0x02, &pbS, &cbS))
    {
        goto cleanup;
    }

    // Check R's validity
    if (((pbR[0] & 0x80) == 0x80) ||                                  // R is negative
        ((cbR > 1) && (pbR[0] == 0x00) && ((pbR[1] & 0x80) != 0x80))) // R is non-zero, and has a redundant leading 0 byte
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "pbR is not strict DER encoded non-negative integer");
        SCOSSL_LOG_BYTES_DEBUG(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                               "pbR", pbR, cbR);
        goto cleanup;
    }
    // Trim leading 0 from R
    if (pbR[0] == 0)
    {
        pbR++;
        cbR--;
    }
    // Check S's validity
    if (((pbS[0] & 0x80) == 0x80) ||                                  // S is negative
        ((cbS > 1) && (pbS[0] == 0x00) && ((pbS[1] & 0x80) != 0x80))) // S is non-zero, and has a redundant leading 0 byte
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "pbS is not strict DER encoded non-negative integer");
        SCOSSL_LOG_BYTES_DEBUG(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                               "pbS", pbS, cbS);
        goto cleanup;
    }
    // Trim leading 0 from S
    if (pbS[0] == 0)
    {
        pbS++;
        cbS--;
    }

    if ((cbSymCryptSignature < 2 * cbR) || (cbSymCryptSignature < 2 * cbS))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "cbR (%d) or cbS (%d) too big for cbSymCryptSignature (%d)", cbR, cbS, cbSymCryptSignature);
        goto cleanup;
    }

    memset(pbSymCryptSignature, 0, cbSymCryptSignature);
    memcpy(pbSymCryptSignature + (cbSymCryptSignature / 2) - cbR, pbR, cbR);
    memcpy(pbSymCryptSignature + cbSymCryptSignature - cbS, pbS, cbS);

    res = SCOSSL_SUCCESS;

cleanup:
    return res;
}

// Quick hack function to generate precisely the DER encodings which we want for ECDSA signatures for the NIST prime curves
// Takes 2 same-size big-endian integers output from SymCrypt and encodes them in the minimally sized (strict) equivalent DER encoding
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on failure.
static SCOSSL_STATUS scossl_ecdsa_apply_der(_In_reads_bytes_(cbSymCryptSignature) PCBYTE pbSymCryptSignature, SIZE_T cbSymCryptSignature,
                                            _Out_writes_bytes_(cbDerSignature) PBYTE pbDerSignature, _Out_ unsigned int* cbDerSignature)
{
    PBYTE  pbWrite = pbDerSignature;
    SIZE_T cbSeq = 0;
    SIZE_T padSeq = 0;
    PCBYTE pbR = NULL;
    SIZE_T cbR = 0;
    SIZE_T padR = 0;
    PCBYTE pbS = NULL;
    SIZE_T cbS = 0;
    SIZE_T padS = 0;
    int res = SCOSSL_FAILURE;

    // Check the provided lengths are within reasonable bounds
    if( (cbSymCryptSignature < SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature > SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature % 2 == 1) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_APPLY_DER, ERR_R_PASSED_INVALID_ARGUMENT,
            "Incorrect size: cbSymCryptSignature %d should be even integer in range [%d, %d]",
            cbSymCryptSignature, SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN, SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN );
        goto cleanup;
    }

    pbR = pbSymCryptSignature;
    cbR = cbSymCryptSignature/2;
    pbS = pbSymCryptSignature + cbR;
    cbS = cbSymCryptSignature/2;

    while( (*pbR == 0) && cbR > 0 )
    {
        pbR++;
        cbR--;
    }
    if( (*pbR & 0x80) == 0x80)
    {
        padR = 1;
    }

    while( (*pbS == 0) && cbS > 0 )
    {
        pbS++;
        cbS--;
    }
    if( (*pbS & 0x80) == 0x80)
    {
        padS = 1;
    }

    cbSeq = cbR + padR + cbS + padS + 4;
    if( cbSeq > 0x7f )
    {
        // cbSeq must be encoded in 2 bytes - 0x81 <cbSeq>
        padSeq = 1;
    }

    *cbDerSignature = (SIZE_T)cbSeq + padSeq + 2;

    // Write SEQUENCE header
    *pbWrite = 0x30;
    pbWrite++;
    if( padSeq )
    {
        *pbWrite = 0x81;
        pbWrite++;
    }
    *pbWrite = (BYTE) cbSeq;
    pbWrite++;

    // Write R
    pbWrite[0] = 0x02;
    pbWrite[1] = (BYTE) (cbR + padR);
    pbWrite += 2;
    if( padR )
    {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbR, cbR);
    pbWrite += cbR;

    // Write S
    pbWrite[0] = 0x02;
    pbWrite[1] = (BYTE) (cbS + padS);
    pbWrite += 2;
    if( padS )
    {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbS, cbS);

    res = SCOSSL_SUCCESS;

cleanup:
    return res;
}

// Return the max length of the DER encoded signature
// 2 * (private key length) + 7 DER encoding header bytes
_Use_decl_annotations_
SIZE_T scossl_ecdsa_size(PCSYMCRYPT_ECURVE curve)
{
    return 2*SymCryptEcurveSizeofScalarMultiplier(curve) + 7;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_ecdsa_sign(PSYMCRYPT_ECKEY key, PCSYMCRYPT_ECURVE curve,
                                PCBYTE pbHashValue, SIZE_T cbHashValue,
                                PBYTE pbSignature, unsigned int* pcbSignature)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE buf[SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = {0};
    SIZE_T cbSymCryptSig = 2*SymCryptEcurveSizeofScalarMultiplier(curve);

    scError = SymCryptEckeyExtendKeyUsage(key, SYMCRYPT_FLAG_ECKEY_ECDSA);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECKEY_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyExtendKeyUsage failed", scError);
        return SCOSSL_FAILURE;
    }

    scError = SymCryptEcDsaSign(
        key,
        pbHashValue,
        cbHashValue,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        buf,
        cbSymCryptSig);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECKEY_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEcDsaSign failed", scError);
        return SCOSSL_FAILURE;
    }

    if (!scossl_ecdsa_apply_der(buf, cbSymCryptSig, pbSignature, pcbSignature))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECKEY_SIGN, ERR_R_OPERATION_FAIL,
            "scossl_ecdsa_apply_der failed");
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_ecdsa_verify(PSYMCRYPT_ECKEY key, PCSYMCRYPT_ECURVE curve,
                                  PCBYTE pbHashValue, SIZE_T cbHashValue,
                                  PCBYTE pbSignature, SIZE_T pcbSignature)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE buf[SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = {0};
    SIZE_T cbSymCryptSig = 2*SymCryptEcurveSizeofScalarMultiplier(curve);

    scError = SymCryptEckeyExtendKeyUsage(key, SYMCRYPT_FLAG_ECKEY_ECDSA);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECKEY_SIGN, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyExtendKeyUsage failed", scError);
        return SCOSSL_FAILURE;
    }

    if (!scossl_ecdsa_remove_der(pbSignature, pcbSignature, &buf[0], cbSymCryptSig))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECKEY_VERIFY, ERR_R_OPERATION_FAIL,
            "scossl_ecdsa_remove_der failed");
        return SCOSSL_FAILURE;
    }

    scError = SymCryptEcDsaVerify(
        key,
        pbHashValue,
        cbHashValue,
        buf,
        cbSymCryptSig,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        if (scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECKEY_VERIFY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptEcDsaVerify returned unexpected error", scError);
        }
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif