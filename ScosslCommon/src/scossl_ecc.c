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

static BOOL scossl_ecc_initialized = FALSE;
static PSYMCRYPT_ECURVE _hidden_curve_P192 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P224 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P256 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P384 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P521 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_X25519 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP256r1 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP256r1tls13 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP384r1 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP384r1tls13 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP512r1 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_brainpoolP512r1tls13 = NULL;


static const BYTE rgbCurveBrainpoolP256[] = {
    // dwVersion
    0x01, 0x00, 0x00, 0x00,
    // dwCurveType (Weierstrass over prime field)
    0x01, 0x00, 0x00, 0x00,
    // dwCurveGenerationAlgId (SYMCRYPT_FLAG_ECURVE_DONT_USE_SEED)
    0x04, 0x00, 0x00, 0x00,
    // cbFieldLength (32 bytes)
    0x20, 0x00, 0x00, 0x00,
    // cbSubgroupOrder
    0x20, 0x00, 0x00, 0x00,
    // cbCofactor
    0x01, 0x00, 0x00, 0x00,
    // cbSeed
    0x00, 0x00, 0x00, 0x00,

    // p (prime)
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
    0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,

    // a
    0x7D, 0x5A, 0x09, 0x75, 0xFC, 0x2C, 0x30, 0x57,
    0xEE, 0xF6, 0x57, 0x5B, 0x26, 0x1C, 0xBE, 0x39,
    0xE8, 0xF6, 0x1B, 0xB1, 0xB9, 0x6B, 0xA4, 0xB6,
    0x3E, 0xDA, 0xA0, 0x74, 0x8B, 0xDB, 0x35, 0x06,

    // b
    0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x8E, 0x80, 0x36,
    0xF8, 0x7B, 0xB7, 0x6E, 0x0A, 0x9C, 0xA2, 0x7B,
    0x2A, 0xB6, 0x98, 0x2F, 0xE8, 0xC1, 0x4A, 0xB6,
    0xB1, 0xD5, 0xF5, 0x4D, 0x7E, 0xA1, 0x0E, 0xE0,

    // Gx
    0x8B, 0xB6, 0xFB, 0x66, 0x7C, 0x47, 0x38, 0x74,
    0xAB, 0xE1, 0x6C, 0xC7, 0x7A, 0x11, 0xE2, 0x31,
    0x8E, 0x9E, 0x82, 0x57, 0x78, 0x6B, 0xB0, 0xF7,
    0x29, 0x89, 0x9C, 0xA5, 0xA8, 0x6C, 0xD9, 0x70,

    // Gy
    0x66, 0xDD, 0x02, 0xA3, 0xD9, 0xC0, 0x2D, 0xB2,
    0x6F, 0x5B, 0xA3, 0x19, 0x8E, 0x2E, 0xD8, 0x7E,
    0xA1, 0x8E, 0x05, 0x6B, 0xE3, 0xF6, 0xA8, 0x6A,
    0xC9, 0x3B, 0xB0, 0xC7, 0xA5, 0xF4, 0x1E, 0xD6,

    // q (order)
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
    0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,

    // h (cofactor)
    0x01,
};

static const BYTE rgbCurveBrainpoolP384[] = {
    // dwVersion = 1
    0x01, 0x00, 0x00, 0x00,
    // dwCurveType = SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS (1)
    0x01, 0x00, 0x00, 0x00,
    // dwCurveGenerationAlgId = SYMCRYPT_FLAG_ECURVE_DONT_USE_SEED (4)
    0x04, 0x00, 0x00, 0x00,
    // cbFieldLength = 48 bytes (384 bits)
    0x30, 0x00, 0x00, 0x00,
    // cbSubgroupOrder = 48 bytes
    0x30, 0x00, 0x00, 0x00,
    // cbCofactor = 1
    0x01, 0x00, 0x00, 0x00,
    // cbSeed = 0
    0x00, 0x00, 0x00, 0x00,

    // p (field prime, 48 bytes, big-endian)
    0x8C, 0x39, 0x46, 0xA6, 0x74, 0x9D, 0x1D, 0xD1,
    0x9C, 0x39, 0x07, 0x34, 0x0C, 0x4A, 0x5F, 0xF0,
    0x8C, 0x61, 0xB1, 0x96, 0xC8, 0x8A, 0xD2, 0x63,
    0x0E, 0xF9, 0xD8, 0x07, 0x7F, 0x14, 0x13, 0x48,
    0xD6, 0xE1, 0x39, 0x8E, 0x9E, 0x18, 0xE9, 0x28,
    0xC1, 0x6B, 0xE3, 0xA6, 0x81, 0x90, 0x9D, 0x0D,

    // a
    0x7B, 0xC3, 0x04, 0x45, 0x38, 0x30, 0x7C, 0x84,
    0x9C, 0xA7, 0x98, 0xC2, 0xE9, 0xC0, 0x26, 0x6D,
    0xC7, 0x40, 0x72, 0x29, 0x18, 0x10, 0x51, 0x27,
    0xC8, 0xC0, 0x6E, 0x1D, 0xB4, 0xCE, 0xB1, 0xD3,
    0x21, 0x6F, 0xB0, 0x85, 0xAB, 0xE8, 0xF7, 0xC0,
    0x8B, 0x86, 0x2B, 0xB1, 0x0A, 0x64, 0x20, 0x89,

    // b
    0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x38,
    0x59, 0x4C, 0xB0, 0x6D, 0xA8, 0x8E, 0x2F, 0xC7,
    0x13, 0x2A, 0xE4, 0xCB, 0xF1, 0x69, 0x3B, 0xA6,
    0x5A, 0x51, 0x29, 0x4A, 0xA7, 0xF3, 0x64, 0x62,
    0x2E, 0xF4, 0x11, 0x9C, 0xD4, 0xB8, 0x32, 0xF2,
    0x4D, 0xC7, 0x20, 0x7F, 0xB0, 0x90, 0x3E, 0xA6,

    // x
    0x1D, 0x1C, 0x64, 0xF0, 0x55, 0x72, 0x8E, 0xD6,
    0x49, 0x04, 0x93, 0xE8, 0xB5, 0xC0, 0x5E, 0xD7,
    0x5F, 0x98, 0x49, 0x5C, 0xA9, 0x65, 0x86, 0x5B,
    0xB4, 0x38, 0xE7, 0x02, 0x2C, 0xD7, 0x6D, 0xB0,
    0x8B, 0x4D, 0xA0, 0xBE, 0xF1, 0x6E, 0xF0, 0x8C,
    0x22, 0x29, 0x5B, 0x64, 0x9A, 0x7F, 0x39, 0x52,

    // y
    0x8A, 0xC0, 0xAA, 0x55, 0x0E, 0x07, 0xD7, 0xFA,
    0xB1, 0xCD, 0xB1, 0xB3, 0xC9, 0xBE, 0xB3, 0x2C,
    0xA5, 0x7F, 0xA0, 0x63, 0xC2, 0x6A, 0x84, 0x2A,
    0xEB, 0x23, 0x82, 0xF4, 0x09, 0xDD, 0x31, 0x44,
    0x45, 0x20, 0x67, 0x20, 0x78, 0xB7, 0x58, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8,

    // q (order)
    0x8C, 0x39, 0x46, 0xA6, 0x74, 0x9D, 0x1D, 0xD1,
    0x9C, 0x39, 0x07, 0x34, 0x0C, 0x4A, 0x5F, 0xF0,
    0x8C, 0x61, 0xB1, 0x96, 0xC8, 0x8A, 0xD2, 0x63,
    0x0E, 0xF9, 0xD8, 0x07, 0x7F, 0x14, 0x13, 0x48,
    0xD6, 0xE1, 0x39, 0x8E, 0x9E, 0x18, 0xE9, 0x28,
    0xC1, 0x6B, 0xE3, 0xA6, 0x81, 0x90, 0x9D, 0x0D,

    // h (cofactor = 1)
    0x01
};

static const BYTE rgbCurveBrainpoolP512[] = {
    // dwVersion = 1
    0x01, 0x00, 0x00, 0x00,
    // dwCurveType = SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS (1)
    0x01, 0x00, 0x00, 0x00,
    // dwCurveGenerationAlgId = SYMCRYPT_FLAG_ECURVE_DONT_USE_SEED (4)
    0x04, 0x00, 0x00, 0x00,
    // cbFieldLength = 64 bytes
    0x40, 0x00, 0x00, 0x00,
    // cbSubgroupOrder = 64 bytes
    0x40, 0x00, 0x00, 0x00,
    // cbCofactor = 1 byte
    0x01, 0x00, 0x00, 0x00,
    // cbSeed = 0
    0x00, 0x00, 0x00, 0x00,

    // p (64 bytes)
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
    0x6E, 0x3B, 0x04, 0x8F, 0x1D, 0xA7, 0x0A, 0xD2,
    0x91, 0xD9, 0x93, 0x4E, 0xC7, 0x55, 0x60, 0xC2,
    0x2B, 0x3B, 0xF1, 0xC6, 0x5D, 0xA9, 0x67, 0x7F,
    0xB9, 0x45, 0x66, 0x49, 0x46, 0x43, 0x03, 0x4A,
    0xFF, 0x3D, 0xF6, 0x38, 0x0E, 0x38, 0x94, 0x2D,
    0xE0, 0x29, 0x0B, 0x73, 0x9B, 0xB4, 0x71, 0x03,

    // a (64 bytes)
    0x78, 0x97, 0x59, 0x9D, 0xE6, 0x36, 0x90, 0x5C,
    0xA1, 0x48, 0x1E, 0xA9, 0xDA, 0x31, 0x13, 0xB9,
    0x44, 0x55, 0x8B, 0xB4, 0x0A, 0xA4, 0xBF, 0xBF,
    0xC8, 0x02, 0x91, 0x6F, 0xFE, 0x26, 0x06, 0xB0,
    0x56, 0xE3, 0xD9, 0x59, 0x18, 0x9C, 0xB7, 0x36,
    0xEC, 0x7A, 0xE2, 0x8F, 0xB5, 0xC5, 0x50, 0xB9,
    0x8A, 0x16, 0x13, 0xDC, 0xD0, 0x72, 0x77, 0x08,
    0xFE, 0xE0, 0xF6, 0x77, 0x2C, 0xE6, 0x88, 0x1F,

    // b (64 bytes)
    0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x8E, 0x5C, 0xA4,
    0xBD, 0xD1, 0x5C, 0x8B, 0xD1, 0xD6, 0x5E, 0x1E,
    0x3A, 0xDC, 0xB3, 0x7A, 0x39, 0x00, 0x99, 0x50,
    0xA5, 0xA4, 0x9F, 0x9E, 0x1A, 0x7F, 0x9B, 0x75,
    0x62, 0x63, 0x6D, 0xDF, 0xF2, 0x0E, 0x2A, 0xBE,
    0xBC, 0xC0, 0xA9, 0x0A, 0xAF, 0xE4, 0x85, 0xBA,
    0xB6, 0x26, 0x7E, 0xF9, 0xDB, 0xA1, 0x66, 0xD3,
    0x92, 0xB4, 0xBD, 0xF7, 0x4F, 0xB7, 0x1E, 0xAF,

    // Gx (64 bytes)
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x71,
    0x8C, 0x39, 0x45, 0xD8, 0x9C, 0xBC, 0xA8, 0x2F,
    0xB1, 0x8A, 0xC6, 0x33, 0x0E, 0xA1, 0x6C, 0x9C,
    0xC1, 0xD6, 0x43, 0xD4, 0x92, 0x74, 0x96, 0x36,
    0xEF, 0xF2, 0x50, 0x4A, 0x1C, 0xC6, 0x6E, 0x38,
    0x47, 0x46, 0xC2, 0x36, 0xDE, 0xCF, 0x98, 0x76,
    0x63, 0x29, 0x88, 0x58, 0x32, 0x2C, 0xC8, 0x91,

    // Gy (64 bytes)
    0x64, 0x48, 0x91, 0x8E, 0x81, 0x11, 0x02, 0x72,
    0x3C, 0xBE, 0xA5, 0x57, 0xF9, 0xD4, 0x34, 0x0C,
    0x5E, 0x36, 0x4F, 0x2E, 0xF3, 0xB7, 0x76, 0x37,
    0x6F, 0x1E, 0xD3, 0x56, 0x1C, 0x00, 0x7E, 0x2D,
    0xE3, 0x80, 0xD7, 0x4E, 0x1E, 0xBE, 0xF1, 0x6E,
    0x6F, 0xCF, 0xF2, 0x4C, 0xDF, 0xF4, 0x4C, 0xE7,
    0x3E, 0xE3, 0x8A, 0x6F, 0xF2, 0xEF, 0xFE, 0x73,
    0x95, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,

    // q (64 bytes)
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x71,
    0x8C, 0x39, 0x45, 0xD8, 0x9C, 0xBC, 0xA8, 0x2F,
    0xB1, 0x8A, 0xC6, 0x33, 0x0E, 0xA1, 0x6C, 0x9C,
    0xC1, 0xD6, 0x43, 0xD4, 0x92, 0x74, 0x96, 0x36,
    0xEF, 0xF2, 0x50, 0x4A, 0x1C, 0xC6, 0x6E, 0x38,
    0x47, 0x46, 0xC2, 0x36, 0xDE, 0xCF, 0x98, 0x76,
    0x63, 0x29, 0x88, 0x58, 0x32, 0x2C, 0xC8, 0x91,

    // h (1 byte): cofactor
    0x01,
};

const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP256r1 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP256;
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP384r1 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP384;
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP512r1 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP512;
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP256r1tls13 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP256;
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP384r1tls13 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP384;
const PCSYMCRYPT_ECURVE_PARAMS SymCryptEcurveParamsBrainpoolP512r1tls13 = (PCSYMCRYPT_ECURVE_PARAMS) rgbCurveBrainpoolP512;


SCOSSL_STATUS scossl_ecc_init_static()
{
    if (scossl_ecc_initialized)
        return SCOSSL_SUCCESS;

    if( ((_hidden_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0)) == NULL) ||
        ((_hidden_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0)) == NULL) ||
        ((_hidden_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0)) == NULL) ||
        ((_hidden_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0)) == NULL) ||
        ((_hidden_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0)) == NULL) ||
        ((_hidden_curve_X25519 = SymCryptEcurveAllocate(SymCryptEcurveParamsCurve25519, 0)) == NULL) || 
        ((_hidden_curve_brainpoolP256r1 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP256r1, 0)) == NULL) ||
        ((_hidden_curve_brainpoolP384r1 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP384r1, 0)) == NULL) ||
        ((_hidden_curve_brainpoolP512r1 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP512r1, 0)) == NULL) ||
        ((_hidden_curve_brainpoolP256r1tls13 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP256r1tls13, 0)) == NULL) ||
        ((_hidden_curve_brainpoolP384r1tls13 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP384r1tls13, 0)) == NULL) || 
        ((_hidden_curve_brainpoolP512r1tls13 = SymCryptEcurveAllocate(SymCryptEcurveParamsBrainpoolP512r1tls13, 0)) == NULL)) 
    {
        return SCOSSL_FAILURE;
    }
    scossl_ecc_initialized = TRUE;
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
    if (_hidden_curve_brainpoolP256r1 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP256r1);
        _hidden_curve_brainpoolP256r1 = NULL;
    }
    if (_hidden_curve_brainpoolP384r1 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP384r1);
        _hidden_curve_brainpoolP384r1 = NULL;
    }
    if (_hidden_curve_brainpoolP512r1 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP512r1);
        _hidden_curve_brainpoolP512r1 = NULL;
    }
    if (_hidden_curve_brainpoolP256r1tls13 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP256r1tls13);
        _hidden_curve_brainpoolP256r1tls13 = NULL;
    }
    if (_hidden_curve_brainpoolP384r1tls13 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP384r1tls13);
        _hidden_curve_brainpoolP384r1tls13 = NULL;
    }
    if (_hidden_curve_brainpoolP512r1tls13 != NULL)
    {
        SymCryptEcurveFree(_hidden_curve_brainpoolP512r1tls13);
        _hidden_curve_brainpoolP512r1tls13 = NULL;
    }

    scossl_ecc_initialized = FALSE;
}

PCSYMCRYPT_ECURVE scossl_ecc_nid_to_symcrypt_curve(int groupNid)
{
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
    case NID_brainpoolP256r1:
        return _hidden_curve_brainpoolP256r1;
    case NID_brainpoolP256r1tls13:
        return _hidden_curve_brainpoolP256r1tls13;
    case NID_brainpoolP384r1:
        return _hidden_curve_brainpoolP384r1;
    case NID_brainpoolP384r1tls13:
        return _hidden_curve_brainpoolP384r1tls13;
    case NID_brainpoolP512r1:
        return _hidden_curve_brainpoolP512r1;
    case NID_brainpoolP512r1tls13:
        return _hidden_curve_brainpoolP512r1tls13;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_ECC_GROUP_TO_SYMCRYPT_CURVE, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "SCOSSL does not yet support this group (nid %d).", groupNid);
    }

    return NULL;
}

_Use_decl_annotations_
PCSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(const EC_GROUP *group)
{
    if (group == NULL)
        return NULL;

    return scossl_ecc_nid_to_symcrypt_curve(EC_GROUP_get_curve_name(group));
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
    else if (pCurve == _hidden_curve_brainpoolP256r1)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
    }
    else if (pCurve == _hidden_curve_brainpoolP256r1tls13)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP256r1tls13);
    }
    else if (pCurve == _hidden_curve_brainpoolP384r1)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP384r1);
    }
    else if (pCurve == _hidden_curve_brainpoolP384r1tls13)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP384r1tls13);
    }
    else if (pCurve == _hidden_curve_brainpoolP512r1)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP512r1);
    }
    else if (pCurve == _hidden_curve_brainpoolP512r1tls13)
    {
        return EC_GROUP_new_by_curve_name(NID_brainpoolP512r1tls13);
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
    else if (curve == _hidden_curve_brainpoolP256r1)
    {
        ret = SN_brainpoolP256r1;
    }
    else if (curve == _hidden_curve_brainpoolP256r1tls13)
    {
        ret = SN_brainpoolP256r1tls13;
    }
    else if (curve == _hidden_curve_brainpoolP384r1)
    {
        ret = SN_brainpoolP384r1;
    }
    else if (curve == _hidden_curve_brainpoolP384r1tls13)
    {
        ret = SN_brainpoolP384r1tls13;
    }
    else if (curve == _hidden_curve_brainpoolP512r1)
    {
        ret = SN_brainpoolP512r1;
    }
    else if (curve == _hidden_curve_brainpoolP512r1tls13)
    {
        ret = SN_brainpoolP512r1tls13;
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
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_POINT_TO_PUBKEY, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(ecGroup, ecPoint, ecPubX, ecPubY, bnCtx))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_POINT_TO_PUBKEY, ERR_R_OPERATION_FAIL,
            "EC_POINT_get_affine_coordinates failed.");
        goto cleanup;
    }

    if (((SIZE_T) BN_bn2binpad(ecPubX, pbPublicKey, cbPublicKey/2) != cbPublicKey/2) ||
        ((SIZE_T) BN_bn2binpad(ecPubY, pbPublicKey + (cbPublicKey/2), cbPublicKey/2) != cbPublicKey/2))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECC_POINT_TO_PUBKEY, ERR_R_OPERATION_FAIL,
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

    if (pbS + cbS != pbSeq + cbSeq)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                         "Unexpected value in sequence");
        SCOSSL_LOG_BYTES_DEBUG(SCOSSL_ERR_F_ECDSA_REMOVE_DER, ERR_R_PASSED_INVALID_ARGUMENT,
                               "pbDerSignature", pbDerSignature, cbDerSignature);
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

/*
ECDSA-Sig-Value ::= SEQUENCE {
    r INTEGER,
    s INTEGER
}
*/

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
// 2 * (private key length) + DER encoding header bytes
_Use_decl_annotations_
SIZE_T scossl_ecdsa_size(PCSYMCRYPT_ECURVE curve)
{
    return 2*SymCryptEcurveSizeofScalarMultiplier(curve) + 8;
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
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECDSA_SIGN,
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
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECDSA_SIGN,
            "SymCryptEcDsaSign failed", scError);
        return SCOSSL_FAILURE;
    }

    if (!scossl_ecdsa_apply_der(buf, cbSymCryptSig, pbSignature, pcbSignature))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_SIGN, ERR_R_OPERATION_FAIL,
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
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECDSA_VERIFY,
            "SymCryptEckeyExtendKeyUsage failed", scError);
        return SCOSSL_FAILURE;
    }

    if (!scossl_ecdsa_remove_der(pbSignature, pcbSignature, &buf[0], cbSymCryptSig))
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ECDSA_VERIFY, ERR_R_OPERATION_FAIL,
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
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ECDSA_VERIFY,
                "SymCryptEcDsaVerify returned unexpected error", scError);
        }
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif