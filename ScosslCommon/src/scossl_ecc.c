//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NID_secp192r1 (NID_X9_62_prime192v1)
#define NID_secp256r1 (NID_X9_62_prime256v1)

static PSYMCRYPT_ECURVE _hidden_curve_P192 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P224 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P256 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P384 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P521 = NULL;

SCOSSL_STATUS scossl_ecc_init_static()
{
    if( ((_hidden_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0)) == NULL) ||
        ((_hidden_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0)) == NULL) ||
        ((_hidden_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0)) == NULL) ||
        ((_hidden_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0)) == NULL) ||
        ((_hidden_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0)) == NULL) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

PSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(EC_GROUP *group)
{
    if (group == NULL)
    {
        return NULL;
    }

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
            "SymCrypt-OpenSSL does not yet support this group (nid %d).", groupNid);
    }

    return NULL;
}

#ifdef __cplusplus
}
#endif