//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Largest supported curve is P521 => 66 * 2 byte SymCrypt signatures
#define SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN (132)

SCOSSL_STATUS scossl_ecc_init_static();
void scossl_ecc_destroy_ecc_curves();

// x25519 is a separate interface in the provider and not supported in the
// engine, so there's no need to fetch the hidden group from an EC_GROUP.
PCSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(_In_ const EC_GROUP *group);
PCSYMCRYPT_ECURVE scossl_ecc_get_x25519_curve();
EC_GROUP *scossl_ecc_symcrypt_curve_to_ecc_group(_In_ PCSYMCRYPT_ECURVE pCurve);
int scossl_ecc_get_curve_security_bits(_In_ PCSYMCRYPT_ECURVE curve);

const char *scossl_ecc_get_curve_name(_In_ PCSYMCRYPT_ECURVE curve);
SCOSSL_STATUS scossl_ec_point_to_pubkey(_In_ const EC_POINT* ecPoint, _In_ const EC_GROUP *ecGroup, _In_ BN_CTX* bnCtx,
                                        _Out_writes_bytes_(cbPublicKey) PBYTE pbPublicKey, SIZE_T cbPublicKey);

SIZE_T scossl_ecdsa_size(_In_ PCSYMCRYPT_ECURVE curve);

SCOSSL_STATUS scossl_ecdsa_sign(_In_ PSYMCRYPT_ECKEY key, _In_ PCSYMCRYPT_ECURVE curve,
                                _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                _Out_writes_bytes_opt_(*pcbSignature) PBYTE pbSignature, _Out_ unsigned int* pcbSignature);
SCOSSL_STATUS scossl_ecdsa_verify(_In_ PSYMCRYPT_ECKEY key, _In_ PCSYMCRYPT_ECURVE curve,
                                  _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                  _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);

#ifdef __cplusplus
}
#endif