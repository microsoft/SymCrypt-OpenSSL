//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NID_secp192r1 (NID_X9_62_prime192v1)
#define NID_secp256r1 (NID_X9_62_prime256v1)

// Smallest supported curve is P192 => 24 * 2 byte SymCrypt signatures
#define SCOSSL_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN (48)
// Largest supported curve is P521 => 66 * 2 byte SymCrypt signatures
#define SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN (132)

SCOSSL_STATUS scossl_ecc_init_static();
void scossl_ecc_destroy_ecc_curves();
PCSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(const EC_GROUP *group);
SCOSSL_STATUS scossl_ec_point_to_pubkey(_In_ const EC_POINT* ecPoint, _In_ const EC_GROUP *ecGroup, _In_ BN_CTX* bnCtx,
                                        _Out_writes_bytes_(cbPublicKey) PBYTE pbPublicKey, SIZE_T cbPublicKey);

SCOSSL_STATUS scossl_ecdsa_sign(_In_ PSYMCRYPT_ECKEY key,
                                _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                _Out_writes_bytes_opt_(*pcbSignature) PBYTE pbSignature, _Out_ unsigned int* pcbSignature);
SCOSSL_STATUS scossl_ecdsa_verify(_In_ PSYMCRYPT_ECKEY key,
                                  _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                  _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);

#ifdef __cplusplus
}
#endif