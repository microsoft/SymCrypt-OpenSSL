//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "keymgmt/p_scossl_composite_mldsa_keymgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa44_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa65_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa65_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(composite_mldsa87_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512)

#ifdef __cplusplus
}
#endif
