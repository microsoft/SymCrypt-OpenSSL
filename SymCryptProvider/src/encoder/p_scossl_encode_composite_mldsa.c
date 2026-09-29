//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_encode_common.h"
#include "signature/p_scossl_composite_mldsa.h"

#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

IMPLEMENT_SCOSSL_MLDSA_ENCODER(composite_mldsa44_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256)
IMPLEMENT_SCOSSL_MLDSA_ENCODER(composite_mldsa65_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512)
IMPLEMENT_SCOSSL_MLDSA_ENCODER(composite_mldsa65_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512)
IMPLEMENT_SCOSSL_MLDSA_ENCODER(composite_mldsa87_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512)

#ifdef __cplusplus
}
#endif
