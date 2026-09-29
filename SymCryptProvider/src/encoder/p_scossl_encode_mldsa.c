//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_encode_common.h"
#include "signature/p_scossl_mldsa.h"

#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

IMPLEMENT_SCOSSL_MLDSA_ENCODER(mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_ENCODER(mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_ENCODER(mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87)

#ifdef __cplusplus
}
#endif
