//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_decode_common.h"
#include "signature/p_scossl_mldsa.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44, SCOSSL_LN_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65, SCOSSL_LN_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_DECODER(PrivateKeyInfo, mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87)
IMPLEMENT_SCOSSL_MLDSA_DECODER(SubjectPublicKeyInfo, mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87, SCOSSL_LN_MLDSA87)

#ifdef __cplusplus
}
#endif
