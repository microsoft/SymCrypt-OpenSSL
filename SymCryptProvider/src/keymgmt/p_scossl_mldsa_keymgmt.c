//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "keymgmt/p_scossl_mldsa_keymgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87)

#ifdef __cplusplus
}
#endif
