//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_STATUS scossl_ecc_init_static();
PSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(EC_GROUP *group);

#ifdef __cplusplus
}
#endif