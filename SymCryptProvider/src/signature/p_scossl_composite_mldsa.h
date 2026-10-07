//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int nid;
    const char *oid;
    const char *snGroupName;
    const char *lnGroupName;
    SYMCRYPT_COMPOSITE_MLDSA_PARAMS mldsaParams;
} SCOSSL_COMPOSITE_MLDSA_ALG_INFO;

typedef struct
{
    SYMCRYPT_COMPOSITE_MLDSA_PARAMS mldsaParams;
    SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT format;
    PSYMCRYPT_COMPOSITE_MLDSAKEY key;
} SCOSSL_COMPOSITE_MLDSA_KEY_CTX;

SCOSSL_STATUS p_scossl_composite_mldsa_register_algorithms();
SCOSSL_COMPOSITE_MLDSA_ALG_INFO *p_scossl_composite_mldsa_get_alg_info_by_nid(int nid);
int p_scossl_composite_mldsa_params_to_nid(SYMCRYPT_COMPOSITE_MLDSA_PARAMS mldsaParams);

#ifdef __cplusplus
}
#endif
