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
    SYMCRYPT_MLDSA_PARAMS mldsaParams;
} SCOSSL_MLDSA_ALG_INFO;

typedef struct
{
    OSSL_LIB_CTX *libctx;

    SYMCRYPT_MLDSA_PARAMS mldsaParams;
    SYMCRYPT_MLDSAKEY_FORMAT format;
    PSYMCRYPT_MLDSAKEY key;
} SCOSSL_MLDSA_KEY_CTX;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(int nid);
int p_scossl_mldsa_params_to_nid(SYMCRYPT_MLDSA_PARAMS mldsaParams);

#ifdef __cplusplus
}
#endif