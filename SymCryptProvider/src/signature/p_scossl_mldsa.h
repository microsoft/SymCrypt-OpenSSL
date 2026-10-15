//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

// Holds either the pure or the composite variant of the corresponding SymCrypt enumeration.
// The two overlap numerically, so an isComposite flag is needed.
typedef int SCOSSL_MLDSA_PARAMS;
typedef int SCOSSL_MLDSAKEY_FORMAT;
typedef PVOID PSCOSSL_MLDSA_KEY;

typedef struct {
    int nid;
    const char *oid;
    const char *snGroupName;
    const char *lnGroupName;
    SCOSSL_MLDSA_PARAMS mldsaParams;
    BOOL isComposite;
} SCOSSL_MLDSA_ALG_INFO;

// The pure and composite SymCrypt key format enumerations overlap numerically, so the
// format values are selected by the keymgmt, which owns the definition of this struct
typedef struct SCOSSL_MLDSA_KEY_FORMATS_st SCOSSL_MLDSA_KEY_FORMATS;

#define SCOSSL_MLDSA_CONTEXT_MAX_LENGTH                                                \
    (SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH > SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH ? \
     SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH : SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH)

typedef struct
{
    const SCOSSL_MLDSA_KEY_FORMATS *formats;
    BOOL isComposite;

    SCOSSL_MLDSA_PARAMS mldsaParams;
    SCOSSL_MLDSAKEY_FORMAT format;

    PSCOSSL_MLDSA_KEY key;
} SCOSSL_MLDSA_KEY_CTX;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(int nid);
int p_scossl_mldsa_params_to_nid(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite);

#ifdef __cplusplus
}
#endif