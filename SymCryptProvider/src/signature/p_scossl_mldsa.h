//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"
#ifdef KEYSINUSE_ENABLED
#include "keysinuse.h"
#endif

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

// Used for key formats a variant does not support. Never matches a SymCrypt key format.
#define SCOSSL_MLDSAKEY_FORMAT_UNSUPPORTED (-1)

// The pure and composite SymCrypt key format enumerations overlap numerically, so
// each key context references the format values for its variant
typedef struct {
    SCOSSL_MLDSAKEY_FORMAT null;
    SCOSSL_MLDSAKEY_FORMAT privateSeed;
    SCOSSL_MLDSAKEY_FORMAT privateKey;
    SCOSSL_MLDSAKEY_FORMAT publicKey;
} SCOSSL_MLDSA_KEY_FORMATS;

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

#ifdef KEYSINUSE_ENABLED
    BOOL isImported;
    SCOSSL_KEYSINUSE_CTX *keysinuseCtx;
#endif
} SCOSSL_MLDSA_KEY_CTX;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(int nid);
int p_scossl_mldsa_params_to_nid(SCOSSL_MLDSA_PARAMS mldsaParams, BOOL isComposite);

#ifdef __cplusplus
}
#endif