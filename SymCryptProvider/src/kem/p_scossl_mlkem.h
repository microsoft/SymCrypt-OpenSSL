//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SCOSSL_PROVCTX *provCtx;

    const char *groupName;
    PSYMCRYPT_MLKEMKEY key;
    SYMCRYPT_MLKEM_PARAMS mlkemParams;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    const char *classicGroupName;
    SCOSSL_ECC_KEY_CTX *classicKeyCtx;
} SCOSSL_MLKEM_KEY_CTX;

SCOSSL_STATUS p_scossl_mlkem_register_algorithms();

#ifdef __cplusplus
}
#endif