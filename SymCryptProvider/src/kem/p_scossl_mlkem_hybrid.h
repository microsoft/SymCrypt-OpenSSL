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

    SYMCRYPT_MLKEM_PARAMS mlkemParams;
    SYMCRYPT_MLKEMKEY_FORMAT format;
    PSYMCRYPT_MLKEMKEY key;

    int classicGroupNid;
    SCOSSL_ECC_KEY_CTX *classicKeyCtx;
} SCOSSL_MLKEM_HYBRID_KEY_CTX;

#ifdef __cplusplus
}
#endif