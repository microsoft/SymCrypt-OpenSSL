//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    PSYMCRYPT_MLKEMKEY key;
    SYMCRYPT_MLKEM_PARAMS params;
    SYMCRYPT_MLKEMKEY_FORMAT format;
} SCOSSL_MLKEM_KEY_CTX;

#ifdef __cplusplus
}
#endif