//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    OSSL_LIB_CTX *libctx;
    BOOL initialized;
    int includePublic;
    PSYMCRYPT_ECKEY key;
    EC_GROUP* ecGroup;
} SCOSSL_ECC_KEY_CTX;

#ifdef __cplusplus
}
#endif