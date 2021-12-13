//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

RAND_METHOD *scossl_rand_method(void);

#ifdef __cplusplus
}
#endif
