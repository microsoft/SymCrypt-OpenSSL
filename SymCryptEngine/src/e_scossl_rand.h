//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl.h"
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

RAND_METHOD *e_scossl_rand_method(void);

#ifdef __cplusplus
}
#endif
