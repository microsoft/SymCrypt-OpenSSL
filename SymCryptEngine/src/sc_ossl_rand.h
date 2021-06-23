//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

RAND_METHOD *sc_ossl_rand_method(void);

#ifdef __cplusplus
}
#endif
