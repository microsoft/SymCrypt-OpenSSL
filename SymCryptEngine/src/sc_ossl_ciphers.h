//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <symcrypt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


int sc_ossl_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);


void sc_ossl_destroy_ciphers(void);

#ifdef __cplusplus
}
#endif
