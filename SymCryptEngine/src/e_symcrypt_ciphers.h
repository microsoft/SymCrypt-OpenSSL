//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <symcrypt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


int symcrypt_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);


void symcrypt_destroy_ciphers(void);

#ifdef __cplusplus
}
#endif
