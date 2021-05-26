//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                               const int **nids, int nid);

void symcrypt_destroy_pkey_methods(void);

#ifdef __cplusplus
}
#endif
