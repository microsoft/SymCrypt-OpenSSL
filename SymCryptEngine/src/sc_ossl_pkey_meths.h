//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

int sc_ossl_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                               const int **nids, int nid);

void sc_ossl_destroy_pkey_methods(void);

#ifdef __cplusplus
}
#endif
