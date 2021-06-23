//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"

#ifdef __cplusplus
extern "C" {
#endif

int sc_ossl_hkdf_init(EVP_PKEY_CTX *ctx);
void sc_ossl_hkdf_cleanup(EVP_PKEY_CTX *ctx);
int sc_ossl_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int sc_ossl_hkdf_derive_init(EVP_PKEY_CTX *ctx);
int sc_ossl_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

#ifdef __cplusplus
}
#endif
