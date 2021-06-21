//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_rsapss_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int symcrypt_rsapss_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);

#ifdef __cplusplus
}
#endif
