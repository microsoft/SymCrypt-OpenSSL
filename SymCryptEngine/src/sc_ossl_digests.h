//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/md2.h>
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

void symcrypt_destroy_digests(void);

#ifdef __cplusplus
}
#endif