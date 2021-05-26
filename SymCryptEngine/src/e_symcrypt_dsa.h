//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <openssl/dsa.h>

#ifdef __cplusplus
extern "C" {
#endif


DSA_SIG* symcrypt_dsa_sign(const unsigned char* dgst, int dlen, DSA* dsa);

int symcrypt_dsa_sign_setup(DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);

int symcrypt_dsa_verify(const unsigned char* dgst, int dgst_len, DSA_SIG* sig, DSA* dsa);

int symcrypt_dsa_init(DSA* dsa);

int symcrypt_dsa_finish(DSA* dsa);

#ifdef __cplusplus
}
#endif


