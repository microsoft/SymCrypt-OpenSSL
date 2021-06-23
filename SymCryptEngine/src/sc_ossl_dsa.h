//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <openssl/dsa.h>

#ifdef __cplusplus
extern "C" {
#endif


DSA_SIG* sc_ossl_dsa_sign(const unsigned char* dgst, int dlen, DSA* dsa);

int sc_ossl_dsa_sign_setup(DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);

int sc_ossl_dsa_verify(const unsigned char* dgst, int dgst_len, DSA_SIG* sig, DSA* dsa);

int sc_ossl_dsa_init(DSA* dsa);

int sc_ossl_dsa_finish(DSA* dsa);

#ifdef __cplusplus
}
#endif
