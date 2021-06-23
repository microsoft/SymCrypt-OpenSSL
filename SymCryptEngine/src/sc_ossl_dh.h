//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

int sc_ossl_dh_generate_key(DH* dh);

int sc_ossl_dh_compute_key(unsigned char* key, const BIGNUM* pub_key, DH* dh);

int sc_ossl_dh_bn_mod_exp(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);

int sc_ossl_dh_init(DH* dh);

int sc_ossl_dh_finish(DH* dh);

#ifdef __cplusplus
}
#endif
