//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_dh_generate_key(DH* dh);

int symcrypt_dh_compute_key(unsigned char* key, const BIGNUM* pub_key, DH* dh);

int symcrypt_dh_bn_mod_exp(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);

int symcrypt_dh_init(DH* dh);

int symcrypt_dh_finish(DH* dh);

#ifdef __cplusplus
}
#endif


