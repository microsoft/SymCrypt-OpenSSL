//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generates public and private DH values.
// Expects shared parameters dh->p and dh->g to be set.
// Generates a random private DH key unless dh->priv_key set, and computes corresponding
// public value dh->pub_key.
// Returns 1 on success, 0 otherwise
SCOSSL_STATUS sc_ossl_dh_generate_key(_Inout_ DH* dh);

// Computes the shared secret from the private DH value in dh and the other party's public
// value in pub_key and stores it in key. key must point to DH_size(dh) bytes of memory.
// Returns size of shared secret on success, or -1 on error.
SCOSSL_RETURNLENGTH sc_ossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key, _In_ const BIGNUM* pub_key, _In_ DH* dh);

// Computes r = a ^ p mod m
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_dh_bn_mod_exp(_In_ const DH* dh, _Out_ BIGNUM* r,
    _In_ const BIGNUM* a, _In_ const BIGNUM* p,
    _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx);

// Initializes a new DH instance.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_dh_init(_Inout_ DH* dh);

// Destroys instance of DH object. The memory for dh is not freed by this function.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_dh_finish(_Inout_ DH* dh);

#ifdef __cplusplus
}
#endif
