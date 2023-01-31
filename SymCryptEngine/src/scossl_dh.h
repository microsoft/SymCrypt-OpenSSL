//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int e_scossl_dh_idx;

// Initialize all of the _hidden_* dh variables
SCOSSL_STATUS e_scossl_dh_init_static();

// Generates public and private DH values.
// Expects shared parameters dh->p and dh->g to be set.
// Generates a random private DH key unless dh->priv_key set, and computes corresponding
// public value dh->pub_key.
// Returns 1 on success, 0 otherwise
SCOSSL_STATUS e_scossl_dh_generate_key(_Inout_ DH* dh);

// Computes the shared secret from the private DH value in dh and the other party's public
// value in pub_key and stores it in key. key must point to DH_size(dh) bytes of memory.
// Returns size of shared secret on success, or -1 on error.
SCOSSL_RETURNLENGTH e_scossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key, _In_ const BIGNUM* pub_key, _In_ DH* dh);

// Destroys instance of DH object. The memory for dh is not freed by this function.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS e_scossl_dh_finish(_Inout_ DH* dh);

// Frees internal SymCrypt safe-prime Dlgroups, only to be used on engine destruction.
void e_scossl_destroy_safeprime_dlgroups(void);

#ifdef __cplusplus
}
#endif
