//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"
#include <openssl/dsa.h>

#ifdef __cplusplus
extern "C" {
#endif


// Computes a digital signature on the dlen byte message digest dgst using the private key dsa
// and returns it in a newly allocated DSA_SIG structure.
// Returns the signature on success, or NULL on error.
_Success_(return != NULL)
DSA_SIG* scossl_dsa_sign(_In_reads_bytes_(dlen) const unsigned char* dgst, int dlen, _In_ DSA* dsa);

// Precalculates the DSA signature values k^-1 and r.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_dsa_sign_setup(_In_ DSA* dsa, _In_ BN_CTX* ctx_in, _Out_ BIGNUM** kinvp, _Out_ BIGNUM** rp);

// Verifies that the signature sig matches a given message digest dgst of size dgst_len.
// dsa is the signer's public key.
// Returns 1 for a valid signature, 0 for an incorrect signature, and -1 on error.
SCOSSL_STATUS scossl_dsa_verify(_In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len, _In_ DSA_SIG* sig, _In_ DSA* dsa);

// Initializes a new DSA instance.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS scossl_dsa_init(_Inout_ DSA* dsa);

// Destroys instance of DSA object. The memory for dsa is not freed by this function.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS scossl_dsa_finish(_Inout_ DSA* dsa);

#ifdef __cplusplus
}
#endif
