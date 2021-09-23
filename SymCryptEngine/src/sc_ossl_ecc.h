//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int eckey_sc_ossl_idx;

typedef int (*PFN_eckey_copy)(EC_KEY *dest, const EC_KEY *src);
typedef int (*PFN_eckey_set_group)(EC_KEY *key, const EC_GROUP *grp);
typedef int (*PFN_eckey_set_private)(EC_KEY *key, const BIGNUM *priv_key);
typedef int (*PFN_eckey_set_public)(EC_KEY *key, const EC_POINT *pub_key);

// Frees SymCrypt-specific components of key
void sc_ossl_eckey_finish(_Inout_ EC_KEY *key);

// Generates a new public and private key for the supplied key object.
// key must have an EC_GROUP object associated with it before calling this function.
// Returns 1 on success or 0 on error.
SCOSSL_STATUS sc_ossl_eckey_keygen(_Inout_ EC_KEY *key);

// Computes shared secret psec and secret length pseclen using pub_key and ecdh.
// Allocates psec on success.
// Returns length of secret on success, or -1 on error.
SCOSSL_RETURNLENGTH sc_ossl_eckey_compute_key(_Out_writes_bytes_(pseclen) unsigned char **psec,
                                                _Out_ size_t *pseclen,
                                                _In_ const EC_POINT *pub_key,
                                                _In_ const EC_KEY *ecdh);

// Computes a digital signature of the dlen bytes hash value dgst using the private EC key eckey
// and the optional pre-computed values kinv and r. The DER encoded signature is stored in sig and its length
// is returned in siglen. (sig must point to ECDSA_size(eckey) bytes of memory). The parameter type is ignored.
// Returns 1 on success or 0 on error.
SCOSSL_STATUS sc_ossl_eckey_sign(int type,
                        _In_reads_bytes_(dlen) const unsigned char* dgst,
                        int dlen,
                        _Out_writes_bytes_(siglen) unsigned char* sig,
                        _Out_ unsigned int* siglen,
                        _In_opt_ const BIGNUM* kinv,
                        _In_opt_ const BIGNUM* r,
                        _In_ EC_KEY* eckey);

// Precomputes parts of signing operation. eckey is the private EC key and ctx_in is a pointer to BN_CTX
// structure (or NULL). The precomputed values are returned in kinv and rp and can be used in a later call
// to ECDSA_sign_ex or ECDSA_do_sign_ex.
// Returns 1 on success or 0 on error.
SCOSSL_STATUS sc_ossl_eckey_sign_setup(_In_ EC_KEY* eckey, _In_ BN_CTX* ctx_in, _Out_ BIGNUM** kinvp, _Out_ BIGNUM** rp);

// Computes a digital signature of the dgst_len bytes hash value dgst using the private EC key eckey
// and the optional pre-computed values in_kinv and in_r.
// Returns the signature in a newly allocated ECDSA_SIG structure, or NULL on error.
ECDSA_SIG* sc_ossl_eckey_sign_sig(_In_reads_bytes_(dgstlen) const unsigned char* dgst, int dgst_len,
                                   _In_opt_ const BIGNUM* in_kinv, _In_opt_ const BIGNUM* in_r,
                                   _In_ EC_KEY* eckey);

// Verifies that the signature in sigbuf of size sig_len is a valid ECDSA signature of the hash value dgst
// of size dgst_len using the public key eckey. The parameter type is ignored.
// Returns 1 for a valid signature, 0 for an invalid signature, and -1 on error.
SCOSSL_STATUS sc_ossl_eckey_verify(int type, _In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len,
                          _In_reads_bytes_(sig_len) const unsigned char* sigbuf, int sig_len, _In_ EC_KEY* eckey);

// Verifies that the signature in sig is a valid ECDSA signature of the hash value dgst of size dgst_len
// using the public key eckey.
// Returns 1 for a valid signature, 0 for an invalid signature, and -1 on error.
SCOSSL_STATUS sc_ossl_eckey_verify_sig(_In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len,
                              _In_ const ECDSA_SIG* sig, _In_ EC_KEY* eckey);

// Frees internal SymCrypt curves, only to be used on engine destruction.
void sc_ossl_destroy_ecc_curves(void);

#ifdef __cplusplus
}
#endif
