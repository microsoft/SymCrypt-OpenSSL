//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef DSA_SIG* (*PFN_DSA_meth_sign) (const unsigned char* dgst, int dlen, DSA* dsa);
typedef int (*PFN_DSA_meth_sign_setup) (DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);
typedef int (*PFN_DSA_meth_verify) (const unsigned char* dgst, int dgst_len, DSA_SIG* sig, DSA* dsa);
typedef int (*PFN_DSA_meth_init)(DSA* dsa);
typedef int (*PFN_DSA_meth_finish)(DSA* dsa);

// Computes a digital signature on the dlen byte message digest dgst using the private key dsa
// and returns it in a newly allocated DSA_SIG structure.
// Returns the signature on success, or NULL on error.
_Success_(return != NULL)
DSA_SIG* sc_ossl_dsa_sign(_In_reads_bytes_(dlen) const unsigned char* dgst, int dlen, _In_ DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_sign pfn_dsa_sign = DSA_meth_get_sign(ossl_dsa_meth);
    if (!pfn_dsa_sign) {
        return 0;
    }

    return pfn_dsa_sign(dgst, dlen, dsa);
}

// Precalculates the DSA signature values k^-1 and r.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_dsa_sign_setup(_In_ DSA* dsa, _In_ BN_CTX* ctx_in,
    _Out_ BIGNUM** kinvp, _Out_ BIGNUM** rp)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_sign_setup pfn_dsa_sign_setup = DSA_meth_get_sign_setup(ossl_dsa_meth);
    if (!pfn_dsa_sign_setup) {
        return 0;
    }

    return pfn_dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}

// Verifies that the signature sig matches a given message digest dgst of size dgst_len.
// dsa is the signer's public key.
// Returns 1 for a valid signature, 0 for an incorrect signature, and -1 on error.
SCOSSL_STATUS sc_ossl_dsa_verify(_In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len,
    _In_ DSA_SIG* sig, _In_ DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_verify pfn_dsa_verify = DSA_meth_get_verify(ossl_dsa_meth);
    if (!pfn_dsa_verify) {
        return 0;
    }

    return pfn_dsa_verify(dgst, dgst_len, sig, dsa);
}

// Initializes a new DSA instance.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_dsa_init(_Inout_ DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_init pfn_dsa_init = DSA_meth_get_init(ossl_dsa_meth);
    if (!pfn_dsa_init) {
        return 0;
    }

    return pfn_dsa_init(dsa);
}


// Destroys instance of DSA object. The memory for dsa is not freed by this function.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_dsa_finish(_Inout_ DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_finish pfn_dsa_finish = DSA_meth_get_finish(ossl_dsa_meth);
    if (!pfn_dsa_finish) {
        return 0;
    }

    return pfn_dsa_finish(dsa);
}


#ifdef __cplusplus
}
#endif


