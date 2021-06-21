//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef DSA_SIG* (*PFN_DSA_meth_sign) (const unsigned char* dgst, int dlen, DSA* dsa);
typedef int (*PFN_DSA_meth_sign_setup) (DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);
typedef int (*PFN_DSA_meth_verify) (const unsigned char* dgst, int dgst_len, DSA_SIG* sig, DSA* dsa);
typedef int (*PFN_DSA_meth_init)(DSA* dsa);
typedef int (*PFN_DSA_meth_finish)(DSA* dsa);

DSA_SIG* symcrypt_dsa_sign(const unsigned char* dgst, int dlen, DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_sign pfn_dsa_sign = DSA_meth_get_sign(ossl_dsa_meth);
    if (!pfn_dsa_sign) {
        return 0;
    }

    return pfn_dsa_sign(dgst, dlen, dsa);
}

int symcrypt_dsa_sign_setup(DSA* dsa, BN_CTX* ctx_in,
    BIGNUM** kinvp, BIGNUM** rp)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_sign_setup pfn_dsa_sign_setup = DSA_meth_get_sign_setup(ossl_dsa_meth);
    if (!pfn_dsa_sign_setup) {
        return 0;
    }

    return pfn_dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}

int symcrypt_dsa_verify(const unsigned char* dgst, int dgst_len,
    DSA_SIG* sig, DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_verify pfn_dsa_verify = DSA_meth_get_verify(ossl_dsa_meth);
    if (!pfn_dsa_verify) {
        return 0;
    }

    return pfn_dsa_verify(dgst, dgst_len, sig, dsa);
}

int symcrypt_dsa_init(DSA* dsa)
{
    const DSA_METHOD* ossl_dsa_meth = DSA_OpenSSL();
    PFN_DSA_meth_init pfn_dsa_init = DSA_meth_get_init(ossl_dsa_meth);
    if (!pfn_dsa_init) {
        return 0;
    }

    return pfn_dsa_init(dsa);
}


int symcrypt_dsa_finish(DSA* dsa)
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


