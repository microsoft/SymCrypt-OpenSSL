//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*PFN_DH_meth_generate_key) (DH*);
typedef int (*PFN_DH_meth_compute_key)(unsigned char* key, const BIGNUM* pub_key, DH* dh);
typedef int (*PFN_DH_meth_bn_mod_exp)(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
typedef int (*PFN_DH_meth_init)(DH* dh);
typedef int (*PFN_DH_meth_finish)(DH* dh);

SCOSSL_STATUS sc_ossl_dh_generate_key(_Inout_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_generate_key pfn_dh_meth_generate_key = DH_meth_get_generate_key(ossl_dh_meth);
    if (!pfn_dh_meth_generate_key) {
        return 0;
    }

    return pfn_dh_meth_generate_key(dh);
}

SCOSSL_RETURNLENGTH sc_ossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key, _In_ const BIGNUM* pub_key, _In_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_compute_key pfn_dh_meth_compute_key = DH_meth_get_compute_key(ossl_dh_meth);
    if (!pfn_dh_meth_compute_key) {
        return 0;
    }

    return pfn_dh_meth_compute_key(key, pub_key, dh);
}

SCOSSL_STATUS sc_ossl_dh_bn_mod_exp(_In_ const DH* dh, _Out_ BIGNUM* r,
    _In_ const BIGNUM* a, _In_ const BIGNUM* p,
    _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_bn_mod_exp pfn_dh_meth_bm_mod_exp = DH_meth_get_bn_mod_exp(ossl_dh_meth);
    if (!pfn_dh_meth_bm_mod_exp) {
        return 0;
    }

    return pfn_dh_meth_bm_mod_exp(dh, r, a, p, m, ctx, m_ctx);
}

SCOSSL_STATUS sc_ossl_dh_init(_Inout_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_init pfn_dh_meth_init = DH_meth_get_init(ossl_dh_meth);
    if (!pfn_dh_meth_init) {
        return 0;
    }

    return pfn_dh_meth_init(dh);
}

SCOSSL_STATUS sc_ossl_dh_finish(_Inout_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_finish pfn_dh_meth_finish = DH_meth_get_finish(ossl_dh_meth);
    if (!pfn_dh_meth_finish) {
        return 0;
    }

    return pfn_dh_meth_finish(dh);
}


#ifdef __cplusplus
}
#endif

