#include "e_symcrypt_dh.h"

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


int symcrypt_dh_generate_key(DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_generate_key pfn_dh_meth_generate_key = DH_meth_get_generate_key(ossl_dh_meth);
    if (!pfn_dh_meth_generate_key) {
        return 0;
    }

    return pfn_dh_meth_generate_key(dh);
}

int symcrypt_dh_compute_key(unsigned char* key, const BIGNUM* pub_key, DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_compute_key pfn_dh_meth_compute_key = DH_meth_get_compute_key(ossl_dh_meth);
    if (!pfn_dh_meth_compute_key) {
        return 0;
    }

    return pfn_dh_meth_compute_key(key, pub_key, dh);
}


int symcrypt_dh_bn_mod_exp(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_bn_mod_exp pfn_dh_meth_bm_mod_exp = DH_meth_get_bn_mod_exp(ossl_dh_meth);
    if (!pfn_dh_meth_bm_mod_exp) {
        return 0;
    }

    return pfn_dh_meth_bm_mod_exp(dh, r, a, p, m, ctx, m_ctx);
}


int symcrypt_dh_init(DH* dh)
{
    const DH_METHOD* ossl_dh_meth = DH_OpenSSL();

    PFN_DH_meth_init pfn_dh_meth_init = DH_meth_get_init(ossl_dh_meth);
    if (!pfn_dh_meth_init) {
        return 0;
    }

    return pfn_dh_meth_init(dh);
}


int symcrypt_dh_finish(DH* dh)
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

