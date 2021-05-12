#include "e_symcrypt_ecc.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*PFN_eckey_sign)(
                            int type, const unsigned char* dgst, int dlen,
                            unsigned char* sig, unsigned int* siglen,
                            const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey);
typedef int (*PFN_eckey_sign_setup)(
                            EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp,
                            BIGNUM** rp);
typedef ECDSA_SIG* (*PFN_eckey_sign_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const BIGNUM* in_kinv, const BIGNUM* in_r,
                            EC_KEY* eckey);
typedef int (*PFN_eckey_verify)(
                            int type, const unsigned char* dgst, int dgst_len,
                            const unsigned char* sigbuf, int sig_len, EC_KEY* eckey);
typedef int (*PFN_eckey_verify_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const ECDSA_SIG* sig, EC_KEY* eckey);
typedef int (*PFN_eckey_init)(EC_KEY *key);
typedef void (*PFN_eckey_finish)(EC_KEY *key);
typedef int (*PFN_eckey_copy)(EC_KEY *dest, const EC_KEY *src);
typedef int (*PFN_eckey_set_group)(EC_KEY *key, const EC_GROUP *grp);
typedef int (*PFN_eckey_set_private)(EC_KEY *key, const BIGNUM *priv_key);
typedef int (*PFN_eckey_set_public)(EC_KEY *key, const EC_POINT *pub_key);

typedef int (*PFN_eckey_keygen)(EC_KEY *key);
typedef int (*PFN_eckey_compute_key)(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh);

typedef struct _SYMCRYPT_ECC_KEY_CONTEXT {
    int initialized;
    unsigned char* data;
    PSYMCRYPT_ECKEY key;
} SYMCRYPT_ECC_KEY_CONTEXT;

int eckey_symcrypt_idx = -1;

int symcrypt_eckey_sign(int type, const unsigned char* dgst, int dlen,
    unsigned char* sig, unsigned int* siglen,
    const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign pfn_eckey_sign = NULL;
    EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
    if (!pfn_eckey_sign) {
        return 0;
    }
    return pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
}


int symcrypt_eckey_sign_setup(EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp,
    BIGNUM** rp)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign_setup pfn_eckey_sign_setup = NULL;

    EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, &pfn_eckey_sign_setup, NULL);
    if (!pfn_eckey_sign_setup) {
        return 0;
    }
    return pfn_eckey_sign_setup(eckey, ctx_in, kinvp, rp);
}


ECDSA_SIG* symcrypt_eckey_sign_sig(const unsigned char* dgst, int dgst_len,
    const BIGNUM* in_kinv, const BIGNUM* in_r,
    EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign_sig pfn_eckey_sign_sig = NULL;

    EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, NULL, &pfn_eckey_sign_sig);
    if (!pfn_eckey_sign_sig) {
        return NULL;
    }

    return pfn_eckey_sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
}


int symcrypt_eckey_verify(
    int type, const unsigned char* dgst, int dgst_len,
    const unsigned char* sigbuf, int sig_len, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_verify pfn_eckey_verify = NULL;

    EC_KEY_METHOD_get_verify(ossl_eckey_method, &pfn_eckey_verify, NULL);
    if (!pfn_eckey_verify) {
        return 0;
    }

    return pfn_eckey_verify(type, dgst, dgst_len, sigbuf, sig_len, eckey);
}


int symcrypt_eckey_verify_sig(
    const unsigned char* dgst, int dgst_len, const ECDSA_SIG* sig, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_verify_sig pfn_eckey_verify_sig = NULL;

    EC_KEY_METHOD_get_verify(ossl_eckey_method, NULL, &pfn_eckey_verify_sig);
    if (!pfn_eckey_verify_sig) {
        return 0;
    }

    return pfn_eckey_verify_sig(dgst, dgst_len, sig, eckey);
}

int symcrypt_eckey_keygen(EC_KEY *key)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_keygen pfn_eckey_keygen = NULL;
    EC_KEY_METHOD_get_keygen(ossl_eckey_method, &pfn_eckey_keygen);
    if (!pfn_eckey_keygen) {
        return 0;
    }
    return pfn_eckey_keygen(key);
}

int symcrypt_eckey_compute_key(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_compute_key pfn_eckey_compute_key = NULL;
    EC_KEY_METHOD_get_compute_key(ossl_eckey_method, &pfn_eckey_compute_key);
    if (!pfn_eckey_compute_key) {
        return 0;
    }
    return pfn_eckey_compute_key(psec, pseclen, pub_key, ecdh);
}

int symcrypt_eckey_init(EC_KEY *key)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if (!keyCtx) {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }
    EC_KEY_set_ex_data(key, eckey_symcrypt_idx, keyCtx);

    ret = 1;

CommonReturn:
    return ret;

err:
    ret = 0;
    goto CommonReturn;
}

void symcrypt_ecc_free_key_context(SYMCRYPT_ECC_KEY_CONTEXT *keyCtx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (keyCtx->data) {
        OPENSSL_free(keyCtx->data);
    }
    if (keyCtx->key) {
        SymCryptEckeyFree(keyCtx->key);
    }
    keyCtx->initialized = 0;
    return;
}

void symcrypt_eckey_finish(EC_KEY *key)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = EC_KEY_get_ex_data(key, eckey_symcrypt_idx);
    symcrypt_ecc_free_key_context(keyCtx);
    EC_KEY_set_ex_data(key, eckey_symcrypt_idx, NULL);
    return;
}

#ifdef __cplusplus
}
#endif
