//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_pkey_meths.h"
#include "sc_ossl_helpers.h"
#include "sc_ossl_hkdf.h"
#include "sc_ossl_tls1prf.h"
#include "sc_ossl_rsapss.h"
#include <openssl/evp.h>
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif


static int sc_ossl_evp_nids[] = {
    EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS,
    EVP_PKEY_TLS1_PRF,
    EVP_PKEY_HKDF,
    // EVP_PKEY_X25519 - Future
};
const int evp_nids_count = sizeof(sc_ossl_evp_nids) / sizeof(sc_ossl_evp_nids[0]);



static const EVP_PKEY_METHOD *_openssl_pkey_rsa = NULL;
static int (*_openssl_pkey_rsa_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) = NULL;
static int (*_openssl_pkey_rsa_verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) = NULL;

static int sc_ossl_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    SC_OSSL_LOG_DEBUG(NULL);
    int padding;

    if( EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get padding");
        return -2;
    }

    if( padding == RSA_PKCS1_PSS_PADDING )
    {
        return sc_ossl_rsapss_sign(ctx, sig, siglen, tbs, tbslen);
    }

    return _openssl_pkey_rsa_sign(ctx, sig, siglen, tbs, tbslen);
}

static int sc_ossl_pkey_rsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    SC_OSSL_LOG_DEBUG(NULL);
    int padding;
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0 )
    {
        SC_OSSL_LOG_ERROR("Failed to get padding");
        return -2;
    }

    if( padding == RSA_PKCS1_PSS_PADDING )
    {
        if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
        {
            SC_OSSL_LOG_ERROR("Failed to get cbSalt");
            return -2;
        }
        if( cbSalt != RSA_PSS_SALTLEN_AUTO )
        {

            return sc_ossl_rsapss_verify(ctx, sig, siglen, tbs, tbslen);
        }
        SC_OSSL_LOG_INFO("SymCrypt Engine does not support RSA_PSS_SALTLEN_AUTO saltlen - falling back to OpenSSL");
    }

    return _openssl_pkey_rsa_verify(ctx, sig, siglen, tbs, tbslen);
}

static EVP_PKEY_METHOD *_sc_ossl_pkey_rsa = NULL;
static EVP_PKEY_METHOD *sc_ossl_pkey_rsa(void)
{
    int (*psign_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*pverify_init) (EVP_PKEY_CTX *ctx) = NULL;
    int flags = 0;

    SC_OSSL_LOG_DEBUG(NULL);
    if( _sc_ossl_pkey_rsa == NULL )
    {
        EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_rsa );

        if( (_sc_ossl_pkey_rsa = EVP_PKEY_meth_new(EVP_PKEY_RSA, flags)) != NULL )
        {
            // start with the default openssl method
            EVP_PKEY_meth_copy(_sc_ossl_pkey_rsa, _openssl_pkey_rsa);

            // overwrite the sign and verify methods
            // we just want to use the pss method if pss padding is specified
            EVP_PKEY_meth_get_sign(_sc_ossl_pkey_rsa, &psign_init, &_openssl_pkey_rsa_sign);
            EVP_PKEY_meth_get_verify(_sc_ossl_pkey_rsa, &psign_init, &_openssl_pkey_rsa_verify);

            EVP_PKEY_meth_set_sign(_sc_ossl_pkey_rsa, psign_init, sc_ossl_pkey_rsa_sign);
            EVP_PKEY_meth_set_verify(_sc_ossl_pkey_rsa, psign_init, sc_ossl_pkey_rsa_verify);
        }
    }
    return _sc_ossl_pkey_rsa;
}

static const EVP_PKEY_METHOD *_openssl_pkey_rsa_pss = NULL;
static EVP_PKEY_METHOD *_sc_ossl_pkey_rsa_pss = NULL;
static EVP_PKEY_METHOD *sc_ossl_pkey_rsa_pss(void)
{
    int (*psign_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*psign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) = NULL;
    int (*pverify_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*pverify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) = NULL;
    int flags = 0;

    SC_OSSL_LOG_DEBUG(NULL);
    if( _sc_ossl_pkey_rsa_pss == NULL )
    {
        EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_rsa_pss );

        if( (_sc_ossl_pkey_rsa_pss = EVP_PKEY_meth_new(EVP_PKEY_RSA_PSS, 0)) != NULL )
        {
            // start with the default openssl method
            EVP_PKEY_meth_copy(_sc_ossl_pkey_rsa_pss, _openssl_pkey_rsa_pss);

            // overwrite the sign and verify methods specifically
            EVP_PKEY_meth_get_sign(_sc_ossl_pkey_rsa_pss, &psign_init, &psign);
            EVP_PKEY_meth_get_verify(_sc_ossl_pkey_rsa_pss, &pverify_init, &pverify);

            EVP_PKEY_meth_set_sign(_sc_ossl_pkey_rsa_pss, psign_init, sc_ossl_rsapss_sign);
            EVP_PKEY_meth_set_verify(_sc_ossl_pkey_rsa_pss, pverify_init, sc_ossl_rsapss_verify);
        }
    }
    return _sc_ossl_pkey_rsa_pss;
}

static const EVP_PKEY_METHOD *_openssl_pkey_tls1_prf = NULL;
static EVP_PKEY_METHOD *_sc_ossl_pkey_tls1_prf = NULL;
static EVP_PKEY_METHOD *sc_ossl_pkey_tls1_prf(void)
{
    int (*pctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2) = NULL;
    int (*pctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value) = NULL;

    SC_OSSL_LOG_DEBUG(NULL);
    if (_sc_ossl_pkey_tls1_prf == NULL)
    {
        if((_sc_ossl_pkey_tls1_prf = EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, 0)) != NULL)
        {
            // Use the default ctrl_str implementation, internally calls our ctrl method
            EVP_PKEY_meth_get_ctrl(_openssl_pkey_tls1_prf, &pctrl, &pctrl_str);

            EVP_PKEY_meth_set_init(_sc_ossl_pkey_tls1_prf, sc_ossl_tls1prf_init);
            EVP_PKEY_meth_set_cleanup(_sc_ossl_pkey_tls1_prf, sc_ossl_tls1prf_cleanup);
            EVP_PKEY_meth_set_derive(_sc_ossl_pkey_tls1_prf, sc_ossl_tls1prf_derive_init, sc_ossl_tls1prf_derive);
            EVP_PKEY_meth_set_ctrl(_sc_ossl_pkey_tls1_prf, sc_ossl_tls1prf_ctrl, pctrl_str);
        }
    }
    return _sc_ossl_pkey_tls1_prf;
}

static const EVP_PKEY_METHOD *_openssl_pkey_hkdf = NULL;
static EVP_PKEY_METHOD *_sc_ossl_pkey_hkdf = NULL;
static EVP_PKEY_METHOD *sc_ossl_pkey_hkdf(void)
{
    int (*pctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2) = NULL;
    int (*pctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value) = NULL;

    SC_OSSL_LOG_DEBUG(NULL);
    if (_sc_ossl_pkey_hkdf == NULL)
    {
        if((_sc_ossl_pkey_hkdf = EVP_PKEY_meth_new(EVP_PKEY_HKDF, 0)) != NULL)
        {
            // Use the default ctrl_str implementation, internally calls our ctrl method
            EVP_PKEY_meth_get_ctrl(_openssl_pkey_hkdf, &pctrl, &pctrl_str);

            EVP_PKEY_meth_set_init(_sc_ossl_pkey_hkdf, sc_ossl_hkdf_init);
            EVP_PKEY_meth_set_cleanup(_sc_ossl_pkey_hkdf, sc_ossl_hkdf_cleanup);
            EVP_PKEY_meth_set_derive(_sc_ossl_pkey_hkdf, sc_ossl_hkdf_derive_init, sc_ossl_hkdf_derive);
            EVP_PKEY_meth_set_ctrl(_sc_ossl_pkey_hkdf, sc_ossl_hkdf_ctrl, pctrl_str);
        }
    }
    return _sc_ossl_pkey_hkdf;
}


int sc_ossl_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                        const int **nids, int nid)
{
    SC_OSSL_LOG_DEBUG(NULL);
    int ok = 1;

    if( _openssl_pkey_rsa == NULL )
    {
        _openssl_pkey_rsa = EVP_PKEY_meth_find(EVP_PKEY_RSA);
        _openssl_pkey_rsa_pss = EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS);
        _openssl_pkey_tls1_prf = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF);
        _openssl_pkey_hkdf = EVP_PKEY_meth_find(EVP_PKEY_HKDF);
    }

    if( !pmeth )
    {
        /* We are returning a list of supported nids */
        *nids = sc_ossl_evp_nids;
        return evp_nids_count;
    }

    /* We are being asked for a specific pkey method */
    switch( nid )
    {
    case EVP_PKEY_RSA:
        *pmeth = sc_ossl_pkey_rsa();
        break;
    case EVP_PKEY_RSA_PSS:
        *pmeth = sc_ossl_pkey_rsa_pss();
        break;
    case EVP_PKEY_TLS1_PRF:
        *pmeth = sc_ossl_pkey_tls1_prf();
        break;
    case EVP_PKEY_HKDF:
        *pmeth = sc_ossl_pkey_hkdf();
        break;
    default:
        SC_OSSL_LOG_ERROR("NID %d not supported");
        ok = 0;
        *pmeth = NULL;
        break;
    }
    return ok;
}

void sc_ossl_destroy_pkey_methods(void)
{
    SC_OSSL_LOG_DEBUG(NULL);

    // It seems that explicitly freeing these methods in the destroy method causes a double free
    // (seen in SslPlay with sanitizers on, or in OpenSSL applications using the engine)
    // For now just don't free these methods here, but keep an eye out for memory leaks

    // EVP_PKEY_meth_free(_sc_ossl_pkey_hkdf);
    // EVP_PKEY_meth_free(_sc_ossl_pkey_tls1_prf);
    // EVP_PKEY_meth_free(_sc_ossl_pkey_rsa_pss);
    // EVP_PKEY_meth_free(_sc_ossl_pkey_rsa);
    _sc_ossl_pkey_hkdf = NULL;
    _sc_ossl_pkey_tls1_prf = NULL;
    _sc_ossl_pkey_rsa_pss = NULL;
    _sc_ossl_pkey_rsa = NULL;
    _openssl_pkey_hkdf = NULL;
    _openssl_pkey_tls1_prf = NULL;
    _openssl_pkey_rsa_pss = NULL;
    _openssl_pkey_rsa = NULL;
}

#ifdef __cplusplus
}
#endif