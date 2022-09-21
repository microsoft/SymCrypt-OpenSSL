//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_pkey_meths.h"
#include "scossl_hkdf.h"
#include "scossl_tls1prf.h"
#include "scossl_rsapss.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif


static int scossl_evp_nids[] = {
    EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS,
    EVP_PKEY_TLS1_PRF,
    EVP_PKEY_HKDF,
    // EVP_PKEY_X25519 - Future
};
static const int scossl_evp_nids_count = sizeof(scossl_evp_nids) / sizeof(scossl_evp_nids[0]);



static const EVP_PKEY_METHOD *_openssl_pkey_rsa = NULL;
static int (*_openssl_pkey_rsa_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                        const unsigned char *tbs, size_t tbslen) = NULL;
static int (*_openssl_pkey_rsa_verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                                        const unsigned char *tbs, size_t tbslen) = NULL;

// Call SymCrypt engine sign if PSS padding, otherwise OpenSSL version.
static int scossl_pkey_rsa_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_bytes_(*siglen) unsigned char *sig,
                                    _Out_ size_t *siglen, _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    int padding;

    if( EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_PKEY_RSA_SIGN, ERR_R_OPERATION_FAIL,
            "Failed to get padding");
        return SCOSSL_UNSUPPORTED;
    }

    if( padding == RSA_PKCS1_PSS_PADDING )
    {
        return scossl_rsapss_sign(ctx, sig, siglen, tbs, tbslen);
    }

    return _openssl_pkey_rsa_sign(ctx, sig, siglen, tbs, tbslen);
}

// Call SymCrypt engine RSA-PSS verify, unless auto salt-length specified (not yet supported by SymCrypt)
static int scossl_pkey_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    int cbSalt = RSA_PSS_SALTLEN_DIGEST;

    if( EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &cbSalt) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_PKEY_RSA_VERIFY, ERR_R_OPERATION_FAIL,
            "Failed to get cbSalt");
        return SCOSSL_UNSUPPORTED;
    }
    if( cbSalt != RSA_PSS_SALTLEN_AUTO )
    {
        return scossl_rsapss_verify(ctx, sig, siglen, tbs, tbslen);
    }
    SCOSSL_LOG_INFO(SCOSSL_ERR_F_PKEY_RSA_VERIFY, SCOSSL_ERR_R_OPENSSL_FALLBACK,
        "SymCrypt Engine does not support RSA_PSS_SALTLEN_AUTO saltlen - falling back to OpenSSL");

    return _openssl_pkey_rsa_verify(ctx, sig, siglen, tbs, tbslen);
}

// Call SymCrypt engine verify if PSS padding, otherwise OpenSSL version.
static int scossl_pkey_rsa_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen)
{
    int padding;

    if( EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_PKEY_RSA_VERIFY, ERR_R_OPERATION_FAIL,
            "Failed to get padding");
        return SCOSSL_UNSUPPORTED;
    }

    if( padding == RSA_PKCS1_PSS_PADDING )
    {
        return scossl_pkey_rsapss_verify(ctx, sig, siglen, tbs, tbslen);
    }

    return _openssl_pkey_rsa_verify(ctx, sig, siglen, tbs, tbslen);
}

static EVP_PKEY_METHOD *_scossl_pkey_rsa = NULL;

// Creates and returns the internal RSA method structure holding methods for RSA functions
static EVP_PKEY_METHOD *scossl_pkey_rsa(void)
{
    int (*psign_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*pverify_init) (EVP_PKEY_CTX *ctx) = NULL;
    int flags = 0;

    EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_rsa );

    if( (_scossl_pkey_rsa = EVP_PKEY_meth_new(EVP_PKEY_RSA, flags)) != NULL )
    {
        // start with the default openssl method
        EVP_PKEY_meth_copy(_scossl_pkey_rsa, _openssl_pkey_rsa);

        // overwrite the sign and verify methods
        // we just want to use the pss method if pss padding is specified
        EVP_PKEY_meth_get_sign(_scossl_pkey_rsa, &psign_init, &_openssl_pkey_rsa_sign);
        EVP_PKEY_meth_get_verify(_scossl_pkey_rsa, &pverify_init, &_openssl_pkey_rsa_verify);

        EVP_PKEY_meth_set_sign(_scossl_pkey_rsa, psign_init, scossl_pkey_rsa_sign);
        EVP_PKEY_meth_set_verify(_scossl_pkey_rsa, pverify_init, scossl_pkey_rsa_verify);
    }
    return _scossl_pkey_rsa;
}

static const EVP_PKEY_METHOD *_openssl_pkey_rsa_pss = NULL;
static EVP_PKEY_METHOD *_scossl_pkey_rsa_pss = NULL;

// Creates and returns the internal RSA PSS method structure holding methods for RSA PSS functions
static EVP_PKEY_METHOD *scossl_pkey_rsa_pss(void)
{
    int (*psign_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*psign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) = NULL;
    int (*pverify_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*pverify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) = NULL;
    int flags = 0;

    EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_rsa_pss );

    if( (_scossl_pkey_rsa_pss = EVP_PKEY_meth_new(EVP_PKEY_RSA_PSS, flags)) != NULL )
    {
        // start with the default openssl method
        EVP_PKEY_meth_copy(_scossl_pkey_rsa_pss, _openssl_pkey_rsa_pss);

        // overwrite the sign and verify methods specifically
        EVP_PKEY_meth_get_sign(_scossl_pkey_rsa_pss, &psign_init, &psign);
        EVP_PKEY_meth_get_verify(_scossl_pkey_rsa_pss, &pverify_init, &pverify);

        EVP_PKEY_meth_set_sign(_scossl_pkey_rsa_pss, psign_init, scossl_rsapss_sign);
        EVP_PKEY_meth_set_verify(_scossl_pkey_rsa_pss, pverify_init, scossl_pkey_rsapss_verify);
    }
    return _scossl_pkey_rsa_pss;
}

static const EVP_PKEY_METHOD *_openssl_pkey_tls1_prf = NULL;
static EVP_PKEY_METHOD *_scossl_pkey_tls1_prf = NULL;

// Creates and returns the internal TLS1 PRF method structure holding methods for TLS1 PRF functions
static EVP_PKEY_METHOD *scossl_pkey_tls1_prf(void)
{
    int (*pctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2) = NULL;
    int (*pctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value) = NULL;
    int flags = 0;

    EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_tls1_prf );

    if((_scossl_pkey_tls1_prf = EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, flags)) != NULL)
    {
        // Use the default ctrl_str implementation, internally calls our ctrl method
        EVP_PKEY_meth_get_ctrl(_openssl_pkey_tls1_prf, &pctrl, &pctrl_str);

        EVP_PKEY_meth_set_init(_scossl_pkey_tls1_prf, scossl_tls1prf_init);
        EVP_PKEY_meth_set_cleanup(_scossl_pkey_tls1_prf, scossl_tls1prf_cleanup);
        EVP_PKEY_meth_set_derive(_scossl_pkey_tls1_prf, scossl_tls1prf_derive_init, scossl_tls1prf_derive);
        EVP_PKEY_meth_set_ctrl(_scossl_pkey_tls1_prf, scossl_tls1prf_ctrl, pctrl_str);
    }
    return _scossl_pkey_tls1_prf;
}

static const EVP_PKEY_METHOD *_openssl_pkey_hkdf = NULL;
static EVP_PKEY_METHOD *_scossl_pkey_hkdf = NULL;

// Creates and returns the internal HKDF method structure holding methods for HKDF functions
static EVP_PKEY_METHOD *scossl_pkey_hkdf(void)
{
    int (*pctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2) = NULL;
    int (*pctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value) = NULL;
    int flags = 0;

    EVP_PKEY_meth_get0_info( NULL, &flags, _openssl_pkey_hkdf );

    if((_scossl_pkey_hkdf = EVP_PKEY_meth_new(EVP_PKEY_HKDF, flags)) != NULL)
    {
        // Use the default ctrl_str implementation, internally calls our ctrl method
        EVP_PKEY_meth_get_ctrl(_openssl_pkey_hkdf, &pctrl, &pctrl_str);

        EVP_PKEY_meth_set_init(_scossl_pkey_hkdf, scossl_hkdf_init);
        EVP_PKEY_meth_set_cleanup(_scossl_pkey_hkdf, scossl_hkdf_cleanup);
        EVP_PKEY_meth_set_derive(_scossl_pkey_hkdf, scossl_hkdf_derive_init, scossl_hkdf_derive);
        EVP_PKEY_meth_set_ctrl(_scossl_pkey_hkdf, scossl_hkdf_ctrl, pctrl_str);
    }
    return _scossl_pkey_hkdf;
}


SCOSSL_STATUS scossl_pkey_methods_init_static()
{
    if( (scossl_pkey_rsa() == NULL) ||
        (scossl_pkey_rsa_pss() == NULL) ||
        (scossl_pkey_tls1_prf() == NULL) ||
        (scossl_pkey_hkdf() == NULL)
        )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

_Success_(return > 0)
int scossl_pkey_methods(_Inout_ ENGINE *e, _Out_opt_ EVP_PKEY_METHOD **pmeth,
                               _Out_opt_ const int **nids, int nid)
{
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
        *nids = scossl_evp_nids;
        return scossl_evp_nids_count;
    }

    /* We are being asked for a specific pkey method */
    switch( nid )
    {
    case EVP_PKEY_RSA:
        *pmeth = _scossl_pkey_rsa;
        break;
    case EVP_PKEY_RSA_PSS:
        *pmeth = _scossl_pkey_rsa_pss;
        break;
    case EVP_PKEY_TLS1_PRF:
        *pmeth = _scossl_pkey_tls1_prf;
        break;
    case EVP_PKEY_HKDF:
        *pmeth = _scossl_pkey_hkdf;
        break;

    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_PKEY_METHODS, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "NID %d not supported");
        ok = 0;
        *pmeth = NULL;
        break;
    }
    return ok;
}

void scossl_destroy_pkey_methods(void)
{
    // It seems that explicitly freeing these methods in the destroy method causes a double free as
    // OpenSSL automatically frees pkey methods associated with an engine in destroying the engine
    // (seen in SslPlay with sanitizers on, or in OpenSSL applications using the engine)
    // For now just don't free these methods here, but keep an eye out for memory leaks

    // EVP_PKEY_meth_free(_scossl_pkey_hkdf);
    // EVP_PKEY_meth_free(_scossl_pkey_tls1_prf);
    // EVP_PKEY_meth_free(_scossl_pkey_rsa_pss);
    // EVP_PKEY_meth_free(_scossl_pkey_rsa);
    _scossl_pkey_hkdf = NULL;
    _scossl_pkey_tls1_prf = NULL;
    _scossl_pkey_rsa_pss = NULL;
    _scossl_pkey_rsa = NULL;
    _openssl_pkey_hkdf = NULL;
    _openssl_pkey_tls1_prf = NULL;
    _openssl_pkey_rsa_pss = NULL;
    _openssl_pkey_rsa = NULL;
}

#ifdef __cplusplus
}
#endif