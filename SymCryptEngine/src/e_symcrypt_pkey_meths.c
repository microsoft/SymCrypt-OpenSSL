//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt_pkey_meths.h"
#include "e_symcrypt_helpers.h"
#include "e_symcrypt_hkdf.h"
#include "e_symcrypt_tls1prf.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

static int symcrypt_evp_nids[] = {
    EVP_PKEY_TLS1_PRF,
    EVP_PKEY_HKDF,
    // EVP_PKEY_X25519 - Future
};
const int evp_nids_count = sizeof(symcrypt_evp_nids) / sizeof(symcrypt_evp_nids[0]);

static EVP_PKEY_METHOD *_symcrypt_pkey_tls1_prf = NULL;
static EVP_PKEY_METHOD *symcrypt_pkey_tls1_prf(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_symcrypt_pkey_tls1_prf == NULL)
    {
        if((_symcrypt_pkey_tls1_prf = EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, 0)) != NULL)
        {
            EVP_PKEY_meth_set_init(_symcrypt_pkey_tls1_prf, symcrypt_tls1prf_init);
            EVP_PKEY_meth_set_cleanup(_symcrypt_pkey_tls1_prf, symcrypt_tls1prf_cleanup);
            EVP_PKEY_meth_set_derive(_symcrypt_pkey_tls1_prf, symcrypt_tls1prf_derive_init, symcrypt_tls1prf_derive);
            EVP_PKEY_meth_set_ctrl(_symcrypt_pkey_tls1_prf, symcrypt_tls1prf_ctrl, NULL);
        }
    }
    return _symcrypt_pkey_tls1_prf;
}

static EVP_PKEY_METHOD *_symcrypt_pkey_hkdf = NULL;
static EVP_PKEY_METHOD *symcrypt_pkey_hkdf(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_symcrypt_pkey_hkdf == NULL)
    {
        if((_symcrypt_pkey_hkdf = EVP_PKEY_meth_new(EVP_PKEY_HKDF, 0)) != NULL)
        {
            EVP_PKEY_meth_set_init(_symcrypt_pkey_hkdf, symcrypt_hkdf_init);
            EVP_PKEY_meth_set_cleanup(_symcrypt_pkey_hkdf, symcrypt_hkdf_cleanup);
            EVP_PKEY_meth_set_derive(_symcrypt_pkey_hkdf, symcrypt_hkdf_derive_init, symcrypt_hkdf_derive);
            EVP_PKEY_meth_set_ctrl(_symcrypt_pkey_hkdf, symcrypt_hkdf_ctrl, NULL);
        }
    }
    return _symcrypt_pkey_hkdf;
}


int symcrypt_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                        const int **nids, int nid)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ok = 1;
    if (!pmeth) {
        /* We are returning a list of supported nids */
        *nids = symcrypt_evp_nids;
        return evp_nids_count;
    }

    /* We are being asked for a specific cipher */
    switch (nid) {
    case EVP_PKEY_TLS1_PRF:
        *pmeth = symcrypt_pkey_tls1_prf();
        break;
    case EVP_PKEY_HKDF:
        *pmeth = symcrypt_pkey_hkdf();
        break;
    default:
        SYMCRYPT_LOG_ERROR("NID %d not supported");
        ok = 0;
        *pmeth = NULL;
        break;
    }
    return ok;
}

void symcrypt_destroy_pkey_methods(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);

    // It seems that explicitly freeing these methods in the destroy method causes a double free
    // (seen in SslPlay with sanitizers on, or in OpenSSL applications using the engine)
    // For now just don't free these methods here, but keep an eye out for memory leaks

    // EVP_PKEY_meth_free(_symcrypt_pkey_hkdf);
    // EVP_PKEY_meth_free(_symcrypt_pkey_tls1_prf);
    _symcrypt_pkey_hkdf = NULL;
    _symcrypt_pkey_tls1_prf = NULL;
}

#ifdef __cplusplus
}
#endif
