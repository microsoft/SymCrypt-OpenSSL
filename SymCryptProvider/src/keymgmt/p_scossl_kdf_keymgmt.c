//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Before OpenSSL 3, HKDF and TLS1-PRF were available through the EVP_PKEY API.
// In OpenSSL 3, these are available through the EVP_KDF API, which uses the
// provider kdf interface. Some callers may still be using the EVP_PKEY API
// for HKDF and TLS1-PRF. The implementations in keyexch/p_scossl_kdf_keyexch
// provide HKDF and TLS1-PRF for the EVP_PKEY API. This keymgmt interface is
// mostly empty but necessary to expose both KDFs through the EVP_PKEY API.

#include "scossl_helpers.h"

#include <openssl/core_dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef BYTE SCOSSL_KDF_KEYMGMT_CTX;

SCOSSL_KDF_KEYMGMT_CTX *p_scossl_kdf_keymgmt_new_ctx(ossl_unused void *provctx)
{
    return OPENSSL_malloc(sizeof(SCOSSL_KDF_KEYMGMT_CTX));
}

void p_scossl_kdf_keymgmt_free_ctx(SCOSSL_KDF_KEYMGMT_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    OPENSSL_free(keyCtx);
}

static BOOL p_scossl_kdf_keymgmt_has(ossl_unused const void *keydata, ossl_unused int selection)
{
    return TRUE;
}

const OSSL_DISPATCH p_scossl_kdf_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_kdf_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_kdf_keymgmt_free_ctx},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_kdf_keymgmt_has},
    {0, NULL}};

#ifdef __cplusplus
}
#endif