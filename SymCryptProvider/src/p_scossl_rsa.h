//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"
#include "p_scossl_keysinuse.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const OSSL_ITEM *mdInfo;
    const OSSL_ITEM *mgf1MdInfo;
    int cbSaltMin;
} SCOSSL_RSA_PSS_RESTRICTIONS;

typedef struct
{
    OSSL_LIB_CTX *libctx;
    BOOL initialized;
    PSYMCRYPT_RSAKEY key;
    UINT padding;
    SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions;

    BOOL isImported;
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo;
} SCOSSL_PROV_RSA_KEY_CTX;

const OSSL_ITEM *p_scossl_rsa_get_supported_md(_In_ OSSL_LIB_CTX *libctx,
                                               _In_ const char *mdname, _In_ const char *propq,
                                               _Out_opt_ EVP_MD **md);

SCOSSL_STATUS p_scossl_rsa_pss_restrictions_from_params(_In_ OSSL_LIB_CTX *libctx, _In_ const OSSL_PARAM params[],
                                                        _Out_ SCOSSL_RSA_PSS_RESTRICTIONS **pPssRestrictions);

SCOSSL_STATUS p_scossl_rsa_pss_restrictions_to_params(_In_ const SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions,
                                                      _Inout_ OSSL_PARAM_BLD *bld);

// Keysinuse requires the public key encoded in the same format as subjectPublicKey in a certificate.
// This was done with i2d_RSAPublicKey for OpenSSL 1.1.1, but now must be done by the provider.
SCOSSL_STATUS p_scossl_rsa_get_encoded_public_key(_In_ PCSYMCRYPT_RSAKEY key,
                                                  _Inout_ PBYTE *ppbEncodedKey, _Inout_ SIZE_T *pcbEncodedKey);

#ifdef __cplusplus
}
#endif