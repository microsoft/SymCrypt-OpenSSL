//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"
#ifdef KEYSINUSE_ENABLED
#include "p_scossl_keysinuse.h"
#endif

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
    UINT keyType;
    SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions;

#ifdef KEYSINUSE_ENABLED
    // TODO: New APIs, remove lock
    BOOL isImported;
    CRYPTO_RWLOCK *keysinuseLock;
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo;
#endif
} SCOSSL_PROV_RSA_KEY_CTX;

const OSSL_ITEM *p_scossl_rsa_get_supported_md(_In_ OSSL_LIB_CTX *libctx, UINT padding,
                                               _In_ const char *mdname, _In_ const char *propq,
                                               _Out_opt_ EVP_MD **md);

SCOSSL_STATUS p_scossl_rsa_pss_restrictions_from_params(_In_ OSSL_LIB_CTX *libctx, _In_ const OSSL_PARAM params[],
                                                        _Out_ SCOSSL_RSA_PSS_RESTRICTIONS **pPssRestrictions);

SCOSSL_STATUS p_scossl_rsa_pss_restrictions_to_params(_In_ const SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions,
                                                      _Inout_ OSSL_PARAM_BLD *bld);

void p_scossl_rsa_pss_restrictions_get_defaults(_Inout_ SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions);  

#ifdef KEYSINUSE_ENABLED
// TODO: New APIs
SCOSSL_STATUS p_scossl_rsa_get_encoded_public_key(_In_ PCSYMCRYPT_RSAKEY key,
                                                  _Inout_ PBYTE *ppbEncodedKey, _Inout_ SIZE_T *pcbEncodedKey);
void p_scossl_rsa_init_keysinuse(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx);
void p_scossl_rsa_reset_keysinuse(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx);
#endif

#ifdef __cplusplus
}
#endif