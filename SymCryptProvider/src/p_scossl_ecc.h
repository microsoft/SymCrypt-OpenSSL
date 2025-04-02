//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
#include "p_scossl_base.h"
#ifdef KEYSINUSE_ENABLED
#include "p_scossl_keysinuse.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    OSSL_LIB_CTX *libctx;
    BOOL initialized;
    PSYMCRYPT_ECKEY key;
    PCSYMCRYPT_ECURVE curve;
    BOOL isX25519;
    // RFC7748 dictates that to decode the x25519 private key, we need to
    // 1. Set the three least significant bits of the MSB to 0
    // 2. Set the most significant bit of the LSB to 0
    // 3. Set the second most significant bit of the LSB to 1
    // SymCrypt expects the operation to be applied to the private
    // key before import. In order to preserve the original key data
    // for export, the transformed bits are stored here. The position
    // of the modified bits in the MSB and LSB differ, so we can use
    // a single byte.
    BYTE modifiedPrivateBits;
    // Not used for crypto operations. Only used in import/export
    // to let the provider handling encoding/decoding whether to
    // include the public key.
    int includePublic;
    point_conversion_form_t conversionFormat;

#ifdef KEYSINUSE_ENABLED
    // TODO: New APIs, remove lock
    BOOL isImported;
    CRYPTO_RWLOCK *keysinuseLock;
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo;
#endif
} SCOSSL_ECC_KEY_CTX;

SCOSSL_ECC_KEY_CTX *p_scossl_ecc_new_ctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_ecc_free_ctx(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx);
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_dup_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection);

SCOSSL_STATUS p_scossl_ecc_set_group(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const char *groupName);

SCOSSL_STATUS p_scossl_ecc_gen(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx);

SIZE_T p_scossl_ecc_get_max_result_size(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, BOOL isEcdh);
SIZE_T p_scossl_ecc_get_encoded_key_size(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection);
SCOSSL_STATUS p_scossl_ecc_get_encoded_key(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                           _Out_writes_bytes_(*pcbKey) PBYTE *ppbKey, _Out_ SIZE_T *pcbKey);
SCOSSL_STATUS p_scossl_ecc_set_encoded_key(_In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                           _In_reads_bytes_opt_(cbEncodedPublicKey) PCBYTE pbEncodedPublicKey, SIZE_T cbEncodedPublicKey,
                                           _In_reads_bytes_opt_(cbEncodedPrivateKey) PCBYTE pbEncodedPrivateKey, SIZE_T cbEncodedPrivateKey);

#ifdef KEYSINUSE_ENABLED
void p_scossl_ecc_init_keysinuse(_In_ SCOSSL_ECC_KEY_CTX *keyCtx);
void p_scossl_ecc_reset_keysinuse(_In_ SCOSSL_ECC_KEY_CTX *keyCtx);
#endif

#ifdef __cplusplus
}
#endif