//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SYMCRYPT_MAC_EXPANDED_KEY   expandedKey;
    SYMCRYPT_MAC_STATE          macState;
    PCSYMCRYPT_MAC              pMac;
    ASN1_OCTET_STRING           pbKey;
} SCOSSL_HMAC_CTX;

SCOSSL_HMAC_CTX *scossl_hmac_newctx();
SCOSSL_HMAC_CTX *scossl_hmac_dupctx(_In_ SCOSSL_HMAC_CTX *ctx);
void scossl_hmac_freectx(_Inout_ SCOSSL_HMAC_CTX *ctx);

SCOSSL_STATUS scossl_hmac_set_mac_key(_Inout_ SCOSSL_HMAC_CTX *ctx,
                                      _In_reads_bytes_(cbMacKey) PBYTE pbMacKey, SIZE_T cbMacKey);
SCOSSL_STATUS scossl_hmac_init(_Inout_ SCOSSL_HMAC_CTX *ctx,
                               _In_reads_bytes_(cbKey) PBYTE pbKey, SIZE_T cbKey);
SCOSSL_STATUS scossl_hmac_update(_Inout_ SCOSSL_HMAC_CTX *ctx,
                                 _In_reads_bytes_(cbData) PCBYTE pbData, SIZE_T cbData);
SCOSSL_STATUS scossl_hmac_final(_Inout_ SCOSSL_HMAC_CTX *ctx,
                                _Out_writes_bytes_(*cbResult) PBYTE pbResult, _Out_ SIZE_T *cbResult);

#ifdef __cplusplus
}
#endif