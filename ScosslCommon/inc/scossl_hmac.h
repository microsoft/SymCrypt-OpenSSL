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
    ASN1_OCTET_STRING           key;
} SCOSSL_HMAC_CTX;

// The HMAC context contains SymCrypt structures that must be properly
// aligned. Because of this, these functions use the pointer to the aligned
// memory rather than the SCOSSL_HMAC_CTX directly. Callers can use
// SCOSSL_ALIGN_UP if they need to access the SCOSSL_HMAC_CTX.
PBYTE scossl_hmac_newctx();
PBYTE scossl_hmac_dupctx(_In_ PBYTE alignedCtx);
void scossl_hmac_freectx(_Inout_ PBYTE alignedCtx);

SCOSSL_STATUS scossl_hmac_set_md(_Inout_ PBYTE alignedCtx, _In_ const EVP_MD *md);
SCOSSL_STATUS scossl_hmac_set_mac_key(_Inout_ PBYTE alignedCtx,
                                      _In_reads_bytes_(cbMacKey) const char *macKey, SIZE_T cbMacKey);
SCOSSL_STATUS scossl_hmac_init(_Inout_ PBYTE alignedCtx,
                               _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);
SCOSSL_STATUS scossl_hmac_update(_Inout_ PBYTE alignedCtx,
                                 _In_reads_bytes_(cbData) PCBYTE pbData, SIZE_T cbData);
SCOSSL_STATUS scossl_hmac_final(_Inout_ PBYTE alignedCtx,
                                _Out_writes_bytes_(*cbResult) PBYTE pbResult, _Out_ SIZE_T *cbResult);

#ifdef __cplusplus
}
#endif