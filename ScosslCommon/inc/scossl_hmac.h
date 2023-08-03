//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_KEY_COPY) (PVOID pSrc, PVOID pDst);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_STATE_COPY) (PVOID pSrc, PVOID pExpandedKey, PVOID pDst);

typedef struct
{
    SYMCRYPT_MAC_EXPANDED_KEY expandedKey;
    SYMCRYPT_MAC_STATE macState;
    PCSYMCRYPT_MAC pMac;
    PSYMCRYPT_MAC_KEY_COPY keyCopyFunc;
    PSYMCRYPT_MAC_STATE_COPY stateCopyFunc;
    PBYTE pbKey;
    SIZE_T cbKey;
} SCOSSL_MAC_CTX;

// The MAC context contains SymCrypt structures that must be properly
// aligned. Because of this, these functions use the pointer to the aligned
// memory rather than the SCOSSL_MAC_CTX directly. Callers can use
// SCOSSL_ALIGN_UP if they need to access the SCOSSL_MAC_CTX.
typedef PVOID PSCOSSL_MAC_ALIGNED_CTX;

PSCOSSL_MAC_ALIGNED_CTX scossl_mac_newctx();
PSCOSSL_MAC_ALIGNED_CTX scossl_mac_dupctx(_In_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx);
void scossl_mac_freectx(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx);

SCOSSL_STATUS scossl_mac_set_md(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx, const _In_ EVP_MD *md);
SCOSSL_STATUS scossl_mac_set_mac_key(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                                      _In_reads_bytes_(cbMacKey) PCBYTE pbMacKey, SIZE_T cbMacKey);
SIZE_T scossl_mac_get_result_size(_In_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx);
SIZE_T scossl_mac_get_block_size(_In_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx);

SCOSSL_STATUS scossl_mac_init(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                               _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);
SCOSSL_STATUS scossl_mac_update(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                                 _In_reads_bytes_(cbData) PCBYTE pbData, SIZE_T cbData);
SCOSSL_STATUS scossl_mac_final(_Inout_ PSCOSSL_MAC_ALIGNED_CTX alignedCtx,
                                _Out_writes_bytes_opt_(*cbResult) PBYTE pbResult, _Out_ SIZE_T *cbResult, SIZE_T outsize);

#ifdef __cplusplus
}
#endif