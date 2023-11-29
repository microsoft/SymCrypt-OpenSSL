//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef PVOID PSCOSSL_MAC_EXPANDED_KEY;
typedef PVOID PSCOSSL_MAC_STATE;

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_KEY_COPY) (PSCOSSL_MAC_EXPANDED_KEY pSrc, PSCOSSL_MAC_EXPANDED_KEY pDst);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_MAC_STATE_COPY) (PSCOSSL_MAC_STATE pSrc, PSCOSSL_MAC_EXPANDED_KEY pExpandedKey, PSCOSSL_MAC_STATE pDst);

// Structure for holding additional constant MAC functions and
// properties needed by SCOSSL
typedef struct
{
    PSYMCRYPT_MAC_KEY_COPY keyCopyFunc;
    PSYMCRYPT_MAC_STATE_COPY stateCopyFunc;
    SIZE_T blockSize;
} SCOSSL_MAC_EX;

typedef struct
{
    PSCOSSL_MAC_EXPANDED_KEY expandedKey;
    PSCOSSL_MAC_STATE macState;
    PCSYMCRYPT_MAC pMac;
    const SCOSSL_MAC_EX *pMacEx;
    PBYTE pbKey;
    SIZE_T cbKey;
} SCOSSL_MAC_CTX;

// The MAC context contains SymCrypt structures that must be properly
// aligned. Because of this, these functions use the pointer to the aligned
// memory rather than the SCOSSL_MAC_CTX directly. Callers can use
// SCOSSL_ALIGN_UP if they need to access the SCOSSL_MAC_CTX directly.

SCOSSL_MAC_CTX *scossl_mac_newctx();
SCOSSL_MAC_CTX *scossl_mac_dupctx(_In_ SCOSSL_MAC_CTX *ctx);
void scossl_mac_freectx(_Inout_ SCOSSL_MAC_CTX *ctx);

SCOSSL_STATUS scossl_mac_set_md(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const EVP_MD *md);
SCOSSL_STATUS scossl_mac_set_cipher(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const EVP_CIPHER *cipher);
SCOSSL_STATUS scossl_mac_set_mac_key(_Inout_ SCOSSL_MAC_CTX *ctx,
                                     _In_reads_bytes_(cbMacKey) PCBYTE pbMacKey, SIZE_T cbMacKey);

SIZE_T scossl_mac_get_result_size(_In_ SCOSSL_MAC_CTX *ctx);
SIZE_T scossl_mac_get_block_size(_In_ SCOSSL_MAC_CTX *ctx);

SCOSSL_STATUS scossl_mac_init(_Inout_ SCOSSL_MAC_CTX *ctx,
                              _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);
SCOSSL_STATUS scossl_mac_update(_Inout_ SCOSSL_MAC_CTX *ctx,
                                _In_reads_bytes_(cbData) PCBYTE pbData, SIZE_T cbData);
SCOSSL_STATUS scossl_mac_final(_Inout_ SCOSSL_MAC_CTX *ctx,
                               _Out_writes_bytes_opt_(*cbResult) PBYTE pbResult, _Out_ SIZE_T *cbResult, SIZE_T outsize);

#ifdef __cplusplus
}
#endif