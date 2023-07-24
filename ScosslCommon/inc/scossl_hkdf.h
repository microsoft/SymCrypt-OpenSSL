//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_MAXBUF 1024

typedef struct
{
    int mode;
    EVP_MD *md;
    PBYTE pbSalt;
    SIZE_T cbSalt;
    PBYTE pbKey;
    SIZE_T cbKey;
    BYTE info[HKDF_MAXBUF];
    SIZE_T cbInfo;
} SCOSSL_HKDF_CTX;

SCOSSL_HKDF_CTX *scossl_hkdf_newctx();
SCOSSL_HKDF_CTX *scossl_hkdf_dupctx(_In_ SCOSSL_HKDF_CTX *ctx);
void scossl_hkdf_freectx(_Inout_ SCOSSL_HKDF_CTX *ctx);

SCOSSL_STATUS scossl_hkdf_reset(_Inout_ SCOSSL_HKDF_CTX *ctx);

SCOSSL_STATUS scossl_hkdf_append_info(_Inout_ SCOSSL_HKDF_CTX *ctx,
                                      _In_reads_bytes_(cbInfo) PCBYTE pbInfo, SIZE_T cbInfo);

SCOSSL_STATUS scossl_hkdf_derive(_In_ SCOSSL_HKDF_CTX *ctx,
                                 _Out_writes_bytes_(keylen) PBYTE key, SIZE_T keylen);

#ifdef __cplusplus
}
#endif