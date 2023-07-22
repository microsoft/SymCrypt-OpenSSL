//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS1_PRF_MAXBUF 1024

typedef struct {
    BOOL isTlsPrf1_1;
    /* Digest to use for PRF */
    PCSYMCRYPT_MAC pMac;

    /* Secret value to use for PRF */
    PBYTE  pbSecret;
    SIZE_T cbSecret;

    /* Buffer of concatenated seed data */
    BYTE   seed[TLS1_PRF_MAXBUF];
    SIZE_T cbSeed;
} SCOSSL_TLS1_PRF_CTX;

SCOSSL_TLS1_PRF_CTX *scossl_tls1prf_newctx();
SCOSSL_TLS1_PRF_CTX *scossl_tls1prf_dupctx(_In_ SCOSSL_TLS1_PRF_CTX *ctx);
void scossl_tls1prf_freectx(_Inout_ SCOSSL_TLS1_PRF_CTX *ctx);
SCOSSL_STATUS scossl_tls1prf_reset(_Inout_ SCOSSL_TLS1_PRF_CTX *ctx);

SCOSSL_STATUS scossl_tls1prf_append_seed(_Inout_ SCOSSL_TLS1_PRF_CTX *ctx,
                                         _In_reads_bytes_(cbSeed) PCBYTE pbSeed, SIZE_T cbSeed);

SCOSSL_STATUS scossl_tls1prf_derive(_In_ SCOSSL_TLS1_PRF_CTX *ctx,
                                    _Out_writes_bytes_(keylen) PBYTE key, SIZE_T keylen);

#ifdef __cplusplus
}
#endif