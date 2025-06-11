//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_MAXBUF 1024

// These macros were renamed in OpenSSL 3. Common implementation
// uses the new names. This mapping from new to old names is
// needed until OpenSSL 1.1.1 builds are no longer needed.
#ifndef EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
#define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
#endif

#ifndef EVP_KDF_HKDF_MODE_EXTRACT_ONLY
#define EVP_KDF_HKDF_MODE_EXTRACT_ONLY EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
#endif

#ifndef EVP_KDF_HKDF_MODE_EXPAND_ONLY
#define EVP_KDF_HKDF_MODE_EXPAND_ONLY EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
#endif

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
    // Below fields (label, prefix, data) are only used in TLS1.3KDF
    PBYTE pbLabel;
    SIZE_T cbLabel;
    PBYTE pbPrefix;
    SIZE_T cbPrefix;
    PBYTE pbData;
    SIZE_T cbData;
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