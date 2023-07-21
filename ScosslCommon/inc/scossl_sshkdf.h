//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SSH_KDF_MAX_DIGEST_SIZE (512 / 8)

typedef struct {
    PCSYMCRYPT_HASH pHash;
    PBYTE  pbKey;
    SIZE_T cbKey;
    BYTE   pbHashValue[SSH_KDF_MAX_DIGEST_SIZE];
    SIZE_T cbHashValue;
    BYTE   pbSessionId[SSH_KDF_MAX_DIGEST_SIZE];
    SIZE_T cbSessionId;
    BYTE   label;
} SCOSSL_SSHKDF_CTX;

SCOSSL_SSHKDF_CTX *scossl_sshkdf_newctx();
SCOSSL_SSHKDF_CTX *scossl_sshkdf_dupctx(_In_ SCOSSL_SSHKDF_CTX *ctx);
void scossl_sshkdf_freectx(_Inout_ SCOSSL_SSHKDF_CTX *ctx);
SCOSSL_STATUS scossl_sshkdf_reset(_Inout_ SCOSSL_SSHKDF_CTX *ctx);

SCOSSL_STATUS scossl_sshkdf_derive(_In_ SCOSSL_SSHKDF_CTX *ctx,
                                   _Out_writes_opt_(*keylen) PBYTE key, SIZE_T keylen);

#ifdef __cplusplus
}
#endif