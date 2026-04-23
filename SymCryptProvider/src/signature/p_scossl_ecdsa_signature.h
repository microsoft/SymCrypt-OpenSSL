//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_ECC_KEY_CTX *keyCtx;
    int operation;

    // Needed for fetching md
    OSSL_LIB_CTX *libctx;
    char* propq;

    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    SIZE_T mdSize;
    BOOL allowMdUpdates;

    // Sigalg state tracking
    BOOL isSigalg;
    BOOL allowUpdate;
    BOOL allowFinal;
    BOOL allowOneshot;

    // Sigalg verify message support
    PBYTE pbSignature;
    SIZE_T cbSignature;
} SCOSSL_ECDSA_CTX;

SCOSSL_ECDSA_CTX *p_scossl_ecdsa_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const char *propq);
void p_scossl_ecdsa_freectx(_Inout_ SCOSSL_ECDSA_CTX *ctx);
SCOSSL_ECDSA_CTX *p_scossl_ecdsa_dupctx(_In_ SCOSSL_ECDSA_CTX *ctx);

SCOSSL_STATUS p_scossl_ecdsa_signverify_init(_Inout_ SCOSSL_ECDSA_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                             _In_ const OSSL_PARAM params[], int operation);

SCOSSL_STATUS p_scossl_ecdsa_sign_internal(_In_ SCOSSL_ECDSA_CTX *ctx,
                                           _Out_writes_bytes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                           _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);
int p_scossl_ecdsa_verify_internal(_In_ SCOSSL_ECDSA_CTX *ctx,
                                   _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                   _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

const OSSL_PARAM *p_scossl_ecdsa_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
SCOSSL_STATUS p_scossl_ecdsa_get_ctx_params(_In_ SCOSSL_ECDSA_CTX *ctx, _Inout_ OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif
