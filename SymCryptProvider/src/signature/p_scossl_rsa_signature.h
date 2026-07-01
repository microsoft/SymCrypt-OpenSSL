//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>

#include "scossl_rsa.h"
#include "p_scossl_rsa.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_PROV_RSA_KEY_CTX *keyCtx;
    UINT8 padding;
    int operation;

    // Needed for fetching md
    OSSL_LIB_CTX *libctx;
    char* propq;

    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    const OSSL_ITEM *mdInfo; // Informational, must match md if set
    BOOL allowMdUpdates;

    // PSS params
    BOOL pssRestricted;
    const OSSL_ITEM *mgf1MdInfo; // Informational, must match md if set
    int cbSalt;
    int cbSaltMin;

    // Sigalg state tracking
    BOOL isSigalg;
    BOOL allowUpdate;
    BOOL allowFinal;
    BOOL allowOneshot;

    // Sigalg verify message support
    PBYTE pbSignature;
    SIZE_T cbSignature;
} SCOSSL_RSA_SIGN_CTX;

SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const char *propq);
void p_scossl_rsa_freectx(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx);
SCOSSL_RSA_SIGN_CTX *p_scossl_rsa_dupctx(_In_ SCOSSL_RSA_SIGN_CTX *ctx);

SCOSSL_STATUS p_scossl_rsa_signverify_init(_Inout_ SCOSSL_RSA_SIGN_CTX *ctx, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx,
                                           _In_ const OSSL_PARAM params[], int operation);

SCOSSL_STATUS p_scossl_rsa_sign_internal(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                         _Out_writes_bytes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                         _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);
SCOSSL_STATUS p_scossl_rsa_verify_internal(_In_ SCOSSL_RSA_SIGN_CTX *ctx,
                                           _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                           _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

const OSSL_PARAM *p_scossl_rsa_gettable_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, ossl_unused void *provctx);
SCOSSL_STATUS p_scossl_rsa_get_ctx_params(_In_ SCOSSL_RSA_SIGN_CTX *ctx, _Inout_ OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif
