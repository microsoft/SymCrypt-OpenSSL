//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "scossl_hkdf.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Needed for fetching md
    OSSL_LIB_CTX *libctx;

    SCOSSL_HKDF_CTX *hkdfCtx;
} SCOSSL_PROV_HKDF_CTX;

SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_newctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_hkdf_freectx(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx);
SCOSSL_PROV_HKDF_CTX *p_scossl_hkdf_dupctx(_In_ SCOSSL_PROV_HKDF_CTX *ctx);

SCOSSL_STATUS p_scossl_hkdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
                                   _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                   _In_ const OSSL_PARAM params[]);

const OSSL_PARAM *p_scossl_hkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
const OSSL_PARAM *p_scossl_hkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
SCOSSL_STATUS p_scossl_hkdf_get_ctx_params(_In_ SCOSSL_PROV_HKDF_CTX *ctx, _Inout_ OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_hkdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

//TLS1.3 KDF functions
SCOSSL_STATUS p_scossl_tls13kdf_derive(_In_ SCOSSL_PROV_HKDF_CTX *ctx,
    _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
    _In_ const OSSL_PARAM params[]);

const OSSL_PARAM *p_scossl_tls13kdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
const OSSL_PARAM *p_scossl_tls13kdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
SCOSSL_STATUS p_scossl_tls13kdf_get_ctx_params(_In_ SCOSSL_PROV_HKDF_CTX *ctx, _Inout_ OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_tls13kdf_set_ctx_params(_Inout_ SCOSSL_PROV_HKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif