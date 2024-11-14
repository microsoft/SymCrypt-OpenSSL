//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "scossl_tls1prf.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Needed for fetching md
    OSSL_LIB_CTX *libctx;

    // Purely informational
    char *mdName;

    SCOSSL_TLS1_PRF_CTX *tls1prfCtx;
} SCOSSL_PROV_TLS1_PRF_CTX;

SCOSSL_PROV_TLS1_PRF_CTX *p_scossl_tls1prf_newctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_tls1prf_freectx(_Inout_ SCOSSL_PROV_TLS1_PRF_CTX *ctx);
SCOSSL_PROV_TLS1_PRF_CTX *p_scossl_tls1prf_dupctx(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx);

SCOSSL_STATUS p_scossl_tls1prf_derive(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx,
                                      _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                      _In_ const OSSL_PARAM params[]);

const OSSL_PARAM *p_scossl_tls1prf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
const OSSL_PARAM *p_scossl_tls1prf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx);
SCOSSL_STATUS p_scossl_tls1prf_get_ctx_params(_In_ SCOSSL_PROV_TLS1_PRF_CTX *ctx, _Inout_ OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_tls1prf_set_ctx_params(_Inout_ SCOSSL_PROV_TLS1_PRF_CTX *ctx, const _In_ OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif