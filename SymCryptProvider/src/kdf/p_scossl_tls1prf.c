//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {

} SCOSSL_TLS1PRF_CTX;

static const OSSL_PARAM p_scossl_tls1prf_gettable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_tls1prf_gettable_ctx_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_tls1prf_settable_ctx_param_types[] = {
    OSSL_PARAM_END};

SCOSSL_TLS1PRF_CTX *p_scossl_tls1prf_newctx(ossl_unused void *provctx)
{
    SCOSSL_TLS1PRF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_TLS1PRF_CTX));

    return ctx;
}

void p_scossl_tls1prf_freectx(_Inout_ SCOSSL_TLS1PRF_CTX *ctx)
{

}

SCOSSL_TLS1PRF_CTX *p_scossl_tls1prf_dupctx(_In_ SCOSSL_TLS1PRF_CTX *ctx)
{
    SCOSSL_TLS1PRF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_TLS1PRF_CTX));
    if (copyCtx != NULL)
    {

    }
    
    return copyCtx;
}

SCOSSL_STATUS p_scossl_tls1prf_reset(_Inout_ SCOSSL_TLS1PRF_CTX *ctx)
{
    return SCOSSL_FAILURE;
}

SCOSSL_STATUS p_scossl_tls1prf_derive(_In_ SCOSSL_TLS1PRF_CTX *ctx, _In_reads_bytes_(keylen) unsigned char *key, size_t keylen,
                                   _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

const OSSL_PARAM *p_scossl_tls1prf_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_tls1prf_gettable_param_types;
}

const OSSL_PARAM *p_scossl_tls1prf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls1prf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_tls1prf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_tls1prf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_tls1prf_get_params(_Inout_ OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_tls1prf_get_ctx_params(_In_ void *ctx, _Inout_ OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_tls1prf_set_ctx_params(_Inout_ void *ctx, _In_ const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_tls1prf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_tls1prf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_tls1prf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_tls1prf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_tls1prf_derive},
    {OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void))p_scossl_tls1prf_gettable_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))p_scossl_tls1prf_get_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_tls1prf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif