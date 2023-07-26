//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hmac.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Needed for fetching md
    OSSL_LIB_CTX *libctx;

    // Purely informational
    const char* mdName;

    SCOSSL_HMAC_CTX hmacCtx;
} SCOSSL_PROV_HMAC_CTX;

static const OSSL_PARAM p_scossl_hmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_hmac_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
    OSSL_PARAM_END};

static SCOSSL_PROV_HMAC_CTX *p_scossl_hmac_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return NULL;
}

static void p_scossl_hmac_freectx(_Inout_ SCOSSL_PROV_HMAC_CTX *ctx)
{

}

static SCOSSL_PROV_HMAC_CTX *p_scossl_hmac_dupctx(_In_ SCOSSL_PROV_HMAC_CTX *ctx)
{
    return NULL;
}

static SCOSSL_STATUS p_scossl_hmac_init(_Inout_ SCOSSL_PROV_HMAC_CTX *ctx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_hmac_update(_Inout_ SCOSSL_PROV_HMAC_CTX *ctx,
                                          _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_hmac_final(_Inout_ SCOSSL_PROV_HMAC_CTX *ctx,
                                         _Out_writes_bytes_(*outl) char *out, _Out_ size_t *outl, size_t outsize)
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_hmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_hmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_hmac_get_ctx_params(_In_ SCOSSL_PROV_HMAC_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_hmac_set_ctx_params(_Inout_ SCOSSL_PROV_HMAC_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

const OSSL_DISPATCH p_scossl_hmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_hmac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_hmac_dupctx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_hmac_freectx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_hmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_hmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_hmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_hmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_hmac_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif