//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const PCSYMCRYPT_MAC pMac;
} SCOSSL_KMAC_CTX;

static const OSSL_PARAM p_scossl_kmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_kmac_ctx_settable_param_types[] = {
    OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_kmac_set_ctx_params(_Inout_ SCOSSL_KMAC_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_KMAC_CTX *p_scossl_kmac128_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return NULL;
}

static SCOSSL_KMAC_CTX *p_scossl_kmac256_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return NULL;
}


static void p_scossl_kmac_freectx(_Inout_ SCOSSL_KMAC_CTX *ctx)
{
}

static SCOSSL_KMAC_CTX *p_scossl_kmac_dupctx(_In_ SCOSSL_KMAC_CTX *ctx)
{
    return NULL;
}

static SCOSSL_STATUS p_scossl_kmac_init(_Inout_ SCOSSL_KMAC_CTX *ctx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_kmac_update(_Inout_ SCOSSL_KMAC_CTX *ctx,
                                          _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_kmac_final(_Inout_ SCOSSL_KMAC_CTX *ctx,
                                         _Out_writes_bytes_(*outl) char *out, _Out_ size_t *outl, size_t outsize)
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_kmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_kmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_kmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_kmac_get_ctx_params(_In_ SCOSSL_KMAC_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_kmac_set_ctx_params(_Inout_ SCOSSL_KMAC_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_kmac128_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_kmac128_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_kmac_dupctx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_kmac_freectx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_kmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_kmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_kmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_set_ctx_params},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_kmac256_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_kmac256_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))p_scossl_kmac_dupctx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))p_scossl_kmac_freectx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_kmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))p_scossl_kmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))p_scossl_kmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_kmac_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif