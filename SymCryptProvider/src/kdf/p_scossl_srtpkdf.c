//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_srtpkdf.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{

} SCOSSL_PROV_SRTPKDF_CTX;


static const OSSL_PARAM p_scossl_srtpkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_srtpkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_newctx(ossl_unused SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_SRTPKDF_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (ctx != NULL)
    {

    }

    return ctx;
}

static void p_scossl_srtpkdf_freectx(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

static SCOSSL_PROV_SRTPKDF_CTX *p_scossl_srtpkdf_dupctx(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    SCOSSL_PROV_SRTPKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SRTPKDF_CTX));

    if (copyCtx != NULL)
    {

    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_srtpkdf_reset(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_srtpkdf_derive(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx,
                                          _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                          _In_ const OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_srtpkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_gettable_ctx_param_types;
}

static const OSSL_PARAM *p_scossl_srtpkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_srtpkdf_settable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_srtpkdf_get_ctx_params(_In_ SCOSSL_PROV_SRTPKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_srtpkdf_set_ctx_params(_Inout_ SCOSSL_PROV_SRTPKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_srtpkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_srtpkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_srtpkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_srtpkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_srtpkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_srtpkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_srtpkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif