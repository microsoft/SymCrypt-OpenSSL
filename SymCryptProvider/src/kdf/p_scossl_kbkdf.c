//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;

} SCOSSL_PROV_KBKDF_CTX;

static const OSSL_PARAM p_scossl_kbkdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_kbkdf_settable_ctx_param_types[] = {
    OSSL_PARAM_END};

static SCOSSL_PROV_KBKDF_CTX *p_scossl_kbkdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{

}

static void p_scossl_kbkdf_freectx(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx)
{

}

static SCOSSL_PROV_KBKDF_CTX *p_scossl_kbkdf_dupctx(_In_ SCOSSL_PROV_KBKDF_CTX *ctx)
{

}

static SCOSSL_STATUS p_scossl_kbkdf_reset(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx)
{

}

static SCOSSL_STATUS p_scossl_kbkdf_derive(_In_ SCOSSL_PROV_KBKDF_CTX *ctx,
                                          _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                          _In_ const OSSL_PARAM params[])
{

}

static const OSSL_PARAM *p_scossl_kbkdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{

}

static const OSSL_PARAM *p_scossl_kbkdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{

}

static SCOSSL_STATUS p_scossl_kbkdf_get_ctx_params(_In_ SCOSSL_PROV_KBKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{

}

static SCOSSL_STATUS p_scossl_kbkdf_set_ctx_params(_Inout_ SCOSSL_PROV_KBKDF_CTX *ctx, const _In_ OSSL_PARAM params[])
{

}

const OSSL_DISPATCH p_scossl_kbkdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_kbkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_kbkdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_kbkdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_kbkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_kbkdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_kbkdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif