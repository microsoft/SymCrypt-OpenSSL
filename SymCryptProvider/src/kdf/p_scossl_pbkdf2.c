//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {

} SCOSSL_PROV_PBKDF2_CTX;

static const OSSL_PARAM p_scossl_pbkdf2_gettable_ctx_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_pbkdf2_settable_ctx_param_types[] = {
    OSSL_PARAM_END};

SCOSSL_STATUS p_scossl_pbkdf2_set_ctx_params(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx, _In_ const OSSL_PARAM params[]);

SCOSSL_PROV_PBKDF2_CTX *p_scossl_pbkdf2_newctx(ossl_unused void *provctx)
{
    SCOSSL_PROV_PBKDF2_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_PBKDF2_CTX));

    return ctx;
}

void p_scossl_pbkdf2_freectx(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx);
}

SCOSSL_PROV_PBKDF2_CTX *p_scossl_pbkdf2_dupctx(_In_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    SCOSSL_PROV_PBKDF2_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_PBKDF2_CTX));
    if (copyCtx != NULL)
    {

    }

    status = SCOSSL_SUCCESS;

cleanup:
    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_pbkdf2_freectx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

SCOSSL_STATUS p_scossl_pbkdf2_reset(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx)
{
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_pbkdf2_derive(_In_ SCOSSL_PROV_PBKDF2_CTX *ctx,
                                    _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                    _In_ const OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;

    if (!p_scossl_pbkdf2_set_ctx_params(ctx, params))
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_pbkdf2_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_pbkdf2_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_pbkdf2_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_pbkdf2_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_pbkdf2_get_ctx_params(_In_ SCOSSL_PROV_PBKDF2_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_pbkdf2_set_ctx_params(_Inout_ SCOSSL_PROV_PBKDF2_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_pbkdf2_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_pbkdf2_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_pbkdf2_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_pbkdf2_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_pbkdf2_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_pbkdf2_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_pbkdf2_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif