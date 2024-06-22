//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    PBYTE pbSalt;
    SIZE_T cbSalt;
    PBYTE pbSecret;
    SIZE_T cbSecret;
    PBYTE pbInfo;
    SIZE_T cbInfo;
    PCSYMCRYPT_SSKDF_MAC_EXPANDED_SALT pMacExpandedSalt;
    PCSYMCRYPT_MAC pMac;
    PCSYMCRYPT_HASH pHash;
} SCOSSL_PROV_SSKDF_CTX;

static const OSSL_PARAM p_scossl_sskdf_gettable_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_sskdf_settable_ctx_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0), // May be set for secret (Z)
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0), // Set in series, contcat
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_MAC_SIZE, NULL),
    OSSL_PARAM_END};


SCOSSL_STATUS p_scossl_sskdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx, _In_ const OSSL_PARAM params[]);

SCOSSL_PROV_SSKDF_CTX *p_scossl_sskdf_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_PROV_SSKDF_CTX));
}

void p_scossl_sskdf_freectx(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    if (ctx != NULL)
    {

    }

    OPENSSL_free(ctx);
}

SCOSSL_PROV_SSKDF_CTX *p_scossl_sskdf_dupctx(_In_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    SCOSSL_PROV_SSKDF_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_SSKDF_CTX));
    if (copyCtx != NULL)
    {

    }

    return copyCtx;
}

SCOSSL_STATUS p_scossl_sskdf_reset(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx)
{
    
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_sskdf_derive(_In_ SCOSSL_PROV_SSKDF_CTX *ctx,
                                     _Out_writes_bytes_(keylen) unsigned char *key, size_t keylen,
                                     _In_ const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_sskdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sskdf_gettable_ctx_param_types;
}

const OSSL_PARAM *p_scossl_sskdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_sskdf_settable_ctx_param_types;
}

SCOSSL_STATUS p_scossl_sskdf_get_ctx_params(_In_ SCOSSL_PROV_SSKDF_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_sskdf_set_ctx_params(_Inout_ SCOSSL_PROV_SSKDF_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_sskdf_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p_scossl_sskdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p_scossl_sskdf_freectx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))p_scossl_sskdf_dupctx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p_scossl_sskdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p_scossl_sskdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p_scossl_sskdf_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif