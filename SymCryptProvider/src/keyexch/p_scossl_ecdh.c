//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct 
{

} SCOSSL_ECDH_CTX;

static const OSSL_PARAM p_scossl_ecdh_ctx_settable_param_types[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecdh_ctx_gettable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_ecdh_set_ctx_params(_Inout_ SCOSSL_ECDH_CTX *ctx, const _In_ OSSL_PARAM params[]);

static SCOSSL_ECDH_CTX *p_scossl_ecdh_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    return NULL;
}

static void p_scossl_ecdh_freectx(_In_ SCOSSL_ECDH_CTX *ctx)
{

}

static SCOSSL_ECDH_CTX *p_scossl_ecdh_dupctx(_In_ SCOSSL_ECDH_CTX *ctx)
{
    return NULL;
}

static SCOSSL_STATUS p_scossl_ecdh_init(_In_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *provkey,
                                        const _In_ OSSL_PARAM params[])
{
    return p_scossl_ecdh_set_ctx_params(ctx, params);
}

static SCOSSL_STATUS p_scossl_ecdh_set_peer(_Inout_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *provkey)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_ecdh_derive(_In_ SCOSSL_ECDH_CTX *ctx, _Out_writes_bytes_opt_(*secretlen) unsigned char *secret,
                                          _Out_ size_t *secretlen, size_t outlen)
{
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_ecdh_set_ctx_params(_Inout_ SCOSSL_ECDH_CTX *ctx, const _In_ OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_ecdh_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_ecdh_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_ecdh_get_ctx_params(_In_ SCOSSL_ECDH_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_ecdh_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_ecdh_ctx_gettable_param_types;
}

const OSSL_DISPATCH p_scossl_ecdh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))p_scossl_ecdh_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))p_scossl_ecdh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))p_scossl_ecdh_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))p_scossl_ecdh_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))p_scossl_ecdh_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))p_scossl_ecdh_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_ecdh_gettable_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif