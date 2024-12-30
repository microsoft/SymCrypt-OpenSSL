//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"

#define SCOSSL_DRBG_STRENGTH 256
#define SCOSSL_DRBG_MAX_REQUEST_SIZE (1 << 16)

#ifdef __cplusplus
extern "C" {
#endif

static const BYTE dummy_scossl_ctx = 0;

static const OSSL_PARAM gettable_ctx_param_types[] = {
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END};

// All state is maintained inside SymCrypt, but newctx and
// freectx are expected. These do nothing in the SymCrypt provider
static void *p_scossl_rand_newctx(ossl_unused void *provctx,
                                  ossl_unused void *parent,
                                  ossl_unused const OSSL_DISPATCH *parent_calls)
{
    return (void *)&dummy_scossl_ctx;
}

static void p_scossl_rand_freectx(ossl_unused void *ctx){}

// RNG state is internally managed by SymCrypt. This function is
// required, but does not actually instantiate SymCrypt's RNG state
static SCOSSL_STATUS p_scossl_rand_instantiate(ossl_unused void *ctx,
                                               unsigned int strength,
                                               int prediction_resistance,
                                               _In_reads_bytes_opt_(addin_len) const unsigned char *addin, size_t addin_len,
                                               ossl_unused const OSSL_PARAM params[])
{
    if (strength > SCOSSL_DRBG_STRENGTH || prediction_resistance)
    {
        return SCOSSL_FAILURE;
    }

    if (addin_len > 0)
    {
        SymCryptProvideEntropy(addin, addin_len);
    }

    return SCOSSL_SUCCESS;
}

// RNG state is internally managed by SymCrypt. This function is
// required, but does not actually uninstantiate SymCrypt's RNG state.
// RNG is uninstantiated on SymCrypt unload
SCOSSL_STATUS p_scossl_rand_uninstantiate(ossl_unused void *ctx)
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rand_generate(ossl_unused void *ctx,
                                            _Out_writes_bytes_(outlen) unsigned char *out, size_t outlen,
                                            ossl_unused unsigned int strength,
                                            ossl_unused int prediction_resistance,
                                            _In_reads_bytes_opt_(addin_len) const unsigned char *addin, size_t addin_len)
{
    if (addin_len > 0)
    {
        SymCryptProvideEntropy(addin, addin_len);
    }

    SymCryptRandom(out, outlen);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_rand_reseed(ossl_unused void *ctx,
                                          ossl_unused int prediction_resistance,
                                          ossl_unused const unsigned char *ent, ossl_unused size_t ent_len,
                                          _In_reads_bytes_opt_(addin_len) const unsigned char *addin, size_t addin_len)
{
    SymCryptProvideEntropy(addin, addin_len);
    return SCOSSL_SUCCESS;
}

// SymCrypt internally mangages locking, so the provider does not need
// to. This function is required but does nothing
static SCOSSL_STATUS p_scossl_rand_enable_locking(ossl_unused void *ctx)
{
    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rand_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return gettable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_rand_get_ctx_params(ossl_unused void *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    // State managed by symcrypt module
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, SCOSSL_DRBG_STRENGTH))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SCOSSL_DRBG_MAX_REQUEST_SIZE))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_rand_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))p_scossl_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))p_scossl_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))p_scossl_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))p_scossl_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))p_scossl_rand_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))p_scossl_rand_reseed},
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))p_scossl_rand_enable_locking},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))p_scossl_rand_get_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif