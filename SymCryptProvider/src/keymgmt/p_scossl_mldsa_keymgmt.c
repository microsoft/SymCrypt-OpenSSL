//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "signature/p_scossl_mldsa_signature.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // TODO
} SCOSSL_MLDSA_KEYGEN_CTX;

static const OSSL_PARAM p_scossl_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_settable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_impexp_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx, _In_ SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    // TODO
    return NULL;
}

static void p_scossl_mldsa_keymgmt_free_key_ctx(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx)
{
    // TODO
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    // TODO
    return NULL;
}

static SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    // TODO
    return SCOSSL_FAILURE;
}

static const OSSL_PARAM *p_scossl_mldsa_keygen_settable_params(_In_ ossl_unused void *provCtx)
{
    return p_scossl_mldsa_keygen_settable_param_types;
}

static void p_scossl_mldsa_keygen_cleanup(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx)
{
    // TODO
}

static SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,
                                                           _In_ const OSSL_PARAM params[], _In_ SYMCRYPT_MLDSA_PARAMS mldsaParams)
{
    // TODO
    return NULL;
}

static SCOSSL_STATUS p_scossl_mldsa_keygen_set_template(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLDSA_KEY_CTX *tmplCtx)
{
    // TODO
    return SCOSSL_SUCCESS;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keygen(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx,
                                                   ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    // TODO
    return NULL;
}

static SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_load(_In_ const void *reference, size_t reference_sz)
{
    // TODO
    return NULL;
}

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_settable_params(ossl_unused void *provctx)
{
    return p_scossl_mldsa_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(ossl_unused SCOSSL_MLDSA_KEY_CTX *keyCtx, ossl_unused const OSSL_PARAM params[])
{
    // TODO
    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_mldsa_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    // TODO
    return SCOSSL_SUCCESS;
}

static BOOL p_scossl_mldsa_keymgmt_has(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection)
{
    // TODO
    return FALSE;
}

static BOOL p_scossl_mldsa_keymgmt_match(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx1, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx2,
                                         int selection)
{
    // TODO
    return FALSE;
}

static const OSSL_PARAM *p_scossl_mldsa_keymgmt_impexp_types(int selection)
{
    return p_scossl_mldsa_impexp_types;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    // TODO
    return SCOSSL_FAILURE;
}

static SCOSSL_STATUS p_scossl_mldsa_keymgmt_export(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection,
                                                   _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    // TODO
    return SCOSSL_FAILURE;
}

#define IMPLEMENT_SCOSSL_MLDSA(bits)                                                                    \
    static SCOSSL_MLDSA_KEY_CTX                                                                         \
    *p_scossl_mldsa_##bits##_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx)                              \
    {                                                                                                   \
        return p_scossl_mldsa_keymgmt_new_ctx(provCtx, SYMCRYPT_MLDSA_PARAMS_MLDSA##bits);              \
    }                                                                                                   \
                                                                                                        \
    static SCOSSL_MLDSA_KEYGEN_CTX                                                                      \
    *p_scossl_mldsa_##bits##_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, ossl_unused int selection,       \
                                         _In_ const OSSL_PARAM params[])                                \
    {                                                                                                   \
        return p_scossl_mldsa_keygen_init(provCtx, selection, params,                                   \
            SYMCRYPT_MLDSA_PARAMS_MLDSA##bits);                                                         \
    }                                                                                                   \
                                                                                                        \
    const OSSL_DISPATCH p_scossl_mldsa##bits##_keymgmt_functions[] = {                                  \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_mldsa_##bits##_keymgmt_new_ctx},               \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mldsa_keymgmt_dup_key_ctx},                    \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                  \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mldsa_keygen_cleanup},                 \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_mldsa_##bits##_keygen_init},              \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mldsa_keygen_set_template},       \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mldsa_keygen},                                 \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mldsa_keymgmt_load},                          \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_settable_params},    \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_set_params},              \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_gettable_params},    \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_get_params},              \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mldsa_keymgmt_has},                            \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mldsa_keymgmt_match},                        \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},          \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mldsa_keymgmt_import},                      \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mldsa_keymgmt_export},                      \
        {0, NULL}};

IMPLEMENT_SCOSSL_MLDSA(44)
IMPLEMENT_SCOSSL_MLDSA(65)
IMPLEMENT_SCOSSL_MLDSA(87)

#ifdef __cplusplus
}
#endif