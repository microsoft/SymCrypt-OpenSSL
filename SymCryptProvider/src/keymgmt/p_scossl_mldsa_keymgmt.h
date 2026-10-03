//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "signature/p_scossl_mldsa.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Shared keymgmt core (referenced by the per-variant dispatch tables)
//
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(_In_ const SCOSSL_MLDSA_BACKEND *backend, int params);
void p_scossl_mldsa_keymgmt_free_key_ctx(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection);
SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_keygen_settable_params(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ void *provCtx);
void p_scossl_mldsa_keygen_cleanup(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx);
SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(_In_ const OSSL_PARAM params[], _In_ const SCOSSL_MLDSA_BACKEND *backend, int mldsaParams);
SCOSSL_STATUS p_scossl_mldsa_keygen_set_template(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLDSA_KEY_CTX *tmplCtx);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keygen(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ OSSL_CALLBACK *cb, _In_ void *cbarg);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_load(_In_ const void *reference, size_t reference_size);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_settable_params(_In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_gettable_params(_In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[]);
BOOL p_scossl_mldsa_keymgmt_has(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection);
BOOL p_scossl_mldsa_keymgmt_match(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx1, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx2, int selection);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_impexp_types(int selection);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_export(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     _Inout_ PBYTE *ppbKey, _Inout_ SIZE_T *pcbKey);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);

//
// Per-variant keymgmt dispatch table generation
//
#define IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(variant, backendPtr, symcryptParams)                                             \
    static SCOSSL_MLDSA_KEY_CTX                                                                                         \
    *p_scossl_##variant##_keymgmt_new_ctx(ossl_unused SCOSSL_PROVCTX *provCtx)                                          \
    {                                                                                                                  \
        return p_scossl_mldsa_keymgmt_new_ctx(backendPtr, symcryptParams);                                             \
    }                                                                                                                  \
                                                                                                                       \
    static SCOSSL_MLDSA_KEYGEN_CTX                                                                                      \
    *p_scossl_##variant##_keygen_init(ossl_unused SCOSSL_PROVCTX *provCtx,                                              \
                                      ossl_unused int selection,                                                        \
                                      _In_ const OSSL_PARAM params[])                                                   \
    {                                                                                                                  \
        return p_scossl_mldsa_keygen_init(params, backendPtr, symcryptParams);                                         \
    }                                                                                                                  \
                                                                                                                       \
    const OSSL_DISPATCH p_scossl_##variant##_keymgmt_functions[] = {                                                   \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_##variant##_keymgmt_new_ctx},                                 \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mldsa_keymgmt_dup_key_ctx},                                   \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_set_params},                          \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_settable_params},                \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mldsa_keygen_cleanup},                                \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_##variant##_keygen_init},                                \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mldsa_keygen_set_template},                      \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mldsa_keygen},                                                \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mldsa_keymgmt_load},                                         \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_settable_params},                   \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_set_params},                             \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_gettable_params},                   \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_get_params},                             \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mldsa_keymgmt_has},                                           \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mldsa_keymgmt_match},                                       \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},                         \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},                         \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mldsa_keymgmt_import},                                     \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mldsa_keymgmt_export},                                     \
        {0, NULL}};

#ifdef __cplusplus
}
#endif
