//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prototype definitions, subject to change
#define IMPLEMENT_SCOSSL_KEYMGMT_FUNCTIONS(alg)                                                           \
    const OSSL_DISPATCH scossl_prov_##alg##_keymgmt_functions[] = {                                       \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))scossl_prov_##alg##_keymgmt_free},                       \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))scossl_prov_##alg##_keymgmt_load},                       \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))scossl_prov_##alg##_keymgmt_get_params},           \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))scossl_prov_##alg##_keymgmt_gettable_params}, \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))scossl_prov_##alg##_keymgmt_set_params},           \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))scossl_prov_##alg##_keymgmt_settable_params}, \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))scossl_prov_##alg##_keymgmt_has},                         \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))scossl_prov_##alg##_keymgmt_match},                     \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))scossl_prov_##alg##_keymgmt_import},                   \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))scossl_prov_##alg##_keymgmt_import_types},       \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))scossl_prov_##alg##_keymgmt_export},                   \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))scossl_prov_##alg##_keymgmt_export_types},       \

#define IMPLEMENT_SCOSSL_KEYMGMT_GEN_FUNCTIONS(alg)                                                       \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))##alg##_gen_init},                                   \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))scossl_prov_##alg##_get_params},                   \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))scossl_prov_##alg##_gen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))scossl_prov_##alg##_gen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))scossl_prov_##alg##_gen},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))scossl_prov_##alg##_gen_cleanup},                 \

#define SCOSSL_KEYMGMT_FUNCTIONS_END \
        {0, NULL}};                  \

#ifdef __cplusplus
}
#endif