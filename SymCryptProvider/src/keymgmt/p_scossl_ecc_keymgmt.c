//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_new_ctx(ossl_unused void *provctx)
{
    return scossl_ecc_new_key_ctx();
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_dup_ctx(SCOSSL_ECC_KEY_CTX *keyCtx, ossl_unused int selection)
{
    return scossl_ecc_dup_key_ctx(keyCtx);
}

const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_ecc_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_ecc_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))scossl_ecc_free_key_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_ecc_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_ecc_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_ecc_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_ecc_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_ecc_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_ecc_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_ecc_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_ecc_keymgmt_export},
    {0, NULL}};

#ifdef __cplusplus
}
#endif