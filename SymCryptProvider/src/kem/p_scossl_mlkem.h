//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    OSSL_FUNC_keymgmt_gen_cleanup_fn *genCleanup;
    OSSL_FUNC_keymgmt_gen_init_fn *genInit;
    OSSL_FUNC_keymgmt_gen_set_template_fn *setTemplate;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_dup_fn *dup;
    OSSL_FUNC_keymgmt_get_params_fn *getParams;
    OSSL_FUNC_keymgmt_set_params_fn *setParams;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_match_fn *match;
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_validate_fn *validate;
} SCOSSL_MLKEM_CLASSIC_KEYMGMT_FNS;

typedef struct {
    SCOSSL_PROVCTX *provCtx;

    const char *groupName;
    PSYMCRYPT_MLKEMKEY key;
    SYMCRYPT_MLKEM_PARAMS mlkemParams;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    const char *classicGroupName;
    SCOSSL_ECC_KEY_CTX *classicKeyCtx;
    const SCOSSL_MLKEM_CLASSIC_KEYMGMT_FNS *classicKeymgmt;
} SCOSSL_MLKEM_KEY_CTX;

#ifdef __cplusplus
}
#endif