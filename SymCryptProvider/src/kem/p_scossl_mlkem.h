//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
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
    OSSL_FUNC_keyexch_newctx_fn *newCtx;
    OSSL_FUNC_keyexch_freectx_fn *freeCtx;
    OSSL_FUNC_keyexch_dupctx_fn *dupCtx;
    OSSL_FUNC_keyexch_init_fn *init;
    OSSL_FUNC_keyexch_set_peer_fn *setPeer;
    OSSL_FUNC_keyexch_derive_fn *derive;
} SCOSSL_MLKEM_CLASSIC_KEYEXCH_FNS;

typedef struct {
    const char *groupName;
    PSYMCRYPT_MLKEMKEY key;
    SYMCRYPT_MLKEM_PARAMS mlkemParams;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    SCOSSL_ECC_KEY_CTX *classicKeyCtx;
    const SCOSSL_MLKEM_CLASSIC_KEYMGMT_FNS *classicKeymgmt;
    const SCOSSL_MLKEM_CLASSIC_KEYEXCH_FNS *classicKeyexch;
} SCOSSL_MLKEM_KEY_CTX;

#ifdef __cplusplus
}
#endif