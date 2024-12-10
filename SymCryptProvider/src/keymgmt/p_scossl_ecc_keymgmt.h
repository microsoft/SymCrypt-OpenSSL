//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;
    PCSYMCRYPT_ECURVE curve;
    BOOL isX25519;
    point_conversion_form_t conversionFormat;
} SCOSSL_ECC_KEYGEN_CTX;

// ECC Key management functions are exposed here for use in hybrid key exchange
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx);
SCOSSL_ECC_KEY_CTX *p_scossl_x25519_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_ecc_keymgmt_free_ctx(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx);
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_dup_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx, int selection);

SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                _In_ const OSSL_PARAM params[]);
SCOSSL_ECC_KEYGEN_CTX *p_scossl_x25519_keygen_init(_In_ SCOSSL_PROVCTX *provctx, ossl_unused int selection,
                                                   _In_ const OSSL_PARAM params[]);
void p_scossl_ecc_keygen_cleanup(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx);
SCOSSL_STATUS p_scossl_ecc_keygen_set_template(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx, _In_ SCOSSL_ECC_KEY_CTX *tmplCtx);
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keygen(_In_ SCOSSL_ECC_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg);

SCOSSL_STATUS p_scossl_ecc_keymgmt_get_params(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_ecc_keymgmt_set_params(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);

BOOL p_scossl_ecc_keymgmt_has(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection);
SCOSSL_STATUS p_scossl_ecc_keymgmt_validate(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, ossl_unused int checktype);
BOOL p_scossl_ecc_keymgmt_match(_In_ SCOSSL_ECC_KEY_CTX *keyCtx1, _In_ SCOSSL_ECC_KEY_CTX *keyCtx2,
                                int selection);

SCOSSL_STATUS p_scossl_ecc_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_ecc_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                          _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);
SCOSSL_STATUS p_scossl_x25519_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_x25519_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                             _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

#ifdef __cplusplus
}
#endif