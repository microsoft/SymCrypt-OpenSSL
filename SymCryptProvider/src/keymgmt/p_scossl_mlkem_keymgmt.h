//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(ossl_unused void *provCtx);
void p_scossl_mlkem_keymgmt_free_key_ctx(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx);

SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                            _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_key_bytes(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                   SYMCRYPT_MLKEMKEY_FORMAT format,
                                                   _Out_writes_bytes_(*cbKey) PBYTE *ppbKey, _Out_ SIZE_T *pcbKey);

#ifdef __cplusplus
}
#endif