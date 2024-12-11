//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_MLKEM_KEY_CTX *p_scossl_mlkem_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx);
void p_scossl_mlkem_keymgmt_free_key_ctx(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx);

SCOSSL_STATUS p_scossl_mlkem_keymgmt_import(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mlkem_keymgmt_export(_In_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                            _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

SCOSSL_STATUS p_scossl_mlkem_keymgmt_get_encoded_key(_In_ const SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                     _Out_writes_bytes_(*pcbKey) PBYTE *ppbKey, _Out_ SIZE_T *pcbKey);
SCOSSL_STATUS p_scossl_mlkem_keymgmt_set_encoded_key(_Inout_ SCOSSL_MLKEM_KEY_CTX *keyCtx, int selection,
                                                     _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);


#ifdef __cplusplus
}
#endif