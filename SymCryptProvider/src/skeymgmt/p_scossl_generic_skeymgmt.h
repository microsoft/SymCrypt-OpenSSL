//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"
#include "p_scossl_skey.h"

#ifdef __cplusplus
extern "C" {
#endif

void p_scossl_generic_skeymgmt_free(_Inout_ SCOSSL_SKEY *skey);

SCOSSL_SKEY *p_scossl_generic_skeymgmt_import(_In_ SCOSSL_PROVCTX *provctx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_generic_skeymgmt_export(_In_ SCOSSL_SKEY *skey, int selection,
                                               _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

SCOSSL_SKEY *p_scossl_generic_skeygen_generate(_In_ SCOSSL_PROVCTX *provctx, _In_ const OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif