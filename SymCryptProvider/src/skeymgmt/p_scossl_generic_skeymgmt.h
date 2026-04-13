//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"
#include "p_scossl_skey.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_SKEY *p_scossl_generic_skeymgmt_new(_In_ OSSL_LIB_CTX *libctx);
void p_scossl_generic_skeymgmt_free(_Inout_ SCOSSL_SKEY *skey);

SCOSSL_STATUS p_scossl_generic_skeymgmt_export(_In_ SCOSSL_SKEY *skey, int selection,
                                               _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

#ifdef __cplusplus
}
#endif