//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

const OSSL_ITEM *p_scossl_rsa_get_supported_md(_In_ OSSL_LIB_CTX *libctx,
                                               _In_ const char *mdname, _In_ const char *propq,
                                               _Out_opt_ EVP_MD **md);

#ifdef __cplusplus
}
#endif