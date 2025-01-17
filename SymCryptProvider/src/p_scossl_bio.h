//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

void p_scossl_set_core_bio(_In_ const OSSL_DISPATCH *dispatch);
BIO_METHOD *p_scossl_bio_init();
BIO *p_scossl_bio_new_from_core_bio(_In_ SCOSSL_PROVCTX *provctx, _In_ OSSL_CORE_BIO *coreBio);

#ifdef __cplusplus
}
#endif