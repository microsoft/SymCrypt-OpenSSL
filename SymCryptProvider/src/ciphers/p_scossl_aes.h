//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_FLAG_AEAD 0x01
#define SCOSSL_FLAG_CUSTOM_IV 0x02

const OSSL_PARAM *p_scossl_aes_generic_gettable_params(void *provctx);
SCOSSL_STATUS p_scossl_aes_generic_get_params(_Inout_ OSSL_PARAM params[],
                                              unsigned int mode,
                                              size_t keylen,
                                              size_t ivlen,
                                              size_t block_size,
                                              unsigned int flags);

#ifdef __cplusplus
}
#endif