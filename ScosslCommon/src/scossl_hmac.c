//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_HMAC_CTX *scossl_hmac_newctx()
{
    return NULL;
}

_Use_decl_annotations_
SCOSSL_HMAC_CTX *scossl_hmac_dupctx(SCOSSL_HMAC_CTX *ctx)
{
    return NULL;
}

_Use_decl_annotations_
void scossl_hmac_freectx(SCOSSL_HMAC_CTX *ctx)
{

}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_set_mac_key(SCOSSL_HMAC_CTX *ctx,
                                      PBYTE pbMacKey, SIZE_T cbMacKey)
{
    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_init(SCOSSL_HMAC_CTX *ctx,
                               PBYTE pbKey, SIZE_T cbKey)
{
    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_update(SCOSSL_HMAC_CTX *ctx,
                                PCBYTE pbData, SIZE_T cbData)
{
    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_hmac_final(SCOSSL_HMAC_CTX *ctx,
                                PBYTE pbResult, SIZE_T *cbResult)
{
    return SCOSSL_FAILURE;
}


#ifdef __cplusplus
}
#endif