//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_dh.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Provider needs to support importing group by parameters.
    // This is only set if the group has been imported by parameters
    // and needs to be freed.
    PSYMCRYPT_DLGROUP pDlGroup;
    SCOSSL_DH_KEY_CTX *keyCtx;
    OSSL_LIB_CTX *libCtx;
} SCOSSL_PROV_DH_KEY_CTX;

#ifdef __cplusplus
}
#endif