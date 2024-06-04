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
    // pDlGroup may be set by params, or reference a static, known
    // named group. If the group is loaded from params it must be
    // freed when the context is freed.
    PSYMCRYPT_DLGROUP pDlGroup;
    SCOSSL_DH_KEY_CTX *keyCtx;
    BOOL groupSetByParams;
    int nBitsPriv;
    OSSL_LIB_CTX *libCtx;
} SCOSSL_PROV_DH_KEY_CTX;

#ifdef __cplusplus
}
#endif