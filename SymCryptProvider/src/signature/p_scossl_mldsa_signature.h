//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;

    SYMCRYPT_MLDSA_PARAMS mldsaParams;
    SYMCRYPT_MLDSAKEY_FORMAT format;
    PSYMCRYPT_MLDSAKEY key;
} SCOSSL_MLDSA_KEY_CTX;

#ifdef __cplusplus
}
#endif