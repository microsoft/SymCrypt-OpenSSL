//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_SKEY_TYPE_GENERIC 1
#define SCOSSL_SKEY_TYPE_AES 2

typedef struct
{
    int type;

    OSSL_LIB_CTX *libctx;

    PBYTE pbKey;
    SIZE_T cbKey;
} SCOSSL_SKEY;

#ifdef __cplusplus
}
#endif