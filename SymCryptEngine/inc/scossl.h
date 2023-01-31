//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// SymCrypt-OpenSSL Engine Initialization.
int SCOSSL_ENGINE_Initialize();

#ifdef __cplusplus
}
#endif
