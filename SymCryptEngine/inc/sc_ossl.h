//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#define     SC_OSSL_LOG_LEVEL_OFF        0
#define     SC_OSSL_LOG_LEVEL_ERROR      1   // DEFAULT
#define     SC_OSSL_LOG_LEVEL_INFO       2
#define     SC_OSSL_LOG_LEVEL_DEBUG      3

void SC_OSSL_ENGINE_set_trace_level(int trace_level);
void SC_OSSL_ENGINE_set_trace_log_filename(const char *filename);

// Symcrypt Engine Initialization.
int SC_OSSL_ENGINE_Initialize();


#ifdef __cplusplus
}
#endif
