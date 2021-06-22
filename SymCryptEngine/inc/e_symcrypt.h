//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#define     SYMCRYPT_LOG_LEVEL_OFF        0
#define     SYMCRYPT_LOG_LEVEL_ERROR      1   // DEFAULT
#define     SYMCRYPT_LOG_LEVEL_INFO       2
#define     SYMCRYPT_LOG_LEVEL_DEBUG      3

void SYMCRYPT_ENGINE_set_trace_level(int trace_level);
void SYMCRYPT_ENGINE_set_trace_log_filename(const char *filename);

// Syncrypt Engine Initialization.
int SYMCRYPT_ENGINE_Initialize();


#ifdef __cplusplus
}
#endif
