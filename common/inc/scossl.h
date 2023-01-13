//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_LOG_LEVEL_NO_CHANGE  (-1)
#define SCOSSL_LOG_LEVEL_OFF        (0)
#define SCOSSL_LOG_LEVEL_ERROR      (1) // DEFAULT for OpenSSL ERR
#define SCOSSL_LOG_LEVEL_INFO       (2) // DEFAULT for stderr / logging to logfile
#define SCOSSL_LOG_LEVEL_DEBUG      (3)

void SCOSSL_ENGINE_set_trace_level(int trace_level, int ossl_ERR_level);
void SCOSSL_ENGINE_set_trace_log_filename(const char *filename);

// SymCrypt-OpenSSL Engine Initialization.
int SCOSSL_ENGINE_Initialize();


#ifdef __cplusplus
}
#endif
