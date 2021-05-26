//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void* SYMCRYPT_ENGINE_zalloc(size_t num);
void* SYMCRYPT_ENGINE_realloc(void *mem, size_t num);
void SYMCRYPT_ENGINE_free(void *mem);

void _SYMCRYPT_log(
    int trace_level,
    const char *func,
    const char *format, ...);

#define SYMCRYPT_LOG_DEBUG(...) \
    _SYMCRYPT_log(SYMCRYPT_LOG_LEVEL_DEBUG, __FUNCTION__, __VA_ARGS__)

#define SYMCRYPT_LOG_INFO(...) \
    _SYMCRYPT_log(SYMCRYPT_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)

#define SYMCRYPT_LOG_ERROR(...) \
    _SYMCRYPT_log(SYMCRYPT_LOG_LEVEL_ERROR, __FUNCTION__, __VA_ARGS__)

void _SYMCRYPT_log_bytes(
    int trace_level,
    const char *func,
    char *description,
    const char *s,
    int len);

#define SYMCRYPT_LOG_BYTES_DEBUG(description, s, len) \
    _SYMCRYPT_log_bytes(SYMCRYPT_LOG_LEVEL_DEBUG, __FUNCTION__, description, (const char*) s, len)

#define SYMCRYPT_LOG_BYTES_INFO(description, s, len) \
    _SYMCRYPT_log_bytes(SYMCRYPT_LOG_LEVEL_INFO, __FUNCTION__, description, (const char*) s, len)

#define SYMCRYPT_LOG_BYTES_ERROR(description, s, len) \
    _SYMCRYPT_log_bytes(SYMCRYPT_LOG_LEVEL_ERROR, __FUNCTION__, description, (const char*) s, len)


void _SYMCRYPT_log_bignum(
    int trace_level,
    const char *func,
    char *description,
    BIGNUM *bn);

#define SYMCRYPT_LOG_BIGNUM_DEBUG(description, bn) \
    _SYMCRYPT_log_bignum(SYMCRYPT_LOG_LEVEL_DEBUG, __FUNCTION__, description, bn)

#define SYMCRYPT_LOG_BIGNUM_INFO(description, s, len) \
    _SYMCRYPT_log_bignum(SYMCRYPT_LOG_LEVEL_INFO, __FUNCTION__, description, bn)

#define SYMCRYPT_LOG_BIGNUM_ERROR(description, s, len) \
    _SYMCRYPT_log_bignum(SYMCRYPT_LOG_LEVEL_ERROR, __FUNCTION__, description, bn)


#ifdef __cplusplus
}
#endif
