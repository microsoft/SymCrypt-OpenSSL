//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <symcrypt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef _Return_type_success_(return == 1) int SCOSSL_STATUS;
typedef _Return_type_success_(return >= 0) int SCOSSL_RETURNLENGTH; // For functions that return length on success and -1 on error

void* SC_OSSL_ENGINE_zalloc(size_t num);
void* SC_OSSL_ENGINE_realloc(void *mem, size_t num);
void SC_OSSL_ENGINE_free(void *mem);

void _sc_ossl_log(
    int trace_level,
    const char *func,
    const char *format, ...);

#define SC_OSSL_LOG_DEBUG(...) \
    _sc_ossl_log(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, __VA_ARGS__)

#define SC_OSSL_LOG_INFO(...) \
    _sc_ossl_log(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)

#define SC_OSSL_LOG_ERROR(...) \
    _sc_ossl_log(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, __VA_ARGS__)

void _sc_ossl_log_bytes(
    int trace_level,
    const char *func,
    char *description,
    const char *s,
    int len);

#define SC_OSSL_LOG_BYTES_DEBUG(description, s, len) \
    _sc_ossl_log_bytes(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, (const char*) s, len)

#define SC_OSSL_LOG_BYTES_INFO(description, s, len) \
    _sc_ossl_log_bytes(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, (const char*) s, len)

#define SC_OSSL_LOG_BYTES_ERROR(description, s, len) \
    _sc_ossl_log_bytes(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, (const char*) s, len)


void _sc_ossl_log_bignum(
    int trace_level,
    const char *func,
    char *description,
    BIGNUM *bn);

#define SC_OSSL_LOG_BIGNUM_DEBUG(description, bn) \
    _sc_ossl_log_bignum(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, bn)

#define SC_OSSL_LOG_BIGNUM_INFO(description, s, len) \
    _sc_ossl_log_bignum(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, bn)

#define SC_OSSL_LOG_BIGNUM_ERROR(description, s, len) \
    _sc_ossl_log_bignum(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, bn)


void _sc_ossl_log_SYMCRYPT_ERROR(
    int trace_level,
    const char *func,
    char *description,
    SYMCRYPT_ERROR symError);


#define SC_OSSL_LOG_SYMERROR_DEBUG(description, symError) \
    _sc_ossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, symError)

#define SC_OSSL_LOG_SYMERROR_INFO(description, symError) \
    _sc_ossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, symError)

#define SC_OSSL_LOG_SYMERROR_ERROR(description, symError) \
    _sc_ossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, symError)

#ifdef __cplusplus
}
#endif
