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

void _scossl_log(
    int trace_level,
    const char *func,
    const char *format, ...);

void _scossl_log_bytes(
    int trace_level,
    const char *func,
    char *description,
    const char *s,
    int len);

void _scossl_log_bignum(
    int trace_level,
    const char *func,
    char *description,
    BIGNUM *bn);

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    const char *func,
    char *description,
    SYMCRYPT_ERROR symError);

// Enable debug and info messages in debug builds, but compile them out in release builds
#if DBG
    #define SC_OSSL_LOG_DEBUG(...) \
        _scossl_log(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, __VA_ARGS__)

    #define SC_OSSL_LOG_INFO(...) \
        _scossl_log(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)

    #define SC_OSSL_LOG_BYTES_DEBUG(description, s, len) \
        _scossl_log_bytes(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, (const char*) s, len)

    #define SC_OSSL_LOG_BYTES_INFO(description, s, len) \
        _scossl_log_bytes(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, (const char*) s, len)

    #define SC_OSSL_LOG_BIGNUM_DEBUG(description, bn) \
        _scossl_log_bignum(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, bn)

    #define SC_OSSL_LOG_BIGNUM_INFO(description, s, len) \
        _scossl_log_bignum(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, bn)

    #define SC_OSSL_LOG_SYMERROR_DEBUG(description, symError) \
        _scossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_DEBUG, __FUNCTION__, description, symError)

    #define SC_OSSL_LOG_SYMERROR_INFO(description, symError) \
        _scossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_INFO, __FUNCTION__, description, symError)
#else
    #define SC_OSSL_LOG_DEBUG(...)
    #define SC_OSSL_LOG_INFO(...)
    #define SC_OSSL_LOG_BYTES_DEBUG(description, s, len)
    #define SC_OSSL_LOG_BYTES_INFO(description, s, len)
    #define SC_OSSL_LOG_BIGNUM_DEBUG(description, bn)
    #define SC_OSSL_LOG_BIGNUM_INFO(description, s, len)
    #define SC_OSSL_LOG_SYMERROR_DEBUG(description, symError)
    #define SC_OSSL_LOG_SYMERROR_INFO(description, symError)
#endif

#define SC_OSSL_LOG_ERROR(...) \
    _scossl_log(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, __VA_ARGS__)

#define SC_OSSL_LOG_BYTES_ERROR(description, s, len) \
    _scossl_log_bytes(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, (const char*) s, len)

#define SC_OSSL_LOG_BIGNUM_ERROR(description, s, len) \
    _scossl_log_bignum(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, bn)

#define SC_OSSL_LOG_SYMERROR_ERROR(description, symError) \
    _scossl_log_SYMCRYPT_ERROR(SC_OSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, symError)

#ifdef __cplusplus
}
#endif
