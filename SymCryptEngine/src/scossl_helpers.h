//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include <symcrypt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int SCOSSL_STATUS;
typedef _Return_type_success_(return >= 0) int SCOSSL_RETURNLENGTH; // For functions that return length on success and -1 on error

void* SCOSSL_ENGINE_zalloc(size_t num);
void* SCOSSL_ENGINE_realloc(void *mem, size_t num);
void SCOSSL_ENGINE_free(void *mem);

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
    SYMCRYPT_ERROR scError);

// Enable debug and info messages in debug builds, but compile them out in release builds
#if DBG
    #define SCOSSL_LOG_DEBUG(...) \
        _scossl_log(SCOSSL_LOG_LEVEL_DEBUG, __func__, __VA_ARGS__)

    #define SCOSSL_LOG_INFO(...) \
        _scossl_log(SCOSSL_LOG_LEVEL_INFO, __func__, __VA_ARGS__)

    #define SCOSSL_LOG_BYTES_DEBUG(description, s, len) \
        _scossl_log_bytes(SCOSSL_LOG_LEVEL_DEBUG, __func__, description, (const char*) s, len)

    #define SCOSSL_LOG_BYTES_INFO(description, s, len) \
        _scossl_log_bytes(SCOSSL_LOG_LEVEL_INFO, __func__, description, (const char*) s, len)

    #define SCOSSL_LOG_BIGNUM_DEBUG(description, bn) \
        _scossl_log_bignum(SCOSSL_LOG_LEVEL_DEBUG, __func__, description, bn)

    #define SCOSSL_LOG_BIGNUM_INFO(description, s, len) \
        _scossl_log_bignum(SCOSSL_LOG_LEVEL_INFO, __func__, description, bn)

    #define SCOSSL_LOG_scError_DEBUG(description, scError) \
        _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_DEBUG, __func__, description, scError)

    #define SCOSSL_LOG_scError_INFO(description, scError) \
        _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_INFO, __func__, description, scError)
#else
    #define SCOSSL_LOG_DEBUG(...)
    #define SCOSSL_LOG_INFO(...)
    #define SCOSSL_LOG_BYTES_DEBUG(description, s, len)
    #define SCOSSL_LOG_BYTES_INFO(description, s, len)
    #define SCOSSL_LOG_BIGNUM_DEBUG(description, bn)
    #define SCOSSL_LOG_BIGNUM_INFO(description, s, len)
    #define SCOSSL_LOG_scError_DEBUG(description, scError)
    #define SCOSSL_LOG_scError_INFO(description, scError)
#endif

#define SCOSSL_LOG_ERROR(...) \
    _scossl_log(SCOSSL_LOG_LEVEL_ERROR, __FUNCTION__, __VA_ARGS__)

#define SCOSSL_LOG_BYTES_ERROR(description, s, len) \
    _scossl_log_bytes(SCOSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, (const char*) s, len)

#define SCOSSL_LOG_BIGNUM_ERROR(description, s, len) \
    _scossl_log_bignum(SCOSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, bn)

#define SCOSSL_LOG_scError_ERROR(description, scError) \
    _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_ERROR, __FUNCTION__, description, scError)

#ifdef __cplusplus
}
#endif
