//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_ENGINE_TRACELOG_PARA_LENGTH        256

#define     SCOSSL_LOG_LEVEL_PREFIX_ERROR     "ERROR"
#define     SCOSSL_LOG_LEVEL_PREFIX_INFO      "INFO"
#define     SCOSSL_LOG_LEVEL_PREFIX_DEBUG     "DEBUG"


static int _traceLogLevel = SCOSSL_LOG_LEVEL_INFO;
static char *_traceLogFilename = NULL;

void SCOSSL_ENGINE_set_trace_level(int trace_level)
{
    if( trace_level >= SCOSSL_LOG_LEVEL_OFF &&
        trace_level <= SCOSSL_LOG_LEVEL_DEBUG )
    {
        _traceLogLevel = trace_level;
    }
    return;
}

void SCOSSL_ENGINE_set_trace_log_filename(const char *filename)
{
    if( _traceLogFilename )
    {
        OPENSSL_free(_traceLogFilename);
    }
    _traceLogFilename = OPENSSL_strdup(filename);
    return;
}

static FILE *_open_trace_log_filename()
{
    FILE *fp = stderr;

    if( _traceLogFilename != NULL )
    {
        fp = fopen(_traceLogFilename, "a");
        if( fp == NULL )
        {
            fp = stderr;
        }
    }
    return fp;
}

static void _close_trace_log_filename(FILE *fp)
{
    if( fp != stderr )
    {
        fflush(fp);
        fclose(fp);
    }
    return;
}

void _scossl_log(
    int trace_level,
    const char *func,
    const char *format, ...)
{
    char paraBuf[SCOSSL_ENGINE_TRACELOG_PARA_LENGTH];
    FILE *fp = NULL;
    va_list args;
    va_start(args, format);
    char *trace_level_prefix = "";

    if( _traceLogLevel < trace_level )
    {
        return;
    }

    switch( trace_level )
    {
        case SCOSSL_LOG_LEVEL_ERROR:
            trace_level_prefix = SCOSSL_LOG_LEVEL_PREFIX_ERROR;
            break;
        case SCOSSL_LOG_LEVEL_INFO:
            trace_level_prefix = SCOSSL_LOG_LEVEL_PREFIX_INFO;
            break;
        case SCOSSL_LOG_LEVEL_DEBUG:
            trace_level_prefix = SCOSSL_LOG_LEVEL_PREFIX_DEBUG;
        default:
            break;
    }
    if( func == NULL )
    {
        func = "";
    }
    if( format == NULL )
    {
        format = "";
    }
    if( vsnprintf(paraBuf, sizeof(paraBuf), format, args) < 0 )
    {
        *paraBuf = '\0';
    }
    fp = _open_trace_log_filename();
    fprintf(fp, "[%s] %s: %s\n", trace_level_prefix, func, paraBuf);
    _close_trace_log_filename(fp);
    return;
}

void _scossl_log_bytes(
    int trace_level,
    const char *func,
    char *description,
    const char *s,
    int len)
{
    if( _traceLogLevel < trace_level )
    {
        return;
    }
    FILE *fp = NULL;
    _scossl_log(trace_level, func, description);
    fp = _open_trace_log_filename();
    BIO_dump_fp(fp, s, len);
    _close_trace_log_filename(fp);
    return;
}

void _scossl_log_bignum(
    int trace_level,
    const char *func,
    char *description,
    BIGNUM *bn)
{
    unsigned char *string = NULL;
    int length = 0;

    if( _traceLogLevel < trace_level )
    {
        return;
    }

    if( bn == NULL )
    {
        return;
    }

    length = BN_num_bytes(bn);
    if( length < 0 )
    {
        return;
    }

    string = (unsigned char *)OPENSSL_zalloc(length);
    if( string == NULL )
    {
        return;
    }

    if( BN_bn2bin(bn, string) < 0 )
    {
        return;
    }

    _scossl_log_bytes(trace_level, func, description, (const char*) string, length);
    OPENSSL_free(string);
    return;
}

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    const char *func,
    char *description,
    SYMCRYPT_ERROR scError)
{
    switch( scError  )
    {
        case SYMCRYPT_NO_ERROR:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_NO_ERROR (0x%x)", description, scError);
            break;
        case SYMCRYPT_UNUSED:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_UNUSED (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_KEY_SIZE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_KEY_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_BLOCK_SIZE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_BLOCK_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_DATA_SIZE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_DATA_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_NONCE_SIZE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_NONCE_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_TAG_SIZE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_TAG_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_ITERATION_COUNT:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_WRONG_ITERATION_COUNT (0x%x)", description, scError);
            break;
        case SYMCRYPT_AUTHENTICATION_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_AUTHENTICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_EXTERNAL_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_EXTERNAL_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_FIPS_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_FIPS_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_HARDWARE_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_HARDWARE_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_NOT_IMPLEMENTED:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_NOT_IMPLEMENTED (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_BLOB:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_INVALID_BLOB (0x%x)", description, scError);
            break;
        case SYMCRYPT_BUFFER_TOO_SMALL:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_BUFFER_TOO_SMALL (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_ARGUMENT:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_INVALID_ARGUMENT (0x%x)", description, scError);
            break;
        case SYMCRYPT_MEMORY_ALLOCATION_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_MEMORY_ALLOCATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_INCOMPATIBLE_FORMAT:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_INCOMPATIBLE_FORMAT (0x%x)", description, scError);
            break;
        case SYMCRYPT_VALUE_TOO_LARGE:
            _scossl_log(trace_level, func, "%s - SYMCRYPT_VALUE_TOO_LARGE (0x%x)", description, scError);
            break;
        default:
            _scossl_log(trace_level, func, "%s - UNKNOWN SYMCRYPT_ERROR (0x%x)", description, scError);
            break;
    }
}

#ifdef __cplusplus
}
#endif
