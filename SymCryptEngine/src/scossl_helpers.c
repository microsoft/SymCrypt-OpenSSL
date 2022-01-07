//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/err.h>
#include "scossl_helpers.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_ENGINE_TRACELOG_PARA_LENGTH  (256)

#define SCOSSL_LOG_LEVEL_PREFIX_ERROR       "ERROR"
#define SCOSSL_LOG_LEVEL_PREFIX_INFO        "INFO"
#define SCOSSL_LOG_LEVEL_PREFIX_DEBUG       "DEBUG"

static int _traceLogLevel = SCOSSL_LOG_LEVEL_INFO;
static char *_traceLogFilename = NULL;

#define SCOSSL_ERR_UNKNOWN_FUNC_CODE        (1)
#define SCOSSL_ERR_UNKNOWN_REASON_CODE      (1)

static int _scossl_err_library_code = 0;

static ERR_STRING_DATA SCOSSL_ERR_strings[] = {
    {0,                                             "SCOSSL"},  // library name
    {ERR_PACK(0, SCOSSL_ERR_UNKNOWN_FUNC_CODE, 0),  ""},        // unknown function name
    {ERR_PACK(0, 0, SCOSSL_ERR_UNKNOWN_REASON_CODE),"Error"},   // unknown reason name
    {0, NULL}
};

void SCOSSL_ENGINE_setup_ERR()
{
    if( _scossl_err_library_code == 0 )
    {
        _scossl_err_library_code = ERR_get_next_error_library();

        // Bind the library name "SCOSSL" to the library code
        SCOSSL_ERR_strings[0].error = ERR_PACK(_scossl_err_library_code, 0, 0);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_strings);
    }
}

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
    const char *file,
    int line,
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
    fprintf(fp, "[%s] %s: %s at %s, line %d\n", trace_level_prefix, func, paraBuf, file, line);
    _close_trace_log_filename(fp);

    // Also log an OpenSSL error for errors, so calling applications can handle them appropriately
    if( trace_level == SCOSSL_LOG_LEVEL_ERROR )
    {
        ERR_PUT_error(_scossl_err_library_code, SCOSSL_ERR_UNKNOWN_FUNC_CODE, SCOSSL_ERR_UNKNOWN_REASON_CODE, file, line);

        // Add error strings indicating the function and the error details as error data, rather
        // than explicitly specifying all functions and error reasons ahead of time
        ERR_add_error_data(3, func, ":", paraBuf);
    }
    return;
}

void _scossl_log_bytes(
    int trace_level,
    const char *func,
    const char *file,
    int line,
    char *description,
    const char *s,
    int len)
{
    if( _traceLogLevel < trace_level )
    {
        return;
    }
    FILE *fp = NULL;
    _scossl_log(trace_level, func, file, line, description);
    fp = _open_trace_log_filename();
    BIO_dump_fp(fp, s, len);
    _close_trace_log_filename(fp);
    return;
}

void _scossl_log_bignum(
    int trace_level,
    const char *func,
    const char *file,
    int line,
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

    _scossl_log_bytes(trace_level, func, file, line, description, (const char*) string, length);
    OPENSSL_free(string);
    return;
}

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    const char *func,
    const char *file,
    int line,
    char *description,
    SYMCRYPT_ERROR scError)
{
    switch( scError  )
    {
        case SYMCRYPT_NO_ERROR:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_NO_ERROR (0x%x)", description, scError);
            break;
        case SYMCRYPT_UNUSED:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_UNUSED (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_KEY_SIZE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_KEY_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_BLOCK_SIZE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_BLOCK_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_DATA_SIZE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_DATA_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_NONCE_SIZE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_NONCE_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_TAG_SIZE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_TAG_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_ITERATION_COUNT:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_WRONG_ITERATION_COUNT (0x%x)", description, scError);
            break;
        case SYMCRYPT_AUTHENTICATION_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_AUTHENTICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_EXTERNAL_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_EXTERNAL_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_FIPS_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_FIPS_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_HARDWARE_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_HARDWARE_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_NOT_IMPLEMENTED:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_NOT_IMPLEMENTED (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_BLOB:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_INVALID_BLOB (0x%x)", description, scError);
            break;
        case SYMCRYPT_BUFFER_TOO_SMALL:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_BUFFER_TOO_SMALL (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_ARGUMENT:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_INVALID_ARGUMENT (0x%x)", description, scError);
            break;
        case SYMCRYPT_MEMORY_ALLOCATION_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_MEMORY_ALLOCATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_INCOMPATIBLE_FORMAT:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_INCOMPATIBLE_FORMAT (0x%x)", description, scError);
            break;
        case SYMCRYPT_VALUE_TOO_LARGE:
            _scossl_log(trace_level, func, file, line, "%s - SYMCRYPT_VALUE_TOO_LARGE (0x%x)", description, scError);
            break;
        default:
            _scossl_log(trace_level, func, file, line, "%s - UNKNOWN SYMCRYPT_ERROR (0x%x)", description, scError);
            break;
    }
}

#ifdef __cplusplus
}
#endif
