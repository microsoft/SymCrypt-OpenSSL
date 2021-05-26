//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt_helpers.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYMCRYPT_ENGINE_TRACELOG_PARA_LENGTH        256

#define     SYMCRYPT_LOG_LEVEL_PREFIX_ERROR     "ERROR"
#define     SYMCRYPT_LOG_LEVEL_PREFIX_INFO      "INFO"
#define     SYMCRYPT_LOG_LEVEL_PREFIX_DEBUG     "DEBUG"


static int _traceLogLevel = SYMCRYPT_LOG_LEVEL_INFO;
static char *_traceLogFilename = NULL;

void SYMCRYPT_ENGINE_set_trace_level(int trace_level)
{
    if (trace_level >= SYMCRYPT_LOG_LEVEL_OFF &&
        trace_level <= SYMCRYPT_LOG_LEVEL_DEBUG)
    {
        _traceLogLevel = trace_level;
    }
    return;
}

void SYMCRYPT_ENGINE_set_trace_log_filename(const char *filename)
{
    if (_traceLogFilename)
        OPENSSL_free(_traceLogFilename);
    _traceLogFilename = OPENSSL_strdup(filename);
    return;
}

static FILE *_open_trace_log_filename()
{
    FILE *fp = stdout;

    if (_traceLogFilename != NULL) {
        fp = fopen(_traceLogFilename, "a");
        if (fp == NULL) {
            fp = stdout;
        }
    }
    return fp;
}

static void _close_trace_log_filename(FILE *fp)
{
    if (fp != stdout) {
        fflush(fp);
        fclose(fp);
    }
    return;
}

void _SYMCRYPT_log(
    int trace_level,
    const char *func,
    const char *format, ...)
{
    char paraBuf[SYMCRYPT_ENGINE_TRACELOG_PARA_LENGTH];
    FILE *fp = NULL;
    va_list args;
    va_start(args, format);
    char *trace_level_prefix = "";

    if (_traceLogLevel < trace_level) {
        return;
    }

    switch(trace_level)
    {
        case SYMCRYPT_LOG_LEVEL_ERROR:
            trace_level_prefix = SYMCRYPT_LOG_LEVEL_PREFIX_ERROR;
        case SYMCRYPT_LOG_LEVEL_INFO:
            trace_level_prefix = SYMCRYPT_LOG_LEVEL_PREFIX_INFO;
            break;
        case SYMCRYPT_LOG_LEVEL_DEBUG:
            trace_level_prefix = SYMCRYPT_LOG_LEVEL_PREFIX_DEBUG;
        default:
            break;
    }
    if (func == NULL) { func = ""; }
    if (format == NULL) { format = ""; }
    if (vsnprintf(paraBuf, sizeof(paraBuf), format, args) < 0) {
        *paraBuf = '\0';
    }
    fp = _open_trace_log_filename();
    fprintf(fp, "[%s] %s: %s\n", trace_level_prefix, func, paraBuf);
    _close_trace_log_filename(fp);
    return;
}

void _SYMCRYPT_log_bytes(
    int trace_level,
    const char *func,
    char *description,
    const char *s,
    int len)
{
    if (_traceLogLevel < trace_level) {
        return;
    }
    FILE *fp = NULL;
    _SYMCRYPT_log(trace_level, func, description);
    fp = _open_trace_log_filename();
    BIO_dump_fp(fp, s, len);
    _close_trace_log_filename(fp);
    return;
}

void _SYMCRYPT_log_bignum(
    int trace_level,
    const char *func,
    char *description,
    BIGNUM *bn)
{
    unsigned char *string = NULL;
    int length = 0;
    FILE *fp = NULL;

    if (_traceLogLevel < trace_level) {
        return;
    }

    if (bn == NULL) {
        return;
    }

    length = BN_num_bytes(bn);
    if (length < 0) {
        return;
    }

    string = (unsigned char *)OPENSSL_zalloc(length);
    if (string == NULL) {
        return;
    }

    if (BN_bn2bin(bn, string) < 0) {
        return;
    }

    _SYMCRYPT_log_bytes(trace_level, func, description, (const char*) string, length);
    OPENSSL_free(string);
    return;
}

#ifdef __cplusplus
}
#endif
