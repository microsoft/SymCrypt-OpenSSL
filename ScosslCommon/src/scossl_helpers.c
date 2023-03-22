//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/err.h>
#include <openssl/crypto.h>
#include "scossl_helpers.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_TRACELOG_PARA_LENGTH  (256)

#define SCOSSL_LOG_LEVEL_PREFIX_ERROR       "ERROR"
#define SCOSSL_LOG_LEVEL_PREFIX_INFO        "INFO"
#define SCOSSL_LOG_LEVEL_PREFIX_DEBUG       "DEBUG"

// Level of tracing that is output to stderr / log file
static int _traceLogLevel = SCOSSL_LOG_LEVEL_INFO;
static char *_traceLogFilename = NULL;
static FILE *_traceLogFile = NULL;

// Level of tracing that is output to OpenSSL ERR infrastructure
// By default only log actual errors, as some OpenSSL unit tests check that successful calls do not
// generate any ERR entries. Callers may wish to set this to SCOSSL_LOG_LEVEL_INFO to expose data
// about where they may not be calling FIPS certified code.
static int _osslERRLogLevel = SCOSSL_LOG_LEVEL_ERROR;

// Lock around writing information to stderr/log file/OpenSSL ERR handling framework to avoid
// muddled error messages in multi-threaded environment
static CRYPTO_RWLOCK *_loggingLock;

static int _scossl_err_library_code = 0;

static ERR_STRING_DATA SCOSSL_ERR_library_string[] = {
    {0, "SCOSSL"},  // library name
    {0, NULL}
};

static ERR_STRING_DATA SCOSSL_ERR_function_strings[] = {
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_CIPHER, 0), "scossl_aes_ccm_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_CTRL, 0), "scossl_aes_ccm_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_TLS, 0), "scossl_aes_ccm_tls"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_CTRL, 0), "scossl_aes_gcm_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_TLS, 0), "scossl_aes_gcm_tls"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_XTS_CIPHER, 0), "scossl_aes_xts_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_XTS_CTRL, 0), "scossl_aes_xts_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_COMPUTE_KEY, 0), "scossl_dh_compute_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_GENERATE_KEY, 0), "scossl_dh_generate_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, 0), "scossl_dh_generate_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, 0), "scossl_dh_import_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_DIGESTS, 0), "scossl_digests"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECC_GENERATE_KEYPAIR, 0), "scossl_ecc_generate_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECC_IMPORT_KEYPAIR, 0), "scossl_ecc_import_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_APPLY_DER, 0), "scossl_ecdsa_apply_der"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, 0), "scossl_ecdsa_der_check_tag_and_get_value_and_length"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_REMOVE_DER, 0), "scossl_ecdsa_remove_der"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_COMPUTE_KEY, 0), "scossl_eckey_compute_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_KEYGEN, 0), "scossl_eckey_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_SIGN, 0), "scossl_eckey_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_SIGN_SETUP, 0), "scossl_eckey_sign_setup"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_SIGN_SIG, 0), "scossl_eckey_sign_sig"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_VERIFY, 0), "scossl_eckey_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECKEY_VERIFY_SIG, 0), "scossl_eckey_verify_sig"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_DH_CONTEXT_EX, 0), "scossl_get_dh_context_ex"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_ECC_CONTEXT_EX, 0), "scossl_get_ecc_context_ex"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, 0), "scossl_get_symcrypt_hash_algorithm"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM, 0), "scossl_get_symcrypt_mac_algorithm"},
    {ERR_PACK(0, SCOSSL_ERR_F_HKDF_CTRL, 0), "scossl_hkdf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_HKDF_DERIVE, 0), "scossl_hkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_HKDF_INIT, 0), "scossl_hkdf_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_INITIALIZE_RSA_KEY, 0), "scossl_initialize_rsa_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_PKEY_METHODS, 0), "scossl_pkey_methods"},
    {ERR_PACK(0, SCOSSL_ERR_F_PKEY_RSA_SIGN, 0), "scossl_pkey_rsa_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_PKEY_RSA_VERIFY, 0), "scossl_pkey_rsa_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_INIT, 0), "scossl_rsa_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_KEYGEN, 0), "scossl_rsa_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PRIV_DEC, 0), "scossl_rsa_priv_dec"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PRIV_ENC, 0), "scossl_rsa_priv_enc"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PUB_DEC, 0), "scossl_rsa_pub_dec"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PUB_ENC, 0), "scossl_rsa_pub_enc"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_SIGN, 0), "scossl_rsa_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_VERIFY, 0), "scossl_rsa_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSAPSS_SIGN, 0), "scossl_rsapss_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSAPSS_VERIFY, 0), "scossl_rsapss_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_TLS1PRF_CTRL, 0), "scossl_tls1prf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_TLS1PRF_DERIVE, 0), "scossl_tls1prf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_TLS1PRF_INIT, 0), "scossl_tls1prf_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_HMAC_INIT, 0), "scossl_hmac_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_HMAC_CTRL, 0), "scossl_hmac_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_HMAC_CTRL_STR, 0), "scossl_hmac_ctrl_str"},
    {ERR_PACK(0, SCOSSL_ERR_F_SSHKDF_NEW, 0), "scossl_sshkdf_new"},
    {ERR_PACK(0, SCOSSL_ERR_F_SSHKDF_CTRL, 0), "scossl_sshkdf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_SSHKDF_CTRL_STR, 0), "scossl_sshkdf_ctrl_str"},
    {ERR_PACK(0, SCOSSL_ERR_F_SSHKDF_DERIVE, 0), "scossl_sshkdf_derive"},
    {0, NULL}
};

C_ASSERT( (sizeof(SCOSSL_ERR_function_strings) / sizeof(ERR_STRING_DATA)) == SCOSSL_ERR_F_ENUM_END-SCOSSL_ERR_F_ENUM_START );


static ERR_STRING_DATA SCOSSL_ERR_reason_strings[] = {
    {ERR_PACK(0, 0, SCOSSL_ERR_R_MISSING_CTX_DATA), "Missing data in context"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_NOT_IMPLEMENTED), "Algorithm not supported by SCOSSL"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM), "Algorithm not FIPS certifiable"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_OPENSSL_FALLBACK), "SCOSSL falling back to OpenSSL"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_SYMCRYPT_FAILURE), "SCOSSL triggered SymCrypt failure"},
    {0, NULL}
};

C_ASSERT( (sizeof(SCOSSL_ERR_reason_strings) / sizeof(ERR_STRING_DATA)) == SCOSSL_ERR_R_ENUM_END-SCOSSL_ERR_R_ENUM_START );

void scossl_setup_logging()
{
    if( _scossl_err_library_code == 0 )
    {
        _scossl_err_library_code = ERR_get_next_error_library();

        // Bind the library name "SCOSSL" to the library code
        SCOSSL_ERR_library_string[0].error = ERR_PACK(_scossl_err_library_code, 0, 0);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_library_string);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_function_strings);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_reason_strings);

        _loggingLock = CRYPTO_THREAD_lock_new();
        SCOSSL_set_trace_log_filename(NULL);
    }
}

void scossl_destroy_logging()
{
    CRYPTO_THREAD_lock_free(_loggingLock);
}

void SCOSSL_set_trace_level(int trace_level, int ossl_ERR_level)
{
    if( trace_level >= SCOSSL_LOG_LEVEL_OFF &&
        trace_level <= SCOSSL_LOG_LEVEL_DEBUG )
    {
        _traceLogLevel = trace_level;
    }
    if( ossl_ERR_level >= SCOSSL_LOG_LEVEL_OFF &&
        ossl_ERR_level <= SCOSSL_LOG_LEVEL_DEBUG )
    {
        _osslERRLogLevel = ossl_ERR_level;
    }
}

void SCOSSL_set_trace_log_filename(const char *filename)
{
    if( _traceLogFilename )
    {
        OPENSSL_free(_traceLogFilename);
    }
    _traceLogFilename = OPENSSL_strdup(filename);

    if( CRYPTO_THREAD_write_lock(_loggingLock) )
    {
        if( _traceLogFile != NULL && _traceLogFile != stderr )
        {
            fflush(_traceLogFile);
            fclose(_traceLogFile);
            _traceLogFile = NULL;
        }
        if( _traceLogFilename != NULL )
        {
            _traceLogFile = fopen(_traceLogFilename, "a");
        }
        if( _traceLogFile == NULL )
        {
            _traceLogFile = stderr;
        }
    }
    CRYPTO_THREAD_unlock(_loggingLock);
    return;
}

static void _scossl_log_bytes_valist(
    int trace_level,
    ossl_unused SCOSSL_ERR_FUNC func_code, // unused in openssl 3
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    const char *s,
    int len,
    const char *format,
    va_list args)
{
    char errStringBuf[SCOSSL_TRACELOG_PARA_LENGTH];
    char paraBuf[SCOSSL_TRACELOG_PARA_LENGTH];
    char *trace_level_prefix = "";

    if( SYMCRYPT_MAX(_traceLogLevel, _osslERRLogLevel) < trace_level )
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
    if( format == NULL )
    {
        format = "";
    }
    if( vsnprintf(paraBuf, sizeof(paraBuf), format, args) < 0 )
    {
        *paraBuf = '\0';
    }

    if( CRYPTO_THREAD_write_lock(_loggingLock) )
    {
        if( _osslERRLogLevel >= trace_level )
        {
            // Log an OpenSSL error, so calling applications can handle the log appropriately
            ERR_put_error(_scossl_err_library_code, func_code, reason_code, file, line);
            // Add error string indicating the error details as error data
            ERR_add_error_data(1, paraBuf);
        }

        if( _traceLogLevel >= trace_level )
        {
            // Log details to stderr or a log file
            ERR_error_string_n(ERR_PACK(_scossl_err_library_code, func_code, reason_code), errStringBuf, sizeof(errStringBuf));

            fprintf(_traceLogFile, "[%s] %s:%s at %s, line %d\n", trace_level_prefix, errStringBuf, paraBuf, file, line);
            if( s )
            {
                fwrite(s, 1, len, _traceLogFile);
            }
        }
    }
    CRYPTO_THREAD_unlock(_loggingLock);
}

void _scossl_log_bytes(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    const char *s,
    int len,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    _scossl_log_bytes_valist(trace_level, func_code, reason_code, file, line, s, len, format, args);
    va_end(args);
}

void _scossl_log(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    _scossl_log_bytes_valist(trace_level, func_code, reason_code, file, line, NULL, 0, format, args);
    va_end(args);
}

void _scossl_log_bignum(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    char *description,
    BIGNUM *bn)
{
    unsigned char *string = NULL;
    int length = 0;

    if( SYMCRYPT_MAX(_traceLogLevel, _osslERRLogLevel) < trace_level )
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

    _scossl_log_bytes(trace_level, func_code, reason_code, file, line, (const char*) string, length, description);
    OPENSSL_free(string);
}

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    char *description,
    SYMCRYPT_ERROR scError)
{
    const char* scErrorString;

    switch( scError )
    {
        case SYMCRYPT_NO_ERROR:
            scErrorString = "SYMCRYPT_NO_ERROR";
            break;
        case SYMCRYPT_WRONG_KEY_SIZE:
            scErrorString = "SYMCRYPT_WRONG_KEY_SIZE";
            break;
        case SYMCRYPT_WRONG_BLOCK_SIZE:
            scErrorString = "SYMCRYPT_WRONG_BLOCK_SIZE";
            break;
        case SYMCRYPT_WRONG_DATA_SIZE:
            scErrorString = "SYMCRYPT_WRONG_DATA_SIZE";
            break;
        case SYMCRYPT_WRONG_NONCE_SIZE:
            scErrorString = "SYMCRYPT_WRONG_NONCE_SIZE";
            break;
        case SYMCRYPT_WRONG_TAG_SIZE:
            scErrorString = "SYMCRYPT_WRONG_TAG_SIZE";
            break;
        case SYMCRYPT_WRONG_ITERATION_COUNT:
            scErrorString = "SYMCRYPT_WRONG_ITERATION_COUNT";
            break;
        case SYMCRYPT_AUTHENTICATION_FAILURE:
            scErrorString = "SYMCRYPT_AUTHENTICATION_FAILURE";
            break;
        case SYMCRYPT_EXTERNAL_FAILURE:
            scErrorString = "SYMCRYPT_EXTERNAL_FAILURE";
            break;
        case SYMCRYPT_FIPS_FAILURE:
            scErrorString = "SYMCRYPT_FIPS_FAILURE";
            break;
        case SYMCRYPT_HARDWARE_FAILURE:
            scErrorString = "SYMCRYPT_HARDWARE_FAILURE";
            break;
        case SYMCRYPT_NOT_IMPLEMENTED:
            scErrorString = "SYMCRYPT_NOT_IMPLEMENTED";
            break;
        case SYMCRYPT_INVALID_BLOB:
            scErrorString = "SYMCRYPT_INVALID_BLOB";
            break;
        case SYMCRYPT_BUFFER_TOO_SMALL:
            scErrorString = "SYMCRYPT_BUFFER_TOO_SMALL";
            break;
        case SYMCRYPT_INVALID_ARGUMENT:
            scErrorString = "SYMCRYPT_INVALID_ARGUMENT";
            break;
        case SYMCRYPT_MEMORY_ALLOCATION_FAILURE:
            scErrorString = "SYMCRYPT_MEMORY_ALLOCATION_FAILURE";
            break;
        case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
            scErrorString = "SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE";
            break;
        case SYMCRYPT_INCOMPATIBLE_FORMAT:
            scErrorString = "SYMCRYPT_INCOMPATIBLE_FORMAT";
            break;
        case SYMCRYPT_VALUE_TOO_LARGE:
            scErrorString = "SYMCRYPT_VALUE_TOO_LARGE";
            break;
        default:
            scErrorString = "UNKNOWN SYMCRYPT_ERROR";
            break;
    }
    _scossl_log(trace_level, func_code, reason_code, file, line, "%s - %s (0x%x)", description, scErrorString, scError);
}

#ifdef __cplusplus
}
#endif
