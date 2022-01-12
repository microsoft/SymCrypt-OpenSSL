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

void SCOSSL_ENGINE_setup_ERR()
{
    if( _scossl_err_library_code == 0 )
    {
        _scossl_err_library_code = ERR_get_next_error_library();

        // Bind the library name "SCOSSL" to the library code
        SCOSSL_ERR_library_string[0].error = ERR_PACK(_scossl_err_library_code, 0, 0);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_library_string);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_function_strings);
        ERR_load_strings(_scossl_err_library_code, SCOSSL_ERR_reason_strings);
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
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    const char *format, ...)
{
    char errStringBuf[SCOSSL_ENGINE_TRACELOG_PARA_LENGTH];
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
    if( format == NULL )
    {
        format = "";
    }
    if( vsnprintf(paraBuf, sizeof(paraBuf), format, args) < 0 )
    {
        *paraBuf = '\0';
    }

    // Log an OpenSSL error, so calling applications can handle the log appropriately
    ERR_put_error(_scossl_err_library_code, func_code, reason_code, file, line);
    // Add error string indicating the error details as error data
    ERR_add_error_data(1, paraBuf);

    // Log details to stderr or a log file
    ERR_error_string_n(ERR_PACK(_scossl_err_library_code, func_code, reason_code), errStringBuf, sizeof(errStringBuf));

    fp = _open_trace_log_filename();
    fprintf(fp, "[%s] %s:%s at %s, line %d\n", trace_level_prefix, errStringBuf, paraBuf, file, line);
    _close_trace_log_filename(fp);

    return;
}

void _scossl_log_bytes(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
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
    _scossl_log(trace_level, func_code, reason_code, file, line, description);
    fp = _open_trace_log_filename();
    BIO_dump_fp(fp, s, len);
    _close_trace_log_filename(fp);
    return;
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

    _scossl_log_bytes(trace_level, func_code, reason_code, file, line, description, (const char*) string, length);
    OPENSSL_free(string);
    return;
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
    switch( scError  )
    {
        case SYMCRYPT_NO_ERROR:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_NO_ERROR (0x%x)", description, scError);
            break;
        case SYMCRYPT_UNUSED:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_UNUSED (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_KEY_SIZE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_KEY_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_BLOCK_SIZE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_BLOCK_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_DATA_SIZE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_DATA_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_NONCE_SIZE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_NONCE_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_TAG_SIZE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_TAG_SIZE (0x%x)", description, scError);
            break;
        case SYMCRYPT_WRONG_ITERATION_COUNT:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_WRONG_ITERATION_COUNT (0x%x)", description, scError);
            break;
        case SYMCRYPT_AUTHENTICATION_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_AUTHENTICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_EXTERNAL_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_EXTERNAL_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_FIPS_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_FIPS_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_HARDWARE_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_HARDWARE_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_NOT_IMPLEMENTED:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_NOT_IMPLEMENTED (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_BLOB:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_INVALID_BLOB (0x%x)", description, scError);
            break;
        case SYMCRYPT_BUFFER_TOO_SMALL:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_BUFFER_TOO_SMALL (0x%x)", description, scError);
            break;
        case SYMCRYPT_INVALID_ARGUMENT:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_INVALID_ARGUMENT (0x%x)", description, scError);
            break;
        case SYMCRYPT_MEMORY_ALLOCATION_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_MEMORY_ALLOCATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE (0x%x)", description, scError);
            break;
        case SYMCRYPT_INCOMPATIBLE_FORMAT:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_INCOMPATIBLE_FORMAT (0x%x)", description, scError);
            break;
        case SYMCRYPT_VALUE_TOO_LARGE:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - SYMCRYPT_VALUE_TOO_LARGE (0x%x)", description, scError);
            break;
        default:
            _scossl_log(trace_level, func_code, reason_code, file, line, "%s - UNKNOWN SYMCRYPT_ERROR (0x%x)", description, scError);
            break;
    }
}

#ifdef __cplusplus
}
#endif
