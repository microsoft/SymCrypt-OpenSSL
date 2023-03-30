//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include <symcrypt.h>
#include <string.h>

#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int SCOSSL_STATUS;
typedef _Return_type_success_(return >= 0) int SCOSSL_RETURNLENGTH; // For functions that return length on success and -1 on error

// Macros giving readable name to return values in functions returning SCOSSL_STATUS
// Note: In some cases return values indicating other specific error conditions may be used
#define SCOSSL_SUCCESS  (1)
#define SCOSSL_FAILURE  (0)
#define SCOSSL_FALLBACK (-1)
// Only applies in certain contexts (used when implementing EVP-layer functionality)
#define SCOSSL_UNSUPPORTED (-2)

#define SCOSSL_LOG_LEVEL_NO_CHANGE  (-1)
#define SCOSSL_LOG_LEVEL_OFF        (0)
#define SCOSSL_LOG_LEVEL_ERROR      (1) // DEFAULT for OpenSSL ERR
#define SCOSSL_LOG_LEVEL_INFO       (2) // DEFAULT for stderr / logging to logfile
#define SCOSSL_LOG_LEVEL_DEBUG      (3)

void SCOSSL_set_trace_level(int trace_level, int ossl_ERR_level);
void SCOSSL_set_trace_log_filename(const char *filename);

// Functions to set up and destroy SCOSSL logging static variables, locks, and integration with
// OpenSSL ERR infrastructure. Should only be called in Engine bind / destroy.
void scossl_setup_logging();
void scossl_destroy_logging();

// SCOSSL function codes
typedef enum {
    SCOSSL_ERR_F_ENUM_START= 100,
    SCOSSL_ERR_F_AES_CCM_CIPHER,
    SCOSSL_ERR_F_AES_CCM_CTRL,
    SCOSSL_ERR_F_AES_CCM_TLS,
    SCOSSL_ERR_F_AES_GCM_CTRL,
    SCOSSL_ERR_F_AES_GCM_TLS,
    SCOSSL_ERR_F_AES_XTS_CIPHER,
    SCOSSL_ERR_F_AES_XTS_CTRL,
    SCOSSL_ERR_F_DH_COMPUTE_KEY,
    SCOSSL_ERR_F_DH_GENERATE_KEY,
    SCOSSL_ERR_F_DH_GENERATE_KEYPAIR,
    SCOSSL_ERR_F_DH_IMPORT_KEYPAIR,
    SCOSSL_ERR_F_DIGESTS,
    SCOSSL_ERR_F_ECC_GENERATE_KEYPAIR,
    SCOSSL_ERR_F_ECC_IMPORT_KEYPAIR,
    SCOSSL_ERR_F_ECDSA_APPLY_DER,
    SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH,
    SCOSSL_ERR_F_ECDSA_REMOVE_DER,
    SCOSSL_ERR_F_ECKEY_COMPUTE_KEY,
    SCOSSL_ERR_F_ECKEY_KEYGEN,
    SCOSSL_ERR_F_ECKEY_SIGN,
    SCOSSL_ERR_F_ECKEY_SIGN_SETUP,
    SCOSSL_ERR_F_ECKEY_SIGN_SIG,
    SCOSSL_ERR_F_ECKEY_VERIFY,
    SCOSSL_ERR_F_ECKEY_VERIFY_SIG,
    SCOSSL_ERR_F_GET_DH_CONTEXT_EX,
    SCOSSL_ERR_F_GET_ECC_CONTEXT_EX,
    SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM,
    SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM,
    SCOSSL_ERR_F_HKDF_CTRL,
    SCOSSL_ERR_F_HKDF_DERIVE,
    SCOSSL_ERR_F_HKDF_INIT,
    SCOSSL_ERR_F_INITIALIZE_RSA_KEY,
    SCOSSL_ERR_F_PKEY_METHODS,
    SCOSSL_ERR_F_PKEY_RSA_SIGN,
    SCOSSL_ERR_F_PKEY_RSA_VERIFY,
    SCOSSL_ERR_F_RSA_INIT,
    SCOSSL_ERR_F_RSA_KEYGEN,
    SCOSSL_ERR_F_RSA_PRIV_DEC,
    SCOSSL_ERR_F_RSA_PRIV_ENC,
    SCOSSL_ERR_F_RSA_PUB_DEC,
    SCOSSL_ERR_F_RSA_PUB_ENC,
    SCOSSL_ERR_F_RSA_SIGN,
    SCOSSL_ERR_F_RSA_VERIFY,
    SCOSSL_ERR_F_RSAPSS_SIGN,
    SCOSSL_ERR_F_RSAPSS_VERIFY,
    SCOSSL_ERR_F_TLS1PRF_CTRL,
    SCOSSL_ERR_F_TLS1PRF_DERIVE,
    SCOSSL_ERR_F_TLS1PRF_INIT,
    SCOSSL_ERR_F_HMAC_INIT,
    SCOSSL_ERR_F_HMAC_CTRL,
    SCOSSL_ERR_F_HMAC_CTRL_STR,
    SCOSSL_ERR_F_SSHKDF_NEW,
    SCOSSL_ERR_F_SSHKDF_CTRL,
    SCOSSL_ERR_F_SSHKDF_CTRL_STR,
    SCOSSL_ERR_F_SSHKDF_DERIVE,
    SCOSSL_ERR_F_ENUM_END
} SCOSSL_ERR_FUNC;

// SCOSSL reason codes
typedef enum {
    SCOSSL_ERR_R_ENUM_START = 100,
    SCOSSL_ERR_R_MISSING_CTX_DATA,
    SCOSSL_ERR_R_NOT_IMPLEMENTED,
    SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
    SCOSSL_ERR_R_OPENSSL_FALLBACK,
    SCOSSL_ERR_R_SYMCRYPT_FAILURE,
    SCOSSL_ERR_R_ENUM_END
} SCOSSL_ERR_REASON;

void _scossl_log(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code, // can also accept generic ERR_R_* values specified by OpenSSL
    const char *file,
    int line,
    const char *format, ...);

void _scossl_log_bytes(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    const char *s,
    int len,
    const char *format, ...);

void _scossl_log_bignum(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    char *description,
    BIGNUM *bn);

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
    SCOSSL_ERR_REASON reason_code,
    const char *file,
    int line,
    char *description,
    SYMCRYPT_ERROR scError);

// Enable debug and info messages in debug builds, but compile them out in release builds
#if DBG
    #define SCOSSL_LOG_DEBUG(func_code, reason_code, ...) \
        _scossl_log(SCOSSL_LOG_LEVEL_DEBUG, func_code, reason_code, __FILE__, __LINE__, __VA_ARGS__)

    #define SCOSSL_LOG_INFO(func_code, reason_code, ...) \
        _scossl_log(SCOSSL_LOG_LEVEL_INFO, func_code, reason_code, __FILE__, __LINE__, __VA_ARGS__)

    #define SCOSSL_LOG_BYTES_DEBUG(func_code, reason_code, description, s, len) \
        _scossl_log_bytes(SCOSSL_LOG_LEVEL_DEBUG, func_code, reason_code, __FILE__, __LINE__, (const char*) s, len, description)

    #define SCOSSL_LOG_BYTES_INFO(func_code, reason_code, description, s, len) \
        _scossl_log_bytes(SCOSSL_LOG_LEVEL_INFO, func_code, reason_code, __FILE__, __LINE__, (const char*) s, len, description)

    #define SCOSSL_LOG_BIGNUM_DEBUG(func_code, reason_code, description, bn) \
        _scossl_log_bignum(SCOSSL_LOG_LEVEL_DEBUG, func_code, reason_code, __FILE__, __LINE__, description, bn)

    #define SCOSSL_LOG_BIGNUM_INFO(func_code, reason_code, description, s, len) \
        _scossl_log_bignum(SCOSSL_LOG_LEVEL_INFO, func_code, reason_code, __FILE__, __LINE__, description, bn)

    #define SCOSSL_LOG_SYMCRYPT_DEBUG(func_code, reason_code, description, scError) \
        _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_DEBUG, func_code, reason_code, __FILE__, __LINE__, description, scError)

    #define SCOSSL_LOG_SYMCRYPT_INFO(func_code, reason_code, description, scError) \
        _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_INFO, func_code, reason_code, __FILE__, __LINE__, description, scError)
#else
    #define SCOSSL_LOG_DEBUG(func_code, reason_code, ...)
    #define SCOSSL_LOG_INFO(func_code, reason_code, ...)
    #define SCOSSL_LOG_BYTES_DEBUG(func_code, reason_code, description, s, len)
    #define SCOSSL_LOG_BYTES_INFO(func_code, reason_code, description, s, len)
    #define SCOSSL_LOG_BIGNUM_DEBUG(func_code, reason_code, description, bn)
    #define SCOSSL_LOG_BIGNUM_INFO(func_code, reason_code, description, s, len)
    #define SCOSSL_LOG_SYMCRYPT_DEBUG(func_code, reason_code, description, scError)
    #define SCOSSL_LOG_SYMCRYPT_INFO(func_code, reason_code, description, scError)
#endif

#define SCOSSL_LOG_ERROR(func_code, reason_code, ...) \
    _scossl_log(SCOSSL_LOG_LEVEL_ERROR, func_code, reason_code, __FILE__, __LINE__, __VA_ARGS__)

#define SCOSSL_LOG_BYTES_ERROR(func_code, reason_code, description, s, len) \
    _scossl_log_bytes(SCOSSL_LOG_LEVEL_ERROR, func_code, reason_code, __FILE__, __LINE__, (const char*) s, len, description)

#define SCOSSL_LOG_BIGNUM_ERROR(func_code, reason_code, description, s, len) \
    _scossl_log_bignum(SCOSSL_LOG_LEVEL_ERROR, func_code, reason_code, __FILE__, __LINE__, description, bn)

#define SCOSSL_LOG_SYMCRYPT_ERROR(func_code, reason_code, description, scError) \
    _scossl_log_SYMCRYPT_ERROR(SCOSSL_LOG_LEVEL_ERROR, func_code, reason_code, __FILE__, __LINE__, description, scError)

#ifdef __cplusplus
}
#endif
