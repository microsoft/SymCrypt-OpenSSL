//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include <string.h>
#include <symcrypt.h>

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

// As a SymCrypt caller, when allocating SymCrypt objects we need to ensure these objects are aligned to SYMCRYPT_ALIGN_VALUE
//
// In the SCOSSL engine, we only have control over the size of an allocation, with OpenSSL doing the allocation / free for us.
// Here we just need to allocate (SYMCRYPT_ALIGN_VALUE-1) extra bytes, and round up the provided pointer to the nearest aligned
// pointer before using it with SymCrypt.
//
// In the SCOSSL provider, it is our responsibility to perform the allocation and free ourselves.
// Here we allocate SYMCRYPT_ALIGN_VALUE extra bytes, and store the offset into our allocation in the byte before the aligned 
// pointer we use in SymCrypt. On free, we look at the byte before the aligned pointer we have been using, to determine the start
// of the allocation and free it correctly.
//
// For simplicity, we just allocate 1 extra byte in the SCOSSL engine so we just need the following 2 macros.
#define SCOSSL_ALIGNED_SIZEOF(typename)         (sizeof(typename) + SYMCRYPT_ALIGN_VALUE)
#define SCOSSL_ALIGN_UP(ptr)                    (SYMCRYPT_ALIGN_UP(ptr))

// We need to be able to represent the offset into our allocation in a single byte
C_ASSERT( SYMCRYPT_ALIGN_VALUE < 256 );

#define SCOSSL_COMMON_ALIGNED_ALLOC_EX(ptr, allocator, typename, size)      \
    typename *ptr;                                                          \
    {                                                                       \
        PBYTE scossl_alloc = allocator(size + SYMCRYPT_ALIGN_VALUE);        \
        PBYTE scossl_aligned = NULL;                                        \
        if (scossl_alloc)                                                   \
        {                                                                   \
            scossl_aligned = SCOSSL_ALIGN_UP(scossl_alloc+1);               \
            *(scossl_aligned - 1) = scossl_aligned - scossl_alloc;          \
        }                                                                   \
        ptr = (typename *) scossl_aligned;                                  \
    }

#define SCOSSL_COMMON_ALIGNED_ALLOC(ptr, allocator, typename) \
    SCOSSL_COMMON_ALIGNED_ALLOC_EX(ptr, allocator, typename, sizeof(typename))

#define SCOSSL_COMMON_ALIGNED_FREE_EX(ptr, deallocator, size)       \
    {                                                               \
        PBYTE scossl_aligned = (PBYTE) ptr;                         \
        PBYTE scossl_alloc = scossl_aligned - *(scossl_aligned-1);  \
        deallocator(scossl_alloc, size + SYMCRYPT_ALIGN_VALUE);     \
        ptr = NULL;                                                 \
    }

#define SCOSSL_COMMON_ALIGNED_FREE(ptr, deallocator, typename)      \
    SCOSSL_COMMON_ALIGNED_FREE_EX(ptr, deallocator, sizeof(typename))

void SCOSSL_set_trace_level(int trace_level, int ossl_ERR_level);
void SCOSSL_set_trace_log_filename(const char *filename);

// Functions to set up and destroy SCOSSL logging static variables, locks, and integration with
// OpenSSL ERR infrastructure. Should only be called in Engine bind / destroy.
void scossl_setup_logging();
void scossl_destroy_logging();

// SCOSSL function codes
typedef enum {
    // ScosslCommon
    SCOSSL_ERR_F_ENUM_START= 100,
    SCOSSL_ERR_F_AES_CCM_CIPHER,
    SCOSSL_ERR_F_AES_CCM_SET_IV_FIXED,
    SCOSSL_ERR_F_AES_CCM_SET_IV_LEN,
    SCOSSL_ERR_F_AES_CCM_SET_TLS1_AAD,
    SCOSSL_ERR_F_AES_CCM_TLS,
    SCOSSL_ERR_F_AES_GCM_CIPHER,
    SCOSSL_ERR_F_AES_GCM_IV_GEN,
    SCOSSL_ERR_F_AES_GCM_SET_IV_FIXED,
    SCOSSL_ERR_F_AES_GCM_SET_IV_INV,
    SCOSSL_ERR_F_AES_GCM_SET_IV_LEN,
    SCOSSL_ERR_F_AES_GCM_SET_TLS1_AAD,
    SCOSSL_ERR_F_AES_GCM_TLS,
    SCOSSL_ERR_F_DH_GENERATE_KEYPAIR,
    SCOSSL_ERR_F_DH_GET_GROUP_BY_NID,
    SCOSSL_ERR_F_DH_IMPORT_KEYPAIR,
    SCOSSL_ERR_F_ECC_GROUP_TO_SYMCRYPT_CURVE,
    SCOSSL_ERR_F_ECC_POINT_TO_PUBKEY,
    SCOSSL_ERR_F_ECDSA_APPLY_DER,
    SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH,
    SCOSSL_ERR_F_ECDSA_REMOVE_DER,
    SCOSSL_ERR_F_ECDSA_SIGN,
    SCOSSL_ERR_F_ECDSA_VERIFY,
    SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM,
    SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM,
    SCOSSL_ERR_F_HKDF_DERIVE,
    SCOSSL_ERR_F_MAC_INIT,
    SCOSSL_ERR_F_MAC_SET_HMAC_MD,
    SCOSSL_ERR_F_RSA_DECRYPT,
    SCOSSL_ERR_F_RSA_ENCRYPT,
    SCOSSL_ERR_F_RSA_EXPORT_KEY,
    SCOSSL_ERR_F_RSA_NEW_EXPORT_PARAMS,
    SCOSSL_ERR_F_RSA_PKCS1_SIGN,
    SCOSSL_ERR_F_RSA_PKCS1_VERIFY,
    SCOSSL_ERR_F_RSAPSS_SIGN,
    SCOSSL_ERR_F_RSAPSS_VERIFY,
    SCOSSL_ERR_F_SSHKDF_DERIVE,
    SCOSSL_ERR_F_TLS1PRF_DERIVE,
    // SymCryptEngine
    SCOSSL_ERR_F_ENG_AES_CCM_CTRL,
    SCOSSL_ERR_F_ENG_AES_GCM_CTRL,
    SCOSSL_ERR_F_ENG_AES_XTS_CIPHER,
    SCOSSL_ERR_F_ENG_AES_XTS_CTRL,
    SCOSSL_ERR_F_ENG_DH_COMPUTE_KEY,
    SCOSSL_ERR_F_ENG_DH_GENERATE_KEY,
    SCOSSL_ERR_F_ENG_DH_GENERATE_KEYPAIR,
    SCOSSL_ERR_F_ENG_DH_IMPORT_KEYPAIR,
    SCOSSL_ERR_F_ENG_DIGESTS,
    SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR,
    SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR,
    SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY,
    SCOSSL_ERR_F_ENG_ECKEY_KEYGEN,
    SCOSSL_ERR_F_ENG_ECKEY_SIGN,
    SCOSSL_ERR_F_ENG_ECKEY_SIGN_SETUP,
    SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG,
    SCOSSL_ERR_F_ENG_ECKEY_VERIFY,
    SCOSSL_ERR_F_ENG_ECKEY_VERIFY_SIG,
    SCOSSL_ERR_F_ENG_GET_DH_CONTEXT_EX,
    SCOSSL_ERR_F_ENG_GET_ECC_CONTEXT_EX,
    SCOSSL_ERR_F_ENG_GET_SYMCRYPT_HASH_ALGORITHM,
    SCOSSL_ERR_F_ENG_HKDF_CTRL,
    SCOSSL_ERR_F_ENG_HKDF_DERIVE,
    SCOSSL_ERR_F_ENG_HKDF_INIT,
    SCOSSL_ERR_F_ENG_HMAC_COPY,
    SCOSSL_ERR_F_ENG_HMAC_CTRL,
    SCOSSL_ERR_F_ENG_HMAC_INIT,
    SCOSSL_ERR_F_ENG_INITIALIZE_RSA_KEY,
    SCOSSL_ERR_F_ENG_PKEY_METHODS,
    SCOSSL_ERR_F_ENG_PKEY_RSA_SIGN,
    SCOSSL_ERR_F_ENG_PKEY_RSA_VERIFY,
    SCOSSL_ERR_F_ENG_PKEY_RSAPSS_VERIFY,
    SCOSSL_ERR_F_ENG_RSA_INIT,
    SCOSSL_ERR_F_ENG_RSA_KEYGEN,
    SCOSSL_ERR_F_ENG_RSA_PRIV_DEC,
    SCOSSL_ERR_F_ENG_RSA_PRIV_ENC,
    SCOSSL_ERR_F_ENG_RSA_PUB_DEC,
    SCOSSL_ERR_F_ENG_RSA_PUB_ENC,
    SCOSSL_ERR_F_ENG_RSA_SIGN,
    SCOSSL_ERR_F_ENG_RSA_VERIFY,
    SCOSSL_ERR_F_ENG_RSAPSS_SIGN,
    SCOSSL_ERR_F_ENG_RSAPSS_VERIFY,
    SCOSSL_ERR_F_ENG_SSHKDF_CTRL,
    SCOSSL_ERR_F_ENG_SSHKDF_CTRL_STR,
    SCOSSL_ERR_F_ENG_SSHKDF_DERIVE,
    SCOSSL_ERR_F_ENG_SSHKDF_NEW,
    SCOSSL_ERR_F_ENG_TLS1PRF_CTRL,
    SCOSSL_ERR_F_ENG_TLS1PRF_INIT,
    // SymCryptProvider
    SCOSSL_ERR_F_PROV_AES_GENERIC_INIT_INTERNAL,
    SCOSSL_ERR_F_PROV_AES_XTS_INIT_INTERNAL,
    SCOSSL_ERR_F_PROV_DH_KEYMGMT_EXPORT,
    SCOSSL_ERR_F_PROV_DH_KEYMGMT_GET_FFC_PARAMS,
    SCOSSL_ERR_F_PROV_DH_KEYMGMT_GET_KEY_PARAMS,
    SCOSSL_ERR_F_PROV_DH_KEYMGMT_MATCH,
    SCOSSL_ERR_F_PROV_DH_KEYMGMT_SET_PARAMS,
    SCOSSL_ERR_F_PROV_DH_PARAMS_TO_GROUP,
    SCOSSL_ERR_F_PROV_DH_PLAIN_DERIVE,
    SCOSSL_ERR_F_PROV_DH_X9_42_DERIVE,
    SCOSSL_ERR_F_PROV_ECC_GET_ENCODED_PUBLIC_KEY,
    SCOSSL_ERR_F_PROV_ECC_INIT_KEYSINUSE,
    SCOSSL_ERR_F_PROV_ECC_KEYGEN,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_DUP_CTX,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_GET_PRIVATE_KEY,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_GET_PUBKEY_POINT,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_IMPORT,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_MATCH,
    SCOSSL_ERR_F_PROV_ECC_KEYMGMT_SET_PARAMS,
    SCOSSL_ERR_F_PROV_ECDH_DERIVE,
    SCOSSL_ERR_F_PROV_KBKDF_DERIVE,
    SCOSSL_ERR_F_PROV_KBKDF_KMAC_DERIVE,
    SCOSSL_ERR_F_PROV_KEYSINUSE_INIT_ONCE,
    SCOSSL_ERR_F_PROV_KMAC_INIT,
    SCOSSL_ERR_F_PROV_KMAC_SET_CTX_PARAMS,
    SCOSSL_ERR_F_PROV_RSA_GET_ENCODED_PUBLIC_KEY,
    SCOSSL_ERR_F_PROV_RSA_KEYGEN,
    SCOSSL_ERR_F_PROV_RSA_KEYMGMT_DUP_KEYDATA,
    SCOSSL_ERR_F_PROV_RSA_KEYMGMT_GET_CRT_KEYDATA,
    SCOSSL_ERR_F_PROV_RSA_KEYMGMT_GET_KEYDATA,
    SCOSSL_ERR_F_PROV_RSA_KEYMGMT_IMPORT,
    SCOSSL_ERR_F_PROV_RSA_KEYMGMT_MATCH,
    SCOSSL_ERR_F_PROV_X25519_KEYMGMT_EXPORT,
    SCOSSL_ERR_F_PROV_X25519_KEYMGMT_IMPORT,
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
    SCOSSL_ERR_R_KEYSINUSE_FAILURE,
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

//
// Common helper functions
//

// Functions for converting OpenSSL types to their SymCrypt equivalent
BOOL scossl_is_md_supported(int mdnid);
PCSYMCRYPT_MAC scossl_get_symcrypt_hmac_algorithm(int mdnid);
PCSYMCRYPT_HASH scossl_get_symcrypt_hash_algorithm(int mdnid);
int scossl_get_mdnid_from_symcrypt_hash_algorithm(_In_ PCSYMCRYPT_HASH symCryptHash);

#ifdef __cplusplus
}
#endif
