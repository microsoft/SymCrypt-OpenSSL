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

// ERR_put_error is deprecated in 3.0+. We replace the functionality with the equivalent
// function calls in OpenSSL 3.0+.
#if OPENSSL_API_LEVEL >= 30000
    #define SCOSSL_put_error(lib, func, reason, file, line) \
        (ERR_new(),                                         \
         ERR_set_debug((file), (line), (func)),             \
         ERR_set_error((lib), (reason), NULL))
#else
    #define SCOSSL_put_error(lib, func, reason, file, line) \
        ERR_put_error((lib), (func), (reason), (file), (line))
#endif

// Level of tracing that is output to stderr / log file
static int _traceLogLevel = SCOSSL_LOG_LEVEL_OFF;
static char *_traceLogFilename = NULL;
static FILE *_traceLogFile = NULL;

// Level of tracing that is output to OpenSSL ERR infrastructure
// By default only log actual errors, as some OpenSSL unit tests check that successful calls do not
// generate any ERR entries. Callers may wish to set this to SCOSSL_LOG_LEVEL_INFO to expose data
// about where they may not be calling FIPS certified code.
static int _osslERRLogLevel = SCOSSL_LOG_LEVEL_ERROR;

// Lock around writing information to stderr/log file/OpenSSL ERR handling framework to avoid
// muddled error messages in multi-threaded environment
static CRYPTO_RWLOCK *_loggingLock = NULL;

static int _scossl_err_library_code = 0;

static ERR_STRING_DATA SCOSSL_ERR_library_string[] = {
    {0, "SCOSSL"},  // library name
    {0, NULL}
};

static ERR_STRING_DATA SCOSSL_ERR_function_strings[] = {
    // ScosslCommon
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_CIPHER, 0), "scossl_aes_ccm_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_SET_IV_FIXED, 0), "scossl_aes_ccm_set_iv_fixed"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_SET_IV_LEN, 0), "scossl_aes_ccm_set_iv_len"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_SET_TLS1_AAD, 0), "scossl_aes_ccm_set_tls1_aad"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_CCM_TLS, 0), "scossl_aes_ccm_tls"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_CIPHER, 0), "scossl_aes_gcm_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_IV_GEN, 0), "scossl_aes_gcm_iv_gen"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_SET_IV_FIXED, 0), "scossl_aes_gcm_set_iv_fixed"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_SET_IV_INV, 0), "scossl_aes_gcm_set_iv_inv"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_SET_IV_LEN, 0), "scossl_aes_gcm_set_iv_len"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_SET_TLS1_AAD, 0), "scossl_aes_gcm_set_tls1_aad"},
    {ERR_PACK(0, SCOSSL_ERR_F_AES_GCM_TLS, 0), "scossl_aes_gcm_tls"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, 0), "scossl_dh_generate_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_GET_GROUP_BY_NID, 0), "scossl_dh_get_group_by_nid"},
    {ERR_PACK(0, SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, 0), "scossl_dh_import_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECC_GROUP_TO_SYMCRYPT_CURVE, 0), "scossl_ecc_group_to_symcrypt_curve"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECC_POINT_TO_PUBKEY, 0), "scossl_ec_point_to_pubkey"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_APPLY_DER, 0), "scossl_ecdsa_apply_der"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_DER_CHECK_TAG_AND_GET_VALUE_AND_LENGTH, 0), "scossl_ecdsa_der_check_tag_and_get_value_and_length"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_REMOVE_DER, 0), "scossl_ecdsa_remove_der"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_SIGN, 0), "scossl_ecdsa_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ECDSA_VERIFY, 0), "scossl_ecdsa_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, 0), "scossl_get_symcrypt_hash_algorithm"},
    {ERR_PACK(0, SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM, 0), "scossl_get_symcrypt_hmac_algorithm"},
    {ERR_PACK(0, SCOSSL_ERR_F_HKDF_DERIVE, 0), "scossl_hkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_MAC_INIT, 0), "scossl_mac_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_MAC_SET_HMAC_MD, 0), "scossl_mac_set_hmac_md"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_DECRYPT, 0), "scossl_rsa_decrypt"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_ENCRYPT, 0), "scossl_rsa_encrypt"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_EXPORT_KEY, 0), "scossl_rsa_export_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_NEW_EXPORT_PARAMS, 0), "scossl_rsa_new_export_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PKCS1_SIGN, 0), "scossl_rsa_pkcs1_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSA_PKCS1_VERIFY, 0), "scossl_rsa_pkcs1_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSAPSS_SIGN, 0), "scossl_rsapss_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_RSAPSS_VERIFY, 0), "scossl_rsapss_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_SSHKDF_DERIVE, 0), "scossl_sshkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_TLS1PRF_DERIVE, 0), "scossl_tls1prf_derive"},
    // SymCryptEngine
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_AES_CCM_CTRL, 0), "e_scossl_aes_ccm_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_AES_GCM_CTRL, 0), "e_scossl_aes_gcm_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_AES_XTS_CIPHER, 0), "e_scossl_aes_xts_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_AES_XTS_CTRL, 0), "e_scossl_aes_xts_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_DH_COMPUTE_KEY, 0), "e_scossl_dh_compute_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_DH_GENERATE_KEY, 0), "e_scossl_dh_generate_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_DH_GENERATE_KEYPAIR, 0), "e_scossl_dh_generate_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_DH_IMPORT_KEYPAIR, 0), "e_scossl_dh_import_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_DIGESTS, 0), "e_scossl_digests"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, 0), "e_scossl_ecc_generate_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, 0), "e_scossl_ecc_import_keypair"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, 0), "e_scossl_eckey_compute_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_KEYGEN, 0), "e_scossl_eckey_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_SIGN, 0), "e_scossl_eckey_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_SIGN_SETUP, 0), "e_scossl_eckey_sign_setup"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, 0), "e_scossl_eckey_sign_sig"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_VERIFY, 0), "e_scossl_eckey_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_ECKEY_VERIFY_SIG, 0), "e_scossl_eckey_verify_sig"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_GET_DH_CONTEXT_EX, 0), "e_scossl_get_dh_context_ex"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_GET_ECC_CONTEXT_EX, 0), "e_scossl_get_ecc_context_ex"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_GET_SYMCRYPT_HASH_ALGORITHM, 0), "e_scossl_get_symcrypt_hash_algorithm"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HKDF_CTRL, 0), "e_scossl_hkdf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HKDF_DERIVE, 0), "e_scossl_hkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HKDF_INIT, 0), "e_scossl_hkdf_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HMAC_COPY, 0), "e_scossl_hmac_copy"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HMAC_CTRL, 0), "e_scossl_hmac_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_HMAC_INIT, 0), "e_scossl_hmac_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_INITIALIZE_RSA_KEY, 0), "e_scossl_initialize_rsa_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_PKEY_METHODS, 0), "e_scossl_pkey_methods"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_PKEY_RSA_SIGN, 0), "e_scossl_pkey_rsa_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_PKEY_RSA_VERIFY, 0), "e_scossl_pkey_rsa_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_PKEY_RSAPSS_VERIFY, 0), "e_scossl_pkey_rsapss_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_INIT, 0), "e_scossl_rsa_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_KEYGEN, 0), "e_scossl_rsa_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_PRIV_DEC, 0), "e_scossl_rsa_priv_dec"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_PRIV_ENC, 0), "e_scossl_rsa_priv_enc"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_PUB_DEC, 0), "e_scossl_rsa_pub_dec"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_PUB_ENC, 0), "e_scossl_rsa_pub_enc"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_SIGN, 0), "e_scossl_rsa_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSA_VERIFY, 0), "e_scossl_rsa_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSAPSS_SIGN, 0), "e_scossl_rsapss_sign"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_RSAPSS_VERIFY, 0), "e_scossl_rsapss_verify"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_SSHKDF_CTRL, 0), "e_scossl_sshkdf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_SSHKDF_CTRL_STR, 0), "e_scossl_sshkdf_ctrl_str"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_SSHKDF_DERIVE, 0), "e_scossl_sshkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_SSHKDF_NEW, 0), "e_scossl_sshkdf_new"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_TLS1PRF_CTRL, 0), "e_scossl_tls1prf_ctrl"},
    {ERR_PACK(0, SCOSSL_ERR_F_ENG_TLS1PRF_INIT, 0), "e_scossl_tls1prf_init"},
    // SymCryptProvider
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_AES_CFB_CIPHER, 0), "p_scossl_aes_cfb_cipher"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_AES_GENERIC_INIT_INTERNAL, 0), "p_scossl_aes_generic_init_internal"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_AES_XTS_INIT_INTERNAL, 0), "p_scossl_aes_xts_init_internal"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_EXPORT, 0), "p_scossl_dh_keymgmt_export"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_GET_PARAMS, 0), "p_scossl_dh_keymgmt_get_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_GET_FFC_PARAMS, 0), "p_scossl_dh_keymgmt_get_ffc_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_GET_KEY_PARAMS, 0), "p_scossl_dh_keymgmt_get_key_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_MATCH, 0), "p_scossl_dh_keymgmt_match"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_KEYMGMT_SET_PARAMS, 0), "p_scossl_dh_keymgmt_set_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_PARAMS_TO_GROUP, 0), "p_scossl_dh_params_to_group"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_PLAIN_DERIVE, 0), "p_scossl_dh_plain_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_DH_X9_42_DERIVE, 0), "p_scossl_dh_x9_42_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_GET_ENCODED_PUBLIC_KEY, 0), "p_scossl_ecc_get_encoded_public_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_INIT_KEYSINUSE, 0), "p_scossl_ecc_init_keysinuse"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYGEN, 0), "p_scossl_ecc_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_DUP_CTX, 0), "p_scossl_ecc_keymgmt_dup_ctx"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_GET_PRIVATE_KEY, 0), "p_scossl_ecc_keymgmt_get_private_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_GET_PUBKEY_POINT, 0), "p_scossl_ecc_keymgmt_get_pubkey_point"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_IMPORT, 0), "p_scossl_ecc_keymgmt_import"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_MATCH, 0), "p_scossl_ecc_keymgmt_match"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECC_KEYMGMT_SET_PARAMS, 0), "p_scossl_ecc_keymgmt_set_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_ECDH_DERIVE, 0), "p_scossl_ecdh_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_KBKDF_DERIVE, 0), "p_scossl_kbkdf_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_KBKDF_KMAC_DERIVE, 0), "p_scossl_kbkdf_kmac_derive"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_KEYSINUSE_INIT_ONCE, 0), "p_scossl_keysinuse_init_once"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_KMAC_INIT, 0), "p_scossl_kmac_init"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_KMAC_SET_CTX_PARAMS, 0), "p_scossl_kmac_set_ctx_params"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_CIPHER_ENCRYPT, 0), "p_scossl_rsa_cipher_encrypt"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_CIPHER_DECRYPT, 0), "p_scossl_rsa_cipher_decrypt"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_GET_ENCODED_PUBLIC_KEY, 0), "p_scossl_rsa_get_encoded_public_key"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYGEN, 0), "p_scossl_rsa_keygen"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYMGMT_DUP_KEYDATA, 0), "p_scossl_rsa_keymgmt_dup_keydata"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYMGMT_GET_CRT_KEYDATA, 0), "p_scossl_rsa_keymgmt_get_crt_keydata"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYMGMT_GET_KEYDATA, 0), "p_scossl_rsa_keymgmt_get_keydata"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYMGMT_IMPORT, 0), "p_scossl_rsa_keymgmt_import"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_KEYMGMT_MATCH, 0), "p_scossl_rsa_keymgmt_match"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_RSA_PSS_PARAMS_TO_ASN1_SEQUENCE, 0), "p_scossl_rsa_pss_params_to_asn1_sequence"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_X25519_KEYMGMT_EXPORT, 0), "p_scossl_x25519_keymgmt_export"},
    {ERR_PACK(0, SCOSSL_ERR_F_PROV_X25519_KEYMGMT_IMPORT, 0), "p_scossl_x25519_keymgmt_import"},
    {0, NULL}
};

C_ASSERT( (sizeof(SCOSSL_ERR_function_strings) / sizeof(ERR_STRING_DATA)) == SCOSSL_ERR_F_ENUM_END-SCOSSL_ERR_F_ENUM_START );


static ERR_STRING_DATA SCOSSL_ERR_reason_strings[] = {
    {ERR_PACK(0, 0, SCOSSL_ERR_R_MISSING_CTX_DATA), "Missing data in context"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_NOT_IMPLEMENTED), "Algorithm not supported by SCOSSL"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM), "Algorithm not FIPS certifiable"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_OPENSSL_FALLBACK), "SCOSSL falling back to OpenSSL"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_SYMCRYPT_FAILURE), "SCOSSL triggered SymCrypt failure"},
    {ERR_PACK(0, 0, SCOSSL_ERR_R_KEYSINUSE_FAILURE), "KeysInUse failure"},
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
    _loggingLock = NULL;
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
            SCOSSL_put_error(_scossl_err_library_code, func_code, reason_code, file, line);
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

void _scossl_log_SYMCRYPT_ERROR(
    int trace_level,
    SCOSSL_ERR_FUNC func_code,
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
    _scossl_log(trace_level, func_code, SCOSSL_ERR_R_SYMCRYPT_FAILURE, file, line, "%s - %s (0x%x)", description, scErrorString, scError);
}

BOOL scossl_is_md_supported(int mdnid)
{
    switch (mdnid)
    {
    case NID_sha1:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
    case NID_sha3_256:
    case NID_sha3_384:
    case NID_sha3_512:
        return TRUE;
    }

    return FALSE;
}

PCSYMCRYPT_MAC scossl_get_symcrypt_hmac_algorithm(int mdnid)
{
    switch(mdnid)
    {
    case NID_sha1:
        return SymCryptHmacSha1Algorithm;
    case NID_sha256:
        return SymCryptHmacSha256Algorithm;
    case NID_sha384:
        return SymCryptHmacSha384Algorithm;
    case NID_sha512:
        return SymCryptHmacSha512Algorithm;
    case NID_sha3_256:
        return SymCryptHmacSha3_256Algorithm;
    case NID_sha3_384:
        return SymCryptHmacSha3_384Algorithm;
    case NID_sha3_512:
        return SymCryptHmacSha3_512Algorithm;
    }
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_MAC_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SCOSSL does not support hmac algorithm %d", mdnid);
    return NULL;
}

PCSYMCRYPT_HASH scossl_get_symcrypt_hash_algorithm(int mdnid)
{
    switch (mdnid)
    {
    case NID_sha1:
        return SymCryptSha1Algorithm;
    case NID_sha256:
        return SymCryptSha256Algorithm;
    case NID_sha384:
        return SymCryptSha384Algorithm;
    case NID_sha512:
        return SymCryptSha512Algorithm;
    case NID_sha3_256:
        return SymCryptSha3_256Algorithm;
    case NID_sha3_384:
        return SymCryptSha3_384Algorithm;
    case NID_sha3_512:
        return SymCryptSha3_512Algorithm;
    }
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SCOSSL does not support hash algorithm %d", mdnid);
    return NULL;
}

_Use_decl_annotations_
int scossl_get_mdnid_from_symcrypt_hash_algorithm(PCSYMCRYPT_HASH symCryptHash)
{
    if (symCryptHash == SymCryptSha1Algorithm)
    {
        return NID_sha1;
    }
    else if (symCryptHash == SymCryptSha256Algorithm)
    {
        return NID_sha256;
    }
    else if (symCryptHash == SymCryptSha384Algorithm)
    {
        return NID_sha384;
    }
    else if (symCryptHash == SymCryptSha512Algorithm)
    {
        return NID_sha512;
    }
    else if (symCryptHash == SymCryptSha3_256Algorithm)
    {
        return NID_sha3_256;
    }
    else if (symCryptHash == SymCryptSha3_384Algorithm)
    {
        return NID_sha3_384;
    }
    else if (symCryptHash == SymCryptSha3_512Algorithm)
    {
        return NID_sha3_512;
    }

    return NID_undef;
}

#ifdef __cplusplus
}
#endif
