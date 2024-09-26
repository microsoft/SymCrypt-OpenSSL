//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/proverr.h>
#include <openssl/prov_ssl.h>

#include "scossl_dh.h"
#include "scossl_ecc.h"
#include "p_scossl_keysinuse.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

// SCOSSL provider debug logging
#define CONF_LOGGING_FILE "logging_file"
#define CONF_LOGGING_LEVEL "logging_level"
#define CONF_ERROR_LEVEL "error_level"

#ifdef KEYSINUSE_ENABLED
#define CONF_KEYSINUSE_ENABLED       "keysinuse.enabled"
#define CONF_KEYSINUSE_MAX_FILE_SIZE "keysinuse.max_file_size"
#define CONF_KEYSINUSE_LOGGING_DELAY "keysinuse.logging_delay_seconds"

// Cap configured file size at 2GB
#define SCOSSL_MAX_CONFIGURABLE_FILE_SIZE (2 << 30)
#endif

#define OSSL_TLS_GROUP_ID_secp192r1        0x0013
#define OSSL_TLS_GROUP_ID_secp224r1        0x0015
#define OSSL_TLS_GROUP_ID_secp256r1        0x0017
#define OSSL_TLS_GROUP_ID_secp384r1        0x0018
#define OSSL_TLS_GROUP_ID_secp521r1        0x0019
#define OSSL_TLS_GROUP_ID_x25519           0x001D
#define OSSL_TLS_GROUP_ID_ffdhe2048        0x0100
#define OSSL_TLS_GROUP_ID_ffdhe3072        0x0101
#define OSSL_TLS_GROUP_ID_ffdhe4096        0x0102

#define ALG(names, funcs) {names, "provider="P_SCOSSL_NAME",fips=yes", funcs, NULL}
#define ALG_TABLE_END {NULL, NULL, NULL, NULL}

typedef struct {
    unsigned int groupId;
    unsigned int securityBits;
    int minTls;
    int maxTls;
    int minDtls;
    int maxDtls;
} SCOSSL_TLS_GROUP_INFO;

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p192 = {
    OSSL_TLS_GROUP_ID_secp192r1, 80,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p224 = {
    OSSL_TLS_GROUP_ID_secp224r1, 112,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p256 = {
    OSSL_TLS_GROUP_ID_secp256r1, 128,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p384 = {
    OSSL_TLS_GROUP_ID_secp384r1, 192,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p521 = {
    OSSL_TLS_GROUP_ID_secp521r1, 256,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_x25519 = {
    OSSL_TLS_GROUP_ID_x25519, 128,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe2048 = {
    OSSL_TLS_GROUP_ID_ffdhe2048, 112,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe3072 = {
    OSSL_TLS_GROUP_ID_ffdhe3072, 128,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe4096 = {
    OSSL_TLS_GROUP_ID_ffdhe4096, 128,
    TLS1_3_VERSION, 0,
    -1, -1};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, group_info) { \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, tlsname, sizeof(tlsname)), \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, realname, sizeof(realname)), \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, algorithm, sizeof(algorithm)), \
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, (unsigned int *)&group_info.groupId), \
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, (unsigned int *)&group_info.securityBits), \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, (int *)&group_info.minTls), \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, (int *)&group_info.maxTls), \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, (int *)&group_info.minTls), \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, (int *)&group_info.maxTls), \
    OSSL_PARAM_END}

static int scossl_prov_initialized = 0;

static OSSL_FUNC_core_get_params_fn *core_get_params;

static const OSSL_PARAM p_scossl_supported_group_list[][11] = {
    TLS_GROUP_ENTRY("secp192r1", SN_X9_62_prime192v1, "EC", scossl_tls_group_info_p192),
    TLS_GROUP_ENTRY("P-192", SN_X9_62_prime192v1, "EC", scossl_tls_group_info_p192),
    TLS_GROUP_ENTRY("secp224r1", SN_secp224r1, "EC", scossl_tls_group_info_p224),
    TLS_GROUP_ENTRY("P-224", SN_secp224r1, "EC", scossl_tls_group_info_p224),
    TLS_GROUP_ENTRY("secp256r1", SN_X9_62_prime256v1, "EC", scossl_tls_group_info_p256),
    TLS_GROUP_ENTRY("P-256", SN_X9_62_prime256v1, "EC", scossl_tls_group_info_p256),
    TLS_GROUP_ENTRY("secp384r1", SN_secp384r1, "EC", scossl_tls_group_info_p384),
    TLS_GROUP_ENTRY("P-384", SN_secp384r1, "EC", scossl_tls_group_info_p384),
    TLS_GROUP_ENTRY("secp521r1", SN_secp521r1, "EC", scossl_tls_group_info_p521),
    TLS_GROUP_ENTRY("P-521", SN_secp521r1, "EC", scossl_tls_group_info_p521),
    TLS_GROUP_ENTRY("x25519", SN_X25519, "X25519", scossl_tls_group_info_x25519),
    TLS_GROUP_ENTRY("ffdhe2048", SN_ffdhe2048, "DH", scossl_tls_group_info_ffdhe2048),
    TLS_GROUP_ENTRY("ffdhe3072", SN_ffdhe3072, "DH", scossl_tls_group_info_ffdhe3072),
    TLS_GROUP_ENTRY("ffdhe4096", SN_ffdhe4096, "DH", scossl_tls_group_info_ffdhe4096)};

// Digest
extern const OSSL_DISPATCH p_scossl_md5_functions[];
extern const OSSL_DISPATCH p_scossl_sha1_functions[];
extern const OSSL_DISPATCH p_scossl_sha224_functions[];
extern const OSSL_DISPATCH p_scossl_sha256_functions[];
extern const OSSL_DISPATCH p_scossl_sha384_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_224_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_256_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_224_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_256_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_384_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_512_functions[];
extern const OSSL_DISPATCH p_scossl_shake_128_functions[];
extern const OSSL_DISPATCH p_scossl_shake_256_functions[];
extern const OSSL_DISPATCH p_scossl_cshake_128_functions[];
extern const OSSL_DISPATCH p_scossl_cshake_256_functions[];

static const OSSL_ALGORITHM p_scossl_digest[] = {
    ALG("MD5:SSL3-MD5:1.2.840.113549.2.5", p_scossl_md5_functions),
    ALG("SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", p_scossl_sha1_functions),
    ALG("SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4", p_scossl_sha224_functions),
    ALG("SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", p_scossl_sha256_functions),
    ALG("SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", p_scossl_sha384_functions),
    ALG("SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", p_scossl_sha512_functions),
    ALG("SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5", p_scossl_sha512_224_functions),
    ALG("SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6", p_scossl_sha512_256_functions),
    ALG("SHA3-224:2.16.840.1.101.3.4.2.7", p_scossl_sha3_224_functions),
    ALG("SHA3-256:2.16.840.1.101.3.4.2.8", p_scossl_sha3_256_functions),
    ALG("SHA3-384:2.16.840.1.101.3.4.2.9", p_scossl_sha3_384_functions),
    ALG("SHA3-512:2.16.840.1.101.3.4.2.10", p_scossl_sha3_512_functions),
    ALG("SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11", p_scossl_shake_128_functions),
    ALG("SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12", p_scossl_shake_256_functions),
    ALG("CSHAKE-128:CSHAKE128", p_scossl_cshake_128_functions),
    ALG("CSHAKE-256:CSHAKE256", p_scossl_cshake_256_functions),
    ALG_TABLE_END};

// Cipher
extern const OSSL_DISPATCH p_scossl_aes128cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes128ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes192ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes256ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes128cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes128cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes128gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes128ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes128xts_functions[];
extern const OSSL_DISPATCH p_scossl_aes256xts_functions[];

static const OSSL_ALGORITHM p_scossl_cipher[] = {
    ALG("AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2", p_scossl_aes128cbc_functions),
    ALG("AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22", p_scossl_aes192cbc_functions),
    ALG("AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42", p_scossl_aes256cbc_functions),
    ALG("AES-128-ECB:2.16.840.1.101.3.4.1.1", p_scossl_aes128ecb_functions),
    ALG("AES-192-ECB:2.16.840.1.101.3.4.1.21", p_scossl_aes192ecb_functions),
    ALG("AES-256-ECB:2.16.840.1.101.3.4.1.41", p_scossl_aes256ecb_functions),
    ALG("AES-128-CFB:2.16.840.1.101.3.4.1.4", p_scossl_aes128cfb_functions),
    ALG("AES-192-CFB:2.16.840.1.101.3.4.1.24", p_scossl_aes192cfb_functions),
    ALG("AES-256-CFB:2.16.840.1.101.3.4.1.44", p_scossl_aes256cfb_functions),
    ALG("AES-128-CFB8", p_scossl_aes128cfb8_functions),
    ALG("AES-192-CFB8", p_scossl_aes192cfb8_functions),
    ALG("AES-256-CFB8", p_scossl_aes256cfb8_functions),
    ALG("AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", p_scossl_aes128gcm_functions),
    ALG("AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26", p_scossl_aes192gcm_functions),
    ALG("AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", p_scossl_aes256gcm_functions),
    ALG("AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7", p_scossl_aes128ccm_functions),
    ALG("AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27", p_scossl_aes192ccm_functions),
    ALG("AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47", p_scossl_aes256ccm_functions),
    ALG("AES-128-XTS:1.3.111.2.1619.0.1.1", p_scossl_aes128xts_functions),
    ALG("AES-256-XTS:1.3.111.2.1619.0.1.2", p_scossl_aes256xts_functions),
    ALG_TABLE_END};

// MAC
extern const OSSL_DISPATCH p_scossl_cmac_functions[];
extern const OSSL_DISPATCH p_scossl_hmac_functions[];
extern const OSSL_DISPATCH p_scossl_kmac128_functions[];
extern const OSSL_DISPATCH p_scossl_kmac256_functions[];

static const OSSL_ALGORITHM p_scossl_mac[] = {
    ALG("CMAC", p_scossl_cmac_functions),
    ALG("HMAC", p_scossl_hmac_functions),
    ALG("KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19", p_scossl_kmac128_functions),
    ALG("KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20", p_scossl_kmac256_functions),
    ALG_TABLE_END};

// KDF
extern const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_kbkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtcpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sshkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sskdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[];

static const OSSL_ALGORITHM p_scossl_kdf[] = {
    ALG("HKDF", p_scossl_hkdf_kdf_functions),
    ALG("KBKDF", p_scossl_kbkdf_kdf_functions),
    ALG("SRTPKDF", p_scossl_srtpkdf_kdf_functions),
    ALG("SRTCPKDF", p_scossl_srtcpkdf_kdf_functions),
    ALG("SSHKDF", p_scossl_sshkdf_kdf_functions),
    ALG("SSKDF", p_scossl_sskdf_kdf_functions),
    ALG("TLS1-PRF", p_scossl_tls1prf_kdf_functions),
    ALG_TABLE_END};

// Rand
extern const OSSL_DISPATCH p_scossl_rand_functions[];

static const OSSL_ALGORITHM p_scossl_rand[] = {
    ALG("CTR-DRBG", p_scossl_rand_functions),
    ALG_TABLE_END};

// Key management
extern const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_kdf_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem_keymgmt_functions[];

static const OSSL_ALGORITHM p_scossl_keymgmt[] = {
    ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", p_scossl_dh_keymgmt_functions),
    ALG("EC:id-ecPublicKey:1.2.840.10045.2.1", p_scossl_ecc_keymgmt_functions),
    ALG("HKDF", p_scossl_kdf_keymgmt_functions),
    ALG("RSA:rsaEncryption:1.2.840.113549.1.1.1:", p_scossl_rsa_keymgmt_functions),
    ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", p_scossl_rsapss_keymgmt_functions),
    ALG("TLS1-PRF", p_scossl_kdf_keymgmt_functions),
    ALG("X25519:1.3.101.110", p_scossl_x25519_keymgmt_functions),
    ALG("MLKEM", p_scossl_mlkem_keymgmt_functions),
    ALG_TABLE_END};

// Key exchange
extern const OSSL_DISPATCH p_scossl_dh_functions[];
extern const OSSL_DISPATCH p_scossl_ecdh_functions[];
extern const OSSL_DISPATCH p_scossl_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_functions[];

static const OSSL_ALGORITHM p_scossl_keyexch[] = {
    ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", p_scossl_dh_functions),
    ALG("ECDH", p_scossl_ecdh_functions),
    ALG("HKDF", p_scossl_hkdf_keyexch_functions),
    ALG("TLS1-PRF", p_scossl_tls1prf_keyexch_functions),
    ALG("X25519:1.3.101.110", p_scossl_ecdh_functions),
    ALG_TABLE_END};

// Signature
extern const OSSL_DISPATCH p_scossl_rsa_signature_functions[];
extern const OSSL_DISPATCH p_scossl_ecdsa_signature_functions[];

static const OSSL_ALGORITHM p_scossl_signature[] = {
    ALG("RSA:rsaEncryption:1.2.840.113549.1.1.1", p_scossl_rsa_signature_functions),
    ALG("ECDSA", p_scossl_ecdsa_signature_functions),
    ALG_TABLE_END};

// Asymmetric Cipher
extern const OSSL_DISPATCH p_scossl_rsa_cipher_functions[];

static const OSSL_ALGORITHM p_scossl_asym_cipher[] = {
    ALG("RSA:rsaEncryption:1.2.840.113549.1.1.1", p_scossl_rsa_cipher_functions),
    ALG_TABLE_END};

// Key encapsulation
extern const OSSL_DISPATCH p_scossl_mlkem_functions[];

static const OSSL_ALGORITHM p_scossl_kem[] = {
    ALG("MLKEM", p_scossl_mlkem_functions),
    ALG_TABLE_END};

static int p_scossl_get_status()
{
    return scossl_prov_initialized;
}

static void p_scossl_teardown(_Inout_ SCOSSL_PROVCTX *provctx)
{
    scossl_destroy_logging();
    scossl_destroy_safeprime_dlgroups();
    scossl_ecc_destroy_ecc_curves();
#ifdef KEYSINUSE_ENABLED
    p_scossl_keysinuse_teardown();
#endif
    if (provctx != NULL)
    {
        OSSL_LIB_CTX_free(provctx->libctx);
        OPENSSL_free(provctx);
    }
}

static const OSSL_PARAM *p_scossl_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_param_types;
}

static SCOSSL_STATUS p_scossl_get_params(ossl_unused void *provctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_NAME))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, p_scossl_get_status()))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_ALGORITHM *p_scossl_query_operation(ossl_unused void *provctx, int operation_id, _Out_ int *no_store)
{
    // Dispatch tables do not change and may be cached
    *no_store = 0;
    switch (operation_id)
    {
    case OSSL_OP_DIGEST:
        return p_scossl_digest;
    case OSSL_OP_CIPHER:
        return p_scossl_cipher;
    case OSSL_OP_MAC:
        return p_scossl_mac;
    case OSSL_OP_KDF:
        return p_scossl_kdf;
    case OSSL_OP_RAND:
        return p_scossl_rand;
    case OSSL_OP_KEYMGMT:
        return p_scossl_keymgmt;
    case OSSL_OP_KEYEXCH:
        return p_scossl_keyexch;
    case OSSL_OP_SIGNATURE:
        return p_scossl_signature;
    case OSSL_OP_ASYM_CIPHER:
        return p_scossl_asym_cipher;
    case OSSL_OP_KEM:
        return p_scossl_kem;
    }

    return NULL;
}

static SCOSSL_STATUS p_scossl_get_capabilities(ossl_unused void *provctx, _In_ const char *capability,
                                               _In_ OSSL_CALLBACK *cb, _In_ void *arg)
{
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
    {
        for (size_t i = 0; i < sizeof(p_scossl_supported_group_list) / sizeof(p_scossl_supported_group_list[0]); i++)
        {
            if (!cb(p_scossl_supported_group_list[i], arg))
            {
                return SCOSSL_FAILURE;
            }
        }

        return SCOSSL_SUCCESS;
    }

    return SCOSSL_FAILURE;
}

#ifdef KEYSINUSE_ENABLED
static void p_scossl_start_keysinuse(_In_ const OSSL_CORE_HANDLE *handle)
{
    BOOL keysinuseEnabled = FALSE;
    // All config params are provided as string pointers
    const char *confEnabled = NULL;
    const char *confMaxFileSize = NULL;
    const char *confLoggingDelay = NULL;
    const char *envEnabled = NULL;

    OSSL_PARAM keysinuseParams[] = {
        OSSL_PARAM_utf8_ptr(CONF_KEYSINUSE_ENABLED, &confEnabled, 0),
        OSSL_PARAM_utf8_ptr(CONF_KEYSINUSE_MAX_FILE_SIZE, &confMaxFileSize, 0),
        OSSL_PARAM_utf8_ptr(CONF_KEYSINUSE_LOGGING_DELAY, &confLoggingDelay, 0),
        OSSL_PARAM_END};

    // Config related errors shouldn't surface to caller
    ERR_set_mark();

    if (core_get_params(handle, keysinuseParams) &&
        confEnabled != NULL)
    {
        keysinuseEnabled = atoi(confEnabled) == 0 ? FALSE : TRUE;
    }

    // KeysInUse can be enabled from environment. This takes precedence over config.
    // NCONF_get_string fetches from the environment if the conf parameter is NULL
    if ((envEnabled = NCONF_get_string(NULL, NULL, "KEYSINUSE_ENABLED")) != NULL)
    {
        keysinuseEnabled = atoi(envEnabled) == 0 ? FALSE : TRUE;
    }

    if (keysinuseEnabled)
    {
        if (confMaxFileSize != NULL)
        {
            // Convert file size to off_t in bytes.
            // This is the same behavior as atol but also handles MB, KB, and GB suffixes.
            off_t maxFileSizeBytes = 0;
            off_t maxFileSizeBytesTmp = 0;
            int i = 0;

            while ('0' <= confMaxFileSize[i] && confMaxFileSize[i] <= '9')
            {
                maxFileSizeBytesTmp = maxFileSizeBytes;

                maxFileSizeBytes = maxFileSizeBytes * 10 + (confMaxFileSize[i++] - '0');

                // Clamp to SCOSSL_MAX_CONFIGURABLE_FILE_SIZE in case of overflow
                if (maxFileSizeBytes < maxFileSizeBytesTmp)
                {
                    maxFileSizeBytes = SCOSSL_MAX_CONFIGURABLE_FILE_SIZE;
                    break;
                }
            }

            // Check for KB, MB, or GB suffixes, case insensitive.
            if (maxFileSizeBytes < SCOSSL_MAX_CONFIGURABLE_FILE_SIZE &&
                confMaxFileSize[i] != '\0' &&
                (confMaxFileSize[i + 1] == 'B' || confMaxFileSize[i + 1] == 'b'))
            {
                maxFileSizeBytesTmp = maxFileSizeBytes;

                switch (confMaxFileSize[i])
                {
                case 'K':
                case 'k':
                    maxFileSizeBytes <<= 10;
                    break;
                case 'M':
                case 'm':
                    maxFileSizeBytes <<= 20;
                    break;
                case 'G':
                case 'g':
                    maxFileSizeBytes <<= 30;
                    break;
                }

                // Clamp to SCOSSL_MAX_CONFIGURABLE_FILE_SIZE in case of overflow
                if (maxFileSizeBytes < maxFileSizeBytesTmp)
                {
                    maxFileSizeBytes = SCOSSL_MAX_CONFIGURABLE_FILE_SIZE;
                }
            }

            p_scossl_keysinuse_set_max_file_size(maxFileSizeBytes);
        }

        if (confLoggingDelay != NULL)
        {
            p_scossl_keysinuse_set_logging_delay(atol(confLoggingDelay));
        }

        p_scossl_keysinuse_init();
    }

    ERR_pop_to_mark();
}
#endif

static int p_scossl_level_string_to_id(_In_ const char *level)
{
    if (level == NULL)
    {
        return SCOSSL_LOG_LEVEL_NO_CHANGE;
    }

    if (OPENSSL_strcasecmp(level, "off") == 0)
    {
        return SCOSSL_LOG_LEVEL_OFF;
    }
    else if (OPENSSL_strcasecmp(level, "error") == 0)
    {
        return SCOSSL_LOG_LEVEL_ERROR;
    }
    else if (OPENSSL_strcasecmp(level, "info") == 0)
    {
        return SCOSSL_LOG_LEVEL_INFO;
    }
    else if (OPENSSL_strcasecmp(level, "debug") == 0)
    {
        return SCOSSL_LOG_LEVEL_DEBUG;
    }

    return SCOSSL_LOG_LEVEL_NO_CHANGE;
}

static void p_scossl_setup_logging(_In_ const OSSL_CORE_HANDLE *handle)
{
    const char *confErrorLevel = NULL;
    const char *confLoggingLevel = NULL;
    const char *confLoggingFile = NULL;

    OSSL_PARAM confParams[] = {
        OSSL_PARAM_utf8_ptr(CONF_LOGGING_FILE, &confLoggingFile, 0),
        OSSL_PARAM_utf8_ptr(CONF_LOGGING_LEVEL, &confLoggingLevel, 0),
        OSSL_PARAM_utf8_ptr(CONF_ERROR_LEVEL, &confErrorLevel, 0),
        OSSL_PARAM_END};

    scossl_setup_logging();

    if (core_get_params != NULL &&
        core_get_params(handle, confParams))
    {
        if (confLoggingFile != NULL)
        {
            SCOSSL_set_trace_log_filename(confLoggingFile);
        }

        SCOSSL_set_trace_level(
            p_scossl_level_string_to_id(confLoggingLevel),
            p_scossl_level_string_to_id(confErrorLevel));
    }
}

static const OSSL_DISPATCH p_scossl_base_dispatch[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_scossl_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))p_scossl_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p_scossl_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_scossl_query_operation},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))p_scossl_get_capabilities},
    {0, NULL}};

SCOSSL_STATUS OSSL_provider_init(_In_ const OSSL_CORE_HANDLE *handle,
                                 _In_ const OSSL_DISPATCH *in,
                                 _Out_ const OSSL_DISPATCH **out,
                                 _Out_ void **provctx)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    SCOSSL_PROVCTX *p_ctx = OPENSSL_malloc(sizeof(SCOSSL_PROVCTX));
    if (p_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    p_ctx->handle = handle;
    p_ctx->libctx = OSSL_LIB_CTX_new_child(handle, in);

    for (; in->function_id != 0; in++)
    {
        switch(in->function_id)
        {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(in);
            break;
        }
    }

    p_scossl_setup_logging(handle);

    if (!scossl_prov_initialized)
    {
        SymCryptModuleInit(P_SCOSSL_SYMCRYPT_MINIMUM_MAJOR, P_SCOSSL_SYMCRYPT_MINIMUM_MINOR);
        if (!scossl_dh_init_static() ||
            !scossl_ecc_init_static())
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);
            goto cleanup;
        }
        scossl_prov_initialized = 1;
    }

    *provctx = p_ctx;

    *out = p_scossl_base_dispatch;

#ifdef KEYSINUSE_ENABLED
    // Start keysinuse if configured
    if (core_get_params != NULL)
    {
        p_scossl_start_keysinuse(handle);
    }
#endif

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS)
    {
        p_scossl_teardown(p_ctx);
    }

    return ret;
}

#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0
EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in)
{
    EVP_MD_CTX *out = EVP_MD_CTX_new();

    if (out != NULL && !EVP_MD_CTX_copy_ex(out, in)) {
        EVP_MD_CTX_free(out);
        out = NULL;
    }
    return out;
}

#if OPENSSL_VERSION_PATCH < 4
int OPENSSL_strcasecmp(const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}
#endif // OPENSSL_VERSION_PATCH < 4

#endif // OPENSSL_VERSION_MINOR == 0

#ifdef __cplusplus
}
#endif