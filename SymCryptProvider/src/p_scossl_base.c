//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/proverr.h>
#include <openssl/prov_ssl.h>

#include "scossl_dh.h"
#include "scossl_ecc.h"
#include "scossl_provider.h"
#include "p_scossl_base.h"
#include "p_scossl_bio.h"
#include "p_scossl_names.h"
#include "kem/p_scossl_mlkem.h"

#ifdef KEYSINUSE_ENABLED
#include "keysinuse.h"
#endif

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
#define SCOSSL_MAX_CONFIGURABLE_FILE_SIZE (2l << 30)
#endif

#define SCOSSL_TLS_GROUP_ID_secp192r1               0x0013
#define SCOSSL_TLS_GROUP_ID_secp224r1               0x0015
#define SCOSSL_TLS_GROUP_ID_secp256r1               0x0017
#define SCOSSL_TLS_GROUP_ID_secp384r1               0x0018
#define SCOSSL_TLS_GROUP_ID_secp521r1               0x0019
#define SCOSSL_TLS_GROUP_ID_x25519                  0x001d
#define SCOSSL_TLS_GROUP_ID_brainpoolP256r1         0x001A
#define SCOSSL_TLS_GROUP_ID_brainpoolP384r1         0x001B
#define SCOSSL_TLS_GROUP_ID_brainpoolP512r1         0x001C
#define SCOSSL_TLS_GROUP_ID_brainpoolP256r1_tls13   0x001F
#define SCOSSL_TLS_GROUP_ID_brainpoolP384r1_tls13   0x0020
#define SCOSSL_TLS_GROUP_ID_brainpoolP512r1_tls13   0x0021
#define SCOSSL_TLS_GROUP_ID_ffdhe2048               0x0100
#define SCOSSL_TLS_GROUP_ID_ffdhe3072               0x0101
#define SCOSSL_TLS_GROUP_ID_ffdhe4096               0x0102
#define SCOSSL_TLS_GROUP_ID_ffdhe6144               0x0103
#define SCOSSL_TLS_GROUP_ID_ffdhe8192               0x0104
#define SCOSSL_TLS_GROUP_ID_mlkem512                0x0200
#define SCOSSL_TLS_GROUP_ID_mlkem768                0x0201
#define SCOSSL_TLS_GROUP_ID_mlkem1024               0x0202
#define SCOSSL_TLS_GROUP_ID_secp256r1mlkem768       0x11eb
#define SCOSSL_TLS_GROUP_ID_x25519mlkem768          0x11ec
#define SCOSSL_TLS_GROUP_ID_secp384r1mlkem1024      0x11ed

#define ALG(names, funcs) {     \
    names,                      \
    "provider="P_SCOSSL_NAME    \
    ",fips=yes",                \
    funcs,                      \
    NULL}

#define ALG_DECODER(algNames, name, decoderType) {      \
    algNames,                                           \
    "provider="P_SCOSSL_NAME                            \
    ",fips=yes"                                         \
    ",input=der"                                        \
    ",structure="#decoderType,                          \
    p_scossl_der_to_##name##_##decoderType##_functions, \
    NULL}

#define ALG_ENCODER(algNames, name, encoderType, format) {      \
    algNames,                                                   \
    "provider="P_SCOSSL_NAME                                    \
    ",fips=yes"                                                 \
    ",output="#format                                           \
    ",structure="#encoderType,                                  \
    p_scossl_##name##_to_##encoderType##_##format##_functions,  \
    NULL}

#define ALG_TEXT_ENCODER(algNames, name) { \
    algNames,                              \
    "provider="P_SCOSSL_NAME               \
    ",fips=yes,output=text",               \
    p_scossl_##name##_to_text_functions,   \
    NULL}

#define ALG_TABLE_END {NULL, NULL, NULL, NULL}

// Convenience macro to define references for all encoder/decoder types for a particular algorithm
#define DECODER_DISPATCH_ALL(algorithm)                                                          \
    extern const OSSL_DISPATCH p_scossl_der_to_##algorithm##_PrivateKeyInfo_functions[];         \
    extern const OSSL_DISPATCH p_scossl_der_to_##algorithm##_SubjectPublicKeyInfo_functions[];

#define DECODER_ENTRIES_ALL(provName, algorithm)                \
    ALG_DECODER(provName, algorithm, PrivateKeyInfo),         \
    ALG_DECODER(provName, algorithm, SubjectPublicKeyInfo),

#define ENCODER_DISPATCH_ALL(algorithm)                                                             \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_PrivateKeyInfo_der_functions[];            \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_PrivateKeyInfo_pem_functions[];            \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_EncryptedPrivateKeyInfo_der_functions[];   \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_EncryptedPrivateKeyInfo_pem_functions[];   \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_SubjectPublicKeyInfo_der_functions[];      \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_SubjectPublicKeyInfo_pem_functions[];      \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_text_functions[];

#define ENCODER_ENTRIES_ALL(provName, algorithm)                        \
    ALG_ENCODER(provName, algorithm, PrivateKeyInfo, der),            \
    ALG_ENCODER(provName, algorithm, PrivateKeyInfo, pem),            \
    ALG_ENCODER(provName, algorithm, EncryptedPrivateKeyInfo, der),   \
    ALG_ENCODER(provName, algorithm, EncryptedPrivateKeyInfo, pem),   \
    ALG_ENCODER(provName, algorithm, SubjectPublicKeyInfo, der),      \
    ALG_ENCODER(provName, algorithm, SubjectPublicKeyInfo, pem),      \
    ALG_TEXT_ENCODER(provName, algorithm),

typedef struct {
    unsigned int groupId;
    unsigned int securityBits;
    int is_kem;
    int minTls;
    int maxTls;
    int minDtls;
    int maxDtls;
} SCOSSL_TLS_GROUP_INFO;

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p192 = {
    SCOSSL_TLS_GROUP_ID_secp192r1, 80, 0,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p224 = {
    SCOSSL_TLS_GROUP_ID_secp224r1, 112, 0,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p256 = {
    SCOSSL_TLS_GROUP_ID_secp256r1, 128, 0,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p384 = {
    SCOSSL_TLS_GROUP_ID_secp384r1, 192, 0,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_p521 = {
    SCOSSL_TLS_GROUP_ID_secp521r1, 256, 0,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_x25519 = {
    SCOSSL_TLS_GROUP_ID_x25519, 128, 0,
    TLS1_VERSION, 0,
    DTLS1_VERSION, 0};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP256r1 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP256r1, 128, 0,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP384r1 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP384r1, 192, 0,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP512r1 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP512r1, 256, 0,
    TLS1_VERSION, TLS1_2_VERSION,
    DTLS1_VERSION, DTLS1_2_VERSION};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP256r1_tls13 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP256r1_tls13, 128, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP384r1_tls13 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP384r1_tls13, 192, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_brainpoolP512r1_tls13 = {
    SCOSSL_TLS_GROUP_ID_brainpoolP512r1_tls13, 256, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe2048 = {
    SCOSSL_TLS_GROUP_ID_ffdhe2048, 112, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe3072 = {
    SCOSSL_TLS_GROUP_ID_ffdhe3072, 128, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe4096 = {
    SCOSSL_TLS_GROUP_ID_ffdhe4096, 128, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe6144 = {
    SCOSSL_TLS_GROUP_ID_ffdhe6144, 128, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_ffdhe8192 = {
    SCOSSL_TLS_GROUP_ID_ffdhe8192, 128, 0,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_mlkem512 = {
    SCOSSL_TLS_GROUP_ID_mlkem512, 128, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_mlkem768 = {
    SCOSSL_TLS_GROUP_ID_mlkem768, 192, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_mlkem1024 = {
    SCOSSL_TLS_GROUP_ID_mlkem1024, 256, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_secp256r1mlkem768 = {
    SCOSSL_TLS_GROUP_ID_secp256r1mlkem768, 192, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_x25519mlkem768 = {
    SCOSSL_TLS_GROUP_ID_x25519mlkem768, 192, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

const SCOSSL_TLS_GROUP_INFO scossl_tls_group_info_secp384r1mlkem1024 = {
    SCOSSL_TLS_GROUP_ID_secp384r1mlkem1024, 256, 1,
    TLS1_3_VERSION, 0,
    -1, -1};

#define NUM_PARAMS_TLS_GROUP_ENTRY 11
#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, group_info) {                                     \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, tlsname, sizeof(tlsname)),                   \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, realname, sizeof(realname)),        \
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, algorithm, sizeof(algorithm)),                \
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, (unsigned int *)&group_info.groupId),                 \
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, (unsigned int *)&group_info.securityBits), \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, (int *)&group_info.minTls),                       \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, (int *)&group_info.maxTls),                       \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, (int *)&group_info.minDtls),                     \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, (int *)&group_info.maxDtls),                     \
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, (int *)&group_info.is_kem),                        \
    OSSL_PARAM_END}

static int scossl_prov_initialized = 0;

static OSSL_FUNC_core_get_params_fn *core_get_params;

static const OSSL_PARAM p_scossl_supported_group_list[][NUM_PARAMS_TLS_GROUP_ENTRY] = {
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
    TLS_GROUP_ENTRY("brainpoolP256r1", SN_brainpoolP256r1, "EC", scossl_tls_group_info_brainpoolP256r1),
    TLS_GROUP_ENTRY("brainpoolP384r1", SN_brainpoolP384r1, "EC", scossl_tls_group_info_brainpoolP384r1),
    TLS_GROUP_ENTRY("brainpoolP512r1", SN_brainpoolP512r1, "EC", scossl_tls_group_info_brainpoolP512r1),
    TLS_GROUP_ENTRY("brainpoolP256r1tls13", SN_brainpoolP256r1, "EC", scossl_tls_group_info_brainpoolP256r1),
    TLS_GROUP_ENTRY("brainpoolP384r1tls13", SN_brainpoolP384r1, "EC", scossl_tls_group_info_brainpoolP384r1),
    TLS_GROUP_ENTRY("brainpoolP512r1tls13", SN_brainpoolP512r1, "EC", scossl_tls_group_info_brainpoolP512r1),
    TLS_GROUP_ENTRY("ffdhe2048", SN_ffdhe2048, "DH", scossl_tls_group_info_ffdhe2048),
    TLS_GROUP_ENTRY("ffdhe3072", SN_ffdhe3072, "DH", scossl_tls_group_info_ffdhe3072),
    TLS_GROUP_ENTRY("ffdhe4096", SN_ffdhe4096, "DH", scossl_tls_group_info_ffdhe4096),
    TLS_GROUP_ENTRY("ffdhe6144", SN_ffdhe6144, "DH", scossl_tls_group_info_ffdhe6144),
    TLS_GROUP_ENTRY("ffdhe8192", SN_ffdhe8192, "DH", scossl_tls_group_info_ffdhe8192),
    TLS_GROUP_ENTRY("MLKEM512", SCOSSL_SN_MLKEM512, "MLKEM512", scossl_tls_group_info_mlkem512),
    TLS_GROUP_ENTRY("MLKEM768", SCOSSL_SN_MLKEM768, "MLKEM768", scossl_tls_group_info_mlkem768),
    TLS_GROUP_ENTRY("MLKEM1024", SCOSSL_SN_MLKEM1024, "MLKEM1024", scossl_tls_group_info_mlkem1024),
    TLS_GROUP_ENTRY("SecP256r1MLKEM768", SCOSSL_SN_P256_MLKEM768, "SecP256r1MLKEM768", scossl_tls_group_info_secp256r1mlkem768),
    TLS_GROUP_ENTRY("X25519MLKEM768", SCOSSL_SN_X25519_MLKEM768, "X25519MLKEM768", scossl_tls_group_info_x25519mlkem768),
    TLS_GROUP_ENTRY("SecP384r1MLKEM1024", SCOSSL_SN_P384_MLKEM1024, "SecP384r1MLKEM1024", scossl_tls_group_info_secp384r1mlkem1024)};

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
    ALG(SCOSSL_ALG_NAME_MD5, p_scossl_md5_functions),
    ALG(SCOSSL_ALG_NAME_SHA1, p_scossl_sha1_functions),
    ALG(SCOSSL_ALG_NAME_SHA224, p_scossl_sha224_functions),
    ALG(SCOSSL_ALG_NAME_SHA256, p_scossl_sha256_functions),
    ALG(SCOSSL_ALG_NAME_SHA384, p_scossl_sha384_functions),
    ALG(SCOSSL_ALG_NAME_SHA512, p_scossl_sha512_functions),
    ALG(SCOSSL_ALG_NAME_SHA512_224, p_scossl_sha512_224_functions),
    ALG(SCOSSL_ALG_NAME_SHA512_256, p_scossl_sha512_256_functions),
    ALG(SCOSSL_ALG_NAME_SHA3_224, p_scossl_sha3_224_functions),
    ALG(SCOSSL_ALG_NAME_SHA3_256, p_scossl_sha3_256_functions),
    ALG(SCOSSL_ALG_NAME_SHA3_384, p_scossl_sha3_384_functions),
    ALG(SCOSSL_ALG_NAME_SHA3_512, p_scossl_sha3_512_functions),
    ALG(SCOSSL_ALG_NAME_SHAKE128, p_scossl_shake_128_functions),
    ALG(SCOSSL_ALG_NAME_SHAKE256, p_scossl_shake_256_functions),
    ALG(SCOSSL_ALG_NAME_CSHAKE128, p_scossl_cshake_128_functions),
    ALG(SCOSSL_ALG_NAME_CSHAKE256, p_scossl_cshake_256_functions),
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
    ALG(SCOSSL_ALG_NAME_AES_128_CBC, p_scossl_aes128cbc_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_CBC, p_scossl_aes192cbc_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_CBC, p_scossl_aes256cbc_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_ECB, p_scossl_aes128ecb_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_ECB, p_scossl_aes192ecb_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_ECB, p_scossl_aes256ecb_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_CFB, p_scossl_aes128cfb_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_CFB, p_scossl_aes192cfb_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_CFB, p_scossl_aes256cfb_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_CFB8, p_scossl_aes128cfb8_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_CFB8, p_scossl_aes192cfb8_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_CFB8, p_scossl_aes256cfb8_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_GCM, p_scossl_aes128gcm_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_GCM, p_scossl_aes192gcm_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_GCM, p_scossl_aes256gcm_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_CCM, p_scossl_aes128ccm_functions),
    ALG(SCOSSL_ALG_NAME_AES_192_CCM, p_scossl_aes192ccm_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_CCM, p_scossl_aes256ccm_functions),
    ALG(SCOSSL_ALG_NAME_AES_128_XTS, p_scossl_aes128xts_functions),
    ALG(SCOSSL_ALG_NAME_AES_256_XTS, p_scossl_aes256xts_functions),
    ALG_TABLE_END};

// MAC
extern const OSSL_DISPATCH p_scossl_cmac_functions[];
extern const OSSL_DISPATCH p_scossl_hmac_functions[];
extern const OSSL_DISPATCH p_scossl_kmac128_functions[];
extern const OSSL_DISPATCH p_scossl_kmac256_functions[];

static const OSSL_ALGORITHM p_scossl_mac[] = {
    ALG(SCOSSL_ALG_NAME_CMAC, p_scossl_cmac_functions),
    ALG(SCOSSL_ALG_NAME_HMAC, p_scossl_hmac_functions),
    ALG(SCOSSL_ALG_NAME_KMAC128, p_scossl_kmac128_functions),
    ALG(SCOSSL_ALG_NAME_KMAC256, p_scossl_kmac256_functions),
    ALG_TABLE_END};

// KDF
extern const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_kbkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_pbkdf2_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtcpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sshkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sskdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls13kdf_kdf_functions[];

static const OSSL_ALGORITHM p_scossl_kdf[] = {
    ALG(SCOSSL_ALG_NAME_HKDF, p_scossl_hkdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_KBKDF, p_scossl_kbkdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_PBKDF2, p_scossl_pbkdf2_kdf_functions),
    ALG(SCOSSL_ALG_NAME_SRTPKDF, p_scossl_srtpkdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_SRTCPKDF, p_scossl_srtcpkdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_SSHKDF, p_scossl_sshkdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_SSKDF, p_scossl_sskdf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_TLS1_PRF, p_scossl_tls1prf_kdf_functions),
    ALG(SCOSSL_ALG_NAME_TLS13_KDF, p_scossl_tls13kdf_kdf_functions),
    ALG_TABLE_END};

// Rand
extern const OSSL_DISPATCH p_scossl_rand_functions[];

static const OSSL_ALGORITHM p_scossl_rand[] = {
    ALG(SCOSSL_ALG_NAME_CTR_DBG, p_scossl_rand_functions),
    ALG_TABLE_END};

// Key management
extern const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_kdf_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem1024_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_p256_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_p384_mlkem1024_keymgmt_functions[];

static const OSSL_ALGORITHM p_scossl_keymgmt[] = {
    ALG(SCOSSL_ALG_NAME_DH, p_scossl_dh_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_EC, p_scossl_ecc_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_HKDF, p_scossl_kdf_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_MLKEM512, p_scossl_mlkem512_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_MLKEM768, p_scossl_mlkem768_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_MLKEM1024, p_scossl_mlkem1024_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_X25519_MLKEM768, p_scossl_x25519_mlkem768_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_SecP256r1_MLKEM768, p_scossl_p256_mlkem768_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_SecP384r1_MLKEM1024, p_scossl_p384_mlkem1024_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_RSA, p_scossl_rsa_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_RSA_PSS, p_scossl_rsapss_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_TLS1_PRF, p_scossl_kdf_keymgmt_functions),
    ALG(SCOSSL_ALG_NAME_X25519, p_scossl_x25519_keymgmt_functions),
    ALG_TABLE_END};

// Key exchange
extern const OSSL_DISPATCH p_scossl_dh_functions[];
extern const OSSL_DISPATCH p_scossl_ecdh_functions[];
extern const OSSL_DISPATCH p_scossl_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_functions[];

static const OSSL_ALGORITHM p_scossl_keyexch[] = {
    ALG(SCOSSL_ALG_NAME_DH, p_scossl_dh_functions),
    ALG(SCOSSL_ALG_NAME_ECDH, p_scossl_ecdh_functions),
    ALG(SCOSSL_ALG_NAME_HKDF, p_scossl_hkdf_keyexch_functions),
    ALG(SCOSSL_ALG_NAME_TLS1_PRF, p_scossl_tls1prf_keyexch_functions),
    ALG(SCOSSL_ALG_NAME_X25519, p_scossl_ecdh_functions),
    ALG_TABLE_END};

// Signature
extern const OSSL_DISPATCH p_scossl_ecdsa_signature_functions[];
extern const OSSL_DISPATCH p_scossl_rsa_signature_functions[];

static const OSSL_ALGORITHM p_scossl_signature[] = {
    ALG(SCOSSL_ALG_NAME_ECDSA, p_scossl_ecdsa_signature_functions),
    ALG(SCOSSL_ALG_NAME_RSA, p_scossl_rsa_signature_functions),
    ALG_TABLE_END};

// Asymmetric Cipher
extern const OSSL_DISPATCH p_scossl_rsa_cipher_functions[];

static const OSSL_ALGORITHM p_scossl_asym_cipher[] = {
    ALG(SCOSSL_ALG_NAME_RSA, p_scossl_rsa_cipher_functions),
    ALG_TABLE_END};

// Key encapsulation
//
// These MLKEM hybrids are for TLS only. HPKE uses a different combiner mechanism
// that will be implemented separately.
extern const OSSL_DISPATCH p_scossl_mlkem_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem_hybrid_functions[];

static const OSSL_ALGORITHM p_scossl_kem[] = {
    ALG(SCOSSL_ALG_NAME_MLKEM512, p_scossl_mlkem_functions),
    ALG(SCOSSL_ALG_NAME_MLKEM768, p_scossl_mlkem_functions),
    ALG(SCOSSL_ALG_NAME_MLKEM1024, p_scossl_mlkem_functions),
    ALG(SCOSSL_ALG_NAME_X25519_MLKEM768, p_scossl_mlkem_hybrid_functions),
    ALG(SCOSSL_ALG_NAME_SecP256r1_MLKEM768, p_scossl_mlkem_hybrid_functions),
    ALG(SCOSSL_ALG_NAME_SecP384r1_MLKEM1024, p_scossl_mlkem_hybrid_functions),
    ALG_TABLE_END};

// Decoders
DECODER_DISPATCH_ALL(mlkem512)
DECODER_DISPATCH_ALL(mlkem768)
DECODER_DISPATCH_ALL(mlkem1024)

static const OSSL_ALGORITHM p_scossl_decoder[] = {
    DECODER_ENTRIES_ALL(SCOSSL_LN_MLKEM512, mlkem512)
    DECODER_ENTRIES_ALL(SCOSSL_LN_MLKEM768, mlkem768)
    DECODER_ENTRIES_ALL(SCOSSL_LN_MLKEM1024, mlkem1024)
    ALG_TABLE_END};

// Encoders
ENCODER_DISPATCH_ALL(mlkem512)
ENCODER_DISPATCH_ALL(mlkem768)
ENCODER_DISPATCH_ALL(mlkem1024)

static const OSSL_ALGORITHM p_scossl_encoder[] = {
    ENCODER_ENTRIES_ALL(SCOSSL_LN_MLKEM512, mlkem512)
    ENCODER_ENTRIES_ALL(SCOSSL_LN_MLKEM768, mlkem768)
    ENCODER_ENTRIES_ALL(SCOSSL_LN_MLKEM1024, mlkem1024)
    ALG_TABLE_END};

static SCOSSL_STATUS p_scossl_register_extended_algorithms()
{
    return p_scossl_mlkem_register_algorithms();
}

static int p_scossl_get_status()
{
    return scossl_prov_initialized;
}

static void p_scossl_teardown(_Inout_ SCOSSL_PROVCTX *provctx)
{
    scossl_destroy_logging();
    scossl_destroy_safeprime_dlgroups();
    scossl_ecc_destroy_ecc_curves();

    if (provctx != NULL)
    {
        BIO_meth_free(provctx->coreBioMeth);
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
    case OSSL_OP_DECODER:
        return p_scossl_decoder;
    case OSSL_OP_ENCODER:
        return p_scossl_encoder;
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

                // Clamp to SCOSSL_MAX_CONFIGURABLE_FILE_SIZE
                if (maxFileSizeBytes >= SCOSSL_MAX_CONFIGURABLE_FILE_SIZE ||
                    maxFileSizeBytes < maxFileSizeBytesTmp)
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

                // Clamp to SCOSSL_MAX_CONFIGURABLE_FILE_SIZE
                if (maxFileSizeBytes >= SCOSSL_MAX_CONFIGURABLE_FILE_SIZE ||
                    maxFileSizeBytes < maxFileSizeBytesTmp)
                {
                    maxFileSizeBytes = SCOSSL_MAX_CONFIGURABLE_FILE_SIZE;
                }
            }

            keysinuse_set_max_file_size(maxFileSizeBytes);
        }

        if (confLoggingDelay != NULL)
        {
            keysinuse_set_logging_delay(atol(confLoggingDelay));
        }

        keysinuse_init();
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

    p_scossl_set_core_bio(in);
    if ((p_ctx->coreBioMeth = p_scossl_bio_init()) == NULL)
    {
        OPENSSL_free(p_ctx);
        goto cleanup;
    }

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
            !scossl_ecc_init_static() ||
            !p_scossl_register_extended_algorithms())
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