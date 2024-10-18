//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Extended algorithms not found in default OpenSSL implementation
//

#define SCOSSL_SN_MLKEM512 "mlkem512"
#define SCOSSL_OID_MLKEM512 "2.16.840.1.101.3.4.4.1"

#define SCOSSL_SN_MLKEM768 "mlkem768"
#define SCOSSL_OID_MLKEM768 "2.16.840.1.101.3.4.4.2"

#define SCOSSL_SN_MLKEM1024 "mlkem1024"
#define SCOSSL_OID_MLKEM1024 "2.16.840.1.101.3.4.4.3"

//
// Provider algorithm names
//

// Ciphers
#define SCOSSL_ALG_NAME_AES_128_CBC     SN_aes_128_cbc":AES128:2.16.840.1.101.3.4.1.2"
#define SCOSSL_ALG_NAME_AES_192_CBC     SN_aes_192_cbc":AES192:2.16.840.1.101.3.4.1.22"
#define SCOSSL_ALG_NAME_AES_256_CBC     SN_aes_256_cbc":AES256:2.16.840.1.101.3.4.1.42"
#define SCOSSL_ALG_NAME_AES_128_ECB     SN_aes_128_ecb":2.16.840.1.101.3.4.1.1"
#define SCOSSL_ALG_NAME_AES_192_ECB     SN_aes_192_ecb":2.16.840.1.101.3.4.1.21"
#define SCOSSL_ALG_NAME_AES_256_ECB     SN_aes_256_ecb":2.16.840.1.101.3.4.1.41"
#define SCOSSL_ALG_NAME_AES_128_CFB     SN_aes_128_cfb128":2.16.840.1.101.3.4.1.4"
#define SCOSSL_ALG_NAME_AES_192_CFB     SN_aes_192_cfb128":2.16.840.1.101.3.4.1.24"
#define SCOSSL_ALG_NAME_AES_256_CFB     SN_aes_256_cfb128":2.16.840.1.101.3.4.1.44"
#define SCOSSL_ALG_NAME_AES_128_CFB8    SN_aes_128_cfb8
#define SCOSSL_ALG_NAME_AES_192_CFB8    SN_aes_192_cfb8
#define SCOSSL_ALG_NAME_AES_256_CFB8    SN_aes_256_cfb8
#define SCOSSL_ALG_NAME_AES_128_GCM     SN_aes_128_gcm":AES-128-GCM:2.16.840.1.101.3.4.1.6"
#define SCOSSL_ALG_NAME_AES_192_GCM     SN_aes_192_gcm":AES-192-GCM:2.16.840.1.101.3.4.1.26"
#define SCOSSL_ALG_NAME_AES_256_GCM     SN_aes_256_gcm":AES-256-GCM:2.16.840.1.101.3.4.1.46"
#define SCOSSL_ALG_NAME_AES_128_CCM     SN_aes_128_ccm":AES-128-CCM:2.16.840.1.101.3.4.1.7"
#define SCOSSL_ALG_NAME_AES_192_CCM     SN_aes_192_ccm":AES-192-CCM:2.16.840.1.101.3.4.1.27"
#define SCOSSL_ALG_NAME_AES_256_CCM     SN_aes_256_ccm":AES-256-CCM:2.16.840.1.101.3.4.1.47"
#define SCOSSL_ALG_NAME_AES_128_XTS     SN_aes_128_xts":1.3.111.2.1619.0.1.1"
#define SCOSSL_ALG_NAME_AES_256_XTS     SN_aes_256_xts":1.3.111.2.1619.0.1.2"

// MAC
#define SCOSSL_ALG_NAME_CMAC    SN_cmac
#define SCOSSL_ALG_NAME_HMAC    SN_hmac
#define SCOSSL_ALG_NAME_KMAC128 SN_kmac128":KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19"
#define SCOSSL_ALG_NAME_KMAC256 SN_kmac256":KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20"

// KDF
#define SCOSSL_ALG_NAME_HKDF        SN_hkdf
#define SCOSSL_ALG_NAME_KBKKDF      "KBKDF"
#define SCOSSL_ALG_NAME_SRTPKDF     "SRTPKDF"
#define SCOSSL_ALG_NAME_SRTCPKDF    "SRTCPKDF"
#define SCOSSL_ALG_NAME_SSHKDF      SN_sshkdf
#define SCOSSL_ALG_NAME_SSKDF       SN_sskdf
#define SCOSSL_ALG_NAME_TLS1_PRF    SN_tls1_prf

// Rand
#define SCOSSL_ALG_NAME_CTR_DBG "CTR-DRBG"

// Key management
#define SCOSSL_ALG_NAME_EC      SN_X9_62_id_ecPublicKey":EC:1.2.840.10045.2.1"
#define SCOSSL_ALG_NAME_RSA_PSS SN_rsassaPss":RSA-PSS:1.2.840.113549.1.1.10"

// Key exchange
#define SCOSSL_ALG_NAME_DH      LN_dhKeyAgreement":DH:1.2.840.113549.1.3.1"
#define SCOSSL_ALG_NAME_ECDH    "ECDH"
#define SCOSSL_ALG_NAME_X25519  SN_X25519":1.3.101.110"

// Signature
#define SCOSSL_ALG_NAME_RSA     SN_rsa":"LN_rsaEncryption":1.2.840.113549.1.1.1"
#define SCOSSL_ALG_NAME_ECDSA   "ECDSA"

// Key encapsulation
#define SCOSSL_ALG_NAME_MLKEM           "MLKEM"
#define SCOSSL_ALG_NAME_MLKEM_DECODER   SCOSSL_ALG_NAME_MLKEM":"SCOSSL_SN_MLKEM512":"SCOSSL_OID_MLKEM512":"SCOSSL_SN_MLKEM768":"SCOSSL_OID_MLKEM768":"SCOSSL_SN_MLKEM1024":"SCOSSL_OID_MLKEM1024

#ifdef __cplusplus
}
#endif