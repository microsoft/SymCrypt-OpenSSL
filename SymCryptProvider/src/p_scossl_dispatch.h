//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#ifndef P_SCOSSL_DISPATCH_H
#define P_SCOSSL_DISPATCH_H

#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Digest */
#ifndef SCOSSL_NO_MD5
extern const OSSL_DISPATCH p_scossl_md5_functions[];
#endif
#ifndef SCOSSL_NO_SHA2
extern const OSSL_DISPATCH p_scossl_sha1_functions[];
extern const OSSL_DISPATCH p_scossl_sha224_functions[];
extern const OSSL_DISPATCH p_scossl_sha256_functions[];
extern const OSSL_DISPATCH p_scossl_sha384_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_224_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_256_functions[];
#endif
#ifndef SCOSSL_NO_SHA3
extern const OSSL_DISPATCH p_scossl_sha3_224_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_256_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_384_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_512_functions[];
#endif
#ifndef SCOSSL_NO_SHAKE
extern const OSSL_DISPATCH p_scossl_shake_128_functions[];
extern const OSSL_DISPATCH p_scossl_shake_256_functions[];
extern const OSSL_DISPATCH p_scossl_cshake_128_functions[];
extern const OSSL_DISPATCH p_scossl_cshake_256_functions[];
#endif

/* Cipher */
#ifndef SCOSSL_NO_AES
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
#endif
#ifndef SCOSSL_NO_AES_AEAD
extern const OSSL_DISPATCH p_scossl_aes128gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes128ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256ccm_functions[];
#endif
#ifndef SCOSSL_NO_AES_XTS
extern const OSSL_DISPATCH p_scossl_aes128xts_functions[];
extern const OSSL_DISPATCH p_scossl_aes256xts_functions[];
#endif

/* MAC */
#ifndef SCOSSL_NO_CMAC
extern const OSSL_DISPATCH p_scossl_cmac_functions[];
#endif
#ifndef SCOSSL_NO_HMAC
extern const OSSL_DISPATCH p_scossl_hmac_functions[];
#endif
#ifndef SCOSSL_NO_KMAC
extern const OSSL_DISPATCH p_scossl_kmac128_functions[];
extern const OSSL_DISPATCH p_scossl_kmac256_functions[];
#endif

/* KDF */
#ifndef SCOSSL_NO_KDF
extern const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_kbkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_pbkdf2_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_srtcpkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sshkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_sskdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls13kdf_kdf_functions[];
#endif

/* Rand */
#ifndef SCOSSL_NO_RAND
extern const OSSL_DISPATCH p_scossl_rand_functions[];
#endif

/* Key management */
#ifndef SCOSSL_NO_DH
extern const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[];
#endif
#ifndef SCOSSL_NO_EC
extern const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[];
#endif
#ifndef SCOSSL_NO_KDF
extern const OSSL_DISPATCH p_scossl_kdf_keymgmt_functions[];
#endif
#ifndef SCOSSL_NO_RSA
extern const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsapss_keymgmt_functions[];
#endif
#ifndef SCOSSL_NO_ECX
extern const OSSL_DISPATCH p_scossl_x25519_keymgmt_functions[];
#endif
#ifndef SCOSSL_NO_MLKEM
extern const OSSL_DISPATCH p_scossl_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem1024_keymgmt_functions[];
#endif
#if !defined(SCOSSL_NO_MLKEM) && !defined(SCOSSL_NO_ECX)
extern const OSSL_DISPATCH p_scossl_x25519_mlkem768_keymgmt_functions[];
#endif
#if !defined(SCOSSL_NO_MLKEM) && !defined(SCOSSL_NO_EC)
extern const OSSL_DISPATCH p_scossl_p256_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_p384_mlkem1024_keymgmt_functions[];
#endif

/* Key exchange */
#ifndef SCOSSL_NO_DH
extern const OSSL_DISPATCH p_scossl_dh_functions[];
#endif
#ifndef SCOSSL_NO_EC
extern const OSSL_DISPATCH p_scossl_ecdh_functions[];
#endif
#ifndef SCOSSL_NO_KDF
extern const OSSL_DISPATCH p_scossl_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_keyexch_functions[];
#endif
#ifndef SCOSSL_NO_ECX
extern const OSSL_DISPATCH p_scossl_x25519_functions[];
#endif

/* Signature */
#ifndef SCOSSL_NO_EC
extern const OSSL_DISPATCH p_scossl_ecdsa_signature_functions[];
#endif
#ifndef SCOSSL_NO_RSA
extern const OSSL_DISPATCH p_scossl_rsa_signature_functions[];
#endif

/* Asymmetric Cipher */
#ifndef SCOSSL_NO_RSA
extern const OSSL_DISPATCH p_scossl_rsa_cipher_functions[];
#endif

/* Key encapsulation */
#ifndef SCOSSL_NO_MLKEM
extern const OSSL_DISPATCH p_scossl_mlkem_functions[];
extern const OSSL_DISPATCH p_scossl_mlkem_hybrid_functions[];
#endif

/* Convenience macro to define references for all encoder/decoder types for a particular algorithm */
#define DECODER_DISPATCH_ALL(algorithm)                                                          \
    extern const OSSL_DISPATCH p_scossl_der_to_##algorithm##_PrivateKeyInfo_functions[];         \
    extern const OSSL_DISPATCH p_scossl_der_to_##algorithm##_SubjectPublicKeyInfo_functions[];

#define ENCODER_DISPATCH_ALL(algorithm)                                                             \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_PrivateKeyInfo_der_functions[];            \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_PrivateKeyInfo_pem_functions[];            \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_EncryptedPrivateKeyInfo_der_functions[];   \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_EncryptedPrivateKeyInfo_pem_functions[];   \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_SubjectPublicKeyInfo_der_functions[];      \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_SubjectPublicKeyInfo_pem_functions[];      \
    extern const OSSL_DISPATCH p_scossl_##algorithm##_to_text_functions[];

/* Decoder dispatch tables for MLKEM algorithms */
#ifndef SCOSSL_NO_MLKEM
DECODER_DISPATCH_ALL(mlkem512)
DECODER_DISPATCH_ALL(mlkem768)
DECODER_DISPATCH_ALL(mlkem1024)
#endif

/* Encoder dispatch tables for MLKEM algorithms */
#ifndef SCOSSL_NO_MLKEM
ENCODER_DISPATCH_ALL(mlkem512)
ENCODER_DISPATCH_ALL(mlkem768)
ENCODER_DISPATCH_ALL(mlkem1024)
#endif

#ifdef __cplusplus
}
#endif

#endif /* P_SCOSSL_DISPATCH_H */