//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// This file contains parameter names and definitions that are not
// part of the default OpenSSL implementation, or belong to an
// algorithm not found in the default OpenSSL implementation,
// but are used by the SymCrypt provider.

#ifdef __cplusplus
extern "C" {
#endif

//
// Digest parameters
//
#define SCOSSL_DIGEST_PARAM_FUNCTION_NAME_STRING "function-name-string"
#define SCOSSL_DIGEST_PARAM_CUSTOMIZATION_STRING "customization-string"

//
// KDF parameters
//
#define SCOSSL_KDF_PARAM_SRTP_RATE "rate"
#define SCOSSL_KDF_PARAM_SRTP_INDEX "index"
#define SCOSSL_KDF_PARAM_SRTP_INDEX_WIDTH "index-width"

//
// SRTP labels
//
#define SCOSSL_SRTP_LABEL_ENCRYPTION "encryption"
#define SCOSSL_SRTP_LABEL_AUTHENTICATION "authentication"
#define SCOSSL_SRTP_LABEL_SALTING "salting"

//
// Extended algorithms that may not be in the OpenSSL default implementation
//
#define SCOSSL_SN_MLDSA44     "id-ml-dsa-44"
#define SCOSSL_LN_MLDSA44     "ML-DSA-44"
#define SCOSSL_OID_MLDSA44    "2.16.840.1.101.3.4.3.17"

#define SCOSSL_SN_MLDSA65     "id-ml-dsa-65"
#define SCOSSL_LN_MLDSA65     "ML-DSA-65"
#define SCOSSL_OID_MLDSA65    "2.16.840.1.101.3.4.3.18"

#define SCOSSL_SN_MLDSA87     "id-ml-dsa-87"
#define SCOSSL_LN_MLDSA87     "ML-DSA-87"
#define SCOSSL_OID_MLDSA87    "2.16.840.1.101.3.4.3.19"

#define SCOSSL_SN_MLKEM512      "id-alg-ml-kem-512"
#define SCOSSL_LN_MLKEM512      "ML-KEM-512"
#define SCOSSL_OID_MLKEM512     "2.16.840.1.101.3.4.4.1"

#define SCOSSL_SN_MLKEM768      "id-alg-ml-kem-768"
#define SCOSSL_LN_MLKEM768      "ML-KEM-768"
#define SCOSSL_OID_MLKEM768     "2.16.840.1.101.3.4.4.2"

#define SCOSSL_SN_MLKEM1024     "id-alg-ml-kem-1024"
#define SCOSSL_LN_MLKEM1024     "ML-KEM-1024"
#define SCOSSL_OID_MLKEM1024    "2.16.840.1.101.3.4.4.3"

#define SCOSSL_SN_X25519_MLKEM768   "id-alg-x25519-ml-kem-768"
#define SCOSSL_LN_X25519_MLKEM768   "X25519-ML-KEM-768"

#define SCOSSL_SN_P256_MLKEM768     "id-alg-secp256r1-ml-kem-768"
#define SCOSSL_LN_P256_MLKEM768     "P256-ML-KEM-768"

#define SCOSSL_SN_P384_MLKEM1024    "id-alg-secp384r1-ml-kem-1024"
#define SCOSSL_LN_P384_MLKEM1024    "P384-ML-KEM-1024"

// OpenSSL 3.5 parameters
#ifndef OSSL_PKEY_PARAM_ML_KEM_SEED
 #define OSSL_PKEY_PARAM_ML_KEM_SEED "seed"
#endif

#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
 #define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif

#ifndef OSSL_SIGNATURE_PARAM_TEST_ENTROPY
 #define OSSL_SIGNATURE_PARAM_TEST_ENTROPY "test-entropy"
#endif

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
 #define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif

#ifndef OSSL_SIGNATURE_PARAM_MU
 #define OSSL_SIGNATURE_PARAM_MU "mu"
#endif

#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
 #define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif

#ifndef OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS
 #define OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS "tls-min-dtls"
#endif

#ifndef OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS
 #define OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS "tls-max-dtls"
#endif

#ifdef __cplusplus
}
#endif