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
// Extended algorithms not found in default OpenSSL implementation
//
#define SCOSSL_SN_MLKEM512      "id-alg-ml-kem-512"
#define SCOSSL_LN_MLKEM512      "ML-KEM-512"
#define SCOSSL_OID_MLKEM512     "2.16.840.1.101.3.4.4.1"

#define SCOSSL_SN_MLKEM768      "id-alg-ml-kem-768"
#define SCOSSL_LN_MLKEM768      "ML-KEM-768"
#define SCOSSL_OID_MLKEM768     "2.16.840.1.101.3.4.4.2"

#define SCOSSL_SN_MLKEM1024     "id-alg-ml-kem-1024"
#define SCOSSL_LN_MLKEM1024     "ML-KEM-1024"
#define SCOSSL_OID_MLKEM1024    "2.16.840.1.101.3.4.4.3"

#define SCOSSL_SN_P256_MLKEM768     "id-alg-secp256r1-ml-kem-768"
#define SCOSSL_LN_P256_MLKEM768     "P256-ML-KEM-768"
#define SCOSSL_OID_P256_MLKEM768    "2.16.840.1.101.3.4.4.4"

#define SCOSSL_SN_X25519_MLKEM768   "id-alg-x25519-ml-kem-768"
#define SCOSSL_LN_X25519_MLKEM768   "X25519-ML-KEM-768"
#define SCOSSL_OID_X25519_MLKEM768  "2.16.840.1.101.3.4.4.5"

#define SCOSSL_SN_P384_MLKEM1024    "id-alg-secp384r1-ml-kem-1024"
#define SCOSSL_LN_P384_MLKEM1024    "P384-ML-KEM-1024"
#define SCOSSL_OID_P384_MLKEM1024   "2.16.840.1.101.3.4.4.6"

#ifdef __cplusplus
}
#endif