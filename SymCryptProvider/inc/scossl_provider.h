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

#ifdef __cplusplus
}
#endif