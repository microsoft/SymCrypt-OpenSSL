//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl.h"

#ifdef __cplusplus
extern "C" {
#endif

// Allocate SymCrypt context inside of ctx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_tls1prf_init(_Inout_ EVP_PKEY_CTX *ctx);

// Frees SymCrypt context inside of ctx.
void e_scossl_tls1prf_cleanup(_Inout_ EVP_PKEY_CTX *ctx);

// Sends a control operation to context ctx. type indicates which operation, and
// p1 and p2 are optional parameters depending on which type is used.
// Returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE on error, or SCOSSL_UNSUPPORTED on not supported.
SCOSSL_STATUS e_scossl_tls1prf_ctrl(_Inout_ EVP_PKEY_CTX *ctx, int type, int p1, _In_ void *p2);

// Initializes context ctx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_tls1prf_derive_init(_Inout_ EVP_PKEY_CTX *ctx);

// Derives a shared secret using ctx.
// NOTE: The documentation states that if the key is NULL, then keylen will be set to the maximum size of
// the output buffer. This is not true for TLS1-PRF, and the keylen is always expected.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_tls1prf_derive(_Inout_ EVP_PKEY_CTX *ctx,
                                      _Out_writes_bytes_(*keylen) unsigned char *key, _In_ size_t *keylen);

#ifdef __cplusplus
}
#endif
