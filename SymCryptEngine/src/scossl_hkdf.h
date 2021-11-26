//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Allocate internal context and attach to ctx.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS scossl_hkdf_init(_Inout_ EVP_PKEY_CTX *ctx);

// Frees the internal context of ctx.
void scossl_hkdf_cleanup(_Inout_ EVP_PKEY_CTX *ctx);

// Sends a control operation to context ctx. type indicates which operation, and
// p1 and p2 are optional parameters depending on which type is used.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error, or SCOSSL_UNSUPPORTED on not supported.
SCOSSL_STATUS scossl_hkdf_ctrl(_Inout_ EVP_PKEY_CTX *ctx, int type, int p1, _In_ void *p2);

// Initializes context ctx.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS scossl_hkdf_derive_init(_Inout_ EVP_PKEY_CTX *ctx);

// Derives a shared secret using ctx. If key is NULL then the maximum size of the output buffer
// is written to the keylen parameter. If key is not NULL, then keylen should contain the length of
// the key buffer, the shared secret is written to key and the amount of data written to keylen.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE or a negative value for failure.
SCOSSL_STATUS scossl_hkdf_derive(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*keylen) unsigned char *key,
                                    _Inout_ size_t *keylen);

#ifdef __cplusplus
}
#endif
