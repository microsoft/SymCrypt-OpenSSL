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
SCOSSL_STATUS e_scossl_hmac_init(_Inout_ EVP_PKEY_CTX *ctx);

// Frees the internal context of ctx.
void e_scossl_hmac_cleanup(_Inout_ EVP_PKEY_CTX *ctx);

// Makes a copy of internal context src
SCOSSL_STATUS e_scossl_hmac_copy(_Out_ EVP_PKEY_CTX *dst, _In_ EVP_PKEY_CTX *src);

// Sends a control operation to context ctx. type indicates which operation, and
// p1 and p2 are optional parameters depending on which type is used.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error, or SCOSSL_UNSUPPORTED on not supported.
SCOSSL_STATUS e_scossl_hmac_ctrl(_Inout_ EVP_PKEY_CTX *ctx, int type, int p1, _In_ void *p2);

// Initializes pkey with the HMAC key from the internal context.
SCOSSL_STATUS e_scossl_hmac_keygen(_Inout_ EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

// Performs initialization on the mdctx object, such as setting the message update function.
SCOSSL_STATUS e_scossl_hmac_signctx_init(_Inout_ EVP_PKEY_CTX *ctx, _In_ EVP_MD_CTX *mdctx);

// Finalizes the HMAC computation by calling the resultFunc of the HMAC algorithm on the mac state
// stored in the internal context.
// If sig is NULL siglen is set to HMAC output length.
// If sig is not NULL, the length siglen points to should not not be smaller than the HMAC output length.
SCOSSL_STATUS e_scossl_hmac_signctx(_Inout_ EVP_PKEY_CTX *ctx, _Out_ unsigned char *sig, _Out_ size_t *siglen, _In_ EVP_MD_CTX *mdctx);

#ifdef __cplusplus
}
#endif
