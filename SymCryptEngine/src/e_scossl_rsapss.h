//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl.h"

#ifdef __cplusplus
extern "C" {
#endif

// Signs tbs using key in ctx and stores signature and length in sig and siglen. NULL sig can be passed to get the
// length needed for sig, returned in siglen.
// Returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE on failure, or a negative value when the operation is not supported
SCOSSL_STATUS e_scossl_rsapss_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

// Verifies signature sig for tbs.
// Returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE on failure, or a negative value when the operation is not supported
SCOSSL_STATUS e_scossl_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

#ifdef __cplusplus
}
#endif
