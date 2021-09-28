//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Signs tbs using key in ctx and stores signature and length in sig and siglen. NULL sig can be passed to get the
// length needed for sig, returned in siglen.
// Returns 1 on success, or negative number for failure.
SCOSSL_STATUS sc_ossl_rsapss_sign(_Inout_ EVP_PKEY_CTX *ctx, _Out_writes_opt_(*siglen) unsigned char *sig, _Out_ size_t *siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

// Verifies signature sig for tbs.
// Returns 1 on success.
SCOSSL_STATUS sc_ossl_rsapss_verify(_Inout_ EVP_PKEY_CTX *ctx, _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                      _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);

#ifdef __cplusplus
}
#endif
