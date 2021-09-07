//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"
#include <openssl/dsa.h>

#ifdef __cplusplus
extern "C" {
#endif


_Success_(return != NULL)
DSA_SIG* sc_ossl_dsa_sign(_In_reads_bytes_(dlen) const unsigned char* dgst, int dlen, _In_ DSA* dsa);

SCOSSL_STATUS sc_ossl_dsa_sign_setup(_In_ DSA* dsa, _In_ BN_CTX* ctx_in, _Out_ BIGNUM** kinvp, _Out_ BIGNUM** rp);

SCOSSL_STATUS sc_ossl_dsa_verify(_In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len, _In_ DSA_SIG* sig, _In_ DSA* dsa);

SCOSSL_STATUS sc_ossl_dsa_init(_Inout_ DSA* dsa);

SCOSSL_STATUS sc_ossl_dsa_finish(_Inout_ DSA* dsa);

#ifdef __cplusplus
}
#endif
