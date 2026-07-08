//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// These helpers manage SCOSSL_ECC_KEY_CTX instances used by the ML-KEM
// hybrid implementation. They intentionally duplicate the logic in
// p_scossl_ecc.c / p_scossl_ecc_keymgmt.c so that the existing ECC code
// paths are left untouched. Only the SCOSSL_ECC_KEY_CTX struct (already
// public via p_scossl_ecc.h) is shared between the two.
//
// Hybrid keys are always ephemeral, used only for ECDH (never ECDSA),
// always use POINT_CONVERSION_UNCOMPRESSED for the classic component,
// and never participate in KeysInUse tracking.
//

SCOSSL_ECC_KEY_CTX *p_scossl_mlkem_hybrid_ecc_new_ctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_mlkem_hybrid_ecc_free_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx);
SCOSSL_ECC_KEY_CTX *p_scossl_mlkem_hybrid_ecc_dup_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx, int selection);

SCOSSL_STATUS p_scossl_mlkem_hybrid_ecc_set_group(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int nid);
SCOSSL_STATUS p_scossl_mlkem_hybrid_ecc_gen(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx);

SIZE_T p_scossl_mlkem_hybrid_ecc_get_max_result_size(int classicGroupNid);
SIZE_T p_scossl_mlkem_hybrid_ecc_get_encoded_key_size(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx, int selection);
SCOSSL_STATUS p_scossl_mlkem_hybrid_ecc_get_encoded_key(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                                        _Inout_ PBYTE *ppbKey, _Inout_ SIZE_T *pcbKey);
SCOSSL_STATUS p_scossl_mlkem_hybrid_ecc_set_encoded_key(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                                        _In_reads_bytes_opt_(cbEncodedPublicKey) PCBYTE pbEncodedPublicKey, SIZE_T cbEncodedPublicKey,
                                                        _In_reads_bytes_opt_(cbEncodedPrivateKey) PCBYTE pbEncodedPrivateKey, SIZE_T cbEncodedPrivateKey);

#ifdef __cplusplus
}
#endif
