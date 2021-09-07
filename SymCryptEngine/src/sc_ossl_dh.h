//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_STATUS sc_ossl_dh_generate_key(_Inout_ DH* dh);

_Success_(return >= 0)
int sc_ossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key, _In_ const BIGNUM* pub_key, _In_ DH* dh);

SCOSSL_STATUS sc_ossl_dh_bn_mod_exp(_In_ const DH* dh, _Out_ BIGNUM* r,
    _In_ const BIGNUM* a, _In_ const BIGNUM* p,
    _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx);

SCOSSL_STATUS sc_ossl_dh_init(_Inout_ DH* dh);

SCOSSL_STATUS sc_ossl_dh_finish(_Inout_ DH* dh);

#ifdef __cplusplus
}
#endif
