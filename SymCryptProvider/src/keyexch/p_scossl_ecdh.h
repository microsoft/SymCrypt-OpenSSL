//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;
    SCOSSL_ECC_KEY_CTX *keyCtx;
    SCOSSL_ECC_KEY_CTX *peerKeyCtx;
} SCOSSL_ECDH_CTX;

// ECDH functions are exposed here for use in hybrid key exchange
SCOSSL_ECDH_CTX *p_scossl_ecdh_newctx(_In_ SCOSSL_PROVCTX *provctx);
void p_scossl_ecdh_freectx(_In_ SCOSSL_ECDH_CTX *ctx);
SCOSSL_ECDH_CTX *p_scossl_ecdh_dupctx(_In_ SCOSSL_ECDH_CTX *ctx);

SCOSSL_STATUS p_scossl_ecdh_init(_In_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                 ossl_unused const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_ecdh_set_peer(_Inout_ SCOSSL_ECDH_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *peerKeyCtx);
SCOSSL_STATUS p_scossl_ecdh_derive(_In_ SCOSSL_ECDH_CTX *ctx,
                                   _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen,
                                   size_t outlen);


#ifdef __cplusplus
}
#endif