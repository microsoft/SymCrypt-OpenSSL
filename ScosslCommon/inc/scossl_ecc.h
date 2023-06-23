//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int initialized;
    PSYMCRYPT_ECKEY key;
    EC_GROUP* ecGroup;
} SCOSSL_ECC_KEY_CTX;

SCOSSL_STATUS scossl_ecc_init_static();
PSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(EC_GROUP *group);
SCOSSL_ECC_KEY_CTX *scossl_ecc_new_key_ctx();
SCOSSL_ECC_KEY_CTX *scossl_ecc_dup_key_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx);
void scossl_ecc_free_key_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx);

#ifdef __cplusplus
}
#endif