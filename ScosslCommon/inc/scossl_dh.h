//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    BOOL initialized;
    PSYMCRYPT_DLKEY dlkey;
} SCOSSL_DH_KEY_CTX;

SCOSSL_DH_KEY_CTX *scossl_dh_new_key_ctx(void);
void scossl_dh_free_key_ctx(_Inout_ SCOSSL_DH_KEY_CTX *ctx);
SCOSSL_DH_KEY_CTX *scossl_dh_dup_key_ctx(_In_ SCOSSL_DH_KEY_CTX *ctx, BOOL copyGroup);

SCOSSL_STATUS scossl_dh_import_keypair(_Inout_ SCOSSL_DH_KEY_CTX *ctx, UINT32 nBitsPriv,
                                        _In_ PCSYMCRYPT_DLGROUP pDlgroup, BOOL skipGroupValidation,
                                       _In_ const BIGNUM *privateKey, _In_ const BIGNUM *publicKey);
SCOSSL_STATUS scossl_dh_create_key(_Inout_ SCOSSL_DH_KEY_CTX *ctx, _In_ PCSYMCRYPT_DLGROUP pDlgroup, UINT32 nBitsPriv, BOOL generatKeyPair);

SCOSSL_STATUS scossl_dh_init_static(void);
void scossl_destroy_safeprime_dlgroups(void);

PCSYMCRYPT_DLGROUP scossl_dh_get_known_group(_In_ PCSYMCRYPT_DLGROUP pDlGroup);
PCSYMCRYPT_DLGROUP scossl_dh_get_group_by_nid(int dlGroupNid, _In_opt_ const BIGNUM* p);
int scossl_dh_get_group_nid(_In_ PCSYMCRYPT_DLGROUP pDlGroup);

#ifdef __cplusplus
}
#endif