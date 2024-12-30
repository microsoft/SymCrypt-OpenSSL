//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int nid;
    const char *oid;
    const char *groupName;
    const char *classicGroupName;
    SYMCRYPT_MLKEM_PARAMS mlkemParams;
} SCOSSL_MLKEM_GROUP_INFO;

typedef struct {
    SCOSSL_PROVCTX *provCtx;

    const SCOSSL_MLKEM_GROUP_INFO *groupInfo;
    PSYMCRYPT_MLKEMKEY key;
    SYMCRYPT_MLKEMKEY_FORMAT format;

    SCOSSL_ECC_KEY_CTX *classicKeyCtx;
} SCOSSL_MLKEM_KEY_CTX;

SCOSSL_STATUS p_scossl_mlkem_register_algorithms();
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info_by_nid(int nid);
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info(_In_ const char *groupName);

#ifdef __cplusplus
}
#endif