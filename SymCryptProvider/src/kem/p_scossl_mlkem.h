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
    const char *snGroupName;
    const char *lnGroupName;
    SYMCRYPT_MLKEM_PARAMS mlkemParams;
} SCOSSL_MLKEM_GROUP_INFO;

typedef struct {
    SCOSSL_PROVCTX *provCtx;

    SYMCRYPT_MLKEM_PARAMS mlkemParams;
    SYMCRYPT_MLKEMKEY_FORMAT format;
    PSYMCRYPT_MLKEMKEY key;
} SCOSSL_MLKEM_KEY_CTX;

#define SCOSSL_MLKEM_PRIVATE_SEED_LENGTH 64

SCOSSL_STATUS p_scossl_mlkem_register_algorithms();
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info_by_nid(int nid);
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info(_In_ const char *groupName);
int p_scossl_mlkem_params_to_nid(SYMCRYPT_MLKEM_PARAMS mlkemParams);

int p_scossl_mlkem_get_bits(SYMCRYPT_MLKEM_PARAMS mlkemParams);
int p_scossl_mlkem_get_security_bits(SYMCRYPT_MLKEM_PARAMS mlkemParams);


#ifdef __cplusplus
}
#endif