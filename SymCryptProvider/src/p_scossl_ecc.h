
#include "scossl_helpers.h"

typedef struct {
    OSSL_LIB_CTX *libctx; 
    int initialized;
    int includePublic;
    PSYMCRYPT_ECKEY key;
    EC_GROUP* ecGroup;
} SCOSSL_ECC_KEY_CTX;