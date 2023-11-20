//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    OSSL_LIB_CTX *libctx;
    BOOL initialized;
    PSYMCRYPT_ECKEY key;
    PCSYMCRYPT_ECURVE curve;
    // Not used for crypto operations. Only used in import/export
    // to let the provider handling encoding/decoding whether to
    // include the public key.
    int includePublic;
} SCOSSL_ECC_KEY_CTX;

#ifdef __cplusplus
}
#endif