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
    BOOL isX25519;
    // RFC7748 dictates that to decode the x25519 private key, we need to
    // 1. Set the three least significant bits of the MSB to 0
    // 2. Set the most significant bit of the LSB to 0
    // 3. Set the second most significant bit of the LSB to 1
    // SymCrypt expects the operation to be applied to the private
    // key before import. In order to preserve the original key data
    // for export, the transformed bits are stored here. The position
    // of the midified bits in the MSB and LSB differ, so we can use
    // a single byte.
    BYTE modifiedPrivateBits;
    // Not used for crypto operations. Only used in import/export
    // to let the provider handling encoding/decoding whether to
    // include the public key.
    int includePublic;
} SCOSSL_ECC_KEY_CTX;

#ifdef __cplusplus
}
#endif