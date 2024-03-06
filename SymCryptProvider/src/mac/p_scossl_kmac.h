//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Some of the structures defined here are used for KBKDF KMAC.
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KMAC_MAX_OUTPUT_LEN (0xFFFFFF / 8)
#define KMAC_MAX_CUSTOM 512

typedef union
{
    SYMCRYPT_KMAC128_EXPANDED_KEY kmac128Key;
    SYMCRYPT_KMAC256_EXPANDED_KEY kmac256Key;
} SCOSSL_KMAC_EXPANDED_KEY;

typedef union
{
    SYMCRYPT_KMAC128_STATE kmac128State;
    SYMCRYPT_KMAC256_STATE kmac256State;
} SCOSSL_KMAC_STATE;

typedef SYMCRYPT_ERROR (SYMCRYPT_CALL * PSYMCRYPT_KMAC_EXPAND_KEY_EX)
                                        (SCOSSL_KMAC_EXPANDED_KEY *pExpandedKey, PCBYTE pbKey, SIZE_T cbKey,
                                         PCBYTE  pbCustomizationString, SIZE_T  cbCustomizationString);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_KMAC_RESULT_EX) (SCOSSL_KMAC_STATE *pState, PVOID pbResult, SIZE_T cbResult);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_KMAC_EXTRACT) (SCOSSL_KMAC_STATE *pState, PVOID pbOutput, SIZE_T cbOutput, BOOLEAN bWipe);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_KMAC_KEY_COPY) (SCOSSL_KMAC_EXPANDED_KEY *pSrc, SCOSSL_KMAC_EXPANDED_KEY *pDst);
typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_KMAC_STATE_COPY) (SCOSSL_KMAC_STATE *pSrc, SCOSSL_KMAC_STATE *pDst);

typedef struct
{
    PSYMCRYPT_KMAC_EXPAND_KEY_EX expandKeyExFunc;
    PSYMCRYPT_KMAC_RESULT_EX     resultExFunc;
    PSYMCRYPT_KMAC_EXTRACT       extractFunc;
    PSYMCRYPT_KMAC_KEY_COPY      keyCopyFunc;
    PSYMCRYPT_KMAC_STATE_COPY    stateCopyFunc;
    SIZE_T blockSize;
} SCOSSL_KMAC_EXTENSIONS;

extern const SCOSSL_KMAC_EXTENSIONS SymCryptKmac128AlgorithmEx;
extern const SCOSSL_KMAC_EXTENSIONS SymCryptKmac256AlgorithmEx;

#ifdef __cplusplus
}
#endif