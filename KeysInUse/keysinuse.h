//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    KEYSINUSE_SIGN,
    KEYSINUSE_DECRYPT
} KEYSINUSE_OPERATION;

typedef void SCOSSL_KEYSINUSE_CTX;  // Exported opaque type

//
// Initialization and teardown
//

// Initializes KeysInUse. Calling this function is optional, since
// it will be called automatically by the first call to the other
// KeysInUse functions. Call this function explicitly if you want
// KeysInUse initialization to happen earlier (e.g., during provider init)
void keysinuse_init();

// Disables KeysInUse for the running process. If KeysInUse is
// already initialized, this function will also tear down KeysInUse
void keysinuse_disable();

// Quick check for callers to see if keysinuse is enabled.
// KeysInUse may be disabled between checking this and calling
// additional keysinuse functions, but callers can use this
// to avoid unnecessary work (e.g. encoding the public key) if
// KeysInUse is already disabled.
int keysinuse_is_running();

//
// Configuration
//

// If an invalid config value is passed, the respective default is used instead
void keysinuse_set_max_file_size(long size);
void keysinuse_set_logging_delay(long delay);

// Computes the key identifier for the encoded public key pbEncodedKey.
// Writes the result of to pbKeyIdentifier, which must be large enough
// to hold the key identifier. If pbKeyIdentifier is NULL, the function will
// return the minimum size required to hold the key identifier.
// On success, the function returns the number of bytes written to pbKeyIdentifier.
unsigned int keysinuse_derive_key_identifier(const void *pbEncodedKey, unsigned long cbEncodedKey,
                                             char *pbKeyIdentifier, unsigned long cbKeyIdentifier);

//
// KeysInUse context management
//
SCOSSL_KEYSINUSE_CTX *keysinuse_load_key(const void *pbEncodedKey, unsigned long cbEncodedKey);
SCOSSL_KEYSINUSE_CTX *keysinuse_load_key_by_ctx(SCOSSL_KEYSINUSE_CTX *ctx);
void keysinuse_unload_key(SCOSSL_KEYSINUSE_CTX *ctx);

// Copies the key identifier from an existing keysinuseCtx to pbKeyIdentifier,
// If pbKeyIdentifier is NULL, the function will return the minimum size required
// to hold the key identifier.
// On success, the function returns the number of bytes written to pbKeyIdentifier.
unsigned int keysinuse_ctx_get_key_identifier(SCOSSL_KEYSINUSE_CTX *ctx, char *pbKeyIdentifier, unsigned long cbKeyIdentifier);

//
// Usage tracking
//
void keysinuse_on_use(SCOSSL_KEYSINUSE_CTX *ctx, KEYSINUSE_OPERATION operation);

#ifdef __cplusplus
}
#endif