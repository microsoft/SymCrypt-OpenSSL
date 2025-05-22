//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    KEYSINUSE_SIGN,
    KEYSINUSE_DECRYPT
} keysinuse_operation;

typedef VOID SCOSSL_KEYSINUSE_CTX;  // Exported opaque type

// Initializes KeysInUse. Calling this function is optional, since
// it will be called automatically by the first call to the other
// KeysInUse functions. Call this function explicitly if you want
// KeysInUse initialization to happen earlier (e.g. during provider init)
void keysinuse_init();

// Disables KeysInUse for the running process. If KeysInUse is
// already initialized, this function will also tear down KeysInUse
void keysinuse_disable();

// Quick check for callers to see if keysinuse is enabled.
// KeysInUse may be disabled between checking this and calling
// additional keysinuse functions, but callers can use this
// to avoid unnecessary work (e.g. encoding the public key) if
// KeysInUse is already disabled.
BOOL keysinuse_is_running();

// Configuration

// If an invalid config value is passed, the respective default is used instead
void keysinuse_set_max_file_size(off_t size);
void keysinuse_set_logging_delay(INT64 delay);

// KeysInUse context management
SCOSSL_KEYSINUSE_CTX *keysinuse_load_key(_In_reads_bytes_opt_(cbEncodedKey) PCBYTE pbEncodedKey, SIZE_T cbEncodedKey);
SCOSSL_KEYSINUSE_CTX *keysinuse_load_key_by_ctx(_In_opt_ SCOSSL_KEYSINUSE_CTX *keysinuseCtx);
void keysinuse_unload_key(_Inout_ SCOSSL_KEYSINUSE_CTX *keysinuseCtx);

// Usage tracking
void keysinuse_on_use(_In_ SCOSSL_KEYSINUSE_CTX *keysinuseInfo, keysinuse_operation operation);

#ifdef __cplusplus
}
#endif