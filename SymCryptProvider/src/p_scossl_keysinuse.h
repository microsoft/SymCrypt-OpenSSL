//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <scossl_helpers.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef VOID SCOSSL_KEYSINUSE_CTX;  // Exported opaque type

// Setup/teardown
void p_scossl_keysinuse_init();         // Exported
void p_scossl_keysinuse_teardown();     // Exported

// Quick check for callers to see if keysinuse is enabled.
// KeysInUse may be disabled between checking this and calling
// additional keysinuse functions, but callers can use this
// to avoid unnecessary work (e.g. encoding the public key) if
// KeysInUse is already disabled.
BOOL p_scossl_keysinuse_is_enabled();   // Exported

// Configuration
// If an invalid config value is passed, the respective default is used instead
void p_scossl_keysinuse_set_logging_id(_In_ const char *id);
void p_scossl_keysinuse_set_max_file_size(off_t size);
void p_scossl_keysinuse_set_logging_delay(INT64 delay);

// KeysInUse context management
SCOSSL_KEYSINUSE_CTX *p_scossl_keysinuse_load_key(_In_reads_bytes_opt_(cbEncodedKey) PCBYTE pbEncodedKey, SIZE_T cbEncodedKey); // Exported
SCOSSL_KEYSINUSE_CTX *p_scossl_keysinuse_load_key_by_ctx(_In_opt_ SCOSSL_KEYSINUSE_CTX *keysinuseCtx);                          // Exported
void p_scossl_keysinuse_unload_key(_Inout_ SCOSSL_KEYSINUSE_CTX *keysinuseCtx);                                                 // Exported

// Usage tracking
void p_scossl_keysinuse_on_sign(_In_ SCOSSL_KEYSINUSE_CTX *keysinuseInfo);    // Exported
void p_scossl_keysinuse_on_decrypt(_In_ SCOSSL_KEYSINUSE_CTX *keysinuseInfo); // Exported

#ifdef __cplusplus
}
#endif