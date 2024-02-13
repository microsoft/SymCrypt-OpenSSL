#include <scossl_helpers.h>
#include <openssl/safestack.h>

// This structure is refcounted and only freed when all references are freed.
// The key object this is associated with may be freed, but logging events may
// be pending according to the logging backoff.
typedef struct
{
    time_t firstUse;
    time_t lastLoggedUse;
    UINT signCounter;
    UINT decryptCounter;
    // The first 32 bytes of the SHA256 hash of the public key,
    // encoded as a hex string
    char keyIdentifier[SYMCRYPT_SHA256_RESULT_SIZE + 1];
    BOOL logPending;
    INT32 refCount;
    CRYPTO_RWLOCK *lock;
} SCOSSL_PROV_KEYSINUSE_INFO;

DEFINE_STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO);

// Setup/teardown
SCOSSL_STATUS p_scsossl_keysinuse_init();
void p_scossl_keysinuse_cleanup();
BOOL p_scossl_keysinuse_is_enabled();

// Configureation
void p_scossl_keysinuse_set_logging_id(_In_ char *id);
SCOSSL_STATUS p_scossl_keysinuse_set_max_file_size(off_t size);
SCOSSL_STATUS p_scossl_keysinuse_set_logging_delay(INT64 delay);

// KeysInUse info management
SCOSSL_PROV_KEYSINUSE_INFO *p_scossl_keysinuse_info_new(_In_reads_bytes_(cbPublicKey) PBYTE pbPublicKey, SIZE_T cbPublicKey);
void p_scossl_keysinuse_info_free(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuse);
SCOSSL_STATUS p_scossl_keysinuse_upref(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, _Out_ INT32 *refOut);
SCOSSL_STATUS p_scossl_keysinuse_downref(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, _Out_ INT32 *refOut);

// Usage tracking
void p_scossl_keysinuse_on_sign(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo);
void p_scossl_keysinuse_on_decrypt(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo);