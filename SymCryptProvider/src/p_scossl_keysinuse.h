#include <scossl_helpers.h>
#include <openssl/safestack.h>

#define TRUNCATED_DIGEST_LENGTH (SYMCRYPT_SHA256_RESULT_SIZE / 2)
#define KEY_IDENTIFIER_CHAR_SIZE (TRUNCATED_DIGEST_LENGTH * 2 + 1)

// This structure is refcounted and only freed when all references are freed.
// The key object this is associated with may be freed, but logging events may
// be pending according to the logging backoff.
typedef struct
{
    time_t first_use;
    time_t last_logged_use;
    UINT signCounter;
    UINT decryptCounter;
    char key_identifier[KEY_IDENTIFIER_CHAR_SIZE];
    BOOL logPending;
    INT32 refCount;
    CRYPTO_RWLOCK *lock;
} SCOSSL_PROV_KEYSINUSE_INFO;

DEFINE_STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO);

BOOL p_scossl_is_keysinuse_enabled();

SCOSSL_STATUS p_scsossl_keysinuse_init();
void p_scossl_keysinuse_cleanup();

SCOSSL_PROV_KEYSINUSE_INFO *p_scossl_keysinuse_info_new(_In_ char key_identifier[static KEY_IDENTIFIER_CHAR_SIZE]);
void p_scossl_keysinuse_info_free(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuse);

SCOSSL_STATUS p_scossl_keysinuse_upref(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, _Out_ INT32 *refOut);
SCOSSL_STATUS p_scossl_keysinuse_downref(_Inout_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, _Out_ INT32 *refOut);

void p_scossl_keysinuse_add_use(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, BOOL isSigning);
void p_scossl_keysinuse_log_error(const char *message, ...);
void p_scossl_keysinuse_log_pending_usage();