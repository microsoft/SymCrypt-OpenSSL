//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "keysinuse.h"
#include "scossl_helpers.h"

#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>

#ifdef KEYSINUSE_LOG_SYSLOG
 #include <systemd/sd-journal.h>
#else
 #include <fcntl.h>
 #include <sys/stat.h>
#endif

#include <openssl/lhash.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    time_t firstLogTime;
    time_t lastLogTime;
    UINT32 signCounter;
    UINT32 decryptCounter;
    // The first 32 bytes of the SHA256 hash of the encoded public key.
    // Use the same encoding rules as the subjectPublicKey field of a certificate
    // (PKCS#1 format for RSA, octet string for ECDSA)
    char keyIdentifier[KEYSINUSE_KEYID_SIZE];
    INT32 refCount;
    CRYPTO_RWLOCK *lock;
} SCOSSL_KEYSINUSE_CTX_IMP;

// KeysInUse context lhash functions
static unsigned long scossl_keysinuse_ctx_hash(_In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx);
static int scossl_keysinuse_ctx_cmp(_In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx1, _In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx2);

#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR > 0
    DEFINE_LHASH_OF_EX(SCOSSL_KEYSINUSE_CTX_IMP);
#else
    DEFINE_LHASH_OF(SCOSSL_KEYSINUSE_CTX_IMP);
#endif

#if OPENSSL_VERSION_MAJOR < 3
    IMPLEMENT_LHASH_DOALL_ARG(SCOSSL_KEYSINUSE_CTX_IMP, VOID);
    #define lh_SCOSSL_KEYSINUSE_CTX_IMP_doall_arg lh_SCOSSL_KEYSINUSE_CTX_IMP_doall_void
#endif

// All keysinuse contexts are created and destroyed by the keysinuse module.
// The keysinuse contexts are refcounted and indexed in lh_keysinuse_ctx_imp by
// their keyIdentifier.
//
// The first call to keysinuse_load_key with a given keyIdentifier
// will create a new keysinuse context, increment its ref count, and add it
// to lh_keysinuse_ctx_imp. Subsequent calls will fetch the existing context
// and increment the refcount. When the ref count reaches zero, the context
// is freed and removed from lh_keysinuse_ctx_imp. When keysinuse_teardown
// is called, all keysinuse contexts are freed and removed from lh_keysinuse_ctx_imp.
static LHASH_OF(SCOSSL_KEYSINUSE_CTX_IMP) *lh_keysinuse_ctx_imp = NULL;
// This lock must be acquired before accessing lh_keysinuse_ctx_imp
// This lock is initialized in keysinuse_init_internal and should only be
// freed in keysinuse_cleanup_internal
static CRYPTO_RWLOCK *lh_keysinuse_ctx_imp_lock = NULL;

//
// Configuration
//

static CRYPTO_ONCE keysinuse_init_once = CRYPTO_ONCE_STATIC_INIT;
static BOOL keysinuse_enabled = TRUE;
static BOOL keysinuse_running = FALSE;

static long max_file_size = 5 << 10; // Default to 5KB
static long logging_delay = 60 * 60; // Default to 1 hour

//
// Logging
//

#ifdef KEYSINUSE_LOG_SYSLOG
 #define KEYSINUSE_MESSAGE "key used"
 #define KEYSINUSE_SYSLOG_IDENTIFIER "keysinuse"
 #define KEYSINUSE_MESSAGE_ID "3bfb12b646534bf0ac67e29b050a78e9"
#else
 // Log files separated by UID.
 // /var/log/keysinuse/keysinuse_<level>_<euid>.log
 #define LOG_DIR       "/var/log/keysinuse"
 #define LOG_PATH_TMPL LOG_DIR "/keysinuse_%.3s_%08x.log"
#endif

#define KEYSINUSE_ERR 0
#define KEYSINUSE_NOTICE 1

#define LOG_MSG_MAX 256

#ifndef KEYSINUSE_LOG_SYSLOG
static const char *default_prefix = "";
static char *prefix = NULL;
static int prefix_size = 0;
#endif

//
// Logging thread
//

// To minimize any overhead to crypto operations, all file writes are handled by
// logging_thread. This thread periodically looks at all of the contexts in
// lh_keysinuse_ctx_imp and logs any usage events that have occurred since the
// last time it logged. The thread sleeps for logging_delay seconds between
// iterations. The thread can be woken up early by signalling
// logging_thread_cond_wake_early when a key is first used.
static pthread_t logging_thread;
static pthread_cond_t logging_thread_cond_wake_early;
static pthread_mutex_t logging_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
// Predicate for logging_thread_cond_wake_early. Ensures any keys that
// were first used while the logging thread was logging are handled before
// the logging thread tries to sleep again. Only modify under logging_thread_mutex.
static BOOL first_use_pending = FALSE;
static BOOL is_logging = FALSE;
static SCOSSL_STATUS logging_thread_exit_status = SCOSSL_FAILURE;

//
// Internal function declarations
//

static void keysinuse_init_internal();
static void keysinuse_cleanup_internal();
static void keysinuse_teardown();

static void keysinuse_free_key_ctx(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx);
static void keysinuse_ctx_log(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _In_ PVOID doallArg);

static void keysinuse_log_common(int level, _In_ const char *message, va_list args);
static void keysinuse_log_error(_In_ const char *message, ...);
static void keysinuse_log_notice(_In_ const char *message, ...);

static void *keysinuse_logging_thread_start(ossl_unused void *arg);

//
// Setup/teardown
//

#ifndef KEYSINUSE_LOG_SYSLOG
static SCOSSL_STATUS keysinuse_init_logging()
{
    int mkdirResult;
    mode_t umaskOriginal;
    char *symlinkPath = NULL;
    int cbSymlink;
    char *procPath = NULL;
    int cbProcPath = PATH_MAX;
    int cbProcPathUsed = 0;
    pid_t pid = getpid();
    time_t initTime = time(NULL);
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    // Generate prefix for all log messages
    // <keysinuse init time>,<process path>

    // Fetch running process path from /proc/<pid>/exe. This path is a symbolic link.
    cbSymlink = snprintf(NULL, 0, "/proc/%d/exe", pid) + 1;
    symlinkPath = OPENSSL_malloc(cbSymlink);

    if (symlinkPath != NULL &&
        snprintf(symlinkPath, cbSymlink, "/proc/%d/exe", pid) > 0)
    {
        if ((procPath = OPENSSL_malloc(cbProcPath)) != NULL &&
            (cbProcPathUsed = readlink(symlinkPath, procPath, cbProcPath)) == -1)
        {
#ifndef KEYSINUSE_STANDALONE
            SCOSSL_PROV_LOG_DEBUG(SCOSSL_ERR_R_KEYSINUSE_FAILURE,
                "Failed to get process path from /proc/%d/exe with error %d", pid, errno);
#endif // KEYSINUSE_STANDALONE
            OPENSSL_free(procPath);
            procPath = NULL;
            cbProcPathUsed = 0;
        }
    }

    // Failure to generate the logging prefix is not fatal but makes it
    // harder to match events to running processes.
    prefix_size = snprintf(NULL, 0, "%ld,", initTime) + cbProcPathUsed;
    if ((prefix = OPENSSL_malloc(prefix_size + 1)) == NULL ||
        snprintf(prefix, prefix_size + 1, "%ld,%.*s", initTime, cbProcPathUsed, procPath) < 0)
    {
#ifndef KEYSINUSE_STANDALONE
        SCOSSL_PROV_LOG_DEBUG(SCOSSL_ERR_R_KEYSINUSE_FAILURE,
            "Failed to generate logging prefix with error %d", errno);
#endif // KEYSINUSE_STANDALONE
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
    }

    // Try to create /var/log/keysinuse if it isn't present.
    // This is a best attempt and only succeeds if the callers
    // has sufficient permissions
    umaskOriginal = umask(0);
    mkdirResult = mkdir(LOG_DIR, 01733);
    umask(umaskOriginal);

    if (mkdirResult == 0)
    {
        if (chown(LOG_DIR, 0, 0) == -1)
        {
            keysinuse_log_error("Failed to set ownership of logging directory at %s,SYS_%d", LOG_DIR, errno);
            rmdir(LOG_DIR);
            goto cleanup;
        }
    }
    else if (errno != EACCES && errno != EEXIST)
    {
        keysinuse_log_error("Failed to create logging directory at %s,SYS_%d", LOG_DIR, errno);
        goto cleanup;
    }

    status = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(symlinkPath);
    OPENSSL_free(procPath);

    return status;
}
#endif

static void keysinuse_init_internal()
{
    pthread_condattr_t attr;
    int pthreadErr;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    const char *env_enabled = getenv("KEYSINUSE_ENABLED");
    if (env_enabled != NULL)
    {
        if (strcmp(env_enabled, "0") == 0)
        {
            keysinuse_enabled = FALSE;
        }
    }

    if (!keysinuse_enabled)
    {
        return;
    }

    lh_keysinuse_ctx_imp_lock = CRYPTO_THREAD_lock_new();
    lh_keysinuse_ctx_imp = lh_SCOSSL_KEYSINUSE_CTX_IMP_new(scossl_keysinuse_ctx_hash, scossl_keysinuse_ctx_cmp);
    if (lh_keysinuse_ctx_imp_lock == NULL || lh_keysinuse_ctx_imp == NULL)
    {
        goto cleanup;
    }

#ifndef KEYSINUSE_LOG_SYSLOG
    if (!keysinuse_init_logging())
    {
        goto cleanup;
    }
#endif

    // Start the logging thread. Monotonic clock needs to be set to
    // prevent wall clock changes from affecting the logging delay sleep time
    is_logging = TRUE;
    if ((pthreadErr = pthread_condattr_init(&attr)) != 0 ||
        (pthreadErr = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) != 0 ||
        (pthreadErr = pthread_cond_init(&logging_thread_cond_wake_early, &attr)) != 0 ||
        (pthreadErr = pthread_create(&logging_thread, NULL, keysinuse_logging_thread_start, NULL)) != 0)
    {
        keysinuse_log_error("Failed to start logging thread,SYS_%d", pthreadErr);
        is_logging = FALSE;
        goto cleanup;
    }

    keysinuse_running = TRUE;
    status = SCOSSL_SUCCESS;

#ifdef KEYSINUSE_LOG_SYSLOG
    keysinuse_log_notice("KeysInUse initialized");
#endif

cleanup:
    if (status == SCOSSL_FAILURE)
    {
        // lh_keysinuse_ctx_imp_lock should be freed in keysinuse_cleanup_internal
        keysinuse_enabled = FALSE;
        lh_SCOSSL_KEYSINUSE_CTX_IMP_free(lh_keysinuse_ctx_imp);
        lh_keysinuse_ctx_imp = NULL;
        keysinuse_teardown();
    }

    pthread_condattr_destroy(&attr);
}

// DO NOT call this function directly. It should only be called when
// the shared library is destroyed since it cleans up global state.
__attribute__((destructor)) static void keysinuse_cleanup_internal()
{
    keysinuse_teardown();

#ifndef KEYSINUSE_LOG_SYSLOG
    if (prefix != default_prefix)
    {
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
        prefix_size = 0;
    }
#endif

    if (lh_keysinuse_ctx_imp != NULL)
    {
        lh_SCOSSL_KEYSINUSE_CTX_IMP_doall(lh_keysinuse_ctx_imp, keysinuse_free_key_ctx);
        lh_SCOSSL_KEYSINUSE_CTX_IMP_free(lh_keysinuse_ctx_imp);
        lh_keysinuse_ctx_imp = NULL;
    }

    pthread_cond_destroy(&logging_thread_cond_wake_early);

    CRYPTO_THREAD_lock_free(lh_keysinuse_ctx_imp_lock);
    lh_keysinuse_ctx_imp_lock = NULL;
}

void keysinuse_init()
{
    CRYPTO_THREAD_run_once(&keysinuse_init_once, keysinuse_init_internal);
}

void keysinuse_teardown()
{
    int pthreadErr;

    keysinuse_running = FALSE;

    // Finish logging thread. The logging thread will call keysinuse_cleanup
    // and free all references to any keysinuse contexts it still has a reference to.
    if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
    {
        if (is_logging)
        {
            is_logging = FALSE;
            pthread_cond_signal(&logging_thread_cond_wake_early);
            pthread_mutex_unlock(&logging_thread_mutex);

            if ((pthreadErr = pthread_join(logging_thread, NULL)) != 0)
            {
                keysinuse_log_error("Failed to join logging thread,SYS_%d", pthreadErr);
            }
            else if (logging_thread_exit_status != SCOSSL_SUCCESS)
            {
                keysinuse_log_error("Logging thread exited with status %d", logging_thread_exit_status);
            }
        }
        else
        {
            pthread_mutex_unlock(&logging_thread_mutex);
        }
    }
    else
    {
        keysinuse_log_error("Cleanup failed to acquire mutex,SYS_%d", pthreadErr);
    }

#ifdef KEYSINUSE_LOG_SYSLOG
    keysinuse_log_notice("KeysInUse stopped");
#endif
}

void keysinuse_disable()
{
    keysinuse_enabled = FALSE;

    // Ensure keysinuse_init has completed in case another
    // thread is in the middle of keysinuse_init
    keysinuse_init();

    keysinuse_teardown();
}

int keysinuse_is_running()
{
    // Try to initialize keysinuse if it hasn't been already
    keysinuse_init();
    return keysinuse_enabled && keysinuse_running;
}

//
// Configuration
//
void keysinuse_set_max_file_size(long size)
{
    if (size > 0)
    {
        max_file_size = (off_t) size;
    }
}

void keysinuse_set_logging_delay(long delay)
{
    if (delay >= 0)
    {
        logging_delay = delay;
    }
}

//
// KeysInUse context lhash functions
//
_Use_decl_annotations_
static unsigned long scossl_keysinuse_ctx_hash(const SCOSSL_KEYSINUSE_CTX_IMP *ctx)
{
    return ctx == NULL ? 0 : OPENSSL_LH_strhash(ctx->keyIdentifier);
}

_Use_decl_annotations_
static int scossl_keysinuse_ctx_cmp(const SCOSSL_KEYSINUSE_CTX_IMP *ctx1, const SCOSSL_KEYSINUSE_CTX_IMP *ctx2)
{
    if (ctx1 == ctx2)
    {
        return 0;
    }

    if (ctx1 != NULL && ctx2 == NULL)
    {
        return 1;
    }

    if (ctx2 != NULL && ctx1 == NULL)
    {
        return -1;
    }

    return memcmp(ctx1->keyIdentifier, ctx2->keyIdentifier, sizeof(ctx1->keyIdentifier));
}

//
// KeysInUse context management
//
_Use_decl_annotations_
SCOSSL_STATUS keysinuse_ctx_upref(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _Out_ INT32 *refOut)
{
    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&ctx->refCount, 1, &ref, ctx->lock))
    {
        keysinuse_log_error("keysinuse_ctx_upref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }

    if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS keysinuse_ctx_downref(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _Out_ INT32 *refOut)
{
    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&ctx->refCount, -1, &ref, ctx->lock))
    {
        keysinuse_log_error("keysinuse_ctx_downref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }

    if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

unsigned int keysinuse_derive_key_identifier(_In_reads_bytes_(cbEncodedKey) const void *pbEncodedKey, unsigned long cbEncodedKey,
                                             _Out_writes_bytes_opt_(cbEncodedKey)char *pbKeyIdentifier, unsigned long cbKeyIdentifier)
{
    BYTE abHash[SYMCRYPT_SHA256_RESULT_SIZE];
    UINT cbHash = SYMCRYPT_SHA256_RESULT_SIZE;

    if (pbKeyIdentifier == NULL)
    {
        return KEYSINUSE_KEYID_SIZE;
    }

    if (cbKeyIdentifier < KEYSINUSE_KEYID_SIZE)
    {
        keysinuse_log_error("Insufficient buffer size for key identifier");
        return 0;
    }

    if (EVP_Digest(pbEncodedKey, cbEncodedKey, abHash, &cbHash, EVP_sha256(), NULL) <= 0)
    {
        keysinuse_log_error("EVP_Digest failed,OPENSSL_%d", ERR_get_error());
        return 0;
    }

    for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE / 2; i++)
    {
        sprintf(&pbKeyIdentifier[i*2], "%02x", abHash[i]);
    }
    pbKeyIdentifier[KEYSINUSE_KEYID_SIZE - 1] = '\0';

    return KEYSINUSE_KEYID_SIZE;
}

SCOSSL_KEYSINUSE_CTX *keysinuse_load_key(_In_reads_bytes_opt_(cbEncodedKey) const void *pbEncodedKey, unsigned long cbEncodedKey)
{
    SCOSSL_KEYSINUSE_CTX_IMP ctxTmpl;
    SCOSSL_KEYSINUSE_CTX_IMP *ctx = NULL;
    SCOSSL_KEYSINUSE_CTX_IMP *localCtx = NULL;
    int lhErr = 0;

    if (!keysinuse_is_running() ||
        pbEncodedKey == NULL || cbEncodedKey == 0)
    {
        goto cleanup;
    }

    if (keysinuse_derive_key_identifier(pbEncodedKey, cbEncodedKey, ctxTmpl.keyIdentifier, sizeof(ctxTmpl.keyIdentifier)) == 0)
    {
        goto cleanup;
    }

    if (CRYPTO_THREAD_read_lock(lh_keysinuse_ctx_imp_lock))
    {
        if (lh_keysinuse_ctx_imp != NULL)
        {
            ctx = lh_SCOSSL_KEYSINUSE_CTX_IMP_retrieve(lh_keysinuse_ctx_imp, &ctxTmpl);
        }

        CRYPTO_THREAD_unlock(lh_keysinuse_ctx_imp_lock);

        if (lh_keysinuse_ctx_imp == NULL)
        {
            keysinuse_log_error("Keysinuse context hash table is missing in keysinuse_load_key");
            goto cleanup;
        }
    }
    else
    {
        keysinuse_log_error("Failed to lock keysinuse context hash table for reading in keysinuse_load_key,OPENSSL_%d", ERR_get_error());
        goto cleanup;
    }

    if (ctx == NULL)
    {
        // New key used for keysinuse. Create a new context and add it to the hash table
        if ((localCtx = OPENSSL_zalloc(sizeof(SCOSSL_KEYSINUSE_CTX_IMP))) == NULL ||
            (localCtx->lock = CRYPTO_THREAD_lock_new()) == NULL)
        {
            keysinuse_log_error("malloc failure in keysinuse_load_key,OPENSSL_%d", ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        memcpy(localCtx->keyIdentifier, ctxTmpl.keyIdentifier, sizeof(ctxTmpl.keyIdentifier));
        localCtx->refCount = 1;

        if (CRYPTO_THREAD_write_lock(lh_keysinuse_ctx_imp_lock))
        {
            if (lh_keysinuse_ctx_imp != NULL)
            {
                // Make sure another thread didn't add the context while we were waiting for the lock
                ctx = lh_SCOSSL_KEYSINUSE_CTX_IMP_retrieve(lh_keysinuse_ctx_imp, localCtx);
                if (ctx == NULL)
                {
                    // Add the new context to the hash table
                    lh_SCOSSL_KEYSINUSE_CTX_IMP_insert(lh_keysinuse_ctx_imp, localCtx);

                    if ((lhErr = lh_SCOSSL_KEYSINUSE_CTX_IMP_error(lh_keysinuse_ctx_imp)))
                    {
                        keysinuse_log_error("Failed to add new keysinuse context to the hash table,OPENSSL_%d", ERR_get_error());
                    }
                    else
                    {
                        // Don't free localCtx now since it's owned by the hash table
                        ctx = localCtx;
                        localCtx = NULL;
                    }
                }
                // Another thread added the context, try to upref and use it instead
                else if (keysinuse_ctx_upref(ctx, NULL) != SCOSSL_SUCCESS)
                {
                    ctx = NULL;
                }
            }
            else
            {
                keysinuse_log_error("Keysinuse context hash table is missing in keysinuse_load_key");
            }

            CRYPTO_THREAD_unlock(lh_keysinuse_ctx_imp_lock);

            if (ctx == NULL)
            {
                goto cleanup;
            }
        }
        else
        {
            keysinuse_log_error("Failed to lock keysinuse context hash table in keysinuse_load_key,OPENSSL_%d", ERR_get_error());
            goto cleanup;
        }
    }
    else if (keysinuse_ctx_upref(ctx, NULL) != SCOSSL_SUCCESS)
    {
        ctx = NULL;
        goto cleanup;
    }

cleanup:
    keysinuse_free_key_ctx(localCtx);

    return ctx;
}

SCOSSL_KEYSINUSE_CTX *keysinuse_load_key_by_ctx(_In_opt_ SCOSSL_KEYSINUSE_CTX *ctx)
{
    if (keysinuse_is_running() && ctx != NULL &&
        keysinuse_ctx_upref(ctx, NULL) == SCOSSL_SUCCESS)
    {
        return ctx;
    }

    return NULL;
}

void keysinuse_unload_key(_In_opt_ SCOSSL_KEYSINUSE_CTX *ctx)
{
    if (keysinuse_is_running() && ctx != NULL)
    {
        // Don't free the key context here. The logging thread will free the context
        // and remove it from the hash table after logging any pending usage events.
        keysinuse_ctx_downref(ctx, NULL);
    }
}

unsigned int keysinuse_ctx_get_key_identifier(_In_ SCOSSL_KEYSINUSE_CTX *ctx,
                                              _Out_writes_bytes_opt_(cbEncodedKey)char *pbKeyIdentifier, unsigned long cbKeyIdentifier)
{
    SCOSSL_KEYSINUSE_CTX_IMP *ctxImp = (SCOSSL_KEYSINUSE_CTX_IMP*)ctx;

    if (!keysinuse_is_running() ||
        ctxImp == NULL)
    {
        return 0;
    }

    if (pbKeyIdentifier == NULL)
    {
        return KEYSINUSE_KEYID_SIZE;
    }

    if (cbKeyIdentifier < KEYSINUSE_KEYID_SIZE)
    {
        keysinuse_log_error("Insufficient buffer size for key identifier, expected %d, got %lu", KEYSINUSE_KEYID_SIZE, cbKeyIdentifier);
        return 0;
    }

    if (CRYPTO_THREAD_read_lock(ctxImp->lock))
    {
        memcpy(pbKeyIdentifier, ctxImp->keyIdentifier, KEYSINUSE_KEYID_SIZE);

        CRYPTO_THREAD_unlock(ctxImp->lock);
    }
    else
    {
        keysinuse_log_error("Failed to lock keysinuse context in keysinuse_ctx_get_key_identifier,OPENSSL_%d", ERR_get_error());
    }

    return KEYSINUSE_KEYID_SIZE;
}

_Use_decl_annotations_
static void keysinuse_free_key_ctx(SCOSSL_KEYSINUSE_CTX_IMP *ctx)
{
    if (ctx == NULL)
        return;

    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_free(ctx);
}

//
// Usage tracking
//
void keysinuse_on_use(_In_ SCOSSL_KEYSINUSE_CTX *ctx, KEYSINUSE_OPERATION operation)
{
    SCOSSL_KEYSINUSE_CTX_IMP *ctxImp = (SCOSSL_KEYSINUSE_CTX_IMP*)ctx;
    int pthreadErr;
    BOOL wakeLoggingThread = FALSE;

    if (!keysinuse_is_running() ||
        ctxImp == NULL)
    {
        return;
    }

    if (CRYPTO_THREAD_write_lock(ctxImp->lock))
    {
        // Increment appropriate usage counter
        switch (operation)
        {
        case KEYSINUSE_SIGN:
            ctxImp->signCounter++;
            break;
        case KEYSINUSE_DECRYPT:
            ctxImp->decryptCounter++;
            break;
        default:
            keysinuse_log_error("Invalid operation in keysinuse_on_use: %d", operation);
            CRYPTO_THREAD_unlock(ctxImp->lock);
            return;
        }

        // First use of this key, wake the logging thread
        if (ctxImp->firstLogTime == 0)
        {
            wakeLoggingThread = TRUE;
        }

        CRYPTO_THREAD_unlock(ctxImp->lock);
    }
    else
    {
        keysinuse_log_error("Failed to lock keysinuse context in keysinuse_on_use,OPENSSL_%d", ERR_get_error());
    }

    if (wakeLoggingThread)
    {
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
        {
            first_use_pending = TRUE;

            if ((pthreadErr = pthread_cond_signal(&logging_thread_cond_wake_early)) != 0)
            {
                keysinuse_log_error("Failed to signal logging thread in keysinuse_on_use,SYS_%d", pthreadErr);
            }
            pthread_mutex_unlock(&logging_thread_mutex);
        }
        else
        {
            keysinuse_log_error("Failed to lock logging thread mutex in keysinuse_on_use,SYS_%d", pthreadErr);
        }
    }
}

// This function should only be called by the logging thread using lh_SCOSSL_KEYSINUSE_CTX_IMP_doall_arg.
// This function assumes that the caller has already acquired the write lock on lh_keysinuse_ctx_imp_lock,
// and that it is safe to call lh_SCOSSL_KEYSINUSE_CTX_IMP_delete (the lhash load factor has been set to 0)
_Use_decl_annotations_
static void keysinuse_ctx_log(SCOSSL_KEYSINUSE_CTX_IMP *ctxImp, PVOID doallArg)
{
    BOOL logEvent = FALSE;
    BOOL freeCtx = FALSE;
    BOOL isScheduledLogEvent;
    time_t now;
    SCOSSL_KEYSINUSE_CTX_IMP ctxImpTmp;

    if (ctxImp == NULL ||
        doallArg == NULL)
    {
        return;
    }

    isScheduledLogEvent = *(BOOL*)doallArg;

    if (CRYPTO_THREAD_write_lock(ctxImp->lock))
    {
        // If the logging thread woke up early due to a key's first use, we only
        // log the first used key(s). Any other keys with pending events will be
        // logged on the logging thread's regular cadence.
        if ((ctxImp->lastLogTime == 0 || isScheduledLogEvent) &&
            (ctxImp->decryptCounter + ctxImp->signCounter > 0))
        {
            now = time(NULL);

            ctxImp->firstLogTime = ctxImp->lastLogTime == 0 ? now : ctxImp->firstLogTime;
            ctxImp->lastLogTime = now;

            // We copy the keysinuse context to a temporary struct to avoid unnecessarily holding
            // the lock during the logging operation.
            ctxImpTmp = *ctxImp;

            ctxImp->decryptCounter = 0;
            ctxImp->signCounter = 0;

            logEvent = TRUE;
        }

        if (ctxImp->refCount == 0)
        {
            freeCtx = TRUE;
        }

        CRYPTO_THREAD_unlock(ctxImp->lock);
    }
    else
    {
        keysinuse_log_error("Failed to lock keysinuse context in keysinuse_ctx_log,OPENSSL_%d", ERR_get_error());
        return;
    }

    if (logEvent)
    {
#ifdef KEYSINUSE_LOG_SYSLOG
        sd_journal_send("MESSAGE=%s: %s", KEYSINUSE_MESSAGE, ctxImpTmp.keyIdentifier,
                        "MESSAGE_ID=%s", KEYSINUSE_MESSAGE_ID,
                        "PRIORITY=%d", LOG_NOTICE,
                        "SYSLOG_IDENTIFIER=%s", KEYSINUSE_SYSLOG_IDENTIFIER,
                        "KEYSINUSE_KEYID=%s", ctxImpTmp.keyIdentifier,
                        "KEYSINUSE_SIGN_COUNT=%d", ctxImpTmp.signCounter,
                        "KEYSINUSE_DECRYPT_COUNT=%d", ctxImpTmp.decryptCounter,
                        "KEYSINUSE_FIRST_LOG_TIME=%ld", ctxImpTmp.firstLogTime,
                        "KEYSINUSE_LAST_LOG_TIME=%ld", ctxImpTmp.lastLogTime,
                        NULL);
#else
        keysinuse_log_notice("%s,%d,%d,%ld,%ld",
            ctxImpTmp.keyIdentifier,
            ctxImpTmp.signCounter,
            ctxImpTmp.decryptCounter,
            ctxImpTmp.firstLogTime,
            ctxImpTmp.lastLogTime);
#endif
    }

    if (freeCtx)
    {
        lh_SCOSSL_KEYSINUSE_CTX_IMP_delete(lh_keysinuse_ctx_imp, ctxImp);
        keysinuse_free_key_ctx(ctxImp);
    }
}

//
// Logging
//

_Use_decl_annotations_
static void keysinuse_log_common(int level, const char *message, va_list args)
#ifdef KEYSINUSE_LOG_SYSLOG
{
    int priority = LOG_NOTICE;
    char msg_buf[LOG_MSG_MAX];
    int msg_len;

    if (level == KEYSINUSE_ERR)
    {
        priority = LOG_WARNING;
    }

    if ((msg_len = vsnprintf(msg_buf, LOG_MSG_MAX, message, args)) > 0)
    {
        sd_journal_send("MESSAGE=%s", msg_buf,
                        "MESSAGE_ID=%s", KEYSINUSE_MESSAGE_ID,
                        "PRIORITY=%d", priority,
                        "SYSLOG_IDENTIFIER=%s", KEYSINUSE_SYSLOG_IDENTIFIER,
                        NULL);
    }
}
#else
{
    char *level_str = "not";
    // (Length of LOG_PATH_TMPL) - (8 for format specifiers)
    //  + (3 for level) + (8 for euid) + (1 for null terminator)
    char log_path[sizeof(LOG_PATH_TMPL) + 4];
    char msg_buf[LOG_MSG_MAX];
    int msg_len;

    if (level == KEYSINUSE_ERR)
    {
        level_str = "err";
    }

    uid_t euid = geteuid();

    sprintf(log_path, LOG_PATH_TMPL, level_str, euid);

    if ((msg_len = vsnprintf(msg_buf, LOG_MSG_MAX, message, args)) > 0)
    {
        int len = prefix_size + msg_len + 6;
        char prefixed_msg[len + 1];
        snprintf(prefixed_msg, len + 1, "%s,%s!%s\n", prefix, level_str, msg_buf);

        // Check the log file to make sure:
        // 1. File isn't a symlink
        // 2. File permissions are 0200
        // 3. Logging won't exceed maximum file size
        struct stat sb;
        if (stat(log_path, &sb) != -1)
        {
            BOOL isBadFile = FALSE;
            if (S_ISLNK(sb.st_mode))
            {
                if (level > KEYSINUSE_ERR)
                {
                    keysinuse_log_error("Found symlink at %s. Removing file", log_path);
                }
#ifdef DEBUG
                else
                {
                    fprintf(stderr, "Found symlink at %s. Removing file\n", log_path);
                }
#endif // DEBUG

                isBadFile = TRUE;
            }

            if (!isBadFile && (sb.st_mode & 0777) != 0200)
            {
                if (level > KEYSINUSE_ERR)
                {
                    keysinuse_log_error("Found unexpected permissions (%o) on %s. Removing file", (sb.st_mode & 0777), log_path);
                }
#ifdef DEBUG
                else
                {
                    fprintf(stderr, "Found unexpected permissions (%o) on %s. Removing file\n", (sb.st_mode & 0777), log_path);
                }
#endif // DEBUG
                isBadFile = TRUE;
            }

            if (isBadFile)
            {
                if (remove(log_path) != 0)
                {
                    if (level > KEYSINUSE_ERR)
                    {
                        keysinuse_log_error("Failed to remove bad log file at %s,SYS_%d", log_path, errno);
                    }
#ifdef DEBUG
                    else
                    {
                        fprintf(stderr, "Failed to remove bad log file at %s,SYS_%d\n", log_path, errno);
                    }
#endif // DEBUG
                    return;
                }
            }
            else if (sb.st_size + len > max_file_size)
            {
                if (level > KEYSINUSE_ERR)
                {
                    keysinuse_log_error("Failed to log to %s. File size capped at %ld bytes", log_path, max_file_size);
                }
#ifdef DEBUG
                else
                {
                    fprintf(stderr, "Failed to log to %s. File size capped at %ld bytes\n", log_path, max_file_size);
                }
#endif // DEBUG
                return;
            }
        }
        else if (errno != ENOENT)
        {
            if (level > KEYSINUSE_ERR)
            {
                keysinuse_log_error("Failed to stat file at %s,SYS_%d", log_path, errno);
            }
#ifdef DEBUG
            else
            {
                fprintf(stderr, "Failed to stat file at %s,SYS_%d\n", log_path, errno);
            }
#endif // DEBUG
            return;
        }

        // Log files are separated by euid. Only write access is needed
        int fd;
        for (int i = 0; i < 3; i++)
        {
            fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0200);
            if (fd >= 0 || errno != EACCES)
            {
                break;
            }
            usleep(500); // Sleep for 500 microseconds
        }

        if (fd < 0)
        {
            if (level > KEYSINUSE_ERR)
            {
                keysinuse_log_error("Failed to open log file for appending at %s,SYS_%d", log_path, errno);
            }
#ifdef DEBUG
            else
            {
                fprintf(stderr, "Failed to open log file for appending at %s,SYS_%d\n", log_path, errno);
            }
#endif // DEBUG
            return;
        }
        fchmod(fd, 0200);

        if (write(fd, prefixed_msg, len) < 0)
        {
            if (level > KEYSINUSE_ERR)
            {
                keysinuse_log_error("Failed to write to log file at %s,SYS_%d", log_path, errno);
            }
#ifdef DEBUG
            else
            {
                fprintf(stderr, "Failed to write to log file at %s,SYS_%d\n", log_path, errno);
            }
#endif // DEBUG
        }

        if (close(fd) < 0)
        {
            if (level > KEYSINUSE_ERR)
            {
                keysinuse_log_error("Failed to close log file at %s,SYS_%d", log_path, errno);
            }
#ifdef DEBUG
            else
            {
                fprintf(stderr, "Failed to close log file at %s,SYS_%d\n", log_path, errno);
            }
#endif // DEBUG
        }
    }
}
#endif // KEYSINUSE_LOG_SYSLOG

// Used for logging keysinuse related errors to a separate log file.
// This avoids poluting the error stack with keysinuse related errors.
_Use_decl_annotations_
static void keysinuse_log_error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    keysinuse_log_common(KEYSINUSE_ERR, message, args);
    va_end(args);
}

_Use_decl_annotations_
static void keysinuse_log_notice(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    keysinuse_log_common(KEYSINUSE_NOTICE, message, args);
    va_end(args);
}

// The logging thread runs in a loop. It checks every context in lh_keysinuse_ctx_imp, to
// determine if they have unlogged usage. If the sign or decrypt counters are non-zero,
// the context is logged as a usage event and the counters are reset. It sleeps for
// logging_delay seconds between each iteration. On the first use of a key, the thread
// is woken immediately and logs all contexts with a first usage. Any contexts that have
// been logged will be skipped until the logging thread wakes up normally. All pending
// events are logged on program exit.
_Use_decl_annotations_
static void *keysinuse_logging_thread_start(ossl_unused void *arg)
{
    // Logging thread is terminated by setting is_logging to FALSE and signaling logging_thread_cond_wake_early
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    BOOL isLoggingThreadRunning = TRUE;
    BOOL isScheduledLogEvent;

    struct timespec abstime;
    int pthreadErr;
    int waitStatus;

    unsigned long lhDownLoad;

    do
    {
        // This is the exit point for the logging thread. In that case, is_logging should be FALSE,
        // and logging_thread_cond_wake_early should be signalled. All pending events are logged
        // before the thread exits.
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
        {
            waitStatus = ETIMEDOUT;

            if (is_logging)
            {
                // Only wait if no first use events are pending. Some may have been added while
                // this thread was logging. In that case immediately handle those events before
                // attempting to wait again.
                if (first_use_pending)
                {
                    // Another thread may add an event to the stack and set this to TRUE again
                    // after the logging thread exits this critical section. In that case, the
                    // event will be handled in this iteration, and the next loop will be a no-op.
                    first_use_pending = FALSE;
                    waitStatus = 0;
                }

                if (waitStatus != 0)
                {
                    clock_gettime(CLOCK_MONOTONIC, &abstime);
                    abstime.tv_sec += logging_delay;

                    // Wait until logging_delay has elapsed or the thread is signaled early. logging_thread_mutex is
                    // unlocked by pthread_cond_timedwait so first use events can be signalled.
                    waitStatus = pthread_cond_timedwait(&logging_thread_cond_wake_early, &logging_thread_mutex, &abstime);

                    // If we are exiting, then treat this iteration like a timeout and log all pending events, even
                    // if the condition was signalled early.
                    if (!is_logging)
                    {
                        waitStatus = ETIMEDOUT;
                        isLoggingThreadRunning = FALSE;
                    }
                }
            }
            else
            {
                // If we are exiting, then treat this iteration like a timeout and log all pending events
                isLoggingThreadRunning = FALSE;
            }
            pthread_mutex_unlock(&logging_thread_mutex);
        }

        if (pthreadErr != 0)
        {
            keysinuse_log_error("Logging thread failed to acquire mutex,SYS_%d", pthreadErr);
            goto cleanup;
        }

        if (waitStatus != 0 && waitStatus != ETIMEDOUT)
        {
            keysinuse_log_error("Logging thread woken up with unexpected status, SYS_%d", waitStatus);
            goto cleanup;
        }

        if (CRYPTO_THREAD_write_lock(lh_keysinuse_ctx_imp_lock))
        {
            if (lh_keysinuse_ctx_imp != NULL)
            {
                // Set load factor to 0 during this operation to prevent hash table contraction.
                // This allows us to safely call lh_SCOSSL_KEYSINUSE_CTX_IMP_delete from
                // keysinuse_ctx_log to safely remove contexts with no more references.
                lhDownLoad = lh_SCOSSL_KEYSINUSE_CTX_IMP_get_down_load(lh_keysinuse_ctx_imp);
                lh_SCOSSL_KEYSINUSE_CTX_IMP_set_down_load(lh_keysinuse_ctx_imp, 0);

                isScheduledLogEvent = waitStatus == ETIMEDOUT;
                lh_SCOSSL_KEYSINUSE_CTX_IMP_doall_arg(lh_keysinuse_ctx_imp, keysinuse_ctx_log, &isScheduledLogEvent);

                lh_SCOSSL_KEYSINUSE_CTX_IMP_set_down_load(lh_keysinuse_ctx_imp, lhDownLoad);
            }

            CRYPTO_THREAD_unlock(lh_keysinuse_ctx_imp_lock);

            if (lh_keysinuse_ctx_imp == NULL)
            {
                keysinuse_log_error("Keysinuse context hash table is missing in logging thread");
                goto cleanup;
            }
        }
        else
        {
            keysinuse_log_error("Logging thread failed to lock keysinuse context hash table for writing,OPENSSL_%d", ERR_get_error());
            goto cleanup;
        }
    }
    while (isLoggingThreadRunning);

    logging_thread_exit_status = SCOSSL_SUCCESS;

cleanup:
    is_logging = FALSE;
    keysinuse_running = FALSE;

    return NULL;
}

#ifdef __cplusplus
}
#endif