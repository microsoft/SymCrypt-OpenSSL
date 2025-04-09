//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/proverr.h>
#include <sys/stat.h>

#include "p_scossl_keysinuse.h"

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
    char keyIdentifier[SYMCRYPT_SHA256_RESULT_SIZE + 1];
    INT32 refCount;
    CRYPTO_RWLOCK *lock;
} SCOSSL_KEYSINUSE_CTX_IMP;

// KeysInUse context lhash functions
static unsigned long scossl_keysinuse_ctx_hash(_In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx);
static int scossl_keysinuse_ctx_cmp(_In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx1, _In_opt_ const SCOSSL_KEYSINUSE_CTX_IMP *ctx2);

static IMPLEMENT_LHASH_HASH_FN(scossl_keysinuse_ctx, SCOSSL_KEYSINUSE_CTX_IMP)
static IMPLEMENT_LHASH_COMP_FN(scossl_keysinuse_ctx, SCOSSL_KEYSINUSE_CTX_IMP)
DEFINE_LHASH_OF_EX(SCOSSL_KEYSINUSE_CTX_IMP);

// All keysinuse contexts are created and destroyed by the keysinuse module.
// The keysinuse contexts are refcounted and indexed in lh_keysinuse_info by
// their keyIdentifier.
//
// The first call to p_scossl_keysinuse_load_key with a given keyIdentifier
// will create a new keysinuse context, increment its ref count, and add it
// to lh_keysinuse_info. Subsequent calls will fetch the existing context
// and increment the refcount. When the ref count reaches zero, the context
// is freed and removed from lh_keysinuse_info. When p_scossl_keysinuse_teardown
// is called, all keysinuse contexts are freed and removed from lh_keysinuse_info.
static LHASH_OF(SCOSSL_KEYSINUSE_CTX) *lh_keysinuse_ctx = NULL;
// This lock must be acquired before accessing lh_keysinuse_ctx
static CRYPTO_RWLOCK *lh_keysinuse_ctx_lock = NULL;

//
// Configuration
//

// TODO: Check, what happens when I load the provider, unload it, and reload it?
static CRYPTO_ONCE keysinuse_init_once = CRYPTO_ONCE_STATIC_INIT;
static off_t max_file_size = 5 << 10; // Default to 5KB
static long logging_delay = 60 * 60; // Default to 1 hour
static BOOL keysinuse_enabled = FALSE;

// Number of times keysinuse has been initialized. If multiple providers are
// using keysinuse, then keysinuse will not clean up until all consumers have
// called p_scossl_keysinuse_teardown.
static int keysinuse_init_count = 0;

// This lock must be acquired for writing before accessing keysinuse_init_count
// or keysinuse_enabled. A read lock must be held for any sections that depend
// on the state of keysinuse_enabled being true.
// NOTE: The caller MUST NOT call any keysinuse functions after p_scossl_keysinuse_teardown.
static CRYPTO_RWLOCK *keysinuse_state_lock = NULL;

//
// Logging
//
#define KEYSINUSE_ERR 0
#define KEYSINUSE_NOTICE 1
// Log files separated by UID.
// /var/log/keysinuse/keysinuse_<level>_<euid>.log
#define LOG_DIR       "/var/log/keysinuse"
#define LOG_PATH_TMPL LOG_DIR "/keysinuse_%.3s_%08x.log"
#define LOG_MSG_MAX 256
static const char *default_prefix = "";
static char *prefix = NULL;
static int prefix_size = 0;

//
// Logging thread
//

// To minimize any overhead to crypto operations, all file writes are handled by
// logging_thread. This thread periodically pops all pending usage data from
// sk_keysinuse_info, and writes to the log file. The thread is signalled to
// wake early by logging_thread_cond_wake_early when a key is first used.
static pthread_t logging_thread;
static pthread_cond_t logging_thread_cond_wake_early;
static pthread_mutex_t logging_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
// Predicate for logging_thread_cond_wake_early. Ensures any keys that
// were first used while the logging thread was logging are handled before
// the logging thread tries to sleep again. Only modify under logging_thread_mutex.
static BOOL first_use_pending = FALSE;
static SCOSSL_STATUS logging_thread_exit_status = SCOSSL_FAILURE;
static BOOL is_logging = FALSE;

//
// Internal function declarations
//

static void p_scossl_keysinuse_init_once();

static void p_scossl_keysinuse_add_use(_In_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, BOOL isSigning);
static void p_scossl_keysinuse_ctx_log(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _In_ PCVOID doallArg);

static void p_scossl_keysinuse_log_common(int level, _In_ const char *message, va_list args);
static void p_scossl_keysinuse_log_error(_In_ const char *message, ...);
static void p_scossl_keysinuse_log_notice(_In_ const char *message, ...);

static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg);

//
// Setup/teardown
//

static void p_scossl_keysinuse_init_once()
{
    int mkdirResult;
    mode_t umaskOriginal;
    pid_t pid = getpid();
    time_t initTime = time(NULL);
    char *symlinkPath = NULL;
    int cbSymlink;
    char *procPath = NULL;
    int cbProcPath = PATH_MAX;
    int cbProcPathUsed = 0;
    pthread_condattr_t attr;
    int pthreadErr;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    keysinuse_state_lock = CRYPTO_THREAD_lock_new();
    lh_keysinuse_ctx_lock = CRYPTO_THREAD_lock_new();
    lh_keysinuse_ctx = lh_SCOSSL_KEYSINUSE_CTX_IMP_new(LHASH_HASH_FN(scossl_keysinuse_ctx), LHASH_COMP_FN(scossl_keysinuse_ctx));

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
            SCOSSL_PROV_LOG_DEBUG(SCOSSL_ERR_R_KEYSINUSE_FAILURE,
                "Failed to get process path from /proc/%d/exe with error %d", pid, errno);
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
        SCOSSL_PROV_LOG_DEBUG(SCOSSL_ERR_R_KEYSINUSE_FAILURE,
            "Failed to generate logging prefix with error %d", errno);
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
            p_scossl_keysinuse_log_error("Failed to set ownership of logging directory at %s,SYS_%d", LOG_DIR, errno);
            rmdir(LOG_DIR);
            goto cleanup;
        }
    }
    else if (errno != EACCES && errno != EEXIST)
    {
        p_scossl_keysinuse_log_error("Failed to create logging directory at %s,SYS_%d", LOG_DIR, errno);
        goto cleanup;
    }

    // Start the logging thread. Monotonic clock needs to be set to
    // prevent wall clock changes from affecting the logging delay sleep time
    is_logging = TRUE;
    if ((pthreadErr = pthread_condattr_init(&attr)) != 0 ||
        (pthreadErr = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) != 0 ||
        (pthreadErr = pthread_cond_init(&logging_thread_cond_wake_early, &attr)) != 0 ||
        (pthreadErr = pthread_create(&logging_thread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
    {
        p_scossl_keysinuse_log_error("Failed to start logging thread,SYS_%d", pthreadErr);
        is_logging = FALSE;
        goto cleanup;
    }

    keysinuse_enabled = TRUE;
    status = SCOSSL_SUCCESS;

cleanup:
    if (!status)
    {
        lh_SCOSSL_KEYSINUSE_CTX_IMP_free(lh_keysinuse_ctx);
        lh_keysinuse_ctx = NULL;
        p_scossl_keysinuse_teardown();
    }

    OPENSSL_free(symlinkPath);
    OPENSSL_free(procPath);
}

void p_scossl_keysinuse_init()
{
    int ref;
    CRYPTO_THREAD_run_once(&keysinuse_init_once, p_scossl_keysinuse_init_once);
    CRYPTO_atomic_add(&keysinuse_init_count, 1, &ref, keysinuse_state_lock);
}

// This function MUST only be called after keysinuse_enabled has been set to FALSE under lock.
// The other keysinuse functions will check keysinuse_enabled and do nothing if it is FALSE, so
// we can safely cleanup the keysinuse contexts saved in the keysinuse context lhash. Typically
// this will only happen when p_scossl_keysinuse_teardown is called, but may also happen if
// the logging thread exits early.
static void p_scossl_keysinuse_cleanup_lhash()
{
    if (CRYPTO_THREAD_write_lock(lh_keysinuse_ctx_lock))
    {
        if (lh_keysinuse_ctx != NULL)
        {
            lh_SCOSSL_KEYSINUSE_CTX_IMP_doall(lh_keysinuse_ctx, p_scossl_keysinuse_free_key_ctx);
            lh_SCOSSL_KEYSINUSE_CTX_IMP_free(lh_keysinuse_ctx);
            lh_keysinuse_ctx = NULL;
        }

        CRYPTO_THREAD_unlock(lh_keysinuse_ctx_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse context hash map,OPENSSL_%d", ERR_get_error());
    }
}

void p_scossl_keysinuse_teardown()
{
    int ref;
    int pthreadErr;

    CRYPTO_atomic_add(&keysinuse_init_count, -1, &ref, keysinuse_state_lock);
    if (ref == 0)
    {
        // Set keysinuse_enabled to FALSE in case the logging thread exits unexpectedly
        // and is unable to properly cleanup. We try to acquire the write lock. We should
        // still set keysinuse_enabled to false even if we fail to acquire the lock, since
        // keysinuse will no longer be in a running state.
        if (!CRYPTO_THREAD_write_lock(keysinuse_state_lock))
        {
            p_scossl_keysinuse_log_error("Failed to lock keysinuse state for writing,OPENSSL_%d", ERR_get_error());
        }

        keysinuse_enabled = FALSE;
        CRYPTO_THREAD_unlock(keysinuse_state_lock);

        // Finish logging thread. The logging thread will call p_scossl_keysinuse_cleanup
        // and free all references to any keysinuse contexts it still has a reference to.
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex) == 0))
        {
            if (is_logging)
            {
                is_logging = FALSE;
                pthread_cond_signal(&logging_thread_cond_wake_early);
                pthread_mutex_unlock(&logging_thread_mutex);

                if ((pthreadErr = pthread_join(logging_thread, NULL)) != 0)
                {
                    p_scossl_keysinuse_log_error("Failed to join logging thread,SYS_%d", pthreadErr);
                }
                else if (logging_thread_exit_status != SCOSSL_SUCCESS)
                {
                    p_scossl_keysinuse_log_error("Logging thread exited with status %d", logging_thread_exit_status);
                }
            }
        }
        else
        {
            p_scossl_keysinuse_log_error("Cleanup failed to acquire mutex,SYS_%d", pthreadErr);
        }
        pthread_mutex_unlock(&logging_thread_mutex);

        if (prefix != default_prefix)
        {
            OPENSSL_free(prefix);
            prefix = (char*)default_prefix;
            prefix_size = 0;
        }

        p_scossl_keysinuse_cleanup_lhash();
        CRYPTO_THREAD_lock_free(lh_keysinuse_ctx_lock);
        CRYPTO_THREAD_lock_free(keysinuse_state_lock);
        lh_keysinuse_ctx_lock = NULL;
        keysinuse_state_lock = NULL;
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state,OPENSSL_%d", ERR_get_error());
    }
}

//
// Configuration
//
void p_scossl_keysinuse_set_max_file_size(off_t size)
{
    if (size > 0)
    {
        max_file_size = size;
    }
}

void p_scossl_keysinuse_set_logging_delay(INT64 delay)
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
    return ctx == NULL ? NULL : OPENSSL_LH_strhash(ctx->keyIdentifier);
}

_Use_decl_annotations_
static int scossl_keysinuse_ctx_cmp(const SCOSSL_KEYSINUSE_CTX_IMP *ctx1, const SCOSSL_KEYSINUSE_CTX_IMP *ctx2)
{
    return ctx1 == NULL  && ctx2 != NULL &&
        memcmp(ctx1->keyIdentifier, ctx2->keyIdentifier, sizeof(ctx1->keyIdentifier)) == 0;
}

//
// KeysInUse context management
//
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_ctx_upref(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _Out_ INT32 *refOut)
{
    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&ctx->refCount, 1, &ref, ctx->lock))
    {
        p_scossl_keysinuse_log_error("p_scossl_keysinuse_ctx_upref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }

    if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_ctx_downref(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx, _Out_ INT32 *refOut)
{
    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&ctx->refCount, -1, &ref, ctx->lock))
    {
        p_scossl_keysinuse_log_error("p_scossl_keysinuse_ctx_downref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }

    if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

void p_scossl_keysinuse_free_key_ctx(_Inout_ SCOSSL_KEYSINUSE_CTX_IMP *ctx)
{
    if (ctx == NULL)
        return;

    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_KEYSINUSE_CTX *p_scossl_keysinuse_load_key(PCBYTE pbEncodedKey, SIZE_T cbEncodedKey)
{
    BOOL lockedState = FALSE;
    BOOL lockedHashTable = FALSE;
    BYTE abHash[SYMCRYPT_SHA256_RESULT_SIZE];
    SCOSSL_KEYSINUSE_CTX_IMP ctxTmpl;
    SCOSSL_KEYSINUSE_CTX_IMP *ctx = NULL;
    int lhErr = 0;
    SCOSSL_STATUS status = SCOSSL_FAILURE;

    if (pbEncodedKey == NULL || cbEncodedKey == 0)
    {
        return NULL;
    }

    // Lock keysinuse state to prevent teardown until after this function finishes
    if (CRYPTO_THREAD_read_lock(keysinuse_state_lock))
    {
        lockedState = TRUE;

        if (!keysinuse_enabled)
        {
            goto cleanup;
        }

        // Compute the key identifier (First 16 bytes of the SHA256 hash of the encoded key)
        SymCryptSha256(pbEncodedKey, cbEncodedKey, abHash);

        for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE / 2; i++)
        {
            sprintf(ctxTmpl.keyIdentifier[i*2], "%02x", abHash[i]);
        }
        ctxTmpl.keyIdentifier[SYMCRYPT_SHA256_RESULT_SIZE] = '\0';

        if (CRYPTO_THREAD_read_lock(lh_keysinuse_ctx_lock))
        {
            ctx = lh_SCOSSL_KEYSINUSE_CTX_IMP_retrieve(lh_keysinuse_ctx, &ctxTmpl);
            CRYPTO_THREAD_unlock(lh_keysinuse_ctx_lock);
        }
        else
        {
            p_scossl_keysinuse_log_error("Failed to keysinuse context hash table for reading,OPENSSL_%d", ERR_get_error());
            goto cleanup;
        }

        if (ctx == NULL)
        {
            // New key used for keysinuse. Create a new context and add it to the hash table
            if ((ctx = OPENSSL_zalloc(sizeof(SCOSSL_KEYSINUSE_CTX_IMP))) == NULL ||
                (ctx->lock = CRYPTO_THREAD_lock_new()) == NULL)
            {
                p_scossl_keysinuse_log_error("malloc failure in p_scossl_keysinuse_load_key,OPENSSL_%d", ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (CRYPTO_THREAD_write_lock(lh_keysinuse_ctx_lock))
            {
                lh_SCOSSL_KEYSINUSE_CTX_IMP_insert(lh_keysinuse_ctx, ctx);
                if (lhErr = lh_SCOSSL_KEYSINUSE_CTX_IMP_error(lh_keysinuse_ctx))
                {
                    p_scossl_keysinuse_log_error("Failed to add new keysinuse context to the hash table,OPENSSL_%d", ERR_get_error());
                }
                else
                {
                    lhErr = 1;
                }

                CRYPTO_THREAD_unlock(lh_keysinuse_ctx_lock);

                if (lhErr)
                {
                    goto cleanup;
                }
            }
            else
            {
                p_scossl_keysinuse_log_error("Failed to keysinuse context hash table,OPENSSL_%d", ERR_get_error());
                goto cleanup;
            }

            ctx->refCount = 1;
        }
        else if (p_scossl_keysinuse_ctx_upref(ctx, NULL) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        status = SCOSSL_SUCCESS;
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state for reading,OPENSSL_%d", ERR_get_error());
    }

cleanup:
    if (lockedState)
    {
        CRYPTO_THREAD_unlock(keysinuse_state_lock);
    }

    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_keysinuse_free_key_ctx(ctx);
        ctx = NULL;
    }

    return ctx;
}

_Use_decl_annotations_
SCOSSL_KEYSINUSE_CTX *p_scossl_keysinuse_load_key_by_ctx(SCOSSL_KEYSINUSE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (CRYPTO_THREAD_read_lock(keysinuse_state_lock))
    {
        if (!keysinuse_enabled ||
            p_scossl_keysinuse_ctx_upref(ctx, NULL) != SCOSSL_SUCCESS)
        {
            ctx = NULL;
        }

        CRYPTO_THREAD_unlock(keysinuse_state_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state for reading,OPENSSL_%d", ERR_get_error());
    }

    return ctx;
}

_Use_decl_annotations_
void p_scossl_keysinuse_unload_key(SCOSSL_KEYSINUSE_CTX *ctx)
{
    INT32 ref;

    if (ctx == NULL)
        return;

    if (CRYPTO_THREAD_read_lock(keysinuse_state_lock))
    {
        // If keysinuse is not enabled, then the hash table and all of its stored contexts have
        // been destroyed. The supplied context was already freed. This can happen if the
        // logging thread exited early. Do nothing.
        if (keysinuse_enabled &&
            p_scossl_keysinuse_ctx_downref(ctx, &ref) &&
            ref == 0)
        {
            if (CRYPTO_THREAD_write_lock(lh_keysinuse_ctx_lock))
            {
                if (lh_SCOSSL_KEYSINUSE_CTX_IMP_delete(lh_keysinuse_ctx, ctx) == NULL)
                {
                    p_scossl_keysinuse_log_error("Failed to remove keysinuse context from the hash table,OPENSSL_%d", ERR_get_error());
                }

                CRYPTO_THREAD_unlock(lh_keysinuse_ctx_lock);
            }
            else
            {
                p_scossl_keysinuse_log_error("Failed to lock keysinuse context hash table,OPENSSL_%d", ERR_get_error());
            }

            p_scossl_keysinuse_free_key_ctx(ctx);
        }

        CRYPTO_THREAD_unlock(keysinuse_state_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state for reading,OPENSSL_%d", ERR_get_error());
    }
}

//
// Usage tracking
//

_Use_decl_annotations_
static void p_scossl_keysinuse_add_use(SCOSSL_KEYSINUSE_CTX_IMP *ctxImp, BOOL isSigning)
{
    int pthreadErr;
    BOOL wakeLoggingThread = FALSE;

    if (ctxImp == NULL)
        return;

    if (CRYPTO_THREAD_read_lock(keysinuse_state_lock))
    {
        // If keysinuse is not enabled, then the hash table and all of its stored contexts have
        // been destroyed. The supplied context was already freed. This can happen if the
        // logging thread exited early. Do nothing.
        if (keysinuse_enabled)
        {
            if (CRYPTO_THREAD_write_lock(ctxImp->lock))
            {
                // Increment appropriate usage counter
                if (isSigning)
                {
                    ctxImp->signCounter++;
                }
                else
                {
                    ctxImp->decryptCounter++;
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
                p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
            }

            if (wakeLoggingThread)
            {
                if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
                {
                    if ((pthreadErr = pthread_cond_signal(&logging_thread_cond_wake_early)) != 0)
                    {
                        p_scossl_keysinuse_log_error("Failed to signal logging thread,SYS_%d", pthreadErr);
                    }
                    pthread_mutex_unlock(&logging_thread_mutex);
                }
                else
                {
                    p_scossl_keysinuse_log_error("Add use failed to lock logging thread mutex,SYS_%d", pthreadErr);
                }
            }
        }

        CRYPTO_THREAD_unlock(keysinuse_state_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state for reading,OPENSSL_%d", ERR_get_error());
    }
}

void p_scossl_keysinuse_on_sign(_In_ SCOSSL_KEYSINUSE_CTX *ctx)
{
    p_scossl_keysinuse_add_use(ctx, TRUE);
}

void p_scossl_keysinuse_on_decrypt(_In_ SCOSSL_KEYSINUSE_CTX *ctx)
{
    p_scossl_keysinuse_add_use(ctx, FALSE);
}

_Use_decl_annotations_
static void p_scossl_keysinuse_ctx_log(SCOSSL_KEYSINUSE_CTX_IMP *ctxImp, PCVOID doallArg)
{
    BOOL isScheduledLogEvent;
    time_t now;
    SCOSSL_KEYSINUSE_CTX_IMP ctxImpTmp;

    if (doallArg == NULL)
        return;

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
        }

        CRYPTO_THREAD_unlock(ctxImp->lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
        return;
    }

    p_scossl_keysinuse_log_notice("%s,%d,%d,%ld,%ld",
        ctxImpTmp.keyIdentifier,
        ctxImpTmp.signCounter,
        ctxImpTmp.decryptCounter,
        ctxImpTmp.firstLogTime,
        ctxImpTmp.lastLogTime);
}

//
// Logging
//
_Use_decl_annotations_
static void p_scossl_keysinuse_log_common(int level, const char *message, va_list args)
{
    char *level_str = "";
    // (Length of LOG_PATH_TMPL) - (8 for format specifiers)
    //  + (3 for level) + (8 for euid) + (1 for null terminator)
    char log_path[sizeof(LOG_PATH_TMPL) + 4];
    char msg_buf[LOG_MSG_MAX];
    int msg_len;

    switch (level)
    {
    case KEYSINUSE_ERR:
        level_str = "err";
        break;
    case KEYSINUSE_NOTICE:
    default:
        level_str = "not";
        break;
    }

    uid_t euid = geteuid();

    sprintf(log_path, LOG_PATH_TMPL, level_str, euid);

    if ((msg_len = vsnprintf(msg_buf, LOG_MSG_MAX, message, args)) > 0)
    {
        int len = prefix_size + msg_len + 6;
        char prefixed_msg[len + 1];
        strcpy(prefixed_msg, "");
        strcat(prefixed_msg, prefix);
        strcat(prefixed_msg, ",");
        strcat(prefixed_msg, level_str);
        strcat(prefixed_msg, "!");
        strcat(prefixed_msg, msg_buf);
        strcat(prefixed_msg, "\n");

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
                    p_scossl_keysinuse_log_error("Found symlink at %s. Removing file", log_path);
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
                    p_scossl_keysinuse_log_error("Found unexpected permissions (%o) on %s. Removing file", (sb.st_mode & 0777), log_path);
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
                        p_scossl_keysinuse_log_error("Failed to remove bad log file at %s,SYS_%d", log_path, errno);
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
                    p_scossl_keysinuse_log_error("Failed to log to %s. File size capped at %ld bytes", log_path, max_file_size);
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
                p_scossl_keysinuse_log_error("Failed to stat file at %s,SYS_%d", log_path, errno);
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
                p_scossl_keysinuse_log_error("Failed to open log file for appending at %s,SYS_%d", log_path, errno);
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
                p_scossl_keysinuse_log_error("Failed to write to log file at %s,SYS_%d", log_path, errno);
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
                p_scossl_keysinuse_log_error("Failed to close log file at %s,SYS_%d", log_path, errno);
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

// Used for logging keysinuse related errors to a separate log file.
// This avoids poluting the error stack with keysinuse related errors.
_Use_decl_annotations_
static void p_scossl_keysinuse_log_error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    p_scossl_keysinuse_log_common(KEYSINUSE_ERR, message, args);
}

_Use_decl_annotations_
static void p_scossl_keysinuse_log_notice(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    p_scossl_keysinuse_log_common(KEYSINUSE_NOTICE, message, args);
}

// The logging thread runs in a loop. It pops all pending usage from sk_keysinuse_info,
// and writes them to the log file. It sleeps for logging_delay seconds between each iteration.
// On the first use of a key, the thread is woken immediatley log the event. All pending
// events are logged on program exit.
_Use_decl_annotations_
static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg)
{
    // Logging thread is terminated by setting is_logging to FALSE and signaling logging_thread_cond_wake_early
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    BOOL isLoggingThreadRunning = TRUE;
    BOOL isScheduledLogEvent;

    struct timespec abstime;
    time_t now;
    int pthreadErr;
    int waitStatus;

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
            p_scossl_keysinuse_log_error("Logging thread failed to accquire mutex,SYS_%d", pthreadErr);
            goto cleanup;
        }

        if (waitStatus != 0 && waitStatus != ETIMEDOUT)
        {
            p_scossl_keysinuse_log_error("Logging thread woken up with unexpected status, SYS_%d", waitStatus);
            goto cleanup;
        }

        if (CRYPTO_THREAD_read_lock(lh_keysinuse_ctx_lock))
        {
            isScheduledLogEvent = waitStatus == ETIMEDOUT;
            lh_SCOSSL_KEYSINUSE_CTX_IMP_doall_arg(lh_keysinuse_ctx, p_scossl_keysinuse_ctx_log, &isScheduledLogEvent);
            CRYPTO_THREAD_unlock(lh_keysinuse_ctx_lock);
        }
        else
        {
            p_scossl_keysinuse_log_error("Failed to keysinuse context hash table for reading,OPENSSL_%d", ERR_get_error());
            goto cleanup;
        }
    }
    while (isLoggingThreadRunning);

cleanup:
    // Only clean up the lhash if we can set keysinuse_enabled to FALSE
    // under lock. Another thread may be in a critical section that touches
    // the keysinuse contexts stored in the hash table. If we fail to cleanup
    // the hash table here, it will be forcibly cleaned in p_scossl_keysinuse_teardown.
    if (CRYPTO_THREAD_write_lock(keysinuse_state_lock))
    {
        keysinuse_enabled = FALSE;
        CRYPTO_THREAD_unlock(keysinuse_state_lock);
        p_scossl_keysinuse_cleanup_lhash();
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse state for writing,OPENSSL_%d", ERR_get_error());
    }

    logging_thread_exit_status = SCOSSL_SUCCESS;

    return NULL;
}

#ifdef __cplusplus
}
#endif