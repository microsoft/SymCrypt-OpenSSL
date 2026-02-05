//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/proverr.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "p_scossl_keysinuse.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Configuration
//
static CRYPTO_ONCE keysinuse_init_once = CRYPTO_ONCE_STATIC_INIT;
static off_t max_file_size = 5 << 10; // Default to 5KB
static long logging_delay = 60 * 60; // Default to 1 hour
static BOOL keysinuse_enabled = FALSE;
static BOOL p_scossl_keysinuse_child_enabled = FALSE;
static pid_t pid = 0;
static pid_t logging_thread_tid = 0;

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
DEFINE_STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO);
// Stack of keysinuseInfo that have pending usage events to be logged by the logging thread.
// This is destroyed if the logging thread fails to start, or when the logging thread exits.
// Always check this is non-NULL outside the logging thread.
static STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info = NULL;
// This lock should be aquired before accessing sk_keysinuse_info
static CRYPTO_RWLOCK *sk_keysinuse_info_lock = NULL;

// To minimize any overhead to crypto operations, all file writes are handled by
// logging_thread. This thread periodically pops all pending usage data from
// sk_keysinuse_info, and writes to the log file. The thread is signalled to
// wake early by logging_thread_cond_wake_early when a key is first used.
static pthread_t logging_thread;
static pthread_cond_t *logging_thread_cond_wake_early = NULL;
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
static void p_scossl_keysinuse_prepare();
static void p_scossl_keysinuse_parent();
static void p_scossl_keysinuse_child();

static void p_scossl_keysinuse_add_use(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, BOOL isSigning);

static void p_scossl_keysinuse_log_common(int level, _In_ const char *message, va_list args);
static void p_scossl_keysinuse_log_error(_In_ const char *message, ...);
static void p_scossl_keysinuse_log_notice(_In_ const char *message, ...);

static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg);

//
// Setup/teardown
//
static void p_scossl_keysinuse_logging_thread_cleanup()
{
    if (CRYPTO_THREAD_write_lock(sk_keysinuse_info_lock))
    {
        // Cleanup any elements in the keysinuse_info stack in case the logging thread failed
        while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info) > 0)
        {
            p_scossl_keysinuse_info_free(sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info));
        }

        sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info);
        sk_keysinuse_info = NULL;

        CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse info stack,OPENSSL_%d", ERR_get_error());
    }
}

static void p_scossl_keysinuse_init_once()
{
    int mkdirResult;
    mode_t umaskOriginal;
    time_t initTime = time(NULL);
    char *symlinkPath = NULL;
    int cbSymlink;
    char *procPath = NULL;
    int cbProcPath = PATH_MAX;
    int cbProcPathUsed = 0;
    pthread_condattr_t attr;
    int pthreadErr;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    BOOL attr_initialized = FALSE;

    // Store process PID for later use
    pid = getpid();

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

    sk_keysinuse_info_lock = CRYPTO_THREAD_lock_new();
    sk_keysinuse_info = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();
    if (sk_keysinuse_info_lock == NULL || sk_keysinuse_info == NULL)
    {
        p_scossl_keysinuse_log_error("Failed to create global objects used by keysinuse");
        goto cleanup;
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
    // Allocate condition variable
    if ((logging_thread_cond_wake_early = OPENSSL_malloc(sizeof(pthread_cond_t))) == NULL)
    {
        p_scossl_keysinuse_log_error("Failed to allocate condition variable");
        goto cleanup;
    }

    if ((pthreadErr = pthread_condattr_init(&attr)) != 0)
    {
        p_scossl_keysinuse_log_error("Failed to init condition attributes,SYS_%d", pthreadErr);
        goto cleanup;
    }

    attr_initialized = TRUE;
    is_logging = TRUE;

    if ((pthreadErr = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) != 0 ||
        (pthreadErr = pthread_cond_init(logging_thread_cond_wake_early, &attr)) != 0 ||
        (pthreadErr = pthread_create(&logging_thread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
    {
        p_scossl_keysinuse_log_error("Failed to start logging thread,SYS_%d", pthreadErr);
        is_logging = FALSE;
        goto cleanup;
    }

    if ((pthreadErr = pthread_atfork(p_scossl_keysinuse_prepare,
                                     p_scossl_keysinuse_parent,
                                     p_scossl_keysinuse_child)) != 0)
    {
        p_scossl_keysinuse_log_error("Failed to register child process reinit. Child processes will not log events,SYS_%d", pthreadErr);
    }

    keysinuse_enabled = TRUE;
    status = SCOSSL_SUCCESS;

cleanup:
    if (attr_initialized)
    {
        pthread_condattr_destroy(&attr);
    }

    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_keysinuse_teardown();
    }

    OPENSSL_free(symlinkPath);
    OPENSSL_free(procPath);
}

void p_scossl_keysinuse_init()
{
    CRYPTO_THREAD_run_once(&keysinuse_init_once, p_scossl_keysinuse_init_once);
}

// Acquire all locks to freeze state before fork
static void p_scossl_keysinuse_prepare()
{
    if (!keysinuse_enabled)
    {
        return;
    }

    // Check if process is multithreaded (more than just main + logging thread)
    // Default to FALSE for safety if we can't determine thread state
    p_scossl_keysinuse_child_enabled = FALSE;

    // Check if any threads exist other than main and logging thread
    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir != NULL)
    {
        struct dirent *entry;
        BOOL has_extra_threads = FALSE;

        while ((entry = readdir(task_dir)) != NULL &&
                !has_extra_threads)
        {
            pid_t tid = (pid_t)strtol(entry->d_name, NULL, 10);

            // Make sure the thread is either the main thread or the logging thread
            // The presence of other threads means keysinuse cannot continue safely
            // in the child process
            if (tid > 0 &&
                tid != pid &&
                tid != logging_thread_tid)
            {
                has_extra_threads = TRUE;
            }
        }
        closedir(task_dir);

        // Enable child logging only if no extra threads were found
        if (!has_extra_threads)
        {
            p_scossl_keysinuse_child_enabled = TRUE;
        }
    }

    // Ensure logging thread is not holding this mutex
    pthread_mutex_lock(&logging_thread_mutex);

    // Prevent updates to the pending keysinuse info stack
    if (sk_keysinuse_info_lock != NULL)
    {
        CRYPTO_THREAD_write_lock(sk_keysinuse_info_lock);
    }
}

// Release all locks in reverse order after fork
static void p_scossl_keysinuse_parent()
{
    if (!keysinuse_enabled)
    {
        return;
    }

    if (sk_keysinuse_info_lock != NULL)
    {
        CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);
    }

    pthread_mutex_unlock(&logging_thread_mutex);
}

// If the calling process forks, the logging thread needs to be restarted in the
// child process, and any locks should be reinitialized in case the parent
// process held a lock at the time of the fork.
static void p_scossl_keysinuse_child()
{
    SCOSSL_PROV_KEYSINUSE_INFO *pKeysinuseInfo = NULL;
    pthread_condattr_t attr;
    int pthreadErr;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    int is_parent_logging = is_logging;
    BOOL attr_initialized = FALSE;

    if (!keysinuse_enabled)
    {
        return;
    }

    // Reset global state
    keysinuse_enabled = FALSE;
    first_use_pending = FALSE;
    is_logging = FALSE;
    logging_thread_exit_status = SCOSSL_FAILURE;

    if (sk_keysinuse_info_lock != NULL)
    {
        CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);

        // Recreate the RW lock just in case there was a read lock in the parent
        CRYPTO_THREAD_lock_free(sk_keysinuse_info_lock);
        sk_keysinuse_info_lock = CRYPTO_THREAD_lock_new();
    }

    pthread_mutex_unlock(&logging_thread_mutex);

    // If any keysinuseInfo were in sk_keysinuse_info_lock, they will
    // be logged by the parent process. Remove them from the child process's
    // stack and reset them. This does not acquire any locks since we cannot
    // guarantee the parent was not multi-threaded and holding a keysinuseInfo lock
    // in another thread. At this point no other threads should be running anyways.
    //
    // In the single-threaded parent case, we know that no other threads were
    // running in the parent process at the time of the fork, so its safe to
    // continue using these keysinuse infos in the child process.
    while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info) > 0)
    {
        pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info);
        if (pKeysinuseInfo != NULL)
        {
            pKeysinuseInfo->logPending = FALSE;
            pKeysinuseInfo->decryptCounter = 0;
            pKeysinuseInfo->signCounter = 0;
            pKeysinuseInfo->refCount--;
            if (pKeysinuseInfo->refCount == 0)
            {
                CRYPTO_THREAD_lock_free(pKeysinuseInfo->lock);
                OPENSSL_free(pKeysinuseInfo);
            }
        }
    }

    // Only recreate logging thread if it was running in the parent process
    if (is_parent_logging && p_scossl_keysinuse_child_enabled)
    {
        OPENSSL_free(logging_thread_cond_wake_early);
        if ((logging_thread_cond_wake_early = OPENSSL_malloc(sizeof(pthread_cond_t))) == NULL)
        {
            p_scossl_keysinuse_log_error("Failed to allocate condition variable");
            goto cleanup;
        }

        if ((pthreadErr = pthread_condattr_init(&attr)) != 0)
        {
            p_scossl_keysinuse_log_error("Failed to init condition attributes,SYS_%d", pthreadErr);
            goto cleanup;
        }

        attr_initialized = TRUE;
        is_logging = TRUE;

        if ((pthreadErr = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) != 0 ||
            (pthreadErr = pthread_cond_init(logging_thread_cond_wake_early, &attr)) != 0 ||
            (pthreadErr = pthread_create(&logging_thread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
        {
            p_scossl_keysinuse_log_error("Failed to start logging thread,SYS_%d", pthreadErr);
            is_logging = FALSE;
            goto cleanup;
        }

        keysinuse_enabled = TRUE;
        status = SCOSSL_SUCCESS;
    }

cleanup:
    // Clean up condition variable inherited from parent if this is a failure case
    if (logging_thread_cond_wake_early != NULL && status != SCOSSL_SUCCESS)
    {
        OPENSSL_free(logging_thread_cond_wake_early);
        logging_thread_cond_wake_early = NULL;
    }

    if (attr_initialized)
    {
        pthread_condattr_destroy(&attr);
    }

    if (status != SCOSSL_SUCCESS)
    {
        p_scossl_keysinuse_teardown();
    }
}

BOOL p_scossl_keysinuse_running()
{
    return keysinuse_enabled;
}

void p_scossl_keysinuse_teardown()
{
    int pthreadErr;

    keysinuse_enabled = FALSE;

    // Finish logging thread
    if (is_logging)
    {
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
        {
            is_logging = FALSE;
            if (logging_thread_cond_wake_early != NULL)
            {
                pthread_cond_signal(logging_thread_cond_wake_early);
            }
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
        else
        {
            p_scossl_keysinuse_log_error("Cleanup failed to acquire mutex,SYS_%d", pthreadErr);
        }
    }

    if (logging_thread_cond_wake_early != NULL)
    {
        OPENSSL_free(logging_thread_cond_wake_early);
        logging_thread_cond_wake_early = NULL;
    }

    if (prefix != default_prefix)
    {
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
        prefix_size = 0;
    }

    CRYPTO_THREAD_lock_free(sk_keysinuse_info_lock);
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info);
    sk_keysinuse_info_lock = NULL;
    sk_keysinuse_info = NULL;
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
// KeysInUse info management
//
_Use_decl_annotations_
SCOSSL_PROV_KEYSINUSE_INFO *p_scossl_keysinuse_info_new(PBYTE pbPublicKey, SIZE_T cbPublicKey)
{
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo = NULL;
    BYTE abHash[SYMCRYPT_SHA256_RESULT_SIZE] = { 0 };

    if (pbPublicKey == NULL)
    {
        return NULL;
    }

    if ((keysinuseInfo = OPENSSL_zalloc(sizeof(SCOSSL_PROV_KEYSINUSE_INFO))) != NULL)
    {
        keysinuseInfo->refCount = 1;

        if ((keysinuseInfo->lock = CRYPTO_THREAD_lock_new()) == NULL)
        {
            p_scossl_keysinuse_log_error("malloc failure in p_scossl_keysinuse_info_new,OPENSSL_%d", ERR_R_MALLOC_FAILURE);
            p_scossl_keysinuse_info_free(keysinuseInfo);
            return NULL;
        }

        SymCryptSha256(pbPublicKey, cbPublicKey, abHash);

        // Convert the first half of the hash to a loggable hexencoded string
        for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE / 2; i++)
        {
            sprintf(&keysinuseInfo->keyIdentifier[i*2], "%02x", abHash[i]);
        }
    }

    return keysinuseInfo;
}

_Use_decl_annotations_
void p_scossl_keysinuse_info_free(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    if (keysinuseInfo == NULL)
        return;

    INT32 ref;

    if (p_scossl_keysinuse_downref(keysinuseInfo, &ref) &&
        ref == 0)
    {
        CRYPTO_THREAD_lock_free(keysinuseInfo->lock);
        OPENSSL_free(keysinuseInfo);
    }
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_upref(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, INT32 *refOut)
{
    if (keysinuseInfo == NULL)
        return SCOSSL_FAILURE;

    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&keysinuseInfo->refCount, 1, &ref, keysinuseInfo->lock))
    {
        p_scossl_keysinuse_log_error("p_scossl_keysinuse_upref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }
    else if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_downref(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, INT32 *refOut)
{
    if (keysinuseInfo == NULL)
        return SCOSSL_FAILURE;

    INT32 ref = 0;

    if (!CRYPTO_atomic_add(&keysinuseInfo->refCount, -1, &ref, keysinuseInfo->lock))
    {
        p_scossl_keysinuse_log_error("p_scossl_keysinuse_downref failed,OPENSSL_%d", ERR_get_error());
        return SCOSSL_FAILURE;
    }
    else if (refOut != NULL)
    {
        *refOut = ref;
    }

    return SCOSSL_SUCCESS;
}

//
// Usage tracking
//
_Use_decl_annotations_
static void p_scossl_keysinuse_add_use(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, BOOL isSigning)
{
    if (keysinuseInfo == NULL || !keysinuse_enabled)
        return;

    int pthreadErr;
    BOOL wakeLoggingThread = FALSE;

    if (CRYPTO_THREAD_write_lock(keysinuseInfo->lock))
    {
        // Increment appropriate usage counter
        if (isSigning)
        {
            keysinuseInfo->signCounter++;
        }
        else
        {
            keysinuseInfo->decryptCounter++;
        }

        // Add to pending usage if not already in stack
        if (!keysinuseInfo->logPending)
        {
            if (CRYPTO_THREAD_write_lock(sk_keysinuse_info_lock))
            {
                if (sk_keysinuse_info != NULL)
                {
                    INT32 ref; // Unused, required for CRYPTO_atomic_add

                    keysinuseInfo->logPending = TRUE;
                    // If atomics aren't supported CRYPTO_atomic_add attempts to modify
                    // keysinuseInfo->refCount under lock, or fails if no lock is passed.
                    // We don't pass keysinuseInfo->lock since we already have the lock.
                    if (!CRYPTO_atomic_add(&keysinuseInfo->refCount, 1, &ref, NULL))
                    {
                        keysinuseInfo->refCount++;
                    }
                    sk_SCOSSL_PROV_KEYSINUSE_INFO_push(sk_keysinuse_info, keysinuseInfo);

                    // First use of this key, wake the logging thread
                    if (keysinuseInfo->firstLogTime == 0)
                    {
                        wakeLoggingThread = TRUE;
                    }
                }
                CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);
            }
            else
            {
                p_scossl_keysinuse_log_error("Failed to lock keysinuse info stack,OPENSSL_%d", ERR_get_error());
            }
        }
        CRYPTO_THREAD_unlock(keysinuseInfo->lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
        return;
    }

    if (wakeLoggingThread)
    {
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
        {
            first_use_pending = TRUE;

            if (logging_thread_cond_wake_early != NULL &&
                (pthreadErr = pthread_cond_signal(logging_thread_cond_wake_early)) != 0)
            {
                p_scossl_keysinuse_log_error("Failed to signal logging thread,SYS_%d", pthreadErr);
            }
            pthread_mutex_unlock(&logging_thread_mutex);
        }
        else
        {
            p_scossl_keysinuse_log_error("Add use failed to accquire mutex,SYS_%d", pthreadErr);
        }
    }
}

void p_scossl_keysinuse_on_sign(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    p_scossl_keysinuse_add_use(keysinuseInfo, TRUE);
}

void p_scossl_keysinuse_on_decrypt(_In_ SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    p_scossl_keysinuse_add_use(keysinuseInfo, FALSE);
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
    // Store the logging thread's TID for thread detection in fork handlers
    logging_thread_tid = syscall(SYS_gettid);

    // Logging thread is terminated by setting is_logging to FALSE and signaling logging_thread_cond_wake_early
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    BOOL isLoggingThreadRunning = TRUE;

    struct timespec abstime;
    time_t now;
    int pthreadErr;
    int waitStatus;

    // Every time the logging loop runs, all pending usage events are popped to sk_keysinuse_info_pending
    // to minimize the time sk_keysinuse_info_lock is held.
    SCOSSL_PROV_KEYSINUSE_INFO *pKeysinuseInfo;
    SCOSSL_PROV_KEYSINUSE_INFO keysinuseInfoTmp;
    STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info_pending = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();

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
                    // after the logging thread exits this critical seciton. In that case, the
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
                    if (logging_thread_cond_wake_early != NULL)
                    {
                        waitStatus = pthread_cond_timedwait(logging_thread_cond_wake_early, &logging_thread_mutex, &abstime);
                    }
                    else
                    {
                        p_scossl_keysinuse_log_error("logging thread wait condition is NULL");
                        goto cleanup;
                    }

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

        if (CRYPTO_THREAD_write_lock(sk_keysinuse_info_lock))
        {
            while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info) > 0)
            {
                pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info);
                if (pKeysinuseInfo != NULL)
                {
                    sk_SCOSSL_PROV_KEYSINUSE_INFO_push(sk_keysinuse_info_pending, pKeysinuseInfo);
                }
            }
            CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);
        }
        else
        {
            p_scossl_keysinuse_log_error("Failed to lock keysinuse info stack,OPENSSL_%d", ERR_get_error());
        }

        // Log all pending usage events under lock. We need to lock in this section
        // in case fork is called
        if ((pthreadErr = pthread_mutex_lock(&logging_thread_mutex)) == 0)
        {
            while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info_pending) > 0)
            {
                pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info_pending);
                if (CRYPTO_THREAD_write_lock(pKeysinuseInfo->lock))
                {
                    now = time(NULL);

                    pKeysinuseInfo->firstLogTime = pKeysinuseInfo->lastLogTime == 0 ? now : pKeysinuseInfo->firstLogTime;
                    pKeysinuseInfo->lastLogTime = now;
                    pKeysinuseInfo->logPending = FALSE;

                    keysinuseInfoTmp = *pKeysinuseInfo;

                    pKeysinuseInfo->decryptCounter = 0;
                    pKeysinuseInfo->signCounter = 0;

                    CRYPTO_THREAD_unlock(pKeysinuseInfo->lock);
                }
                else
                {
                    p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
                    keysinuseInfoTmp.refCount = -1;
                }

                p_scossl_keysinuse_info_free(pKeysinuseInfo);

                if (keysinuseInfoTmp.refCount > 0)
                {
                    p_scossl_keysinuse_log_notice("%s,%d,%d,%ld,%ld",
                    keysinuseInfoTmp.keyIdentifier,
                    keysinuseInfoTmp.signCounter,
                    keysinuseInfoTmp.decryptCounter,
                    keysinuseInfoTmp.firstLogTime,
                    keysinuseInfoTmp.lastLogTime);
                }
            }

            pthread_mutex_unlock(&logging_thread_mutex);
        }
    }
    while (isLoggingThreadRunning);

cleanup:
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info_pending);
    logging_thread_exit_status = SCOSSL_SUCCESS;
    keysinuse_enabled = FALSE;
    p_scossl_keysinuse_logging_thread_cleanup();

    return NULL;
}

#ifdef __cplusplus
}
#endif