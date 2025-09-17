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

//
// Configuration
//
static CRYPTO_ONCE keysinuse_init_once = CRYPTO_ONCE_STATIC_INIT;
static off_t max_file_size = 5 << 10; // Default to 5KB
static long logging_delay = 60 * 60; // Default to 1 hour
static BOOL keysinuse_enabled = FALSE;

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
// Stack of keysinuseInfo that have been popped by the logging thread, but not yet logged.
// This should only be used in the logging thread. It is defined here to avoid reallocation
// and leaks if the process forks and a new logging thread is created in the child process.
static STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info_pending = NULL;
// This lock should be aquired before accessing sk_keysinuse_info
static CRYPTO_RWLOCK *sk_keysinuse_info_lock = NULL;

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
static void p_scossl_keysinuse_atfork_reinit();

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

    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info_pending);
    sk_keysinuse_info_pending = NULL;
}

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
    sk_keysinuse_info_pending = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();
    if (sk_keysinuse_info_lock == NULL || 
        sk_keysinuse_info == NULL ||
        sk_keysinuse_info_pending == NULL)
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

    if ((pthreadErr = pthread_atfork(NULL, NULL, p_scossl_keysinuse_atfork_reinit)) != 0)
    {
        p_scossl_keysinuse_log_error("Failed to register child process reinit. Child processes will not log events,SYS_%d", pthreadErr);
    }

    keysinuse_enabled = TRUE;
    status = SCOSSL_SUCCESS;

cleanup:
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

// If the calling process forks, the logging thread needs to be restarted in the
// child process, and any locks should be reinitialized in case the parent
// process held a lock at the time of the fork. 
static void p_scossl_keysinuse_atfork_reinit()
{
    SCOSSL_PROV_KEYSINUSE_INFO *pKeysinuseInfo = NULL;
    pthread_condattr_t attr;
    int pthreadErr;
    SCOSSL_STATUS status = SCOSSL_FAILURE;
    int is_parent_logging = is_logging;

    // Reset global state
    keysinuse_enabled = FALSE;
    first_use_pending = FALSE;
    is_logging = FALSE;
    logging_thread_exit_status = SCOSSL_FAILURE;

    // Recreate global locks in case they were held by the logging
    // thread in the parent process at the time of the fork.
    CRYPTO_THREAD_lock_free(sk_keysinuse_info_lock);
    sk_keysinuse_info_lock = CRYPTO_THREAD_lock_new();
    if (sk_keysinuse_info_lock == NULL)
    {
        p_scossl_keysinuse_log_error("Failed to create keysinuse lock in child process");
        goto cleanup;
    }

    logging_thread_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    // If any keysinuseInfo were in either stack, they will
    // be logged by the parent process. Remove them from the child process's
    // stacks and reset them. 
    if (CRYPTO_THREAD_write_lock(sk_keysinuse_info_lock))
    {
        while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info) > 0)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info);
            if (pKeysinuseInfo != NULL)
            {
                if (CRYPTO_THREAD_write_lock(pKeysinuseInfo->lock))
                {
                    pKeysinuseInfo->logPending = FALSE;
                    pKeysinuseInfo->decryptCounter = 0;
                    pKeysinuseInfo->signCounter = 0;
    
                    CRYPTO_THREAD_unlock(pKeysinuseInfo->lock);
                }
                else
                {
                    p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
                }

                p_scossl_keysinuse_info_free(pKeysinuseInfo);
            }
        }

        CRYPTO_THREAD_unlock(sk_keysinuse_info_lock);
    }
    else
    {
        p_scossl_keysinuse_log_error("Failed to lock keysinuse info stack,OPENSSL_%d", ERR_get_error());
    }

    while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info_pending) > 0)
    {
        pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info_pending);
        if (pKeysinuseInfo != NULL)
        {
            if (CRYPTO_THREAD_write_lock(pKeysinuseInfo->lock))
            {
                pKeysinuseInfo->logPending = FALSE;
                pKeysinuseInfo->decryptCounter = 0;
                pKeysinuseInfo->signCounter = 0;

                CRYPTO_THREAD_unlock(pKeysinuseInfo->lock);
            }
            else
            {
                p_scossl_keysinuse_log_error("Failed to lock keysinuse info,OPENSSL_%d", ERR_get_error());
            }

            p_scossl_keysinuse_info_free(pKeysinuseInfo);
        }
    }

    // Only recreate logging thread if it was running in the parent process
    if (is_parent_logging)
    {     
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
    }


cleanup:
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
        else
        {
            pthread_mutex_unlock(&logging_thread_mutex);
        }
    }
    else
    {
        p_scossl_keysinuse_log_error("Cleanup failed to acquire mutex,SYS_%d", pthreadErr);
    }

    if (prefix != default_prefix)
    {
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
        prefix_size = 0;
    }

    CRYPTO_THREAD_lock_free(sk_keysinuse_info_lock);
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info);
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info_pending);
    sk_keysinuse_info_lock = NULL;
    sk_keysinuse_info = NULL;
    sk_keysinuse_info_pending = NULL;
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

            if ((pthreadErr = pthread_cond_signal(&logging_thread_cond_wake_early)) != 0)
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
    }
    while (isLoggingThreadRunning);

cleanup:
    logging_thread_exit_status = SCOSSL_SUCCESS;
    keysinuse_enabled = FALSE;
    p_scossl_keysinuse_logging_thread_cleanup();

    return NULL;
}

#ifdef __cplusplus
}
#endif