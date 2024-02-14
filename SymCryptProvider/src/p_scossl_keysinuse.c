#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/proverr.h>
#include <sys/stat.h>

#include "p_scossl_keysinuse.h"

#define KEYSINUSE_ERR 0
#define KEYSINUSE_NOTICE 1

// Log files separated by UID.
#define LOG_DIR "/var/log/keysinuse/"
#define LOG_PATH_TMPL LOG_DIR "keysinuse_%.3s_%08x_%.32s.log"
// /var/log/keysinuse/keysinuse_<level>_<id>_<uid>.log
// (Max len of level + id + uid) - (len of format specifiers) = 30
#define LOG_PATH_LEN sizeof(LOG_PATH_TMPL) + 30
#define LOG_MSG_MAX 256

#define DEFAULT_loggingDelay 60 * 60
#define LOG_ID_LEN_MAX 16

static const char *default_log_id = "default";
static const char *default_prefix = "";
static char log_id[LOG_ID_LEN_MAX+1] = {0};
static char *prefix = NULL;
static int prefix_size = 0;
static off_t max_file_size = 1024 * 5; // 5KB

static int keysinuse_enabled = 0;
static long loggingDelay = DEFAULT_loggingDelay;

// This lock should be aquired before accessing sk_keysinuse_info and first_use_counter
static CRYPTO_RWLOCK *keysinuse_info_pending_lock = NULL;

// Stack of keysinuseInfo that have pending usage events to be logged by the
// logging thread.
static STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info = NULL;
static UINT first_use_counter = 0;

// To minimize any overhead to crypto operations, all file writes are handled by
// logging_thread. This thread periodically pops all pending usage data from
// sk_keysinuse_info, and writes to the log file. The thread wakes up early
// to immediately log the first use(s) of a key when logging_thread_cond_wake_early
// is signalled.
static pthread_t logging_thread;
static pthread_cond_t logging_thread_cond_wake_early;
static pthread_mutex_t logging_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
SCOSSL_STATUS logging_thread_exit_status = SCOSSL_FAILURE;
BOOL is_logging = FALSE;

static void p_scossl_keysinuse_log_error(const char *message, ...);

static void p_scossl_keysinuse_log_common(int level, const char *message, va_list args)
{
    char *level_str = "";
    char log_path[LOG_PATH_LEN + 1];
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

    sprintf(log_path, LOG_PATH_TMPL, level_str, euid, log_id);

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
            int isBadFile = 0;
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

                isBadFile = 1;
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
                isBadFile = 1;
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

        // Log files are separated by uid. Only write access is needed
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

// Used for logging keysinuse related errors to a separate log file
static void p_scossl_keysinuse_log_error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    p_scossl_keysinuse_log_common(KEYSINUSE_ERR, message, args);
}

static void p_scossl_keysinuse_log_notice(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    p_scossl_keysinuse_log_common(KEYSINUSE_ERR, message, args);
}

// The logging thread runs in a loop. It pops all pending usage from sk_keysinuse_info,
// and writes them to the log file. It sleeps for loggingDelay seconds between each iteration.
// On the first use of a key, the thread wakes up early to immediatley log the event. All pending
// events are logged on program exit.
static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg)
{
    // Logging thread is terminated by setting is_logging to FALSE and signaling logging_thread_cond_wake_early
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    // Every time the logging loop runs, all pending usage events are popped to this thread-local stack
    // to minimize the time keysinuse_info_pending_lock is held.
    BOOL isLoggingThreadRunning = TRUE;
    STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info_pending = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();
    struct timespec abstime;
    time_t now;
    SCOSSL_PROV_KEYSINUSE_INFO *pKeysinuseInfo;
    SCOSSL_PROV_KEYSINUSE_INFO keysinuseInfoTmp;
    int numInfoPending;
    int waitStatus;

    do
    {
        // This is the exit point for the logging thread. In that case, is_logging should be FALSE,
        // and logging_thread_cond_wake_early should be signalled. All pending events are logged
        // before the thread exits.
        pthread_mutex_lock(&logging_thread_mutex);
        if (is_logging)
        {
            CRYPTO_THREAD_write_lock(keysinuse_info_pending_lock);

            // Only wait if no first use events are pending. Some may have been added while
            // this thread was logging. In that case immediately handle those events before
            // attempting to wait again.
            if (first_use_counter == 0)
            {
                CRYPTO_THREAD_lock_free(keysinuse_info_pending_lock);

                clock_gettime(CLOCK_MONOTONIC, &abstime);
                abstime.tv_sec += loggingDelay;

                // Wait until loggingDelay has elapsed or the thread is signaled early. logging_thread_mutex is
                // unlocked by pthread_cond_timedwait so first use events can be signalled.
                waitStatus = pthread_cond_timedwait(&logging_thread_cond_wake_early, &logging_thread_mutex, &abstime);

                // If we are exiting, then treat this iteration as a timeout and log all pending events
                if (!is_logging)
                {
                    waitStatus = ETIMEDOUT;
                    isLoggingThreadRunning = FALSE;
                }

                CRYPTO_THREAD_write_lock(keysinuse_info_pending_lock);
            }
            else
            {
                waitStatus = 0;
            }
        }
        else
        {
            // Logging thread
            waitStatus = ETIMEDOUT;
            isLoggingThreadRunning = FALSE;
        }
        pthread_mutex_unlock(&logging_thread_mutex);

        now = time(NULL);

        // Condition signaled to wake the thread early. Log only first key use(s)
        if (waitStatus == 0)
        {
            numInfoPending = first_use_counter;
        }
        // Timeout expired. Log all events
        else if (waitStatus == ETIMEDOUT)
        {
            // Pop all elements
            numInfoPending = sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info);
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        first_use_counter = 0;

        for (int i = 0; i < numInfoPending; i++)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info);
            if (pKeysinuseInfo != NULL)
            {
                sk_SCOSSL_PROV_KEYSINUSE_INFO_push(sk_keysinuse_info_pending, pKeysinuseInfo);
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            }
        }
        CRYPTO_THREAD_unlock(keysinuse_info_pending_lock);

        while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info_pending) > 0)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info_pending);
            if (pKeysinuseInfo != NULL &&
                CRYPTO_THREAD_write_lock(pKeysinuseInfo->lock))
            {
                pKeysinuseInfo->firstUse = pKeysinuseInfo->lastLoggedUse == 0 ? now : pKeysinuseInfo->firstUse;
                pKeysinuseInfo->lastLoggedUse = now;

                keysinuseInfoTmp = *pKeysinuseInfo;

                CRYPTO_THREAD_unlock(pKeysinuseInfo->lock);

                p_scossl_keysinuse_log_notice("%s,%d,%d,%ld,%ld",
                   keysinuseInfoTmp.keyIdentifier,
                   keysinuseInfoTmp.signCounter,
                   keysinuseInfoTmp.decryptCounter,
                   keysinuseInfoTmp.firstUse,
                   keysinuseInfoTmp.lastLoggedUse);
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            }

            p_scossl_keysinuse_info_free(pKeysinuseInfo);
        }
    }
    while (isLoggingThreadRunning);

cleanup:
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info_pending);
    logging_thread_exit_status = SCOSSL_SUCCESS;

    return NULL;
}

// Setup/teardown
SCOSSL_STATUS p_scossl_keysinuse_init(char *logging_id)
{
    pid_t pid = getpid();
    int cbSymlink;
    char *symlinkPath = NULL;
    struct stat symlinkStat;
    char *procPath = NULL;
    int cbProcPath = 0;
    int cbProcPathUsed = 0;
    struct timespec now;

    int pthread_err;
    pthread_condattr_t attr;

    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (logging_id != NULL && *logging_id != '\0')
    {
        strncpy(log_id, logging_id, LOG_ID_LEN_MAX);
        log_id[LOG_ID_LEN_MAX] = '\0';
    }
    else
    {
        strcpy(log_id, default_log_id);
    }

    // Generate prefix for all log messages
    // <keysinuse init time>,<process path>

    // The only reasonable failure here is EINVAL, meaning the CLOCK_MONOTONIC
    // is not supported. Additional KeysInUse behavior requires CLOCK_MONOTONIC,
    // so fail here if it is not supported. This should usually be availabile.
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    // Fetch running process path from /proc/<pid>/exe. This path is a symbolic link.
    cbSymlink = snprintf(NULL, 0, "/proc/%d/exe", pid) + 1;
    symlinkPath = OPENSSL_zalloc(cbSymlink);

    if (symlinkPath != NULL &&
        snprintf(symlinkPath, cbSymlink, "/proc/%d/exe", pid) > 0 &&
        lstat(symlinkPath, &symlinkStat) != -1)
    {
        cbProcPath = symlinkStat.st_size == 0 ? PATH_MAX : symlinkStat.st_size;

        procPath = OPENSSL_malloc(cbProcPath);
        if (procPath != NULL &&
            (cbProcPathUsed = readlink(procPath, symlinkPath, cbProcPath)) == -1)
        {
            // Failure to read the the process path is not fatal but makes it
            // harder to match events to running processes.
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(procPath);
            procPath = NULL;
            cbProcPathUsed = 0;
        }
    }

    // Failure to generate the logging prefix is not fatal but makes it
    // harder to match events to running processes.
    prefix_size = snprintf(NULL, 0, "%ld,", now.tv_sec) + cbProcPathUsed;
    if ((prefix = OPENSSL_malloc(prefix_size + 1)) == NULL ||
        snprintf(prefix, prefix_size + 1, "%ld,%s", now.tv_sec, procPath == NULL ? "" : procPath) < 0)
    {
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
    }

    keysinuse_info_pending_lock = CRYPTO_THREAD_lock_new();
    sk_keysinuse_info = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();

    // Start the logging thread
    is_logging = TRUE;
    if (!pthread_condattr_init(&attr) ||
        !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) ||
        !pthread_cond_init(&logging_thread_cond_wake_early, &attr) ||
        (pthread_err = pthread_create(&logging_thread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
    {
        is_logging = FALSE;
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    keysinuse_enabled = TRUE;
    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        p_scossl_keysinuse_cleanup();
    }

    OPENSSL_free(symlinkPath);
    OPENSSL_free(procPath);

    return ret;
}

void p_scossl_keysinuse_cleanup()
{
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfoTmp;
    int pthread_err;

    if (prefix != default_prefix)
    {
        OPENSSL_free(prefix);
        prefix = (char*)default_prefix;
    }

    // Finish logging thread
    pthread_mutex_lock(&logging_thread_mutex);
    if (is_logging)
    {
        is_logging = FALSE;

        pthread_cond_signal(&logging_thread_cond_wake_early);
    }
    pthread_mutex_unlock(&logging_thread_mutex);

    if ((pthread_err = pthread_join(logging_thread, NULL)) != 0 ||
        logging_thread_exit_status != SCOSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    }

    // Cleanup any elements in the stack in case the logging thread failed
    while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info) > 0)
    {
        keysinuseInfoTmp = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info);
        p_scossl_keysinuse_info_free(keysinuseInfoTmp);
    }

    CRYPTO_THREAD_lock_free(keysinuse_info_pending_lock);
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info);
    sk_keysinuse_info = NULL;
    keysinuse_enabled = FALSE;
}

BOOL p_scossl_keysinuse_is_enabled()
{
    return keysinuse_enabled;
}

// Configuration
void p_scossl_keysinuse_set_enabled(BOOL enabled)
{
    keysinuse_enabled = enabled;
}

_Use_decl_annotations_
void p_scossl_keysinuse_set_logging_id(const char *id)
{
    if (id != NULL && *id != '\0')
    {
        strncpy(log_id, id, LOG_ID_LEN_MAX);
        log_id[LOG_ID_LEN_MAX] = '\0';
    }
    else
    {
        strcpy(log_id, default_log_id);
    }
}

SCOSSL_STATUS p_scossl_keysinuse_set_max_file_size(off_t size)
{
    if (size < 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
        return SCOSSL_FAILURE;
    }

    max_file_size = size;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_keysinuse_set_logging_delay(INT64 delay)
{
    if (delay < 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
        return SCOSSL_FAILURE;
    }

    loggingDelay = delay;

    return SCOSSL_SUCCESS;
}

// KeysInUse info management
_Use_decl_annotations_
SCOSSL_PROV_KEYSINUSE_INFO *p_scossl_keysinuse_info_new(_In_reads_bytes_(cbPublicKey) PBYTE pbPublicKey, SIZE_T cbPublicKey)
{
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo = NULL;
    PBYTE pbHash = NULL;
    SIZE_T hexStrLength;

    if (pbPublicKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto cleanup;
    }

    if ((keysinuseInfo = OPENSSL_zalloc(sizeof(SCOSSL_PROV_KEYSINUSE_INFO))) != NULL)
    {
        if ((pbHash = OPENSSL_malloc(SYMCRYPT_SHA256_RESULT_SIZE)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        SymCryptSha256(pbPublicKey, cbPublicKey, pbHash);

        if (!OPENSSL_buf2hexstr_ex(keysinuseInfo->keyIdentifier, SYMCRYPT_SHA256_RESULT_SIZE, &hexStrLength,
                                   pbHash, SYMCRYPT_SHA256_RESULT_SIZE, '\0'))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if ((keysinuseInfo->lock = CRYPTO_THREAD_lock_new()) == NULL ||
            !p_scossl_keysinuse_upref(keysinuseInfo, NULL))
        {
            p_scossl_keysinuse_info_free(keysinuseInfo);
            keysinuseInfo = NULL;
            goto cleanup;
        }
    }

cleanup:
    OPENSSL_free(pbHash);
    return keysinuseInfo;
}

_Use_decl_annotations_
void p_scossl_keysinuse_info_free(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    if (keysinuseInfo == NULL)
        return;

    INT32 ref = 0;

    if (!p_scossl_keysinuse_downref(keysinuseInfo, &ref))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return;
    }

    if (ref == 0)
    {
        CRYPTO_THREAD_lock_free(keysinuseInfo->lock);
        OPENSSL_free(keysinuseInfo);
    }
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_upref(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, INT32 *refOut)
{
    INT32 ref = 0;
    SCOSSL_STATUS ret = CRYPTO_atomic_add(&keysinuseInfo->refCount, 1, &ref, keysinuseInfo->lock);

    if (refOut != NULL)
        *refOut = ref;

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_keysinuse_downref(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, INT32 *refOut)
{
    INT32 ref = 0;
    SCOSSL_STATUS ret = CRYPTO_atomic_add(&keysinuseInfo->refCount, -1, &ref, keysinuseInfo->lock);

    if (refOut != NULL)
        *refOut = ref;

    return ret;
}

// Usage tracking
static void p_scossl_keysinuse_add_use(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, BOOL isSigning)
{
    if (p_scossl_keysinuse_is_enabled())
    {
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
                if (CRYPTO_THREAD_write_lock(keysinuse_info_pending_lock))
                {
                    sk_SCOSSL_PROV_KEYSINUSE_INFO_push(sk_keysinuse_info, keysinuseInfo);
                    p_scossl_keysinuse_upref(keysinuseInfo, NULL);
                    keysinuseInfo->logPending = TRUE;

                    // First use of this key, wake the logging thread
                    if (keysinuseInfo->firstUse == 0)
                    {
                        first_use_counter++;

                        CRYPTO_THREAD_unlock(keysinuse_info_pending_lock);

                        // Immediatly log use, signal logging thread
                        if (!pthread_mutex_lock(&logging_thread_mutex) ||
                            !pthread_cond_signal(&logging_thread_cond_wake_early))
                        {
                            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                        }
                        pthread_mutex_unlock(&logging_thread_mutex);
                    }
                    else
                    {
                        CRYPTO_THREAD_unlock(keysinuse_info_pending_lock);
                    }
                }
                else
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                }
            }

            CRYPTO_THREAD_unlock(keysinuseInfo->lock);
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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
