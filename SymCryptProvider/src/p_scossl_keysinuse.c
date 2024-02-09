#include <p_scossl_keysinuse.h>
#include <p_scossl_base.h>

#include <openssl/proverr.h>

#include <pthread.h>
#include <linux/limits.h>
#include <linux/time.h>
#include <sys/stat.h>

#define DEFAULT_loggingDelay 60 * 60
#define LOG_ID_LEN_MAX 16

static const char *default_log_id = "default";
static const char *default_prefix = "";
static char log_id[LOG_ID_LEN_MAX+1] = {0};
static char *prefix = NULL;
static int prefix_size = 0;

static int keysinuse_enabled = 0;
static long loggingDelay = DEFAULT_loggingDelay;

// This lock should be aquired before accessing sk_keysinuse_info and first_use_counter
static CRYPTO_RWLOCK *keysinuse_info_pending_lock = NULL;

// Stack of keysinuseInfo that have pending usage events to be logged by the
// logging thread.
// TODO stack cleanup on exit
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
BOOL logging_trhead_running = TRUE;

static void p_scossl_keysinuse_log_usage(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    // TODO write line to log
}

// The logging thread runs in a loop. It pops all pending usage from sk_keysinuse_info,
// and writes them to the log file. It sleeps for loggingDelay seconds between each iteration.
// On the first use of a key, the thread wakes up early to immediatley log the event. All pending
// events are logged on program exit.
static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg)
{
    // Logging thread is terminated by setting logging_trhead_running to FALSE and signaling logging_thread_cond_wake_early
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    // Every time the logging loop runs, all pending usage events are popped to this thread-local stack
    // to minimize the time keysinuse_info_pending_lock is held.
    STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *sk_keysinuse_info_pending = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();
    struct timespec abstime;
    time_t now;
    SCOSSL_PROV_KEYSINUSE_INFO *pKeysinuseInfo;
    SCOSSL_PROV_KEYSINUSE_INFO keysinuseInfoTmp;
    int numInfoPending;
    int waitStatus;

    /* TODO:
        - Check if /var/log/keysinuse exists
            - If not, create /var/log/keysinuse
                - 01733, root owner, root group
    */
    clock_gettime(CLOCK_MONOTONIC, &abstime);

    while (logging_trhead_running)
    {
        abstime.tv_sec += loggingDelay;

        // IF any first use events were added while this thread was logging, handle
        // them first before trying to sleep again.
        CRYPTO_THREAD_write_lock(keysinuse_info_pending_lock);
        if (first_use_counter == 0)
        {
            // Block logging_thread_cond_wake_early from being signaled before unlocking keysinuse_info_pending_lock.
            // If another thread adds another first use event between here and pthread_cond_timedwait,
            // then it will have to wait until pthread_cond_timedwait is called to signal logging_thread_cond_wake_early.
            pthread_mutex_lock(&logging_thread_mutex);
            CRYPTO_THREAD_lock_free(keysinuse_info_pending_lock);

            // Wait until loggingDelay has elapsed or the thread is signaled early.
            if (logging_trhead_running)
            {
                waitStatus = pthread_cond_timedwait(&logging_thread_cond_wake_early, &logging_thread_mutex, &abstime);
            }

            // IMPORTANT: Unlock logging_thread_mutex before aqcuiring keysinuse_info_pending_lock. The reverse
            // can lead to deadlock. If another thread acquires keysinuse_info_pending_lock first, and
            // needed to signal this thread, this thread would be waiting on keysinuse_info_pending_lock
            // and the other thread would be waiting on logging_thread_mutex..
            pthread_mutex_unlock(&logging_thread_mutex);
            CRYPTO_THREAD_write_lock(keysinuse_info_pending_lock);
        }

        clock_gettime(CLOCK_MONOTONIC, &abstime);
        now = abstime.tv_sec;

        // Condition signaled to wake the thread early. First key usage for first_use_counter keys
        if (waitStatus == 0)
        {
            numInfoPending = first_use_counter;
            first_use_counter = 0;

        }
        else if (waitStatus == ETIMEDOUT)
        {
            // Pop all elements
            numInfoPending = sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info);
            abstime.tv_sec += loggingDelay;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            break;
        }

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

        // TODO: Log all events in sk_keysinuse_info_pending

        while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(sk_keysinuse_info_pending) > 0)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(sk_keysinuse_info_pending);
            if (pKeysinuseInfo != NULL &&
                CRYPTO_THREAD_write_lock(pKeysinuseInfo->lock))
            {
                pKeysinuseInfo->first_use = pKeysinuseInfo->last_logged_use;
                pKeysinuseInfo->last_logged_use = now;

                keysinuseInfoTmp = *pKeysinuseInfo;

                CRYPTO_THREAD_unlock(pKeysinuseInfo->lock);

                p_scossl_keysinuse_log_usage(&keysinuseInfoTmp);
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            }

            p_scossl_keysinuse_info_free(pKeysinuseInfo);
        }
    }

    // TODO additional thread cleanup
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(sk_keysinuse_info_pending);
    logging_thread_exit_status = SCOSSL_SUCCESS;

    return NULL;
}

// Setup/teardown
SCOSSL_STATUS p_scsossl_keysinuse_init(char *logging_id)
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
        snprintf(procPath, cbSymlink, "/proc/%d/exe", pid) > 0 &&
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
    if (!pthread_condattr_init(&attr) ||
        !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) ||
        !pthread_cond_init(&logging_thread_cond_wake_early, &attr) ||
        (pthread_err = pthread_create(&logging_thread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    keysinuse_enabled = TRUE;
    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        logging_trhead_running = FALSE;
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
    if (logging_trhead_running)
    {
        logging_trhead_running = FALSE;

        pthread_mutex_lock(&logging_thread_mutex);
        pthread_cond_signal(&logging_thread_cond_wake_early);
        pthread_mutex_unlock(&logging_thread_mutex);

        if ((pthread_err = pthread_join(logging_thread, NULL)) != 0 ||
            logging_thread_exit_status != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        }
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

BOOL p_scossl_is_keysinuse_enabled()
{
    return keysinuse_enabled;
}

// Configuration
void p_scossl_keysinuse_set_enabled(BOOL enabled)
{
    keysinuse_enabled = enabled;
}

_Use_decl_annotations_
void p_scossl_keysinuse_set_logging_id(char *id)
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

// KeysInUse Info management
_Use_decl_annotations_
SCOSSL_PROV_KEYSINUSE_INFO *p_scossl_keysinuse_info_new(char key_identifier[static KEY_IDENTIFIER_CHAR_SIZE])
{
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo = OPENSSL_zalloc(sizeof(SCOSSL_PROV_KEYSINUSE_INFO));
    if (keysinuseInfo != NULL)
    {
        keysinuseInfo->lock = CRYPTO_THREAD_lock_new();
        OPENSSL_strlcpy(keysinuseInfo->key_identifier, key_identifier, KEY_IDENTIFIER_CHAR_SIZE);

        if (!p_scossl_keysinuse_upref(keysinuseInfo, NULL))
        {
            p_scossl_keysinuse_free(keysinuseInfo);
            return NULL;
        }
    }

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

void p_scossl_keysinuse_add_use(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo, BOOL isSigning)
{
    if (p_scossl_is_keysinuse_enabled())
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
                    if (keysinuseInfo->first_use == 0)
                    {
                        first_use_counter++;

                        CRYPTO_THREAD_unlock(keysinuse_info_pending_lock);

                        // Immediatly log use, signal logging thread
                        // TODO check returns
                        pthread_mutex_lock(&logging_thread_mutex);
                        pthread_cond_signal(&logging_thread_cond_wake_early);
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
/*
    OLD CODE TODO
*/
void set_loggingDelay(long new_backoff)
{
    loggingDelay = new_backoff;
}

// void set_logging_id(char *id);
// {
//     // Restrict log id length
//     if (id != NULL && *id != '\0')
//     {
//         strncpy(log_id, id, LOG_ID_LEN_MAX);
//         // Ensure log_id is null terminated. If id is longer
//         // than id_len then stdncpy will not null terminate log_id
//         log_id[LOG_ID_LEN_MAX] = '\0';
//     }
//     else
//     {
//         strcpy(log_id, default_log_id);
//     }
// }
// void log_init()
// {
//     set_logging_id(NULL);
//     char *exe_path = NULL;
//     time_t start_time = time(NULL);

// #ifdef __linux__
//     exe_path = OPENSSL_zalloc(PATH_MAX + 1);

//     pid_t pid = getpid();
//     int len_sym_path = snprintf(NULL, 0, "/proc/%d/exe", pid) + 1;
//     char *sym_path = OPENSSL_zalloc(len_sym_path);

//     if (snprintf(sym_path, len_sym_path, "/proc/%d/exe", pid) > 0)
//     {
//         readlink(sym_path, exe_path, PATH_MAX + 1);
//     }
//     else
//     {
//         strcpy(exe_path, "");
//     }

//     OPENSSL_free(sym_path);
// #endif //__linux__

//     if (exe_path)
//     {
//         iden_len = snprintf(NULL, 0, "%ld,%s", start_time, exe_path);
//         iden_len = iden_len > ID_LEN_MAX ? ID_LEN_MAX : iden_len;

//         iden = OPENSSL_malloc(iden_len + 1);

//         // If sprintf fails, we can still log key usage. This should never
//         // happen, but we don't want to cause any crashes in case it does.
//         if (iden == NULL ||
//             snprintf(iden, iden_len + 1, "%ld,%s", start_time, exe_path) < 0)
//         {
//             OPENSSL_free(iden);
//             iden = (char*)default_iden;
//         }
//     }

//     OPENSSL_free(exe_path);
// }

// void log_cleanup()
// {
//     if (iden != default_iden)
//     {
//         OPENSSL_free(iden);
//         iden = (char *)default_iden;
//     }
// }

// void log_debug(const char *message, ...)
// {
// #ifdef DEBUG
//     va_list args;
//     va_start(args, message);
//     _log_internal(LOG_DEBUG, message, args);
// #endif // DEBUG
// }

// void log_error(const char *message, ...)
// {
//     va_list args;
//     va_start(args, message);
//     _log_internal(LOG_ERR, message, args);
// }

// void log_notice(const char *message, ...)
// {
//     va_list args;
//     va_start(args, message);
//     _log_internal(LOG_NOTICE, message, args);
// }

// static void _log_internal(int level, const char *message, va_list args)
// {
//     char *level_str = "";
//     char log_path[LOG_PATH_LEN + 1];
//     char msg_buf[LOG_MSG_MAX];
//     int msg_len;

//     switch (level)
//     {
// #ifdef DEBUG
//     case LOG_DEBUG:
//         level_str = "dbg";
//         break;
// #endif // DEBUG
//     case LOG_ERR:
//         level_str = "err";
//         break;
//     case LOG_NOTICE:
//     default:
//         level_str = "not";
//         break;
//     }

//     uid_t euid = geteuid();

//     sprintf(log_path, LOG_PATH_TMPL, level_str, euid, log_id);

//     if ((msg_len = vsnprintf(msg_buf, LOG_MSG_MAX, message, args)) > 0)
//     {
//         int len = iden_len + msg_len + 6;
//         char prefixed_msg[len + 1];
//         strcpy(prefixed_msg, "");
//         strcat(prefixed_msg, iden);
//         strcat(prefixed_msg, ",");
//         strcat(prefixed_msg, level_str);
//         strcat(prefixed_msg, "!");
//         strcat(prefixed_msg, msg_buf);
//         strcat(prefixed_msg, "\n");

//         // Check the log file to make sure:
//         // 1. File isn't a symlink
//         // 2. File permissions are 0200
//         // 3. Logging won't exceed maximum file size
//         struct stat sb;
//         if (__xstat(STAT_VER, log_path, &sb) != -1)
//         {
//             int isBadFile = 0;
//             if (S_ISLNK(sb.st_mode))
//             {
//                 if (level > LOG_ERR)
//                 {
//                     log_error("Found symlink at %s. Removing file", log_path);
//                 }
// #ifdef DEBUG
//                 else
//                 {
//                     fprintf(stderr, "Found symlink at %s. Removing file\n", log_path);
//                 }
// #endif // DEBUG

//                 isBadFile = 1;
//             }

//             if (!isBadFile && (sb.st_mode & 0777) != 0200)
//             {
//                 if (level > LOG_ERR)
//                 {
//                     log_error("Found unexpected permissions (%o) on %s. Removing file", (sb.st_mode & 0777), log_path);
//                 }
// #ifdef DEBUG
//                 else
//                 {
//                     fprintf(stderr, "Found unexpected permissions (%o) on %s. Removing file\n", (sb.st_mode & 0777), log_path);
//                 }
// #endif // DEBUG
//                 isBadFile = 1;
//             }

//             if (isBadFile)
//             {
//                 if (remove(log_path) != 0)
//                 {
//                     if (level > LOG_ERR)
//                     {
//                         log_error("Failed to remove bad log file at %s,SYS_%d", log_path, errno);
//                     }
//     #ifdef DEBUG
//                 else
//                 {
//                     fprintf(stderr, "Failed to remove bad log file at %s,SYS_%d\n", log_path, errno);
//                 }
// #endif // DEBUG
//                     return;
//                 }
//             }
//             else if (sb.st_size + len > max_file_size)
//             {
//                 if (level > LOG_ERR)
//                 {
//                     log_error("Failed to log to %s. File size capped at %ld bytes", log_path, max_file_size);
//                 }
// #ifdef DEBUG
//                 else
//                 {
//                     fprintf(stderr, "Failed to log to %s. File size capped at %ld bytes\n", log_path, max_file_size);
//                 }
// #endif // DEBUG
//                 return;
//             }
//         }
//         else if (errno != ENOENT)
//         {
//             if (level > LOG_ERR)
//             {
//                 log_error("Failed to stat file at %s,SYS_%d", log_path, errno);
//             }
// #ifdef DEBUG
//             else
//             {
//                 fprintf(stderr, "Failed to stat file at %s,SYS_%d\n", log_path, errno);
//             }
// #endif // DEBUG
//             return;
//         }

//         // Log files are separated by uid. Only write access is needed
//         int fd;
//         for (int i = 0; i < 3; i++)
//         {
//             fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0200);
//             if (fd >= 0 || errno != EACCES)
//             {
//                 break;
//             }
//             usleep(500); // Sleep for 500 microseconds
//         }

//         if (fd < 0)
//         {
//             if (level > LOG_ERR)
//             {
//                 log_error("Failed to open log file for appending at %s,SYS_%d", log_path, errno);
//             }
// #ifdef DEBUG
//             else
//             {
//                 fprintf(stderr, "Failed to open log file for appending at %s,SYS_%d\n", log_path, errno);
//             }
// #endif // DEBUG
//             return;
//         }
//         fchmod(fd, 0200);

//         if (write(fd, prefixed_msg, len) < 0)
//         {
//             if (level > LOG_ERR)
//             {
//                 log_error("Failed to write to log file at %s,SYS_%d", log_path, errno);
//             }
// #ifdef DEBUG
//             else
//             {
//                 fprintf(stderr, "Failed to write to log file at %s,SYS_%d\n", log_path, errno);
//             }
// #endif // DEBUG
//         }

//         if (close(fd) < 0 && level > LOG_ERR)
//         {
//             if (level > LOG_ERR)
//             {
//                 log_error("Failed to close log file at %s,SYS_%d", log_path, errno);
//             }
// #ifdef DEBUG
//             else
//             {
//                 fprintf(stderr, "Failed to close log file at %s,SYS_%d\n", log_path, errno);
//             }
// #endif // DEBUG
//         }
//     }
// }