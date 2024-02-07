#include <p_scossl_keysinuse.h>
#include <p_scossl_base.h>

#include <time.h>
#include <pthread.h>

#define DEFAULT_loggingDelay 60 * 60
#define LOG_ID_LEN_MAX 16

static const char *default_log_id = "default";
static const char *default_iden = "";
static char log_id[LOG_ID_LEN_MAX+1] = {0};
static char *iden;
static int iden_len;

static int keysinuse_enabled = 0;
static long loggingDelay = DEFAULT_loggingDelay;

// This lock should be aquired before accessing keysinuseInfoPending and numFirstUse
static CRYPTO_RWLOCK *keysinuseInfoPendingLock = NULL;

// Stack of keysinuseInfo that have pending usage events to be logged by the
// logging thread.
// TODO stack cleanup on exit
static STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *keysinuseInfoPending = NULL;
static UINT numFirstUse = 0;

// On a busy machine, multiple processes using OpenSSL may be writing to the same log
// file at once. To minimize any overhead to crypto operations, all file writes are
// handled by the loggingThread. This thread periodically pops all pending usage
// data from keysinuseInfoPending, and writes to the log file. The thread wakes up early
// to immediately log the first use of a given key.
static pthread_t loggingThread;
static pthread_cond_t loggingThreadCond;
static pthread_mutex_t loggingThreadMutex = PTHREAD_MUTEX_INITIALIZER;
SCOSSL_STATUS loggingThreadExitStatus = SCOSSL_FAILURE;
BOOL loggingThreadRunning = TRUE;

static void *p_scossl_keysinuse_logging_thread_start(void *arg);

BOOL p_scossl_is_keysinuse_enabled()
{
    return keysinuse_enabled && scossl_prov_is_initialized();
}

SCOSSL_STATUS p_scsossl_keysinuse_init()
{
    int pthread_err;
    pthread_condattr_t attr;

    keysinuseInfoPendingLock = CRYPTO_THREAD_lock_new();
    keysinuseInfoPending = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();

    // Start the logging thread
    if (!pthread_condattr_init(&attr) ||
        !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) ||
        !pthread_cond_init(&loggingThreadCond, &attr) ||
        (pthread_err = pthread_create(&loggingThread, NULL, p_scossl_keysinuse_logging_thread_start, NULL)) != 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        loggingThreadRunning = FALSE;
        p_scossl_keysinuse_cleanup();
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

void p_scossl_keysinuse_cleanup()
{
    SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfoTmp;
    int pthread_err;
    // Finish logging thread
    if (loggingThreadRunning)
    {
        loggingThreadRunning = FALSE;

        pthread_mutex_lock(&loggingThreadMutex);
        pthread_cond_signal(&loggingThreadCond);
        pthread_mutex_unlock(&loggingThreadMutex);

        if ((pthread_err = pthread_join(loggingThread, NULL)) != 0 ||
            loggingThreadExitStatus != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        }
    }

    // Cleanup any elements in the stack in case the logging thread failed
    while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(keysinuseInfoPending) > 0)
    {
        keysinuseInfoTmp = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(keysinuseInfoPending);
        p_scossl_keysinuse_info_free(keysinuseInfoTmp);
    }

    CRYPTO_THREAD_lock_free(keysinuseInfoPendingLock);
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(keysinuseInfoPending);
    keysinuseInfoPending = NULL;
    keysinuse_enabled = FALSE;
}


static void p_scossl_keysinuse_log_usage(SCOSSL_PROV_KEYSINUSE_INFO *keysinuseInfo)
{
    // TODO write line to log
}


// The logging thread runs in a loop. It pops all pending usage from keysinuseInfoPending,
// and writes them to the log file. It sleeps for loggingDelay seconds between each iteration.
// On the first use of a key, the thread wakes up early to immediatley log the event. All pending
// events are logged on program exit.
static void *p_scossl_keysinuse_logging_thread_start(ossl_unused void *arg)
{
    // Logging thread is terminated by setting loggingThreadRunning to FALSE and signaling loggingThreadCond
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    // Every time the logging loop runs, all pending usage events are popped to this thread-local stack
    // to minimize the time keysinuseInfoPendingLock is held.
    STACK_OF(SCOSSL_PROV_KEYSINUSE_INFO) *keysinuseInfoPendingLocal = sk_SCOSSL_PROV_KEYSINUSE_INFO_new_null();
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

    while (loggingThreadRunning)
    {
        abstime.tv_sec += loggingDelay;

        // IF any first use events were added while this thread was logging, handle
        // them first before trying to sleep again.
        CRYPTO_THREAD_write_lock(keysinuseInfoPendingLock);
        if (numFirstUse == 0)
        {
            // Block loggingThreadCond from being signaled before unlocking keysinuseInfoPendingLock.
            // If another thread adds another first use event between here and pthread_cond_timedwait,
            // then it will have to wait until pthread_cond_timedwait is called to signal loggingThreadCond.
            pthread_mutex_lock(&loggingThreadMutex);
            CRYPTO_THREAD_lock_free(keysinuseInfoPendingLock);

            // Wait until loggingDelay has elapsed or the thread is signaled early.
            if (loggingThreadRunning)
            {
                waitStatus = pthread_cond_timedwait(&loggingThreadCond, &loggingThreadMutex, &abstime);
            }

            // IMPORTANT: Unlock loggingThreadMutex before aqcuiring keysinuseInfoPendingLock. The reverse
            // can lead to deadlock. If another thread acquires keysinuseInfoPendingLock first, and
            // needed to signal this thread, this thread would be waiting on keysinuseInfoPendingLock
            // and the other thread would be waiting on loggingThreadMutex..
            pthread_mutex_unlock(&loggingThreadMutex);
            CRYPTO_THREAD_write_lock(keysinuseInfoPendingLock);
        }

        clock_gettime(CLOCK_MONOTONIC, &abstime);
        now = abstime.tv_sec;

        // Condition signaled to wake the thread early. First key usage for numFirstUse keys
        if (waitStatus == 0)
        {
            numInfoPending = numFirstUse;
            numFirstUse = 0;

        }
        else if (waitStatus == ETIMEDOUT)
        {
            // Pop all elements
            numInfoPending = sk_SCOSSL_PROV_KEYSINUSE_INFO_num(keysinuseInfoPending);
            abstime.tv_sec += loggingDelay;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            break;
        }

        for (int i = 0; i < numInfoPending; i++)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(keysinuseInfoPending);
            if (pKeysinuseInfo != NULL)
            {
                sk_SCOSSL_PROV_KEYSINUSE_INFO_push(keysinuseInfoPendingLocal, pKeysinuseInfo);
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            }
        }
        CRYPTO_THREAD_unlock(keysinuseInfoPendingLock);

        // TODO: Log all events in keysinuseInfoPendingLocal

        while (sk_SCOSSL_PROV_KEYSINUSE_INFO_num(keysinuseInfoPendingLocal) > 0)
        {
            pKeysinuseInfo = sk_SCOSSL_PROV_KEYSINUSE_INFO_pop(keysinuseInfoPendingLocal);
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
    sk_SCOSSL_PROV_KEYSINUSE_INFO_free(keysinuseInfoPendingLocal);
    loggingThreadExitStatus = SCOSSL_SUCCESS;

    return NULL;
}

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
                if (CRYPTO_THREAD_write_lock(keysinuseInfoPendingLock))
                {
                    sk_SCOSSL_PROV_KEYSINUSE_INFO_push(keysinuseInfoPending, keysinuseInfo);
                    p_scossl_keysinuse_upref(keysinuseInfo, NULL);
                    keysinuseInfo->logPending = TRUE;

                    // First use of this key, wake the logging thread
                    if (keysinuseInfo->first_use == 0)
                    {
                        numFirstUse++;

                        CRYPTO_THREAD_unlock(keysinuseInfoPendingLock);

                        // Immediatly log use, signal logging thread
                        // TODO check returns
                        pthread_mutex_lock(&loggingThreadMutex);
                        pthread_cond_signal(&loggingThreadCond);
                        pthread_mutex_unlock(&loggingThreadMutex);
                    }
                    else
                    {
                        CRYPTO_THREAD_unlock(keysinuseInfoPendingLock);
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