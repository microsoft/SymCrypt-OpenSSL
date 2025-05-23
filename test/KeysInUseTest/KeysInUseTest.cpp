//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <fstream>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#ifndef KEYSINUSE_LOG_SYSLOG
    #include <ftw.h>
#endif

#include "scossl_helpers.h"
#include "keysinuse.h"

#include <openssl/evp.h>

#if OPENSSL_VERSION_MAJOR >= 3
    #include <openssl/core_names.h>
    #include <openssl/provider.h>
#endif

#define KEYSINUSE_TEST_LOG_DELAY 2 // seconds
// Time to wait for the log thread to finish writing
#define KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME 200 * 1000 // 200 milliseconds

#define KEYSINUSE_TEST_SIGN_PLAINTEXT_SIZE 256
#define KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE 64
#define SCOSSL_KEYID_SIZE (SYMCRYPT_SHA256_RESULT_SIZE + 1)

#ifndef KEYSINUSE_LOG_SYSLOG
    #define KEYSINUSE_TEST_ROOT "keysinuse_test_root"
    #define KEYSINUSE_LOG_DIR "/var/log/keysinuse"
    #define KEYSINUSE_LOG_FILE KEYSINUSE_LOG_DIR "/keysinuse_not_00000000.log"
#endif

static bool logVerbose = false;
static bool checkSyslog = false;

using namespace std;

typedef struct
{
    char keyIdentifier[SCOSSL_KEYID_SIZE];
    PCBYTE pbKey;
    SIZE_T cbKey;
} KEYSINUSE_TEST_CASE;

// Represents the expected events logged for a key.
typedef struct
{
    int signCount;
    int decryptCount;
    time_t loggingDelay;
} KEYSINUSE_EXPECTED_EVENT;

// Represents a provider to test and whether *provider is a
// filepath or provider name.
static void _test_log_err(const char *file, int line, const char *message, ...)
{
    va_list args;
    va_start(args, message);

    fprintf(stderr, "\033[1;31m%s:%d: ", file, line);
    vfprintf(stderr, message, args);
    fprintf(stderr, "\033[0m\n");
}

static void _test_log_openssl_err(const char *file, int line, const char *message, ...)
{
    va_list args;
    va_start(args, message);

    fprintf(stderr, "\033[1;31m%s:%d: ", file, line);
    vfprintf(stderr, message, args);
    fprintf(stderr, "\n");
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\033[0m\n");
}

#define TEST_LOG_ERROR(...) _test_log_err(__FILE__, __LINE__, __VA_ARGS__);
#define TEST_LOG_OPENSSL_ERROR(...) _test_log_openssl_err(__FILE__, __LINE__, __VA_ARGS__);
#define TEST_LOG_VERBOSE(...) if (logVerbose) printf(__VA_ARGS__);

typedef struct
{
    const int keyType;
    const int keygenParams; // Type specific keygen params. Key size for RSA, group nid for ECDSA
    EVP_PKEY *pkey;
    PBYTE pbEncodedKey;
    SIZE_T cbEncodedKey;
    char pbKeyId[SCOSSL_KEYID_SIZE];
} KEYSINUSE_TEST_KEY;

static KEYSINUSE_TEST_KEY testKeys[] = {
    {EVP_PKEY_RSA,      2048,                   nullptr, nullptr, 0, {}},
    {EVP_PKEY_RSA,      3072,                   nullptr, nullptr, 0, {}},
    {EVP_PKEY_RSA,      4096,                   nullptr, nullptr, 0, {}},
#if OPENSSL_VERSION_MAJOR >= 3
    {EVP_PKEY_X25519,   0,                      nullptr, nullptr, 0, {}},
#endif
    {EVP_PKEY_EC,       NID_X9_62_prime192v1,   nullptr, nullptr, 0, {}},
    {EVP_PKEY_EC,       NID_secp224r1,          nullptr, nullptr, 0, {}},
    {EVP_PKEY_EC,       NID_X9_62_prime256v1,   nullptr, nullptr, 0, {}},
    {EVP_PKEY_EC,       NID_secp384r1,          nullptr, nullptr, 0, {}},
    {EVP_PKEY_EC,       NID_secp521r1,          nullptr, nullptr, 0, {}}};

static char *processName;
static time_t processStartTime;

#if OPENSSL_VERSION_MAJOR < 3
// OpenSSL 1.1.1 doesn't natively support EVP_PKEY duplication.
// This function duplicates the EVP_PKEY by exporting and re-importing
// the key into a new EVP_PKEY structure.
EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey)
{
    EVP_PKEY *pkeyCopy = nullptr;
    unsigned char *pbKey = nullptr;
    SIZE_T cbKey = 0;

    if (!i2d_PrivateKey(pkey, &pbKey))
    {
        TEST_LOG_OPENSSL_ERROR("Failed to convert private key to DER format")
        goto cleanup;
    }

    if (!d2i_PrivateKey(EVP_PKEY_id(pkey), &pkeyCopy, (const unsigned char **)&pbKey, cbKey))
    {
        TEST_LOG_OPENSSL_ERROR("Failed to convert DER format to private key")
        goto cleanup;
    }

cleanup:
    OPENSSL_free(pbKey);

    return pkeyCopy;
}
#endif

static void keysinuse_test_cleanup()
{
#ifndef KEYSINUSE_LOG_SYSLOG
    int nftwCleanupRes;

    nftwCleanupRes = nftw(KEYSINUSE_TEST_ROOT,
        [](const char *path, const struct stat *sb, int ftwType, struct FTW *ftw) {
            return remove(path);
        },
        16, FTW_DEPTH);

    if (nftwCleanupRes == -1)
    {
        if (errno != ENOENT)
        {
            TEST_LOG_ERROR("Failed to cleanup testing root: %d", errno)
        }
    }
    else if (nftwCleanupRes != 0)
    {
        TEST_LOG_ERROR("Failed to cleanup testing root: %d", nftwCleanupRes)
    }
#endif

    for (int i = 0; i < sizeof(testKeys) / sizeof(testKeys[0]); i++)
    {
        EVP_PKEY_free(testKeys[i].pkey);
        OPENSSL_free(testKeys[i].pbEncodedKey);
    }
}

static bool isNumeric(const char *str)
{
    for (int i = 0; str[i] != '\0'; i++)
    {
        if (!isdigit(str[i]))
        {
            return false;
        }
    }
    return true;
}

static SCOSSL_STATUS keysinuse_test_check_log(char pbKeyId[SCOSSL_KEYID_SIZE], KEYSINUSE_EXPECTED_EVENT expectedEvents[], int numExpectedEvents)
{
    FILE *logOutput = nullptr;
    struct stat sb;
    char *pbLine = nullptr;
    char *curLine = nullptr;
    SIZE_T cbLine = 0;
    ssize_t cbRead = 0;
    char *pbExpectedHeader = nullptr;
    char *pbHeader;
    char *pbBody;
    char *pbCurToken;
    time_t loggedStartTime;
    time_t firstLogTime;
    time_t lastLogTime;

    SCOSSL_STATUS ret = SCOSSL_FAILURE;

#ifdef KEYSINUSE_LOG_SYSLOG
    char journalCtlCommand[64];

    if (sprintf(journalCtlCommand, "/usr/bin/journalctl -t keysinuse -n %d", numExpectedEvents) < 0)
    {
        TEST_LOG_ERROR("Failed to create journalctl command")
        goto cleanup;
    }

    if ((logOutput = popen(journalCtlCommand, "r")) == NULL)
    {
        TEST_LOG_ERROR("Failed to run journalctl: %d", errno)
        goto cleanup;
    }

    // First line of journalctl is informational and should be skipped
    if (getline(&pbLine, &cbLine, logOutput) < 0)
    {
        TEST_LOG_ERROR("No output from journalctl")
        goto cleanup;
    }
#else
    if ((logOutput = fopen(KEYSINUSE_LOG_FILE, "r")) == NULL ||
        stat(KEYSINUSE_LOG_FILE, &sb) == -1)
    {
        TEST_LOG_ERROR("Failed to open log file: %d", errno)
        goto cleanup;
    }

    if ((sb.st_mode & 0777) != 0200)
    {
        TEST_LOG_ERROR("Log file permissions are not 0200: %o", (sb.st_mode & 0777))
        goto cleanup;
    }
#endif

    // Read and validate the first line's header. The rest of the lines
    // should match exactly.
    if ((cbRead = getline(&pbLine, &cbLine, logOutput)) < 0)
    {
        TEST_LOG_ERROR("Reached end of log file before expected.")
        goto cleanup;
    }
    curLine = pbLine;

    pbLine[cbRead - 1] = '\0'; // Remove the newline character
    TEST_LOG_VERBOSE("\t\t1: %s\n", curLine);

#ifdef KEYSINUSE_LOG_SYSLOG
    // Skip past the syslog header first
    pbHeader = strpbrk(curLine, "]");
    pbHeader += 3;
    pbHeader = strtok(pbHeader, "!");
#else
    pbHeader = strtok(curLine, "!");
#endif
    pbBody = strtok(nullptr, "");


    if (pbHeader == NULL || pbBody == NULL)
    {
        TEST_LOG_ERROR("Failed to parse log file header")
        goto cleanup;
    }

    pbExpectedHeader = strdup(pbHeader);

    // Check the logged start time >= processStartTime
    if ((pbCurToken = strtok(pbHeader, ",")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse process start time")
        goto cleanup;
    }

    if ((loggedStartTime = atol(pbCurToken)) < processStartTime)
    {
        TEST_LOG_ERROR("Logged process start time is before the test started. Expected >= %ld, Logged: %ld", processStartTime, loggedStartTime)
        goto cleanup;
    }

    // Check the logged process name name matches the current process name
    if ((pbCurToken = strtok(nullptr, ",")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse process name")
        goto cleanup;
    }

    if (strcmp(pbCurToken, processName) != 0)
    {
        TEST_LOG_ERROR("Logged process name does not match.\n\tExpected %s\n\tLogged: %s", processName, pbCurToken)
        goto cleanup;
    }

    // Check the logging level == not
    if ((pbCurToken = strtok(nullptr, "!")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse logging level")
        goto cleanup;
    }

    if (strcmp(pbCurToken, "not") != 0)
    {
        TEST_LOG_ERROR("Header logging level is not \"not\". Logged: %s", pbCurToken)
        goto cleanup;
    }

    for (int i = 0; i < numExpectedEvents; i++)
    {
        if (i != 0)
        {
            if ((cbRead = getline(&curLine, &cbLine, logOutput)) < 0)
            {
                TEST_LOG_ERROR("Reached end of log file before expected.")
                goto cleanup;
            }

            pbLine[cbRead - 1] = '\0'; // Remove the newline character
            TEST_LOG_VERBOSE("\t\t1: %s\n", curLine);

#ifdef KEYSINUSE_LOG_SYSLOG
            // Skip past the syslog header first
            pbHeader = strpbrk(curLine, "]");
            pbHeader += 3;
            pbHeader = strtok(pbHeader, "!");
#else
            pbHeader = strtok(curLine, "!");
#endif

            if (pbHeader == NULL || pbBody == NULL)
            {
                TEST_LOG_ERROR("Failed to parse log file header.")
                goto cleanup;
            }

            if (strcmp(pbExpectedHeader, pbHeader) != 0)
            {
                TEST_LOG_ERROR("Logged header does not match.\n\tExpected %s\n\tLogged: %s", pbExpectedHeader, pbHeader)
                goto cleanup;
            }
        }

        // Check key ID
        if ((pbCurToken = strtok(pbBody, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse key ID")
            goto cleanup;
        }

        if (strcmp(pbKeyId, pbCurToken) != 0)
        {
            TEST_LOG_ERROR("Logged key ID does not match. Expected %s, Logged: %s", pbKeyId, pbCurToken)
            goto cleanup;
        }

        // Check sign count
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse key ID")
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged sign count is not numeric. Logged: %s", pbCurToken)
            goto cleanup;
        }

        if (atoi(pbCurToken) != expectedEvents[i].signCount)
        {
            TEST_LOG_ERROR("Logged sign count does not match. Expected %d, Logged: %s", expectedEvents[i].signCount, pbCurToken)
            goto cleanup;
        }

        // Check decrypt count
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse decrypt count.")
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged decrypt count is not numeric. Logged: %s", pbCurToken)
            goto cleanup;
        }

        if (atoi(pbCurToken) != expectedEvents[i].decryptCount)
        {
            TEST_LOG_ERROR("Logged decrypt count does not match. Expected %d, Logged: %s", expectedEvents[i].decryptCount, pbCurToken)
            goto cleanup;
        }

        // Check first log time
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse first log time.")
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged first log time is not numeric. Logged: %s", pbCurToken)
            goto cleanup;
        }

        firstLogTime = atol(pbCurToken);

        if (i > 0 &&
            firstLogTime < lastLogTime)
        {
            TEST_LOG_ERROR("Logged first log time is before the last log time from the previous logging event. First: %ld, Last: %ld", firstLogTime, lastLogTime)
            goto cleanup;
        }

        // Check last log time
        if ((pbCurToken = strtok(nullptr, "")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse last log time.");
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged last log time is not numeric. Logged: %s", pbCurToken)
            goto cleanup;
        }

        lastLogTime = atol(pbCurToken);

        // Check the first log time >= processStartTime
        if (firstLogTime < processStartTime)
        {
            TEST_LOG_ERROR("First log time is before the test started. Expected >= %ld, Logged: %ld", processStartTime, firstLogTime)
            goto cleanup;
        }

        if (expectedEvents[i].loggingDelay != 0)
        {
            if (lastLogTime - firstLogTime < expectedEvents[i].loggingDelay)
            {
                TEST_LOG_ERROR("Event logged before expected logging delay expired. Expected >= %lds, Logged: %lds", expectedEvents[i].loggingDelay, firstLogTime - loggedStartTime)
                goto cleanup;
            }
        }
        else if (firstLogTime != lastLogTime)
        {
            TEST_LOG_ERROR("First and last log time do not match. First: %ld, Last: %ld", firstLogTime, lastLogTime)
            goto cleanup;
        }
    }

    if (getline(&curLine, &cbLine, logOutput) >= 0)
    {
        TEST_LOG_ERROR("Log file has more lines than expected.")
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:

    if (logOutput != NULL)
    {
#ifdef KEYSINUSE_LOG_SYSLOG
        pclose(logOutput);
#else
        fclose(logOutput);
#endif
    }

    free(pbExpectedHeader);
    free(pbLine);

    return ret;
}

SCOSSL_STATUS keysinuse_test_api_functions(PCBYTE pcbPublicKey, SIZE_T cbPublicKey, char pbKeyId[SCOSSL_KEYID_SIZE], keysinuse_operation operation)
{
    SCOSSL_KEYSINUSE_CTX *keysinuseCtx = NULL;
    // Second keysinuse context loaded with the same key bytes
    SCOSSL_KEYSINUSE_CTX *keysinuseCtxCopy = NULL;
    // Third keysinuse context loaded by reference
    SCOSSL_KEYSINUSE_CTX *keysinuseCtxCopyByRef = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, KEYSINUSE_TEST_LOG_DELAY},
        {0, 0, 0}};

    // Load the keysinuse context
    if ((keysinuseCtx = keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load keysinuse context")
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by bytes again
    if ((keysinuseCtxCopy = keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes")
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by reference
    if ((keysinuseCtxCopyByRef = keysinuse_load_key_by_ctx(keysinuseCtx)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context by reference")
        return SCOSSL_FAILURE;
    }

    if (keysinuseCtx != keysinuseCtxCopy ||
        keysinuseCtx != keysinuseCtxCopyByRef)
    {
        TEST_LOG_ERROR("KeysInUse contexts do not match")
        return SCOSSL_FAILURE;
    }

    // Unload one of the keysinuse contexts. The other two should still be valid
    keysinuse_unload_key(keysinuseCtxCopy);
    keysinuseCtxCopy = NULL;

    // Test three consecutive uses. The first event should be logged.
    // The second event should only be logged after the elapsed wait time.
    keysinuse_on_use(keysinuseCtx, operation);

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second sign. Only the first event should be logged.
    keysinuse_on_use(keysinuseCtx, operation);
    keysinuse_on_use(keysinuseCtxCopyByRef, operation);

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    keysinuse_unload_key(keysinuseCtx);
    keysinuseCtx = NULL;

    keysinuse_unload_key(keysinuseCtxCopyByRef);
    keysinuseCtxCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if ((keysinuseCtxCopy = keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes")
        return SCOSSL_FAILURE;
    }

    // Test key use again, this event should be immediately logged
    keysinuse_on_use(keysinuseCtxCopy, operation);

    if (operation == KEYSINUSE_SIGN)
    {
        expectedEvents[0].signCount = 1;
        expectedEvents[1].signCount = 2;
        expectedEvents[2].signCount = 1;
    }
    else
    {
        expectedEvents[0].decryptCount = 1;
        expectedEvents[1].decryptCount = 2;
        expectedEvents[2].decryptCount = 1;
    }

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
#ifndef KEYSINUSE_LOG_SYSLOG
    remove(KEYSINUSE_LOG_FILE);
#endif

cleanup:
    keysinuse_unload_key(keysinuseCtx);
    keysinuse_unload_key(keysinuseCtxCopy);
    keysinuse_unload_key(keysinuseCtxCopyByRef);

    return ret;
}

#if OPENSSL_VERSION_MAJOR >= 3
SCOSSL_STATUS keysinuse_test_provider_sign(EVP_PKEY *pkeyBase, char pbKeyId[SCOSSL_KEYID_SIZE], string providerName)
{
    string propq;
    const char *keyType = EVP_PKEY_get0_type_name(pkeyBase);
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *importCtx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctxCopy = NULL;
    EVP_PKEY_CTX *ctxCopyByRef = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyCopy = NULL;
    EVP_PKEY *pkeyCopyByRef = NULL;
    BYTE pbPlainText[SHA256_DIGEST_LENGTH];
    SIZE_T cbPlainText = SHA256_DIGEST_LENGTH;
    PBYTE pbCipherText = NULL;
    SIZE_T cbCipherText = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, KEYSINUSE_TEST_LOG_DELAY},
        {0, 0, 0}};

    propq = "provider=" + providerName;

    if (!EVP_PKEY_todata(pkeyBase, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, &params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_todata failed")
        goto cleanup;
    }

    if ((importCtx = EVP_PKEY_CTX_new_from_name(NULL, keyType, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_name failed")
        goto cleanup;
    }

    if (!EVP_PKEY_fromdata_init(importCtx))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_fromdata_init failed")
        goto cleanup;
    }

    // Same key material for distinct pkey objects should log with the same keysinuse info
    if (!EVP_PKEY_fromdata(importCtx, &pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params) ||
        !EVP_PKEY_fromdata(importCtx, &pkeyCopy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params))   {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_fromdata failed");
        goto cleanup;
    }

    if (RAND_bytes(pbPlainText, cbPlainText) != 1)
    {
        TEST_LOG_ERROR("RAND_bytes failed")
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, propq.c_str())) == NULL ||
        (ctxCopy = EVP_PKEY_CTX_new_from_pkey(NULL, pkeyCopy, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    // Sign init
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_sign_init(ctxCopy) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_PKEY_sign_init
    // should trigger keysinuse_load_key_by_ctx
    if ((pkeyCopyByRef = EVP_PKEY_dup(pkey)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctxCopyByRef = EVP_PKEY_CTX_new_from_pkey(NULL, pkeyCopyByRef, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    if (EVP_PKEY_sign_init(ctxCopyByRef) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    // Sign
    if (!EVP_PKEY_sign(ctx, NULL, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }

    if ((pbCipherText = (PBYTE)OPENSSL_malloc(cbCipherText)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OPENSSL_malloc failed")
        goto cleanup;
    }

    if (!EVP_PKEY_sign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }
    expectedEvents[0].signCount = 1;

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second and third sign. Only the first event should be logged.
    if (!EVP_PKEY_sign(ctxCopy, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) ||
        !EVP_PKEY_sign(ctxCopyByRef, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }
    expectedEvents[1].signCount = 2;

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    ctx = NULL;
    ctxCopy = NULL;
    ctxCopyByRef = NULL;
    pkey = NULL;
    pkeyCopy = NULL;
    pkeyCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if (!EVP_PKEY_fromdata(importCtx, &pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_new_raw_private_key_ex failed");
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_MD_CTX_new failed")
        goto cleanup;
    }

    // Test key use again, this event should be immediately logged
    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    if (!EVP_PKEY_sign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[2].signCount = 1;

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
#ifndef KEYSINUSE_LOG_SYSLOG
    remove(KEYSINUSE_LOG_FILE);
#endif

cleanup:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(importCtx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    OPENSSL_free(pbCipherText);

    return ret;
}

SCOSSL_STATUS keysinuse_test_provider_decrypt(EVP_PKEY *pkeyBase, char pbKeyId[SCOSSL_KEYID_SIZE], string providerName)
{
    string propq;
    const char *keyType = EVP_PKEY_get0_type_name(pkeyBase);
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *importCtx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctxCopy = NULL;
    EVP_PKEY_CTX *ctxCopyByRef = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyCopy = NULL;
    EVP_PKEY *pkeyCopyByRef = NULL;
    BYTE pbPlainText[KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE];
    SIZE_T cbPlainText = KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE;
    PBYTE pbCipherText = NULL;
    SIZE_T cbCipherText = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, KEYSINUSE_TEST_LOG_DELAY},
        {0, 0, 0}};

    propq = "provider=" + providerName;

    if (RAND_bytes(pbPlainText, cbPlainText) != 1)
    {
        TEST_LOG_ERROR("RAND_bytes failed")
        goto cleanup;
    }

    if (!EVP_PKEY_todata(pkeyBase, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, &params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_todata failed")
        goto cleanup;
    }

    if ((importCtx = EVP_PKEY_CTX_new_from_name(NULL, keyType, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_name failed")
        goto cleanup;
    }

    if (!EVP_PKEY_fromdata_init(importCtx))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_fromdata_init failed")
        goto cleanup;
    }

    // Same key material for distinct pkey objects should log with the same keysinuse info
    if (!EVP_PKEY_fromdata(importCtx, &pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params) ||
        !EVP_PKEY_fromdata(importCtx, &pkeyCopy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params))   {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_fromdata failed")
        goto cleanup;
    }

    // Generate test ciphertext
    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkeyBase, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_pkey failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt_init failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt failed")
        goto cleanup;
    }

    if ((pbCipherText = (PBYTE)OPENSSL_malloc(cbCipherText)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OPENSSL_malloc failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt failed")
        goto cleanup;
    }

    EVP_PKEY_CTX_free(ctx);

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, propq.c_str())) == NULL ||
        (ctxCopy = EVP_PKEY_CTX_new_from_pkey(NULL, pkeyCopy, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_pkey failed")
        goto cleanup;
    }

    // Decrypt init
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_decrypt_init(ctxCopy) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_PKEY_decrypt_init
    // should trigger keysinuse_load_key_by_ctx
    if ((pkeyCopyByRef = EVP_PKEY_dup(pkey)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctxCopyByRef = EVP_PKEY_CTX_new_from_pkey(NULL, pkeyCopyByRef, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_pkey failed")
        goto cleanup;
    }

    if (EVP_PKEY_decrypt_init(ctxCopyByRef) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    // Decrypt
    if (EVP_PKEY_decrypt(ctx, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt failed")
        goto cleanup;
    }
    expectedEvents[0].decryptCount = 1;

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second and third decrypt. Only the first event should be logged.
    if (EVP_PKEY_decrypt(ctxCopy, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0 ||
        EVP_PKEY_decrypt(ctxCopyByRef, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[1].decryptCount = 2;

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    ctx = NULL;
    ctxCopy = NULL;
    ctxCopyByRef = NULL;
    pkey = NULL;
    pkeyCopy = NULL;
    pkeyCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if (!EVP_PKEY_fromdata(importCtx, &pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_new_raw_private_key_ex failed")
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, propq.c_str())) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_pkey failed")
        goto cleanup;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(ctx, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt failed")
        goto cleanup;
    }
    expectedEvents[2].decryptCount = 1;

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
#ifndef KEYSINUSE_LOG_SYSLOG
    remove(KEYSINUSE_LOG_FILE);
#endif

cleanup:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(importCtx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    OPENSSL_free(pbCipherText);

    return ret;
}
#endif

SCOSSL_STATUS keysinuse_test_engine_sign(EVP_PKEY *pkeyBase, char pbKeyId[SCOSSL_KEYID_SIZE], ENGINE *engine)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctxCopy = NULL;
    EVP_PKEY_CTX *ctxCopyByRef = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyCopy = NULL;
    EVP_PKEY *pkeyCopyByRef = NULL;
    BYTE pbPlainText[SHA256_DIGEST_LENGTH];
    SIZE_T cbPlainText = SHA256_DIGEST_LENGTH;
    PBYTE pbCipherText = NULL;
    SIZE_T cbCipherText = 0;
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, KEYSINUSE_TEST_LOG_DELAY},
        {0, 0, 0}};

    // Same key material for distinct pkey objects should log with the same keysinuse info
    if ((pkey = EVP_PKEY_dup(pkeyBase)) == NULL ||
        (pkeyCopy = EVP_PKEY_dup(pkeyBase)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if (RAND_bytes(pbPlainText, cbPlainText) != 1)
    {
        TEST_LOG_ERROR("RAND_bytes failed")
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new(pkey, engine)) == NULL ||
        (ctxCopy = EVP_PKEY_CTX_new(pkeyCopy, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    // Sign init
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_sign_init(ctxCopy) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_DigestSignInit
    // should trigger keysinuse_load_key_by_ctx
    if ((pkeyCopyByRef = EVP_PKEY_dup(pkey)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctxCopyByRef = EVP_PKEY_CTX_new(pkeyCopyByRef, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    if (EVP_PKEY_sign_init(ctxCopyByRef) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    // Sign
    if (!EVP_PKEY_sign(ctx, NULL, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }

    if ((pbCipherText = (PBYTE)OPENSSL_malloc(cbCipherText)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OPENSSL_malloc failed")
        goto cleanup;
    }

    if (!EVP_PKEY_sign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }
    expectedEvents[0].signCount = 1;

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second and third sign. Only the first event should be logged.
    if (!EVP_PKEY_sign(ctxCopy, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) ||
        !EVP_PKEY_sign(ctxCopyByRef, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign failed")
        goto cleanup;
    }
    expectedEvents[1].signCount = 2;

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    ctx = NULL;
    ctxCopy = NULL;
    ctxCopyByRef = NULL;
    pkey = NULL;
    pkeyCopy = NULL;
    pkeyCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if ((pkey = EVP_PKEY_dup(pkeyBase)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new(pkey, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    // Test key use again, this event should be immediately logged
    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_sign_init failed")
        goto cleanup;
    }

    if (!EVP_PKEY_sign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[2].signCount = 1;

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
#ifndef KEYSINUSE_LOG_SYSLOG
    remove(KEYSINUSE_LOG_FILE);
#endif

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    OPENSSL_free(pbCipherText);

    return ret;
}

SCOSSL_STATUS keysinuse_test_engine_decrypt(EVP_PKEY *pkeyBase, char pbKeyId[SCOSSL_KEYID_SIZE], ENGINE *engine)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ctxCopy = NULL;
    EVP_PKEY_CTX *ctxCopyByRef = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyCopy = NULL;
    EVP_PKEY *pkeyCopyByRef = NULL;
    BYTE pbPlainText[KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE];
    SIZE_T cbPlainText = KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE;
    PBYTE pbCipherText = NULL;
    SIZE_T cbCipherText = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, KEYSINUSE_TEST_LOG_DELAY},
        {0, 0, 0}};

    if (RAND_bytes(pbPlainText, cbPlainText) != 1)
    {
        TEST_LOG_ERROR("RAND_bytes failed")
        goto cleanup;
    }

    // Same key material for distinct pkey objects should log with the same keysinuse info
    if ((pkey = EVP_PKEY_dup(pkeyBase)) == NULL ||
        (pkeyCopy = EVP_PKEY_dup(pkeyBase)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    // Generate test ciphertext
    if ((ctx = EVP_PKEY_CTX_new(pkeyBase, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt_init failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt failed")
        goto cleanup;
    }

    if ((pbCipherText = (PBYTE)OPENSSL_malloc(cbCipherText)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OPENSSL_malloc failed")
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_encrypt failed")
        goto cleanup;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if ((ctx = EVP_PKEY_CTX_new(pkey, engine)) == NULL ||
        (ctxCopy = EVP_PKEY_CTX_new(pkeyCopy, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    // Decrypt init
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_decrypt_init(ctxCopy) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_PKEY_decrypt_init
    // should trigger keysinuse_load_key_by_ctx
    if ((pkeyCopyByRef = EVP_PKEY_dup(pkey)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctxCopyByRef = EVP_PKEY_CTX_new(pkeyCopyByRef, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    if (EVP_PKEY_decrypt_init(ctxCopyByRef) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    // Decrypt
    cbPlainText = KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE;
    if (EVP_PKEY_decrypt(ctx, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt failed")
        goto cleanup;
    }
    expectedEvents[0].decryptCount = 1;

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second and third decrypt. Only the first event should be logged.
    cbPlainText = KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE;
    if (EVP_PKEY_decrypt(ctxCopy, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0 ||
        EVP_PKEY_decrypt(ctxCopyByRef, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[1].decryptCount = 2;

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    ctx = NULL;
    ctxCopy = NULL;
    ctxCopyByRef = NULL;
    pkey = NULL;
    pkeyCopy = NULL;
    pkeyCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if ((pkey = EVP_PKEY_dup(pkeyBase)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new(pkey, engine)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new failed")
        goto cleanup;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    cbPlainText = KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE;
    if (EVP_PKEY_decrypt(ctx, pbPlainText, &cbPlainText, pbCipherText, cbCipherText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt failed")
        goto cleanup;
    }
    expectedEvents[2].decryptCount = 1;

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
#ifndef KEYSINUSE_LOG_SYSLOG
    remove(KEYSINUSE_LOG_FILE);
#endif

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ctxCopy);
    EVP_PKEY_CTX_free(ctxCopyByRef);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyCopy);
    EVP_PKEY_free(pkeyCopyByRef);
    OPENSSL_free(pbCipherText);

    return ret;
}

// Generates a key with the specified parameters. *ppbKey is set to the encoded
// public key bytes, and pbKeyId is set to the expected keyId. The size of the
// encoded public key bytes is returned, and 0 is returned on error. The default
// provider will be explicitly used for this step to ensure any regressions in
// the tested provider(s) key encoding logic are caught by the tests.
SCOSSL_STATUS keysinuse_test_generate_keys()
{
    unsigned char pbKeyHash[SYMCRYPT_SHA256_RESULT_SIZE];
    int cbPublicKey = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    EVP_PKEY_CTX *ctx = NULL;

    for (int i = 0; i < sizeof(testKeys) / sizeof(testKeys[0]); i++)
    {
        if ((ctx = EVP_PKEY_CTX_new_id(testKeys[i].keyType, NULL)) == NULL)
        {
            TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_id failed")
            goto cleanup;
        }
        
        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen_init failed")
            goto cleanup;
        }

        if (testKeys[i].keyType == EVP_PKEY_RSA)
        {
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, testKeys[i].keygenParams) <= 0)
            {
                TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_set_rsa_keygen_bits failed")
                goto cleanup;
            }
        }
        else if (testKeys[i].keyType == EVP_PKEY_EC)
        {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, testKeys[i].keygenParams) <= 0)
            {
                TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed")
                goto cleanup;
            }
        }
        
        if (EVP_PKEY_keygen(ctx, &testKeys[i].pkey) <= 0)
        {
            TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen failed")
            goto cleanup;
        }
        
        // Encode the public key
        cbPublicKey = i2d_PublicKey(testKeys[i].pkey, &testKeys[i].pbEncodedKey);
        if (cbPublicKey <= 0)
        {
            TEST_LOG_OPENSSL_ERROR("i2d_PublicKey failed")
            goto cleanup;
        }
        testKeys[i].cbEncodedKey = cbPublicKey;

        if (EVP_Digest(testKeys[i].pbEncodedKey, testKeys[i].cbEncodedKey, pbKeyHash, NULL, EVP_sha256(), NULL) <= 0)
        {
            TEST_LOG_OPENSSL_ERROR("EVP_Digest failed")
            goto cleanup;
        }

        for (int j = 0; j < SYMCRYPT_SHA256_RESULT_SIZE / 2; j++)
        {
            sprintf(&testKeys[i].pbKeyId[j*2], "%02x", pbKeyHash[j]);
        }
        testKeys[i].pbKeyId[SYMCRYPT_SHA256_RESULT_SIZE] = '\0';
    
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

SCOSSL_STATUS keysinuse_test_run_tests(KEYSINUSE_TEST_KEY testKey, keysinuse_operation operation,
                                       vector<ENGINE *> engines, vector<PVOID> providers)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (logVerbose)
    {
        for(SIZE_T i = 0; i < testKey.cbEncodedKey; i++)
        {
            if (i % 15 == 0)
            {
                printf("\t");
            }

            printf("%02x%s", testKey.pbEncodedKey[i], (i < testKey.cbEncodedKey - 1) ? ":" : "\n");

            if (i % 15 == 14 && i < testKey.cbEncodedKey - 1)
            {
                printf("\n");
            }
        }
    }
    TEST_LOG_VERBOSE("\n\tKeyId: %s\n\n", testKey.pbKeyId)

    printf("\tTesting KeysInUse API functions\n");
    if (keysinuse_test_api_functions(testKey.pbEncodedKey, testKey.cbEncodedKey, testKey.pbKeyId, operation) == SCOSSL_FAILURE)
    {
        return SCOSSL_FAILURE;
    }

    // Wait for logging delay to ensure the logging thread has cleaned up
    // the keysinuse info created in keysinuse_test_api_functions
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    for (ENGINE *engine : engines)
    {
        printf("\tTesting engine (%s) functions\n", ENGINE_get_id(engine));
        if (operation == KEYSINUSE_SIGN)
        {
            if (keysinuse_test_engine_sign(testKey.pkey, testKey.pbKeyId, engine) == SCOSSL_FAILURE)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            if (keysinuse_test_engine_decrypt(testKey.pkey, testKey.pbKeyId, engine) == SCOSSL_FAILURE)
            {
                return SCOSSL_FAILURE;
            }
        }
    }

    sleep(KEYSINUSE_TEST_LOG_DELAY);

#if OPENSSL_VERSION_MAJOR >= 3
    for (PVOID provider : providers)
    {
        const char *providerName = OSSL_PROVIDER_get0_name((OSSL_PROVIDER *)provider);
        printf("\tTesting provider (%s) functions\n", providerName);
        if (operation == KEYSINUSE_SIGN)
        {
            if (keysinuse_test_provider_sign(testKey.pkey, testKey.pbKeyId, string(providerName)) == SCOSSL_FAILURE)
            {
                return SCOSSL_FAILURE;
            }
        }
        else
        {
            if (keysinuse_test_provider_decrypt(testKey.pkey, testKey.pbKeyId, string(providerName)) == SCOSSL_FAILURE)
            {
                return SCOSSL_FAILURE;
            }
        }
    }
#endif

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS keysinuse_test_create_fakeroot()
{
#ifdef KEYSINUSE_LOG_SYSLOG
    // No need to create a fake root for syslog logging
    return SCOSSL_SUCCESS;
#else
    mode_t umaskOriginal;
    char keysinuseLogDir[sizeof(KEYSINUSE_LOG_DIR)];
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Create fake root directory for testing. This ensures the log files
    // aren't written by keysinuse running on the system.
    umaskOriginal = umask(0);

    if (mkdir(KEYSINUSE_TEST_ROOT, 0777) == 0 ||
        errno == EEXIST)
    {
        if (chroot(KEYSINUSE_TEST_ROOT) == -1)
        {
            TEST_LOG_ERROR("Failed to chroot to testing root: %d", errno)
            rmdir(KEYSINUSE_TEST_ROOT);
            goto cleanup;
        }
    }
    else
    {
        TEST_LOG_ERROR("Failed to create testing root: %d", errno)
        goto cleanup;
    }

    // Create the keysinuse logging parent directories
    for (int i = 0; i < sizeof(KEYSINUSE_LOG_DIR); i++)
    {
        keysinuseLogDir[i] = KEYSINUSE_LOG_DIR[i];
        if (i > 0 && keysinuseLogDir[i] == '/')
        {
            keysinuseLogDir[i] = '\0';

            if (mkdir(keysinuseLogDir, 0755) == -1 &&
                errno != EACCES &&
                errno != EEXIST)
            {
                TEST_LOG_ERROR("Failed to create parent of logging directory %s: %d", keysinuseLogDir, errno)
                goto cleanup;
            }
            keysinuseLogDir[i] = '/';
        }
    }

    // Create the keysinuse logging directory with expected permissions
    if (mkdir(KEYSINUSE_LOG_DIR, 01733) == 0)
    {
        if (chown(KEYSINUSE_LOG_DIR, 0, 0) == -1)
        {
            TEST_LOG_ERROR("Failed to set ownership of logging directory: %d", errno)
            rmdir(KEYSINUSE_LOG_DIR);
            goto cleanup;
        }
    }
    else if (errno != EACCES && errno != EEXIST)
    {
        TEST_LOG_ERROR("Failed to create logging directory: %d", errno)
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    umask(umaskOriginal);

    return ret;
#endif
}

int main(int argc, char** argv)
{
    ENGINE *engine = NULL;
    vector<ENGINE *> engines;
    vector<PVOID> providers;

    char pbKeyId[SCOSSL_KEYID_SIZE];
    int ret = 0;

    keysinuse_test_cleanup();

    OPENSSL_init_crypto(0, NULL);

    if (keysinuse_test_generate_keys() != SCOSSL_SUCCESS)
    {
        TEST_LOG_ERROR("Failed to generate keys")
        goto cleanup;
    }

    // Loading engines and providers may push errors to the error stack
    // that are not test failures and may lead to misleading error messages.
    ERR_set_mark();

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            printf("Usage: KeysInUseTest <options>\n");
            printf("Options:\n");
            printf("  --engine-path <engine_path>       Specify the path of an engine to test.\n");
            printf("  --engine <engine_name>            Specify an engine to use for key operations\n");
#if OPENSSL_VERSION_MAJOR >= 3
            printf("  --provider-dir <provider_path>    Specify a directory to locate providers with with keysinuse. Must come before provider\n");
            printf("  --provider <provider_name>        Specify a provider with keysinuse to test by name\n");
#endif
            printf("  --verbose                         Enable verbose output\n");
            return 0;
        }
        else if (strcmp(argv[i], "--verbose") == 0)
        {
            logVerbose = true;
        }
        else if (strcmp(argv[i], "--engine-path") == 0)
        {
            if (argc < ++i)
            {
                TEST_LOG_ERROR("Missing engine path")
                goto cleanup;
            }
            if ((engine = ENGINE_by_id("dynamic")) == NULL ||
                !ENGINE_ctrl_cmd_string(engine, "SO_PATH", argv[i], 0) ||
                !ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "2", 0) ||
                !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0))
            {
                TEST_LOG_OPENSSL_ERROR("Failed to load engine by path %s", argv[i]);
                goto cleanup;
            }
        }
        else if (strcmp(argv[i], "--engine") == 0)
        {
            if (argc < ++i)
            {
                TEST_LOG_ERROR("Missing engine name")
                goto cleanup;
            }

            if ((engine = ENGINE_by_id(argv[i])) == NULL)
            {
                TEST_LOG_OPENSSL_ERROR("ENGINE_by_id failed")
                goto cleanup;
            }

            if (!ENGINE_init(engine))
            {
                ENGINE_free(engine);
                TEST_LOG_OPENSSL_ERROR("ENGINE_init failed")
                goto cleanup;
            }

            engines.push_back(engine);
            engine = NULL;
        }
#if OPENSSL_VERSION_MAJOR >= 3
        else if (strcmp(argv[i], "--provider") == 0)
        {
            if (argc < ++i)
            {
                TEST_LOG_ERROR("Missing provider name")
                goto cleanup;
            }

            OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, argv[i]);
            if (provider == NULL)
            {
                TEST_LOG_OPENSSL_ERROR("Provider %s not available", argv[i])
                goto cleanup;
            }

            providers.push_back(provider);
        }
        else if (strcmp(argv[i], "--provider-dir") == 0)
        {
            if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[++i]))
            {
                {
                    TEST_LOG_OPENSSL_ERROR("Failed to set provider directory %s", argv[i])
                    goto cleanup;
                }
            }
        }
#endif
        else
        {
            TEST_LOG_ERROR("Unknown argument: %s", argv[i])
            goto cleanup;
        }
    }

    ERR_pop_to_mark();

    keysinuse_set_logging_delay(KEYSINUSE_TEST_LOG_DELAY);
    keysinuse_init();

    processName = realpath(argv[0], NULL);
    processStartTime = time(NULL);

    if (keysinuse_test_create_fakeroot() == SCOSSL_FAILURE)
    {
        TEST_LOG_ERROR("Failed to create fake root")
        goto cleanup;
    }

    if (!keysinuse_is_running())
    {
        TEST_LOG_ERROR("KeysInUse is not enabled")
        goto cleanup;
    }

    for (KEYSINUSE_TEST_KEY testKey : testKeys)
    {
        if (testKey.keyType == EVP_PKEY_RSA)
        {
            printf("Testing RSA sign with size %d\n", testKey.keygenParams);
        }
        else if (testKey.keyType == EVP_PKEY_EC)
        {
            printf("Testing ECDSA sign with curve %s\n", OBJ_nid2sn(testKey.keygenParams));
        }
        else if (testKey.keyType == EVP_PKEY_X25519)
        {
            printf("Testing X25519 sign\n");
        }

        if (keysinuse_test_run_tests(testKey, KEYSINUSE_SIGN, engines, providers) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        if (testKey.keyType == EVP_PKEY_RSA)
        {
            printf("\nTesting RSA decrypt with size %d\n", testKey.keygenParams);
            if (keysinuse_test_run_tests(testKey, KEYSINUSE_DECRYPT, engines, providers) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }
        }

        printf("\n");
    }

    printf("All tests passed\n");
    ret = 1;

cleanup:
#if OPENSSL_VERSION_MAJOR >= 3
    for (PVOID provider : providers)
    {
        OSSL_PROVIDER_unload((OSSL_PROVIDER *)provider);
    }
#endif

    for (ENGINE *e : engines)
    {
        ENGINE_finish(e);
        ENGINE_free(e);
    }

    OPENSSL_free(processName);
    keysinuse_test_cleanup();
    OPENSSL_cleanup();

    return ret;
}