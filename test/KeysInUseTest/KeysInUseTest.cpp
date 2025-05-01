//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <fstream>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>

#include "scossl_helpers.h"
#include "p_scossl_keysinuse.h"

#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

#define KEYSINUSE_TEST_LOG_DELAY 2 // seconds
// Time to wait for the log thread to finish writing
#define KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME 200 * 1000 // 200 milliseconds
#define KEYSINUSE_TEST_ROOT "keysinuse_test_root"
#define KEYSINUSE_LOG_DIR "/var/log/keysinuse"
#define KEYSINUSE_LOG_FILE KEYSINUSE_LOG_DIR "/keysinuse_not_00000000.log"
#define KEYSINUSE_TEST_SIGN_PLAINTEXT_SIZE 256
#define KEYSINUSE_TEST_DECRYPT_PLAINTEXT_SIZE 64
#define SCOSSL_KEYID_SIZE (SYMCRYPT_SHA256_RESULT_SIZE + 1)

static bool logVerbose = false;

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
typedef struct
{
    bool isPath;
    const char *providerName;
} KEYSINUSE_TEST_PROVIDER;

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

static const UINT32 rsaTestSizes[] = {
    2048,
    3072,
    4096};

static const char *eccTestGroups[] = {
    SN_X9_62_prime192v1,
    SN_secp224r1,
    SN_X9_62_prime256v1,
    SN_secp384r1,
    SN_secp521r1,
    SN_X25519};

static char *processName;
static time_t processStartTime;

static void keysinsue_test_cleanup()
{
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
    struct stat sb;
    ifstream logFile(KEYSINUSE_LOG_FILE);
    string curLine;
    char *pbExpectedHeader = nullptr;
    char *pbHeader;
    char *pbBody;
    char *pbCurToken;
    time_t loggedStartTime;
    time_t firstLogTime;
    time_t lastLogTime;

    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (!logFile.is_open() ||
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

    // Read and validate the first line's header. The rest of the lines
    // should match exactly.
    if (!getline(logFile, curLine))
    {
        TEST_LOG_ERROR("Failed to read line 0 of log file")
        goto cleanup;
    }

    TEST_LOG_VERBOSE("\t\t1: %s\n", curLine.c_str());

    pbHeader = strtok((char *)curLine.c_str(), "!");
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
            if (!getline(logFile, curLine))
            {
                TEST_LOG_ERROR("Expected to read line %d of log file but reached end of log.", i + 1)
                goto cleanup;
            }

            TEST_LOG_VERBOSE("\t\t%d: %s\n", i + 1, curLine.c_str())

            pbHeader = strtok((char *)curLine.c_str(), "!");
            pbBody = strtok(nullptr, "");

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
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
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

    if (getline(logFile, curLine))
    {
        TEST_LOG_ERROR("Log file has more lines than expected.")
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:

    free(pbExpectedHeader);

    return ret;
}

SCOSSL_STATUS keysinuse_test_api_functions(PCBYTE pcbPublicKey, SIZE_T cbPublicKey, char pbKeyId[SCOSSL_KEYID_SIZE], BOOL testSign)
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
    if ((keysinuseCtx = p_scossl_keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load keysinuse context")
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by bytes again
    if ((keysinuseCtxCopy = p_scossl_keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes")
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by reference
    if ((keysinuseCtxCopyByRef = p_scossl_keysinuse_load_key_by_ctx(keysinuseCtx)) == NULL)
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
    p_scossl_keysinuse_unload_key(keysinuseCtxCopy);
    keysinuseCtxCopy = NULL;

    // Test three consecutive uses. The first event should be logged.
    // The second event should only be logged after the elapsed wait time.
    if (testSign)
    {
        // Test sign
        p_scossl_keysinuse_on_sign(keysinuseCtx);
        expectedEvents[0].signCount = 1;

        // Wait a little to allow the logging thread to process the event
        usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

        // Test second sign. Only the first event should be logged.
        p_scossl_keysinuse_on_sign(keysinuseCtx);
        p_scossl_keysinuse_on_sign(keysinuseCtxCopyByRef);
        expectedEvents[1].signCount = 2;
    }
    else
    {
        // Test decrypt
        p_scossl_keysinuse_on_decrypt(keysinuseCtx);
        expectedEvents[0].decryptCount = 1;

        // Wait a little to allow the logging thread to process the event
        usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

        // Test second decrypt. Only the first event should be logged.
        p_scossl_keysinuse_on_decrypt(keysinuseCtx);
        p_scossl_keysinuse_on_decrypt(keysinuseCtxCopyByRef);
        expectedEvents[1].decryptCount = 2;
    }

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    p_scossl_keysinuse_unload_key(keysinuseCtx);
    keysinuseCtx = NULL;

    p_scossl_keysinuse_unload_key(keysinuseCtxCopyByRef);
    keysinuseCtxCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    // Reload they key by bytes after original references were unloaded.
    if ((keysinuseCtxCopy = p_scossl_keysinuse_load_key(pcbPublicKey, cbPublicKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes")
        return SCOSSL_FAILURE;
    }

    // Test key use again, this event should be immediately logged
    if (testSign)
    {
        p_scossl_keysinuse_on_sign(keysinuseCtxCopy);
        expectedEvents[2].signCount = 1;
    }
    else
    {
        p_scossl_keysinuse_on_decrypt(keysinuseCtxCopy);
        expectedEvents[2].decryptCount = 1;
    }

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
    remove(KEYSINUSE_LOG_FILE);

cleanup:
    p_scossl_keysinuse_unload_key(keysinuseCtx);
    p_scossl_keysinuse_unload_key(keysinuseCtxCopy);
    p_scossl_keysinuse_unload_key(keysinuseCtxCopyByRef);

    return ret;
}

SCOSSL_STATUS keysinuse_test_provider_sign(EVP_PKEY *pkeyBase, char pbKeyId[SCOSSL_KEYID_SIZE], string providerName)
{
    string propq;
    const char *keyType = EVP_PKEY_get0_type_name(pkeyBase);
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyCopy = NULL;
    EVP_PKEY *pkeyCopyByRef = NULL;
    EVP_PKEY_CTX *importCtx = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD_CTX *ctxCopy = NULL;
    EVP_MD_CTX *ctxCopyByRef = NULL;
    BYTE pbPlainText[KEYSINUSE_TEST_SIGN_PLAINTEXT_SIZE];
    SIZE_T cbPlainText = KEYSINUSE_TEST_SIGN_PLAINTEXT_SIZE;
    PBYTE pbCipherText = NULL;
    SIZE_T cbCipherText = 0;
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;

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

    if ((ctx = EVP_MD_CTX_new()) == NULL ||
        (ctxCopy = EVP_MD_CTX_new()) == NULL ||
        (ctxCopyByRef = EVP_MD_CTX_new()) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_MD_CTX_new failed")
        goto cleanup;
    }

    // Sign init
    if (EVP_DigestSignInit_ex(ctx, NULL,
        SN_sha256,
        NULL,
        propq.c_str(),
        pkey,
        NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSignInit_ex failed")
        goto cleanup;
    }

    if (EVP_DigestSignInit_ex(ctxCopy, NULL,
        SN_sha256,
        NULL,
        propq.c_str(),
        pkeyCopy,
        NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSignInit_ex failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_DigestSignInit_ex
    // should trigger p_scossl_keysinuse_load_key_by_ctx
    if ((pkeyCopyByRef = EVP_PKEY_dup(pkey)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_dup failed")
        goto cleanup;
    }

    if (EVP_DigestSignInit_ex(ctxCopyByRef, NULL,
        SN_sha256,
        NULL,
        propq.c_str(),
        pkeyCopyByRef,
        NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSignInit_ex failed")
        goto cleanup;
    }

    // Sign
    if (EVP_DigestSign(ctx, NULL, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }

    if ((pbCipherText = (PBYTE)OPENSSL_malloc(cbCipherText)) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OPENSSL_malloc failed")
        goto cleanup;
    }

    if (EVP_DigestSign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[0].signCount = 1;

    // Wait a little to allow the logging thread to process the event
    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    // Test second and third sign. Only the first event should be logged.
    if (EVP_DigestSign(ctxCopy, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0 ||
        EVP_DigestSign(ctxCopyByRef, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[1].signCount = 2;

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctxCopy);
    EVP_MD_CTX_free(ctxCopyByRef);
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

    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_MD_CTX_new failed")
        goto cleanup;
    }

    // Test key use again, this event should be immediately logged
    if (EVP_DigestSignInit_ex(ctx, NULL,
        SN_sha256,
        NULL,
        propq.c_str(),
        pkey,
        NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSignInit_ex failed")
        goto cleanup;
    }

    if (EVP_DigestSign(ctx, pbCipherText, &cbCipherText, pbPlainText, cbPlainText) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_DigestSign failed")
        goto cleanup;
    }
    expectedEvents[2].signCount = 1;

    usleep(KEYSINUSE_TEST_LOG_THREAD_WAIT_TIME);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
    remove(KEYSINUSE_LOG_FILE);

cleanup:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(importCtx);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctxCopy);
    EVP_MD_CTX_free(ctxCopyByRef);
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
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;

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

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    // Decrypt init
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_decrypt_init(ctxCopy) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_decrypt_init failed")
        goto cleanup;
    }

    // Duplicating the pkey object after EVP_PKEY_decrypt_init
    // should trigger p_scossl_keysinuse_load_key_by_ctx
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
    remove(KEYSINUSE_LOG_FILE);

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

// Generates a key with the specified parameters. *ppbKey is set to the encoded
// public key bytes, and pbKeyId is set to the expected keyId. The size of the
// encoded public key bytes is returned, and 0 is returned on error. The default
// provider will be explicitly used for this step to ensure any regressions in
// the tested provider(s) key encoding logic are caught by the tests.
SIZE_T keysinuse_test_generate_key(_In_ const char *algName, _In_ const OSSL_PARAM params[],
                                   _Out_ EVP_PKEY **ppkey,
                                   _Out_ PBYTE *ppbKey, _Out_ char pbKeyId[SCOSSL_KEYID_SIZE])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;
    OSSL_ENCODER_CTX *encoderCtx = NULL;
    BYTE pbKeyIdBytes[SYMCRYPT_SHA256_RESULT_SIZE];
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;

    // Generate key with parameters
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, "provider=default")) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_name failed")
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen_init failed")
        goto cleanup;
    }

    if (!EVP_PKEY_CTX_set_params(ctx, params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_set_params failed")
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen failed")
        goto cleanup;
    }

    if ((cbKey = i2d_PublicKey(pkey, &pbKey)) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("i2d_PublicKey failed")
        goto cleanup;
    }

    if ((md = EVP_MD_fetch(NULL, "SHA256", "provider=default")) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_MD_fetch failed")
        goto cleanup;
    }

    if (EVP_Digest(pbKey, cbKey, pbKeyIdBytes, NULL, md, NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_Digest failed")
        goto cleanup;
    }

    for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE / 2; i++)
    {
        sprintf(&pbKeyId[i*2], "%02x", pbKeyIdBytes[i]);
    }
    pbKeyId[SYMCRYPT_SHA256_RESULT_SIZE] = '\0';

    *ppkey = pkey;
    *ppbKey = pbKey;
    pbKey = NULL;
    pkey = NULL;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OSSL_ENCODER_CTX_free(encoderCtx);
    EVP_MD_free(md);
    OPENSSL_free(pbKey);

    return pbKey == NULL ? cbKey : 0;
}

SCOSSL_STATUS keysinuse_run_tests(const OSSL_PARAM *params, const char *algName, BOOL testSign,
                                  vector<KEYSINUSE_TEST_PROVIDER> providers)
{
    EVP_PKEY *pkey = NULL;
    PBYTE pbEncodedKey = NULL;
    SIZE_T cbEncodedKey = 0;
    char pbKeyId[SCOSSL_KEYID_SIZE];
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Generate key
    if ((cbEncodedKey = keysinuse_test_generate_key("RSA", params, &pkey, &pbEncodedKey, pbKeyId)) == 0)
    {
        goto cleanup;
    }

    if (logVerbose)
    {
        for(SIZE_T i = 0; i < cbEncodedKey; i++)
        {
            if (i % 15 == 0)
            {
                printf("\t");
            }

            printf("%02x%s", pbEncodedKey[i], (i < cbEncodedKey - 1) ? ":" : "\n");

            if (i % 15 == 14 && i < cbEncodedKey - 1)
            {
                printf("\n");
            }
        }
    }
    TEST_LOG_VERBOSE("\n\tKeyId: %s\n\n", pbKeyId)

    printf("\tTesting KeysInUse API functions\n");
    keysinuse_test_api_functions(pbEncodedKey, cbEncodedKey, pbKeyId, testSign);

    // Wait for logging delay to ensure the logging thread has cleaned up
    // the keysinuse info created in keysinuse_test_api_functions
    sleep(KEYSINUSE_TEST_LOG_DELAY);

    for (KEYSINUSE_TEST_PROVIDER provider : providers)
    {
        printf("\tTesting provider (%s) functions\n", provider.providerName);
        if (testSign)
        {
            keysinuse_test_provider_sign(pkey, pbKeyId, string(provider.providerName));
        }
        else
        {
            keysinuse_test_provider_decrypt(pkey, pbKeyId, string(provider.providerName));
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbEncodedKey);
    EVP_PKEY_free(pkey);

    return ret;
}

int main(int argc, char** argv)
{
    vector<KEYSINUSE_TEST_PROVIDER> providers;
    mode_t umaskOriginal;
    EVP_PKEY *pkey = NULL;
    PBYTE pbEncodedKey = NULL;
    SIZE_T cbEncodedKey = 0;
    char keysinuseLogDir[sizeof(KEYSINUSE_LOG_DIR)];
    char pbKeyId[SCOSSL_KEYID_SIZE];
    OSSL_PARAM params[2] = { OSSL_PARAM_END };
    int ret = 0;
    void * p = malloc(5);
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--provider") == 0)
        {
            if (argc < ++i)
            {
                TEST_LOG_ERROR("Missing provider name")
                goto cleanup;
            }

            // OSSL_PROVIDER_load(NULL, argv[i + 1]);
            if (!OSSL_PROVIDER_available(NULL, argv[i]))
            {
                TEST_LOG_ERROR("Provider %s not available", argv[i])
                goto cleanup;
            }

            providers.push_back({false, argv[i]});
        }
        else if (strcmp(argv[i], "--provider-path") == 0)
        {
            OSSL_PROVIDER_set_default_search_path(NULL, argv[++i]);
        }
        else if (strcmp(argv[i], "--verbose") == 0)
        {
            logVerbose = true;
        }
        else if (strcmp(argv[i], "--help") == 0)
        {
            printf("Usage: KeysInUseTest <options>\n");
            printf("Multiple providers can be specified for testing.\n");
            printf("Options:\n");
            printf("  --provider-path <provider_path>  Specify a directory to locate providers with with keysinuse. Must come before provider\n");
            printf("  --provider <provider_name>       Specify a provider with keysinuse to test by name\n");
            return 0;
        }
        else
        {
            TEST_LOG_ERROR("Unknown argument: %s", argv[i])
            goto cleanup;
        }
    }

    p_scossl_keysinuse_set_logging_delay(KEYSINUSE_TEST_LOG_DELAY);
    p_scossl_keysinuse_init();

    processName = realpath(argv[0], NULL);
    processStartTime = time(NULL);

    // Create fake root directory for testing. This ensures the log files
    // aren't written by keysinuse running on the system.
    umaskOriginal = umask(0);

    keysinsue_test_cleanup();
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

    umask(umaskOriginal);

    if (!p_scossl_keysinuse_is_enabled())
    {
        TEST_LOG_ERROR("KeysInUse is not enabled")
        goto cleanup;
    }

    // Test RSA sign
    for (int i = 0; i < sizeof(rsaTestSizes) / sizeof(rsaTestSizes[0]); i++)
    {
        printf("Testing RSA sign with size %d\n", rsaTestSizes[i]);

        params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, (int *)&rsaTestSizes[i]);
        if (keysinuse_run_tests(params, "RSA", TRUE, providers) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }

        printf("Testing RSA decrypt with size %d\n", rsaTestSizes[i]);
        if (keysinuse_run_tests(params, "RSA", FALSE, providers) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    // Test ECDSA/X25519 sign
    for (int i = 0; i < sizeof(eccTestGroups) / sizeof(eccTestGroups[0]); i++)
    {
        printf("Testing ECDSA sign with group %s\n", eccTestGroups[i]);

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)eccTestGroups[i], sizeof(eccTestGroups[i]));
        if (keysinuse_run_tests(params, "EC", TRUE, providers) != SCOSSL_SUCCESS)
        {
            goto cleanup;
        }
    }

    ret = 1;

cleanup:
    OPENSSL_free(processName);
    OPENSSL_free(pbEncodedKey);
    EVP_PKEY_free(pkey);
    p_scossl_keysinuse_teardown();
    keysinsue_test_cleanup();

    return ret;
}