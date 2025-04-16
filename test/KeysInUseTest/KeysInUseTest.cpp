//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <fstream>

#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>

#include "scossl_helpers.h"
#include "p_scossl_keysinuse.h"

#include <openssl/core_names.h>
#include <openssl/encoder.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KEYSINUSE_TEST_ROOT "keysinuse_test_root"
#define KEYSINUSE_LOG_DIR "/var/log/keysinuse"
#define KEYSINUSE_LOG_FILE KEYSINUSE_LOG_DIR "/keysinuse_not_00000000.log"
#define SCOSSL_KEYID_SIZE (SYMCRYPT_SHA256_RESULT_SIZE + 1)

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
    const char *provider;
} KEYSINUSE_TEST_PROVIDER;

static void _test_print_key(PCBYTE pbBytes, SIZE_T cbBytes)
{
    for(SIZE_T i = 0; i < cbBytes; i++)
    {
        if (i % 15 == 0)
        {
            printf("\n\t");
        }

        printf("%02x%s", pbBytes[i], (i < cbBytes - 1) ? ":" : "\n");
    }
}

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
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\033[0m\n");
}

#define TEST_LOG_ERROR(...) _test_log_err(__FILE__, __LINE__, __VA_ARGS__)
#define TEST_LOG_OPENSSL_ERROR(...) _test_log_openssl_err(__FILE__, __LINE__, __VA_ARGS__)
#define TEST_PRINT_BYTES(pbBytes, cbBytes) _test_print_key(pbBytes, cbBytes)

static const UINT32 rsaTestSizes[] = {
    2048,
    3072,
    4096};

static const char *eccTestGroups[] = {
    SN_X9_62_prime192v1,
    SN_secp224r1,
    SN_X9_62_prime256v1,
    SN_secp384r1,
    SN_secp521r1};

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
            TEST_LOG_ERROR("Failed to cleanup testing root: %d", errno);
        }
    }
    else if (nftwCleanupRes != 0)
    {
        TEST_LOG_ERROR("Failed to cleanup testing root: %d", nftwCleanupRes);
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
        TEST_LOG_ERROR("Failed to open log file: %d", errno);
        goto cleanup;
    }

    if ((sb.st_mode & 0777) != 0200)
    {
        TEST_LOG_ERROR("Log file permissions are not 0200: %o", (sb.st_mode & 0777));
        goto cleanup;
    }

    // Read and validate the first line's header. The rest of the lines
    // should match exactly.
    if (!getline(logFile, curLine))
    {
        TEST_LOG_ERROR("Failed to read line 0 of log file");
        goto cleanup;
    }

    printf("\t\t1: %s\n", curLine.c_str());

    pbHeader = strtok((char *)curLine.c_str(), "!");
    pbBody = strtok(nullptr, "");
    if (pbHeader == NULL || pbBody == NULL)
    {
        TEST_LOG_ERROR("Failed to parse log file header");
        goto cleanup;
    }

    pbExpectedHeader = strdup(pbHeader);

    // Check the logged start time >= processStartTime
    if ((pbCurToken = strtok(pbHeader, ",")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse process start time");
        goto cleanup;
    }

    if ((loggedStartTime = atol(pbCurToken)) < processStartTime)
    {
        TEST_LOG_ERROR("Logged process start time is before the test started. Expected >= %ld, Logged: %ld", processStartTime, loggedStartTime);
        goto cleanup;
    }

    // Check the logged process name name matches the current process name
    if ((pbCurToken = strtok(nullptr, ",")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse process name");
        goto cleanup;
    }

    if (strcmp(pbCurToken, processName) != 0)
    {
        TEST_LOG_ERROR("Logged process name does not match.\n\tExpected %s\n\tLogged: %s", processName, pbCurToken);
        goto cleanup;
    }

    // Check the logging level == not
    if ((pbCurToken = strtok(nullptr, "!")) == NULL)
    {
        TEST_LOG_ERROR("Failed to parse logging level");
        goto cleanup;
    }

    if (strcmp(pbCurToken, "not") != 0)
    {
        TEST_LOG_ERROR("Header logging level is not \"not\". Logged: %s", pbCurToken);
        goto cleanup;
    }

    for (int i = 0; i < numExpectedEvents; i++)
    {
        if (i != 0)
        {
            if (!getline(logFile, curLine))
            {
                TEST_LOG_ERROR("Expected to read line %d of log file but reached end of log.", i + 1);
                goto cleanup;
            }

            printf("\t\t%d: %s\n", i + 1, curLine.c_str());

            pbHeader = strtok((char *)curLine.c_str(), "!");
            pbBody = strtok(nullptr, "");

            if (pbHeader == NULL || pbBody == NULL)
            {
                TEST_LOG_ERROR("Failed to parse log file header.");
                goto cleanup;
            }

            if (strcmp(pbExpectedHeader, pbHeader) != 0)
            {
                TEST_LOG_ERROR("Logged header does not match.\n\tExpected %s\n\tLogged: %s", pbExpectedHeader, pbHeader);
                goto cleanup;
            }
        }


        // Check key ID
        if ((pbCurToken = strtok(pbBody, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse key ID");
            goto cleanup;
        }

        if (strcmp(pbKeyId, pbCurToken) != 0)
        {
            TEST_LOG_ERROR("Logged key ID does not match. Expected %s, Logged: %s", pbKeyId, pbCurToken);
            goto cleanup;
        }

        // Check sign count
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse key ID");
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged sign count is not numeric. Logged: %s", pbCurToken);
            goto cleanup;
        }

        if (atoi(pbCurToken) != expectedEvents[i].signCount)
        {
            TEST_LOG_ERROR("Logged sign count does not match. Expected %d, Logged: %s", expectedEvents[i].signCount, pbCurToken);
            goto cleanup;
        }

        // Check decrypt count
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse decrypt count.");
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged decrypt count is not numeric. Logged: %s", pbCurToken);
            goto cleanup;
        }

        if (atoi(pbCurToken) != expectedEvents[i].decryptCount)
        {
            TEST_LOG_ERROR("Logged decrypt count does not match. Expected %d, Logged: %s", expectedEvents[i].decryptCount, pbCurToken);
            goto cleanup;
        }

        // Check first log time
        if ((pbCurToken = strtok(nullptr, ",")) == NULL)
        {
            TEST_LOG_ERROR("Failed to parse first log time.");
            goto cleanup;
        }

        if (!isNumeric(pbCurToken))
        {
            TEST_LOG_ERROR("Logged first log time is not numeric. Logged: %s", pbCurToken);
            goto cleanup;
        }

        firstLogTime = atol(pbCurToken);

        if (i > 0 &&
            firstLogTime < lastLogTime)
        {
            TEST_LOG_ERROR("Logged first log time is before the last log time from the previous logging event. First: %ld, Last: %ld", firstLogTime, lastLogTime);
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
            TEST_LOG_ERROR("Logged last log time is not numeric. Logged: %s", pbCurToken);
            goto cleanup;
        }

        lastLogTime = atol(pbCurToken);

        // Check the first log time >= processStartTime
        if (firstLogTime < processStartTime)
        {
            TEST_LOG_ERROR("First log time is before the test started. Expected >= %ld, Logged: %ld", processStartTime, firstLogTime);
            goto cleanup;
        }

        if (expectedEvents[i].loggingDelay != 0)
        {
            if (lastLogTime - firstLogTime < expectedEvents[i].loggingDelay)
            {
                TEST_LOG_ERROR("Event logged before expected logging delay expired. Expected >= %lds, Logged: %lds", expectedEvents[i].loggingDelay, firstLogTime - loggedStartTime);
                goto cleanup;
            }
        }
        else if (firstLogTime != lastLogTime)
        {
            TEST_LOG_ERROR("First and last log time do not match. First: %ld, Last: %ld", firstLogTime, lastLogTime);
            goto cleanup;
        }
    }

    if (getline(logFile, curLine))
    {
        TEST_LOG_ERROR("Log file has more lines than expected.");
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:

    free(pbExpectedHeader);

    return ret;
}

SCOSSL_STATUS keysinuse_test_api_functions(PCBYTE pcbKey, SIZE_T cbKey, char pbKeyId[SCOSSL_KEYID_SIZE], BOOL testSign)
{
    SCOSSL_KEYSINUSE_CTX *keysinuseCtx = NULL;
    // Second keysinuse context loaded with the same key bytes
    SCOSSL_KEYSINUSE_CTX *keysinuseCtxCopy = NULL;
    // Third keysinuse context loaded by reference
    SCOSSL_KEYSINUSE_CTX *keysinuseCtxCopyByRef = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    KEYSINUSE_EXPECTED_EVENT expectedEvents[3] = {
        {0, 0, 0},
        {0, 0, 5},
        {0, 0, 0}};

    // Load the keysinuse context
    if ((keysinuseCtx = p_scossl_keysinuse_load_key(pcbKey, cbKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load keysinuse context");
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by bytes again
    if ((keysinuseCtxCopy = p_scossl_keysinuse_load_key(pcbKey, cbKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes");
        return SCOSSL_FAILURE;
    }

    // Load the same keysinuse context by reference
    if ((keysinuseCtxCopyByRef = p_scossl_keysinuse_load_key_by_ctx(keysinuseCtx)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context by reference");
        return SCOSSL_FAILURE;
    }

    if (keysinuseCtx != keysinuseCtxCopy ||
        keysinuseCtx != keysinuseCtxCopyByRef)
    {
        TEST_LOG_ERROR("KeysInUse contexts do not match");
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
        sleep(1);

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
        sleep(1);

        // Test second decrypt. Only the first event should be logged.
        p_scossl_keysinuse_on_decrypt(keysinuseCtx);
        p_scossl_keysinuse_on_decrypt(keysinuseCtxCopyByRef);
        expectedEvents[1].signCount = 2;
    }

    // Unload all references to the key. Pending events should still be logged
    // after the after the unload.
    p_scossl_keysinuse_unload_key(keysinuseCtx);
    keysinuseCtx = NULL;

    p_scossl_keysinuse_unload_key(keysinuseCtxCopyByRef);
    keysinuseCtxCopyByRef = NULL;

    // Wait for the logging delay to elapse so ensure events from unloaded
    // keys are written.
    sleep(5);

    // Reload they key by bytes after original references were unloaded.
    if ((keysinuseCtxCopy = p_scossl_keysinuse_load_key(pcbKey, cbKey)) == NULL)
    {
        TEST_LOG_ERROR("Failed to load second keysinuse context with key bytes");
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

    sleep(1);

    ret = keysinuse_test_check_log(pbKeyId, expectedEvents, sizeof(expectedEvents) / sizeof(expectedEvents[0]));
    remove(KEYSINUSE_LOG_FILE);

cleanup:
    p_scossl_keysinuse_unload_key(keysinuseCtx);
    p_scossl_keysinuse_unload_key(keysinuseCtxCopy);
    p_scossl_keysinuse_unload_key(keysinuseCtxCopyByRef);

    return ret;
}

SCOSSL_STATUS keysinuse_test_provider_sign(PCBYTE pcbKey, SIZE_T cbKey)
{
    SCOSSL_STATUS status = SCOSSL_SUCCESS;
    EVP_PKEY *pkeyCopy = NULL;

    // Test load
    // Test load by ctx
    // Test unload
    // Test sign
    // Test second+ sign throttled
    // Test decrypt
    // Test second decrypt+ throttled

    return status;
}

SCOSSL_STATUS keysinuse_test_provider_decrypt(PCBYTE pcbKey, SIZE_T cbKey)
{
    SCOSSL_STATUS status = SCOSSL_SUCCESS;
    EVP_PKEY *pkeyCopy = NULL;

    // Test load
    // Test load by ctx
    // Test unload
    // Test sign
    // Test second+ sign throttled
    // Test decrypt
    // Test second decrypt+ throttled

    return status;
}

// Generates a key with the specified parameters. *ppbKey is set to the encoded
// public key bytes, and pbKeyId is set to the expected keyId. The size of the
// encoded public key bytes is returned, and 0 is returned on error. The default
// provider will be explicitly used for this step to ensure any regressions in
// the tested provider(s) key encoding logic are caught by the tests.
SIZE_T keysinuse_test_generate_key(_In_ const char *algName, _In_ const OSSL_PARAM params[],
                                   _Out_ PBYTE *ppbKey, _Out_ char pbKeyId[SCOSSL_KEYID_SIZE])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;
    OSSL_ENCODER_CTX *encoderCtx = NULL;
    BYTE pbKeyIdBytes[SYMCRYPT_SHA256_RESULT_SIZE];
    SIZE_T cbKey = 0;
    PBYTE pbKey = NULL;

    // Generate key with parameters
    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, "provider=default")) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_new_from_name failed");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen_init failed");
        goto cleanup;
    }

    if (!EVP_PKEY_CTX_set_params(ctx, params))
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_CTX_set_params failed");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_PKEY_keygen failed");
        goto cleanup;
    }

    if ((encoderCtx = OSSL_ENCODER_CTX_new_for_pkey(pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", "provider=default")) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("OSSL_ENCODER_CTX_new_for_pkey failed");
        goto cleanup;
    }

    if (OSSL_ENCODER_CTX_get_num_encoders(encoderCtx) == 0)
    {
        TEST_LOG_ERROR("No SubjectPublicKeyInfo encoders available");
        goto cleanup;
    }

    if (!OSSL_ENCODER_to_data(encoderCtx, &pbKey, &cbKey))
    {
        TEST_LOG_OPENSSL_ERROR("OSSL_ENCODER_to_data failed");
        goto cleanup;
    }

    if ((md = EVP_MD_fetch(NULL, "SHA256", "provider=default")) == NULL)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_MD_fetch failed");
        goto cleanup;
    }

    if (EVP_Digest(pbKey, cbKey, pbKeyIdBytes, NULL, md, NULL) <= 0)
    {
        TEST_LOG_OPENSSL_ERROR("EVP_Digest failed");
        goto cleanup;
    }

    for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE / 2; i++)
    {
        sprintf(&pbKeyId[i*2], "%02x", pbKeyIdBytes[i]);
    }
    pbKeyId[SYMCRYPT_SHA256_RESULT_SIZE] = '\0';

    *ppbKey = pbKey;
    pbKey = NULL;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OSSL_ENCODER_CTX_free(encoderCtx);
    EVP_MD_free(md);
    OPENSSL_free(pbKey);

    return pbKey == NULL ? cbKey : 0;
}

int main(int argc, char** argv)
{
    mode_t umaskOriginal;
    PBYTE pbKey = NULL;
    SIZE_T cbKey = 0;
    char keysinuseLogDir[sizeof(KEYSINUSE_LOG_DIR)];
    char pbKeyId[SCOSSL_KEYID_SIZE];
    OSSL_PARAM params[2] = { OSSL_PARAM_END };
    int ret = 0;

    p_scossl_keysinuse_set_logging_delay(5);
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
            TEST_LOG_ERROR("Failed to chroot to testing root: %d", errno);
            rmdir(KEYSINUSE_TEST_ROOT);
            goto cleanup;
        }
    }
    else
    {
        TEST_LOG_ERROR("Failed to create testing root: %d", errno);
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
                TEST_LOG_ERROR("Failed to create parent of logging directory %s: %d", keysinuseLogDir, errno);
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
            TEST_LOG_ERROR("Failed to set ownership of logging directory: %d", errno);
            rmdir(KEYSINUSE_LOG_DIR);
            goto cleanup;
        }
    }
    else if (errno != EACCES && errno != EEXIST)
    {
        TEST_LOG_ERROR("Failed to create logging directory: %d", errno);
        goto cleanup;
    }

    umask(umaskOriginal);

    if (!p_scossl_keysinuse_is_enabled())
    {
        TEST_LOG_ERROR("KeysInUse is not enabled");
        goto cleanup;
    }

    for (int i = 0; i < sizeof(rsaTestSizes) / sizeof(rsaTestSizes[0]); i++)
    {
        // Generate key
        params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, (int *)&rsaTestSizes[i]);
        if ((cbKey = keysinuse_test_generate_key("RSA", params, &pbKey, pbKeyId)) == 0)
        {
            goto cleanup;
        }

        printf("Testing RSA key with size %d:", rsaTestSizes[i]);
        TEST_PRINT_BYTES(pbKey, cbKey);
        printf("\n\tKeyId: %s\n\n", pbKeyId);

        printf("\tTesting KeysInUse API functions:\n");
        keysinuse_test_api_functions(pbKey, cbKey, pbKeyId, TRUE);
        // keysinuse_test_provider_sign
    }

    for (int i = 0; i < sizeof(eccTestGroups) / sizeof(eccTestGroups[0]); i++)
    {
        // Generate key
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)eccTestGroups[i], sizeof(eccTestGroups[i]));
        if ((cbKey = keysinuse_test_generate_key("EC", params, &pbKey, pbKeyId)) == 0)
        {
            goto cleanup;
        }

        printf("Testing ECDSA key with group %s:\n", eccTestGroups[i]);
        printf("\n\tPublic Key: %s", pbKeyId);
        TEST_PRINT_BYTES(pbKey, cbKey);
        printf("\n\tKeyId: %s\n\n", pbKeyId);

        printf("\tTesting KeysInUse API functions:\n");
        keysinuse_test_api_functions(pbKey, cbKey, pbKeyId, TRUE);

        // keysinuse_test_api_functions
        // keysinuse_test_provider_sign
    }
    // For EC params in ec test cases
        // Generate key
        // keysinuse_test_api_functions
        // keysinuse_test_provider_sign
    // For x25519 params in x25519 test cases
        // Generate key
        // keysinuse_test_api_functions
        // keysinuse_test_provider_sign
    // For RSA params in rsa sign test cases
        // Generate key
        // keysinuse_test_api_functions
        // keysinuse_test_provider_sign
    // For RSA params in rsa decrypt test cases
        // Generate key
        // keysinuse_test_api_functions
        // keysinuse_test_provider_decrypt

    ret = 1;

cleanup:
    free(processName);
    free(pbKey);
    p_scossl_keysinuse_teardown();
    keysinsue_test_cleanup();

    return ret;
}

#ifdef __cplusplus
}
#endif