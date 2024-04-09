# EVP tests

The test recipes contained in this folder are intended to be used with the OpenSSL evp_test application. The application
is produced in the _test_ folder when building OpenSSL from source. A small modification is also needed to test the engine
and provider properly (see below). These recipes are a modified version of the
[upstream EVP test recipes](https://github.com/openssl/openssl/tree/master/test/recipes/30-test_evp_data).
The SymCrypt engine and provider don't support all the algorithms in the test files. These are left in the test files to validate algorithm fetching when the SymCrypt engine and/or provider are configured.

Note that some tests under '3.0' are suffixed with 'provider' and 'engine'. These are intended to be run with the provider
and engine configured respectively due to minor support differences. Additionally, the SymCrypt engine is always used for
OpenSSL 3.0 ciphers if configured.

## Running

The below steps assume you have some config file with the SymCrypt engine and/or provider configured.

### OpenSSL 1.1.1

1. Update evp_test.c to load the config in `setup_test()`

    ```diff
    @@ -2718,6 +2718,13 @@ int setup_tests(void)
    {
        size_t n = test_get_argument_count();

    +    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
    +    {
    +        TEST_error("OPENSSL_init_crypto failed");
    +        TEST_openssl_errors();
    +        return 0;
    +    }
    +
        if (n == 0) {
            TEST_error("Usage: %s file...", test_get_program_name());
            return 0;
    ```

2. Build evp_test
3. Run evp_test against test files in EvpTestRecipes/1.1.1

    ```console
    OPENSSL_CONF=<path_to_your_config> \
    test/evp_test <SymCrypt-OpenSSL_root>/EvpTestRecipes/1.1.1/<test_name>.txt
    ```

### OpenSSL 3.0

1. Update evp_test.c to skip the IV check in the cipher tests for engines

    ```diff
    @@ -813,7 +813,8 @@ static int cipher_test_enc(EVP_TEST *t, int enc,
        }

        /* Check that we get the same IV back */
    -    if (expected->iv != NULL) {
    +    if (expected->iv != NULL &&
    +        EVP_CIPHER_get0_provider(EVP_CIPHER_CTX_get0_cipher(ctx_base)) != NULL) {
            /* Some (e.g., GCM) tests use IVs longer than EVP_MAX_IV_LENGTH. */
            unsigned char iv[128];
            if (!TEST_true(EVP_CIPHER_CTX_get_updated_iv(ctx_base, iv, sizeof(iv)))
    ```

2. Build evp_test
3. Run evp_test against test files in EvpTestRecipes/3.0

    ```console
    test/evp_test -config <path_to_your_config> \<SymCrypt-OpenSSL_root>/EvpTestRecipes/3.0/<test_name>.txt
    ```

## Tests

### OpenSSL 1.1.1

| Test Name | Test File |
|-----------|-----------|
| Case Insensitive | evpcase.txt |
| AES-CCM CAVS | evpccmcavs.txt |
| Ciphers | evpciph.txt |
| Digests | evpdigest.txt |
| Key Derivation | evpkdf.txt |
| MAC | evpmac.txt |
| ECDH | evppkey_ecc.txt |
| Sign/Verify | evppkey.txt |

### OpenSSL 3.0

| Test Name | Test File |
|-----------|-----------|
| AES-CCM CAVS | evpciph_aes_ccm_cavs.txt |
| AES (Engine) | evpciph_aes_engine.txt |
| AES (Provider) | evpciph_aes_provider.txt |
| HKDF | evpkdf_hkdf.txt |
| KBKDF Counter (SP800-108) | evpkdf_kbkdf_counter.txt |
| KBKDF KMAC (SP800-108)| evpkdf_kbkdf_kmac.txt |
| SSHKDF | evpkdf_ssh.txt |
| TLS1 PRF | evpkdf_tls11_prf.txt |
| TLS1.2 PRF | evpkdf_tls12_prf.txt |
| MAC | evpmac_common.txt |
| HMAC MD5 (Engine) | evpmac_engine.txt |
| DH | evppkey_dh.txt |
| ECDH | evppkey_ecdh.txt |
| ECDSA | evppkey_ecdsa.txt |
| X25519 | evppkey_ecx.txt |
| FFDHE | evppkey_ffdhe.txt |
| RSA | evppkey_rsa_common.txt |
| RSA (Engine) | evppkey_rsa_engine.txt |
| RSA (Provider) | evppkey_rsa_provider.txt |
| RSA (Additional) | evppkey_rsa.txt |
