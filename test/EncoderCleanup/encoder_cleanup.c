//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stdio.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
    ERR_print_errors_fp(stderr); goto cleanup; } } while (0)

static const char *propq = "provider=symcryptprovider";
static const unsigned char password[] = "encoder cleanup regression";

static int is_symcrypt(EVP_PKEY *key)
{
    const OSSL_PROVIDER *provider = EVP_PKEY_get0_provider(key);
    return provider != NULL &&
        strcmp(OSSL_PROVIDER_get0_name(provider), "symcryptprovider") == 0;
}

static int roundtrip(OSSL_LIB_CTX *libctx, EVP_PKEY *key, const char *format)
{
    OSSL_ENCODER_CTX *enc = NULL;
    OSSL_DECODER_CTX *dec = NULL;
    EVP_PKEY *decoded = NULL;
    unsigned char *bytes = NULL;
    const unsigned char *cursor;
    size_t length = 0, remaining;
    int ok = 0;
    enc = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
        format, "EncryptedPrivateKeyInfo", propq);
    CHECK(enc && OSSL_ENCODER_CTX_get_num_encoders(enc) > 0);
    CHECK(OSSL_ENCODER_CTX_set_cipher(enc, "AES-128-CBC", NULL) == 1);
    CHECK(OSSL_ENCODER_CTX_set_cipher(enc, "AES-256-CBC", NULL) == 1);
    CHECK(OSSL_ENCODER_CTX_set_passphrase(enc, password, sizeof(password) - 1) == 1);
    CHECK(OSSL_ENCODER_to_data(enc, &bytes, &length) == 1 && length > 0);
    OSSL_ENCODER_CTX_free(enc);
    enc = NULL;

    dec = OSSL_DECODER_CTX_new_for_pkey(&decoded, format, NULL, NULL,
        OSSL_KEYMGMT_SELECT_KEYPAIR, libctx, "?provider=symcryptprovider");
    CHECK(dec && OSSL_DECODER_CTX_set_passphrase(dec, password, sizeof(password) - 1) == 1);
    cursor = bytes;
    remaining = length;
    CHECK(OSSL_DECODER_from_data(dec, &cursor, &remaining) == 1 && remaining == 0);
    CHECK(decoded && is_symcrypt(decoded) && EVP_PKEY_eq(key, decoded) == 1);
    ok = 1;
cleanup:
    OSSL_ENCODER_CTX_free(enc);
    OSSL_DECODER_CTX_free(dec);
    EVP_PKEY_free(decoded);
    OPENSSL_clear_free(bytes, length);
    return ok;
}

static int context_cleanup(EVP_PKEY *key)
{
    OSSL_ENCODER_CTX *enc = NULL;
    int ok = 0;
    for (int mode = 0; mode < 4; ++mode)
    {
        enc = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
            "DER", "EncryptedPrivateKeyInfo", propq);
        CHECK(enc && OSSL_ENCODER_CTX_get_num_encoders(enc) > 0);
        if (mode != 0)
            CHECK(OSSL_ENCODER_CTX_set_cipher(enc, "AES-256-CBC", NULL) == 1);
        if (mode == 2)
            CHECK(OSSL_ENCODER_CTX_set_cipher(enc, NULL, NULL) == 1);
        if (mode == 3)
        {
            CHECK(OSSL_ENCODER_CTX_set_cipher(enc, "not-a-cipher", NULL) == 0);
            ERR_clear_error();
        }
        OSSL_ENCODER_CTX_free(enc);
        enc = NULL;
    }
    ok = 1;
cleanup:
    OSSL_ENCODER_CTX_free(enc);
    return ok;
}

static int run_algorithm(OSSL_LIB_CTX *libctx, const char *name, int encodeRoundtrip)
{
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    EVP_PKEY *key = NULL;
    int ok = 0;
    CHECK(gen && EVP_PKEY_keygen_init(gen) == 1 && EVP_PKEY_generate(gen, &key) == 1);
    CHECK(key && is_symcrypt(key));
    for (int i = 0; i < 3; ++i)
    {
        if (encodeRoundtrip)
        {
            CHECK(roundtrip(libctx, key, "DER"));
            CHECK(roundtrip(libctx, key, "PEM"));
        }
        CHECK(context_cleanup(key));
    }
    ok = 1;
cleanup:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *symcrypt = NULL;
    int ok = 0;
    if (argc != 2)
    {
        fprintf(stderr, "Usage: encoder_cleanup PROVIDER_DIRECTORY\n");
        return 2;
    }
    CHECK(OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) == 1);
    deflt = OSSL_PROVIDER_load(libctx, "default");
    symcrypt = OSSL_PROVIDER_load(libctx, "symcryptprovider");
    CHECK(deflt && symcrypt);
    CHECK(run_algorithm(libctx, "ML-DSA-44", 1));
    CHECK(run_algorithm(libctx, "ML-DSA-65", 1));
    CHECK(run_algorithm(libctx, "ML-DSA-87", 1));
    CHECK(run_algorithm(libctx, "ML-KEM-512", 0));
    CHECK(run_algorithm(libctx, "ML-KEM-768", 0));
    CHECK(run_algorithm(libctx, "ML-KEM-1024", 0));
    ok = 1;
cleanup:
    OSSL_PROVIDER_unload(symcrypt);
    OSSL_PROVIDER_unload(deflt);
    OPENSSL_cleanup();
    return ok ? 0 : 1;
}
