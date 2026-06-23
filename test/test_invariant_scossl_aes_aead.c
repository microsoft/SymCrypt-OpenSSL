#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Include the header that declares the function
#include "scossl_aes_aead.h"

START_TEST(test_aes_gcm_iv_length_validation)
{
    // Invariant: IV length must be validated before memcpy to prevent heap overflow
    // The function must reject SIZE_MAX as ivlen to prevent unbounded copy
    
    size_t test_ivlens[] = {
        (size_t)-1,     // SIZE_MAX - the exploit case
        SIZE_MAX - 1,   // Boundary case near SIZE_MAX
        12,             // Valid GCM IV length
    };
    int num_tests = sizeof(test_ivlens) / sizeof(test_ivlens[0]);
    
    unsigned char small_iv[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    
    for (int i = 0; i < num_tests; i++) {
        SCOSSL_CIPHER_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_CIPHER_GCM_CTX));
        ck_assert_ptr_nonnull(ctx);
        
        // Initialize with a safe ivlen
        ctx->ivlen = 12;
        ctx->iv = OPENSSL_malloc(12);
        ck_assert_ptr_nonnull(ctx->iv);
        
        int result = scossl_aes_gcm_set_iv_fixed(ctx, test_ivlens[i], small_iv);
        
        // Security invariant: function must reject dangerous ivlen values
        // SIZE_MAX and near-SIZE_MAX values must fail (return 0 or negative)
        if (test_ivlens[i] >= (size_t)INT_MAX) {
            ck_assert_msg(result <= 0, 
                "Function accepted dangerous ivlen=%zu, risking heap overflow", 
                test_ivlens[i]);
        }
        
        OPENSSL_free(ctx->iv);
        OPENSSL_free(ctx);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_aes_gcm_iv_length_validation);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}