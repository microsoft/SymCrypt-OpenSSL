#define IMPLEMENT_SCOSSL_CIPHER_FUNCTIONS(alg, bits, lc)                                                     \
    const OSSL_DISPATCH scossl_prov_##alg##kbits##lc##_functions[] = {                                       \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))scossl_prov_##alg##kbits##lc##_newctx},                    \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))scossl_prov_##alg##_##lc##_freectx},                      \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))scossl_prov_##alg##lc##_encrypt_init},               \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))scossl_prov_##alg##lc##_decrypt_init},               \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))scossl_prov_##alg##lc##_update},                           \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))scossl_prov_##alg##lc##_final},                             \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))scossl_prov_##alg##lc##_cipher},                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))alg##_##kbits##_##lc##_get_params},                    \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))scossl_prov_##lc##_get_ctx_params},                \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))scossl_prov_##lc##_set_ctx_params},                \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))scossl_prov_cipher_gettable_params},      \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_cipher_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_cipher_settable_ctx_params}, \
        {0, NULL}};