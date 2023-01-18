#define IMPLEMENT_SCOSSL_SIGNATURE(alg)                                                               \
    const OSSL_DISPATCH scossl_prov_##alg##_signature[] = {                                           \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))scossl_prov_##alg##_sig_sig_newctx},                                 \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))scossl_prov_##alg##_sig_sig_sign_init},                           \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))scossl_prov_##alg##_sig_sig_sign},                                     \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))scossl_prov_##alg##_sig_sig_verify_init},                       \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))scossl_prov_##alg##_sig_sig_verify},                                 \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_sign_init},             \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_signverify_update},   \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_sign_final},           \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_verify_init},         \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_signverify_update}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))scossl_prov_##alg##_sig_sig_digest_verify_final},       \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))scossl_prov_##alg##_sig_sig_freectx},                               \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))scossl_prov_##alg##_sig_sig_dupctx},                                 \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_get_ctx_params},                 \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_gettable_ctx_params},       \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_set_ctx_params},                 \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_settable_ctx_params},       \
        {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_get_ctx_md_params},           \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_gettable_ctx_md_params}, \
        {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_set_ctx_md_params},           \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))scossl_prov_##alg##_sig_sig_settable_ctx_md_params}, \
        {0, NULL}};
