//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prototype definition, subject to change
#define IMPLEMENT_SCOSSL_SIGNATURE(alg)                                                                                   \
    const OSSL_DISPATCH p_scossl_##alg##_signature[] = {                                                               \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_##alg##_sig_sig_newctx},                                 \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_##alg##_sig_sig_sign_init},                           \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_##alg##_sig_sig_sign},                                     \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_##alg##_sig_sig_verify_init},                       \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_##alg##_sig_sig_verify},                                 \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_##alg##_sig_sig_digest_sign_init},             \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))p_scossl_##alg##_sig_sig_digest_signverify_update},   \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))p_scossl_##alg##_sig_sig_digest_sign_final},           \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_##alg##_sig_sig_digest_verify_init},         \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))p_scossl_##alg##_sig_sig_digest_signverify_update}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))p_scossl_##alg##_sig_sig_digest_verify_final},       \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_##alg##_sig_sig_freectx},                               \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_##alg##_sig_sig_dupctx},                                 \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_get_ctx_params},                 \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_gettable_ctx_params},       \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_set_ctx_params},                 \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_settable_ctx_params},       \
        {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_get_ctx_md_params},           \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_gettable_ctx_md_params}, \
        {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_set_ctx_md_params},           \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))p_scossl_##alg##_sig_sig_settable_ctx_md_params}, \
        {0, NULL}};

#ifdef __cplusplus
}
#endif