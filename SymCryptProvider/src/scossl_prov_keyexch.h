#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#define IMPLEMENT_SCOSSL_KEYEXCH_FUNCTIONS(alg)                                                                   \
    const OSSL_DISPATCH scossl_prov_##alg##_keyexch_functions = {                                                 \
        {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))scossl_prov_##alg##_keyexch_newctx},                           \ 
        {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))scossl_prov_##alg##_keyexch_init},                               \ 
        {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))scossl_prov_##alg##_keyexch_derive},                           \ 
        {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))scossl_prov_##alg##_keyexch_set_peer},                       \ 
        {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))scossl_prov_##alg##_keyexch_freectx},                         \ 
        {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))scossl_prov_##alg##_keyexch_dupctx},                           \ 
        {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_keyexch_set_ctx_params},           \ 
        {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_keyexch_settable_ctx_params}, \ 
        {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_keyexch_get_ctx_params},           \ 
        {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))scossl_prov_##alg##_keyexch_gettable_ctx_params}, \ 
        {0, NULL}};