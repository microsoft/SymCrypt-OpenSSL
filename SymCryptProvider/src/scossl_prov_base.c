#include "scossl_prov_base.h"

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

#define ALG(names, funcs) {names, "provider="SCOSSL_NAME, funcs}
#define ALG_TABLE_END { NULL, NULL, NULL, NULL}

static const OSSL_ALGORITHM scossl_prov_digest[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_cipher[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_mac[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_kdf[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_rand[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_keymgmt[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_keyexch[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_signature[] = {

    ALG_TABLE_END
};

static const OSSL_ALGORITHM scossl_prov_asym_cipher[] = {

    ALG_TABLE_END
};


static int scossl_prov_get_status()
{
    return 1;
}

static void scossl_prov_teardown(PSCOSSL_PROV_CTX *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *scossl_prov_gettable_params(PSCOSSL_PROV_CTX *provctx)
{
    return scossl_prov_param_types;
}

static int scossl_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, scossl_prov_get_status()))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *scossl_prov_query_operation(void *provctx, int operation_id, int *no_store)
{
    switch (operation_id)
    {
        case OSSL_OP_DIGEST:
            return scossl_prov_digest;
        case OSSL_OP_CIPHER:
            return scossl_prov_cipher;
        case OSSL_OP_MAC:
            return scossl_prov_mac;
        case OSSL_OP_KDF:
            return scossl_prov_kdf;
        case OSSL_OP_RAND:
            return scossl_prov_rand;
        case OSSL_OP_KEYMGMT:
            return scossl_prov_keymgmt;
        case OSSL_OP_KEYEXCH:
            return scossl_prov_keyexch;
        case OSSL_OP_SIGNATURE:
            return scossl_prov_signature;
        case OSSL_OP_ASYM_CIPHER:
            return scossl_prov_asym_cipher;
    }

    return NULL;
}

static const OSSL_DISPATCH scossl_prov_base_dispatch[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))scossl_prov_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))scossl_prov_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))scossl_prov_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))scossl_prov_query_operation},
    {0, NULL}};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    PSCOSSL_PROV_CTX p_ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_CTX));
    if (p_ctx != NULL)
    {
        p_ctx->handle = handle;
        *provctx = p_ctx;
    }

    *out = scossl_prov_base_dispatch;

    return 1;
}