//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_base.h"
#include "p_scossl_mlkem.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLKEM_SECRET_LENGTH 32

static SCOSSL_MLKEM_GROUP_INFO p_scossl_mlkem_groups[] = {
    {NID_undef, SCOSSL_OID_MLKEM512, SCOSSL_SN_MLKEM512, SCOSSL_LN_MLKEM512, NULL, SYMCRYPT_MLKEM_PARAMS_MLKEM512},
    {NID_undef, SCOSSL_OID_MLKEM768, SCOSSL_SN_MLKEM768, SCOSSL_LN_MLKEM768, NULL, SYMCRYPT_MLKEM_PARAMS_MLKEM768},
    {NID_undef, SCOSSL_OID_MLKEM1024, SCOSSL_SN_MLKEM1024, SCOSSL_LN_MLKEM1024, NULL, SYMCRYPT_MLKEM_PARAMS_MLKEM1024},
    {NID_undef, SCOSSL_OID_P256_MLKEM768, SCOSSL_SN_P256_MLKEM768, SCOSSL_LN_P256_MLKEM768, SN_X9_62_prime256v1, SYMCRYPT_MLKEM_PARAMS_MLKEM768},
    {NID_undef, SCOSSL_OID_X25519_MLKEM768, SCOSSL_SN_X25519_MLKEM768, SCOSSL_LN_X25519_MLKEM768, SN_X25519, SYMCRYPT_MLKEM_PARAMS_MLKEM768},
    {NID_undef, SCOSSL_OID_P384_MLKEM1024, SCOSSL_SN_P384_MLKEM1024, SCOSSL_LN_P384_MLKEM1024, SN_secp384r1, SYMCRYPT_MLKEM_PARAMS_MLKEM1024}};
typedef struct
{
    int operation;
    SCOSSL_MLKEM_KEY_CTX *keyCtx;
} SCOSSL_MLKEM_CTX;

static const OSSL_PARAM p_scossl_mlkem_param_types[] = {
    OSSL_PARAM_END};

/* Context management */
static SCOSSL_MLKEM_CTX *p_scossl_mlkem_newctx(ossl_unused SCOSSL_PROVCTX *provctx)
{
    SCOSSL_MLKEM_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_CTX));

    return ctx;
}

static void p_scossl_mlkem_freectx(_Inout_ SCOSSL_MLKEM_CTX *ctx)
{
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx);
}

static SCOSSL_MLKEM_CTX *p_scossl_mlkem_dupctx(_In_ SCOSSL_MLKEM_CTX *ctx)
{
    SCOSSL_MLKEM_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->operation = ctx->operation;
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                         int operation)
{
    if (ctx == NULL || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return SCOSSL_SUCCESS;
}

//
// Encapsulation
//
static SCOSSL_STATUS p_scossl_mlkem_encapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_ENCAPSULATE);
}

static SCOSSL_STATUS p_scossl_mlkem_encapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen)
{
    SIZE_T cbMlkemCiphertext = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if (ctx->operation != EVP_PKEY_OP_ENCAPSULATE)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        goto cleanup;
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofCiphertextFromParams failed", scError);
        goto cleanup;
    }

    if (out != NULL)
    {
        if (secret == NULL || outlen == NULL || secretlen == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            goto cleanup;
        }

        if ((*outlen < cbMlkemCiphertext) ||
            (*secretlen < SCOSSL_MLKEM_SECRET_LENGTH))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        scError = SymCryptMlKemEncapsulate(ctx->keyCtx->key, secret, SCOSSL_MLKEM_SECRET_LENGTH, out, cbMlkemCiphertext);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemEncapsulate failed", scError);
            goto cleanup;
        }
    }
    else if (outlen == NULL && secretlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (outlen != NULL)
    {
        *outlen = cbMlkemCiphertext;
    }

    if (secretlen != NULL)
    {
        *secretlen = SCOSSL_MLKEM_SECRET_LENGTH;
    }

    ret = SCOSSL_SUCCESS;

cleanup:

    return ret;
}

//
// Decapsulation
//
static SCOSSL_STATUS p_scossl_mlkem_decapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    if (keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED &&
        keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_DECAPSULATE) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mlkem_decapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{

    SIZE_T cbMlkemCiphertext = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if (ctx->operation != EVP_PKEY_OP_DECAPSULATE)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        goto cleanup;
    }

    if (outlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofCiphertextFromParams failed", scError);
        goto cleanup;
    }

    if (out != NULL)
    {
        if (inlen != cbMlkemCiphertext)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
            goto cleanup;
        }

        if (*outlen < SCOSSL_MLKEM_SECRET_LENGTH)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        scError = SymCryptMlKemDecapsulate(ctx->keyCtx->key, in, cbMlkemCiphertext, out, SCOSSL_MLKEM_SECRET_LENGTH);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemDecapsulate failed", scError);
            goto cleanup;
        }
    }

    *outlen = SCOSSL_MLKEM_SECRET_LENGTH;
    ret = SCOSSL_SUCCESS;

cleanup:

    return ret;
}

//
// Parameters
//
static const OSSL_PARAM *p_scossl_mlkem_ctx_param_types(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_mlkem_param_types;
}

static SCOSSL_STATUS p_scossl_mlkem_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mlkem_get_ctx_params(ossl_unused void *ctx, ossl_unused OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_mlkem_functions[] = {
    {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p_scossl_mlkem_newctx},
    {OSSL_FUNC_KEM_FREECTX, (void (*)(void))p_scossl_mlkem_freectx},
    {OSSL_FUNC_KEM_DUPCTX, (void (*)(void))p_scossl_mlkem_dupctx},
    {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_encapsulate_init},
    {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p_scossl_mlkem_encapsulate},
    {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p_scossl_mlkem_decapsulate_init},
    {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p_scossl_mlkem_decapsulate},
    {OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_set_ctx_params},
    {OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_ctx_param_types},
    {OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_get_ctx_params},
    {OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mlkem_ctx_param_types},
    {0, NULL}};

_Use_decl_annotations_
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info_by_nid(int nid)
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mlkem_groups) / sizeof(SCOSSL_MLKEM_GROUP_INFO); i++)
    {
        if (p_scossl_mlkem_groups[i].nid == nid)
        {
            return &p_scossl_mlkem_groups[i];
        }
    }

    return NULL;
}

_Use_decl_annotations_
SCOSSL_MLKEM_GROUP_INFO *p_scossl_mlkem_get_group_info(_In_ const char *groupName)
{
    return p_scossl_mlkem_get_group_info_by_nid(OBJ_sn2nid(groupName));
}

SCOSSL_STATUS p_scossl_mlkem_register_algorithms()
{
    for (SIZE_T i = 0; i < sizeof(p_scossl_mlkem_groups) / sizeof(SCOSSL_MLKEM_GROUP_INFO); i++)
    {
        p_scossl_mlkem_groups[i].nid = OBJ_create(p_scossl_mlkem_groups[i].oid, p_scossl_mlkem_groups[i].snGroupName, p_scossl_mlkem_groups[i].lnGroupName);
        if (p_scossl_mlkem_groups[i].nid == NID_undef)
        {
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

int p_scossl_mlkem_get_bits(SYMCRYPT_MLKEM_PARAMS mlkemParams)
{
    switch (mlkemParams)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        return 512;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        return 768;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        return 1024;
    default:
    }

    return 0;
}

int p_scossl_mlkem_get_security_bits(SYMCRYPT_MLKEM_PARAMS mlkemParams)
{
    switch(mlkemParams)
    {
    case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
        return 128;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
        return 192;
    case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
        return 256;
    default:
    }

    return 0;
}

#ifdef __cplusplus
}
#endif