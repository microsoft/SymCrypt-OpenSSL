//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "kem/p_scossl_mlkem.h"
#include "keyexch/p_scossl_ecdh.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYMCRYPT_MLKEM_SECRET_LENGTH 32

typedef struct
{
    // Unused by MLKEM, but forwarded to the classic key exchange
    SCOSSL_PROVCTX *provCtx;

    SCOSSL_MLKEM_KEY_CTX *keyCtx;
    int operation;

    SCOSSL_ECDH_CTX *classicKeyexchCtx;
} SCOSSL_MLKEM_CTX;

static const OSSL_PARAM p_scossl_mlkem_param_types[] = {
    OSSL_PARAM_END};

/* Context management */
static SCOSSL_MLKEM_CTX *p_scossl_mlkem_newctx(ossl_unused void *provctx)
{
    SCOSSL_MLKEM_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MLKEM_CTX));

    if (ctx != NULL)
    {
        ctx->provCtx = provctx;
    }

    return ctx;
}

static void p_scossl_mlkem_freectx(_Inout_ SCOSSL_MLKEM_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->classicKeyexchCtx != NULL)
    {
        p_scossl_ecdh_freectx(ctx->classicKeyexchCtx);
    }

    OPENSSL_free(ctx);
}

static SCOSSL_MLKEM_CTX *p_scossl_mlkem_dupctx(_In_ SCOSSL_MLKEM_CTX *ctx)
{
    SCOSSL_MLKEM_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_MLKEM_CTX));

    if (copyCtx != NULL)
    {
        copyCtx->keyCtx = ctx->keyCtx;
        copyCtx->operation = ctx->operation;
        copyCtx->provCtx = ctx->provCtx;

        if (ctx->classicKeyexchCtx != NULL)
        {
            copyCtx->classicKeyexchCtx = NULL;
        }
        else if ((copyCtx->classicKeyexchCtx = p_scossl_ecdh_dupctx(ctx->classicKeyexchCtx)) == NULL)
        {
            OPENSSL_free(copyCtx);
            copyCtx = NULL;
        }
    }

    return copyCtx;
}

static SCOSSL_STATUS p_scossl_mlkem_classic_keyexch_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, PVOID classicKeyCtx)
{
    if (ctx->classicKeyexchCtx == NULL &&
        (ctx->classicKeyexchCtx = p_scossl_ecdh_newctx(ctx->provCtx)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_ecdh_init(ctx->classicKeyexchCtx, classicKeyCtx, NULL) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_mlkem_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                         int operation)
{
    if (ctx == NULL || keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (keyCtx == NULL || keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return SCOSSL_SUCCESS;
}

//
// Encapsulation
//

// We don't initialize the classic key context for hybrid here, since
// ctx->keyCtx->classicKeyCtx contains the peer key, and 'our' key is generated
// during encapsulation.
static SCOSSL_STATUS p_scossl_mlkem_encapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_ENCAPSULATE);
}

// Performs ML-KEM encapsulation using the previously initialized context. If
// this is a hybrid group, then hybrid encapsulation is performed.
// ctx->keyCtx->classicKeyCtx is used as the peer key, and an ephemeral
// ECDH key is generated as 'our' key to derive the shared ECDH secret.
//
// secret == ECDH shared secret | MLKEM secret
// out == Ephemeral ECDH public key | MLKEM ciphertext
static SCOSSL_STATUS p_scossl_mlkem_encapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _Out_writes_bytes_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen)
{
    SIZE_T cbClassicKey = 0;
    SIZE_T cbMlkemCiphertext = 0;
    SIZE_T cbClassicSecret = 0;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPeer = NULL;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPrivate = NULL;
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

    classicKeyCtxPeer = ctx->keyCtx->classicKeyCtx;

    if (ctx->keyCtx->classicGroupName != NULL)
    {
        if (classicKeyCtxPeer == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        // Get key size
        cbClassicKey = p_scossl_ecc_get_encoded_key_size(classicKeyCtxPeer, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

        // Get secret size
        if ((cbClassicSecret = p_scossl_ecc_get_max_size(classicKeyCtxPeer, TRUE)) == 0)
        {
            goto cleanup;
        }
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (out != NULL)
    {
        if ((outlen != NULL && *outlen < cbClassicKey + cbMlkemCiphertext) ||
            (secretlen != NULL && *secretlen < cbClassicSecret + SYMCRYPT_MLKEM_SECRET_LENGTH))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        scError = SymCryptMlKemEncapsulate(ctx->keyCtx->key, secret, SYMCRYPT_MLKEM_SECRET_LENGTH, out, cbMlkemCiphertext);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        out += cbMlkemCiphertext;
        secret += SYMCRYPT_MLKEM_SECRET_LENGTH;

        if (ctx->keyCtx->classicGroupName != NULL)
        {
            // Generate ephemeral ECDH key
            if ((classicKeyCtxPrivate = p_scossl_ecc_new_ctx(ctx->provCtx)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (p_scossl_ecc_set_group(classicKeyCtxPrivate, ctx->keyCtx->classicGroupName) != SCOSSL_SUCCESS ||
                p_scossl_ecc_gen(classicKeyCtxPrivate) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Write encoded public key bytes
            if (p_scossl_ecc_get_encoded_key(classicKeyCtxPrivate, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &out, &cbClassicKey) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Derive ECDH secret
            if (p_scossl_mlkem_classic_keyexch_init(ctx, classicKeyCtxPrivate) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_set_peer(ctx->classicKeyexchCtx, classicKeyCtxPeer) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_derive(ctx->classicKeyexchCtx, secret, &cbClassicSecret, *secretlen) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }
        }
    }
    else if (outlen == NULL && secretlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (outlen != NULL)
    {
        *outlen = cbClassicKey + cbMlkemCiphertext;
    }

    if (secretlen != NULL)
    {
        *secretlen = cbClassicSecret + SYMCRYPT_MLKEM_SECRET_LENGTH;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    p_scossl_ecc_free_ctx(classicKeyCtxPrivate);

    return ret;
}

//
// Decapsulation
//
static SCOSSL_STATUS p_scossl_mlkem_decapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_DECAPSULATE) &&
           p_scossl_mlkem_classic_keyexch_init(ctx, ctx->keyCtx->classicKeyCtx);
}

// Performs ML-KEM decapsulation using the previously initialized context. If
// this is a hybrid group, then hybrid decapsulation is performed.
// ctx->keyCtx->classicKeyCtx is used as 'our' key, and the peer key is
// extracted from the beginning of 'in'
//
// in == Ephemeral ECDH public key | MLKEM ciphertext
// out == ECDH shared secret | MLKEM secret
static SCOSSL_STATUS p_scossl_mlkem_decapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{
    SIZE_T cbClassicKey = 0;
    SIZE_T cbMlkemCiphertext = 0;
    SIZE_T cbClassicSecret = 0;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPeer = NULL;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPrivate = NULL;
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

    classicKeyCtxPrivate = ctx->keyCtx->classicKeyCtx;

    if (ctx->keyCtx->classicGroupName != NULL)
    {
        if (classicKeyCtxPrivate == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        // Get key size
        cbClassicKey = p_scossl_ecc_get_encoded_key_size(classicKeyCtxPrivate, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

        // Get secret size
        if ((cbClassicSecret = p_scossl_ecc_get_max_size(classicKeyCtxPrivate, TRUE)) == 0)
        {
            goto cleanup;
        }
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(ctx->keyCtx->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (inlen != cbMlkemCiphertext + cbClassicKey)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        goto cleanup;
    }

    if (out != NULL)
    {
        if (outlen != NULL && *outlen < SYMCRYPT_MLKEM_SECRET_LENGTH + cbClassicSecret)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        scError = SymCryptMlKemDecapsulate(ctx->keyCtx->key, in, cbMlkemCiphertext, out, SYMCRYPT_MLKEM_SECRET_LENGTH);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        in += cbMlkemCiphertext;
        out += SYMCRYPT_MLKEM_SECRET_LENGTH;

        if (ctx->keyCtx->classicGroupName != NULL)
        {
            // Extract ECDH public key from in
            if ((classicKeyCtxPeer = p_scossl_ecc_new_ctx(ctx->provCtx)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (p_scossl_ecc_set_group(classicKeyCtxPeer, ctx->keyCtx->classicGroupName) != SCOSSL_SUCCESS ||
                p_scossl_ecc_set_encoded_key(classicKeyCtxPeer, in, cbClassicKey, NULL, 0) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Derive shared ECDH secret
            if (p_scossl_ecdh_set_peer(ctx->classicKeyexchCtx, classicKeyCtxPeer) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_derive(ctx->classicKeyexchCtx, out, &cbClassicSecret, *outlen - SYMCRYPT_MLKEM_SECRET_LENGTH) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }
        }
    }
    else if (outlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (outlen != NULL)
    {
        *outlen = SYMCRYPT_MLKEM_SECRET_LENGTH + cbClassicSecret;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    p_scossl_ecc_free_ctx(classicKeyCtxPeer);

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

#ifdef __cplusplus
}
#endif