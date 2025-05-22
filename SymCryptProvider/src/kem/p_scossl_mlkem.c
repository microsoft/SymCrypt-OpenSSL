//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_base.h"
#include "p_scossl_mlkem.h"
#include "keyexch/p_scossl_ecdh.h"

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
    // Unused by MLKEM, but forwarded to the classic key exchange
    SCOSSL_PROVCTX *provCtx;

    int operation;
    SCOSSL_MLKEM_KEY_CTX *keyCtx;

    SCOSSL_ECDH_CTX *classicKeyexchCtx;
} SCOSSL_MLKEM_CTX;

static const OSSL_PARAM p_scossl_mlkem_param_types[] = {
    OSSL_PARAM_END};

/* Context management */
static SCOSSL_MLKEM_CTX *p_scossl_mlkem_newctx(_In_ SCOSSL_PROVCTX *provctx)
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

    p_scossl_ecdh_freectx(ctx->classicKeyexchCtx);
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

static SCOSSL_STATUS p_scossl_mlkem_classic_keyexch_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_ECC_KEY_CTX *classicKeyCtx)
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

    if (keyCtx->key == NULL ||
        keyCtx->groupInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_mlkem_is_hybrid(keyCtx) &&
        keyCtx->classicKeyCtx == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Missing classic key in hybrid MLKEM key");
        return SCOSSL_FAILURE;
    }

    ctx->keyCtx = keyCtx;
    ctx->operation = operation;

    return SCOSSL_SUCCESS;
}

//
// Encapsulation
//

// We don't initialize the classic key context for hybrid here.
// ctx->keyCtx->classicKeyCtx contains the peer key. Our ephemeral key
// is generated during encapsulation.
static SCOSSL_STATUS p_scossl_mlkem_encapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    return p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_ENCAPSULATE);
}

// Performs ML-KEM encapsulation using the previously initialized context. If
// this is a hybrid group, then hybrid encapsulation is performed.
// ctx->keyCtx->classicKeyCtx is used as the peer key, and our ephemeral
// ECDH key is generated as to derive the shared ECDH secret. The concatenated
// order of classic and ML-KEM data depends on the classic group.
//
// - secret
//      X25519:         MLKEM shared secret || ECDH shared secret
//      P-256/P-384:    ECDH shared secret || MLKEM shared secret
// - out
//      X25519:         MLKEM ciphertext || Ephemeral ECDH public key
//      P-256/P-384:    Ephemeral ECDH public key || MLKEM ciphertext
static SCOSSL_STATUS p_scossl_mlkem_encapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _Out_writes_bytes_opt_(*secretlen) unsigned char *secret, _Out_ size_t *secretlen)
{
    PBYTE pbMlkemCipherText = NULL;
    PBYTE pbClassicKey = NULL;
    PBYTE pbMlkemSecret = NULL;
    PBYTE pbClassicSecret = NULL;
    SIZE_T cbClassicKey = 0;
    SIZE_T cbMlkemCiphertext = 0;
    SIZE_T cbClassicSecret = 0;
    SIZE_T cbOut;
    SIZE_T cbSecret;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPeer = NULL;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPrivate = NULL;
    const SCOSSL_MLKEM_GROUP_INFO *groupInfo;
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

    groupInfo = ctx->keyCtx->groupInfo;

    if (groupInfo->classicGroupName != NULL)
    {
        if ((classicKeyCtxPeer = ctx->keyCtx->classicKeyCtx) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        cbClassicKey = p_scossl_ecc_get_encoded_key_size(classicKeyCtxPeer, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

        if ((cbClassicSecret = p_scossl_ecc_get_max_result_size(classicKeyCtxPeer, TRUE)) == 0)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "p_scossl_ecc_get_max_result_size failed");
            goto cleanup;
        }
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(groupInfo->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofCiphertextFromParams failed", scError);
        goto cleanup;
    }

    cbOut = cbClassicKey + cbMlkemCiphertext;
    cbSecret = cbClassicSecret + SCOSSL_MLKEM_SECRET_LENGTH;

    if (out != NULL)
    {
        if (secret == NULL || outlen == NULL || secretlen == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            goto cleanup;
        }

        if ((*outlen < cbOut) ||
            (*secretlen < cbSecret))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        if (groupInfo->classicGroupName != NULL)
        {
            if (classicKeyCtxPeer->isX25519)
            {
                pbMlkemCipherText = out;
                pbClassicKey = out + cbMlkemCiphertext;
                pbMlkemSecret = secret;
                pbClassicSecret = secret + SCOSSL_MLKEM_SECRET_LENGTH;
            }
            else
            {
                pbClassicKey = out;
                pbMlkemCipherText = out + cbClassicKey;
                pbClassicSecret = secret;
                pbMlkemSecret = secret + cbClassicSecret;
            }

            // Generate ephemeral ECDH key
            if ((classicKeyCtxPrivate = p_scossl_ecc_new_ctx(ctx->provCtx)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (p_scossl_ecc_set_group(classicKeyCtxPrivate, groupInfo->classicGroupName) != SCOSSL_SUCCESS ||
                p_scossl_ecc_gen(classicKeyCtxPrivate) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Write encoded public key bytes
            if (p_scossl_ecc_get_encoded_key(classicKeyCtxPrivate, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pbClassicKey, &cbClassicKey) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Derive ECDH secret
            if (p_scossl_mlkem_classic_keyexch_init(ctx, classicKeyCtxPrivate) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_set_peer(ctx->classicKeyexchCtx, classicKeyCtxPeer) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_derive(ctx->classicKeyexchCtx, pbClassicSecret, &cbClassicSecret, cbClassicSecret) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }
        }
        else
        {
            pbMlkemCipherText = out;
            pbMlkemSecret = secret;
        }

        scError = SymCryptMlKemEncapsulate(ctx->keyCtx->key, pbMlkemSecret, SCOSSL_MLKEM_SECRET_LENGTH, pbMlkemCipherText, cbMlkemCiphertext);
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
        *outlen = cbOut;
    }

    if (secretlen != NULL)
    {
        *secretlen = cbSecret;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    p_scossl_ecc_free_ctx(classicKeyCtxPrivate);

    return ret;
}

//
// Decapsulation
//

// Unlike encapsulation, we initialize the classic key context for hybrid here,
// since ctx->keyCtx->classicKeyCtx contains our private key. The peer key is
// extracted from the public data passed to decapsulate.
static SCOSSL_STATUS p_scossl_mlkem_decapsulate_init(_Inout_ SCOSSL_MLKEM_CTX *ctx, _In_ SCOSSL_MLKEM_KEY_CTX *keyCtx,
                                                     ossl_unused const OSSL_PARAM params[])
{
    if (p_scossl_mlkem_init(ctx, keyCtx, EVP_PKEY_OP_DECAPSULATE) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED &&
        ctx->keyCtx->format != SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return SCOSSL_FAILURE;   
    }

    if (keyCtx->groupInfo->classicGroupName != NULL &&
        p_scossl_mlkem_classic_keyexch_init(ctx, ctx->keyCtx->classicKeyCtx) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// Performs ML-KEM decapsulation using the previously initialized context. If
// this is a hybrid group, then hybrid decapsulation is performed.
// ctx->keyCtx->classicKeyCtx is used as our key, and the peer key is
// extracted from the beginning of 'in'. The concatenated
// order of classic and ML-KEM data depends on the classic group.
//
// - out
//      X25519:         MLKEM shared secret || ECDH shared secret
//      P-256/P-384:    ECDH shared secret || MLKEM shared secret
static SCOSSL_STATUS p_scossl_mlkem_decapsulate(_In_ SCOSSL_MLKEM_CTX *ctx,
                                                _Out_writes_bytes_opt_(*outlen) unsigned char *out, _Out_ size_t *outlen,
                                                _In_reads_bytes_(inlen) const unsigned char *in, size_t inlen)
{
    PCBYTE pbMlkemCipherText = NULL;
    PCBYTE pbClassicKey = NULL;
    PBYTE pbMlkemSecret = NULL;
    PBYTE pbClassicSecret = NULL;
    SIZE_T cbClassicKey = 0;
    SIZE_T cbMlkemCiphertext = 0;
    SIZE_T cbClassicSecret = 0;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPeer = NULL;
    SCOSSL_ECC_KEY_CTX *classicKeyCtxPrivate = NULL;
    const SCOSSL_MLKEM_GROUP_INFO *groupInfo;
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

    groupInfo = ctx->keyCtx->groupInfo;

    if (groupInfo->classicGroupName != NULL)
    {
        if ((classicKeyCtxPrivate = ctx->keyCtx->classicKeyCtx) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        cbClassicKey = p_scossl_ecc_get_encoded_key_size(classicKeyCtxPrivate, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);

        if ((cbClassicSecret = p_scossl_ecc_get_max_result_size(classicKeyCtxPrivate, TRUE)) == 0)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "p_scossl_ecc_get_max_result_size failed");
            goto cleanup;
        }
    }

    scError = SymCryptMlKemSizeofCiphertextFromParams(groupInfo->mlkemParams, &cbMlkemCiphertext);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemSizeofCiphertextFromParams failed", scError);
        goto cleanup;
    }

    if (out != NULL)
    {
        if (inlen != cbMlkemCiphertext + cbClassicKey)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
            goto cleanup;
        }

        if (outlen == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            goto cleanup;
        }

        if (*outlen < SCOSSL_MLKEM_SECRET_LENGTH + cbClassicSecret)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            goto cleanup;
        }

        if (groupInfo->classicGroupName != NULL)
        {
            if (classicKeyCtxPrivate->isX25519)
            {
                pbMlkemCipherText = in;
                pbClassicKey = in + cbMlkemCiphertext;
                pbMlkemSecret = out;
                pbClassicSecret = out + SCOSSL_MLKEM_SECRET_LENGTH;
            }
            else
            {
                pbClassicKey = in;
                pbMlkemCipherText = in + cbClassicKey;
                pbClassicSecret = out;
                pbMlkemSecret = out + cbClassicSecret;
            }

            // Extract ECDH public key from in
            if ((classicKeyCtxPeer = p_scossl_ecc_new_ctx(ctx->provCtx)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (p_scossl_ecc_set_group(classicKeyCtxPeer, groupInfo->classicGroupName) != SCOSSL_SUCCESS ||
                p_scossl_ecc_set_encoded_key(classicKeyCtxPeer, pbClassicKey, cbClassicKey, NULL, 0) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }

            // Derive shared ECDH secret
            if (p_scossl_ecdh_set_peer(ctx->classicKeyexchCtx, classicKeyCtxPeer) != SCOSSL_SUCCESS ||
                p_scossl_ecdh_derive(ctx->classicKeyexchCtx, pbClassicSecret, &cbClassicSecret, cbClassicSecret) != SCOSSL_SUCCESS)
            {
                goto cleanup;
            }
        }
        else
        {
            pbMlkemCipherText = in;
            pbMlkemSecret = out;
        }

        scError = SymCryptMlKemDecapsulate(ctx->keyCtx->key, pbMlkemCipherText, cbMlkemCiphertext, pbMlkemSecret, SCOSSL_MLKEM_SECRET_LENGTH);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptMlKemDecapsulate failed", scError);
            goto cleanup;
        }
    }
    else if (outlen == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto cleanup;
    }

    if (outlen != NULL)
    {
        *outlen = SCOSSL_MLKEM_SECRET_LENGTH + cbClassicSecret;
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

_Use_decl_annotations_
BOOL p_scossl_mlkem_is_hybrid(const SCOSSL_MLKEM_KEY_CTX *keyCtx)
{
    return keyCtx != NULL &&
           keyCtx->groupInfo != NULL &&
           keyCtx->groupInfo->classicGroupName != NULL;
}
    
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

#ifdef __cplusplus
}
#endif