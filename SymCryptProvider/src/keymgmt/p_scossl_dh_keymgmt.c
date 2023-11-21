//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "keyexch/p_scossl_dh.h"

#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    SCOSSL_PROVCTX *provCtx;
    PCSYMCRYPT_DLGROUP pDlGroup;
    SIZE_T pbits;
    UINT32 nBitsPriv;
    int selection;
} SCOSSL_DH_KEYGEN_CTX;

#define P_SCOSSL_DH_PBITS_DEFAULT 2048

#define P_SCOSSL_DH_FFC_TYPE_DEFAULT "default"
#define P_SCOSSL_DH_FFC_TYPE_GROUP   "group"

// Constant values for parameters not used but may
// be expected by caller
#define P_SCOSSL_DH_GINDEX -1
#define P_SCOSSL_DH_PCOUNTER -1
#define P_SCOSSL_DH_H 0

#define P_SCOSSL_DH_PARAMETER_TYPES                                    \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),                 \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                     \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),        \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, NULL, 0),       \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, NULL, 0), \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0)

#define P_SCOSSL_DH_PKEY_PARAMETER_TYPES             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

// Keygen param types
static const OSSL_PARAM p_scossl_dh_keygen_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_END};

// Import/export types
static const OSSL_PARAM p_scossl_dh_param_types[] = {
    P_SCOSSL_DH_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_pkey_types[] = {
    P_SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_all_types[] = {
    P_SCOSSL_DH_PARAMETER_TYPES,
    P_SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM *p_scossl_dh_impexp_types[] = {
    NULL,
    p_scossl_dh_param_types,
    p_scossl_dh_pkey_types,
    p_scossl_dh_all_types};

// Gettable/settable key types

static const OSSL_PARAM p_scossl_dh_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    P_SCOSSL_DH_PARAMETER_TYPES,
    P_SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx)
{
    SCOSSL_PROV_DH_KEY_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_DH_KEY_CTX));
    if (ctx != NULL)
    {
        if ((ctx->keyCtx = scossl_dh_new_key_ctx()) == NULL)
        {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
        else
        {
            ctx->pDlGroup = NULL;
            ctx->libCtx = provCtx->libctx;
        }
    }

    return ctx;
}

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keymgmt_dup_key_ctx(_In_ const SCOSSL_PROV_DH_KEY_CTX *ctx, ossl_unused int selection)
{
    SCOSSL_PROV_DH_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_DH_KEY_CTX));

    if (copyCtx != NULL)
    {
        if ((copyCtx->keyCtx = scossl_dh_dup_key_ctx(ctx->keyCtx, ctx->pDlGroup != NULL)) == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }

        if (copyCtx->keyCtx->initialized)
        {
            copyCtx->pDlGroup = (PSYMCRYPT_DLGROUP) (ctx->keyCtx->dlkey);
        }
        copyCtx->libCtx = ctx->libCtx;
    }

    return copyCtx;
}

static void p_scossl_dh_keymgmt_free_key_ctx(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    scossl_dh_free_key_ctx(ctx->keyCtx);

    if (ctx->pDlGroup != NULL)
    {
        SymCryptDlgroupFree(ctx->pDlGroup);
    }
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_dh_keygen_set_params(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    // SymCrypt provider only supports named groups. We don't set anything here,
    // instead notifying the caller that the operation is unsupported.
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE)) != NULL)
    {
        const char *ffcTypeName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &ffcTypeName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (OPENSSL_strcasecmp(ffcTypeName, P_SCOSSL_DH_FFC_TYPE_DEFAULT) != 0 &&
            OPENSSL_strcasecmp(ffcTypeName, P_SCOSSL_DH_FFC_TYPE_GROUP) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *groupName;
        PCSYMCRYPT_DLGROUP pDlGroup;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &groupName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((pDlGroup = scossl_dh_get_group_by_nid(OBJ_sn2nid(groupName), NULL)) == NULL)
        {
            return SCOSSL_FAILURE;
        }

        genCtx->pDlGroup = pDlGroup;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &genCtx->pbits))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL)
    {
        int nBitsPriv;
        if (!OSSL_PARAM_get_int(p, &nBitsPriv))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // SymCryptDlkeySetPrivateKeyLength will validate this key size.
        // Here we just need to be sure we can safely cast to UINT32
        if (nBitsPriv < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return SCOSSL_FAILURE;
        }

        genCtx->nBitsPriv = (UINT32)nBitsPriv;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_dh_keygen_settable_params(ossl_unused void *genCtx, ossl_unused void *provCtx)
{
    return p_scossl_dh_keygen_param_types;
}

static void p_scossl_dh_keygen_cleanup(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx)
{
    if (genCtx == NULL)
        return;

    OPENSSL_free(genCtx);
}

static SCOSSL_DH_KEYGEN_CTX *p_scossl_dh_keygen_init(_In_ SCOSSL_PROVCTX *provCtx, int selection,
                                                     _In_ const OSSL_PARAM params[])
{
    SCOSSL_DH_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_KEYGEN_CTX));
    if (genCtx != NULL)
    {
        genCtx->pDlGroup = NULL;
        genCtx->nBitsPriv = 0;
        genCtx->pbits = P_SCOSSL_DH_PBITS_DEFAULT;
        genCtx->selection = selection;
        genCtx->provCtx = provCtx;

        if (!p_scossl_dh_keygen_set_params(genCtx, params))
        {
            OPENSSL_free(genCtx);
            genCtx = NULL;
        }
    }

    return genCtx;
}

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keygen(_In_ SCOSSL_DH_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_PROV_DH_KEY_CTX *ctx;
    BOOL generateKeyPair;

    // Select named group based on pbits if one was not supplied by
    // the caller
    if (genCtx->pDlGroup == NULL)
    {
        int dlGroupNid = 0;
        PCSYMCRYPT_DLGROUP pDlGroup = NULL;
        switch(genCtx->pbits)
        {
            case 2048:
                dlGroupNid = NID_ffdhe2048;
                break;
            case 3072:
                dlGroupNid = NID_ffdhe3072;
                break;
            case 4096:
                dlGroupNid = NID_ffdhe4096;
                break;
        }

        if ((pDlGroup = scossl_dh_get_group_by_nid(dlGroupNid, NULL)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);
            return NULL;
        }

        genCtx->pDlGroup = pDlGroup;
    }

    if ((ctx = p_scossl_dh_keymgmt_new_ctx(genCtx->provCtx)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    generateKeyPair = (genCtx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    if (!scossl_dh_create_key(ctx->keyCtx, genCtx->pDlGroup, genCtx->nBitsPriv, generateKeyPair))
    {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static const OSSL_PARAM *p_scossl_dh_keymgmt_gettable_params(ossl_unused void *provCtx)
{
    return p_scossl_dh_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_get_ffc_params(_In_ SCOSSL_DH_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE  pbCur;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrimeP;
    SIZE_T cbPrimeP;
    PBYTE  pbPrimeQ;
    SIZE_T cbPrimeQ;
    PBYTE  pbGenG;
    SIZE_T cbGenG;
    PBYTE  pbSeed;
    SIZE_T cbSeed;
    OSSL_PARAM *p;
    OSSL_PARAM *paramPrimeP;
    OSSL_PARAM *paramPrimeQ;
    OSSL_PARAM *paramGenG;
    OSSL_PARAM *paramSeed;
    BIGNUM *bnPrimeP = NULL;
    BIGNUM *bnPrimeQ = NULL;
    BIGNUM *bnGenG = NULL;

    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    SymCryptDlgroupGetSizes(
        keyCtx->dlkey->pDlgroup,
        &cbPrimeP,
        &cbPrimeQ,
        &cbGenG,
        &cbSeed);

    paramPrimeP = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_P);
    paramPrimeQ = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_Q);
    paramGenG = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_G);
    paramSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_SEED);

    cbPrimeP = paramPrimeP == NULL ? 0 : cbPrimeP;
    cbPrimeQ = paramPrimeQ == NULL ? 0 : cbPrimeQ;
    cbGenG = paramGenG == NULL ? 0 : cbGenG;
    cbSeed = paramSeed == NULL ? 0 : cbSeed;

    cbData =
        cbPrimeP +
        cbPrimeQ +
        cbGenG +
        cbSeed;

    if (cbData != 0)
    {
        if ((pbData = OPENSSL_malloc(cbData)) == NULL ||
            ((bnPrimeP = BN_new()) == NULL) ||
            ((bnPrimeQ = BN_new()) == NULL) ||
            ((bnGenG = BN_new()) == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbCur = pbData;

        pbPrimeP = cbPrimeP == 0 ? NULL : pbCur;
        pbCur += cbPrimeP;

        pbPrimeQ = cbPrimeQ == 0 ? NULL : pbCur;
        pbCur += cbPrimeQ;

        pbGenG = cbGenG == 0 ? NULL : pbCur;
        pbCur += cbGenG;

        pbSeed = cbSeed == 0 ? NULL : pbCur;
        pbCur += cbSeed;

        if (SymCryptDlgroupGetValue(
                keyCtx->dlkey->pDlgroup,
                pbPrimeP, cbPrimeP,
                pbPrimeQ, cbPrimeQ,
                pbGenG, cbGenG,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                NULL,
                pbSeed, cbSeed,
                NULL) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (pbPrimeP != NULL &&
            (BN_bin2bn(pbPrimeP, cbPrimeP, bnPrimeP) == NULL ||
                !OSSL_PARAM_set_BN(paramPrimeP, bnPrimeP)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if (pbPrimeQ != NULL &&
            (BN_bin2bn(pbPrimeQ, cbPrimeQ, bnPrimeQ) == NULL ||
                !OSSL_PARAM_set_BN(paramPrimeQ, bnPrimeQ)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if (pbGenG != NULL &&
            (BN_bin2bn(pbGenG, cbGenG, bnGenG) == NULL ||
                !OSSL_PARAM_set_BN(paramGenG, bnGenG)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }

        if (pbSeed != NULL &&
            !OSSL_PARAM_set_octet_string(paramSeed, pbSeed, cbSeed))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_GINDEX)) != NULL &&
        !OSSL_PARAM_set_int(p, P_SCOSSL_DH_GINDEX))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_PCOUNTER)) != NULL &&
        !OSSL_PARAM_set_int(p, P_SCOSSL_DH_PCOUNTER))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_H)) != NULL &&
        !OSSL_PARAM_set_int(p, P_SCOSSL_DH_H))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    BN_free(bnPrimeP);
    BN_free(bnPrimeQ);
    BN_free(bnGenG);

    return ret;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_get_key_params(_In_ SCOSSL_DH_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    PBYTE  pbData;
    SIZE_T cbData;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    BIGNUM *bnPrivKey = NULL;
    BIGNUM *bnPubKey = NULL;
    OSSL_PARAM *paramEncodedKey;
    OSSL_PARAM *paramPrivKey;
    OSSL_PARAM *paramPubKey;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);

    if (paramPrivKey != NULL)
    {
        cbPrivateKey = SymCryptDlkeySizeofPrivateKey(keyCtx->dlkey);
    }

    if (paramEncodedKey != NULL ||
        paramPubKey != NULL)
    {
        cbPublicKey = SymCryptDlkeySizeofPublicKey(keyCtx->dlkey);
    }

    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if (pbData == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    pbPrivateKey = cbPrivateKey == 0 ? NULL : pbData;
    pbPublicKey = cbPublicKey == 0 ? NULL : pbData + cbPrivateKey;

    if (SymCryptDlkeyGetValue(
            keyCtx->dlkey,
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0) != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (paramEncodedKey != NULL &&
        !OSSL_PARAM_set_octet_string(paramEncodedKey, pbPublicKey, cbPublicKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if (paramPrivKey != NULL)
    {
        if ((bnPrivKey = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if ((BN_bin2bn(pbPrivateKey, cbPrivateKey, bnPrivKey)) == NULL ||
            !OSSL_PARAM_set_BN(paramPrivKey, bnPrivKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPubKey != NULL)
    {
        if ((bnPubKey = BN_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if ((BN_bin2bn(pbPublicKey, cbPublicKey, bnPubKey)) == NULL ||
            !OSSL_PARAM_set_BN(paramPubKey, bnPubKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    BN_clear_free(bnPrivKey);
    BN_free(bnPubKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_get_params(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, _Inout_ OSSL_PARAM params[])
{

    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptDlkeySizeofPublicKey(ctx->keyCtx->dlkey) * 8))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL)
    {
        int pubKeyBits = SymCryptDlkeySizeofPublicKey(ctx->keyCtx->dlkey) * 8;
        int privKeyBits = SymCryptDlkeySizeofPrivateKey(ctx->keyCtx->dlkey) * 8;

        if (!OSSL_PARAM_set_int(p, BN_security_bits(pubKeyBits, privKeyBits)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptDlkeySizeofPublicKey(ctx->keyCtx->dlkey)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL &&
        !OSSL_PARAM_set_int(p, SymCryptDlkeySizeofPrivateKey(ctx->keyCtx->dlkey) * 8))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        int dlGroupNid = scossl_dh_get_group_nid(ctx->keyCtx->dlkey->pDlgroup);
        if (dlGroupNid == 0)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_utf8_string(p, OBJ_nid2sn(dlGroupNid)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return p_scossl_dh_keymgmt_get_ffc_params(ctx->keyCtx, params) &&
           p_scossl_dh_keymgmt_get_key_params(ctx->keyCtx, params);
}


static BOOL p_scossl_dh_keymgmt_has(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, int selection)
{
    BOOL ret = TRUE;

    if (ctx->keyCtx->dlkey == NULL)
    {
        return FALSE;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        ret = ret && (ctx->keyCtx->dlkey->pDlgroup != NULL);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        ret = ret && ctx->keyCtx->initialized;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        ret = ret && SymCryptDlkeyHasPrivateKey(ctx->keyCtx->dlkey);
    }

    return ret;
}

static BOOL p_scossl_dh_keymgmt_match(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx1, _In_ SCOSSL_PROV_DH_KEY_CTX *ctx2,
                                       int selection)
{
    BOOL ret = FALSE;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey1 = NULL;
    PBYTE  pbPrivateKey2 = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey1 = NULL;
    PBYTE  pbPublicKey2 = NULL;
    SIZE_T cbPublicKey = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            cbPrivateKey = SymCryptDlkeySizeofPrivateKey(ctx1->keyCtx->dlkey);
            if (SymCryptDlkeySizeofPrivateKey(ctx2->keyCtx->dlkey) != cbPrivateKey)
            {
                goto cleanup;
            }
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            cbPublicKey = SymCryptDlkeySizeofPublicKey(ctx1->keyCtx->dlkey);
            if (SymCryptDlkeySizeofPublicKey(ctx2->keyCtx->dlkey) != cbPublicKey)
            {
                goto cleanup;
            }
        }

        cbData = cbPrivateKey * 2 + cbPublicKey * 2;
        if ((pbData = OPENSSL_zalloc(cbData)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbPrivateKey1 = cbPrivateKey == 0 ? NULL : pbData;
        pbPrivateKey2 = cbPrivateKey == 0 ? NULL : pbData + cbPrivateKey;

        pbPublicKey1 = cbPublicKey == 0 ? NULL : pbData + cbPrivateKey * 2;
        pbPublicKey2 = cbPublicKey == 0 ? NULL : pbData + cbPrivateKey * 2 + cbPublicKey;

        if (SymCryptDlkeyGetValue(
                ctx1->keyCtx->dlkey,
                pbPrivateKey1, cbPrivateKey,
                pbPublicKey1, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0) != SYMCRYPT_NO_ERROR ||
            SymCryptDlkeyGetValue(
                ctx2->keyCtx->dlkey,
                pbPrivateKey2, cbPrivateKey,
                pbPublicKey2, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (memcmp(pbPrivateKey1, pbPrivateKey2, cbPrivateKey) != 0 ||
            memcmp(pbPublicKey1, pbPublicKey2, cbPublicKey) != 0)
        {
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        BOOL isGroup1Set = ctx1->keyCtx->dlkey != NULL && ctx1->keyCtx->dlkey->pDlgroup != NULL;
        BOOL isGroup2Set = ctx2->keyCtx->dlkey != NULL && ctx2->keyCtx->dlkey->pDlgroup != NULL;

        // Both groups must be either NULL or equal
        if (isGroup1Set != isGroup2Set ||
            (isGroup1Set && isGroup2Set &&
             !SymCryptDlgroupIsSame(ctx1->keyCtx->dlkey->pDlgroup, ctx2->keyCtx->dlkey->pDlgroup)))
        {
            goto cleanup;
        }
    }

    ret = TRUE;

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return ret;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_dh_keymgmt_impexp_types(int selection)
{
    int idx = 0;
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
    {
        idx += 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        idx += 2;
    }

    return p_scossl_dh_impexp_types[idx];
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_import(_Inout_ SCOSSL_PROV_DH_KEY_CTX *ctx, int selection, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const OSSL_PARAM *paramP;
    const OSSL_PARAM *paramQ;
    const OSSL_PARAM *paramG;
    BIGNUM *bnP = NULL;
    BIGNUM *bnQ = NULL;
    BIGNUM *bnG = NULL;
    PBYTE pbPrimeP = NULL;
    PBYTE pbPrimeQ = NULL;
    PBYTE pbGenG = NULL;
    SIZE_T cbPrimeP = 0;
    SIZE_T cbPrimeQ = 0;
    SIZE_T cbGenG = 0;
    const char *groupName;
    BOOL groupSetByParams = FALSE;
    PSYMCRYPT_DLGROUP pDlGroup = NULL;
    BIGNUM *bnPrivateKey = NULL;
    BIGNUM *bnPublicKey = NULL;
    int nBitsPriv = 0;
    SYMCRYPT_ERROR scError =  SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Group required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &groupName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((pDlGroup = (PSYMCRYPT_DLGROUP)scossl_dh_get_group_by_nid(OBJ_sn2nid(groupName), NULL)) == NULL)
        {
            goto cleanup;
        }
    }
    else
    {
        PCSYMCRYPT_DLGROUP pKnownDlGroup = NULL;
        PCSYMCRYPT_HASH pHashAlgorithm = NULL;
        PBYTE pbSeed = NULL;
        SIZE_T cbSeed = 0;
        int genCounter = 0;

        groupSetByParams = TRUE;
        // P and either Q or G are required for import
        paramP = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
        paramQ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
        paramG = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

        if (paramP == NULL || (paramQ == NULL && paramG == NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto cleanup;
        }

        if (!OSSL_PARAM_get_BN(paramP, &bnP) ||
            (paramQ != NULL && !OSSL_PARAM_get_BN(paramQ, &bnQ)) ||
            (paramG != NULL && !OSSL_PARAM_get_BN(paramG, &bnG)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        cbPrimeP = BN_num_bytes(bnP);
        cbPrimeQ = bnQ != NULL ? BN_num_bytes(bnQ) : 0;
        cbGenG = bnG != NULL ? BN_num_bytes(bnG) : 0;

        if ((pbPrimeP = OPENSSL_malloc(cbPrimeP)) == NULL ||
            (bnQ != NULL && (pbPrimeQ = OPENSSL_malloc(cbPrimeQ)) == NULL) ||
            (bnG != NULL && (pbGenG = OPENSSL_malloc(cbGenG)) == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!BN_bn2bin(bnP, pbPrimeP) ||
            (bnQ != NULL && !BN_bn2bin(bnQ, pbPrimeQ)) ||
            (bnG != NULL && !BN_bn2bin(bnG, pbGenG)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((pDlGroup = SymCryptDlgroupAllocate(BN_num_bits(bnP), bnQ == NULL ? 0 : BN_num_bits(bnQ))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED)) != NULL)
        {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbSeed, &cbSeed))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST)) != NULL)
        {
            EVP_MD *md;
            const char *mdName;
            const char *mdProps = NULL;

            if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            mdProps = NULL;
            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS)) != NULL &&
                !OSSL_PARAM_get_utf8_string_ptr(p, &mdProps))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }

            md = EVP_MD_fetch(ctx->libCtx, mdName, mdProps);
            if (md != NULL)
            {
                pHashAlgorithm  = scossl_get_symcrypt_hash_algorithm(EVP_MD_type(md));
            }

            EVP_MD_free(md);

            if (pHashAlgorithm == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER)) != NULL &&
            !OSSL_PARAM_get_int(p, &genCounter))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        scError = SymCryptDlgroupSetValue(
            pbPrimeP, cbPrimeP,
            pbPrimeQ, cbPrimeQ,
            pbGenG, cbGenG,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pHashAlgorithm,
            pbSeed, cbSeed,
            genCounter,
            SYMCRYPT_DLGROUP_FIPS_NONE,
            pDlGroup);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        // Check whether this is actually a known group set by params.
        if ((pKnownDlGroup = scossl_dh_get_known_group(pDlGroup)) != NULL)
        {
            SymCryptDlgroupFree(pDlGroup);
            pDlGroup = (PSYMCRYPT_DLGROUP)pKnownDlGroup;
            groupSetByParams = FALSE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL)
    {
        if (!OSSL_PARAM_get_int(p, &nBitsPriv))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        // SymCryptDlkeySetPrivateKeyLength will validate this key size.
        // Here we just need to be sure we can safely cast to UINT32
        if (nBitsPriv < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        if ((bnPrivateKey = BN_secure_new()) == NULL ||
            !OSSL_PARAM_get_BN(p, &bnPrivateKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto cleanup;
        }

        if ((bnPublicKey = BN_new()) == NULL ||
            !OSSL_PARAM_get_BN(p, &bnPublicKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    if (!scossl_dh_import_keypair(ctx->keyCtx, nBitsPriv, pDlGroup, groupSetByParams, bnPrivateKey, bnPublicKey))
    {
        goto cleanup;
    }

    if (groupSetByParams)
    {
        ctx->pDlGroup = pDlGroup;
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    OPENSSL_free(pbPrimeP);
    OPENSSL_free(pbPrimeQ);
    OPENSSL_free(pbGenG);
    BN_free(bnP);
    BN_free(bnQ);
    BN_free(bnG);

    if (!ret)
    {
        if (ctx->keyCtx->dlkey != NULL)
        {
            SymCryptDlkeyFree(ctx->keyCtx->dlkey);
            ctx->keyCtx->dlkey = NULL;
            ctx->keyCtx->initialized = FALSE;
        }

        if (groupSetByParams &&
            pDlGroup != NULL)
        {
            SymCryptDlgroupFree(pDlGroup);
            ctx->pDlGroup = NULL;
        }

        BN_clear_free(bnPrivateKey);
        BN_free(bnPublicKey);
    }

    return ret;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_export(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, int selection,
                                                _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BOOL includePublic = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    BOOL includePrivate = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int dlGroupNid;
    const char *dlGroup;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;

    PBYTE  pbPrivateKey;
    PBYTE  pbPublicKey;
    SIZE_T cbPrivateKey;
    SIZE_T cbPublicKey;
    BIGNUM *bnPrivKey = NULL;
    BIGNUM *bnPubKey = NULL;

    BIGNUM *bnP = NULL;
    BIGNUM *bnQ = NULL;
    BIGNUM *bnG = NULL;
    PBYTE pbPrimeP = NULL;
    PBYTE pbPrimeQ = NULL;
    PBYTE pbGenG = NULL;
    PBYTE pbSeed = NULL;
    SIZE_T cbPrimeP = 0;
    SIZE_T cbPrimeQ = 0;
    SIZE_T cbGenG = 0;
    SIZE_T cbSeed = 0;
    PCSYMCRYPT_HASH pHashAlgorithm;
    int mdnid;
    UINT32 genCounter;

    SYMCRYPT_ERROR scError =  SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->keyCtx == NULL ||
        ctx->keyCtx->dlkey == NULL ||
        ctx->keyCtx->dlkey->pDlgroup == NULL ||
        (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0 ||
        ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && !ctx->keyCtx->initialized))
    {
        return SCOSSL_FAILURE;
    }

    if ((bld = OSSL_PARAM_BLD_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    SymCryptDlgroupGetSizes(
        ctx->keyCtx->dlkey->pDlgroup,
        &cbPrimeP,
        &cbPrimeQ,
        &cbGenG,
        &cbSeed);

    if ((pbPrimeP = OPENSSL_malloc(cbPrimeP)) == NULL ||
        (cbPrimeQ != 0 && (pbPrimeQ = OPENSSL_malloc(cbPrimeQ)) == NULL) ||
        (cbGenG != 0 && (pbGenG = OPENSSL_malloc(cbGenG)) == NULL) ||
        (cbSeed != 0 && (pbSeed = OPENSSL_malloc(cbSeed)) == NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // Always export group parameters
    scError = SymCryptDlgroupGetValue(
        ctx->keyCtx->dlkey->pDlgroup,
        pbPrimeP, cbPrimeP,
        pbPrimeQ, cbPrimeQ,
        pbGenG, cbGenG,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &pHashAlgorithm,
        pbSeed, cbSeed,
        &genCounter);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if ((bnP = BN_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (BN_lebin2bn(pbPrimeP, cbPrimeP, bnP) == NULL ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bnP))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if (pbPrimeQ != NULL)
    {
        if ((bnQ = BN_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (BN_lebin2bn(pbPrimeQ, cbPrimeQ, bnQ) == NULL ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bnQ))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (pbGenG != NULL)
    {
        if ((bnG = BN_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (BN_lebin2bn(pbGenG, cbGenG, bnG) == NULL ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bnG))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (pbSeed != NULL &&
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_FFC_SEED, pbSeed, cbSeed))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((mdnid = scossl_get_mdnid_from_symcrypt_hash_algorithm(pHashAlgorithm)) != NID_undef)
    {
        const char *mdName = OBJ_nid2sn(mdnid);

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_FFC_DIGEST, mdName, strlen(mdName)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    // Group name may not be available if the group was imported by params
    if ((dlGroupNid = scossl_dh_get_group_nid(ctx->keyCtx->dlkey->pDlgroup)) != 0)
    {
        if ((dlGroup = OBJ_nid2sn(dlGroupNid)) == NULL ||
            !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, dlGroup, strlen(dlGroup)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        cbPrivateKey = includePrivate ? SymCryptDlkeySizeofPrivateKey(ctx->keyCtx->dlkey) : 0;
        cbPublicKey = includePublic ? SymCryptDlkeySizeofPublicKey(ctx->keyCtx->dlkey) : 0;

        cbData = cbPrivateKey + cbPublicKey;
        if ((pbData = OPENSSL_zalloc(cbData)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbPrivateKey = includePrivate ? pbData : NULL;
        pbPublicKey = includePublic ? pbData + cbPrivateKey : NULL;

        if (SymCryptDlkeyGetValue(
                ctx->keyCtx->dlkey,
                pbPrivateKey, cbPrivateKey,
                pbPublicKey, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (includePrivate)
        {
            if ((bnPrivKey = BN_secure_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (BN_bin2bn(pbPrivateKey, cbPrivateKey, bnPrivKey) == NULL ||
                OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bnPrivKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }

        if (includePublic)
        {
            if ((bnPubKey = BN_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (BN_bin2bn(pbPublicKey, cbPublicKey, bnPubKey) == NULL ||
                OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bnPubKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }
    }

    if (!OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, SymCryptDlkeySizeofPrivateKey(ctx->keyCtx->dlkey) * 8) ||
        (params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    ret = param_cb(params, cbarg);

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    OPENSSL_free(pbPrimeP);
    OPENSSL_free(pbPrimeQ);
    OPENSSL_free(pbGenG);
    OPENSSL_free(pbSeed);

    BN_free(bnP);
    BN_free(bnQ);
    BN_free(bnG);

    BN_clear_free(bnPrivKey);
    BN_free(bnPubKey);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static const char *p_scossl_dh_keymgmt_query_operation_name(ossl_unused int operation_id)
{
    return "DH";
}

const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_dh_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_dh_keymgmt_dup_key_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_dh_keymgmt_free_key_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_dh_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_dh_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_dh_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_dh_keygen},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_dh_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_dh_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_dh_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_dh_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))p_scossl_dh_keymgmt_query_operation_name},
    {0, NULL}};

#ifdef __cplusplus
}
#endif