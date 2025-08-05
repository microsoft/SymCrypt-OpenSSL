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

#define SCOSSL_DH_KEYGEN_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

#define SCOSSL_DH_PBITS_DEFAULT 2048
// Private key length determined by group
// Setting this to -1 matches the OpenSSL implementation for paramater fetching
#define SCOSSL_DH_PRIVATE_BITS_DEFAULT -1

#define SCOSSL_DH_FFC_TYPE_DEFAULT "default"
#define SCOSSL_DH_FFC_TYPE_GROUP   "group"

// Constant values for unused parameters that may be requested by caller
#define SCOSSL_DH_GINDEX -1
#define SCOSSL_DH_PCOUNTER -1
#define SCOSSL_DH_H 0

typedef struct
{
    SCOSSL_PROVCTX *provCtx;
    PCSYMCRYPT_DLGROUP pDlGroup;
    SIZE_T nBitsPub;
    int nBitsPriv;
} SCOSSL_DH_KEYGEN_CTX;

#define SCOSSL_DH_PARAMETER_TYPES                                      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),                 \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                     \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),        \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, NULL, 0),       \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, NULL, 0), \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0)

#define SCOSSL_DH_PKEY_PARAMETER_TYPES             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

// Keygen param types
static const OSSL_PARAM p_scossl_dh_keygen_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_size_t("dh_paramgen_prime_len", NULL),
    OSSL_PARAM_size_t("dh_paramgen_subprime_len", NULL),
    OSSL_PARAM_uint("dh_paramgen_generator", NULL),
    OSSL_PARAM_END};

// Import/export types
static const OSSL_PARAM p_scossl_dh_param_types[] = {
    SCOSSL_DH_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_pkey_types[] = {
    SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_all_types[] = {
    SCOSSL_DH_PARAMETER_TYPES,
    SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static const OSSL_PARAM *p_scossl_dh_impexp_types[] = {
    NULL,
    p_scossl_dh_param_types,
    p_scossl_dh_pkey_types,
    p_scossl_dh_all_types};

static const OSSL_PARAM p_scossl_dh_keymgmt_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_dh_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    SCOSSL_DH_PARAMETER_TYPES,
    SCOSSL_DH_PKEY_PARAMETER_TYPES,
    OSSL_PARAM_END};

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provCtx)
{
    SCOSSL_PROV_DH_KEY_CTX *ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_DH_KEY_CTX));
    if (ctx != NULL)
    {
        if ((ctx->keyCtx = scossl_dh_new_key_ctx()) == NULL)
        {
            OPENSSL_free(ctx);
            return NULL;
        }

        ctx->pDlGroup = NULL;
        ctx->groupSetByParams = FALSE;
        ctx->nBitsPriv = SCOSSL_DH_PRIVATE_BITS_DEFAULT;
        ctx->libCtx = provCtx->libctx;
    }

    return ctx;
}

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keymgmt_dup_key_ctx(_In_ const SCOSSL_PROV_DH_KEY_CTX *ctx, ossl_unused int selection)
{
    SCOSSL_PROV_DH_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_PROV_DH_KEY_CTX));

    if (copyCtx != NULL)
    {
        *copyCtx = *ctx;

        if ((copyCtx->keyCtx = scossl_dh_dup_key_ctx(ctx->keyCtx, ctx->groupSetByParams)) == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }

        // Group set by params means we need to copy the group, regardless of whether the
        // key has been set
        if (ctx->groupSetByParams)
        {
            // scossl_dh_dup_key_ctx performs a deep copy. If a custom group was set in ctx,
            // then a new copy of that group is used by the key in copyCtx. We need to save this
            // to copyCtx to ensure it properly gets freed.
            if (copyCtx->keyCtx->initialized)
            {
                copyCtx->pDlGroup = (PSYMCRYPT_DLGROUP) SymCryptDlkeyGetGroup(copyCtx->keyCtx->dlkey);
            }
            // No key was set, but we still need to copy the group from ctx
            else
            {
                SIZE_T pcbPrimeP;
                SIZE_T pcbPrimeQ;

                SymCryptDlgroupGetSizes(
                    ctx->pDlGroup,
                    &pcbPrimeP,
                    &pcbPrimeQ,
                    NULL,
                    NULL);

                if ((copyCtx->pDlGroup = SymCryptDlgroupAllocate(pcbPrimeP, pcbPrimeQ)) == NULL)
                {
                    OPENSSL_free(copyCtx);
                    return NULL;
                }

                SymCryptDlgroupCopy(ctx->pDlGroup, copyCtx->pDlGroup);
            }
        }
    }

    return copyCtx;
}

static void p_scossl_dh_keymgmt_free_key_ctx(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    scossl_dh_free_key_ctx(ctx->keyCtx);

    if (ctx->groupSetByParams)
    {
        SymCryptDlgroupFree(ctx->pDlGroup);
    }

    OPENSSL_free(ctx);
}

// Helper functions for retrieving public and private key size.
// ctx->keyCtx->dlkey may not be set, in which case the key size
// must be retrieved from ctx->pDlGroup
static int p_scossl_dh_pubkey_bits(SCOSSL_PROV_DH_KEY_CTX *ctx)
{
    if (ctx->pDlGroup != NULL)
    {
        SIZE_T cbPrimeP;

        SymCryptDlgroupGetSizes(
            ctx->pDlGroup,
            &cbPrimeP,
            NULL,
            NULL,
            NULL);

        return cbPrimeP * 8;
    }

    return -1;
}

static int p_scossl_dh_privkey_bits(SCOSSL_PROV_DH_KEY_CTX *ctx)
{
    if (ctx->nBitsPriv > 0)
    {
        return ctx->nBitsPriv;
    }

    // Default max size is bits of P - 1
    return p_scossl_dh_pubkey_bits(ctx) - 1;
}

// This function attempts to create a PSYMCRYPT_DLGROUP from params, and store the result in *ppDlGroup.
// If the group name is present, it will be the only thing used to fetch a known group. If the group is named
// but unknown, this will fail. If no group name is supplied, then the group parameters are used to create
// a new group and *pGroupSetByParams will be TRUE on success. If *pGroupSetByParams is TRUE, then the caller
// is responsible for freeing the group.
static SCOSSL_STATUS p_scossl_dh_params_to_group(_In_ OSSL_LIB_CTX *libCtx, _In_ const OSSL_PARAM params[],
                                                 _Out_ PSYMCRYPT_DLGROUP *ppDlGroup, _Out_ BOOL *pGroupSetByParams)
{
    const OSSL_PARAM *p;
    BIGNUM *bnP = NULL;
    BIGNUM *bnQ = NULL;
    BIGNUM *bnG = NULL;
    PBYTE pbData = NULL;
    SIZE_T cbData = 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError =  SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlGroupTmp = NULL;

    *pGroupSetByParams = FALSE;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        const char *groupName;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &groupName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // Provider does not support fallback, so fail in case of SCOSSL_FALLBACK too.
        if (scossl_dh_get_group_by_nid(OBJ_sn2nid(groupName), NULL, (PCSYMCRYPT_DLGROUP *)&pDlGroupTmp) != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }
    else if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P)) != NULL)
    {
        const OSSL_PARAM *paramQ;
        const OSSL_PARAM *paramG;
        PBYTE pbPrimeP;
        PBYTE pbPrimeQ;
        PBYTE pbGenG;
        PBYTE pbSeed = NULL;
        SIZE_T cbPrimeP;
        SIZE_T cbPrimeQ;
        SIZE_T cbGenG;
        SIZE_T cbSeed = 0;
        int genCounter = 0;
        PCSYMCRYPT_DLGROUP pKnownDlGroup;
        PCSYMCRYPT_HASH pHashAlgorithm = NULL;

        // Q or G are required for import
        paramQ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
        paramG = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

        if (paramQ == NULL && paramG == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto cleanup;
        }

        if (!OSSL_PARAM_get_BN(p, &bnP) ||
            (paramQ != NULL && !OSSL_PARAM_get_BN(paramQ, &bnQ)) ||
            (paramG != NULL && !OSSL_PARAM_get_BN(paramG, &bnG)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        cbPrimeP = BN_num_bytes(bnP);
        cbPrimeQ = bnQ == NULL ? 0 : BN_num_bytes(bnQ);
        cbGenG = bnG == NULL ? 0 : BN_num_bytes(bnG);
        cbData = cbPrimeP + cbPrimeQ + cbGenG;

        if ((pbData = OPENSSL_malloc(cbData)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbPrimeP = pbData;
        pbPrimeQ = bnQ == NULL ? NULL : pbData + cbPrimeP;
        pbGenG = bnG == NULL ? NULL : pbData + cbPrimeP + cbPrimeQ;

        if (!BN_bn2bin(bnP, pbPrimeP) ||
            (bnQ != NULL && !BN_bn2bin(bnQ, pbPrimeQ)) ||
            (bnG != NULL && !BN_bn2bin(bnG, pbGenG)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((pDlGroupTmp = SymCryptDlgroupAllocate(cbPrimeP * 8, cbPrimeQ * 8)) == NULL)
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

            if ((md = EVP_MD_fetch(libCtx, mdName, mdProps)) != NULL)
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
            pDlGroupTmp);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlgroupSetValue failed", scError);
            goto cleanup;
        }

        // Check whether this is actually a known group set by params.
        if ((pKnownDlGroup = scossl_dh_get_known_group(pDlGroupTmp)) != NULL)
        {
            SymCryptDlgroupFree(pDlGroupTmp);
            pDlGroupTmp = (PSYMCRYPT_DLGROUP)pKnownDlGroup;
        }
        else
        {
            *pGroupSetByParams = TRUE;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbData);
    BN_free(bnP);
    BN_free(bnQ);
    BN_free(bnG);

    if (!ret && pDlGroupTmp != NULL)
    {
        SymCryptDlgroupFree(pDlGroupTmp);
        pDlGroupTmp = NULL;
    }

    *ppDlGroup = pDlGroupTmp;

    return ret;
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_dh_keygen_set_params(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    PSYMCRYPT_DLGROUP pDlGroup;
    BOOL groupSetByParams;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE)) != NULL)
    {
        const char *ffcTypeName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &ffcTypeName))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (OPENSSL_strcasecmp(ffcTypeName, SCOSSL_DH_FFC_TYPE_DEFAULT) != 0 &&
            OPENSSL_strcasecmp(ffcTypeName, SCOSSL_DH_FFC_TYPE_GROUP) != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL &&
        !OSSL_PARAM_get_size_t(p, &genCtx->nBitsPub))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL &&
        !OSSL_PARAM_get_int(p, &genCtx->nBitsPriv))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    // We advertize only supporting named groups for keygen, but callers may still try to
    // import the group by parameters. This should only be done with the DHX key type,
    // which we defer to the default openssl implementation.
    if (!p_scossl_dh_params_to_group(genCtx->provCtx->libctx,
                                     params,
                                     &pDlGroup,
                                     &groupSetByParams))
    {
        return SCOSSL_FAILURE;
    }

    if (groupSetByParams)
    {
        SymCryptDlgroupFree(pDlGroup);
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return SCOSSL_FAILURE;
    }

    if (pDlGroup != NULL)
    {
        genCtx->pDlGroup = (PCSYMCRYPT_DLGROUP) pDlGroup;
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
    SCOSSL_DH_KEYGEN_CTX *genCtx = NULL;

    if ((selection & SCOSSL_DH_KEYGEN_POSSIBLE_SELECTIONS) != 0 &&
        (genCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_KEYGEN_CTX))) != NULL)
    {
        genCtx->pDlGroup = NULL;
        genCtx->nBitsPub = SCOSSL_DH_PBITS_DEFAULT;
        genCtx->nBitsPriv = SCOSSL_DH_PRIVATE_BITS_DEFAULT;
        genCtx->provCtx = provCtx;

        if (!p_scossl_dh_keygen_set_params(genCtx, params))
        {
            OPENSSL_free(genCtx);
            genCtx = NULL;
        }
    }

    return genCtx;
}

static SCOSSL_STATUS p_scossl_dh_keygen_set_template(_Inout_ SCOSSL_DH_KEYGEN_CTX *genCtx, _In_ SCOSSL_PROV_DH_KEY_CTX *tmplCtx)
{
    if (genCtx == NULL ||
        tmplCtx == NULL)
    {
        return SCOSSL_FAILURE;
    }

    // DH keygen only supports named groups, which are all statically
    // defined, so we can safely copy tmplCtx->pDlGroup by reference.
    if (tmplCtx->pDlGroup != NULL)
    {
        genCtx->pDlGroup = tmplCtx->pDlGroup;
        genCtx->nBitsPriv = tmplCtx->nBitsPriv;
        genCtx->nBitsPub = p_scossl_dh_pubkey_bits(tmplCtx);
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_PROV_DH_KEY_CTX *p_scossl_dh_keygen(_In_ SCOSSL_DH_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SCOSSL_PROV_DH_KEY_CTX *ctx;

    // Select named group based on nBitsPub if named group was not explicitly set.
    // Note that the ffdhe group, not the modp group is used to match the behavior
    // of the default openssl implementation.
    if (genCtx->pDlGroup == NULL)
    {
        int dlGroupNid = 0;
        switch(genCtx->nBitsPub)
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
            case 6144:
                dlGroupNid = NID_ffdhe6144;
                break;
            case 8192:
                dlGroupNid = NID_ffdhe8192;
                break;
        }

        if (scossl_dh_get_group_by_nid(dlGroupNid, NULL, &genCtx->pDlGroup) != SCOSSL_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return NULL;
        }
    }

    if ((ctx = p_scossl_dh_keymgmt_new_ctx(genCtx->provCtx)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!scossl_dh_generate_keypair(ctx->keyCtx, genCtx->nBitsPriv, genCtx->pDlGroup))
    {
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->pDlGroup = (PSYMCRYPT_DLGROUP) genCtx->pDlGroup;

    return ctx;
}

static const OSSL_PARAM *p_scossl_dh_keymgmt_settable_params(ossl_unused void *provCtx)
{
    return p_scossl_dh_keymgmt_settable_param_types;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_set_params(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL)
    {
        SYMCRYPT_ERROR scError;
        PCBYTE pbPublicKey;
        SIZE_T cbPublicKey;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pbPublicKey, &cbPublicKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (ctx->pDlGroup == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
            return SCOSSL_FAILURE;
        }

        if (ctx->keyCtx->initialized)
        {
            SymCryptDlkeyFree(ctx->keyCtx->dlkey);
            ctx->keyCtx->initialized = FALSE;
        }

        if ((ctx->keyCtx->dlkey = SymCryptDlkeyAllocate(ctx->pDlGroup)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return SCOSSL_FAILURE;
        }

        scError = SymCryptDlkeySetValue(
            NULL, 0,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_FLAG_DLKEY_DH,
            ctx->keyCtx->dlkey);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SymCryptDlkeyFree(ctx->keyCtx->dlkey);
            ctx->keyCtx->dlkey = NULL;

            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlkeySetValue failed", scError);
            return SCOSSL_FAILURE;
        }

        ctx->keyCtx->initialized = TRUE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_dh_keymgmt_gettable_params(ossl_unused void *provCtx)
{
    return p_scossl_dh_keymgmt_gettable_param_types;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_get_ffc_params(_In_ SYMCRYPT_DLGROUP *pDlGroup, _Inout_ OSSL_PARAM params[])
{
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    PBYTE  pbPrimeP = NULL;
    PBYTE  pbPrimeQ = NULL;
    PBYTE  pbGenG = NULL;
    PBYTE  pbSeed = NULL;
    PBYTE  pbCur;
    PBYTE  pbData = NULL;
    SIZE_T cbPrimeP = 0;
    SIZE_T cbPrimeQ = 0;
    SIZE_T cbGenG = 0;
    SIZE_T cbSeed = 0;
    SIZE_T cbData = 0;
    BIGNUM *bnPrimeP = NULL;
    BIGNUM *bnPrimeQ = NULL;
    BIGNUM *bnGenG = NULL;
    OSSL_PARAM *p;
    OSSL_PARAM *paramPrimeP = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_P);
    OSSL_PARAM *paramPrimeQ = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_Q);
    OSSL_PARAM *paramGenG = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_G);
    OSSL_PARAM *paramSeed = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_SEED);

    SymCryptDlgroupGetSizes(
        pDlGroup,
        &cbPrimeP,
        &cbPrimeQ,
        &cbGenG,
        &cbSeed);

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
            (cbPrimeP != 0 && (bnPrimeP = BN_new()) == NULL) ||
            (cbPrimeQ != 0 && (bnPrimeQ = BN_new()) == NULL) ||
            (cbGenG != 0 && (bnGenG = BN_new()) == NULL))
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

        scError = SymCryptDlgroupGetValue(
            pDlGroup,
            pbPrimeP, cbPrimeP,
            pbPrimeQ, cbPrimeQ,
            pbGenG, cbGenG,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            NULL,
            pbSeed, cbSeed,
            NULL);

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlgroupGetValue failed", scError);
            goto cleanup;
        }
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

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_GINDEX)) != NULL &&
        !OSSL_PARAM_set_int(p, SCOSSL_DH_GINDEX))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_PCOUNTER)) != NULL &&
        !OSSL_PARAM_set_int(p, SCOSSL_DH_PCOUNTER))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_H)) != NULL &&
        !OSSL_PARAM_set_int(p, SCOSSL_DH_H))
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
    PBYTE pbPrivateKey;
    PBYTE pbPublicKey;
    PBYTE pbData = NULL;
    SIZE_T cbPrivateKey = 0;
    SIZE_T cbPublicKey = 0;
    SIZE_T cbData = 0;
    BIGNUM *bnPrivKey = NULL;
    BIGNUM *bnPubKey = NULL;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    OSSL_PARAM *paramEncodedKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    OSSL_PARAM *paramPrivKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    OSSL_PARAM *paramPubKey = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);

    if (paramEncodedKey == NULL &&
        paramPrivKey == NULL &&
        paramPubKey == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return SCOSSL_FAILURE;
    }

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

    if (cbData != 0)
    {
        pbData = OPENSSL_zalloc(cbData);
        if (pbData == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbPrivateKey = cbPrivateKey == 0 ? NULL : pbData;
        pbPublicKey = cbPublicKey == 0 ? NULL : pbData + cbPrivateKey;

        scError = SymCryptDlkeyGetValue(
            keyCtx->dlkey,
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlkeyGetValue failed", scError);
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
    int pubKeyBits = p_scossl_dh_pubkey_bits(ctx);
    int privKeyBits = p_scossl_dh_privkey_bits(ctx);

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        (pubKeyBits < 0 || !OSSL_PARAM_set_int(p, pubKeyBits)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL)
    {
        if (pubKeyBits < 0 ||
            privKeyBits < 0 ||
            !OSSL_PARAM_set_int(p, BN_security_bits(pubKeyBits, privKeyBits)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        (pubKeyBits < 0 || !OSSL_PARAM_set_int(p, pubKeyBits / 8)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL &&
        (privKeyBits < 0 || !OSSL_PARAM_set_int(p, privKeyBits)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {
        int dlGroupNid = scossl_dh_get_group_nid(SymCryptDlkeyGetGroup(ctx->keyCtx->dlkey));
        if (dlGroupNid == 0)
        {
            SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "Failed to get NID for previously set group in DH key context");
            return SCOSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_utf8_string(p, OBJ_nid2sn(dlGroupNid)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return p_scossl_dh_keymgmt_get_ffc_params(ctx->pDlGroup, params) &&
           p_scossl_dh_keymgmt_get_key_params(ctx->keyCtx, params);
}


static BOOL p_scossl_dh_keymgmt_has(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, int selection)
{
    BOOL ret = TRUE;

    if (ctx == NULL || ctx->keyCtx->dlkey == NULL)
    {
        return FALSE;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        ret = ret && ctx->pDlGroup != NULL;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        ret = ret && ctx->keyCtx->initialized;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        ret = ret && ctx->keyCtx->dlkey != NULL &&
                     SymCryptDlkeyHasPrivateKey(ctx->keyCtx->dlkey);
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
    SYMCRYPT_ERROR scError;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (!ctx1->keyCtx->initialized || !ctx2->keyCtx->initialized)
        {
            goto cleanup;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            cbPublicKey = SymCryptDlkeySizeofPublicKey(ctx1->keyCtx->dlkey);
            if (SymCryptDlkeySizeofPublicKey(ctx2->keyCtx->dlkey) != cbPublicKey)
            {
                goto cleanup;
            }
        }
        // Only need to check the private key if we aren't already checking
        // the public key. Same behavior as default openssl implementation.
        else if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
                 SymCryptDlkeyHasPrivateKey(ctx1->keyCtx->dlkey) &&
                 SymCryptDlkeyHasPrivateKey(ctx2->keyCtx->dlkey))
        {
            cbPrivateKey = SymCryptDlkeySizeofPrivateKey(ctx1->keyCtx->dlkey);
            if (SymCryptDlkeySizeofPrivateKey(ctx2->keyCtx->dlkey) != cbPrivateKey)
            {
                goto cleanup;
            }
        }
        else
        {
            goto cleanup;
        }

        cbData = cbPrivateKey * 2 + cbPublicKey * 2;
        if ((pbData = OPENSSL_zalloc(cbData)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        // Only the private or public keys will be compared, but not both.
        // The below ensures the appropriate pointers are set for,
        // SymCryptDlkeyGetValue and memcmp and the others are NULL.
        pbPublicKey1 = cbPublicKey == 0 ? NULL : pbData;
        pbPrivateKey1 = cbPrivateKey == 0 ? NULL : pbData;

        pbPublicKey2 = cbPublicKey == 0 ? NULL : pbData + cbPublicKey + cbPrivateKey;
        pbPrivateKey2 = cbPrivateKey == 0 ? NULL : pbData + cbPublicKey + cbPrivateKey;

        scError = SymCryptDlkeyGetValue(
                ctx1->keyCtx->dlkey,
                pbPrivateKey1, cbPrivateKey,
                pbPublicKey1, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlkeyGetValue failed", scError);
            goto cleanup;
        }

        scError = SymCryptDlkeyGetValue(
                ctx2->keyCtx->dlkey,
                pbPrivateKey2, cbPrivateKey,
                pbPublicKey2, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlkeyGetValue failed", scError);
            goto cleanup;
        }

        if (memcmp(pbPublicKey1, pbPublicKey2, cbPublicKey) != 0 ||
            memcmp(pbPrivateKey1, pbPrivateKey2, cbPrivateKey) != 0)
        {
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 &&
        ctx1->pDlGroup != ctx2->pDlGroup)
    {
        if (ctx1->pDlGroup == NULL ||
            ctx2->pDlGroup == NULL ||
            !SymCryptDlgroupIsSame(ctx1->pDlGroup, ctx2->pDlGroup))
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
    BOOL groupSetByParams = FALSE;
    PSYMCRYPT_DLGROUP pDlGroup = NULL;
    BIGNUM *bnPrivateKey = NULL;
    BIGNUM *bnPublicKey = NULL;
    int nBitsPriv = SCOSSL_DH_PRIVATE_BITS_DEFAULT;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Group required for import
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->groupSetByParams)
    {
        SymCryptDlgroupFree(ctx->pDlGroup);
        ctx->pDlGroup = NULL;
        ctx->groupSetByParams = FALSE;
    }

    if (!p_scossl_dh_params_to_group(ctx->libCtx,
                                     params,
                                     &pDlGroup,
                                     &groupSetByParams) ||
        pDlGroup == NULL)
    {
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN)) != NULL &&
        !OSSL_PARAM_get_int(p, &nBitsPriv))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    // If keypair is selected, either the private or public key must be
    // available. Private or public key flags may be set in selection,
    // but only one needs to be set in the parameters.
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
            (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL)
        {
            if ((bnPrivateKey = BN_secure_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (!OSSL_PARAM_get_BN(p, &bnPrivateKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
            (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL)
        {
            if ((bnPublicKey = BN_new()) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            if (!OSSL_PARAM_get_BN(p, &bnPublicKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if (!scossl_dh_import_keypair(ctx->keyCtx, nBitsPriv, pDlGroup, groupSetByParams, bnPrivateKey, bnPublicKey))
        {
            goto cleanup;
        }
    }

    ctx->pDlGroup = pDlGroup;
    ctx->groupSetByParams = groupSetByParams;
    ctx->nBitsPriv = nBitsPriv;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        if (ctx->keyCtx->dlkey != NULL)
        {
            SymCryptDlkeyFree(ctx->keyCtx->dlkey);
            ctx->keyCtx->dlkey = NULL;
            ctx->keyCtx->initialized = FALSE;
        }

        if (groupSetByParams && pDlGroup != NULL)
        {
            SymCryptDlgroupFree(pDlGroup);
            ctx->pDlGroup = NULL;
        }
    }

    BN_clear_free(bnPrivateKey);
    BN_free(bnPublicKey);

    return ret;
}

static SCOSSL_STATUS p_scossl_dh_keymgmt_export(_In_ SCOSSL_PROV_DH_KEY_CTX *ctx, int selection,
                                                _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BOOL includePublic = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;;
    BOOL includePrivate = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    PBYTE pbPrimeP = NULL;
    PBYTE pbPrimeQ = NULL;
    PBYTE pbGenG = NULL;
    PBYTE pbSeed = NULL;
    PBYTE  pbPrivateKey;
    PBYTE  pbPublicKey;
    PBYTE  pbCur;
    PBYTE  pbData = NULL;
    SIZE_T cbPrimeP;
    SIZE_T cbPrimeQ;
    SIZE_T cbGenG;
    SIZE_T cbSeed;
    SIZE_T cbPublicKey;
    SIZE_T cbPrivateKey;
    SIZE_T cbData = 0;
    BIGNUM *bnPrimeP = NULL;
    BIGNUM *bnPrimeQ = NULL;
    BIGNUM *bnGenG = NULL;
    BIGNUM *bnPrivKey = NULL;
    BIGNUM *bnPubKey = NULL;
    int mdNid;
    int dlGroupNid;
    int privateKeyBits;
    const char *dlGroupName;
    PCSYMCRYPT_HASH pHashAlgorithm;
    UINT32 genCounter;

    SYMCRYPT_ERROR scError =  SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->keyCtx == NULL ||
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
        ctx->pDlGroup,
        &cbPrimeP,
        &cbPrimeQ,
        &cbGenG,
        &cbSeed);

    if (cbPrimeP == 0)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "SymCryptDlgroupGetSizes returned 0 for prime P size");
        goto cleanup;
    }

    cbData =
        cbPrimeP +
        cbPrimeQ +
        cbGenG +
        cbSeed;

    if ((pbData = OPENSSL_malloc(cbData)) == NULL ||
        (cbPrimeP != 0 && (bnPrimeP = BN_new()) == NULL) ||
        (cbPrimeQ != 0 && (bnPrimeQ = BN_new()) == NULL) ||
        (cbGenG != 0 && (bnGenG = BN_new()) == NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    pbPrimeP = pbData;

    pbCur = pbData + cbPrimeP;
    pbPrimeQ = cbPrimeQ == 0 ? NULL : pbCur;

    pbCur += cbPrimeQ;
    pbGenG = cbGenG == 0 ? NULL : pbCur;

    pbCur += cbGenG;
    pbSeed = cbSeed == 0 ? NULL : pbCur;

    // Always export group parameters
    scError = SymCryptDlgroupGetValue(
        ctx->pDlGroup,
        pbPrimeP, cbPrimeP,
        pbPrimeQ, cbPrimeQ,
        pbGenG, cbGenG,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &pHashAlgorithm,
        pbSeed, cbSeed,
        &genCounter);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlgroupGetValue failed", scError);
        goto cleanup;
    }

    if (pbPrimeP != NULL &&
            (BN_bin2bn(pbPrimeP, cbPrimeP, bnPrimeP) == NULL ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bnPrimeP)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if (pbPrimeQ != NULL &&
            (BN_bin2bn(pbPrimeQ, cbPrimeQ, bnPrimeQ) == NULL ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bnPrimeQ)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if (pbGenG != NULL &&
            (BN_bin2bn(pbGenG, cbGenG, bnGenG) == NULL ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bnGenG)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if (pbSeed != NULL &&
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_FFC_SEED, pbSeed, cbSeed))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((mdNid = scossl_get_mdnid_from_symcrypt_hash_algorithm(pHashAlgorithm)) != NID_undef)
    {
        const char *mdName = OBJ_nid2sn(mdNid);

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_FFC_DIGEST, mdName, strlen(mdName)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    // Group name may not be available if the group was imported by params
    if ((dlGroupNid = scossl_dh_get_group_nid(ctx->pDlGroup)) != 0)
    {
        if ((dlGroupName = OBJ_nid2sn(dlGroupNid)) == NULL ||
            !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, dlGroupName, strlen(dlGroupName)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        cbPrivateKey = includePrivate ? SymCryptDlkeySizeofPrivateKey(ctx->keyCtx->dlkey) : 0;
        cbPublicKey = includePublic ? SymCryptDlkeySizeofPublicKey(ctx->keyCtx->dlkey) : 0;

        OPENSSL_free(pbData);
        cbData = cbPrivateKey + cbPublicKey;
        if ((pbData = OPENSSL_zalloc(cbData)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        pbPrivateKey = includePrivate ? pbData : NULL;
        pbPublicKey = includePublic ? pbData + cbPrivateKey : NULL;

        scError = SymCryptDlkeyGetValue(
            ctx->keyCtx->dlkey,
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptDlkeyGetValue failed", scError);
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
                !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bnPrivKey))
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
                !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bnPubKey))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                goto cleanup;
            }
        }
    }

    privateKeyBits = p_scossl_dh_privkey_bits(ctx);

    if (privateKeyBits < 0 ||
        !OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, privateKeyBits) ||
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
    BN_free(bnPrimeP);
    BN_free(bnPrimeQ);
    BN_free(bnGenG);
    BN_free(bnPubKey);
    BN_clear_free(bnPrivKey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_dh_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_dh_keymgmt_dup_key_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_dh_keymgmt_free_key_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_dh_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_dh_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_dh_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_dh_keygen_set_template},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_dh_keygen},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_dh_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_dh_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_dh_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_dh_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_dh_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_dh_keymgmt_export},
    {0, NULL}};

#ifdef __cplusplus
}
#endif