//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe4096 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp4096 = NULL;
static BIGNUM* _hidden_bignum_modp2048 = NULL;
static BIGNUM* _hidden_bignum_modp3072 = NULL;
static BIGNUM* _hidden_bignum_modp4096 = NULL;

SCOSSL_DH_KEY_CTX *scossl_dh_new_key_ctx(void)
{
    return OPENSSL_zalloc(sizeof(SCOSSL_DH_KEY_CTX));
}

void scossl_dh_free_key_ctx(SCOSSL_DH_KEY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->dlkey != NULL)
    {
        SymCryptDlkeyFree(ctx->dlkey);
    }

    OPENSSL_free(ctx);
}

SCOSSL_DH_KEY_CTX *scossl_dh_dup_key_ctx(SCOSSL_DH_KEY_CTX *ctx, BOOL copyGroup)
{
    SCOSSL_DH_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DH_KEY_CTX));
    PCSYMCRYPT_DLGROUP pDlgroup;
    PSYMCRYPT_DLGROUP pDlgroupCopy;

    if (copyCtx != NULL)
    {
        copyCtx->initialized = ctx->initialized;
        if (ctx->initialized)
        {
            pDlgroup = SymCryptDlkeyGetGroup(ctx->dlkey);

            // The provider supports importing groups by parameters.
            // In that case we need to copy the group as well rather than
            // using a pointer to one of the statically defined groups.
            if (copyGroup)
            {
                SIZE_T pcbPrimeP;
                SIZE_T pcbPrimeQ;

                SymCryptDlgroupGetSizes(
                    pDlgroup,
                    &pcbPrimeP,
                    &pcbPrimeQ,
                    NULL,
                    NULL);

                if ((pDlgroupCopy = SymCryptDlgroupAllocate(pcbPrimeP, pcbPrimeQ)) != NULL)
                {
                    SymCryptDlgroupCopy(pDlgroup, pDlgroupCopy);
                }

                pDlgroup = pDlgroupCopy;
            }

            if (pDlgroup == NULL ||
                (copyCtx->dlkey = SymCryptDlkeyAllocate(pDlgroup)) == NULL)
            {
                SymCryptDlgroupFree(pDlgroupCopy);
                OPENSSL_free(copyCtx);
                copyCtx = NULL;
            }
            else
            {
                SymCryptDlkeyCopy(ctx->dlkey, copyCtx->dlkey);
            }
        }
        else
        {
            copyCtx->dlkey = NULL;
        }
    }

    return copyCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_dh_import_keypair(SCOSSL_DH_KEY_CTX *ctx, UINT32 nBitsPriv,
                                       PCSYMCRYPT_DLGROUP pDlgroup, BOOL skipGroupValidation,
                                       const BIGNUM *privateKey, const BIGNUM *publicKey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPrivateKey;
    SIZE_T cbPublicKey;
    UINT32 flags = SYMCRYPT_FLAG_DLKEY_DH;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (ctx->dlkey != NULL)
    {
        SymCryptDlkeyFree(ctx->dlkey);
    }

    ctx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if (ctx->dlkey == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                         "SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    if (nBitsPriv != 0)
    {
        scError = SymCryptDlkeySetPrivateKeyLength(ctx->dlkey, nBitsPriv, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptDlkeySetPrivateKeyLength failed", scError);
            goto cleanup;
        }
    }

    if (privateKey != NULL || publicKey != NULL)
    {
        cbPrivateKey = SymCryptDlkeySizeofPrivateKey(ctx->dlkey);
        cbPublicKey = SymCryptDlkeySizeofPublicKey(ctx->dlkey);
        // For simplicity, always allocate enough space for a private key and a public key, even if we may only use one
        cbData = cbPublicKey + cbPrivateKey;
        if ((pbData = OPENSSL_zalloc(cbData)) == NULL)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
                            "OPENSSL_zalloc returned NULL.");
            goto cleanup;
        }

        if (privateKey != NULL)
        {
            pbPrivateKey = pbData;
            if ((SIZE_T)BN_bn2binpad(privateKey, pbPrivateKey, cbPrivateKey) != cbPrivateKey)
            {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
                                "BN_bn2binpad did not write expected number of private key bytes.");
                goto cleanup;
            }
        }
        else
        {
            cbPrivateKey = 0;
        }

        if (publicKey != NULL)
        {
            pbPublicKey = pbData + cbPrivateKey;
            if ((SIZE_T)BN_bn2binpad(publicKey, pbPublicKey, cbPublicKey) != cbPublicKey)
            {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
                                "BN_bn2binpad did not write expected number of public key bytes.");
                goto cleanup;
            }
        }
        else
        {
            cbPublicKey = 0;
        }

        // The SymCrypt provider must support non-FIPS groups since it cannot
        // fallback to the default implementation like the engine.
        if (skipGroupValidation)
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
                            "Importing non-FIPS DH group.");
            flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        }

        scError = SymCryptDlkeySetValue(
            pbPrivateKey, cbPrivateKey,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            flags,
            ctx->dlkey);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                    "SymCryptDlkeySetValue failed", scError);
            goto cleanup;
        }

        ctx->initialized = TRUE;
    }
    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        ctx->initialized = FALSE;
        SymCryptDlkeyFree(ctx->dlkey);
        ctx->dlkey = NULL;
    }

    if (pbData != NULL)
    {
        OPENSSL_clear_free( pbData, cbData );
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_dh_create_key(SCOSSL_DH_KEY_CTX *ctx, PCSYMCRYPT_DLGROUP pDlgroup, UINT32 nBitsPriv, BOOL generateKeyPair)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    ctx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if (ctx->dlkey == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                         "SymCryptDlkeyAllocate returned NULL.");
        return SCOSSL_FAILURE;
    }

    if (nBitsPriv != 0)
    {
        scError = SymCryptDlkeySetPrivateKeyLength(ctx->dlkey, nBitsPriv, 0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                      "SymCryptDlkeySetPrivateKeyLength failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    if (generateKeyPair)
    {
        scError = SymCryptDlkeyGenerate(SYMCRYPT_FLAG_DLKEY_DH, ctx->dlkey);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                                    "SymCryptDlkeyGenerate failed", scError);
            return SCOSSL_FAILURE;
        }

        ctx->initialized = TRUE;
    }

    return SCOSSL_SUCCESS;
}

static PSYMCRYPT_DLGROUP scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE dhSafePrimeType,
                                                             UINT32 nBitsOfP)
{
    PSYMCRYPT_DLGROUP pDlgroup;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    pDlgroup = SymCryptDlgroupAllocate( nBitsOfP, nBitsOfP-1 );
    if (pDlgroup == NULL)
    {
        goto cleanup;
    }

    scError = SymCryptDlgroupSetValueSafePrime(dhSafePrimeType, pDlgroup);

cleanup:
    if (pDlgroup != NULL && scError != SYMCRYPT_NO_ERROR)
    {
        SymCryptDlgroupFree(pDlgroup);
        pDlgroup = NULL;
    }

    return pDlgroup;
}

SCOSSL_STATUS scossl_dh_init_static(void)
{
    if (((_hidden_dlgroup_ffdhe2048 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 2048)) == NULL) ||
        ((_hidden_dlgroup_ffdhe3072 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 3072)) == NULL) ||
        ((_hidden_dlgroup_ffdhe4096 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 4096)) == NULL) ||
        ((_hidden_dlgroup_modp2048 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 2048)) == NULL) ||
        ((_hidden_dlgroup_modp3072 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 3072)) == NULL) ||
        ((_hidden_dlgroup_modp4096 = scossl_initialize_safeprime_dlgroup(SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 4096)) == NULL) ||
        ((_hidden_bignum_modp2048 = BN_get_rfc3526_prime_2048(NULL)) == NULL) ||
        ((_hidden_bignum_modp3072 = BN_get_rfc3526_prime_3072(NULL)) == NULL) ||
        ((_hidden_bignum_modp4096 = BN_get_rfc3526_prime_4096(NULL)) == NULL) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

void scossl_destroy_safeprime_dlgroups(void)
{
    if (_hidden_dlgroup_ffdhe2048)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe2048);
        _hidden_dlgroup_ffdhe2048 = NULL;
    }
    if (_hidden_dlgroup_ffdhe3072)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe3072);
        _hidden_dlgroup_ffdhe3072 = NULL;
    }
    if (_hidden_dlgroup_ffdhe4096)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe4096);
        _hidden_dlgroup_ffdhe4096 = NULL;
    }
    if (_hidden_dlgroup_modp2048)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp2048);
        _hidden_dlgroup_modp2048 = NULL;
    }
    if (_hidden_dlgroup_modp3072)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp3072);
        _hidden_dlgroup_modp3072 = NULL;
    }
    if (_hidden_dlgroup_modp4096)
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp4096);
        _hidden_dlgroup_modp4096 = NULL;
    }
    BN_free(_hidden_bignum_modp2048);
    _hidden_bignum_modp2048 = NULL;
    BN_free(_hidden_bignum_modp3072);
    _hidden_bignum_modp3072 = NULL;
    BN_free(_hidden_bignum_modp4096);
    _hidden_bignum_modp4096 = NULL;
}

// Other providers may export the group to the SymCrypt provider by parameters
// rather than by NID. In that case, we need to check whether the group is known
// to avoid redundant allocations and ensure that the group will pass any FIPS
// related validation by SymCrypt.
_Use_decl_annotations_
PCSYMCRYPT_DLGROUP scossl_dh_get_known_group(PCSYMCRYPT_DLGROUP pDlGroup)
{
    PCSYMCRYPT_DLGROUP pKnownDlGroup = NULL;

    if (SymCryptDlgroupIsSame(_hidden_dlgroup_ffdhe2048, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_ffdhe2048;
    }
    else if (SymCryptDlgroupIsSame(_hidden_dlgroup_ffdhe3072, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_ffdhe3072;
    }
    else if (SymCryptDlgroupIsSame(_hidden_dlgroup_ffdhe4096, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_ffdhe4096;
    }
    else if (SymCryptDlgroupIsSame(_hidden_dlgroup_modp2048, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_modp2048;
    }
    else if (SymCryptDlgroupIsSame(_hidden_dlgroup_modp3072, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_modp3072;
    }
    else if (SymCryptDlgroupIsSame(_hidden_dlgroup_modp4096, pDlGroup))
    {
        pKnownDlGroup = _hidden_dlgroup_modp4096;
    }

    return pKnownDlGroup;
}

_Use_decl_annotations_
PCSYMCRYPT_DLGROUP scossl_dh_get_group_by_nid(int dlGroupNid, const BIGNUM* p)
{
    PCSYMCRYPT_DLGROUP pDlGroup = NULL;
    switch (dlGroupNid)
    {
    case NID_ffdhe2048:
        pDlGroup = _hidden_dlgroup_ffdhe2048;
        break;
    case NID_ffdhe3072:
        pDlGroup = _hidden_dlgroup_ffdhe3072;
        break;
    case NID_ffdhe4096:
        pDlGroup = _hidden_dlgroup_ffdhe4096;
        break;
#if OPENSSL_VERSION_MAJOR >= 3
    case NID_modp_2048:
        pDlGroup = _hidden_dlgroup_modp2048;
        break;
    case NID_modp_3072:
        pDlGroup = _hidden_dlgroup_modp3072;
        break;
    case NID_modp_4096:
        pDlGroup = _hidden_dlgroup_modp4096;
        break;
#endif // OPENSSL_VERSION_MAJOR >= 3
    default:
        // Not one of the supported ffdhe groups, but may still be a supported MODP group
        // Given we know the generator is 2, we can now check whether P corresponds to a MODP group
        if (p != NULL)
        {
            if (BN_cmp(p, _hidden_bignum_modp2048) == 0)
            {
                pDlGroup = _hidden_dlgroup_modp2048;
            }
            else if (BN_cmp(p, _hidden_bignum_modp3072) == 0)
            {
                pDlGroup = _hidden_dlgroup_modp3072;
            }
            else if (BN_cmp(p, _hidden_bignum_modp4096) == 0)
            {
                pDlGroup = _hidden_dlgroup_modp4096;
            }
        }
    }

    return pDlGroup;
}

_Use_decl_annotations_
int scossl_dh_get_group_nid(PCSYMCRYPT_DLGROUP pDlGroup)
{
    int dlGroupNid = 0;

    if (pDlGroup == _hidden_dlgroup_ffdhe2048)
    {
        dlGroupNid = NID_ffdhe2048;
    }
    else if (pDlGroup == _hidden_dlgroup_ffdhe3072)
    {
        dlGroupNid = NID_ffdhe3072;
    }
    else if (pDlGroup == _hidden_dlgroup_ffdhe4096)
    {
        dlGroupNid = NID_ffdhe4096;
    }
#if OPENSSL_VERSION_MAJOR >= 3
    else if (pDlGroup == _hidden_dlgroup_modp2048)
    {
        dlGroupNid = NID_modp_2048;
    }
    else if (pDlGroup == _hidden_dlgroup_modp3072)
    {
        dlGroupNid = NID_modp_3072;
    }
    else if (pDlGroup == _hidden_dlgroup_modp4096)
    {
        dlGroupNid = NID_modp_4096;
    }
#endif // OPENSSL_VERSION_MAJOR >= 3

    return dlGroupNid;
}

#ifdef __cplusplus
}
#endif