//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NID_secp192r1 (NID_X9_62_prime192v1)
#define NID_secp256r1 (NID_X9_62_prime256v1)

static PSYMCRYPT_ECURVE _hidden_curve_P192 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P224 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P256 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P384 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P521 = NULL;

SCOSSL_STATUS scossl_ecc_init_static()
{
    if( ((_hidden_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0)) == NULL) ||
        ((_hidden_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0)) == NULL) ||
        ((_hidden_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0)) == NULL) ||
        ((_hidden_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0)) == NULL) ||
        ((_hidden_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0)) == NULL) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

PSYMCRYPT_ECURVE scossl_ecc_group_to_symcrypt_curve(EC_GROUP *group)
{
    if (group == NULL)
    {
        return NULL;
    }

    int groupNid = EC_GROUP_get_curve_name(group);

    // Only reroute NIST Prime curves to SymCrypt for now
    switch (groupNid)
    {
    case NID_secp192r1:
        return _hidden_curve_P192;
    case NID_secp224r1:
        return _hidden_curve_P224;
    case NID_secp256r1:
        return _hidden_curve_P256;
    case NID_secp384r1:
        return _hidden_curve_P384;
    case NID_secp521r1:
        return _hidden_curve_P521;
    default:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_ECC_CONTEXT_EX, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "SymCrypt-OpenSSL does not yet support this group (nid %d).", groupNid);
    }

    return NULL;
}

SCOSSL_ECC_KEY_CTX *scossl_ecc_new_key_ctx()
{
    SCOSSL_COMMON_ALIGNED_ALLOC(keyCtx, OPENSSL_zalloc, SCOSSL_ECC_KEY_CTX);
    return keyCtx;
}

SCOSSL_ECC_KEY_CTX *scossl_ecc_dup_key_ctx(_In_ const SCOSSL_ECC_KEY_CTX *keyCtx)
{
    SCOSSL_COMMON_ALIGNED_ALLOC(copy_ctx, OPENSSL_malloc, SCOSSL_ECC_KEY_CTX);
    if (copy_ctx == NULL)
    {
        return NULL;
    }

    if (keyCtx->initialized)
    {
        if (keyCtx->ecGroup == NULL)
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_ECC_CONTEXT_EX, ERR_R_INTERNAL_ERROR,
                "ECC key inititalized but group not set"); 
        }
        copy_ctx->ecGroup = keyCtx->ecGroup;
        copy_ctx->key = SymCryptEckeyAllocate(scossl_ecc_nid_to_symcrypt_curve(copy_ctx->ecGroup));
        SymCryptEckeyCopy(keyCtx->key, copy_ctx->key);
    }
    else
    {
        copy_ctx->initialized = 0;
        copy_ctx->key = NULL;
        copy_ctx->ecGroup = NULL;
    }

    return copy_ctx;
}

void scossl_ecc_free_key_ctx(_In_ SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

    EC_GROUP_free(keyCtx->ecGroup);    
    OPENSSL_free(keyCtx);
}

#ifdef __cplusplus
}
#endif