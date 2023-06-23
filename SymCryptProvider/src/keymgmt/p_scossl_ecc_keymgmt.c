//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "p_scossl_base.h"

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;
    EC_GROUP *ecGroup;
} SCOSSL_ECC_KEYGEN_CTX;

// ScOSSL only supports named curves
static const OSSL_PARAM p_scossl_ecc_keygen_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecc_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_ecc_keymgmt_impexp_param_types[] = {
    OSSL_PARAM_END};

// Key Context Management
//
// Key import uses keymgmt_new to allocate an empty key object
// first, then passes that reference to keymgmt_import. Since
// the size of the SYMCRYPT_ECKEY depends on parameters that aren't
// known until import, no key is actually allocated here.
static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_new_ctx(ossl_unused void *provctx)
{
    return scossl_ecc_new_key_ctx();
}

static SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keymgmt_dup_ctx(SCOSSL_ECC_KEY_CTX *keyCtx, ossl_unused int selection)
{
    return scossl_ecc_dup_key_ctx(keyCtx);
}

//
// Key Generation
//
SCOSSL_STATUS p_scossl_ecc_keygen_set_params(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(p, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL)
    {
        genCtx->ecGroup = EC_GROUP_new_from_params(params, genCtx->libctx, NULL);
        if (genCtx->ecGroup == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return SCOSSL_FAILURE;
        }      
    }

cleanup:
    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_ecc_keygen_settable_params(ossl_unused void *genCtx,
                                                      ossl_unused void *provctx)
{
    return p_scossl_ecc_keygen_settable_param_types;
}

void p_scossl_ecc_keygen_cleanup(_Inout_ SCOSSL_ECC_KEYGEN_CTX *genCtx)
{
    if (genCtx != NULL) 
    {
        EC_GROUP_free(genCtx->ecGroup);
    }
    OPENSSL_free(genCtx);
}

SCOSSL_ECC_KEYGEN_CTX *p_scossl_ecc_keygen_init(_In_ SCOSSL_PROVCTX *provctx, int selection,
                                                const _In_ OSSL_PARAM params[])
{
    SCOSSL_COMMON_ALIGNED_ALLOC(genCtx, OPENSSL_malloc, SCOSSL_ECC_KEYGEN_CTX);
    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genCtx->libctx = provctx->libctx;

    if (!p_scossl_ecc_keygen_set_params(genCtx, params))
    {
        p_scossl_ecc_keygen_cleanup(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

SCOSSL_ECC_KEY_CTX *p_scossl_ecc_keygen(_In_ SCOSSL_ECC_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_ECURVE pCurve = NULL;

    SCOSSL_COMMON_ALIGNED_ALLOC(keyCtx, OPENSSL_malloc, SCOSSL_ECC_KEY_CTX);
    if (keyCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    keyCtx->ecGroup = genCtx->ecGroup;
    genCtx->ecGroup = NULL;

    pCurve = scossl_ecc_group_to_symcrypt_curve(keyCtx->ecGroup);
    if (pCurve == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto cleanup; 
    }

    keyCtx->key = SymCryptEckeyAllocate(pCurve);
    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // We don't know whether this key will be used for ECDSA or ECDH
    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

cleanup:
    if (!keyCtx->initialized)
    {
        scossl_ecc_free_key_ctx(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

SCOSSL_STATUS p_scossl_ecc_keymgmt_get_params(_In_ PSYMCRYPT_RSAKEY keydata, _Inout_ OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_ecc_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_ecc_keymgmt_gettable_param_types;
}

BOOL p_scossl_ecc_keymgmt_has(_In_ PSYMCRYPT_RSAKEY keydata, int selection)
{
    return TRUE;
}

BOOL p_scossl_ecc_keymgmt_match(_In_ PSYMCRYPT_RSAKEY keydata1, _In_ PSYMCRYPT_RSAKEY keydata2,
                            int selection)
{
    return TRUE;
}

//
// Key import/export
//
const OSSL_PARAM *p_scossl_ecc_keymgmt_impexp_types(int selection)
{
    return p_scossl_ecc_keymgmt_impexp_param_types;
}

SCOSSL_STATUS p_scossl_ecc_keymgmt_import(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection, const _In_ OSSL_PARAM params[])
{
    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_ecc_keymgmt_export(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                      _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    return SCOSSL_SUCCESS;
}

const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_ecc_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_ecc_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))scossl_ecc_free_key_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_ecc_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_ecc_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_ecc_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_ecc_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_ecc_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_ecc_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_ecc_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_ecc_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_ecc_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_ecc_keymgmt_export},
    {0, NULL}};

#ifdef __cplusplus
}
#endif