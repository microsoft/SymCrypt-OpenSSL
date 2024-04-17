//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Common functions for rsa sign and rsa asym cipher interfaces

#include "p_scossl_rsa.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_PROV_RSA_PSS_DEFAULT_MD (0) // Index of the default MD in p_scossl_rsa_supported_mds (SHA1)
#define SCOSSL_PROV_RSA_PSS_DEFAULT_SALTLEN_MIN (20)

static const OSSL_ITEM p_scossl_rsa_supported_mds[] = {
    {NID_sha1,     OSSL_DIGEST_NAME_SHA1}, // Default
    {NID_sha256,   OSSL_DIGEST_NAME_SHA2_256},
    {NID_sha384,   OSSL_DIGEST_NAME_SHA2_384},
    {NID_sha512,   OSSL_DIGEST_NAME_SHA2_512},
    {NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256},
    {NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384},
    {NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512}};

_Use_decl_annotations_
const OSSL_ITEM *p_scossl_rsa_get_supported_md(OSSL_LIB_CTX *libctx,
                                               const char *mdname, const char *propq,
                                               EVP_MD **md)
{
    EVP_MD *mdInt = NULL;
    const OSSL_ITEM *mdInfo = NULL;

    if ((mdInt = EVP_MD_fetch(libctx, mdname, propq)) != NULL)
    {
        for (size_t i = 0; i < sizeof(p_scossl_rsa_supported_mds) / sizeof(OSSL_ITEM); i++)
        {
            if (mdInt != NULL && EVP_MD_is_a(mdInt, p_scossl_rsa_supported_mds[i].ptr))
            {
                mdInfo = &p_scossl_rsa_supported_mds[i];
            }
        }
    }

    if (md != NULL)
    {
        *md = mdInt;
    }
    else
    {
        EVP_MD_free(mdInt);
    }

    return mdInfo;
}

static const OSSL_ITEM *p_scossl_rsa_pss_param_to_mdinfo(_In_ OSSL_LIB_CTX *libctx,
                                                         _In_ const OSSL_PARAM *p, _In_ const char *mdProps)
{
    const OSSL_ITEM *mdInfo;
    const char *mdName;

    if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return NULL;
    }

    mdInfo = p_scossl_rsa_get_supported_md(libctx, mdName, mdProps, NULL);
    if (mdInfo == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return NULL;
    }

    return mdInfo;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_rsa_pss_restrictions_from_params(OSSL_LIB_CTX *libctx, const OSSL_PARAM params[],
                                                        SCOSSL_RSA_PSS_RESTRICTIONS **pPssRestrictions)
{
    const char *mdProps = NULL;
    SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    const OSSL_PARAM *paramSaltlenMin = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
    const OSSL_PARAM *paramPropq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
    const OSSL_PARAM *paramMd = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    const OSSL_PARAM *paramMgf1md = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);

    if (paramSaltlenMin == NULL &&
        paramPropq == NULL &&
        paramMd == NULL &&
        paramMgf1md == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if (*pPssRestrictions == NULL)
    {
        if ((pssRestrictions = OPENSSL_malloc(sizeof(SCOSSL_RSA_PSS_RESTRICTIONS))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        // Set defaults based on RFC 8017, A.2.3. This is the same behavior
        // as the default provider.
        pssRestrictions->mdInfo = &p_scossl_rsa_supported_mds[SCOSSL_PROV_RSA_PSS_DEFAULT_MD];
        pssRestrictions->mgf1MdInfo = &p_scossl_rsa_supported_mds[SCOSSL_PROV_RSA_PSS_DEFAULT_MD];
        pssRestrictions->cbSaltMin = SCOSSL_PROV_RSA_PSS_DEFAULT_SALTLEN_MIN;

        *pPssRestrictions = pssRestrictions;
    }
    else
    {
        pssRestrictions = *pPssRestrictions;
    }

    if (paramSaltlenMin != NULL &&
        !OSSL_PARAM_get_int(paramSaltlenMin, &pssRestrictions->cbSaltMin))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
        goto cleanup;
    }

    if (paramPropq != NULL &&
        !OSSL_PARAM_get_utf8_string_ptr(paramPropq, &mdProps))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        goto cleanup;
    }

    if (paramMd != NULL &&
        (pssRestrictions->mdInfo = p_scossl_rsa_pss_param_to_mdinfo(libctx, paramMd, mdProps)) == NULL)
    {
        goto cleanup;
    }

    if (paramMgf1md != NULL &&
        (pssRestrictions->mgf1MdInfo = p_scossl_rsa_pss_param_to_mdinfo(libctx, paramMgf1md, mdProps)) == NULL)
    {
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        OPENSSL_free(pssRestrictions);
        *pPssRestrictions = NULL;
    }

    return ret;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_rsa_pss_restrictions_to_params(const SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions,
                                              OSSL_PARAM_BLD *bld)
{
    return OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_DIGEST, pssRestrictions->mdInfo->ptr, 0) &&
           OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, pssRestrictions->mgf1MdInfo->ptr, 0) &&
           OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, pssRestrictions->cbSaltMin);
}

#ifdef __cplusplus
}
#endif