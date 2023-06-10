//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_rsa.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

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
            if (EVP_MD_is_a(mdInt, p_scossl_rsa_supported_mds[i].ptr))
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

#ifdef __cplusplus
}
#endif