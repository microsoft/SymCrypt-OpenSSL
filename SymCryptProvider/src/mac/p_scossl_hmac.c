//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_mac.h"
#include "p_scossl_base.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM p_scossl_hmac_ctx_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_hmac_ctx_settable_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};

static SCOSSL_STATUS p_scossl_hmac_set_ctx_params(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const OSSL_PARAM params[]);

static SCOSSL_MAC_CTX *p_scossl_hmac_newctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_MAC_CTX *ctx = OPENSSL_zalloc(sizeof(SCOSSL_MAC_CTX));
    if (ctx != NULL)
    {
        ctx->libctx = provctx->libctx;
    }

    return ctx;
}

static SCOSSL_STATUS p_scossl_hmac_init(_Inout_ SCOSSL_MAC_CTX *ctx,
                                        _In_reads_bytes_opt_(keylen) unsigned char *key, size_t keylen,
                                        _In_ const OSSL_PARAM params[])
{
    return p_scossl_hmac_set_ctx_params(ctx, params) &&
           scossl_mac_init(ctx, key, keylen);
}

static const OSSL_PARAM *p_scossl_hmac_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hmac_ctx_gettable_param_types;
}

static const OSSL_PARAM *p_scossl_hmac_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_hmac_ctx_settable_param_types;
}

static SCOSSL_STATUS p_scossl_hmac_get_ctx_params(_In_ SCOSSL_MAC_CTX *ctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->pMac == NULL ? 0 : ctx->pMac->resultSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->pMacEx == NULL ? 0 : ctx->pMacEx->blockSize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_DIGEST)) != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mdName == NULL ? "" : ctx->mdName))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// The MD's nid may not be retrievable from EVP_MD_type(). In that
// case, we need to check each MD we support with EVP_MD_is_a()
static int p_scossl_hmac_get_mdnid(_In_ EVP_MD *md)
{
    int mdNid = EVP_MD_type(md);
    if (mdNid == NID_undef)
    {
        if (EVP_MD_is_a(md, SN_sha1))
        {
            mdNid = NID_sha1;
        }
        if (EVP_MD_is_a(md, SN_sha224))
        {
            mdNid = NID_sha224;
        }
        if (EVP_MD_is_a(md, SN_sha256))
        {
            mdNid = NID_sha256;
        }
        if (EVP_MD_is_a(md, SN_sha384))
        {
            mdNid = NID_sha384;
        }
        if (EVP_MD_is_a(md, SN_sha512))
        {
            mdNid = NID_sha512;
        }
        if (EVP_MD_is_a(md, SN_sha512_224))
        {
            mdNid = NID_sha512_224;
        }
        if (EVP_MD_is_a(md, SN_sha512_256))
        {
            mdNid = NID_sha512_256;
        }
        if (EVP_MD_is_a(md, SN_sha3_224))
        {
            mdNid = NID_sha3_224;
        }
        if (EVP_MD_is_a(md, SN_sha3_256))
        {
            mdNid = NID_sha3_256;
        }
        if (EVP_MD_is_a(md, SN_sha3_384))
        {
            mdNid = NID_sha3_384;
        }
        if (EVP_MD_is_a(md, SN_sha3_512))
        {
            mdNid = NID_sha3_512;
        }
    }

    return mdNid;
}

static SCOSSL_STATUS p_scossl_hmac_set_ctx_params(_Inout_ SCOSSL_MAC_CTX *ctx, _In_ const OSSL_PARAM params[])
{
    char *mdName = NULL;
    char *mdProps = NULL;
    PBYTE pbMacKey = NULL;
    EVP_MD *md = NULL;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST)) != NULL)
    {
        OPENSSL_free(ctx->mdName);
        ctx->mdName = NULL;

        // mdname is not directly set from parameters. The name is fetched from the
        // provider in case the provider is registered under multiple names for the
        // same digest, or surfaces the digest under a different name.
        if (!OSSL_PARAM_get_utf8_string(p, &mdName, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES)) != NULL &&
            !OSSL_PARAM_get_utf8_string(p, &mdProps, 0))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        // Get mdname from provider
        if ((md = EVP_MD_fetch(ctx->libctx, mdName, mdProps)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            goto cleanup;
        }

        if (!scossl_mac_set_hmac_md(ctx, p_scossl_hmac_get_mdnid(md)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            goto cleanup;
        }

        if ((ctx->mdName = OPENSSL_strdup(mdName)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        SIZE_T cbMacKey;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pbMacKey, 0, &cbMacKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (!scossl_mac_init(ctx, pbMacKey, cbMacKey))
        {
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    OPENSSL_free(mdName);
    OPENSSL_free(mdProps);
    OPENSSL_free(pbMacKey);
    EVP_MD_free(md);

    return ret;
}

const OSSL_DISPATCH p_scossl_hmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p_scossl_hmac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))scossl_mac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))scossl_mac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))p_scossl_hmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))scossl_mac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))scossl_mac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_hmac_settable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))p_scossl_hmac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))p_scossl_hmac_set_ctx_params},
    {0, NULL}};

#ifdef __cplusplus
}
#endif