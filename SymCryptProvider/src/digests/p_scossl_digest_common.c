//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "digests/p_scossl_digest_common.h"

#ifdef __cplusplus
extern "C" {
#endif

const OSSL_PARAM p_scossl_digest_gettable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END};

_Use_decl_annotations_
void p_scossl_digest_freectx(SCOSSL_DIGEST_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->pState != NULL)
    {
        SCOSSL_COMMON_ALIGNED_FREE_EX(ctx->pState, OPENSSL_clear_free, SymCryptHashStateSize(ctx->pHash));
    }

    OPENSSL_free(ctx);
}

_Use_decl_annotations_
SCOSSL_DIGEST_CTX *p_scossl_digest_dupctx(SCOSSL_DIGEST_CTX *ctx)
{
    SCOSSL_DIGEST_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_DIGEST_CTX));

    if (copyCtx != NULL)
    {
        SCOSSL_COMMON_ALIGNED_ALLOC_EX(pStateTmp, OPENSSL_malloc, PVOID, SymCryptHashStateSize(ctx->pHash));
        if (pStateTmp == NULL)
        {
            OPENSSL_free(copyCtx);
            return NULL;
        }

        ctx->pHash->stateCopyFunc(ctx->pState, pStateTmp);
        copyCtx->pState = pStateTmp;

        copyCtx->pHash = ctx->pHash;
        copyCtx->xofLen = ctx->xofLen;
    }

    return copyCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_digest_get_params(OSSL_PARAM params[], size_t size, size_t blocksize, UINT32 flags)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, blocksize))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF)) != NULL &&
        !OSSL_PARAM_set_int(p, (flags & SCOSSL_DIGEST_FLAG_XOF) != 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT)) != NULL &&
        !OSSL_PARAM_set_int(p, (flags & SCOSSL_DIGEST_FLAG_ALGID_ABSENT) != 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_digest_gettable_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_digest_gettable_param_types;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_digest_update(SCOSSL_DIGEST_CTX *ctx,
                                     const unsigned char *in, size_t inl)
{
    SymCryptHashAppend(ctx->pHash, ctx->pState, in, inl);
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_digest_digest(PCSYMCRYPT_HASH pHash,
                                     const unsigned char *in, size_t inl,
                                     unsigned char *out, size_t *outl, size_t outlen)
{
    SIZE_T cbResult = SymCryptHashResultSize(pHash);

    if (outlen < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    SymCryptHash(pHash, in, inl, out, cbResult);
    *outl = cbResult;

    return SCOSSL_SUCCESS;
}