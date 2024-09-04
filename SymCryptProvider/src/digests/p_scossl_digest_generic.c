//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "digests/p_scossl_digest_common.h"

#ifdef __cplusplus
extern "C" {
#endif

static SCOSSL_STATUS p_scossl_digest_generic_init(_Inout_ SCOSSL_DIGEST_CTX *ctx, ossl_unused const OSSL_PARAM params[])
{
    SymCryptHashInit(ctx->pHash, ctx->pState);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_generic_final(_In_ SCOSSL_DIGEST_CTX *ctx,
                                                   _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    SIZE_T cbResult = SymCryptHashResultSize(ctx->pHash);

    if (outlen < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    SymCryptHashResult(ctx->pHash, ctx->pState, out, cbResult);
    *outl = cbResult;

    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_DIGEST_GENERIC(alg, dispatch_name, flags)           \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name, flags)                \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_digest_generic_init},   \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_digest_generic_final}, \
    SCOSSL_DIGEST_FUNCTIONS_END

// MD5 and SHA1, supported for compatability
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Md5, md5, 0)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha1, sha1, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

// SHA2
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha256, sha256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha384, sha384, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha512, sha512, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

//SHA3
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_256, sha3_256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_384, sha3_384, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_512, sha3_512, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

#ifdef __cplusplus
}
#endif