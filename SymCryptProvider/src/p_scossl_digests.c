//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_digests.h"

#include <openssl/core_names.h>

#ifdef __cplusplus
extern "C" {
#endif

static const OSSL_PARAM scossl_digest_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL)};

const OSSL_PARAM *scossl_digest_gettable_params_generic(_Inout_ void *dctx, _In_ void *provctx)
{
    return scossl_digest_param_types;
}

SCOSSL_STATUS scossl_digest_get_params_generic(_Inout_ OSSL_PARAM params[], size_t blocksize, size_t size)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blocksize))
    {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
    {
        return 0;
    }
    return SCOSSL_SUCCESS;
}

IMPLEMENT_SCOSSL_DIGEST(md5, Md5, MD5);
IMPLEMENT_SCOSSL_DIGEST(sha1, Sha1, SHA1);
IMPLEMENT_SCOSSL_DIGEST(sha256, Sha256, SHA256);
IMPLEMENT_SCOSSL_DIGEST(sha384, Sha384, SHA384);
IMPLEMENT_SCOSSL_DIGEST(sha512, Sha512, SHA512);
IMPLEMENT_SCOSSL_DIGEST(sha3_256, Sha3_256, SHA3_256);
IMPLEMENT_SCOSSL_DIGEST(sha3_384, Sha3_384, SHA3_384);
IMPLEMENT_SCOSSL_DIGEST(sha3_512, Sha3_512, SHA3_512);

#ifdef __cplusplus
}
#endif