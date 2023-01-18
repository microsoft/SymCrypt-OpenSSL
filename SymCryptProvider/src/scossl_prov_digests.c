#include "scossl_prov_digests.h"

static const OSSL_PARAM scossl_prov_digest_param_types[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL)};

const OSSL_PARAM *scossl_prov_digest_gettable_params(void *dctx, void *provctx)
{
    return scossl_prov_digest_param_types;
}

SCOSSL_STATUS scossl_prov_digest_get_params_common(OSSL_PARAM params[], size_t blocksize, size_t size)
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

IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Md5, SYMCRYPT_MD5_STATE, SYMCRYPT_MD5_INPUT_BLOCK_SIZE, SYMCRYPT_MD5_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha1, SYMCRYPT_SHA1_STATE, SYMCRYPT_SHA1_INPUT_BLOCK_SIZE, SYMCRYPT_SHA1_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha256, SYMCRYPT_SHA256_STATE, SYMCRYPT_SHA256_INPUT_BLOCK_SIZE, SYMCRYPT_SHA256_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha384, SYMCRYPT_SHA384_STATE, SYMCRYPT_SHA384_INPUT_BLOCK_SIZE, SYMCRYPT_SHA384_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha512, SYMCRYPT_SHA512_STATE, SYMCRYPT_SHA512_INPUT_BLOCK_SIZE, SYMCRYPT_SHA512_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha3_256, SYMCRYPT_SHA3_256_STATE, SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE, SYMCRYPT_SHA3_256_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha3_384, SYMCRYPT_SHA3_384_STATE, SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE, SYMCRYPT_SHA3_384_RESULT_SIZE);
IMPLEMENT_SCOSSL_DIGEST_FUNCTIONS(Sha3_512, SYMCRYPT_SHA3_512_STATE, SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE, SYMCRYPT_SHA3_512_RESULT_SIZE);