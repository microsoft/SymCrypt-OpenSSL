//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_digests.h"

#ifdef __cplusplus
extern "C" {
#endif

static int sc_ossl_digest_nids[] = {
    NID_md5,
    NID_sha1,
    NID_sha256,
    NID_sha384,
    NID_sha512
};

/* MD5 */
static SCOSSL_STATUS sc_ossl_digest_md5_init(_Out_ EVP_MD_CTX *ctx);
static SCOSSL_STATUS sc_ossl_digest_md5_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data, size_t count);
static SCOSSL_STATUS sc_ossl_digest_md5_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_MD5_RESULT_SIZE) unsigned char *md);
static SCOSSL_STATUS sc_ossl_digest_md5_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from);
static EVP_MD *_hidden_md5_md = NULL;
static const EVP_MD *sc_ossl_digest_md5(void)
{
    if ((_hidden_md5_md = EVP_MD_meth_new(NID_md5, NID_md5WithRSAEncryption)) == NULL
        || !EVP_MD_meth_set_result_size(_hidden_md5_md, MD5_DIGEST_LENGTH)
        || !EVP_MD_meth_set_input_blocksize(_hidden_md5_md, MD5_CBLOCK)
        || !EVP_MD_meth_set_app_datasize(_hidden_md5_md, sizeof(SYMCRYPT_MD5_STATE))
        || !EVP_MD_meth_set_flags(_hidden_md5_md, 0)
        || !EVP_MD_meth_set_init(_hidden_md5_md, sc_ossl_digest_md5_init)
        || !EVP_MD_meth_set_update(_hidden_md5_md, sc_ossl_digest_md5_update)
        || !EVP_MD_meth_set_final(_hidden_md5_md, sc_ossl_digest_md5_final)
        || !EVP_MD_meth_set_copy(_hidden_md5_md, sc_ossl_digest_md5_copy)
        )
    {
        EVP_MD_meth_free(_hidden_md5_md);
        _hidden_md5_md = NULL;
    }
    return _hidden_md5_md;
}

/* SHA1 */
static SCOSSL_STATUS sc_ossl_digest_sha1_init(_Out_ EVP_MD_CTX *ctx);
static SCOSSL_STATUS sc_ossl_digest_sha1_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data, size_t count);
static SCOSSL_STATUS sc_ossl_digest_sha1_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA1_RESULT_SIZE) unsigned char *md);
static SCOSSL_STATUS sc_ossl_digest_sha1_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from);
static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *sc_ossl_digest_sha1(void)
{
    if( (_hidden_sha1_md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
        || !EVP_MD_meth_set_result_size(_hidden_sha1_md, SHA_DIGEST_LENGTH)
        || !EVP_MD_meth_set_input_blocksize(_hidden_sha1_md, SHA_CBLOCK)
        || !EVP_MD_meth_set_app_datasize(_hidden_sha1_md, sizeof(SYMCRYPT_SHA1_STATE))
        || !EVP_MD_meth_set_flags(_hidden_sha1_md, EVP_MD_FLAG_DIGALGID_ABSENT)
        || !EVP_MD_meth_set_init(_hidden_sha1_md, sc_ossl_digest_sha1_init)
        || !EVP_MD_meth_set_update(_hidden_sha1_md, sc_ossl_digest_sha1_update)
        || !EVP_MD_meth_set_final(_hidden_sha1_md, sc_ossl_digest_sha1_final)
        || !EVP_MD_meth_set_copy(_hidden_sha1_md, sc_ossl_digest_sha1_copy)
        )
    {
        EVP_MD_meth_free(_hidden_sha1_md);
        _hidden_sha1_md = NULL;
    }
    return _hidden_sha1_md;
}

/* SHA256 */
static SCOSSL_STATUS sc_ossl_digest_sha256_init(_Out_ EVP_MD_CTX *ctx);
static SCOSSL_STATUS sc_ossl_digest_sha256_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data, size_t count);
static SCOSSL_STATUS sc_ossl_digest_sha256_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA256_RESULT_SIZE) unsigned char *md);
static SCOSSL_STATUS sc_ossl_digest_sha256_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from);
static EVP_MD *_hidden_sha256_md = NULL;
static const EVP_MD *sc_ossl_digest_sha256(void)
{
    if( (_hidden_sha256_md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
        || !EVP_MD_meth_set_result_size(_hidden_sha256_md, SHA256_DIGEST_LENGTH)
        || !EVP_MD_meth_set_input_blocksize(_hidden_sha256_md, SHA256_CBLOCK)
        || !EVP_MD_meth_set_app_datasize(_hidden_sha256_md, sizeof(SYMCRYPT_SHA256_STATE))
        || !EVP_MD_meth_set_flags(_hidden_sha256_md, EVP_MD_FLAG_DIGALGID_ABSENT)
        || !EVP_MD_meth_set_init(_hidden_sha256_md, sc_ossl_digest_sha256_init)
        || !EVP_MD_meth_set_update(_hidden_sha256_md, sc_ossl_digest_sha256_update)
        || !EVP_MD_meth_set_final(_hidden_sha256_md, sc_ossl_digest_sha256_final)
        || !EVP_MD_meth_set_copy(_hidden_sha256_md, sc_ossl_digest_sha256_copy)
        )
    {
        EVP_MD_meth_free(_hidden_sha256_md);
        _hidden_sha256_md = NULL;
    }
    return _hidden_sha256_md;
}

/* SHA384 */
static SCOSSL_STATUS sc_ossl_digest_sha384_init(_Out_ EVP_MD_CTX *ctx);
static SCOSSL_STATUS sc_ossl_digest_sha384_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data, size_t count);
static SCOSSL_STATUS sc_ossl_digest_sha384_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA384_RESULT_SIZE) unsigned char *md);
static SCOSSL_STATUS sc_ossl_digest_sha384_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from);
static EVP_MD *_hidden_sha384_md = NULL;
static const EVP_MD *sc_ossl_digest_sha384(void)
{
    if( (_hidden_sha384_md = EVP_MD_meth_new(NID_sha384, NID_sha384WithRSAEncryption)) == NULL
        || !EVP_MD_meth_set_result_size(_hidden_sha384_md, SHA384_DIGEST_LENGTH)
        || !EVP_MD_meth_set_input_blocksize(_hidden_sha384_md, SHA512_CBLOCK)
        || !EVP_MD_meth_set_app_datasize(_hidden_sha384_md, sizeof(SYMCRYPT_SHA384_STATE))
        || !EVP_MD_meth_set_flags(_hidden_sha384_md, EVP_MD_FLAG_DIGALGID_ABSENT)
        || !EVP_MD_meth_set_init(_hidden_sha384_md, sc_ossl_digest_sha384_init)
        || !EVP_MD_meth_set_update(_hidden_sha384_md, sc_ossl_digest_sha384_update)
        || !EVP_MD_meth_set_final(_hidden_sha384_md, sc_ossl_digest_sha384_final)
        || !EVP_MD_meth_set_copy(_hidden_sha384_md, sc_ossl_digest_sha384_copy)
        )
    {
        EVP_MD_meth_free(_hidden_sha384_md);
        _hidden_sha384_md = NULL;
    }
    return _hidden_sha384_md;
}

/* SHA512 */
static SCOSSL_STATUS sc_ossl_digest_sha512_init(_Out_ EVP_MD_CTX *ctx);
static SCOSSL_STATUS sc_ossl_digest_sha512_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data, size_t count);
static SCOSSL_STATUS sc_ossl_digest_sha512_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA512_RESULT_SIZE) unsigned char *md);
static SCOSSL_STATUS sc_ossl_digest_sha512_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from);
static EVP_MD *_hidden_sha512_md = NULL;
static const EVP_MD *sc_ossl_digest_sha512(void)
{
    if( (_hidden_sha512_md = EVP_MD_meth_new(NID_sha512, NID_sha512WithRSAEncryption)) == NULL
        || !EVP_MD_meth_set_result_size(_hidden_sha512_md, SHA512_DIGEST_LENGTH)
        || !EVP_MD_meth_set_input_blocksize(_hidden_sha512_md, SHA512_CBLOCK)
        || !EVP_MD_meth_set_app_datasize(_hidden_sha512_md, sizeof(SYMCRYPT_SHA512_STATE))
        || !EVP_MD_meth_set_flags(_hidden_sha512_md, EVP_MD_FLAG_DIGALGID_ABSENT)
        || !EVP_MD_meth_set_init(_hidden_sha512_md, sc_ossl_digest_sha512_init)
        || !EVP_MD_meth_set_update(_hidden_sha512_md, sc_ossl_digest_sha512_update)
        || !EVP_MD_meth_set_final(_hidden_sha512_md, sc_ossl_digest_sha512_final)
        || !EVP_MD_meth_set_copy(_hidden_sha512_md, sc_ossl_digest_sha512_copy)
        )
    {
        EVP_MD_meth_free(_hidden_sha512_md);
        _hidden_sha512_md = NULL;
    }
    return _hidden_sha512_md;
}

void sc_ossl_destroy_digests(void)
{
    EVP_MD_meth_free(_hidden_md5_md);
    EVP_MD_meth_free(_hidden_sha1_md);
    EVP_MD_meth_free(_hidden_sha256_md);
    EVP_MD_meth_free(_hidden_sha384_md);
    EVP_MD_meth_free(_hidden_sha512_md);
    _hidden_md5_md = NULL;
    _hidden_sha1_md = NULL;
    _hidden_sha256_md = NULL;
    _hidden_sha384_md = NULL;
    _hidden_sha512_md = NULL;
}

SCOSSL_STATUS scossl_digests_init_static()
{
    if( (sc_ossl_digest_md5() == NULL) ||
        (sc_ossl_digest_sha1() == NULL) ||
        (sc_ossl_digest_sha256() == NULL) ||
        (sc_ossl_digest_sha384() == NULL) ||
        (sc_ossl_digest_sha512() == NULL) )
    {
        return 0;
    }
    return 1;
}

_Success_(return > 0)
int sc_ossl_digests(_Inout_ ENGINE *e, _Out_opt_ const EVP_MD **digest,
                          _Out_opt_ const int **nids, int nid)
{
    int ok = 1;
    if( !digest )
    {
        /* We are returning a list of supported nids */
        *nids = sc_ossl_digest_nids;
        return (sizeof(sc_ossl_digest_nids))
               / sizeof(sc_ossl_digest_nids[0]);
    }

    /* We are being asked for a specific digest */
    switch (nid)
    {
    case NID_md5:
        *digest = _hidden_md5_md;
        break;
    case NID_sha1:
        *digest = _hidden_sha1_md;
        break;
    case NID_sha256:
        *digest = _hidden_sha256_md;
        break;
    case NID_sha384:
        *digest = _hidden_sha384_md;
        break;
    case NID_sha512:
        *digest = _hidden_sha512_md;
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

/*
 * MD5 implementation.
 */
static SCOSSL_STATUS sc_ossl_digest_md5_init(_Out_ EVP_MD_CTX *ctx)
{
    PSYMCRYPT_MD5_STATE state = (PSYMCRYPT_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptMd5Init(state);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_md5_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data,
                             size_t count)
{
    PSYMCRYPT_MD5_STATE state = (PSYMCRYPT_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptMd5Append(state, data, count);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_md5_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_MD5_RESULT_SIZE) unsigned char *md)
{
    PSYMCRYPT_MD5_STATE state = (PSYMCRYPT_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptMd5Result(state, md);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_md5_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from)
{
    PSYMCRYPT_MD5_STATE state_to = (PSYMCRYPT_MD5_STATE)EVP_MD_CTX_md_data(to);
    PSYMCRYPT_MD5_STATE state_from = (PSYMCRYPT_MD5_STATE)EVP_MD_CTX_md_data(from);
    if( state_to == NULL )
    {
        return 1;
    }
    if( state_from == NULL )
    {
        return 1;
    }

    SymCryptMd5StateCopy(state_from, state_to);
    return 1;
}

/*
 * SHA1 implementation.
 */
static SCOSSL_STATUS sc_ossl_digest_sha1_init(_Out_ EVP_MD_CTX *ctx)
{
    PSYMCRYPT_SHA1_STATE state = (PSYMCRYPT_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha1Init(state);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha1_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data,
                              size_t count)
{
    PSYMCRYPT_SHA1_STATE state = (PSYMCRYPT_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha1Append(state, data, count);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha1_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA1_RESULT_SIZE) unsigned char *md)
{
    PSYMCRYPT_SHA1_STATE state = (PSYMCRYPT_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha1Result(state, md);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha1_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from)
{
    PSYMCRYPT_SHA1_STATE state_to = (PSYMCRYPT_SHA1_STATE)EVP_MD_CTX_md_data(to);
    PSYMCRYPT_SHA1_STATE state_from = (PSYMCRYPT_SHA1_STATE)EVP_MD_CTX_md_data(from);
    if( state_to == NULL )
    {
        return 1;
    }
    if( state_from == NULL )
    {
        return 1;
    }

    SymCryptSha1StateCopy(state_from, state_to);
    return 1;
}


/*
 * SHA256 implementation.
 */
static SCOSSL_STATUS sc_ossl_digest_sha256_init(_Out_ EVP_MD_CTX *ctx)
{
    PSYMCRYPT_SHA256_STATE state = (PSYMCRYPT_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha256Init(state);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha256_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data,
                                size_t count)
{
    PSYMCRYPT_SHA256_STATE state = (PSYMCRYPT_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha256Append(state, data, count);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha256_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA256_RESULT_SIZE) unsigned char *md)
{
    PSYMCRYPT_SHA256_STATE state = (PSYMCRYPT_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha256Result(state, md);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha256_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from)
{
    PSYMCRYPT_SHA256_STATE state_to = (PSYMCRYPT_SHA256_STATE)EVP_MD_CTX_md_data(to);
    PSYMCRYPT_SHA256_STATE state_from = (PSYMCRYPT_SHA256_STATE)EVP_MD_CTX_md_data(from);
    if( state_to == NULL )
    {
        return 1;
    }
    if( state_from == NULL )
    {
        return 1;
    }

    SymCryptSha256StateCopy(state_from, state_to);
    return 1;
}

/*
 * SHA384 implementation.
 */
static SCOSSL_STATUS sc_ossl_digest_sha384_init(_Out_ EVP_MD_CTX *ctx)
{
    PSYMCRYPT_SHA384_STATE state = (PSYMCRYPT_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha384Init(state);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha384_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data,
                                size_t count)
{
    PSYMCRYPT_SHA384_STATE state = (PSYMCRYPT_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha384Append(state, data, count);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha384_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA384_RESULT_SIZE) unsigned char *md)
{
    PSYMCRYPT_SHA384_STATE state = (PSYMCRYPT_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha384Result(state, md);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha384_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from)
{
    PSYMCRYPT_SHA384_STATE state_to = (PSYMCRYPT_SHA384_STATE)EVP_MD_CTX_md_data(to);
    PSYMCRYPT_SHA384_STATE state_from = (PSYMCRYPT_SHA384_STATE)EVP_MD_CTX_md_data(from);
    if( state_to == NULL )
    {
        return 1;
    }
    if( state_from == NULL )
    {
        return 1;
    }

    SymCryptSha384StateCopy(state_from, state_to);
    return 1;
}

/*
 * SHA512 implementation.
 */
static SCOSSL_STATUS sc_ossl_digest_sha512_init(_Out_ EVP_MD_CTX *ctx)
{
    PSYMCRYPT_SHA512_STATE state = (PSYMCRYPT_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha512Init(state);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha512_update(_Inout_ EVP_MD_CTX *ctx, _In_reads_bytes_(count) const void *data,
                                size_t count)
{
    PSYMCRYPT_SHA512_STATE state = (PSYMCRYPT_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha512Append(state, data, count);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha512_final(_Inout_ EVP_MD_CTX *ctx, _Out_writes_(SYMCRYPT_SHA512_RESULT_SIZE) unsigned char *md)
{
    PSYMCRYPT_SHA512_STATE state = (PSYMCRYPT_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if( state == NULL )
    {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }

    SymCryptSha512Result(state, md);
    return 1;
}

static SCOSSL_STATUS sc_ossl_digest_sha512_copy(_Out_ EVP_MD_CTX *to, _In_ const EVP_MD_CTX *from)
{
    PSYMCRYPT_SHA512_STATE state_to = (PSYMCRYPT_SHA512_STATE)EVP_MD_CTX_md_data(to);
    PSYMCRYPT_SHA512_STATE state_from = (PSYMCRYPT_SHA512_STATE)EVP_MD_CTX_md_data(from);
    if( state_to == NULL )
    {
        return 1;
    }
    if( state_from == NULL )
    {
        return 1;
    }

    SymCryptSha512StateCopy(state_from, state_to);
    return 1;
}

#ifdef __cplusplus
}
#endif