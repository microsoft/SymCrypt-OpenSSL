//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_digests.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MD5 */
typedef struct _SC_OSSL_MD_MD5_STATE {
    PSYMCRYPT_MD5_STATE state;
} SC_OSSL_MD_MD5_STATE, *PSC_OSSL_MD_MD5_STATE;
static int sc_ossl_digest_md5_init(EVP_MD_CTX *ctx);
static int sc_ossl_digest_md5_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sc_ossl_digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md);
static int sc_ossl_digest_md5_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int sc_ossl_digest_md5_cleanup(EVP_MD_CTX *ctx);
static EVP_MD *_hidden_md5_md = NULL;
static const EVP_MD *sc_ossl_digest_md5(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    if (_hidden_md5_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_md5, NID_md5WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, MD5_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, MD5_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SC_OSSL_MD_MD5_STATE))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, sc_ossl_digest_md5_init)
            || !EVP_MD_meth_set_update(md, sc_ossl_digest_md5_update)
            || !EVP_MD_meth_set_final(md, sc_ossl_digest_md5_final)
            || !EVP_MD_meth_set_copy(md, sc_ossl_digest_md5_copy)
            || !EVP_MD_meth_set_cleanup(md, sc_ossl_digest_md5_cleanup)
            )
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_md5_md = md;
    }
    return _hidden_md5_md;
}

/* SHA1 */
typedef struct _SC_OSSL_MD_SHA1_STATE {
    PSYMCRYPT_SHA1_STATE state;
} SC_OSSL_MD_SHA1_STATE, *PSC_OSSL_MD_SHA1_STATE;
static int sc_ossl_digest_sha1_init(EVP_MD_CTX *ctx);
static int sc_ossl_digest_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sc_ossl_digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);
static int sc_ossl_digest_sha1_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int sc_ossl_digest_sha1_cleanup(EVP_MD_CTX *ctx);
static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *sc_ossl_digest_sha1(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SC_OSSL_MD_SHA1_STATE))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, sc_ossl_digest_sha1_init)
            || !EVP_MD_meth_set_update(md, sc_ossl_digest_sha1_update)
            || !EVP_MD_meth_set_final(md, sc_ossl_digest_sha1_final)
            || !EVP_MD_meth_set_copy(md, sc_ossl_digest_sha1_copy)
            || !EVP_MD_meth_set_cleanup(md, sc_ossl_digest_sha1_cleanup)
            )
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}

/* SHA256 */
typedef struct _SC_OSSL_MD_SHA256_STATE {
    PSYMCRYPT_SHA256_STATE state;
} SC_OSSL_MD_SHA256_STATE, *PSC_OSSL_MD_SHA256_STATE;
static int sc_ossl_digest_sha256_init(EVP_MD_CTX *ctx);
static int sc_ossl_digest_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sc_ossl_digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
static int sc_ossl_digest_sha256_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int sc_ossl_digest_sha256_cleanup(EVP_MD_CTX *ctx);
static EVP_MD *_hidden_sha256_md = NULL;
static const EVP_MD *sc_ossl_digest_sha256(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    if (_hidden_sha256_md == NULL) {
        EVP_MD *md;
        if ((md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA256_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA256_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SC_OSSL_MD_SHA256_STATE))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, sc_ossl_digest_sha256_init)
            || !EVP_MD_meth_set_update(md, sc_ossl_digest_sha256_update)
            || !EVP_MD_meth_set_final(md, sc_ossl_digest_sha256_final)
            || !EVP_MD_meth_set_copy(md, sc_ossl_digest_sha256_copy)
            || !EVP_MD_meth_set_cleanup(md, sc_ossl_digest_sha256_cleanup)
            )
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha256_md = md;
    }
    return _hidden_sha256_md;
}

/* SHA384 */
typedef struct _SC_OSSL_MD_SHA384_STATE {
    PSYMCRYPT_SHA384_STATE state;
} SC_OSSL_MD_SHA384_STATE, *PSC_OSSL_MD_SHA384_STATE;
static int sc_ossl_digest_sha384_init(EVP_MD_CTX *ctx);
static int sc_ossl_digest_sha384_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sc_ossl_digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static int sc_ossl_digest_sha384_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int sc_ossl_digest_sha384_cleanup(EVP_MD_CTX *ctx);
static EVP_MD *_hidden_sha384_md = NULL;
static const EVP_MD *sc_ossl_digest_sha384(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    if (_hidden_sha384_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha384, NID_sha384WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA384_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SC_OSSL_MD_SHA384_STATE))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, sc_ossl_digest_sha384_init)
            || !EVP_MD_meth_set_update(md, sc_ossl_digest_sha384_update)
            || !EVP_MD_meth_set_final(md, sc_ossl_digest_sha384_final)
            || !EVP_MD_meth_set_copy(md, sc_ossl_digest_sha384_copy)
            || !EVP_MD_meth_set_cleanup(md, sc_ossl_digest_sha384_cleanup)
            )
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha384_md = md;
    }
    return _hidden_sha384_md;
}

/* SHA512 */
typedef struct _SC_OSSL_MD_SHA512_STATE {
    PSYMCRYPT_SHA512_STATE state;
} SC_OSSL_MD_SHA512_STATE, *PSC_OSSL_MD_SHA512_STATE;
static int sc_ossl_digest_sha512_init(EVP_MD_CTX *ctx);
static int sc_ossl_digest_sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sc_ossl_digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md);
static int sc_ossl_digest_sha512_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int sc_ossl_digest_sha512_cleanup(EVP_MD_CTX *ctx);
static EVP_MD *_hidden_sha512_md = NULL;
static const EVP_MD *sc_ossl_digest_sha512(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    if (_hidden_sha512_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha512, NID_sha512WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA512_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SC_OSSL_MD_SHA512_STATE))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, sc_ossl_digest_sha512_init)
            || !EVP_MD_meth_set_update(md, sc_ossl_digest_sha512_update)
            || !EVP_MD_meth_set_final(md, sc_ossl_digest_sha512_final)
            || !EVP_MD_meth_set_copy(md, sc_ossl_digest_sha512_copy)
            || !EVP_MD_meth_set_cleanup(md, sc_ossl_digest_sha512_cleanup)
            )
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha512_md = md;
    }
    return _hidden_sha512_md;
}
void sc_ossl_destroy_digests(void)
{
    SC_OSSL_LOG_DEBUG(NULL);
    EVP_MD_meth_free(_hidden_md5_md);
    _hidden_md5_md = NULL;
    EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
    EVP_MD_meth_free(_hidden_sha256_md);
    _hidden_sha256_md = NULL;
    EVP_MD_meth_free(_hidden_sha384_md);
    _hidden_sha384_md = NULL;
    EVP_MD_meth_free(_hidden_sha512_md);
    _hidden_sha512_md = NULL;
}
static int sc_ossl_digest_nids(const int **nids)
{
    SC_OSSL_LOG_DEBUG(NULL);
    static int sc_ossl_digest_nids[6] = { 0, 0, 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = sc_ossl_digest_md5()) != NULL)
            sc_ossl_digest_nids[pos++] = EVP_MD_type(md);
        if ((md = sc_ossl_digest_sha1()) != NULL)
            sc_ossl_digest_nids[pos++] = EVP_MD_type(md);
        if ((md = sc_ossl_digest_sha256()) != NULL)
            sc_ossl_digest_nids[pos++] = EVP_MD_type(md);
        if ((md = sc_ossl_digest_sha384()) != NULL)
            sc_ossl_digest_nids[pos++] = EVP_MD_type(md);
        if ((md = sc_ossl_digest_sha512()) != NULL)
            sc_ossl_digest_nids[pos++] = EVP_MD_type(md);
        sc_ossl_digest_nids[pos] = 0;
        init = 1;
    }
    *nids = sc_ossl_digest_nids;
    return pos;
}

int sc_ossl_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    SC_OSSL_LOG_DEBUG(NULL);
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return sc_ossl_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = sc_ossl_digest_md5();
        break;
    case NID_sha1:
        *digest = sc_ossl_digest_sha1();
        break;
    case NID_sha256:
        *digest = sc_ossl_digest_sha256();
        break;
    case NID_sha384:
        *digest = sc_ossl_digest_sha384();
        break;
    case NID_sha512:
        *digest = sc_ossl_digest_sha512();
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
static int sc_ossl_digest_md5_init(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_MD5_STATE md_state = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    md_state->state = (PSYMCRYPT_MD5_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_MD5_STATE));
    if (md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    SymCryptMd5Init(md_state->state);
    return 1;
}

static int sc_ossl_digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    SC_OSSL_LOG_DEBUG("Count: %d", count);
    PSC_OSSL_MD_MD5_STATE md_state = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptMd5Append(md_state->state, data, count);
    return 1;
}

static int sc_ossl_digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_MD5_STATE md_state = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptMd5Result(md_state->state, md);
    return 1;
}

static int sc_ossl_digest_md5_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_MD5_STATE md_state_to = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(to);
    PSC_OSSL_MD_MD5_STATE md_state_from = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(from);
    if (md_state_from == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD 'from' Present");
        return 1;
    }
    if (md_state_from->state == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD Symcrypt State Present in 'from'");
        return 1;
    }

    md_state_to->state = (PSYMCRYPT_MD5_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_MD5_STATE));
    if (md_state_to->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }

    SymCryptMd5StateCopy(md_state_from->state, md_state_to->state);
    return 1;
}

static int sc_ossl_digest_md5_cleanup(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_MD5_STATE md_state = (PSC_OSSL_MD_MD5_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state != NULL && md_state->state != NULL) {
        OPENSSL_free(md_state->state);
        md_state->state = NULL;
    }
    return 1;
}

/*
 * SHA1 implementation.
 */
static int sc_ossl_digest_sha1_init(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA1_STATE md_state = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    md_state->state = (PSYMCRYPT_SHA1_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA1_STATE));
    if (md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    SymCryptSha1Init(md_state->state);
    return 1;
}

static int sc_ossl_digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count)
{
    SC_OSSL_LOG_DEBUG("Count: %d", count);
    PSC_OSSL_MD_SHA1_STATE md_state = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha1Append(md_state->state, data, count);
    return 1;
}

static int sc_ossl_digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA1_STATE md_state = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha1Result(md_state->state, md);
    return 1;
}

static int sc_ossl_digest_sha1_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA1_STATE md_state_to = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(to);
    PSC_OSSL_MD_SHA1_STATE md_state_from = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(from);
    if (md_state_from == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD 'from' Present");
        return 1;
    }
    if (md_state_from->state == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD Symcrypt State Present in 'from'");
        return 1;
    }

    md_state_to->state = (PSYMCRYPT_SHA1_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA1_STATE));
    if (md_state_to->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }

    SymCryptSha1StateCopy(md_state_from->state, md_state_to->state);
    return 1;
}

static int sc_ossl_digest_sha1_cleanup(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA1_STATE md_state = (PSC_OSSL_MD_SHA1_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state != NULL && md_state->state != NULL) {
        OPENSSL_free(md_state->state);
        md_state->state = NULL;
    }
    return 1;
}


/*
 * SHA256 implementation.
 */
static int sc_ossl_digest_sha256_init(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA256_STATE md_state = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    md_state->state = (PSYMCRYPT_SHA256_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA256_STATE));
    if (md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    SymCryptSha256Init(md_state->state);
    return 1;
}

static int sc_ossl_digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    SC_OSSL_LOG_DEBUG("Count: %d", count);
    PSC_OSSL_MD_SHA256_STATE md_state = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha256Append(md_state->state, data, count);
    return 1;
}

static int sc_ossl_digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA256_STATE md_state = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha256Result(md_state->state, md);
    return 1;
}

static int sc_ossl_digest_sha256_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA256_STATE md_state_to = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(to);
    PSC_OSSL_MD_SHA256_STATE md_state_from = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(from);
    if (md_state_from == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD 'from' Present");
        return 1;
    }
    if (md_state_from->state == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD Symcrypt State Present in 'from'");
        return 1;
    }

    md_state_to->state = (PSYMCRYPT_SHA256_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA256_STATE));
    if (md_state_to->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }

    SymCryptSha256StateCopy(md_state_from->state, md_state_to->state);
    return 1;
}

static int sc_ossl_digest_sha256_cleanup(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA256_STATE md_state = (PSC_OSSL_MD_SHA256_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state != NULL && md_state->state != NULL) {
        OPENSSL_free(md_state->state);
        md_state->state = NULL;
    }
    return 1;
}

/*
 * SHA384 implementation.
 */
static int sc_ossl_digest_sha384_init(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA384_STATE md_state = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    md_state->state = (PSYMCRYPT_SHA384_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA384_STATE));
    if (md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    SymCryptSha384Init(md_state->state);
    return 1;
}

static int sc_ossl_digest_sha384_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    SC_OSSL_LOG_DEBUG("Count: %d", count);
    PSC_OSSL_MD_SHA384_STATE md_state = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha384Append(md_state->state, data, count);
    return 1;
}

static int sc_ossl_digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA384_STATE md_state = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha384Result(md_state->state, md);
    return 1;
}

static int sc_ossl_digest_sha384_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA384_STATE md_state_to = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(to);
    PSC_OSSL_MD_SHA384_STATE md_state_from = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(from);
    if (md_state_from == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD 'from' Present");
        return 1;
    }
    if (md_state_from->state == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD Symcrypt State Present in 'from'");
        return 1;
    }

    md_state_to->state = (PSYMCRYPT_SHA384_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA384_STATE));
    if (md_state_to->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }

    SymCryptSha384StateCopy(md_state_from->state, md_state_to->state);
    return 1;
}

static int sc_ossl_digest_sha384_cleanup(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA384_STATE md_state = (PSC_OSSL_MD_SHA384_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state != NULL && md_state->state != NULL) {
        OPENSSL_free(md_state->state);
        md_state->state = NULL;
    }
    return 1;
}


/*
 * SHA512 implementation.
 */
static int sc_ossl_digest_sha512_init(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA512_STATE md_state = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    md_state->state = (PSYMCRYPT_SHA512_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA512_STATE));
    if (md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }
    SymCryptSha512Init(md_state->state);
    return 1;
}

static int sc_ossl_digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    SC_OSSL_LOG_DEBUG("Count: %d", count);
    PSC_OSSL_MD_SHA512_STATE md_state = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha512Append(md_state->state, data, count);
    return 1;
}

static int sc_ossl_digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA512_STATE md_state = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state == NULL || md_state->state == NULL) {
        SC_OSSL_LOG_ERROR("No MD Data Present");
        return 0;
    }
    SymCryptSha512Result(md_state->state, md);
    return 1;
}

static int sc_ossl_digest_sha512_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA512_STATE md_state_to = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(to);
    PSC_OSSL_MD_SHA512_STATE md_state_from = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(from);
    if (md_state_from == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD 'from' Present");
        return 1;
    }
    if (md_state_from->state == NULL)  {
        SC_OSSL_LOG_DEBUG("No MD Symcrypt State Present in 'from'");
        return 1;
    }

    md_state_to->state = (PSYMCRYPT_SHA512_STATE)OPENSSL_zalloc(sizeof(SYMCRYPT_SHA512_STATE));
    if (md_state_to->state == NULL) {
        SC_OSSL_LOG_ERROR("Memory Allocation Error");
        return 0;
    }

    SymCryptSha512StateCopy(md_state_from->state, md_state_to->state);
    return 1;
}

static int sc_ossl_digest_sha512_cleanup(EVP_MD_CTX *ctx)
{
    SC_OSSL_LOG_DEBUG(NULL);
    PSC_OSSL_MD_SHA512_STATE md_state = (PSC_OSSL_MD_SHA512_STATE)EVP_MD_CTX_md_data(ctx);
    if (md_state != NULL && md_state->state != NULL) {
        OPENSSL_free(md_state->state);
        md_state->state = NULL;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif