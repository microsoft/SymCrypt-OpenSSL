//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_ciphers.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cipher_cbc_ctx {
    INT32 enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_ecb_ctx {
    INT32 enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_xts_ctx {
    INT32 enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
};

#define SC_OSSL_GCM_IV_LENGTH      12

struct cipher_gcm_ctx {
    INT32 enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    INT32 operationInProgress;
    BYTE iv[SC_OSSL_GCM_IV_LENGTH];
    SYMCRYPT_GCM_STATE state;
    SYMCRYPT_GCM_EXPANDED_KEY key;
    BYTE tag[EVP_GCM_TLS_TAG_LEN];
    INT32 taglen;
    BYTE tlsAad[EVP_AEAD_TLS1_AAD_LEN];
    INT32 tlsAadSet;
};


static int sc_ossl_cipher_nids[] = {
    NID_aes_128_cbc,
    NID_aes_192_cbc,
    NID_aes_256_cbc,

    NID_aes_128_ecb,
    NID_aes_192_ecb,
    NID_aes_256_ecb,

    // Disabling XTS for now.
    // EVP API provides tweaks of 16B, while in SymCrypt we take 8B tweaks.
    // Need to read up on the spec to determine if we can safely truncate the provided tweak from
    // the EVP API.
    // Also need to push the FIPS mode XTS flag into the SymCrypt API, and expose an XTS key copy
    // method
    // NID_aes_128_xts,
    // NID_aes_256_xts,

    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
};

int sc_ossl_aes_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sc_ossl_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int sc_ossl_aes_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32
#define AES_CBC_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE|EVP_CIPH_CUSTOM_COPY \
                         |EVP_CIPH_ALWAYS_CALL_INIT)

/* AES128 - CBC */
static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *sc_ossl_aes_128_cbc(void)
{
    if( _hidden_aes_128_cbc == NULL
        && ((_hidden_aes_128_cbc = EVP_CIPHER_meth_new(NID_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc, AES_CBC_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc, sc_ossl_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc, sc_ossl_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc, sc_ossl_aes_cbc_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc, sizeof(struct cipher_cbc_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}

/* AES192 - CBC */
static EVP_CIPHER *_hidden_aes_192_cbc = NULL;
static const EVP_CIPHER *sc_ossl_aes_192_cbc(void)
{
    if( _hidden_aes_192_cbc == NULL
        && ((_hidden_aes_192_cbc = EVP_CIPHER_meth_new(NID_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_cbc, AES_CBC_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_cbc, sc_ossl_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_cbc, sc_ossl_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_cbc, sc_ossl_aes_cbc_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_cbc, sizeof(struct cipher_cbc_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
        _hidden_aes_192_cbc = NULL;
    }
    return _hidden_aes_192_cbc;
}

/* AES256 - CBC */
static EVP_CIPHER *_hidden_aes_256_cbc = NULL;
static const EVP_CIPHER *sc_ossl_aes_256_cbc(void)
{
    if( _hidden_aes_256_cbc == NULL
        && ((_hidden_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc, AES_CBC_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc, sc_ossl_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc, sc_ossl_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc, sc_ossl_aes_cbc_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc, sizeof(struct cipher_cbc_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
        _hidden_aes_256_cbc = NULL;
    }
    return _hidden_aes_256_cbc;
}

int sc_ossl_aes_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sc_ossl_aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int sc_ossl_aes_ecb_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
#define AES_ECB_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE|EVP_CIPH_CUSTOM_COPY)

/* AES128 - ecb */
static EVP_CIPHER *_hidden_aes_128_ecb = NULL;
static const EVP_CIPHER *sc_ossl_aes_128_ecb(void)
{
    if( _hidden_aes_128_ecb == NULL
        && ((_hidden_aes_128_ecb = EVP_CIPHER_meth_new(NID_aes_128_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_ecb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ecb, AES_ECB_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ecb, sc_ossl_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ecb, sc_ossl_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_ecb, sc_ossl_aes_ecb_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ecb, sizeof(struct cipher_ecb_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
        _hidden_aes_128_ecb = NULL;
    }
    return _hidden_aes_128_ecb;
}

/* AES192 - ecb */
static EVP_CIPHER *_hidden_aes_192_ecb = NULL;
static const EVP_CIPHER *sc_ossl_aes_192_ecb(void)
{
    if( _hidden_aes_192_ecb == NULL
        && ((_hidden_aes_192_ecb = EVP_CIPHER_meth_new(NID_aes_192_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_ecb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ecb, AES_ECB_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ecb, sc_ossl_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ecb, sc_ossl_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_ecb, sc_ossl_aes_ecb_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ecb, sizeof(struct cipher_ecb_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
        _hidden_aes_192_ecb = NULL;
    }
    return _hidden_aes_192_ecb;
}

/* AES256 - ecb */
static EVP_CIPHER *_hidden_aes_256_ecb = NULL;
static const EVP_CIPHER *sc_ossl_aes_256_ecb(void)
{
    if( _hidden_aes_256_ecb == NULL
        && ((_hidden_aes_256_ecb = EVP_CIPHER_meth_new(NID_aes_256_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_ecb, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ecb, AES_ECB_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ecb, sc_ossl_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ecb, sc_ossl_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_ecb, sc_ossl_aes_ecb_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ecb, sizeof(struct cipher_ecb_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
        _hidden_aes_256_ecb = NULL;
    }
    return _hidden_aes_256_ecb;
}


int sc_ossl_aes_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sc_ossl_aes_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int sc_ossl_aes_xts_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
#define AES_XTS_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_XTS_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_FLAG_CUSTOM_CIPHER)

/* AES128 - XTS */
static EVP_CIPHER *_hidden_aes_128_xts = NULL;
static const EVP_CIPHER *sc_ossl_aes_128_xts(void)
{
    if( _hidden_aes_128_xts == NULL
        && ((_hidden_aes_128_xts = EVP_CIPHER_meth_new(NID_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE * 2)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_xts, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_xts, AES_XTS_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_xts, sc_ossl_aes_xts_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_xts, sc_ossl_aes_xts_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_xts, sc_ossl_aes_xts_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_xts, sizeof(struct cipher_xts_ctx))) )
    {
        SC_OSSL_LOG_ERROR("CIPHER Initialization Failed");
        EVP_CIPHER_meth_free(_hidden_aes_128_xts);
        _hidden_aes_128_xts = NULL;
    }
    return _hidden_aes_128_xts;
}

/* AES256 - XTS */
static EVP_CIPHER *_hidden_aes_256_xts = NULL;
static const EVP_CIPHER *sc_ossl_aes_256_xts(void)
{
    if( _hidden_aes_256_xts == NULL
        && ((_hidden_aes_256_xts = EVP_CIPHER_meth_new(NID_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE * 2)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_xts, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_xts, AES_XTS_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_xts, sc_ossl_aes_xts_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_xts, sc_ossl_aes_xts_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_xts, sc_ossl_aes_xts_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_xts, sizeof(struct cipher_xts_ctx))) )
    {
        SC_OSSL_LOG_ERROR("CIPHER Initialization Failed");
        EVP_CIPHER_meth_free(_hidden_aes_256_xts);
        _hidden_aes_256_xts = NULL;
    }
    return _hidden_aes_256_xts;
}

int sc_ossl_aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sc_ossl_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int sc_ossl_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_GCM_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_FLAG_CUSTOM_CIPHER|EVP_CIPH_ALWAYS_CALL_INIT \
                        |EVP_CIPH_CTRL_INIT|EVP_CIPH_FLAG_AEAD_CIPHER)

/* AES128 - GCM */
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;
static const EVP_CIPHER *sc_ossl_aes_128_gcm(void)
{
    if( _hidden_aes_128_gcm == NULL
        && ((_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm, sc_ossl_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm, sc_ossl_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, sc_ossl_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm, sizeof(struct cipher_gcm_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

/* AES192 - GCM */
static EVP_CIPHER *_hidden_aes_192_gcm = NULL;
static const EVP_CIPHER *sc_ossl_aes_192_gcm(void)
{
    if( _hidden_aes_192_gcm == NULL
        && ((_hidden_aes_192_gcm = EVP_CIPHER_meth_new(NID_aes_192_gcm, 1, AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_gcm, sc_ossl_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_gcm, sc_ossl_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_gcm, sc_ossl_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_gcm, sizeof(struct cipher_gcm_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_gcm);
        _hidden_aes_192_gcm = NULL;
    }
    return _hidden_aes_192_gcm;
}

/* AES256 - GCM */
static EVP_CIPHER *_hidden_aes_256_gcm = NULL;
static const EVP_CIPHER *sc_ossl_aes_256_gcm(void)
{
    if( _hidden_aes_256_gcm == NULL
        && ((_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1, AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm, sc_ossl_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm, sc_ossl_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, sc_ossl_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm, sizeof(struct cipher_gcm_ctx))) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
        _hidden_aes_256_gcm = NULL;
    }
    return _hidden_aes_256_gcm;
}


void sc_ossl_destroy_ciphers(void)
{
    EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
    EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
    EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
    // EVP_CIPHER_meth_free(_hidden_aes_128_xts);
    // EVP_CIPHER_meth_free(_hidden_aes_256_xts);
    EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
    EVP_CIPHER_meth_free(_hidden_aes_192_gcm);
    EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
    _hidden_aes_128_cbc = NULL;
    _hidden_aes_192_cbc = NULL;
    _hidden_aes_256_cbc = NULL;
    _hidden_aes_128_ecb = NULL;
    _hidden_aes_192_ecb = NULL;
    _hidden_aes_256_ecb = NULL;
    _hidden_aes_128_xts = NULL;
    _hidden_aes_256_xts = NULL;
    _hidden_aes_128_gcm = NULL;
    _hidden_aes_192_gcm = NULL;
    _hidden_aes_256_gcm = NULL;
}

int sc_ossl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                     const int **nids, int nid)
{
    int ok = 1;
    if( !cipher )
    {
        /* We are returning a list of supported nids */
        *nids = sc_ossl_cipher_nids;
        return (sizeof(sc_ossl_cipher_nids))
               / sizeof(sc_ossl_cipher_nids[0]);
    }

    /* We are being asked for a specific cipher */
    switch( nid )
    {
    case NID_aes_128_cbc:
        *cipher = sc_ossl_aes_128_cbc();
        break;
    case NID_aes_192_cbc:
        *cipher = sc_ossl_aes_192_cbc();
        break;
    case NID_aes_256_cbc:
        *cipher = sc_ossl_aes_256_cbc();
        break;
    case NID_aes_128_ecb:
        *cipher = sc_ossl_aes_128_ecb();
        break;
    case NID_aes_192_ecb:
        *cipher = sc_ossl_aes_192_ecb();
        break;
    case NID_aes_256_ecb:
        *cipher = sc_ossl_aes_256_ecb();
        break;
    // case NID_aes_128_xts:
    //     *cipher = sc_ossl_aes_128_xts();
    //     break;
    // case NID_aes_256_xts:
    //     *cipher = sc_ossl_aes_256_xts();
    //     break;
    case NID_aes_128_gcm:
        *cipher = sc_ossl_aes_128_gcm();
        break;
    case NID_aes_192_gcm:
        *cipher = sc_ossl_aes_192_gcm();
        break;
    case NID_aes_256_gcm:
        *cipher = sc_ossl_aes_256_gcm();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

/*
 * AES-CBC Implementation
 */
 
// Initializes ctx with the provided key and iv, along with enc/dec mode.
// enc should be set to 1 for encryption, 0 for decryption, and -1 to leave value unchanged.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_cbc_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, int enc)
{
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    PBYTE ctx_iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    cipherCtx->enc = enc;
    if( iv )
    {
        memcpy(ctx_iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    if( key )
    {
        SymError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or ecrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_cbc_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    PBYTE ctx_iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    if( cipherCtx->enc )
    {
        SymCryptAesCbcEncrypt(&cipherCtx->key, ctx_iv, in, out, inl);
    }
    else
    {
        SymCryptAesCbcDecrypt(&cipherCtx->key, ctx_iv, in, out, inl);
    }

    ret = 1;

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS sc_ossl_aes_cbc_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_cbc_ctx *srcCtx;
    struct cipher_cbc_ctx *dstCtx;
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        srcCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(                  ctx);
        dstCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptAesKeyCopy(&srcCtx->key, &dstCtx->key);
        break;
    default:
        return 0;
    }
    return 1;
}

/*
 * AES-ECB Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// enc should be set to 1 for encryption, 0 for decryption, and -1 to leave value unchanged.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_ecb_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, int enc)
{
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    cipherCtx->enc = enc;
    if( key )
    {
        SymError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or ecrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_ecb_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if( cipherCtx->enc )
    {
        SymCryptAesEcbEncrypt(&cipherCtx->key, in, out, inl);
    }
    else
    {
        SymCryptAesEcbDecrypt(&cipherCtx->key, in, out, inl);
    }
    ret = 1;

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS sc_ossl_aes_ecb_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_cbc_ctx *srcCtx;
    struct cipher_cbc_ctx *dstCtx;
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        srcCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(                  ctx);
        dstCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptAesKeyCopy(&srcCtx->key, &dstCtx->key);
        break;
    default:
        return 0;
    }
    return 1;
}

/*
 * AES-XTS Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// enc should be set to 1 for encryption, 0 for decryption, and -1 to leave value unchanged.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_xts_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, int enc)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    cipherCtx->enc = enc;
    if( iv )
    {
        memcpy(cipherCtx->iv, iv, 8); // copy only the first 8B
        // check bytes 8-15 are all zero?
    }
    else
    {
        return 0;
    }
    if( key )
    {
        SymError = SymCryptXtsAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or ecrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_xts_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if( inl > 0 )
    {
        if( (inl % 16) != 0 )
        {
            SC_OSSL_LOG_ERROR("Data length (%d) is not a multiple of the AES block size. SymCrypt does not support this size", inl);
            return -1;
        }

        // It appears that the EVP API for exposing AES-XTS does not allow definition of the size of
        // a data unit. My understanding is that callers are expected to make a single call through
        // the EVP interface per data unit - so we pass inl to both cbDataUnit and cbData.

        if( cipherCtx->enc )
        {
            SymCryptXtsAesEncrypt(
                &cipherCtx->key,
                inl,
                *(UINT64 *) cipherCtx->iv,
                in,
                out,
                inl);
        }
        else
        {
            SymCryptXtsAesDecrypt(
                &cipherCtx->key,
                inl,
                *(UINT64 *) cipherCtx->iv,
                in,
                out,
                inl);
        }
        ret = 1;
    }

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS sc_ossl_aes_xts_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        SC_OSSL_LOG_ERROR("No copy method currently implemented");
        // We need a SymCryptXtsKeyCopy function for this as we don't have explicit control over the AES key
        // struct here
        // srcCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(                  ctx);
        // dstCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        // SymCryptXtsKeyCopy(&srcCtx->key, &dstCtx->key);
        return 0;
    default:
        return 0;
    }
    return 1;
}

/*
 * AES-GCM Implementation
 */
 
// Initializes ctx with the provided key and iv, along with enc/dec mode.
// enc should be set to 1 for encryption, 0 for decryption, and -1 to leave value unchanged.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_aes_gcm_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, int enc)
{
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    cipherCtx->operationInProgress = 0;
    cipherCtx->enc = enc;
    if( iv )
    {
        memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    if( key )
    {
        SymError = SymCryptGcmExpandKey(&cipherCtx->key, SymCryptAesBlockCipher, key, EVP_CIPHER_CTX_key_length(ctx));
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

#define SC_OSSL_AESGCM_TLS_IV_LEN 8
#define SC_OSSL_AESGCM_TLS_ICV_LEN 16

// Encrypts or ecrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS sc_ossl_aes_gcm_tls(_Inout_ struct cipher_gcm_ctx *cipherCtx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    UINT64 nextIV = 0;
    PBYTE  pbPayload = NULL;
    SIZE_T cbPayload = 0;

    // For TLS we only support in-place en/decryption of an ESP taking the form:
    // IV (8B) || Ciphertext (variable) || ICV (Auth Tag) (16B)

    // When encrypting, the space for the IV and ICV should be provided by the caller with the
    // plaintext starting 8B from the start of the buffer and ending 16B from the end
    if( in != out )
    {
        SC_OSSL_LOG_ERROR("AES-GCM TLS does not support out-of-place operation");
        goto cleanup;
    }
    if( inl < SC_OSSL_AESGCM_TLS_IV_LEN + SC_OSSL_AESGCM_TLS_ICV_LEN )
    {
        SC_OSSL_LOG_ERROR("AES-GCM TLS buffer too small");
        goto cleanup;
    }
    if( cipherCtx->operationInProgress )
    {
        SC_OSSL_LOG_ERROR("AES-GCM TLS operation cannot be multi-stage");
        goto cleanup;
    }
    if( cipherCtx->taglen != SC_OSSL_AESGCM_TLS_ICV_LEN )
    {
        SC_OSSL_LOG_ERROR("AES-GCM TLS taglen must be %d", SC_OSSL_AESGCM_TLS_ICV_LEN);
        goto cleanup;
    }

    if( cipherCtx->enc )
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it from the context
        memcpy(out, cipherCtx->iv + SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN, SC_OSSL_AESGCM_TLS_IV_LEN);

        // Set up the cipher state with the full IV
        SymCryptGcmInit(&cipherCtx->state, &cipherCtx->key, cipherCtx->iv, SC_OSSL_GCM_IV_LENGTH);

        // Set up the cipher state with the next IV
        nextIV = SYMCRYPT_LOAD_MSBFIRST64( cipherCtx->iv + SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN ) + 1;
        SYMCRYPT_STORE_MSBFIRST64( cipherCtx->iv + SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN, nextIV );
    }
    else
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it to the context
        memcpy(cipherCtx->iv + SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN, out, SC_OSSL_AESGCM_TLS_IV_LEN);

        // Set up the cipher state with the full IV
        SymCryptGcmInit(&cipherCtx->state, &cipherCtx->key, cipherCtx->iv, SC_OSSL_GCM_IV_LENGTH);
    }

    pbPayload = out + SC_OSSL_AESGCM_TLS_IV_LEN;
    cbPayload = inl - (SC_OSSL_AESGCM_TLS_IV_LEN + SC_OSSL_AESGCM_TLS_ICV_LEN);

    // Add Auth Data to Gcm State
    SymCryptGcmAuthPart(&cipherCtx->state, cipherCtx->tlsAad, EVP_AEAD_TLS1_AAD_LEN);

    if( cipherCtx->enc )
    {
        // Encrypt payload
        SymCryptGcmEncryptPart(&cipherCtx->state, pbPayload, pbPayload, cbPayload);

        // Set ICV
        SymCryptGcmEncryptFinal(&cipherCtx->state, pbPayload+cbPayload, SC_OSSL_AESGCM_TLS_ICV_LEN);

        ret = inl;
    }
    else
    {
        // Decrypt payload
        SymCryptGcmDecryptPart(&cipherCtx->state, pbPayload, pbPayload, cbPayload);

        // Check ICV
        SymError = SymCryptGcmDecryptFinal(&cipherCtx->state, pbPayload+cbPayload, SC_OSSL_AESGCM_TLS_ICV_LEN);
        if( SymError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptGcmDecryptFinal failed", SymError);
            goto cleanup;
        }

        ret = cbPayload;
    }

cleanup:
    if( ret == 0 )
    {
        OPENSSL_cleanse(out, inl);
    }

    return ret;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
int sc_ossl_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    int ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if( cipherCtx->tlsAadSet )
    {
        return sc_ossl_aes_gcm_tls(cipherCtx, out, in, inl);
    }

    if( !cipherCtx->operationInProgress )
    {
        SymCryptGcmInit(&cipherCtx->state, &cipherCtx->key, cipherCtx->iv, EVP_CIPHER_CTX_iv_length(ctx));
        cipherCtx->operationInProgress = 1;
    }

    if( out == NULL && in != NULL && inl > 0 )
    {
        // Auth Data Passed in
        SymCryptGcmAuthPart(&cipherCtx->state, in, inl);
        ret = 0;
        goto end;
    }

    if( cipherCtx->enc )
    {
        if( inl > 0 )
        {
            // Encrypt Part
            SymCryptGcmEncryptPart(&cipherCtx->state, in, out, inl);
            ret = inl;
            goto end;
        }
        else
        {
            // Final Encrypt Call
            SymCryptGcmEncryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            ret = 0;
            goto end;
        }
    }
    else
    {
        if( inl > 0 )
        {
            // Decrypt Part
            SymCryptGcmDecryptPart(&cipherCtx->state, in, out, inl);
            ret = inl;
            goto end;
        }
        else
        {
            // Final Decrypt Call
            SymError = SymCryptGcmDecryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            if( SymError != SYMCRYPT_NO_ERROR )
            {
                SC_OSSL_LOG_SYMERROR_ERROR("SymCryptGcmDecryptFinal failed", SymError);
                ret = -1;
                goto end;
            }
            ret = 0;
            goto end;
        }
    }
end:
    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS sc_ossl_aes_gcm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct cipher_gcm_ctx *dstCtx;
    unsigned char *iv = NULL;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    UINT16 tls_buffer_len = 0;
    UINT16 min_tls_buffer_len = 0;
    switch( type )
    {
    case EVP_CTRL_INIT:
        iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
        if( iv )
        {
            memcpy(cipherCtx->iv, iv, SC_OSSL_GCM_IV_LENGTH);
        }
        cipherCtx->taglen = EVP_GCM_TLS_TAG_LEN;
        cipherCtx->tlsAadSet = 0;
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = SC_OSSL_GCM_IV_LENGTH;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        // Symcrypt only supports SC_OSSL_GCM_IV_LENGTH
        if( arg != SC_OSSL_GCM_IV_LENGTH )
        {
            SC_OSSL_LOG_ERROR("SymCrypt Engine only supports %d byte IV for AES-GCM", SC_OSSL_GCM_IV_LENGTH);
            return 0;
        }
        break;
    case EVP_CTRL_AEAD_SET_TAG:
        if( arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(ctx) )
        {
            SC_OSSL_LOG_ERROR("Set tag error");
            return 0;
        }
        memcpy(cipherCtx->tag, ptr, arg);
        cipherCtx->taglen = arg;
        break;
    case EVP_CTRL_AEAD_GET_TAG:
        if( arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(ctx) )
        {
            SC_OSSL_LOG_ERROR("Get tag error");
            return 0;
        }
        memcpy(ptr, cipherCtx->tag, cipherCtx->taglen);
        break;
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the GCM structs using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        dstCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptGcmKeyCopy(&cipherCtx->key, &dstCtx->key);
        SymCryptGcmStateCopy(&cipherCtx->state, &dstCtx->key, &dstCtx->state);
        break;
    case EVP_CTRL_GCM_SET_IV_FIXED:
        if( arg == -1 )
        {
            memcpy(cipherCtx->iv, ptr, SC_OSSL_GCM_IV_LENGTH);
            break;
        }
        if( arg != SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN )
        {
            SC_OSSL_LOG_ERROR("set_iv_fixed incorrect length");
            return 0;
        }
        // Set first 4B of IV to ptr value
        memcpy(cipherCtx->iv, ptr, SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN);
        // If encrypting, randomly set the last 8B of IV
        if( EVP_CIPHER_CTX_encrypting(ctx) &&
            (RAND_bytes(cipherCtx->iv + SC_OSSL_GCM_IV_LENGTH - SC_OSSL_AESGCM_TLS_IV_LEN, SC_OSSL_AESGCM_TLS_IV_LEN) <= 0) )
        {
            return 0;
        }
        break;
    case EVP_CTRL_AEAD_TLS1_AAD:
        if( arg != EVP_AEAD_TLS1_AAD_LEN )
        {
            SC_OSSL_LOG_ERROR("Set tlsAad error");
            return 0;
        }
        memcpy(cipherCtx->tlsAad, ptr, EVP_AEAD_TLS1_AAD_LEN);
        cipherCtx->tlsAadSet = 1;

        if( EVP_CIPHER_CTX_encrypting(ctx) )
        {
            // Provided AAD contains len of plaintext + IV (8B)
            min_tls_buffer_len = SC_OSSL_AESGCM_TLS_IV_LEN;
        }
        else
        {
            // Provided AAD contains len of ciphertext + IV (8B) + ICV (16B)
            min_tls_buffer_len = SC_OSSL_AESGCM_TLS_IV_LEN + SC_OSSL_AESGCM_TLS_ICV_LEN;
        }

        tls_buffer_len = SYMCRYPT_LOAD_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2);
        if( tls_buffer_len < min_tls_buffer_len )
        {
            SC_OSSL_LOG_ERROR("tls_buffer_len too short");
            return 0;
        }
        tls_buffer_len -= min_tls_buffer_len;
        SYMCRYPT_STORE_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2, tls_buffer_len);

        return SC_OSSL_AESGCM_TLS_ICV_LEN;
    default:
        SC_OSSL_LOG_ERROR("SymCrypt Engine does not support control type (%d)", type);
        return 0;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif
