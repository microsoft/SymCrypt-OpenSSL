#include "e_symcrypt_ciphers.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cipher_cbc_ctx {
    int enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    unsigned char iv[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_ecb_ctx {
    int enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    unsigned char iv[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_xts_ctx {
    int enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    unsigned char iv[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
};

#define SYMCRYPT_GCM_IV_LENGTH      12

struct cipher_ctx_gcm {
    int enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    unsigned char iv[SYMCRYPT_GCM_IV_LENGTH];
    SYMCRYPT_GCM_STATE state;
    SYMCRYPT_GCM_EXPANDED_KEY key;
    unsigned char tag[EVP_GCM_TLS_TAG_LEN];
    int taglen;
};


static int symcrypt_cipher_nids[] = {
    NID_aes_128_cbc,
    NID_aes_192_cbc,
    NID_aes_256_cbc,

    NID_aes_128_ecb,
    NID_aes_192_ecb,
    NID_aes_256_ecb,

    NID_aes_128_xts,
    NID_aes_256_xts,

    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
};

int symcrypt_aes_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int symcrypt_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32

/* AES128 - CBC */
static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *symcrypt_aes_128_cbc(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_128_cbc == NULL
        && ((_hidden_aes_128_cbc = EVP_CIPHER_meth_new(NID_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc, symcrypt_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc, symcrypt_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc, sizeof(struct cipher_cbc_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}

/* AES192 - CBC */
static EVP_CIPHER *_hidden_aes_192_cbc = NULL;
static const EVP_CIPHER *symcrypt_aes_192_cbc(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_192_cbc == NULL
        && ((_hidden_aes_192_cbc = EVP_CIPHER_meth_new(NID_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_cbc, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_cbc, symcrypt_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_cbc, symcrypt_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_cbc, sizeof(struct cipher_cbc_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
        _hidden_aes_192_cbc = NULL;
    }
    return _hidden_aes_192_cbc;
}

/* AES256 - CBC */
static EVP_CIPHER *_hidden_aes_256_cbc = NULL;
static const EVP_CIPHER *symcrypt_aes_256_cbc(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_256_cbc == NULL
        && ((_hidden_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc, symcrypt_aes_cbc_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc, symcrypt_aes_cbc_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc, sizeof(struct cipher_cbc_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
        _hidden_aes_256_cbc = NULL;
    }
    return _hidden_aes_256_cbc;
}

int symcrypt_aes_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int symcrypt_aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

/* AES128 - ecb */
static EVP_CIPHER *_hidden_aes_128_ecb = NULL;
static const EVP_CIPHER *symcrypt_aes_128_ecb(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_128_ecb == NULL
        && ((_hidden_aes_128_ecb = EVP_CIPHER_meth_new(NID_aes_128_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_ecb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ecb, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ecb, symcrypt_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ecb, symcrypt_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ecb, sizeof(struct cipher_ecb_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
        _hidden_aes_128_ecb = NULL;
    }
    return _hidden_aes_128_ecb;
}

/* AES192 - ecb */
static EVP_CIPHER *_hidden_aes_192_ecb = NULL;
static const EVP_CIPHER *symcrypt_aes_192_ecb(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_192_ecb == NULL
        && ((_hidden_aes_192_ecb = EVP_CIPHER_meth_new(NID_aes_192_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_ecb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ecb, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ecb, symcrypt_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ecb, symcrypt_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ecb, sizeof(struct cipher_ecb_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
        _hidden_aes_192_ecb = NULL;
    }
    return _hidden_aes_192_ecb;
}

/* AES256 - ecb */
static EVP_CIPHER *_hidden_aes_256_ecb = NULL;
static const EVP_CIPHER *symcrypt_aes_256_ecb(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_256_ecb == NULL
        && ((_hidden_aes_256_ecb = EVP_CIPHER_meth_new(NID_aes_256_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_ecb, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ecb, EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ecb, symcrypt_aes_ecb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ecb, symcrypt_aes_ecb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ecb, sizeof(struct cipher_ecb_ctx))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
        _hidden_aes_256_ecb = NULL;
    }
    return _hidden_aes_256_ecb;
}


int symcrypt_aes_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int symcrypt_aes_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
#define AES_XTS_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_XTS_MODE )

/* AES128 - XTS */
static EVP_CIPHER *_hidden_aes_128_xts = NULL;
static const EVP_CIPHER *symcrypt_aes_128_xts(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_128_xts == NULL
        && ((_hidden_aes_128_xts = EVP_CIPHER_meth_new(NID_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE * 2)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_xts, 8)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_xts, AES_XTS_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_xts, symcrypt_aes_xts_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_xts, symcrypt_aes_xts_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_xts, sizeof(struct cipher_xts_ctx))))
    {
        SYMCRYPT_LOG_ERROR("CIPHER Initialization Failed");
        EVP_CIPHER_meth_free(_hidden_aes_128_xts);
        _hidden_aes_128_xts = NULL;
    }
    return _hidden_aes_128_xts;
}

/* AES256 - XTS */
static EVP_CIPHER *_hidden_aes_256_xts = NULL;
static const EVP_CIPHER *symcrypt_aes_256_xts(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_256_xts == NULL
        && ((_hidden_aes_256_xts = EVP_CIPHER_meth_new(NID_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE * 2)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_xts, 8)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_xts, AES_XTS_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_xts, symcrypt_aes_xts_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_xts, symcrypt_aes_xts_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_xts, sizeof(struct cipher_xts_ctx))))
    {
        SYMCRYPT_LOG_ERROR("CIPHER Initialization Failed");
        EVP_CIPHER_meth_free(_hidden_aes_256_xts);
        _hidden_aes_256_xts = NULL;
    }
    return _hidden_aes_256_xts;
}

int symcrypt_aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int symcrypt_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int symcrypt_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_FLAG_AEAD_CIPHER \
                | EVP_CIPH_GCM_MODE)

/* AES128 - GCM */
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;
static const EVP_CIPHER *symcrypt_aes_128_gcm(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_128_gcm == NULL
        && ((_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, AES_128_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm, symcrypt_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm, symcrypt_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, symcrypt_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm, sizeof(struct cipher_ctx_gcm))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

/* AES192 - GCM */
static EVP_CIPHER *_hidden_aes_192_gcm = NULL;
static const EVP_CIPHER *symcrypt_aes_192_gcm(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_192_gcm == NULL
        && ((_hidden_aes_192_gcm = EVP_CIPHER_meth_new(NID_aes_192_gcm, 1, AES_192_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_gcm, symcrypt_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_gcm, symcrypt_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_gcm, symcrypt_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_gcm, sizeof(struct cipher_ctx_gcm))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_gcm);
        _hidden_aes_192_gcm = NULL;
    }
    return _hidden_aes_192_gcm;
}

/* AES256 - GCM */
static EVP_CIPHER *_hidden_aes_256_gcm = NULL;
static const EVP_CIPHER *symcrypt_aes_256_gcm(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (_hidden_aes_256_gcm == NULL
        && ((_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1, AES_256_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm, symcrypt_aes_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm, symcrypt_aes_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, symcrypt_aes_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm, sizeof(struct cipher_ctx_gcm))))
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
        _hidden_aes_256_gcm = NULL;
    }
    return _hidden_aes_256_gcm;
}


void symcrypt_destroy_ciphers(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
    EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
    EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
    EVP_CIPHER_meth_free(_hidden_aes_128_xts);
    EVP_CIPHER_meth_free(_hidden_aes_256_xts);
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

int symcrypt_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                     const int **nids, int nid)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = symcrypt_cipher_nids;
        return (sizeof(symcrypt_cipher_nids))
               / sizeof(symcrypt_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = symcrypt_aes_128_cbc();
        break;
    case NID_aes_192_cbc:
        *cipher = symcrypt_aes_192_cbc();
        break;
    case NID_aes_256_cbc:
        *cipher = symcrypt_aes_256_cbc();
        break;
    case NID_aes_128_ecb:
        *cipher = symcrypt_aes_128_ecb();
        break;
    case NID_aes_192_ecb:
        *cipher = symcrypt_aes_192_ecb();
        break;
    case NID_aes_256_ecb:
        *cipher = symcrypt_aes_256_ecb();
        break;
    case NID_aes_128_xts:
        *cipher = symcrypt_aes_128_xts();
        break;
    case NID_aes_256_xts:
        *cipher = symcrypt_aes_256_xts();
        break;
    case NID_aes_128_gcm:
        *cipher = symcrypt_aes_128_gcm();
        break;
    case NID_aes_192_gcm:
        *cipher = symcrypt_aes_192_gcm();
        break;
    case NID_aes_256_gcm:
        *cipher = symcrypt_aes_256_gcm();
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
int symcrypt_aes_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("Encryption?: %d", enc);
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    cipherCtx->enc = enc;
    if (iv) {
        memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
    return 1;
}

int symcrypt_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("in: %x, out: %x, Input Length: %ld", in, out, inl);
    int ret = 0;
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_LOG_DEBUG("cipherCtx->key: %x, cipherCtx->iv: %x", cipherCtx->key, cipherCtx->iv);
    if (cipherCtx->enc)
    {
        SymCryptAesCbcEncrypt(&cipherCtx->key, cipherCtx->iv, in, out, inl);
    }
    else
    {
        SymCryptAesCbcDecrypt(&cipherCtx->key, cipherCtx->iv, in, out, inl);
    }
    ret = 1;
end:
    return ret;
}

/*
 * AES-ECB Implementation
 */
int symcrypt_aes_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    // SYMCRYPT_LOG_DEBUG(NULL);
    // SYMCRYPT_LOG_DEBUG("Encryption?: %d", enc);
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    cipherCtx->enc = enc;
    //memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
    return 1;
}

int symcrypt_aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    // TOO NOISY
    // SYMCRYPT_LOG_DEBUG(NULL);
    // SYMCRYPT_LOG_DEBUG("in: %x, out: %x, Input Length: %ld", in, out, inl);
    int ret = 0;
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    //SYMCRYPT_LOG_DEBUG("cipherCtx->key: %x, cipherCtx->iv: %x", cipherCtx->key, cipherCtx->iv);
    if (cipherCtx->enc)
    {
        SymCryptAesEcbEncrypt(&cipherCtx->key, in, out, inl);
    }
    else
    {
        SymCryptAesEcbDecrypt(&cipherCtx->key, in, out, inl);
    }
    ret = 1;
end:
    return ret;
}

/*
 * AES-XTS Implementation
 */
int symcrypt_aes_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("Encryption?: %d, EVP_CIPHER_CTX_iv_length: %d", enc, EVP_CIPHER_CTX_iv_length(ctx));
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    cipherCtx->enc = enc;
    if(iv)
    {
        memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    SymCryptXtsAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
    return 1;
}

int symcrypt_aes_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("in: %x, out: %x, Input Length: %ld", in, out, inl);
    int ret = 0;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_LOG_DEBUG("cipherCtx->key: %x, cipherCtx->iv: %x", cipherCtx->key, cipherCtx->iv);
    if (inl > 0)
    {
        if ((inl % 16) != 0)
        {
            SYMCRYPT_LOG_ERROR("Data length (%d) is not a multiple of the AES block size. SymCrypt does not support this size", inl);
            return -1;
        }

        // It appears that the EVP API for exposing AES-XTS does not allow definition of the size of
        // a data unit. My understanding is that callers are expected to make a single call through
        // the EVP interface per data unit - so we pass inl to both cbDataUnit and cbData.

        if (cipherCtx->enc)
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
        ret = inl;
    }
end:
    return ret;
}

/*
 * AES-GCM Implementation
 */
int symcrypt_aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("Encryption?: %d", enc);
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    struct cipher_ctx_gcm *cipherCtx = (struct cipher_ctx_gcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    cipherCtx->enc = enc;
    if (iv) {
        memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
        SYMCRYPT_LOG_BYTES_DEBUG("Saved IV", cipherCtx->iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    if (key)
    {
        SYMCRYPT_LOG_DEBUG("SymCryptGcmExpandKey Input: key");
        SymError = SymCryptGcmExpandKey(&cipherCtx->key, SymCryptAesBlockCipher, key, EVP_CIPHER_CTX_key_length(ctx));
        if (SymError != SYMCRYPT_NO_ERROR)
        {
            SYMCRYPT_LOG_DEBUG("ERROR: SymCryptGcmExpandKey failed. SymError = %d ", SymError);
            return 0;
        }
        SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmInit Input cipherCtx->IV", cipherCtx->iv, EVP_CIPHER_CTX_iv_length(ctx));
        SymCryptGcmInit(&cipherCtx->state, &cipherCtx->key, cipherCtx->iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    return 1;
}

int symcrypt_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int ret = 0;
    SYMCRYPT_ERROR SymError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_LOG_DEBUG("Input Length: %ld", inl);
    struct cipher_ctx_gcm *cipherCtx = (struct cipher_ctx_gcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (out == NULL && in != NULL && inl > 0)
    {
        // Auth Data Passed in
        SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmAuthPart input: AuthData", (const char *)in, inl);
        SymCryptGcmAuthPart(&cipherCtx->state, in, inl);
        ret = 1;
        goto end;
    }

    if (cipherCtx->enc)
    {
        if (inl > 0)
        {
            // Encrypt Part
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmEncryptPart output: in", (const char *)in, inl);
            SymCryptGcmEncryptPart(&cipherCtx->state, in, out, inl);
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmEncryptPart output: out", (const char *)out, inl);
            ret = inl;
            goto end;
        }
        else
        {
            // Final Encrypt Call
            SymCryptGcmEncryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmEncryptFinal output: tag", (const char *)cipherCtx->tag, cipherCtx->taglen);
            ret = 0;
            goto end;
        }
    }
    else
    {
        if (inl > 0)
        {
            // Decrypt Part
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmDecryptPart output: in", (const char *)in, inl);
            SymCryptGcmDecryptPart(&cipherCtx->state, in, out, inl);
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmDecryptPart output: out", (const char *)out, inl);
            ret = inl;
            goto end;
        }
        else
        {
            // Final Decrypt Call
            SymError = SymCryptGcmDecryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            if (SymError != SYMCRYPT_NO_ERROR)
            {
                SYMCRYPT_LOG_ERROR("SymCryptGcmDecryptFinal failed. SymError = %ld", SymError);
                return -1;
            }
            SYMCRYPT_LOG_BYTES_DEBUG("SymCryptGcmDecryptFinal output: tag", (const char *)cipherCtx->tag, cipherCtx->taglen);
            ret = 0;
            goto end;
        }
    }
end:
    return ret;
}

static int symcrypt_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_LOG_DEBUG("type: %d, arg: %d", type, arg);
    struct cipher_ctx_gcm *cipherCtx = (struct cipher_ctx_gcm *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = NULL;
    switch(type) {
    case EVP_CTRL_INIT:
        iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
        if (iv)
        {
            memcpy(cipherCtx->iv, iv, SYMCRYPT_GCM_IV_LENGTH);
        }
        cipherCtx->taglen = EVP_GCM_TLS_TAG_LEN;
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = SYMCRYPT_GCM_IV_LENGTH;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        // Symcrypt only support SYMCRYPT_GCM_IV_LENGTH
        break;
    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(cipherCtx->tag, ptr, arg);
        cipherCtx->taglen = arg;
        break;
    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(ptr, cipherCtx->tag, cipherCtx->taglen);
        break;
    default:
        break;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif
