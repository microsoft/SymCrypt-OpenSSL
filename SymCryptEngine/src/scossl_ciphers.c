//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int SCOSSL_ENCRYPTION_MODE;
#define SCOSSL_ENCRYPTION_MODE_ENCRYPT (1)
#define SCOSSL_ENCRYPTION_MODE_DECRYPT (0)
#define SCOSSL_ENCRYPTION_MODE_NOCHANGE (-1)

struct cipher_cbc_ctx {
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_ecb_ctx {
    SYMCRYPT_AES_EXPANDED_KEY key;
};

struct cipher_xts_ctx {
    BYTE iv[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_XTS_AES_EXPANDED_KEY key;
};

#define SCOSSL_GCM_IV_LENGTH      (12)
#define SCOSSL_GCM_MIN_TAG_LENGTH (12)
#define SCOSSL_GCM_MAX_TAG_LENGTH (16)

struct cipher_gcm_ctx {
    INT32 operationInProgress;
    BYTE iv[SCOSSL_GCM_IV_LENGTH];
    INT32 ivlen;
    SYMCRYPT_GCM_STATE state;
    SYMCRYPT_GCM_EXPANDED_KEY key;
    BYTE tag[EVP_GCM_TLS_TAG_LEN];
    INT32 taglen;
    BYTE tlsAad[EVP_AEAD_TLS1_AAD_LEN];
    INT32 tlsAadSet;
};

#define SCOSSL_CCM_MIN_IV_LENGTH    (7)
#define SCOSSL_CCM_MAX_IV_LENGTH    (13)
#define SCOSSL_CCM_MIN_TAG_LENGTH   (4)
#define SCOSSL_CCM_MAX_TAG_LENGTH   (16)

// The way CCM works with the EVP APIs is quite specific, there are 2 cases:
//  Encrypt/Decrypt with no AAD
//      => We expect 1 call to en/decrypt the buffer from in to out (and set return to failure on tag mismatch for decrypt)
//      => Then 1 call to "finalize" - does nothing (in==NULL, inl==0, out!=NULL)
//  Encrypt/Decrypt with AAD
//      => We expect 1 call to set the total input length (i.e. plain/ciphertext + AAD) (in==NULL, inl==cbData, out==NULL)
//      => Then 1 call to set all of the AAD (if any) (in==pbAuthData, inl==cbAuthData, out==NULL)
//      => Then 1 call to en/decrypt the buffer from in to out (and set return to failure on tag mismatch for decrypt)
//      => Then 1 call to "finalize" - does nothing (in==NULL, inl==0, out!=NULL)
typedef enum {
    SCOSSL_CCM_STAGE_INIT = 0,      // The initial state
    SCOSSL_CCM_STAGE_SET_CBDATA,    // The state after a call providing the total input length
    SCOSSL_CCM_STAGE_SET_AAD,       // The state after a call providing the AAD
    SCOSSL_CCM_STAGE_COMPLETE,      // The state after a call providing the plain/ciphertext
} SCOSSL_CCM_STAGE;

struct cipher_ccm_ctx {
    INT32 enc;                     /* COP_ENCRYPT or COP_DECRYPT */
    SCOSSL_CCM_STAGE ccmStage;
    BYTE iv[SCOSSL_CCM_MAX_IV_LENGTH];
    INT32 ivlen;
    SYMCRYPT_CCM_STATE state;
    SYMCRYPT_AES_EXPANDED_KEY key;
    BYTE tag[EVP_CCM_TLS_TAG_LEN];
    INT32 taglen;
    UINT64 cbData;
    BYTE tlsAad[EVP_AEAD_TLS1_AAD_LEN];
    INT32 tlsAadSet;
};

static int scossl_cipher_nids[] = {
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

    NID_aes_128_ccm,
    NID_aes_192_ccm,
    NID_aes_256_ccm,
};

#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32

SCOSSL_STATUS scossl_aes_cbc_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS scossl_aes_cbc_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS scossl_aes_cbc_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_CBC_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE|EVP_CIPH_CUSTOM_COPY \
                         |EVP_CIPH_ALWAYS_CALL_INIT)

/* AES128 - CBC */
static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *scossl_aes_128_cbc(void)
{
    if( (_hidden_aes_128_cbc = EVP_CIPHER_meth_new(NID_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc, scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc, scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc, scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}

/* AES192 - CBC */
static EVP_CIPHER *_hidden_aes_192_cbc = NULL;
static const EVP_CIPHER *scossl_aes_192_cbc(void)
{
    if( (_hidden_aes_192_cbc = EVP_CIPHER_meth_new(NID_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_cbc, scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_cbc, scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_cbc, scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
        _hidden_aes_192_cbc = NULL;
    }
    return _hidden_aes_192_cbc;
}

/* AES256 - CBC */
static EVP_CIPHER *_hidden_aes_256_cbc = NULL;
static const EVP_CIPHER *scossl_aes_256_cbc(void)
{
    if( (_hidden_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc, scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc, scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc, scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
        _hidden_aes_256_cbc = NULL;
    }
    return _hidden_aes_256_cbc;
}

SCOSSL_STATUS scossl_aes_ecb_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS scossl_aes_ecb_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS scossl_aes_ecb_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_ECB_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE|EVP_CIPH_CUSTOM_COPY)

/* AES128 - ecb */
static EVP_CIPHER *_hidden_aes_128_ecb = NULL;
static const EVP_CIPHER *scossl_aes_128_ecb(void)
{
    if( (_hidden_aes_128_ecb = EVP_CIPHER_meth_new(NID_aes_128_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ecb, scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ecb, scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_ecb, scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
        _hidden_aes_128_ecb = NULL;
    }
    return _hidden_aes_128_ecb;
}

/* AES192 - ecb */
static EVP_CIPHER *_hidden_aes_192_ecb = NULL;
static const EVP_CIPHER *scossl_aes_192_ecb(void)
{
    if( (_hidden_aes_192_ecb = EVP_CIPHER_meth_new(NID_aes_192_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ecb, scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ecb, scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_ecb, scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
        _hidden_aes_192_ecb = NULL;
    }
    return _hidden_aes_192_ecb;
}

/* AES256 - ecb */
static EVP_CIPHER *_hidden_aes_256_ecb = NULL;
static const EVP_CIPHER *scossl_aes_256_ecb(void)
{
    if( (_hidden_aes_256_ecb = EVP_CIPHER_meth_new(NID_aes_256_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ecb, scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ecb, scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_ecb, scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
        _hidden_aes_256_ecb = NULL;
    }
    return _hidden_aes_256_ecb;
}

// Disabling XTS for now - remove with if region to avoid unused function warning
#if 0
SCOSSL_STATUS scossl_aes_xts_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS scossl_aes_xts_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS scossl_aes_xts_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_XTS_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_XTS_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_FLAG_CUSTOM_CIPHER)

/* AES128 - XTS */
static EVP_CIPHER *_hidden_aes_128_xts = NULL;
static const EVP_CIPHER *scossl_aes_128_xts(void)
{
    if( (_hidden_aes_128_xts = EVP_CIPHER_meth_new(NID_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE * 2)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_xts, AES_XTS_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_xts, scossl_aes_xts_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_xts, scossl_aes_xts_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_xts, scossl_aes_xts_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_xts, sizeof(struct cipher_xts_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_xts);
        _hidden_aes_128_xts = NULL;
    }
    return _hidden_aes_128_xts;
}

/* AES256 - XTS */
static EVP_CIPHER *_hidden_aes_256_xts = NULL;
static const EVP_CIPHER *scossl_aes_256_xts(void)
{
    if( (_hidden_aes_256_xts = EVP_CIPHER_meth_new(NID_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE * 2)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_xts, AES_XTS_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_xts, scossl_aes_xts_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_xts, scossl_aes_xts_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_xts, scossl_aes_xts_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_xts, sizeof(struct cipher_xts_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_xts);
        _hidden_aes_256_xts = NULL;
    }
    return _hidden_aes_256_xts;
}
#endif


SCOSSL_STATUS scossl_aes_gcm_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_RETURNLENGTH scossl_aes_gcm_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS scossl_aes_gcm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_GCM_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_CUSTOM_IV_LENGTH|EVP_CIPH_FLAG_CUSTOM_CIPHER \
                        |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CTRL_INIT|EVP_CIPH_FLAG_AEAD_CIPHER)

/* AES128 - GCM */
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;
static const EVP_CIPHER *scossl_aes_128_gcm(void)
{
    if( (_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm, scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm, scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm, sizeof(struct cipher_gcm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

/* AES192 - GCM */
static EVP_CIPHER *_hidden_aes_192_gcm = NULL;
static const EVP_CIPHER *scossl_aes_192_gcm(void)
{
    if( (_hidden_aes_192_gcm = EVP_CIPHER_meth_new(NID_aes_192_gcm, 1, AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_gcm, scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_gcm, scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_gcm, scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_gcm, sizeof(struct cipher_gcm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_gcm);
        _hidden_aes_192_gcm = NULL;
    }
    return _hidden_aes_192_gcm;
}

/* AES256 - GCM */
static EVP_CIPHER *_hidden_aes_256_gcm = NULL;
static const EVP_CIPHER *scossl_aes_256_gcm(void)
{
    if( (_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1, AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm, scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm, scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm, sizeof(struct cipher_gcm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
        _hidden_aes_256_gcm = NULL;
    }
    return _hidden_aes_256_gcm;
}

SCOSSL_STATUS scossl_aes_ccm_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_RETURNLENGTH scossl_aes_ccm_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS scossl_aes_ccm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_CCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CCM_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_CUSTOM_IV_LENGTH|EVP_CIPH_FLAG_CUSTOM_CIPHER \
                        |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CTRL_INIT|EVP_CIPH_FLAG_AEAD_CIPHER)

/* AES128 - CCM */
static EVP_CIPHER *_hidden_aes_128_ccm = NULL;
static const EVP_CIPHER *scossl_aes_128_ccm(void)
{
    if( (_hidden_aes_128_ccm = EVP_CIPHER_meth_new(NID_aes_128_ccm, 1, AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ccm, scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ccm, scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_ccm, scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ccm, sizeof(struct cipher_ccm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ccm);
        _hidden_aes_128_ccm = NULL;
    }
    return _hidden_aes_128_ccm;
}

/* AES192 - CCM */
static EVP_CIPHER *_hidden_aes_192_ccm = NULL;
static const EVP_CIPHER *scossl_aes_192_ccm(void)
{
    if( (_hidden_aes_192_ccm = EVP_CIPHER_meth_new(NID_aes_192_ccm, 1, AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ccm, scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ccm, scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_ccm, scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ccm, sizeof(struct cipher_ccm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ccm);
        _hidden_aes_192_ccm = NULL;
    }
    return _hidden_aes_192_ccm;
}

/* AES256 - CCM */
static EVP_CIPHER *_hidden_aes_256_ccm = NULL;
static const EVP_CIPHER *scossl_aes_256_ccm(void)
{
    if( (_hidden_aes_256_ccm = EVP_CIPHER_meth_new(NID_aes_256_ccm, 1, AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ccm, scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ccm, scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_ccm, scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ccm, sizeof(struct cipher_ccm_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ccm);
        _hidden_aes_256_ccm = NULL;
    }
    return _hidden_aes_256_ccm;
}


void scossl_destroy_ciphers(void)
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
    EVP_CIPHER_meth_free(_hidden_aes_128_ccm);
    EVP_CIPHER_meth_free(_hidden_aes_192_ccm);
    EVP_CIPHER_meth_free(_hidden_aes_256_ccm);
    _hidden_aes_128_cbc = NULL;
    _hidden_aes_192_cbc = NULL;
    _hidden_aes_256_cbc = NULL;
    _hidden_aes_128_ecb = NULL;
    _hidden_aes_192_ecb = NULL;
    _hidden_aes_256_ecb = NULL;
    // _hidden_aes_128_xts = NULL;
    // _hidden_aes_256_xts = NULL;
    _hidden_aes_128_gcm = NULL;
    _hidden_aes_192_gcm = NULL;
    _hidden_aes_256_gcm = NULL;
    _hidden_aes_128_ccm = NULL;
    _hidden_aes_192_ccm = NULL;
    _hidden_aes_256_ccm = NULL;
}

SCOSSL_STATUS scossl_ciphers_init_static()
{
    if( (scossl_aes_128_cbc() == NULL) ||
        (scossl_aes_192_cbc() == NULL) ||
        (scossl_aes_256_cbc() == NULL) ||
        (scossl_aes_128_ecb() == NULL) ||
        (scossl_aes_192_ecb() == NULL) ||
        (scossl_aes_256_ecb() == NULL) ||
        // (scossl_aes_128_xts() == NULL) ||
        // (scossl_aes_256_xts() == NULL) ||
        (scossl_aes_128_gcm() == NULL) ||
        (scossl_aes_192_gcm() == NULL) ||
        (scossl_aes_256_gcm() == NULL) ||
        (scossl_aes_128_ccm() == NULL) ||
        (scossl_aes_192_ccm() == NULL) ||
        (scossl_aes_256_ccm() == NULL) )
    {
        return 0;
    }
    return 1;
}

int scossl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                     const int **nids, int nid)
{
    int ok = 1;
    if( !cipher )
    {
        /* We are returning a list of supported nids */
        *nids = scossl_cipher_nids;
        return (sizeof(scossl_cipher_nids))
               / sizeof(scossl_cipher_nids[0]);
    }

    /* We are being asked for a specific cipher */
    switch( nid )
    {
    case NID_aes_128_cbc:
        *cipher = _hidden_aes_128_cbc;
        break;
    case NID_aes_192_cbc:
        *cipher = _hidden_aes_192_cbc;
        break;
    case NID_aes_256_cbc:
        *cipher = _hidden_aes_256_cbc;
        break;
    case NID_aes_128_ecb:
        *cipher = _hidden_aes_128_ecb;
        break;
    case NID_aes_192_ecb:
        *cipher = _hidden_aes_192_ecb;
        break;
    case NID_aes_256_ecb:
        *cipher = _hidden_aes_256_ecb;
        break;
    // case NID_aes_128_xts:
    //     *cipher = _hidden_aes_128_xts;
    //     break;
    // case NID_aes_256_xts:
    //     *cipher = _hidden_aes_256_xts;
    //     break;
    case NID_aes_128_gcm:
        *cipher = _hidden_aes_128_gcm;
        break;
    case NID_aes_192_gcm:
        *cipher = _hidden_aes_192_gcm;
        break;
    case NID_aes_256_gcm:
        *cipher = _hidden_aes_256_gcm;
        break;
    case NID_aes_128_ccm:
        *cipher = _hidden_aes_128_ccm;
        break;
    case NID_aes_192_ccm:
        *cipher = _hidden_aes_192_ccm;
        break;
    case NID_aes_256_ccm:
        *cipher = _hidden_aes_256_ccm;
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
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_cbc_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    if( key )
    {
        scError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_cbc_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    PBYTE ctx_iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    if( EVP_CIPHER_CTX_encrypting(ctx) )
    {
        SymCryptAesCbcEncrypt(&cipherCtx->key, ctx_iv, in, out, inl);
    }
    else
    {
        SymCryptAesCbcDecrypt(&cipherCtx->key, ctx_iv, in, out, inl);
    }

    return 1;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS scossl_aes_cbc_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
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
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_ecb_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    if( key )
    {
        scError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_ecb_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if( EVP_CIPHER_CTX_encrypting(ctx) )
    {
        SymCryptAesEcbEncrypt(&cipherCtx->key, in, out, inl);
    }
    else
    {
        SymCryptAesEcbDecrypt(&cipherCtx->key, in, out, inl);
    }

    return 1;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS scossl_aes_ecb_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_ecb_ctx *srcCtx;
    struct cipher_ecb_ctx *dstCtx;
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        srcCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(                  ctx);
        dstCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptAesKeyCopy(&srcCtx->key, &dstCtx->key);
        break;
    default:
        return 0;
    }
    return 1;
}

// Disabling XTS for now - remove with if region to avoid unused function warning
#if 0
/*
 * AES-XTS Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_xts_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
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
        scError = SymCryptXtsAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH scossl_aes_xts_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if( inl > 0 )
    {
        if( (inl % SYMCRYPT_AES_BLOCK_SIZE) != 0 )
        {
            SCOSSL_LOG_ERROR("Data length (%d) is not a multiple of the AES block size. SymCrypt does not support this size", inl);
            return -1;
        }

        // It appears that the EVP API for exposing AES-XTS does not allow definition of the size of
        // a data unit. My understanding is that callers are expected to make a single call through
        // the EVP interface per data unit - so we pass inl to both cbDataUnit and cbData.

        if( EVP_CIPHER_CTX_encrypting(ctx) )
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

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS scossl_aes_xts_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        SCOSSL_LOG_ERROR("No copy method currently implemented");
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
#endif

/*
 * AES-GCM Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_gcm_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    cipherCtx->operationInProgress = 0;
    if( iv )
    {
        memcpy(cipherCtx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    }
    if( key )
    {
        scError = SymCryptGcmExpandKey(&cipherCtx->key, SymCryptAesBlockCipher, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

#define EVP_GCM_TLS_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns length of out on success, or -1 on error.
static SCOSSL_RETURNLENGTH scossl_aes_gcm_tls(_In_ const EVP_CIPHER_CTX *ctx, _Inout_ struct cipher_gcm_ctx *cipherCtx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl, BOOL enc)
{
    int ret = -1;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbPayload = NULL;
    SIZE_T cbPayload = 0;

    // For TLS we only support in-place en/decryption of an ESP taking the form:
    // IV (8B) || Ciphertext (variable) || ICV (Auth Tag) (16B)

    // When encrypting, the space for the IV and ICV should be provided by the caller with the
    // plaintext starting 8B from the start of the buffer and ending 16B from the end
    if( in != out )
    {
        SCOSSL_LOG_ERROR("AES-GCM TLS does not support out-of-place operation");
        goto cleanup;
    }
    if( inl < EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN )
    {
        SCOSSL_LOG_ERROR("AES-GCM TLS buffer too small");
        goto cleanup;
    }
    if( cipherCtx->operationInProgress )
    {
        SCOSSL_LOG_ERROR("AES-GCM TLS operation cannot be multi-stage");
        goto cleanup;
    }
    if( cipherCtx->taglen != EVP_GCM_TLS_TAG_LEN )
    {
        SCOSSL_LOG_ERROR("AES-GCM TLS taglen must be %d", EVP_GCM_TLS_TAG_LEN);
        goto cleanup;
    }

    pbPayload = out + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    cbPayload = inl - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);

    if( EVP_CIPHER_CTX_encrypting(ctx) )
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it from the context
        memcpy(out, cipherCtx->iv + cipherCtx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN, EVP_GCM_TLS_EXPLICIT_IV_LEN);

        // Encrypt payload
        SymCryptGcmEncrypt(
            &cipherCtx->key,
            cipherCtx->iv, cipherCtx->ivlen,
            cipherCtx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload+cbPayload, EVP_GCM_TLS_TAG_LEN );

        ret = inl;
    }
    else
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it to the context
        memcpy(cipherCtx->iv + cipherCtx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN, out, EVP_GCM_TLS_EXPLICIT_IV_LEN);

        // Check ICV
        scError = SymCryptGcmDecrypt(
            &cipherCtx->key,
            cipherCtx->iv, cipherCtx->ivlen,
            cipherCtx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload+cbPayload, EVP_GCM_TLS_TAG_LEN );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        ret = cbPayload;
    }

cleanup:
    if( ret == -1 )
    {
        OPENSSL_cleanse(out, inl);
    }

    return ret;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH scossl_aes_gcm_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = -1;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if( cipherCtx->tlsAadSet )
    {
        return scossl_aes_gcm_tls(ctx, cipherCtx, out, in, inl, EVP_CIPHER_CTX_encrypting(ctx));
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
        goto cleanup;
    }

    if( EVP_CIPHER_CTX_encrypting(ctx) )
    {
        if( inl > 0 )
        {
            // Encrypt Part
            SymCryptGcmEncryptPart(&cipherCtx->state, in, out, inl);
            ret = inl;
        }
        else
        {
            // Final Encrypt Call
            SymCryptGcmEncryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            ret = 0;
        }
    }
    else
    {
        if( inl > 0 )
        {
            // Decrypt Part
            SymCryptGcmDecryptPart(&cipherCtx->state, in, out, inl);
            ret = inl;
        }
        else
        {
            // Final Decrypt Call
            scError = SymCryptGcmDecryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            if( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }
            ret = 0;
        }
    }

cleanup:
    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS scossl_aes_gcm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_gcm_ctx *cipherCtx = (struct cipher_gcm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct cipher_gcm_ctx *dstCtx;
    unsigned char *iv = NULL;
    UINT16 tls_buffer_len = 0;
    UINT16 min_tls_buffer_len = 0;
    switch( type )
    {
    case EVP_CTRL_INIT:
        cipherCtx->ivlen = SCOSSL_GCM_IV_LENGTH;
        iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
        if( iv )
        {
            memcpy(cipherCtx->iv, iv, cipherCtx->ivlen);
        }
        cipherCtx->taglen = EVP_GCM_TLS_TAG_LEN;
        cipherCtx->tlsAadSet = 0;
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = SCOSSL_GCM_IV_LENGTH;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        // SymCrypt currently only supports SCOSSL_GCM_IV_LENGTH
        if( arg != SCOSSL_GCM_IV_LENGTH )
        {
            SCOSSL_LOG_ERROR("SymCrypt Engine only supports %d byte IV for AES-GCM", SCOSSL_GCM_IV_LENGTH);
            return 0;
        }
        break;
    case EVP_CTRL_AEAD_SET_TAG:
        if( arg < SCOSSL_GCM_MIN_TAG_LENGTH || arg > SCOSSL_GCM_MAX_TAG_LENGTH || EVP_CIPHER_CTX_encrypting(ctx) )
        {
            SCOSSL_LOG_ERROR("Set tag error");
            return 0;
        }
        memcpy(cipherCtx->tag, ptr, arg);
        cipherCtx->taglen = arg;
        break;
    case EVP_CTRL_AEAD_GET_TAG:
        if( arg < SCOSSL_GCM_MIN_TAG_LENGTH || arg > SCOSSL_GCM_MAX_TAG_LENGTH ||
            arg > cipherCtx->taglen || !EVP_CIPHER_CTX_encrypting(ctx) )
        {
            SCOSSL_LOG_ERROR("Get tag error");
            return 0;
        }
        memcpy(ptr, cipherCtx->tag, arg);
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
        if( cipherCtx->ivlen != EVP_GCM_TLS_IV_LEN )
        {
            SCOSSL_LOG_ERROR("set_iv_fixed only works with TLS IV length");
            return 0;
        }
        if( arg == -1 )
        {
            memcpy(cipherCtx->iv, ptr, cipherCtx->ivlen);
            break;
        }
        if( arg != cipherCtx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN )
        {
            SCOSSL_LOG_ERROR("set_iv_fixed incorrect length");
            return 0;
        }
        // Set first 4B of IV to ptr value
        memcpy(cipherCtx->iv, ptr, cipherCtx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN);
        // If encrypting, randomly set the last 8B of IV
        if( EVP_CIPHER_CTX_encrypting(ctx) &&
            (RAND_bytes(cipherCtx->iv + cipherCtx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN, EVP_GCM_TLS_EXPLICIT_IV_LEN) <= 0) )
        {
            return 0;
        }
        break;
    case EVP_CTRL_AEAD_TLS1_AAD:
        if( arg != EVP_AEAD_TLS1_AAD_LEN )
        {
            SCOSSL_LOG_ERROR("Set tlsAad error");
            return 0;
        }
        memcpy(cipherCtx->tlsAad, ptr, EVP_AEAD_TLS1_AAD_LEN);
        cipherCtx->tlsAadSet = 1;

        if( EVP_CIPHER_CTX_encrypting(ctx) )
        {
            // Provided AAD contains len of plaintext + IV (8B)
            min_tls_buffer_len = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        }
        else
        {
            // Provided AAD contains len of ciphertext + IV (8B) + ICV (16B)
            min_tls_buffer_len = EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
        }

        tls_buffer_len = SYMCRYPT_LOAD_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2);
        if( tls_buffer_len < min_tls_buffer_len )
        {
            SCOSSL_LOG_ERROR("tls_buffer_len too short");
            return 0;
        }
        tls_buffer_len -= min_tls_buffer_len;
        SYMCRYPT_STORE_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2, tls_buffer_len);

        return EVP_GCM_TLS_TAG_LEN;
    default:
        SCOSSL_LOG_ERROR("SymCrypt Engine does not support control type (%d)", type);
        return 0;
    }
    return 1;
}

/*
 * AES-CCM Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS scossl_aes_ccm_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    struct cipher_ccm_ctx *cipherCtx = (struct cipher_ccm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    cipherCtx->ccmStage = SCOSSL_CCM_STAGE_INIT;
    cipherCtx->cbData = 0;
    if( iv )
    {
        memcpy(cipherCtx->iv, iv, cipherCtx->ivlen);
    }
    if( key )
    {
        scError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return 0;
        }
    }
    return 1;
}

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns length of out on success, or -1 on error.
static SCOSSL_RETURNLENGTH scossl_aes_ccm_tls(_In_ const EVP_CIPHER_CTX *ctx, _Inout_ struct cipher_ccm_ctx *cipherCtx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = -1;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbPayload = NULL;
    SIZE_T cbPayload = 0;

    // For TLS we only support in-place en/decryption of an ESP taking the form:
    // IV (8B) || Ciphertext (variable) || ICV (Auth Tag) (8 or 16B)

    // When encrypting, the space for the IV and ICV should be provided by the caller with the
    // plaintext starting 8B from the start of the buffer and ending 8 or 16B from the end
    if( in != out )
    {
        SCOSSL_LOG_ERROR("AES-CCM TLS does not support out-of-place operation");
        goto cleanup;
    }
    if( inl < (SIZE_T) EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherCtx->taglen )
    {
        SCOSSL_LOG_ERROR("AES-CCM TLS buffer too small");
        goto cleanup;
    }
    if( cipherCtx->ccmStage != SCOSSL_CCM_STAGE_INIT )
    {
        SCOSSL_LOG_ERROR("AES-CCM TLS operation cannot be multi-stage");
        goto cleanup;
    }
    if( cipherCtx->ivlen != EVP_CCM_TLS_IV_LEN )
    {
        SCOSSL_LOG_ERROR("AES-CCM TLS operation with incorrect IV length");
        goto cleanup;
    }
    if( cipherCtx->taglen != EVP_CCM_TLS_TAG_LEN && cipherCtx->taglen != EVP_CCM8_TLS_TAG_LEN )
    {
        SCOSSL_LOG_ERROR("AES-CCM TLS operation with incorrect tag length");
        goto cleanup;
    }

    pbPayload = out + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    cbPayload = inl - (EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherCtx->taglen);

    if( EVP_CIPHER_CTX_encrypting(ctx) )
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it from the context
        memcpy(out, cipherCtx->iv + cipherCtx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, EVP_CCM_TLS_EXPLICIT_IV_LEN);

        // Encrypt payload
        SymCryptCcmEncrypt(
            SymCryptAesBlockCipher,
            &cipherCtx->key,
            cipherCtx->iv, cipherCtx->ivlen,
            cipherCtx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload+cbPayload, cipherCtx->taglen );

        ret = inl;
    }
    else
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it to the context
        memcpy(cipherCtx->iv + cipherCtx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, out, EVP_CCM_TLS_EXPLICIT_IV_LEN);

        // Check ICV
        scError = SymCryptCcmDecrypt(
            SymCryptAesBlockCipher,
            &cipherCtx->key,
            cipherCtx->iv, cipherCtx->ivlen,
            cipherCtx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload+cbPayload, cipherCtx->taglen );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        ret = cbPayload;
    }

cleanup:
    if( ret == -1 )
    {
        OPENSSL_cleanse(out, inl);
    }

    return ret;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH scossl_aes_ccm_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = -1;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    struct cipher_ccm_ctx *cipherCtx = (struct cipher_ccm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    PCBYTE pbAuthData = NULL;
    SIZE_T cbAuthdata = 0;

    if( cipherCtx->tlsAadSet )
    {
        return scossl_aes_ccm_tls(ctx, cipherCtx, out, in, inl);
    }

    // See SCOSSL_CCM_STAGE definition above - callers to CCM must use the API in a very particular way
    if( cipherCtx->ccmStage == SCOSSL_CCM_STAGE_COMPLETE )
    {
        if( in == NULL )
        {
            if( out != NULL )
            {
                // Expected redundant Finalize call - allow context to be reused but do nothing else
                cipherCtx->ccmStage = SCOSSL_CCM_STAGE_INIT;
            }
            else
            {
                // Special case for openssl speed encrypt loop - set cbData
                cipherCtx->cbData = inl;
                cipherCtx->ccmStage = SCOSSL_CCM_STAGE_SET_CBDATA;
            }
            ret = 0;
            goto cleanup;
        }
        else
        {
            SCOSSL_LOG_ERROR("Data provided to CCM after CCM operation is complete");
            goto cleanup;
        }
    }

    if( cipherCtx->ccmStage == SCOSSL_CCM_STAGE_INIT )
    {
        if( in != NULL && out == NULL )
        {
            SCOSSL_LOG_ERROR("AAD provided to CCM before cbData has been set");
            goto cleanup;
        }

        cipherCtx->cbData = inl;
        cipherCtx->ccmStage = SCOSSL_CCM_STAGE_SET_CBDATA;

        if( in == NULL )
        {
            // Setting cbData for following call which may provide AAD
            ret = 0;
            goto cleanup;
        }
        // otherwise continue so we can perform the en/decryption with no AAD
    }

    if( cipherCtx->ccmStage == SCOSSL_CCM_STAGE_SET_CBDATA )
    {
        if( out == NULL )
        {
            // Auth Data Passed in
            pbAuthData = in;
            cbAuthdata = inl;
        }

        SymCryptCcmInit(
            &cipherCtx->state,
            SymCryptAesBlockCipher,
            &cipherCtx->key,
            cipherCtx->iv, cipherCtx->ivlen,
            pbAuthData, cbAuthdata,
            cipherCtx->cbData,
            cipherCtx->taglen);
        cipherCtx->ccmStage = SCOSSL_CCM_STAGE_SET_AAD;

        if( out == NULL )
        {
            // Auth Data Passed in
            ret = 0;
            goto cleanup;
        }
    }

    if( cipherCtx->ccmStage == SCOSSL_CCM_STAGE_SET_AAD)
    {
        if( EVP_CIPHER_CTX_encrypting(ctx) )
        {
            // Encryption
            if( in != NULL )
            {
                SymCryptCcmEncryptPart(&cipherCtx->state, in, out, inl);
            }
            SymCryptCcmEncryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            cipherCtx->ccmStage = SCOSSL_CCM_STAGE_COMPLETE;
        }
        else
        {
            // Decryption
            if( in != NULL )
            {
                SymCryptCcmDecryptPart(&cipherCtx->state, in, out, inl);
            }
            scError = SymCryptCcmDecryptFinal(&cipherCtx->state, cipherCtx->tag, cipherCtx->taglen);
            cipherCtx->ccmStage = SCOSSL_CCM_STAGE_COMPLETE;
            if( scError != SYMCRYPT_NO_ERROR )
            {
                ret = -1;
                goto cleanup;
            }
        }
        ret = inl;
    }

cleanup:
    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns 1 on success, or 0 on error.
static SCOSSL_STATUS scossl_aes_ccm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    struct cipher_ccm_ctx *cipherCtx = (struct cipher_ccm_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct cipher_ccm_ctx *dstCtx;
    unsigned char *iv = NULL;
    UINT16 tls_buffer_len = 0;
    UINT16 min_tls_buffer_len = 0;
    switch( type )
    {
    case EVP_CTRL_INIT:
        cipherCtx->ivlen = SCOSSL_CCM_MIN_IV_LENGTH;
        iv = (unsigned char *)EVP_CIPHER_CTX_iv(ctx);
        if( iv )
        {
            memcpy(cipherCtx->iv, iv, cipherCtx->ivlen);
        }
        cipherCtx->taglen = SCOSSL_CCM_MAX_TAG_LENGTH;
        cipherCtx->tlsAadSet = 0;
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = cipherCtx->ivlen;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        if( arg < SCOSSL_CCM_MIN_IV_LENGTH || arg > SCOSSL_CCM_MAX_IV_LENGTH )
        {
            SCOSSL_LOG_ERROR("SymCrypt Engine only supports [%d-%d] byte IVs for AES-CCM", SCOSSL_CCM_MIN_IV_LENGTH, SCOSSL_CCM_MAX_IV_LENGTH);
            return 0;
        }
        cipherCtx->ivlen = arg;
        break;
    case EVP_CTRL_AEAD_SET_TAG:
        if( (arg & 1) || arg < SCOSSL_CCM_MIN_TAG_LENGTH || arg > SCOSSL_CCM_MAX_TAG_LENGTH ||
            (EVP_CIPHER_CTX_encrypting(ctx) && ptr != NULL) )
        {
            SCOSSL_LOG_ERROR("Set tag error");
            return 0;
        }
        if( ptr != NULL )
        {
            memcpy(cipherCtx->tag, ptr, arg);
        }
        cipherCtx->taglen = arg;
        break;
    case EVP_CTRL_AEAD_GET_TAG:
        if( (arg & 1) || arg < SCOSSL_CCM_MIN_TAG_LENGTH || arg > SCOSSL_CCM_MAX_TAG_LENGTH ||
            arg > cipherCtx->taglen || !EVP_CIPHER_CTX_encrypting(ctx) )
        {
            SCOSSL_LOG_ERROR("Get tag error");
            return 0;
        }
        memcpy(ptr, cipherCtx->tag, arg);
        break;
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        dstCtx = (struct cipher_ccm_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptAesKeyCopy(&cipherCtx->key, &dstCtx->key);
        // make sure the dstCtx uses its copy of the expanded key TODO: implement SymCryptCcmStateCopy
        dstCtx->state = cipherCtx->state;
        dstCtx->state.pExpandedKey = &dstCtx->key;
        break;
    case EVP_CTRL_CCM_SET_IV_FIXED:
        if( cipherCtx->ivlen != EVP_CCM_TLS_IV_LEN )
        {
            SCOSSL_LOG_ERROR("set_iv_fixed only works with TLS IV length");
            return 0;
        }
        if( arg == -1 )
        {
            memcpy(cipherCtx->iv, ptr, cipherCtx->ivlen);
            break;
        }
        if( arg != cipherCtx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN )
        {
            SCOSSL_LOG_ERROR("set_iv_fixed incorrect length");
            return 0;
        }
        // Set first 4B of IV to ptr value
        memcpy(cipherCtx->iv, ptr, cipherCtx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN);
        // If encrypting, randomly set the last 8B of IV
        if( EVP_CIPHER_CTX_encrypting(ctx) &&
            (RAND_bytes(cipherCtx->iv + cipherCtx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, EVP_CCM_TLS_EXPLICIT_IV_LEN) <= 0) )
        {
            return 0;
        }
        break;
    case EVP_CTRL_AEAD_TLS1_AAD:
        if( arg != EVP_AEAD_TLS1_AAD_LEN )
        {
            SCOSSL_LOG_ERROR("Set tlsAad error");
            return 0;
        }
        if( cipherCtx->taglen != EVP_CCM_TLS_TAG_LEN && cipherCtx->taglen != EVP_CCM8_TLS_TAG_LEN )
        {
            SCOSSL_LOG_ERROR("Invalid taglen for TLS");
            return 0;
        }
        memcpy(cipherCtx->tlsAad, ptr, EVP_AEAD_TLS1_AAD_LEN);
        cipherCtx->tlsAadSet = 1;

        if( EVP_CIPHER_CTX_encrypting(ctx) )
        {
            // Provided AAD contains len of plaintext + IV (8B)
            min_tls_buffer_len = EVP_CCM_TLS_EXPLICIT_IV_LEN;
        }
        else
        {
            // Provided AAD contains len of ciphertext + IV (8B) + ICV (16B)
            min_tls_buffer_len = EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherCtx->taglen;
        }

        tls_buffer_len = SYMCRYPT_LOAD_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2);
        if( tls_buffer_len < min_tls_buffer_len )
        {
            SCOSSL_LOG_ERROR("tls_buffer_len too short");
            return 0;
        }
        tls_buffer_len -= min_tls_buffer_len;
        SYMCRYPT_STORE_MSBFIRST16(cipherCtx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2, tls_buffer_len);

        return cipherCtx->taglen;
    default:
        SCOSSL_LOG_ERROR("SymCrypt Engine does not support control type (%d)", type);
        return 0;
    }
    return 1;
}

#ifdef __cplusplus
}
#endif
