//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_aead_ciphers.h"
#include "e_scossl_ciphers.h"

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

SCOSSL_STATUS e_scossl_aes_cbc_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS e_scossl_aes_cbc_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS e_scossl_aes_cbc_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_CBC_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE|EVP_CIPH_CUSTOM_COPY \
                         |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_FLAG_FIPS)

/* AES128 - CBC */
static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *e_scossl_aes_128_cbc(void)
{
    if( (_hidden_aes_128_cbc = EVP_CIPHER_meth_new(NID_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc, e_scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc, e_scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc, e_scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}

/* AES192 - CBC */
static EVP_CIPHER *_hidden_aes_192_cbc = NULL;
static const EVP_CIPHER *e_scossl_aes_192_cbc(void)
{
    if( (_hidden_aes_192_cbc = EVP_CIPHER_meth_new(NID_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_cbc, e_scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_cbc, e_scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_cbc, e_scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_cbc);
        _hidden_aes_192_cbc = NULL;
    }
    return _hidden_aes_192_cbc;
}

/* AES256 - CBC */
static EVP_CIPHER *_hidden_aes_256_cbc = NULL;
static const EVP_CIPHER *e_scossl_aes_256_cbc(void)
{
    if( (_hidden_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc, AES_CBC_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc, e_scossl_aes_cbc_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc, e_scossl_aes_cbc_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc, e_scossl_aes_cbc_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc, sizeof(struct cipher_cbc_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
        _hidden_aes_256_cbc = NULL;
    }
    return _hidden_aes_256_cbc;
}

SCOSSL_STATUS e_scossl_aes_ecb_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS e_scossl_aes_ecb_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS e_scossl_aes_ecb_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_ECB_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_ECB_MODE|EVP_CIPH_CUSTOM_COPY \
                         |EVP_CIPH_FLAG_FIPS)

/* AES128 - ecb */
static EVP_CIPHER *_hidden_aes_128_ecb = NULL;
static const EVP_CIPHER *e_scossl_aes_128_ecb(void)
{
    if( (_hidden_aes_128_ecb = EVP_CIPHER_meth_new(NID_aes_128_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ecb, e_scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ecb, e_scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_ecb, e_scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
        _hidden_aes_128_ecb = NULL;
    }
    return _hidden_aes_128_ecb;
}

/* AES192 - ecb */
static EVP_CIPHER *_hidden_aes_192_ecb = NULL;
static const EVP_CIPHER *e_scossl_aes_192_ecb(void)
{
    if( (_hidden_aes_192_ecb = EVP_CIPHER_meth_new(NID_aes_192_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ecb, e_scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ecb, e_scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_ecb, e_scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
        _hidden_aes_192_ecb = NULL;
    }
    return _hidden_aes_192_ecb;
}

/* AES256 - ecb */
static EVP_CIPHER *_hidden_aes_256_ecb = NULL;
static const EVP_CIPHER *e_scossl_aes_256_ecb(void)
{
    if( (_hidden_aes_256_ecb = EVP_CIPHER_meth_new(NID_aes_256_ecb, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ecb, AES_ECB_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ecb, e_scossl_aes_ecb_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ecb, e_scossl_aes_ecb_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_ecb, e_scossl_aes_ecb_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ecb, sizeof(struct cipher_ecb_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
        _hidden_aes_256_ecb = NULL;
    }
    return _hidden_aes_256_ecb;
}

// Disabling XTS for now - remove with if region to avoid unused function warning
#if 0
SCOSSL_STATUS e_scossl_aes_xts_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_STATUS e_scossl_aes_xts_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static SCOSSL_STATUS e_scossl_aes_xts_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_XTS_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_XTS_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_FLAG_CUSTOM_CIPHER)

/* AES128 - XTS */
static EVP_CIPHER *_hidden_aes_128_xts = NULL;
static const EVP_CIPHER *e_scossl_aes_128_xts(void)
{
    if( (_hidden_aes_128_xts = EVP_CIPHER_meth_new(NID_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_128_KEY_SIZE * 2)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_xts, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_xts, AES_XTS_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_xts, e_scossl_aes_xts_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_xts, e_scossl_aes_xts_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_xts, e_scossl_aes_xts_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_xts, sizeof(struct cipher_xts_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_xts);
        _hidden_aes_128_xts = NULL;
    }
    return _hidden_aes_128_xts;
}

/* AES256 - XTS */
static EVP_CIPHER *_hidden_aes_256_xts = NULL;
static const EVP_CIPHER *e_scossl_aes_256_xts(void)
{
    if( (_hidden_aes_256_xts = EVP_CIPHER_meth_new(NID_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE , AES_256_KEY_SIZE * 2)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_xts, SYMCRYPT_AES_BLOCK_SIZE)
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_xts, AES_XTS_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_xts, e_scossl_aes_xts_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_xts, e_scossl_aes_xts_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_xts, e_scossl_aes_xts_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_xts, sizeof(struct cipher_xts_ctx)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_xts);
        _hidden_aes_256_xts = NULL;
    }
    return _hidden_aes_256_xts;
}
#endif


SCOSSL_STATUS e_scossl_aes_gcm_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_RETURNLENGTH e_scossl_aes_gcm_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static _Success_(return > 0) int e_scossl_aes_gcm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_GCM_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_CUSTOM_IV_LENGTH|EVP_CIPH_FLAG_CUSTOM_CIPHER \
                        |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CTRL_INIT|EVP_CIPH_FLAG_AEAD_CIPHER \
                        |EVP_CIPH_FLAG_FIPS)

/* AES128 - GCM */
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;
static const EVP_CIPHER *e_scossl_aes_128_gcm(void)
{
    if( (_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm, e_scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm, e_scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, e_scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm, sizeof(SCOSSL_CIPHER_GCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

/* AES192 - GCM */
static EVP_CIPHER *_hidden_aes_192_gcm = NULL;
static const EVP_CIPHER *e_scossl_aes_192_gcm(void)
{
    if( (_hidden_aes_192_gcm = EVP_CIPHER_meth_new(NID_aes_192_gcm, 1, AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_gcm, e_scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_gcm, e_scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_gcm, e_scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_gcm, sizeof(SCOSSL_CIPHER_GCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_gcm);
        _hidden_aes_192_gcm = NULL;
    }
    return _hidden_aes_192_gcm;
}

/* AES256 - GCM */
static EVP_CIPHER *_hidden_aes_256_gcm = NULL;
static const EVP_CIPHER *e_scossl_aes_256_gcm(void)
{
    if( (_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm, 1, AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm, e_scossl_aes_gcm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm, e_scossl_aes_gcm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, e_scossl_aes_gcm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm, sizeof(SCOSSL_CIPHER_GCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
        _hidden_aes_256_gcm = NULL;
    }
    return _hidden_aes_256_gcm;
}

SCOSSL_STATUS e_scossl_aes_ccm_init_key(
    _Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key, _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc);
SCOSSL_RETURNLENGTH e_scossl_aes_ccm_cipher(
    _Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out, _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
static _Success_(return > 0) int e_scossl_aes_ccm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg, _Inout_ void *ptr);
#define AES_CCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CCM_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_CUSTOM_IV_LENGTH|EVP_CIPH_FLAG_CUSTOM_CIPHER \
                        |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CTRL_INIT|EVP_CIPH_FLAG_AEAD_CIPHER \
                        |EVP_CIPH_FLAG_FIPS )

/* AES128 - CCM */
static EVP_CIPHER *_hidden_aes_128_ccm = NULL;
static const EVP_CIPHER *e_scossl_aes_128_ccm(void)
{
    if( (_hidden_aes_128_ccm = EVP_CIPHER_meth_new(NID_aes_128_ccm, 1, AES_128_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ccm, e_scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ccm, e_scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_ccm, e_scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ccm, sizeof(SCOSSL_CIPHER_CCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_128_ccm);
        _hidden_aes_128_ccm = NULL;
    }
    return _hidden_aes_128_ccm;
}

/* AES192 - CCM */
static EVP_CIPHER *_hidden_aes_192_ccm = NULL;
static const EVP_CIPHER *e_scossl_aes_192_ccm(void)
{
    if( (_hidden_aes_192_ccm = EVP_CIPHER_meth_new(NID_aes_192_ccm, 1, AES_192_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ccm, e_scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ccm, e_scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_192_ccm, e_scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ccm, sizeof(SCOSSL_CIPHER_CCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_192_ccm);
        _hidden_aes_192_ccm = NULL;
    }
    return _hidden_aes_192_ccm;
}

/* AES256 - CCM */
static EVP_CIPHER *_hidden_aes_256_ccm = NULL;
static const EVP_CIPHER *e_scossl_aes_256_ccm(void)
{
    if( (_hidden_aes_256_ccm = EVP_CIPHER_meth_new(NID_aes_256_ccm, 1, AES_256_KEY_SIZE)) == NULL
        || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ccm, AES_CCM_FLAGS)
        || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ccm, e_scossl_aes_ccm_init_key)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ccm, e_scossl_aes_ccm_cipher)
        || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_ccm, e_scossl_aes_ccm_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ccm, sizeof(SCOSSL_CIPHER_CCM_CTX)) )
    {
        EVP_CIPHER_meth_free(_hidden_aes_256_ccm);
        _hidden_aes_256_ccm = NULL;
    }
    return _hidden_aes_256_ccm;
}


void e_scossl_destroy_ciphers(void)
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

SCOSSL_STATUS e_scossl_ciphers_init_static()
{
    if( (e_scossl_aes_128_cbc() == NULL) ||
        (e_scossl_aes_192_cbc() == NULL) ||
        (e_scossl_aes_256_cbc() == NULL) ||
        (e_scossl_aes_128_ecb() == NULL) ||
        (e_scossl_aes_192_ecb() == NULL) ||
        (e_scossl_aes_256_ecb() == NULL) ||
        // (e_scossl_aes_128_xts() == NULL) ||
        // (e_scossl_aes_256_xts() == NULL) ||
        (e_scossl_aes_128_gcm() == NULL) ||
        (e_scossl_aes_192_gcm() == NULL) ||
        (e_scossl_aes_256_gcm() == NULL) ||
        (e_scossl_aes_128_ccm() == NULL) ||
        (e_scossl_aes_192_ccm() == NULL) ||
        (e_scossl_aes_256_ccm() == NULL) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

int e_scossl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
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
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_cbc_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    struct cipher_cbc_ctx *cipherCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    if( key )
    {
        scError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_cbc_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
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

    return SCOSSL_SUCCESS;
}

// Allows various cipher specific parameters to be determined and set.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
static SCOSSL_STATUS e_scossl_aes_cbc_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
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
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

/*
 * AES-ECB Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_ecb_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    struct cipher_ecb_ctx *cipherCtx = (struct cipher_ecb_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    if( key )
    {
        scError = SymCryptAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

// Encrypts or decrypts in, storing result in out, depending on mode set in ctx.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_ecb_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
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

    return SCOSSL_SUCCESS;
}

// Allows various cipher specific parameters to be determined and set.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
static SCOSSL_STATUS e_scossl_aes_ecb_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
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
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

// Disabling XTS for now - remove with if region to avoid unused function warning
#if 0
/*
 * AES-XTS Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_xts_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
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
        return SCOSSL_FAILURE;
    }
    if( key )
    {
        scError = SymCryptXtsAesExpandKey(&cipherCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));
        if( scError != SYMCRYPT_NO_ERROR )
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH e_scossl_aes_xts_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = 0;
    struct cipher_xts_ctx *cipherCtx = (struct cipher_xts_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if( inl > 0 )
    {
        if( (inl % SYMCRYPT_AES_BLOCK_SIZE) != 0 )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_XTS_CIPHER, ERR_R_PASSED_INVALID_ARGUMENT,
                "Data length (%d) is not a multiple of the AES block size. SymCrypt does not support this size", inl);
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
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
static SCOSSL_STATUS e_scossl_aes_xts_ctrl(_In_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    switch( type )
    {
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_XTS_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "No copy method currently implemented");
        // We need a SymCryptXtsKeyCopy function for this as we don't have explicit control over the AES key
        // struct here
        // srcCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(                  ctx);
        // dstCtx = (struct cipher_cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        // SymCryptXtsKeyCopy(&srcCtx->key, &dstCtx->key);
        return SCOSSL_FAILURE;
    default:
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}
#endif

/*
 * AES-GCM Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_gcm_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    SCOSSL_CIPHER_GCM_CTX *cipherCtx = (SCOSSL_CIPHER_GCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    return scossl_aes_gcm_init_key(cipherCtx, key, EVP_CIPHER_CTX_key_length(ctx), iv, EVP_CIPHER_CTX_iv_length(ctx));
}

#define EVP_GCM_TLS_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH e_scossl_aes_gcm_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = -1;
    size_t outl;
    SCOSSL_CIPHER_GCM_CTX *cipherCtx = (SCOSSL_CIPHER_GCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if ( scossl_aes_gcm_cipher(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), out, &outl, in, inl) )
    {
        ret = outl;
    }

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE on error, or taglen on successful query of
// EVP_CTRL_AEAD_TLS1_AAD.
static int e_scossl_aes_gcm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    SCOSSL_CIPHER_GCM_CTX *cipherCtx = (SCOSSL_CIPHER_GCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SCOSSL_CIPHER_GCM_CTX *dstCtx;
    switch( type )
    {
    case EVP_CTRL_INIT:
        scossl_aes_gcm_init_ctx(cipherCtx, EVP_CIPHER_CTX_key_length(ctx), EVP_CIPHER_CTX_iv(ctx));
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = SCOSSL_GCM_IV_LENGTH;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        // SymCrypt currently only supports SCOSSL_GCM_IV_LENGTH
        if( arg != SCOSSL_GCM_IV_LENGTH )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
                "SymCrypt Engine only supports %d byte IV for AES-GCM", SCOSSL_GCM_IV_LENGTH);
            return SCOSSL_FAILURE;
        }
        break;
    case EVP_CTRL_AEAD_SET_TAG:
        return scossl_aes_gcm_set_aead_tag(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_AEAD_GET_TAG:
        return scossl_aes_gcm_get_aead_tag(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the GCM structs using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        dstCtx = (SCOSSL_CIPHER_GCM_CTX *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptGcmKeyCopy(&cipherCtx->key, &dstCtx->key);
        SymCryptGcmStateCopy(&cipherCtx->state, &dstCtx->key, &dstCtx->state);
        break;
    case EVP_CTRL_GCM_SET_IV_FIXED:
        return scossl_aes_gcm_set_iv_fixed(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_GCM_IV_GEN:
        return scossl_aes_gcm_iv_gen(cipherCtx, ptr, arg);
    case EVP_CTRL_GCM_SET_IV_INV:
        return scossl_aes_gcm_set_iv_inv(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_AEAD_TLS1_AAD:
        return scossl_aes_gcm_set_tls1_aad(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support control type (%d)", type);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

/*
 * AES-CCM Implementation
 */

// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns SCOSSL_SUCCESS on success, or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_aes_ccm_init_key(_Inout_ EVP_CIPHER_CTX *ctx, _In_ const unsigned char *key,
                             _In_ const unsigned char *iv, SCOSSL_ENCRYPTION_MODE enc)
{
    SCOSSL_CIPHER_CCM_CTX *cipherCtx = (SCOSSL_CIPHER_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    return scossl_aes_ccm_init_key(cipherCtx, key, EVP_CIPHER_CTX_key_length(ctx), iv, cipherCtx->ivlen);
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of bytes written to out on success (may be 0)
SCOSSL_RETURNLENGTH e_scossl_aes_ccm_cipher(_Inout_ EVP_CIPHER_CTX *ctx, _Out_ unsigned char *out,
                               _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    int ret = -1;
    size_t outl;
    SCOSSL_CIPHER_CCM_CTX *cipherCtx = (SCOSSL_CIPHER_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if ( scossl_aes_ccm_cipher(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), out, &outl, in, inl) )
    {
        ret = outl;
    }

    return ret;
}

// Allows various cipher specific parameters to be determined and set.
// Returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE on error, or taglen on successful query of
// EVP_CTRL_AEAD_TLS1_AAD.
static int e_scossl_aes_ccm_ctrl(_Inout_ EVP_CIPHER_CTX *ctx, int type, int arg,
                                    _Inout_ void *ptr)
{
    SCOSSL_CIPHER_CCM_CTX *cipherCtx = (SCOSSL_CIPHER_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    SCOSSL_CIPHER_CCM_CTX *dstCtx;

    switch( type )
    {
    case EVP_CTRL_INIT:
        scossl_aes_ccm_init_ctx(cipherCtx, EVP_CIPHER_CTX_key_length(ctx), EVP_CIPHER_CTX_iv(ctx));
        break;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = cipherCtx->ivlen;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        return scossl_aes_ccm_set_iv_len(cipherCtx, arg);
    case EVP_CTRL_AEAD_SET_TAG:
        return scossl_aes_ccm_set_aead_tag(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_AEAD_GET_TAG:
        return scossl_aes_ccm_get_aead_tag(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_COPY:
        // We expose the EVP_CTRL_COPY method which is called after the cipher context is copied because we
        // set EVP_CIPH_CUSTOM_COPY flag on all our AES ciphers
        // We must explicitly copy the AES key struct using SymCrypt as the AES key structure contains pointers
        // to itself, so a plain memcpy will maintain pointers to the source context
        dstCtx = (SCOSSL_CIPHER_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data((EVP_CIPHER_CTX *)ptr);
        SymCryptAesKeyCopy(&cipherCtx->key, &dstCtx->key);
        // make sure the dstCtx uses its copy of the expanded key TODO: implement SymCryptCcmStateCopy
        dstCtx->state = cipherCtx->state;
        dstCtx->state.pExpandedKey = &dstCtx->key;
        break;
    case EVP_CTRL_CCM_SET_IV_FIXED:
        return scossl_aes_ccm_set_iv_fixed(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    case EVP_CTRL_AEAD_TLS1_AAD:
        return scossl_aes_ccm_set_tls1_aad(cipherCtx, EVP_CIPHER_CTX_encrypting(ctx), ptr, arg);
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_CTRL, SCOSSL_ERR_R_NOT_IMPLEMENTED,
            "SymCrypt Engine does not support control type (%d)", type);
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

#ifdef __cplusplus
}
#endif
