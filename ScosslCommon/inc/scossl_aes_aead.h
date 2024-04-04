//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/evp.h>
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// RFC5647 section 7 documents a specific way for AES-GCM IVs to be formed
//
// It appears that a slightly more generalized way of forming IVs, of which RFC5647 is a subset, is
// supported in OpenSSL APIs using undocumented controls:
// EVP_CTRL_GCM_SET_IV_FIXED, EVP_CTRL_GCM_IV_GEN, and EVP_CTRL_GCM_SET_IV_INV
// The idea is to support IV generation with an AES-GCM context, rather than making the caller have
// to explicitly track and update the IV.
//
// My understanding from looking at how these controls are used, and reading the RFC is:
//  EVP_CTRL_GCM_SET_IV_FIXED is used to set up an initial IV
//      The caller has 2 options:
//          1) Set the whole IV (including the initial value of the invocation counter), by
//             providing the full 12 bytes
//          2) Set the fixed part of the IV (up to 4 bytes), and allow the initial value of the
//             invocation counter (the rest of the initial IV) to be set randomly
//
//  EVP_CTRL_GCM_IV_GEN is used to consume an IV, and indicate the invocation field (at least 8
//  bytes) must be incremented to form the next IV
//
//  EVP_CTRL_GCM_SET_IV_INV is used in decryption to set only the invocation field
//
// In SCOSSL we are tracking this using the fields below:
//  ivInvocation is the 64b counter which is incremented on each call to EVP_CTRL_GCM_IV_GEN, the
//  MSB first value is inserted into the IV. Caller will guarantee there are not 2^64 calls.
//  useInvocation is set to 1 to indicate that the ivInvocation field is in use (set on a successful
//  call to EVP_CTRL_GCM_SET_IV_FIXED)

#define SCOSSL_GCM_IV_LENGTH (12)
#define SCOSSL_GCM_MIN_IV_LENGTH (1)
#define SCOSSL_GCM_MIN_TAG_LENGTH (12)
#define SCOSSL_GCM_MAX_TAG_LENGTH (16)

#define EVP_GCM_TLS_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)

typedef struct
{
    INT32 operationInProgress;
    PBYTE iv;
    SIZE_T ivlen;
    SYMCRYPT_GCM_STATE state;
    SYMCRYPT_GCM_EXPANDED_KEY key;
    BYTE tag[EVP_GCM_TLS_TAG_LEN];
    SIZE_T taglen;
    BYTE tlsAad[EVP_AEAD_TLS1_AAD_LEN];
    INT32 tlsAadSet;
    UINT64 ivInvocation;
    INT32 useInvocation;

    SIZE_T keylen;
    INT32 encrypt;
} SCOSSL_CIPHER_GCM_CTX;

#define SCOSSL_CCM_MIN_IV_LENGTH (7)
#define SCOSSL_CCM_MAX_IV_LENGTH (13)
#define SCOSSL_CCM_MIN_TAG_LENGTH (4)
#define SCOSSL_CCM_MAX_TAG_LENGTH (16)

// The way CCM works with the EVP APIs is quite specific, there are 2 cases:
//  Encrypt/Decrypt with no AAD
//      => We expect 1 call to en/decrypt the buffer from in to out (and set return to failure on tag mismatch for decrypt)
//      => Then 1 call to "finalize" - does nothing (in==NULL, inl==0, out!=NULL)
//  Encrypt/Decrypt with AAD
//      => We expect 1 call to set the total input length (i.e. plain/ciphertext + AAD) (in==NULL, inl==cbData, out==NULL)
//      => Then 1 call to set all of the AAD (if any) (in==pbAuthData, inl==cbAuthData, out==NULL)
//      => Then 1 call to en/decrypt the buffer from in to out (and set return to failure on tag mismatch for decrypt)
//      => Then 1 call to "finalize" - does nothing (in==NULL, inl==0, out!=NULL)
typedef enum
{
    SCOSSL_CCM_STAGE_INIT = 0,   // The initial state
    SCOSSL_CCM_STAGE_SET_CBDATA, // The state after a call providing the total input length
    SCOSSL_CCM_STAGE_SET_AAD,    // The state after a call providing the AAD
    SCOSSL_CCM_STAGE_COMPLETE,   // The state after a call providing the plain/ciphertext
} SCOSSL_CCM_STAGE;

typedef struct
{
    SCOSSL_CCM_STAGE ccmStage;
    BYTE iv[SCOSSL_CCM_MAX_IV_LENGTH];
    SYMCRYPT_CCM_STATE state;
    SYMCRYPT_AES_EXPANDED_KEY key;
    BYTE tag[EVP_CCM_TLS_TAG_LEN];
    SIZE_T taglen;
    UINT64 cbData;
    BYTE tlsAad[EVP_AEAD_TLS1_AAD_LEN];
    INT32 tlsAadSet;

    // Provider-only fields. Tracked by EVP_CIPHER_CTX in engine
    SIZE_T ivlen;
    SIZE_T keylen;
    INT32 encrypt;
} SCOSSL_CIPHER_CCM_CTX;

SCOSSL_STATUS scossl_aes_gcm_init_ctx(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                      _In_reads_bytes_opt_(ivlen) const unsigned char *iv);
SCOSSL_STATUS scossl_aes_gcm_init_key(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                      _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                      _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen);
SCOSSL_STATUS scossl_aes_gcm_cipher(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                    _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl,
                                    _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
SCOSSL_STATUS scossl_aes_gcm_get_aead_tag(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          _Out_writes_bytes_(taglen) unsigned char *tag, size_t taglen);
SCOSSL_STATUS scossl_aes_gcm_set_aead_tag(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          _In_reads_bytes_(taglen) unsigned char *tag, size_t taglen);
SCOSSL_STATUS scossl_aes_gcm_set_iv_len(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, size_t ivlen);
SCOSSL_STATUS scossl_aes_gcm_set_iv_fixed(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          _In_ unsigned char *iv, size_t ivlen);
SCOSSL_STATUS scossl_aes_gcm_iv_gen(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx,
                                    _Out_writes_bytes_(outsize) unsigned char *out, size_t outsize);
SCOSSL_STATUS scossl_aes_gcm_set_iv_inv(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                        _In_ unsigned char *iv, size_t ivlen);
UINT16 scossl_aes_gcm_set_tls1_aad(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                   _In_reads_bytes_(aadlen) unsigned char *aad, size_t aadlen);

void scossl_aes_ccm_init_ctx(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                             _In_opt_ const unsigned char *iv);
SCOSSL_STATUS scossl_aes_ccm_init_key(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx,
                                      _In_reads_bytes_opt_(keylen) const unsigned char *key, size_t keylen,
                                      _In_reads_bytes_opt_(ivlen) const unsigned char *iv, size_t ivlen);
SCOSSL_STATUS scossl_aes_ccm_cipher(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                    _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl,
                                    _In_reads_bytes_(inl) const unsigned char *in, size_t inl);
SCOSSL_STATUS scossl_aes_ccm_get_aead_tag(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          _Out_writes_bytes_(taglen) unsigned char *tag, size_t taglen);
SCOSSL_STATUS scossl_aes_ccm_set_aead_tag(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          _In_reads_bytes_(taglen) unsigned char *tag, size_t taglen);
SCOSSL_STATUS scossl_aes_ccm_set_iv_len(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, size_t ivlen);
SCOSSL_STATUS scossl_aes_ccm_set_iv_fixed(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          _In_ unsigned char *iv, size_t ivlen);
UINT16 scossl_aes_ccm_set_tls1_aad(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                   _In_reads_bytes_(aadlen) unsigned char *aad, size_t aadlen);

#ifdef __cplusplus
}
#endif