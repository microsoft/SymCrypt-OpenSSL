//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#define OSSL_MAX_NAME_SIZE 50

typedef struct 
{
    void *vLibCtx;

    int initialized;
    PSYMCRYPT_RSAKEY key;
} SCOSSL_RSA_KEY_CTX;

typedef struct
{
    SCOSSL_RSA_KEY_CTX *kctx;
    UINT padding;
    UINT operation;

    // Needed for fetching 
    OSSL_LIB_CTX *libctx;
    char* propq;

    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    char mdname[OSSL_MAX_NAME_SIZE];
    int mdnid;
    BOOL allowMdUpdates;

    // PSS params
    char mgf1mdname[OSSL_MAX_NAME_SIZE];
    int mgf1mdnid;
    int cbSalt;
} SCOSSL_RSA_SIGN_CTX;

// The minimum PKCS1 padding is 11 bytes
#define SCOSSL_MIN_PKCS1_PADDING (11)
// The minimum OAEP padding is 2*hashlen + 2, and the minimum hashlen is SHA1 - with 20B hash => minimum 42B of padding
#define SCOSSL_MIN_OAEP_PADDING (42)

// Hash digest lengths
#define SCOSSL_MD5_DIGEST_LENGTH (16)
#define SCOSSL_SHA1_DIGEST_LENGTH (20)
#define SCOSSL_MD5_SHA1_DIGEST_LENGTH (SCOSSL_MD5_DIGEST_LENGTH + SCOSSL_SHA1_DIGEST_LENGTH) //36
#define SCOSSL_SHA256_DIGEST_LENGTH (32)
#define SCOSSL_SHA384_DIGEST_LENGTH (48)
#define SCOSSL_SHA512_DIGEST_LENGTH (64)

// Option added in 3.1, but unused in the engine. Redefined here
// so it can be used in common code.
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4
#endif

SCOSSL_RSA_KEY_CTX *scossl_rsa_new_key_ctx();
SCOSSL_RSA_KEY_CTX *scossl_rsa_dup_key_ctx(_In_ const SCOSSL_RSA_KEY_CTX *keyCtx);
void scossl_rsa_free_key_ctx(_In_ SCOSSL_RSA_KEY_CTX *keyCtx);

SCOSSL_STATUS scossl_rsa_pkcs1_sign(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid, 
                                    _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                    _Out_writes_bytes_(*pcbSignature) PBYTE pbSignature, _Out_ SIZE_T* pcbSignature);
SCOSSL_STATUS scossl_rsa_pkcs1_verify(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, int mdnid, 
                                      _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                      _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);
SCOSSL_STATUS scossl_rsapss_sign(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, _In_ EVP_MD *md, int cbSalt, 
                                 _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                 _Out_writes_bytes_(*pcbSignature) PBYTE pbSignature, _Out_ SIZE_T* pcbSignature);
SCOSSL_STATUS scossl_rsapss_verify(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, _In_ EVP_MD *md, int cbSalt, 
                                   _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                   _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);

                                