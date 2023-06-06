//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#define OSSL_MAX_NAME_SIZE 50

typedef struct 
{
    int initialized;
    PSYMCRYPT_RSAKEY key;
} SCOSSL_RSA_KEY_CTX;

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

SCOSSL_STATUS scossl_rsa_encrypt(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding, int mdnid,
                                 _In_reads_bytes_opt_(cbLabel) PCBYTE pbLabel, SIZE_T cbLabel,
                                 _In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc,
                                 _Out_writes_bytes_(*pcbDst) PBYTE pbDst, _Out_ INT32 *pcbDst, SIZE_T cbDst);

SCOSSL_STATUS scossl_rsa_decrypt(_In_ SCOSSL_RSA_KEY_CTX *keyCtx, UINT padding, int mdnid,
                                 _In_reads_bytes_opt_(cbLabel) PCBYTE pbLabel, SIZE_T cbLabel,
                                 _In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc,
                                 _Out_writes_bytes_(*pcbDst) PBYTE pbDst, _Out_ INT32 *pcbDst, SIZE_T cbDst);