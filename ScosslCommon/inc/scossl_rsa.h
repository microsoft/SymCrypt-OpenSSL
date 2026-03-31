//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *d;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
} SCOSSL_RSA_PRIVATE_EXPORT_PARAMS;

typedef struct
{
    BIGNUM *n;
    BIGNUM *e;
    SCOSSL_RSA_PRIVATE_EXPORT_PARAMS *privateParams;
} SCOSSL_RSA_EXPORT_PARAMS;

SCOSSL_STATUS scossl_rsa_pkcs1_sign(_In_ PSYMCRYPT_RSAKEY key, int mdnid,
                                    _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                    _Out_writes_bytes_(*pcbSignature) PBYTE pbSignature, _Out_ SIZE_T* pcbSignature);
SCOSSL_STATUS scossl_rsa_pkcs1_verify(_In_ PSYMCRYPT_RSAKEY key, int mdnid,
                                      _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                      _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);

SCOSSL_STATUS scossl_rsapss_sign(_In_ PSYMCRYPT_RSAKEY key, int mdnid, int cbSalt,
                                 _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                 _Out_writes_bytes_(*pcbSignature) PBYTE pbSignature, _Out_ SIZE_T* pcbSignature);
SCOSSL_STATUS scossl_rsapss_verify(_In_ PSYMCRYPT_RSAKEY key, int mdnid, int cbSalt,
                                   _In_reads_bytes_(cbHashValue) PCBYTE pbHashValue, SIZE_T cbHashValue,
                                   _In_reads_bytes_(pcbSignature) PCBYTE pbSignature, SIZE_T pcbSignature);

SCOSSL_STATUS scossl_rsa_encrypt(_In_ PSYMCRYPT_RSAKEY key, UINT8 padding,
                                 int mdnid, _In_reads_bytes_opt_(cbLabel) PCBYTE pbLabel, SIZE_T cbLabel,
                                 _In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc,
                                 _Out_writes_bytes_(*pcbDst) PBYTE pbDst, _Out_ INT32 *pcbDst, SIZE_T cbDst);

SCOSSL_STATUS scossl_rsa_decrypt(_In_ PSYMCRYPT_RSAKEY key, UINT8 padding,
                                 int mdnid, _In_reads_bytes_opt_(cbLabel) PCBYTE pbLabel, SIZE_T cbLabel,
                                 _In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc,
                                 _Out_writes_bytes_(*pcbDst) PBYTE pbDst, _Out_ INT32 *pcbDst, SIZE_T cbDst);

SCOSSL_RSA_EXPORT_PARAMS *scossl_rsa_new_export_params(BOOL includePrivate);
void scossl_rsa_free_export_params(_In_ SCOSSL_RSA_EXPORT_PARAMS *rsaParam, BOOL freeParams);
SCOSSL_STATUS scossl_rsa_export_key(_In_ PCSYMCRYPT_RSAKEY key, _Out_ SCOSSL_RSA_EXPORT_PARAMS *rsaParams);

SIZE_T scossl_get_expected_hash_length(int mdnid);
int scossl_rsa_pss_get_salt_max(_In_ PSYMCRYPT_RSAKEY key, SIZE_T cbHashValue);

#ifdef __cplusplus
}
#endif