//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define select_PrivateKeyInfo OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define select_EncryptedPrivateKeyInfo OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define select_SubjectPublicKeyInfo OSSL_KEYMGMT_SELECT_PUBLIC_KEY

typedef enum {
    SCOSSL_ENCODE_DER = 1,
    SCOSSL_ENCODE_PEM,
    SCOSSL_ENCODE_TEXT
} SCOSSL_ENCODE_OUT_FORMAT;

typedef SCOSSL_STATUS (*PSCOSSL_ENCODE_INTERNAL_FN) (_In_ PVOID encodeCtx, _Inout_ BIO *out,
                                                     _In_ PCVOID keyCtx,
                                                     int selection,
                                                     _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);

typedef struct
{
    int selection;
    SCOSSL_ENCODE_OUT_FORMAT outFormat;

    PSCOSSL_ENCODE_INTERNAL_FN encodeInternal;
} SCOSSL_ENCODE_KEYTYPE_DESC;

typedef struct
{
    SCOSSL_PROVCTX *provctx;

    EVP_CIPHER *cipher;

    const SCOSSL_ENCODE_KEYTYPE_DESC *desc;
} SCOSSL_ENCODE_CTX;

SCOSSL_ENCODE_CTX *p_scossl_encode_newctx(_In_ SCOSSL_PROVCTX *provctx, const SCOSSL_ENCODE_KEYTYPE_DESC *desc);
void p_scossl_encode_freectx(_Inout_ SCOSSL_ENCODE_CTX *ctx);

SCOSSL_STATUS p_scossl_encode_set_ctx_params(_In_ SCOSSL_ENCODE_CTX *ctx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_encode_settable_ctx_params(ossl_unused void *provctx);

BOOL p_scossl_encode_does_selection(_In_ const SCOSSL_ENCODE_KEYTYPE_DESC *desc, int selection);

SCOSSL_STATUS p_scossl_encode(_In_ SCOSSL_ENCODE_CTX *ctx, _In_ OSSL_CORE_BIO *coreOut,
                              _In_ const void *keyCtx,
                              _In_ const OSSL_PARAM keyAbstract[],
                              int selection,
                              _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);

SCOSSL_STATUS p_scossl_encode_write_key_bytes(_In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey, _Inout_ BIO *out);

#ifdef __cplusplus
}
#endif