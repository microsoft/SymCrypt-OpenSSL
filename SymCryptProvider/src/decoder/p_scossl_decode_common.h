//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_base.h"
#include "kem/p_scossl_mlkem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define select_PrivateKeyInfo OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define select_SubjectPublicKeyInfo OSSL_KEYMGMT_SELECT_PUBLIC_KEY

typedef PVOID (*PSCOSSL_DECODE_INTERNAL_FN) (_In_ BIO *bio);

typedef struct
{
    const char *dataType;
    int selection;

    PSCOSSL_DECODE_INTERNAL_FN decodeInternal;
    OSSL_FUNC_keymgmt_free_fn *freeKeyCtx;
} SCOSSL_DECODE_KEYTYPE_DESC;

typedef struct
{
    SCOSSL_PROVCTX *provctx;

    const SCOSSL_DECODE_KEYTYPE_DESC *desc;
} SCOSSL_DECODE_CTX;

typedef struct
{
    X509_ALGOR *algorithm;
    ASN1_BIT_STRING *subjectPublicKey;
} SUBJECT_PUBKEY_INFO;

SCOSSL_DECODE_CTX *p_scossl_decode_newctx(_In_ SCOSSL_PROVCTX *provctx, _In_ const SCOSSL_DECODE_KEYTYPE_DESC *desc);
void p_scossl_decode_freectx(_Inout_ SCOSSL_DECODE_CTX *ctx);

const OSSL_PARAM *p_scossl_decode_settable_ctx_params(ossl_unused void *ctx);
SCOSSL_STATUS p_scossl_decode_set_ctx_params(ossl_unused void *ctx, ossl_unused const OSSL_PARAM params[]);

BOOL p_scossl_decode_does_selection(_In_ SCOSSL_DECODE_KEYTYPE_DESC *desc, int selection);

SCOSSL_STATUS p_scossl_decode(_In_ SCOSSL_DECODE_CTX *ctx, _In_ OSSL_CORE_BIO *in,
                              int selection,
                              _In_ OSSL_CALLBACK *dataCb, _In_ void *dataCbArg,
                              ossl_unused OSSL_PASSPHRASE_CALLBACK *passphraseCb, ossl_unused void *passphraseCbArg);

const ASN1_ITEM *p_scossl_decode_get_pubkey_asn1_item();

#ifdef __cplusplus
}
#endif