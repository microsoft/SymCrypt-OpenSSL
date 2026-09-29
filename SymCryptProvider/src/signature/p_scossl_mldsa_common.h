//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

// Sentinel used by a backend to indicate that a particular key format is not
// supported by the family (e.g. the private seed format for Composite-ML-DSA).
// No real SymCrypt key format value is negative, so this never collides with a
// valid format.
#define SCOSSL_MLDSA_FORMAT_NONE (-1)

// Both ML-DSA and Composite-ML-DSA use the same maximum context length.
#define SCOSSL_MLDSA_CONTEXT_MAX_LENGTH SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH

typedef struct _SCOSSL_MLDSA_BACKEND SCOSSL_MLDSA_BACKEND;

typedef struct
{
    int nid;
    const char *oid;
    const char *snGroupName;
    const char *lnGroupName;
    // SymCrypt parameter set for this algorithm, stored as the underlying enum value.
    int params;
} SCOSSL_MLDSA_ALG_INFO;

// Unified key context for both ML-DSA and Composite-ML-DSA. The family specific
// behavior is dispatched through the backend descriptor. The raw SymCrypt key
// handle is stored as a PVOID and the current key format as a plain int because
// the underlying enum values differ between families.
typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    int params;
    int format;
    PVOID key;
} SCOSSL_MLDSA_KEY_CTX;

// Backend descriptor encapsulating every family specific difference between the
// "pure" ML-DSA and Composite-ML-DSA implementations. The shared core operates
// exclusively through this vtable, which lets both families share a single
// implementation of the signature, keymgmt, decoder and encoder logic.
struct _SCOSSL_MLDSA_BACKEND
{
    // Human readable family name used when printing keys (e.g. "MLDSA").
    const char *textName;

    // Key format enum values for this family. Values differ between families,
    // so the shared code always compares against these instead of hardcoded
    // constants. formatPrivateSeed is SCOSSL_MLDSA_FORMAT_NONE when the family
    // does not support the private seed format.
    int formatNull;
    int formatPublicKey;
    int formatPrivateKey;
    int formatPrivateSeed;

    // Whether the family supports the private seed format, and the seed size.
    BOOL supportsSeed;
    SIZE_T cbPrivateSeed;

    // Key format assigned to a freshly generated key.
    int generatedFormat;

    // Algorithm/OID table and its length.
    SCOSSL_MLDSA_ALG_INFO *algInfos;
    SIZE_T cAlgInfos;

    // Settable signature context parameters for this family, and an optional
    // validator for the additional (currently unsupported) parameters exposed
    // by "pure" ML-DSA. validateExtraSigCtxParams is NULL when there are none.
    const OSSL_PARAM *sigSettableCtxParams;
    SCOSSL_STATUS (*validateExtraSigCtxParams)(_In_ const OSSL_PARAM params[]);

    // Settable key generation parameters for this family.
    const OSSL_PARAM *keygenSettableParams;

    // SymCrypt operation wrappers. The key handle is passed as a PVOID and key
    // formats/parameter sets as ints; each wrapper casts to the concrete
    // SymCrypt types before calling the underlying function.
    PVOID          (*keyAllocate)(int params);
    void           (*keyFree)(_In_ PVOID key);
    SYMCRYPT_ERROR (*keyGenerate)(_Inout_ PVOID key, UINT32 flags);
    SYMCRYPT_ERROR (*keySetValue)(_In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc, int format, UINT32 flags, _Inout_ PVOID key);
    SYMCRYPT_ERROR (*keyGetValue)(_In_ PVOID key, _Out_writes_bytes_(cbDst) PBYTE pbDst, SIZE_T cbDst, int format, UINT32 flags);
    SYMCRYPT_ERROR (*sizeofKeyFormat)(int params, int format, _Out_ SIZE_T *pcbKeyFormat);
    SYMCRYPT_ERROR (*sizeofSignature)(int params, _Out_ SIZE_T *pcbSignature);
    // Common signing wrapper. pcbResult receives the number of bytes written,
    // which for fixed-size families is simply the maximum signature size.
    SYMCRYPT_ERROR (*sign)(_In_ PVOID key,
                           _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                           _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                           UINT32 flags,
                           _Out_writes_bytes_(cbSig) PBYTE pbSig, SIZE_T cbSig, _Out_ SIZE_T *pcbResult);
    SYMCRYPT_ERROR (*verify)(_In_ PVOID key,
                             _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                             _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                             _In_reads_bytes_(cbSig) PCBYTE pbSig, SIZE_T cbSig,
                             UINT32 flags);
    int            (*getBits)(int params);
    int            (*getSecurityBits)(int params);
};

// Key generation context, shared by both families. The seed fields are only
// used by families that support the private seed format.
typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    int params;
    BYTE abSeed[SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE];
    SIZE_T cbSeed;
} SCOSSL_MLDSA_KEYGEN_CTX;

// Signature context, shared by both families.
typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    int params;
    SCOSSL_MLDSA_KEY_CTX *keyCtx;
    int operation;

    BYTE abContext[SCOSSL_MLDSA_CONTEXT_MAX_LENGTH];
    SIZE_T cbContext;
} SCOSSL_MLDSA_SIGNATURE_CTX;

//
// Shared registration / lookup helpers (signature core)
//
SCOSSL_STATUS p_scossl_mldsa_register_backend(_In_ const SCOSSL_MLDSA_BACKEND *backend);
SCOSSL_MLDSA_ALG_INFO *p_scossl_mldsa_get_alg_info_by_nid(_In_ const SCOSSL_MLDSA_BACKEND *backend, int nid);
int p_scossl_mldsa_params_to_nid(_In_ const SCOSSL_MLDSA_BACKEND *backend, int params);

//
// Shared signature core (referenced by the per-variant dispatch tables)
//
SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_newctx(_In_ const SCOSSL_MLDSA_BACKEND *backend, int params);
void p_scossl_mldsa_freectx(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx);
SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_dupctx(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx);
SCOSSL_STATUS p_scossl_mldsa_sign_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mldsa_sign(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                  _Out_writes_bytes_(*siglen) unsigned char *sig, _Out_ size_t *siglen, size_t sigsize,
                                  _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);
SCOSSL_STATUS p_scossl_mldsa_verify_init(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mldsa_verify(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx,
                                    _In_reads_bytes_(siglen) const unsigned char *sig, size_t siglen,
                                    _In_reads_bytes_(tbslen) const unsigned char *tbs, size_t tbslen);
SCOSSL_STATUS p_scossl_mldsa_digest_sign_init(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const char *mdname, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mldsa_digest_verify_init(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const char *mdname, _In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_settable_ctx_params(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_set_ctx_params(_Inout_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_gettable_ctx_params(_In_ void *ctx, _In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_get_ctx_params(_In_ SCOSSL_MLDSA_SIGNATURE_CTX *ctx, _Inout_ OSSL_PARAM params[]);

//
// Shared keymgmt core (referenced by the per-variant dispatch tables)
//
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_new_ctx(_In_ const SCOSSL_MLDSA_BACKEND *backend, int params);
void p_scossl_mldsa_keymgmt_free_key_ctx(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_dup_key_ctx(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection);
SCOSSL_STATUS p_scossl_mldsa_keygen_set_params(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_keygen_settable_params(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ void *provCtx);
void p_scossl_mldsa_keygen_cleanup(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx);
SCOSSL_MLDSA_KEYGEN_CTX *p_scossl_mldsa_keygen_init(_In_ const OSSL_PARAM params[], _In_ const SCOSSL_MLDSA_BACKEND *backend, int mldsaParams);
SCOSSL_STATUS p_scossl_mldsa_keygen_set_template(_Inout_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ SCOSSL_MLDSA_KEY_CTX *tmplCtx);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keygen(_In_ SCOSSL_MLDSA_KEYGEN_CTX *genCtx, _In_ OSSL_CALLBACK *cb, _In_ void *cbarg);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_keymgmt_load(_In_ const void *reference, size_t reference_size);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_settable_params(_In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _In_ const OSSL_PARAM params[]);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_gettable_params(_In_ void *provctx);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_params(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[]);
BOOL p_scossl_mldsa_keymgmt_has(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection);
BOOL p_scossl_mldsa_keymgmt_match(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx1, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx2, int selection);
const OSSL_PARAM *p_scossl_mldsa_keymgmt_impexp_types(int selection);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_import(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[]);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_export(_In_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int selection, _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg);

SCOSSL_STATUS p_scossl_mldsa_keymgmt_get_encoded_key(_In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     _Inout_ PBYTE *ppbKey, _Inout_ SIZE_T *pcbKey);
SCOSSL_STATUS p_scossl_mldsa_keymgmt_set_encoded_key(_Inout_ SCOSSL_MLDSA_KEY_CTX *keyCtx, int format,
                                                     _In_reads_bytes_(cbKey) PCBYTE pbKey, SIZE_T cbKey);

//
// Shared decoder core. The decode context is passed as a PVOID so that the
// signature and keymgmt translation units, which include this header, do not
// need to pull in the decoder common header. The decoder translation units cast
// it back to SCOSSL_DECODE_CTX.
//
SCOSSL_MLDSA_KEY_CTX *p_scossl_PrivateKeyInfo_to_mldsa(_In_ PVOID ctx, _In_ const SCOSSL_MLDSA_BACKEND *backend, int params, _In_ BIO *bio);
SCOSSL_MLDSA_KEY_CTX *p_scossl_SubjectPublicKeyInfo_to_mldsa(_In_ PVOID ctx, _In_ const SCOSSL_MLDSA_BACKEND *backend, int params, _In_ BIO *bio);
SCOSSL_STATUS p_scossl_der_to_mldsa_export_object(_In_ PVOID ctx,
                                                  _In_reads_bytes_(cbObjRef) const void *pbObjRef, _In_ size_t cbObjRef,
                                                  _In_ OSSL_CALLBACK *exportCb, _In_ void *exportCbArg);

//
// Shared encoder core. As with the decoder core, the encode context is passed
// as a PVOID to avoid coupling every includer to the encoder common header.
//
SCOSSL_STATUS p_scossl_mldsa_to_PrivateKeyInfo(_In_ PVOID ctx, _Inout_ BIO *out, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                               int selection, _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);
SCOSSL_STATUS p_scossl_mldsa_to_EncryptedPrivateKeyInfo(_In_ PVOID ctx, _Inout_ BIO *out, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                        int selection, _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);
SCOSSL_STATUS p_scossl_mldsa_to_SubjectPublicKeyInfo(_In_ PVOID ctx, _Inout_ BIO *out, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                                     int selection, _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);
SCOSSL_STATUS p_scossl_mldsa_to_text(_In_ PVOID ctx, _Inout_ BIO *out, _In_ const SCOSSL_MLDSA_KEY_CTX *keyCtx,
                                     int selection, _In_ OSSL_PASSPHRASE_CALLBACK *passphraseCb, _In_ void *passphraseCbArgs);
SCOSSL_MLDSA_KEY_CTX *p_scossl_mldsa_encoder_import_object(_In_ PVOID ctx, _In_ const SCOSSL_MLDSA_BACKEND *backend, int symcryptParams,
                                                           int selection, _In_ const OSSL_PARAM params[]);

//
// Per-variant signature dispatch table generation
//
#define SCOSSL_MLDSA_SIGNATURE_FNS(variant, backendPtr, symcryptParams)                                                 \
    static SCOSSL_MLDSA_SIGNATURE_CTX                                                                                   \
    *p_scossl_##variant##_newctx(ossl_unused SCOSSL_PROVCTX *provctx, ossl_unused const char *propq)                    \
    {                                                                                                                  \
        return p_scossl_mldsa_newctx(backendPtr, symcryptParams);                                                      \
    }                                                                                                                  \
                                                                                                                       \
    const OSSL_DISPATCH p_scossl_##variant##_signature_functions[] = {                                                 \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p_scossl_##variant##_newctx},                                     \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))p_scossl_mldsa_dupctx},                                           \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p_scossl_mldsa_freectx},                                         \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p_scossl_mldsa_sign_init},                                     \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p_scossl_mldsa_sign},                                               \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_verify_init},                                 \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                                           \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p_scossl_mldsa_digest_sign_init},                       \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))p_scossl_mldsa_sign},                                        \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))p_scossl_mldsa_digest_verify_init},                   \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))p_scossl_mldsa_verify},                                    \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_get_ctx_params},                           \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_gettable_ctx_params},                 \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_set_ctx_params},                           \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_mldsa_settable_ctx_params},

#define SCOSSL_MLDSA_SIGN_MESSAGE_FNS                                                       \
    {OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_sign_init},      \
    {OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (void (*)(void))p_scossl_mldsa_verify_init},

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
    #define IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(variant, backendPtr, symcryptParams)  \
        SCOSSL_MLDSA_SIGNATURE_FNS(variant, backendPtr, symcryptParams)            \
        SCOSSL_MLDSA_SIGN_MESSAGE_FNS                                              \
        {0, NULL}};
#else
    #define IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(variant, backendPtr, symcryptParams)  \
        SCOSSL_MLDSA_SIGNATURE_FNS(variant, backendPtr, symcryptParams)            \
        {0, NULL}};
#endif

//
// Per-variant keymgmt dispatch table generation
//
#define IMPLEMENT_SCOSSL_MLDSA_KEYMGMT(variant, backendPtr, symcryptParams)                                             \
    static SCOSSL_MLDSA_KEY_CTX                                                                                         \
    *p_scossl_##variant##_keymgmt_new_ctx(ossl_unused SCOSSL_PROVCTX *provCtx)                                          \
    {                                                                                                                  \
        return p_scossl_mldsa_keymgmt_new_ctx(backendPtr, symcryptParams);                                             \
    }                                                                                                                  \
                                                                                                                       \
    static SCOSSL_MLDSA_KEYGEN_CTX                                                                                      \
    *p_scossl_##variant##_keygen_init(ossl_unused SCOSSL_PROVCTX *provCtx,                                              \
                                      ossl_unused int selection,                                                        \
                                      _In_ const OSSL_PARAM params[])                                                   \
    {                                                                                                                  \
        return p_scossl_mldsa_keygen_init(params, backendPtr, symcryptParams);                                         \
    }                                                                                                                  \
                                                                                                                       \
    const OSSL_DISPATCH p_scossl_##variant##_keymgmt_functions[] = {                                                   \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_##variant##_keymgmt_new_ctx},                                 \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_mldsa_keymgmt_dup_key_ctx},                                   \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_set_params},                          \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keygen_settable_params},                \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_mldsa_keygen_cleanup},                                \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_##variant##_keygen_init},                                \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))p_scossl_mldsa_keygen_set_template},                      \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_mldsa_keygen},                                                \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p_scossl_mldsa_keymgmt_load},                                         \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_settable_params},                   \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_set_params},                             \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_gettable_params},                   \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_mldsa_keymgmt_get_params},                             \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_mldsa_keymgmt_has},                                           \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_mldsa_keymgmt_match},                                       \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},                         \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_mldsa_keymgmt_impexp_types},                         \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_mldsa_keymgmt_import},                                     \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_mldsa_keymgmt_export},                                     \
        {0, NULL}};

//
// Per-variant decoder dispatch table generation
//
#define IMPLEMENT_SCOSSL_MLDSA_DECODER(decoderType, variant, backendPtr, symcryptParams, keytypeName)               \
    static SCOSSL_MLDSA_KEY_CTX                                                                                     \
    *p_scossl_##decoderType##_to_##variant(_In_ SCOSSL_DECODE_CTX *ctx, _In_ BIO *bio)                              \
    {                                                                                                              \
        return p_scossl_##decoderType##_to_mldsa(ctx, backendPtr, symcryptParams, bio);                            \
    }                                                                                                              \
                                                                                                                   \
    static const SCOSSL_DECODE_KEYTYPE_DESC p_scossl_##variant##_##decoderType##_desc = {                          \
        keytypeName,                                                                                               \
        select_##decoderType,                                                                                      \
        (PSCOSSL_DECODE_INTERNAL_FN)p_scossl_##decoderType##_to_##variant,                                         \
        (OSSL_FUNC_keymgmt_free_fn *)p_scossl_mldsa_keymgmt_free_key_ctx};                                         \
                                                                                                                   \
    static SCOSSL_DECODE_CTX *                                                                                     \
    p_scossl_der_to_##variant##_##decoderType##_newctx(_In_ SCOSSL_PROVCTX *provctx)                               \
    {                                                                                                              \
        return p_scossl_decode_newctx(provctx, &p_scossl_##variant##_##decoderType##_desc);                        \
    }                                                                                                              \
                                                                                                                   \
    static BOOL                                                                                                    \
    p_scossl_der_to_##variant##_##decoderType##_does_selection(ossl_unused void *provctx, int selection)           \
    {                                                                                                              \
        return p_scossl_decode_does_selection(&p_scossl_##variant##_##decoderType##_desc, selection);              \
    }                                                                                                              \
                                                                                                                   \
    const OSSL_DISPATCH p_scossl_der_to_##variant##_##decoderType##_functions[] = {                                \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))p_scossl_der_to_##variant##_##decoderType##_newctx},             \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))p_scossl_decode_freectx},                                      \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_decode_set_ctx_params},                        \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_decode_settable_ctx_params},              \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))                                                        \
            p_scossl_der_to_##variant##_##decoderType##_does_selection},                                           \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))p_scossl_decode},                                               \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))p_scossl_der_to_mldsa_export_object},                    \
        {0, NULL}};

//
// Per-variant encoder dispatch table generation
//
#define IMPLEMENT_SCOSSL_MLDSA_ASN1_ENCODER(variant, encoderType)                                                  \
    static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_##variant##_##encoderType##_der_desc = {                            \
        select_##encoderType,                                                                                      \
        SCOSSL_ENCODE_DER,                                                                                         \
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_##encoderType};                                             \
                                                                                                                   \
    static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_##variant##_##encoderType##_pem_desc = {                            \
        select_##encoderType,                                                                                      \
        SCOSSL_ENCODE_PEM,                                                                                         \
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_##encoderType};                                             \
                                                                                                                   \
    static SCOSSL_ENCODE_CTX *p_scossl_##variant##_to_##encoderType##_der_newctx(_In_ SCOSSL_PROVCTX *provctx)     \
    {                                                                                                              \
        return p_scossl_encode_newctx(provctx, &p_scossl_##variant##_##encoderType##_der_desc);                   \
    }                                                                                                              \
                                                                                                                   \
    static SCOSSL_ENCODE_CTX *p_scossl_##variant##_to_##encoderType##_pem_newctx(_In_ SCOSSL_PROVCTX *provctx)     \
    {                                                                                                              \
        return p_scossl_encode_newctx(provctx, &p_scossl_##variant##_##encoderType##_pem_desc);                   \
    }                                                                                                              \
                                                                                                                   \
    static BOOL p_scossl_der_to_##variant##_##encoderType##_does_selection(ossl_unused void *provctx, int selection) \
    {                                                                                                              \
        return p_scossl_encode_does_selection(&p_scossl_##variant##_##encoderType##_der_desc, selection);         \
    }

#define IMPLEMENT_SCOSSL_MLDSA_ENCODER_DISPATCH(variant, encoderType)                                              \
    const OSSL_DISPATCH p_scossl_##variant##_to_##encoderType##_der_functions[] = {                                \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_##variant##_to_##encoderType##_der_newctx},            \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                     \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                       \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},             \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_##variant##_##encoderType##_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                              \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_##variant##_encoder_import_object},             \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                     \
        {0, NULL}};                                                                                                \
                                                                                                                   \
    const OSSL_DISPATCH p_scossl_##variant##_to_##encoderType##_pem_functions[] = {                                \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_##variant##_to_##encoderType##_pem_newctx},            \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                     \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))p_scossl_encode_set_ctx_params},                       \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_encode_settable_ctx_params},             \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))p_scossl_der_to_##variant##_##encoderType##_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                              \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_##variant##_encoder_import_object},             \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                     \
        {0, NULL}};

#define IMPLEMENT_SCOSSL_MLDSA_ENCODER(variant, backendPtr, symcryptParams)                                       \
    static SCOSSL_MLDSA_KEY_CTX *p_scossl_##variant##_encoder_import_object(_In_ SCOSSL_ENCODE_CTX *ctx,           \
                                                                            int selection,                        \
                                                                            _In_ const OSSL_PARAM params[])       \
    {                                                                                                              \
        return p_scossl_mldsa_encoder_import_object(ctx, backendPtr, symcryptParams, selection, params);          \
    }                                                                                                              \
                                                                                                                   \
    static SCOSSL_ENCODE_KEYTYPE_DESC p_scossl_##variant##_text_desc = {                                          \
        0,                                                                                                        \
        SCOSSL_ENCODE_TEXT,                                                                                       \
        (PSCOSSL_ENCODE_INTERNAL_FN)p_scossl_mldsa_to_text};                                                      \
                                                                                                                   \
    static SCOSSL_ENCODE_CTX *p_scossl_##variant##_to_text_newctx(_In_ SCOSSL_PROVCTX *provctx)                   \
    {                                                                                                              \
        return p_scossl_encode_newctx(provctx, &p_scossl_##variant##_text_desc);                                  \
    }                                                                                                              \
                                                                                                                   \
    const OSSL_DISPATCH p_scossl_##variant##_to_text_functions[] = {                                              \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))p_scossl_##variant##_to_text_newctx},                          \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))p_scossl_encode_freectx},                                     \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))p_scossl_encode},                                              \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))p_scossl_##variant##_encoder_import_object},             \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))p_scossl_mldsa_keymgmt_free_key_ctx},                     \
        {0, NULL}};                                                                                                \
                                                                                                                   \
    IMPLEMENT_SCOSSL_MLDSA_ASN1_ENCODER(variant, PrivateKeyInfo)                                                  \
    IMPLEMENT_SCOSSL_MLDSA_ASN1_ENCODER(variant, EncryptedPrivateKeyInfo)                                         \
    IMPLEMENT_SCOSSL_MLDSA_ASN1_ENCODER(variant, SubjectPublicKeyInfo)                                            \
    IMPLEMENT_SCOSSL_MLDSA_ENCODER_DISPATCH(variant, PrivateKeyInfo)                                              \
    IMPLEMENT_SCOSSL_MLDSA_ENCODER_DISPATCH(variant, EncryptedPrivateKeyInfo)                                     \
    IMPLEMENT_SCOSSL_MLDSA_ENCODER_DISPATCH(variant, SubjectPublicKeyInfo)

#ifdef __cplusplus
}
#endif
