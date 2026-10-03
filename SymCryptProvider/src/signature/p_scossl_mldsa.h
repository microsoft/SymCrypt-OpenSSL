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
// "Pure" ML-DSA backend descriptor, shared by the signature, keymgmt, decoder
// and encoder translation units for this family.
//
extern const SCOSSL_MLDSA_BACKEND p_scossl_mldsa_backend;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();

#ifdef __cplusplus
}
#endif
