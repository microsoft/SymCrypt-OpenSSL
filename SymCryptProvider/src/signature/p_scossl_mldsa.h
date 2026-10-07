//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLDSA_CONTEXT_MAX_LENGTH SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH

// Carried as an int because the two families use distinct SymCrypt parameter-set
// enums; each backend casts it to the enum for its family.
typedef int SCOSSL_MLDSA_PARAMS;

// Family independent key format; each backend translates it to the concrete
// SymCrypt format enum for its family.
typedef enum
{
    SCOSSL_MLDSA_KEY_FORMAT_NULL = 0,
    SCOSSL_MLDSA_KEY_FORMAT_PUBLIC,
    SCOSSL_MLDSA_KEY_FORMAT_PRIVATE,
    SCOSSL_MLDSA_KEY_FORMAT_PRIVATE_SEED,
} SCOSSL_MLDSA_KEY_FORMAT;

typedef struct _SCOSSL_MLDSA_BACKEND SCOSSL_MLDSA_BACKEND;

typedef struct
{
    int nid;
    const char *oid;
    const char *snGroupName;
    const char *lnGroupName;
    SCOSSL_MLDSA_PARAMS params;
} SCOSSL_MLDSA_ALG_INFO;

typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    SCOSSL_MLDSA_PARAMS params;
    SCOSSL_MLDSA_KEY_FORMAT format;
    PVOID key;
} SCOSSL_MLDSA_KEY_CTX;

// Vtable capturing every difference between "pure" ML-DSA and Composite-ML-DSA.
// The shared core operates only through this descriptor.
struct _SCOSSL_MLDSA_BACKEND
{
    const char *textName;

    BOOL supportsSeed;
    SIZE_T cbPrivateSeed;

    SCOSSL_MLDSA_ALG_INFO *algInfos;
    SIZE_T cAlgInfos;

    const OSSL_PARAM *sigSettableCtxParams;
    // NULL if the family has no extra signature context params to validate.
    SCOSSL_STATUS (*validateExtraSigCtxParams)(_In_ const OSSL_PARAM params[]);
    const OSSL_PARAM *keygenSettableParams;

    PVOID          (*keyAllocate)(SCOSSL_MLDSA_PARAMS params);
    void           (*keyFree)(_In_ PVOID key);
    SYMCRYPT_ERROR (*keyGenerate)(_Inout_ PVOID key, UINT32 flags);
    SYMCRYPT_ERROR (*keySetValue)(_In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags, _Inout_ PVOID key);
    SYMCRYPT_ERROR (*keyGetValue)(_In_ PVOID key, _Out_writes_bytes_(cbDst) PBYTE pbDst, SIZE_T cbDst, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags);
    SYMCRYPT_ERROR (*sizeofKeyFormat)(SCOSSL_MLDSA_PARAMS params, SCOSSL_MLDSA_KEY_FORMAT format, _Out_ SIZE_T *pcbKeyFormat);
    SYMCRYPT_ERROR (*sizeofSignature)(SCOSSL_MLDSA_PARAMS params, _Out_ SIZE_T *pcbSignature);
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
    int            (*getBits)(SCOSSL_MLDSA_PARAMS params);
    int            (*getSecurityBits)(SCOSSL_MLDSA_PARAMS params);
};

// Seed fields are only used by families that support the private seed format.
typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    SCOSSL_MLDSA_PARAMS params;
    BYTE abSeed[SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE];
    SIZE_T cbSeed;
} SCOSSL_MLDSA_KEYGEN_CTX;

typedef struct
{
    const SCOSSL_MLDSA_BACKEND *backend;
    SCOSSL_MLDSA_PARAMS params;
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
int p_scossl_mldsa_params_to_nid(_In_ const SCOSSL_MLDSA_BACKEND *backend, SCOSSL_MLDSA_PARAMS params);

//
// Shared signature core (referenced by the per-variant dispatch tables)
//
SCOSSL_MLDSA_SIGNATURE_CTX *p_scossl_mldsa_newctx(_In_ const SCOSSL_MLDSA_BACKEND *backend, SCOSSL_MLDSA_PARAMS params);
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
        return p_scossl_mldsa_newctx(backendPtr, symcryptParams);                                                   \
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
// "Pure" ML-DSA backend descriptor, shared across this family's translation units.
//
extern const SCOSSL_MLDSA_BACKEND p_scossl_mldsa_backend;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();

#ifdef __cplusplus
}
#endif
