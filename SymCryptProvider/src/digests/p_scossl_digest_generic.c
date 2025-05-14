//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "digests/p_scossl_digest_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_DIGEST_PARAM_STATE "state"
#define SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM "recompute_checksum"

typedef VOID (SYMCRYPT_CALL * PSYMCRYPT_DIGEST_STATE_EXPORT) (PVOID pState, PBYTE pbBlob);
typedef SYMCRYPT_ERROR (SYMCRYPT_CALL * PSYMCRYPT_DIGEST_STATE_IMPORT) (PVOID pState, PCBYTE pbBlob);

const OSSL_PARAM p_scossl_digest_export_settable_param_types[] = {
    OSSL_PARAM_octet_string(SCOSSL_DIGEST_PARAM_STATE, NULL, 0),
    OSSL_PARAM_int(SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM, NULL),
    OSSL_PARAM_END};

const OSSL_PARAM p_scossl_digest_export_gettable_ctx_param_types[] = {
    OSSL_PARAM_int(SCOSSL_DIGEST_PARAM_STATE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *p_scossl_digest_export_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_digest_export_settable_param_types;
}

const OSSL_PARAM *p_scossl_digest_export_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return p_scossl_digest_export_gettable_ctx_param_types;
}

static SCOSSL_STATUS p_scossl_digest_get_state_internal(_In_ SCOSSL_DIGEST_CTX *ctx, _Inout_ OSSL_PARAM params[],
                                                        _In_ PSYMCRYPT_DIGEST_STATE_EXPORT pExportFunc,
                                                        SIZE_T cbExportBlob)
{
    BYTE pbExportBlob[cbExportBlob];
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, SCOSSL_DIGEST_PARAM_STATE)) != NULL)
    {
        pExportFunc(ctx->pState, pbExportBlob);

        if (!OSSL_PARAM_set_octet_string(p, pbExportBlob, cbExportBlob))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_set_state_internal(_In_ SCOSSL_DIGEST_CTX *ctx, _In_ const OSSL_PARAM params[],
                                                        _In_ PSYMCRYPT_DIGEST_STATE_IMPORT pImportFunc)
{
    PBYTE pbImportBlob;
    SIZE_T cbImportBlob;
    int recomputeChecksum = 0;
    SYMCRYPT_ERROR scError;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, SCOSSL_DIGEST_PARAM_STATE)) != NULL)
    {
        if (!OSSL_PARAM_get_octet_string_ptr(p, (void *)&pbImportBlob, &cbImportBlob))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if ((p = OSSL_PARAM_locate_const(params, SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM)) != NULL &&
            !OSSL_PARAM_get_int(p, &recomputeChecksum))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (recomputeChecksum)
        {
            // The state being imported has been constructed and does not have a checksum.
            // Recompute the checksum here and set it to the last 8 bytes of the blob.
            SymCryptMarvin32(SymCryptMarvin32DefaultSeed, (PCBYTE) pbImportBlob, cbImportBlob - 8, &pbImportBlob[cbImportBlob - 8]);
        }

        scError = pImportFunc(ctx->pState, pbImportBlob);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("Digest state import failed", scError);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_generic_init(_Inout_ SCOSSL_DIGEST_CTX *ctx, ossl_unused const OSSL_PARAM params[])
{
    SymCryptHashInit(ctx->pHash, ctx->pState);
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_digest_generic_final(_In_ SCOSSL_DIGEST_CTX *ctx,
                                                   _Out_writes_bytes_(*outl) unsigned char *out, _Out_ size_t *outl, size_t outlen)
{
    SIZE_T cbResult = SymCryptHashResultSize(ctx->pHash);

    if (outlen < cbResult)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return SCOSSL_FAILURE;
    }

    SymCryptHashResult(ctx->pHash, ctx->pState, out, cbResult);
    *outl = cbResult;

    return SCOSSL_SUCCESS;
}

#define IMPLEMENT_SCOSSL_DIGEST_EXPORT_FUNCTIONS(state_name, export_func, import_func, state_size)  \
    static SCOSSL_STATUS p_scossl_digest_get_##state_name(_In_ SCOSSL_DIGEST_CTX *ctx,              \
                                                          _Inout_ OSSL_PARAM params[])              \
    {                                                                                               \
        return p_scossl_digest_get_state_internal(ctx, params,                                      \
            (PSYMCRYPT_DIGEST_STATE_EXPORT) export_func, state_size);                               \
    }                                                                                               \
                                                                                                    \
    static SCOSSL_STATUS p_scossl_digest_set_##state_name(_Inout_ SCOSSL_DIGEST_CTX *ctx,           \
                                                          _In_ const OSSL_PARAM params[])           \
    {                                                                                               \
        return p_scossl_digest_set_state_internal(ctx, params,                                      \
            (PSYMCRYPT_DIGEST_STATE_IMPORT) import_func);                                           \
    }                                                                                               \
                                                                                                    \
    static SCOSSL_STATUS p_scossl_digest_##state_name##_init(_Inout_ SCOSSL_DIGEST_CTX *ctx,        \
                                                             _In_ const OSSL_PARAM params[])        \
    {                                                                                               \
        SymCryptHashInit(ctx->pHash, ctx->pState);                                                  \
        return p_scossl_digest_set_##state_name(ctx, params);                                       \
    }

IMPLEMENT_SCOSSL_DIGEST_EXPORT_FUNCTIONS(md5_state, SymCryptMd5StateExport, SymCryptMd5StateImport, SYMCRYPT_MD5_STATE_EXPORT_SIZE)
IMPLEMENT_SCOSSL_DIGEST_EXPORT_FUNCTIONS(sha1_state, SymCryptSha1StateExport, SymCryptSha1StateImport, SYMCRYPT_SHA1_STATE_EXPORT_SIZE)
IMPLEMENT_SCOSSL_DIGEST_EXPORT_FUNCTIONS(sha256_state, SymCryptSha256StateExport, SymCryptSha256StateImport, SYMCRYPT_SHA256_STATE_EXPORT_SIZE)
IMPLEMENT_SCOSSL_DIGEST_EXPORT_FUNCTIONS(sha512_state, SymCryptSha512StateExport, SymCryptSha512StateImport, SYMCRYPT_SHA512_STATE_EXPORT_SIZE)

#define IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(alg, dispatch_name, state_name, flags)                       \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name, flags)                                           \
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))p_scossl_digest_set_##state_name},                \
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_digest_export_settable_ctx_params}, \
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))p_scossl_digest_get_##state_name},                \
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_digest_export_gettable_ctx_params}, \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_digest_##state_name##_init},                       \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_digest_generic_final},                            \
    SCOSSL_DIGEST_FUNCTIONS_END

#define IMPLEMENT_SCOSSL_DIGEST_GENERIC(alg, dispatch_name, flags)           \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name, flags)                \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_digest_generic_init},   \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_digest_generic_final}, \
    SCOSSL_DIGEST_FUNCTIONS_END

// MD5 and SHA1, supported for compatability
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Md5, md5, md5_state, 0)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha1, sha1, sha1_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

// SHA2
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha224, sha224, sha256_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha256, sha256, sha256_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha384, sha384, sha512_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512, sha512, sha512_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512_224, sha512_224, sha512_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512_256, sha512_256, sha512_state, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

//SHA3
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_224, sha3_224, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_256, sha3_256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_384, sha3_384, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_GENERIC(Sha3_512, sha3_512, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

#ifdef __cplusplus
}
#endif