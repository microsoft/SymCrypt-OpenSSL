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
    OSSL_PARAM_octet_string(SCOSSL_DIGEST_PARAM_STATE, NULL, 0),
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

#define IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(alg, dispatch_name, uc_name, flags)                          \
    static SCOSSL_STATUS p_scossl_digest_set_##dispatch_name##_state(_Inout_ SCOSSL_DIGEST_CTX *ctx,    \
                                                                     _In_ const OSSL_PARAM params[])    \
    {                                                                                                   \
        return p_scossl_digest_set_state_internal(ctx, params,                                          \
            (PSYMCRYPT_DIGEST_STATE_IMPORT) SymCrypt##alg##StateImport);                                \
    }                                                                                                   \
                                                                                                        \
    static SCOSSL_STATUS p_scossl_digest_get_##dispatch_name##_state(_In_ SCOSSL_DIGEST_CTX *ctx,       \
                                                                     _Inout_ OSSL_PARAM params[])       \
    {                                                                                                   \
        return p_scossl_digest_get_state_internal(ctx, params,                                          \
            (PSYMCRYPT_DIGEST_STATE_EXPORT) SymCrypt##alg##StateExport,                                 \
            SYMCRYPT_##uc_name##_STATE_EXPORT_SIZE);                                                    \
    }                                                                                                   \
                                                                                                        \
    static SCOSSL_STATUS p_scossl_digest_##dispatch_name##_init(_Inout_ SCOSSL_DIGEST_CTX *ctx,         \
                                                                _In_ const OSSL_PARAM params[])         \
    {                                                                                                   \
        SymCryptHashInit(ctx->pHash, ctx->pState);                                                      \
        return p_scossl_digest_set_##dispatch_name##_state(ctx, params);                                \
    }                                                                                                   \
                                                                                                        \
    SCOSSL_DIGEST_FUNCTIONS_COMMON(alg, dispatch_name, flags)                                           \
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))p_scossl_digest_set_##dispatch_name##_state},     \
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_digest_export_settable_ctx_params}, \
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))p_scossl_digest_get_##dispatch_name##_state},     \
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))p_scossl_digest_export_gettable_ctx_params}, \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p_scossl_digest_##dispatch_name##_init},                    \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p_scossl_digest_generic_final},                            \
    SCOSSL_DIGEST_FUNCTIONS_END

// MD5 and SHA1, supported for compatability
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Md5, md5, MD5, 0)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha1, sha1, SHA1, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

// SHA2
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha224, sha224, SHA224, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha256, sha256, SHA256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha384, sha384, SHA384, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512, sha512, SHA512, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512_224, sha512_224, SHA512_224, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha512_256, sha512_256, SHA512_256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

//SHA3
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha3_224, sha3_224, SHA3_224, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha3_256, sha3_256, SHA3_256, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha3_384, sha3_384, SHA3_384, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)
IMPLEMENT_SCOSSL_DIGEST_EXPORTABLE(Sha3_512, sha3_512, SHA3_512, SCOSSL_DIGEST_FLAG_ALGID_ABSENT)

#ifdef __cplusplus
}
#endif