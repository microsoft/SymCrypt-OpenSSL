//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_mldsa.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_MLDSA_MSG_ENCODING_PURE 1

SCOSSL_MLDSA_ALG_INFO p_scossl_mldsa_algs[] = {
    {NID_undef, SCOSSL_OID_MLDSA44, SCOSSL_SN_MLDSA44, SCOSSL_LN_MLDSA44, SYMCRYPT_MLDSA_PARAMS_MLDSA44},
    {NID_undef, SCOSSL_OID_MLDSA65, SCOSSL_SN_MLDSA65, SCOSSL_LN_MLDSA65, SYMCRYPT_MLDSA_PARAMS_MLDSA65},
    {NID_undef, SCOSSL_OID_MLDSA87, SCOSSL_SN_MLDSA87, SCOSSL_LN_MLDSA87, SYMCRYPT_MLDSA_PARAMS_MLDSA87}};

static const OSSL_PARAM p_scossl_mldsa_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END};

// Backend wrappers translating the family independent key handle, params and
// format to the concrete "pure" ML-DSA SymCrypt types.

static SYMCRYPT_MLDSAKEY_FORMAT p_scossl_mldsa_backend_format(SCOSSL_MLDSA_KEY_FORMAT format)
{
    switch (format)
    {
        case SCOSSL_MLDSA_KEY_FORMAT_PUBLIC:       return SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
        case SCOSSL_MLDSA_KEY_FORMAT_PRIVATE:      return SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
        case SCOSSL_MLDSA_KEY_FORMAT_PRIVATE_SEED: return SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
        default:                                   return SYMCRYPT_MLDSAKEY_FORMAT_NULL;
    }
}

static PVOID p_scossl_mldsa_backend_key_allocate(SCOSSL_MLDSA_PARAMS params)
{
    return SymCryptMlDsakeyAllocate((SYMCRYPT_MLDSA_PARAMS)params);
}

static void p_scossl_mldsa_backend_key_free(_In_ PVOID key)
{
    SymCryptMlDsakeyFree((PSYMCRYPT_MLDSAKEY)key);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_key_generate(_Inout_ PVOID key, UINT32 flags)
{
    return SymCryptMlDsakeyGenerate((PSYMCRYPT_MLDSAKEY)key, flags);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_key_set_value(_In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags, _Inout_ PVOID key)
{
    return SymCryptMlDsakeySetValue(pbSrc, cbSrc, p_scossl_mldsa_backend_format(format), flags, (PSYMCRYPT_MLDSAKEY)key);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_key_get_value(_In_ PVOID key, _Out_writes_bytes_(cbDst) PBYTE pbDst, SIZE_T cbDst, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags)
{
    return SymCryptMlDsakeyGetValue((PCSYMCRYPT_MLDSAKEY)key, pbDst, cbDst, p_scossl_mldsa_backend_format(format), flags);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_sizeof_key_format(SCOSSL_MLDSA_PARAMS params, SCOSSL_MLDSA_KEY_FORMAT format, _Out_ SIZE_T *pcbKeyFormat)
{
    return SymCryptMlDsaSizeofKeyFormatFromParams((SYMCRYPT_MLDSA_PARAMS)params, p_scossl_mldsa_backend_format(format), pcbKeyFormat);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_sizeof_signature(SCOSSL_MLDSA_PARAMS params, _Out_ SIZE_T *pcbSignature)
{
    return SymCryptMlDsaSizeofSignatureFromParams((SYMCRYPT_MLDSA_PARAMS)params, pcbSignature);
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_sign(_In_ PVOID key,
                                                  _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                                                  _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                                                  UINT32 flags,
                                                  _Out_writes_bytes_(cbSig) PBYTE pbSig, SIZE_T cbSig, _Out_ SIZE_T *pcbResult)
{
    // "Pure" ML-DSA signatures are always exactly cbSig bytes long.
    SYMCRYPT_ERROR scError = SymCryptMlDsaSign((PCSYMCRYPT_MLDSAKEY)key, pbMsg, cbMsg, pbCtx, cbCtx, flags, pbSig, cbSig);
    if (scError == SYMCRYPT_NO_ERROR && pcbResult != NULL)
    {
        *pcbResult = cbSig;
    }

    return scError;
}

static SYMCRYPT_ERROR p_scossl_mldsa_backend_verify(_In_ PVOID key,
                                                    _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                                                    _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                                                    _In_reads_bytes_(cbSig) PCBYTE pbSig, SIZE_T cbSig,
                                                    UINT32 flags)
{
    return SymCryptMlDsaVerify((PCSYMCRYPT_MLDSAKEY)key, pbMsg, cbMsg, pbCtx, cbCtx, pbSig, cbSig, flags);
}

static int p_scossl_mldsa_backend_get_bits(SCOSSL_MLDSA_PARAMS params)
{
    switch ((SYMCRYPT_MLDSA_PARAMS)params)
    {
        case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
            return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44 * 8;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
            return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65 * 8;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
            return SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87 * 8;
        default:
            break;
    }

    return 0;
}

static int p_scossl_mldsa_backend_get_security_bits(SCOSSL_MLDSA_PARAMS params)
{
    switch ((SYMCRYPT_MLDSA_PARAMS)params)
    {
        case SYMCRYPT_MLDSA_PARAMS_MLDSA44:
            return 128;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA65:
            return 192;
        case SYMCRYPT_MLDSA_PARAMS_MLDSA87:
            return 256;
        default:
            break;
    }

    return 0;
}

// "Pure" ML-DSA exposes several additional signature context parameters that are
// not supported yet. Validate that they are absent or set to their default value.
static SCOSSL_STATUS p_scossl_mldsa_validate_extra_sig_ctx_params(_In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING)) != NULL)
    {
        int messageEncoding;
        if (!OSSL_PARAM_get_int(p, &messageEncoding))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (messageEncoding != SCOSSL_MLDSA_MSG_ENCODING_PURE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC)) != NULL)
    {
        int deterministic;
        if (!OSSL_PARAM_get_int(p, &deterministic))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (deterministic != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY)) != NULL &&
        p->data_size != 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU)) != NULL)
    {
        int mu;
        if (!OSSL_PARAM_get_int(p, &mu))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (mu != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    return SCOSSL_SUCCESS;
}

const SCOSSL_MLDSA_BACKEND p_scossl_mldsa_backend = {
    "MLDSA",
    TRUE,
    SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE,
    p_scossl_mldsa_algs,
    sizeof(p_scossl_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO),
    p_scossl_mldsa_ctx_settable_param_types,
    p_scossl_mldsa_validate_extra_sig_ctx_params,
    p_scossl_mldsa_keygen_settable_param_types,
    p_scossl_mldsa_backend_key_allocate,
    p_scossl_mldsa_backend_key_free,
    p_scossl_mldsa_backend_key_generate,
    p_scossl_mldsa_backend_key_set_value,
    p_scossl_mldsa_backend_key_get_value,
    p_scossl_mldsa_backend_sizeof_key_format,
    p_scossl_mldsa_backend_sizeof_signature,
    p_scossl_mldsa_backend_sign,
    p_scossl_mldsa_backend_verify,
    p_scossl_mldsa_backend_get_bits,
    p_scossl_mldsa_backend_get_security_bits};

IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa44, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA44)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa65, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA65)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(mldsa87, &p_scossl_mldsa_backend, SYMCRYPT_MLDSA_PARAMS_MLDSA87)

SCOSSL_STATUS p_scossl_mldsa_register_algorithms()
{
    // Don't double register ML-DSA algorithms. These should already be registered
    // on OpenSSL 3.5+.
    return p_scossl_mldsa_register_backend(&p_scossl_mldsa_backend);
}

#ifdef __cplusplus
}
#endif
