//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_provider.h"
#include "p_scossl_composite_mldsa.h"

#include <openssl/proverr.h>

#ifdef __cplusplus
extern "C" {
#endif

SCOSSL_MLDSA_ALG_INFO p_scossl_composite_mldsa_algs[] = {
    {NID_undef, SCOSSL_OID_MLDSA44_ECDSA_P256_SHA256, SCOSSL_SN_MLDSA44_ECDSA_P256_SHA256, SCOSSL_LN_MLDSA44_ECDSA_P256_SHA256, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256},
    {NID_undef, SCOSSL_OID_MLDSA65_ECDSA_P256_SHA512, SCOSSL_SN_MLDSA65_ECDSA_P256_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P256_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512},
    {NID_undef, SCOSSL_OID_MLDSA65_ECDSA_P384_SHA512, SCOSSL_SN_MLDSA65_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA65_ECDSA_P384_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512},
    {NID_undef, SCOSSL_OID_MLDSA87_ECDSA_P384_SHA512, SCOSSL_SN_MLDSA87_ECDSA_P384_SHA512, SCOSSL_LN_MLDSA87_ECDSA_P384_SHA512, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512}};

static const OSSL_PARAM p_scossl_composite_mldsa_ctx_settable_param_types[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_END};

// Composite-ML-DSA does not support generating a key from a seed, so there are
// no settable key generation parameters.
static const OSSL_PARAM p_scossl_composite_mldsa_keygen_settable_param_types[] = {
    OSSL_PARAM_END};

//
// Backend wrappers. Each casts the generic PVOID key handle and the named int
// typedef format/parameter values to the concrete Composite-ML-DSA SymCrypt types.
//

static PVOID p_scossl_composite_mldsa_backend_key_allocate(SCOSSL_MLDSA_PARAMS params)
{
    return SymCryptCompositeMlDsakeyAllocate((SYMCRYPT_COMPOSITE_MLDSA_PARAMS)params);
}

static void p_scossl_composite_mldsa_backend_key_free(_In_ PVOID key)
{
    SymCryptCompositeMlDsakeyFree((PSYMCRYPT_COMPOSITE_MLDSAKEY)key);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_key_generate(_Inout_ PVOID key, UINT32 flags)
{
    return SymCryptCompositeMlDsakeyGenerate((PSYMCRYPT_COMPOSITE_MLDSAKEY)key, flags);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_key_set_value(_In_reads_bytes_(cbSrc) PCBYTE pbSrc, SIZE_T cbSrc, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags, _Inout_ PVOID key)
{
    return SymCryptCompositeMlDsakeySetValue(pbSrc, cbSrc, (SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT)format, flags, (PSYMCRYPT_COMPOSITE_MLDSAKEY)key);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_key_get_value(_In_ PVOID key, _Out_writes_bytes_(cbDst) PBYTE pbDst, SIZE_T cbDst, SCOSSL_MLDSA_KEY_FORMAT format, UINT32 flags)
{
    return SymCryptCompositeMlDsakeyGetValue((PCSYMCRYPT_COMPOSITE_MLDSAKEY)key, pbDst, cbDst, (SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT)format, flags);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_sizeof_key_format(SCOSSL_MLDSA_PARAMS params, SCOSSL_MLDSA_KEY_FORMAT format, _Out_ SIZE_T *pcbKeyFormat)
{
    return SymCryptCompositeMlDsaSizeofKeyFormatFromParams((SYMCRYPT_COMPOSITE_MLDSA_PARAMS)params, (SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT)format, pcbKeyFormat);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_sizeof_signature(SCOSSL_MLDSA_PARAMS params, _Out_ SIZE_T *pcbSignature)
{
    return SymCryptCompositeMlDsaSizeofSignatureFromParams((SYMCRYPT_COMPOSITE_MLDSA_PARAMS)params, pcbSignature);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_sign(_In_ PVOID key,
                                                            _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                                                            _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                                                            UINT32 flags,
                                                            _Out_writes_bytes_(cbSig) PBYTE pbSig, SIZE_T cbSig, _Out_ SIZE_T *pcbResult)
{
    // Composite-ML-DSA signatures may be shorter than cbSig due to variations in
    // Ecdsa-Sig-Value encoding; SymCryptCompositeMlDsaSign reports the exact size.
    return SymCryptCompositeMlDsaSign((PCSYMCRYPT_COMPOSITE_MLDSAKEY)key, pbMsg, cbMsg, pbCtx, cbCtx, flags, pbSig, cbSig, pcbResult);
}

static SYMCRYPT_ERROR p_scossl_composite_mldsa_backend_verify(_In_ PVOID key,
                                                              _In_reads_bytes_(cbMsg) PCBYTE pbMsg, SIZE_T cbMsg,
                                                              _In_reads_bytes_opt_(cbCtx) PCBYTE pbCtx, SIZE_T cbCtx,
                                                              _In_reads_bytes_(cbSig) PCBYTE pbSig, SIZE_T cbSig,
                                                              UINT32 flags)
{
    return SymCryptCompositeMlDsaVerify((PCSYMCRYPT_COMPOSITE_MLDSAKEY)key, pbMsg, cbMsg, pbCtx, cbCtx, pbSig, cbSig, flags);
}

static int p_scossl_composite_mldsa_backend_get_bits(SCOSSL_MLDSA_PARAMS params)
{
    switch ((SYMCRYPT_COMPOSITE_MLDSA_PARAMS)params)
    {
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256:
            return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256 * 8;
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512:
            return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512 * 8;
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512:
            return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512 * 8;
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512:
            return SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512 * 8;
        default:
            break;
    }

    return 0;
}

static int p_scossl_composite_mldsa_backend_get_security_bits(SCOSSL_MLDSA_PARAMS params)
{
    switch ((SYMCRYPT_COMPOSITE_MLDSA_PARAMS)params)
    {
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256:
            return 128;
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512:
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512:
            return 192;
        case SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512:
            return 256;
        default:
            break;
    }

    return 0;
}

const SCOSSL_MLDSA_BACKEND p_scossl_composite_mldsa_backend = {
    "Composite-ML-DSA",
    SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL,
    SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY,
    SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
    SCOSSL_MLDSA_FORMAT_NONE,
    FALSE,
    0,
    SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
    p_scossl_composite_mldsa_algs,
    sizeof(p_scossl_composite_mldsa_algs) / sizeof(SCOSSL_MLDSA_ALG_INFO),
    p_scossl_composite_mldsa_ctx_settable_param_types,
    NULL,
    p_scossl_composite_mldsa_keygen_settable_param_types,
    p_scossl_composite_mldsa_backend_key_allocate,
    p_scossl_composite_mldsa_backend_key_free,
    p_scossl_composite_mldsa_backend_key_generate,
    p_scossl_composite_mldsa_backend_key_set_value,
    p_scossl_composite_mldsa_backend_key_get_value,
    p_scossl_composite_mldsa_backend_sizeof_key_format,
    p_scossl_composite_mldsa_backend_sizeof_signature,
    p_scossl_composite_mldsa_backend_sign,
    p_scossl_composite_mldsa_backend_verify,
    p_scossl_composite_mldsa_backend_get_bits,
    p_scossl_composite_mldsa_backend_get_security_bits};

IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa44_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa65_ecdsa_p256, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa65_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512)
IMPLEMENT_SCOSSL_MLDSA_SIGNATURE(composite_mldsa87_ecdsa_p384, &p_scossl_composite_mldsa_backend, SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512)

SCOSSL_STATUS p_scossl_composite_mldsa_register_algorithms()
{
    // Composite-ML-DSA is not part of the default OpenSSL implementation, so the
    // objects must be created if they have not already been registered.
    return p_scossl_mldsa_register_backend(&p_scossl_composite_mldsa_backend);
}

#ifdef __cplusplus
}
#endif
