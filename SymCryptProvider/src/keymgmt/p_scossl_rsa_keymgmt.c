//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"

typedef struct
{
    SIZE_T nBitsOfModulus;
    UINT64 pubExp64;
    UINT32 nPubExp;
} SCOSSL_RSA_KEYGEN_CTX;

static const OSSL_PARAM p_scossl_rsa_keygen_settable_param_types[] = {
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, 0),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_E, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_N, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_E, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_D, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL),
    OSSL_PARAM_END};

// This function is actually unnecessary for the SymCrypt provider,
// but required to support key import. A new RSA key object is allocated
// in RSA import,
PSYMCRYPT_RSAKEY p_scossl_rsa_keymgmt_new(ossl_unused void *provctx)
{
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS;
    SymcryptRsaParam.nPrimes = 0;
    SymcryptRsaParam.nPubExp = 1;

    return SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
}

// Key Generation
SCOSSL_STATUS p_scossl_rsa_keygen_set_params(_Inout_ SCOSSL_RSA_KEYGEN_CTX *genctx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &genctx->nBitsOfModulus))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_uint64(p, &genctx->pubExp64))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        genctx->nPubExp = 1;
    }

    return SCOSSL_SUCCESS;
}

const OSSL_PARAM *p_scossl_rsa_keygen_settable_params(ossl_unused void *genctx,
                                                      ossl_unused void *provctx)
{
    return p_scossl_rsa_keygen_settable_param_types;
}

void p_scossl_rsa_keygen_cleanup(_Inout_ SCOSSL_RSA_KEYGEN_CTX *genctx)
{
    OPENSSL_clear_free(genctx, sizeof(SCOSSL_RSA_KEYGEN_CTX));
}

SCOSSL_RSA_KEYGEN_CTX *p_scossl_rsa_keygen_init(ossl_unused void *provctx, int selection,
                                                _In_ const OSSL_PARAM params[])
{
    // Sanity check
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
    {
        return NULL;
    }

    SCOSSL_RSA_KEYGEN_CTX *genctx = OPENSSL_zalloc(sizeof(SCOSSL_RSA_KEYGEN_CTX));
    if (genctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genctx->nBitsOfModulus = 2048;
    genctx->nPubExp = 0;

    if (!p_scossl_rsa_keygen_set_params(genctx, params))
    {
        p_scossl_rsa_keygen_cleanup(genctx);
        genctx = NULL;
    }

    return genctx;
}

PSYMCRYPT_RSAKEY p_scossl_rsa_keygen(_In_ SCOSSL_RSA_KEYGEN_CTX *genctx, _In_opt_ OSSL_CALLBACK *cb, _In_opt_ void *cbarg)
{
    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    PSYMCRYPT_RSAKEY key;
    SYMCRYPT_ERROR scError;

    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = genctx->nBitsOfModulus;
    SymcryptRsaParam.nPrimes = 2;
    SymcryptRsaParam.nPubExp = genctx->nPubExp;

    key = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);
    if (key == NULL)
    {
        goto err;
    }

    scError = SymCryptRsakeyGenerate(key, &genctx->pubExp64, genctx->nPubExp, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        goto err;
    }

    return key;

err:
    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
    if (key != NULL)
    {
        SymCryptRsakeyFree(key);
    }
    return NULL;
}

// Security bits calculated with formula given in
// NIST SP 800-56B Rev. 2 Appendix D. Implementation from
// openssl/crypto/rsa/rsa_lib.c:ossl_ifc_ffc_compute_security_bits
static const unsigned int scale = 1 << 18;
static const unsigned int cbrt_scale = 1 << (2 * 18 / 3);
static const unsigned int log_2 = 0x02c5c8;
static const unsigned int log_e = 0x05c551;
static const unsigned int c1_923 = 0x07b126;
static const unsigned int c4_690 = 0x12c28f;

static ossl_inline UINT64 mul2(UINT64 a, UINT64 b)
{
    return a * b / scale;
}

static UINT64 icbrt64(UINT64 x)
{
    UINT64 r = 0;
    UINT64 b;
    int s;

    for (s = 63; s >= 0; s -= 3)
    {
        r <<= 1;
        b = 3 * r * (r + 1) + 1;
        if ((x >> s) >= b)
        {
            x -= b << s;
            r++;
        }
    }
    return r * cbrt_scale;
}

static UINT32 ilog_e(UINT64 v)
{
    UINT32 i, r = 0;

    while (v >= 2 * scale)
    {
        v >>= 1;
        r += scale;
    }
    for (i = scale / 2; i != 0; i /= 2)
    {
        v = mul2(v, v);
        if (v >= 2 * scale)
        {
            v >>= 1;
            r += i;
        }
    }
    r = (r * (UINT64)scale) / log_e;
    return r;
}

static UINT16 p_scossl_rsa_compute_security_bits(UINT32 n)
{
    UINT64 x;
    UINT32 lx;
    UINT16 y, cap;

    if (n <= 7680)
        cap = 192;
    else if (n <= 15360)
        cap = 256;
    else
        cap = 1200;

    x = n * (UINT64)log_2;
    lx = ilog_e(x);
    y = (UINT16)((mul2(c1_923, icbrt64(mul2(mul2(x, lx), lx))) - c4_690) / log_2);
    y = (y + 4) & ~7;
    if (y > cap)
        y = cap;

    return y;
}

static UINT16 p_scossl_rsa_get_security_bits(_In_ PSYMCRYPT_RSAKEY keydata)
{
    UINT16 ret = 0;
    UINT32 nBNitsOfModulus = SymCryptRsakeyModulusBits(keydata);

    // Common key sizes are hardcoded
    switch (nBNitsOfModulus)
    {
    case 1024:
        ret = 80;
        break;
    case 2048:
        ret = 112;
        break;
    case 3072:
        ret = 128;
        break;
    case 4096:
        ret = 152;
        break;
    case 7680:
        ret = 192;
        break;
    case 8192:
        ret = 200;
        break;
    case 15360:
        ret = 256;
        break;
    default:
        ret = p_scossl_rsa_compute_security_bits(nBNitsOfModulus);
    }

    return ret;
}

SCOSSL_STATUS p_scossl_keymgmt_get_params(_In_ PSYMCRYPT_RSAKEY keydata, _Inout_ OSSL_PARAM params[])
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    OSSL_PARAM *p;
    OSSL_PARAM *p_d;
    OSSL_PARAM *p_crt_exp1;
    OSSL_PARAM *p_crt_exp2;
    OSSL_PARAM *p_coefficient;
    OSSL_PARAM *p_n;
    OSSL_PARAM *p_e;
    OSSL_PARAM *p_prime1;
    OSSL_PARAM *p_prime2;
    UINT64 p_data_uint64;

    UINT32 cbModulus = SymCryptRsakeySizeofModulus(keydata);
    PBYTE pbModulus = NULL;
    PBYTE pbPrivateExponent = NULL;
    PBYTE pbCrtCoefficient = NULL;
    PBYTE ppbPrimes[2] = {0};
    PBYTE ppbCrtExponents[2] = {0};

    SIZE_T pcbPrimes[2] = {
        SymCryptRsakeySizeofPrime(keydata, 0),
        SymCryptRsakeySizeofPrime(keydata, 1)};

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, SymCryptRsakeyModulusBits(keydata)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, p_scossl_rsa_get_security_bits(keydata)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, cbModulus))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    p_d = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_D);
    p_crt_exp1 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
    p_crt_exp2 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
    p_coefficient = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    if (p_d != NULL ||
        p_crt_exp1 != NULL ||
        p_crt_exp2 != NULL ||
        p_coefficient != NULL)
    {
        if (((pbPrivateExponent  = OPENSSL_secure_malloc(cbModulus))    == NULL) ||
            ((pbCrtCoefficient   = OPENSSL_secure_malloc(pcbPrimes[0])) == NULL) ||
            ((ppbCrtExponents[0] = OPENSSL_secure_malloc(pcbPrimes[0])) == NULL) ||
            ((ppbCrtExponents[1] = OPENSSL_secure_malloc(pcbPrimes[1])) == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (SymCryptRsakeyGetCrtValue(
                keydata,
                ppbCrtExponents,
                pcbPrimes,
                2,
                pbCrtCoefficient,
                pcbPrimes[0],
                pbPrivateExponent,
                cbModulus,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (p_d != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)pbPrivateExponent, cbModulus, &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_d, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_crt_exp1 != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)ppbCrtExponents[0], pcbPrimes[0], &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_crt_exp1, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_crt_exp2 != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)ppbCrtExponents[1], pcbPrimes[1], &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_crt_exp2, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_coefficient != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)pbCrtCoefficient, pcbPrimes[0], &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_coefficient, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    p_n = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    p_e = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    p_prime1 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
    p_prime2 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
    if (p_n != NULL ||
        p_e != NULL ||
        p_prime1 != NULL ||
        p_prime2 != NULL)
    {
        UINT64 pubExp64;

        if (((pbModulus    = OPENSSL_malloc(cbModulus))           == NULL) ||
            ((ppbPrimes[0] = OPENSSL_secure_malloc(pcbPrimes[0])) == NULL) ||
            ((ppbPrimes[1] = OPENSSL_secure_malloc(pcbPrimes[1])) == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (SymCryptRsakeyGetValue(
                keydata,
                pbModulus,
                cbModulus,
                &pubExp64,
                1,
                ppbPrimes,
                pcbPrimes,
                2,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0) != SYMCRYPT_NO_ERROR)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }

        if (p_n != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)pbModulus, cbModulus, &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_n, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_e != NULL &&
            !OSSL_PARAM_set_uint64(p_e, pubExp64))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_prime1 != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)ppbPrimes[0], pcbPrimes[0], &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_prime1, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
        if (p_prime2 != NULL &&
            (SymCryptLoadMsbFirstUint64((PCBYTE)ppbPrimes[1], pcbPrimes[1], &p_data_uint64) != SYMCRYPT_NO_ERROR ||
             !OSSL_PARAM_set_uint64(p_prime2, p_data_uint64)))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;
cleanup:
    OPENSSL_free(pbModulus);
    OPENSSL_secure_clear_free(pbPrivateExponent, cbModulus);
    OPENSSL_secure_clear_free(pbCrtCoefficient, pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbCrtExponents[0], pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbCrtExponents[1], pcbPrimes[1]);
    OPENSSL_secure_clear_free(ppbPrimes[0], pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbPrimes[1], pcbPrimes[1]);

    return ret;
}

const OSSL_PARAM *p_scossl_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_rsa_keymgmt_gettable_param_types;
}

BOOL p_scossl_keymgmt_has(_In_ PSYMCRYPT_RSAKEY keydata, int selection)
{
    BOOL ret = TRUE;
    if (keydata == NULL)
    {
        return FALSE;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        ret = ret && SymCryptRsakeyHasPrivateKey(keydata);
    }
    return ret;
}
SCOSSL_STATUS p_scossl_keymgmt_match(_In_ PSYMCRYPT_RSAKEY keydata, _In_ PSYMCRYPT_RSAKEY keydata2,
                                     int selection)
{
}

SCOSSL_STATUS p_scossl_keymgmt_import(_In_ PSYMCRYPT_RSAKEY keydata, int selection, _In_ const OSSL_PARAM params[])
{
}

const OSSL_PARAM *p_scossl_keymgmt_import_types(int selection)
{
}

SCOSSL_STATUS p_scossl_keymgmt_export(_In_ PSYMCRYPT_RSAKEY keydata, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg)
{
}

const OSSL_PARAM *p_scossl_keymgmt_export_types(int selection)
{
}

const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_rsa_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))SymCryptRsakeyFree},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_rsa_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_rsa_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_rsa_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_rsa_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_rsa_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_keymgmt_export_types},

    {0, NULL}};
