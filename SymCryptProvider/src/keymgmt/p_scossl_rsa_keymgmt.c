//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/param_build.h>
#include <openssl/proverr.h>

#include "p_scossl_base.h"
#include "p_scossl_rsa.h"
#include "scossl_rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    OSSL_LIB_CTX *libctx;
    // May be set for PSS
    UINT keyType;
    SCOSSL_RSA_PSS_RESTRICTIONS *pssRestrictions;

    UINT32 nBitsOfModulus;
    UINT64 pubExp64;
    UINT32 nPubExp;
} SCOSSL_RSA_KEYGEN_CTX;

#define SCOSSL_RSA_DEFAULT_DIGEST SN_sha256
#define SCOSSL_RSA_DEFAULT_BITS 2048
#define SCOSSL_RSA_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define SCOSSL_RSA_KEYMGMT_PARAMS                  \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),

// OpenSSL supports up to 10 primes via parameters,
// but SymCrypt only accepts 2
#define SCOSSL_MP_RSA_KEYMGMT_PARAMS                       \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0), \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),

#define SCOSSL_RSA_FIPS_MIN_SECURITY_BITS 112

#define SCOSSL_RSA_MR_DEFAULT_ITERATIONS 5
#define SCOSSL_RSA_MR_STATUS_ERROR -1
#define SCOSSL_RSA_MR_STATUS_PRIME 0
#define SCOSSL_RSA_MR_STATUS_COMPOSITE_WITH_FACTOR 1
#define SCOSSL_RSA_MR_STATUS_COMPOSITE_NOT_POWER 2

static const BYTE p_scossl_rsa_small_primes_product[] = {
    0x17, 0xB1, 0x5F, 0x27, 0x04, 0x60, 0xEC, 0x0C, 
    0x57, 0x27, 0x36, 0xED, 0x1A, 0x6C, 0x0E, 0x24,
    0x86, 0xBF, 0xBB, 0xA5, 0x11, 0x12, 0x5E, 0x2B, 
    0x3A, 0xEA, 0x2E, 0xB0, 0x72, 0xD8, 0x6B, 0x32,
    0x22, 0x44, 0xD8, 0x5A, 0x1B, 0x28, 0x7F, 0x5E, 
    0xC7, 0x8E, 0xDB, 0xA5, 0x33, 0x68, 0x36, 0xBC,
    0x85, 0xC4, 0xEB, 0x77, 0x51, 0xF3, 0x54, 0xAE, 
    0xC8, 0x93, 0x4A, 0xCA, 0xD6, 0xB9, 0x4D, 0x6C,
    0x02, 0x6B, 0xDB, 0x5B, 0x93, 0xC2, 0x97, 0xF0, 
    0x50, 0xB3, 0x77, 0xD1, 0x2F, 0xEE, 0x9B, 0x82,
    0x21, 0x0A, 0x0A, 0x84, 0xD8, 0x17, 0x5A, 0x14, 
    0x48, 0x71, 0x6B, 0x55, 0x51, 0x4B, 0xBF, 0x26,
    0xC4, 0x83, 0x3E, 0xB2, 0x33, 0xD3, 0x24, 0xF7, 
    0x91, 0x2B, 0x95, 0xE2, 0x23, 0x8C, 0x0B, 0xF9,
    0x48, 0x62, 0x71, 0x16, 0x1E, 0xB6, 0xCD, 0x2D, 
    0x65, 0x5F, 0xC4, 0x30, 0x93, 0x33, 0x3E, 0xF4,
    0xE3, 0xE1
};

static const OSSL_PARAM p_scossl_rsa_keygen_settable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_E, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsapss_keygen_settable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
    OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_E, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_keymgmt_gettable_param_types[] = {
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_uint32(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_uint(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    SCOSSL_RSA_KEYMGMT_PARAMS
    SCOSSL_MP_RSA_KEYMGMT_PARAMS
    OSSL_PARAM_END};

static const OSSL_PARAM p_scossl_rsa_keymgmt_impexp_param_types[] = {
    SCOSSL_RSA_KEYMGMT_PARAMS
    SCOSSL_MP_RSA_KEYMGMT_PARAMS
    OSSL_PARAM_END};

//
// Key Context Management
//
// Key import uses keymgmt_new to allocate an empty key object
// first, then passes that reference to keymgmt_import. Since
// the size of the SYMPCRYPT_RSAKEY depends on parameters that aren't
// known until import, no key is actually allocated here.
static SCOSSL_PROV_RSA_KEY_CTX *p_scossl_rsa_keymgmt_new_ctx(ossl_unused void *provctx)
{
    SCOSSL_PROV_RSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_RSA_KEY_CTX));
    if (keyCtx != NULL)
    {
        keyCtx->keyType = RSA_FLAG_TYPE_RSA;
#ifdef KEYSINUSE_ENABLED
        keyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();
        if (keyCtx->keysinuseLock == NULL)
        {
            OPENSSL_free(keyCtx);
            return NULL;
        }
#endif
    }
    return keyCtx;
}

static SCOSSL_PROV_RSA_KEY_CTX *p_scossl_rsapss_keymgmt_new_ctx(_In_ SCOSSL_PROVCTX *provctx)
{
    SCOSSL_PROV_RSA_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_RSA_KEY_CTX));
    if (keyCtx != NULL)
    {
        keyCtx->libctx = provctx->libctx;
        keyCtx->keyType = RSA_FLAG_TYPE_RSASSAPSS;
#ifdef KEYSINUSE_ENABLED
        keyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();
        if (keyCtx->keysinuseLock == NULL)
        {
            OPENSSL_free(keyCtx);
            return NULL;
        }
#endif
    }
    return keyCtx;
}

void p_scossl_rsa_keymgmt_free_ctx(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;

    if (keyCtx->key != NULL)
    {
        SymCryptRsakeyFree(keyCtx->key);
    }
#ifdef KEYSINUSE_ENABLED
    p_scossl_rsa_reset_keysinuse(keyCtx);
    CRYPTO_THREAD_lock_free(keyCtx->keysinuseLock);
#endif
    OPENSSL_free(keyCtx->pssRestrictions);
    OPENSSL_free(keyCtx);
}

// We need to export, then import the key to copy with optional private key.
static SCOSSL_STATUS p_scossl_rsa_keymgmt_dup_keydata(_In_ PCSYMCRYPT_RSAKEY fromKey, _Out_ PSYMCRYPT_RSAKEY *toKey, BOOL includePrivate)
{
    UINT64  pubExp64;
    PBYTE   pbModulus = NULL;
    SIZE_T  cbModulus = 0;
    PBYTE   ppbPrimes[2] = {0};
    SIZE_T  pcbPrimes[2] = {0};
    SIZE_T  cbPrime1 = 0;
    SIZE_T  cbPrime2 = 0;
    SIZE_T  nPrimes = includePrivate ? 2 : 0;
    PBYTE   pbCurrent = NULL;
    PBYTE   pbData = NULL;
    SIZE_T  cbData = 0;
    SCOSSL_STATUS  ret = SCOSSL_FAILURE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    cbModulus = SymCryptRsakeySizeofModulus(fromKey);
    cbPrime1 = SymCryptRsakeySizeofPrime(fromKey, 0);
    cbPrime2 = SymCryptRsakeySizeofPrime(fromKey, 1);

    cbData = cbModulus; // Modulus[cbModulus] // Big-endian.

    if (includePrivate)
    {
        cbData = cbModulus +     // Modulus[cbModulus] // Big-endian.
                 cbPrime1 +      // Prime1[cbPrime1] // Big-endian.
                 cbPrime2;       // Prime2[cbPrime2] // Big-endian.
    }

    pbData = OPENSSL_zalloc(cbData);
    if (pbData == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    pbCurrent = pbData;

    pbModulus = pbCurrent;
    pbCurrent += cbModulus;

    if (includePrivate)
    {
        ppbPrimes[0] = pbCurrent;
        pcbPrimes[0] = cbPrime1;
        pbCurrent += cbPrime1;

        ppbPrimes[1] = pbCurrent;
        pcbPrimes[1] = cbPrime2;
        pbCurrent += cbPrime2;
    }

    scError = SymCryptRsakeyGetValue(
                fromKey,
                pbModulus, cbModulus,
                &pubExp64, 1,
                ppbPrimes, pcbPrimes, nPrimes,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    SYMCRYPT_RSA_PARAMS SymcryptRsaParam;
    SymcryptRsaParam.version = 1;
    SymcryptRsaParam.nBitsOfModulus = cbModulus * 8;
    SymcryptRsaParam.nPrimes = nPrimes;
    SymcryptRsaParam.nPubExp = 1;
    *toKey = SymCryptRsakeyAllocate(&SymcryptRsaParam, 0);

    if (*toKey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptRsakeySetValue(
        pbModulus, cbModulus,
        &pubExp64, 1,
        (PCBYTE *)ppbPrimes, (SIZE_T *)pcbPrimes, nPrimes,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        *toKey);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeySetValue failed", scError);
        goto cleanup;
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    if(pbData)
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    if (!ret && toKey != NULL)
    {
        SymCryptRsakeyFree(*toKey);
    }

    return ret;
}

static SCOSSL_PROV_RSA_KEY_CTX *p_scossl_rsa_keymgmt_dup_ctx(_In_ const SCOSSL_PROV_RSA_KEY_CTX *keyCtx, int selection)
{
    SCOSSL_PROV_RSA_KEY_CTX *copyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_RSA_KEY_CTX));
    if (copyCtx == NULL)
    {
        return NULL;
    }

#ifdef KEYSINUSE_ENABLED
    copyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();
    if (copyCtx->keysinuseLock == NULL)
    {
        OPENSSL_free(copyCtx);
        return NULL;
    }

    if (keyCtx->keysinuseInfo == NULL ||
        p_scossl_keysinuse_upref(keyCtx->keysinuseInfo, NULL))
    {
        copyCtx->keysinuseInfo = keyCtx->keysinuseInfo;
    }
#endif

    copyCtx->initialized = keyCtx->initialized;
    copyCtx->keyType = keyCtx->keyType;

    if (keyCtx->initialized && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (!p_scossl_rsa_keymgmt_dup_keydata((PCSYMCRYPT_RSAKEY) keyCtx->key, &copyCtx->key,
                                              (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))
        {
            p_scossl_rsa_keymgmt_free_ctx(copyCtx);
            return NULL;
        }
    }

    if (keyCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS &&
        keyCtx->pssRestrictions != NULL &&
        (copyCtx->pssRestrictions = OPENSSL_memdup(keyCtx->pssRestrictions, sizeof(SCOSSL_RSA_PSS_RESTRICTIONS))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        p_scossl_rsa_keymgmt_free_ctx(copyCtx);
        return NULL;
    }

    return copyCtx;
}

//
// Key Generation
//
static SCOSSL_STATUS p_scossl_rsa_keygen_set_params(_Inout_ SCOSSL_RSA_KEYGEN_CTX *genCtx, _In_ const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL)
    {
        UINT32 nBitsOfModulus;

        if (!OSSL_PARAM_get_uint32(p, &nBitsOfModulus))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        // Provider is expected to validate lower bound here
        if (nBitsOfModulus < SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            return SCOSSL_FAILURE;
        }

        genCtx->nBitsOfModulus = nBitsOfModulus;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL)
    {
        SIZE_T nPrimes;
        if (!OSSL_PARAM_get_size_t(p, &nPrimes))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }

        if (nPrimes != 2)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL)
    {
        if (!OSSL_PARAM_get_uint64(p, &genCtx->pubExp64))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return SCOSSL_FAILURE;
        }
        genCtx->nPubExp = 1;
    }

    if (genCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS &&
        !p_scossl_rsa_pss_restrictions_from_params(genCtx->libctx, params, &genCtx->pssRestrictions))
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_PARAM *p_scossl_rsa_keygen_settable_params(ossl_unused void *genCtx,
                                                             ossl_unused void *provctx)
{
    return p_scossl_rsa_keygen_settable_param_types;
}

static const OSSL_PARAM *p_scossl_rsapss_keygen_settable_params(ossl_unused void *genCtx,
                                                                ossl_unused void *provctx)
{
    return p_scossl_rsapss_keygen_settable_param_types;
}

static void p_scossl_rsa_keygen_cleanup(_Inout_ SCOSSL_RSA_KEYGEN_CTX *genCtx)
{
    if (genCtx == NULL)
        return;

    OPENSSL_free(genCtx->pssRestrictions);
    OPENSSL_clear_free(genCtx, sizeof(SCOSSL_RSA_KEYGEN_CTX));
}

static SCOSSL_RSA_KEYGEN_CTX *p_scossl_rsa_keygen_init_common(_In_ SCOSSL_PROVCTX *provctx, int selection,
                                                              _In_ const OSSL_PARAM params[], UINT keyType)
{
    // Sanity check
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return NULL;
    }

    SCOSSL_RSA_KEYGEN_CTX *genCtx = OPENSSL_malloc(sizeof(SCOSSL_RSA_KEYGEN_CTX));
    if (genCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genCtx->nBitsOfModulus = SCOSSL_RSA_DEFAULT_BITS;
    genCtx->nPubExp = 0;
    genCtx->libctx = provctx->libctx;
    genCtx->keyType = keyType;
    genCtx->pssRestrictions = NULL;

    if (!p_scossl_rsa_keygen_set_params(genCtx, params))
    {
        p_scossl_rsa_keygen_cleanup(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

static SCOSSL_RSA_KEYGEN_CTX *p_scossl_rsa_keygen_init(_In_ SCOSSL_PROVCTX *provctx, int selection,
                                                       _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_keygen_init_common(provctx, selection, params, RSA_FLAG_TYPE_RSA);
}

static SCOSSL_RSA_KEYGEN_CTX *p_scossl_rsapss_keygen_init(_In_ SCOSSL_PROVCTX *provctx, int selection,
                                                          _In_ const OSSL_PARAM params[])
{
    return p_scossl_rsa_keygen_init_common(provctx, selection, params, RSA_FLAG_TYPE_RSASSAPSS);
}

static SCOSSL_PROV_RSA_KEY_CTX *p_scossl_rsa_keygen(_In_ SCOSSL_RSA_KEYGEN_CTX *genCtx, ossl_unused OSSL_CALLBACK *cb, ossl_unused void *cbarg)
{
    SYMCRYPT_RSA_PARAMS symcryptRsaParam;
    SCOSSL_PROV_RSA_KEY_CTX *keyCtx;
    SYMCRYPT_ERROR scError;
    PUINT64 pPubExp64;

    keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_PROV_RSA_KEY_CTX));
    if (keyCtx == NULL)
    {
        goto cleanup;
    }

    symcryptRsaParam.version = 1;
    symcryptRsaParam.nBitsOfModulus = genCtx->nBitsOfModulus;
    symcryptRsaParam.nPrimes = 2;
    symcryptRsaParam.nPubExp = 1;

    keyCtx->key = SymCryptRsakeyAllocate(&symcryptRsaParam, 0);
    if (keyCtx->key == NULL)
    {
        SCOSSL_PROV_LOG_ERROR(ERR_R_INTERNAL_ERROR, "SymCryptRsakeyAllocate failed");
        goto cleanup;
    }

    pPubExp64 = genCtx->nPubExp > 0 ? &genCtx->pubExp64 : NULL;
    scError = SymCryptRsakeyGenerate(keyCtx->key, pPubExp64, genCtx->nPubExp, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGenerate failed", scError);
        goto cleanup;
    }

    keyCtx->keyType = genCtx->keyType;
    keyCtx->pssRestrictions = genCtx->pssRestrictions;
    genCtx->pssRestrictions = NULL;
#ifdef KEYSINUSE_ENABLED
    keyCtx->isImported = FALSE;
    keyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();
    if (keyCtx->keysinuseLock == NULL)
    {
        goto cleanup;
    }
    keyCtx->keysinuseInfo = NULL;
#endif

    keyCtx->initialized = TRUE;

cleanup:
    if (keyCtx != NULL && !keyCtx->initialized)
    {
        if (keyCtx->key != NULL)
        {
            SymCryptRsakeyFree(keyCtx->key);
        }

        OPENSSL_free(keyCtx);
        keyCtx = NULL;
    }

    return keyCtx;
}

//
// Key context property querying
//

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

// p_scossl_rsa_keymgmt_get_keydata and p_scossl_rsa_keymgmt_get_crt_keydata are helper
// functions to fetch key data from SymCryptRsakeyGetValue SymCryptRsakeyGetCrtValue respectively.
// These are for p_scossl_rsa_keymgmt_get_params, where exporting the whole key with scossl_rsa_export_key
// is normally not necessary, since as few as one key parameters will be fetched.
static SCOSSL_STATUS p_scossl_rsa_keymgmt_get_keydata(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *paramModulus;
    PBYTE pbModulus = NULL;
    UINT32 cbModulus = 0;
    BIGNUM *bnModulus = NULL;

    OSSL_PARAM *paramPublicExponent;
    UINT64 publicExponent;
    PUINT64 pPublicExponent = NULL;
    BYTE pbLePublicExponent[8];
    UINT32 nPublicExponent = 0;
    BIGNUM *bnPublicExponent = NULL;

    OSSL_PARAM *paramPrime1;
    OSSL_PARAM *paramPrime2;
    PBYTE ppbPrimes[2] = {0};
    SIZE_T pcbPrimes[2] = {0};
    UINT32 nPrimes = 0;
    BIGNUM *bnPrime1 = NULL;
    BIGNUM *bnPrime2 = NULL;

    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    // Parameters fetched with SymCryptRsakeyGetValue
    paramModulus = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    paramPublicExponent = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    paramPrime1 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
    paramPrime2 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_FACTOR2);

    if (paramModulus == NULL &&
        paramPublicExponent == NULL &&
        paramPrime1 == NULL &&
        paramPrime2 == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    // Allocate buffers and BIGNUMs for requested parameters
    if (paramModulus != NULL)
    {
        cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
        if ((pbModulus = OPENSSL_malloc(cbModulus)) == NULL ||
            (bnModulus = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if (paramPublicExponent != NULL)
    {
        pPublicExponent = &publicExponent;
        nPublicExponent = 1;
        if ((bnPublicExponent = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if (paramPrime1 != NULL || paramPrime2 != NULL)
    {
        pcbPrimes[0] = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
        pcbPrimes[1] = SymCryptRsakeySizeofPrime(keyCtx->key, 1);
        nPrimes = 2;
        if ((ppbPrimes[0] = OPENSSL_secure_malloc(pcbPrimes[0])) == NULL ||
            (ppbPrimes[1] = OPENSSL_secure_malloc(pcbPrimes[1])) == NULL ||
            (bnPrime1 = BN_secure_new()) == NULL ||
            (bnPrime2 = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    // Unrequested parameters will be NULL and ignored
    scError = SymCryptRsakeyGetValue(
        keyCtx->key,
        pbModulus, cbModulus,
        pPublicExponent, nPublicExponent,
        ppbPrimes, pcbPrimes, nPrimes,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    // Convert buffers to BIGNUMs and set parameters
    if (paramModulus != NULL)
    {
        if (BN_lebin2bn(pbModulus, cbModulus, bnModulus) == NULL ||
            !OSSL_PARAM_set_BN(paramModulus, bnModulus))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPublicExponent != NULL)
    {
        scError = SymCryptStoreLsbFirstUint64(publicExponent, pbLePublicExponent, sizeof(pbLePublicExponent));

        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptStoreLsbFirstUint64 failed", scError);
            goto cleanup;
        }

        if (BN_lebin2bn(pbLePublicExponent, sizeof(pbLePublicExponent), bnPublicExponent) == NULL ||
            !OSSL_PARAM_set_BN(paramPublicExponent, bnPublicExponent))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrime1 != NULL)
    {
        if (BN_lebin2bn(ppbPrimes[0], pcbPrimes[0], bnPrime1) == NULL ||
            !OSSL_PARAM_set_BN(paramPrime1, bnPrime1))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramPrime2 != NULL)
    {
        if (BN_lebin2bn(ppbPrimes[1], pcbPrimes[1], bnPrime2) == NULL ||
            !OSSL_PARAM_set_BN(paramPrime2, bnPrime2))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_free(pbModulus);
    OPENSSL_secure_clear_free(ppbPrimes[0], pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbPrimes[1], pcbPrimes[1]);

    BN_free(bnModulus);
    BN_free(bnPublicExponent);
    BN_clear_free(bnPrime1);
    BN_clear_free(bnPrime2);

    return ret;
}


static SCOSSL_STATUS p_scossl_rsa_keymgmt_get_crt_keydata(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *paramPrivateExponent;
    PBYTE pbPrivateExponent = NULL;
    SIZE_T cbPrivateExponent = 0;
    BIGNUM *bnPrivateExponent = NULL;

    OSSL_PARAM *paramCrtExp1;
    OSSL_PARAM *paramCrtExp2;
    PBYTE ppbCrtExponents[2] = {0};
    SIZE_T pcbCrtExponents[2] = {0};
    UINT32 nCrtExponents = 0;
    BIGNUM *bnCrtExp1 = NULL;
    BIGNUM *bnCrtExp2 = NULL;

    OSSL_PARAM *paramCoefficient;
    PBYTE pbCrtCoefficient = NULL;
    SIZE_T cbCrtCoefficient = 0;
    BIGNUM *bnCoefficient = NULL;

    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    paramPrivateExponent = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_D);
    paramCrtExp1 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
    paramCrtExp2 = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
    paramCoefficient = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    if (paramCoefficient == NULL &&
        paramCrtExp1 == NULL &&
        paramCrtExp2 == NULL &&
        paramPrivateExponent == NULL)
    {
        return SCOSSL_SUCCESS;
    }

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    // Allocate buffers and BIGNUMs for requested parameters
    if (paramPrivateExponent != NULL)
    {
        cbPrivateExponent = SymCryptRsakeySizeofModulus(keyCtx->key);
        if ((pbPrivateExponent = OPENSSL_secure_malloc(cbPrivateExponent)) == NULL ||
            (bnPrivateExponent = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if (paramCrtExp1 != NULL || paramCrtExp2 != NULL)
    {
        pcbCrtExponents[0] = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
        pcbCrtExponents[1] = SymCryptRsakeySizeofPrime(keyCtx->key, 1);
        nCrtExponents = 2;
        if (((ppbCrtExponents[0] = OPENSSL_secure_malloc(pcbCrtExponents[0])) == NULL) ||
            ((ppbCrtExponents[1] = OPENSSL_secure_malloc(pcbCrtExponents[1])) == NULL) ||
            ((bnCrtExp1 = BN_secure_new()) == NULL) ||
            ((bnCrtExp2 = BN_secure_new()) == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    if (paramCoefficient != NULL)
    {
        cbCrtCoefficient = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
        if ((pbCrtCoefficient = OPENSSL_secure_malloc(cbCrtCoefficient)) == NULL ||
            (bnCoefficient = BN_secure_new()) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }
    }

    // Unrequested parameters will be NULL and ignored
    scError = SymCryptRsakeyGetCrtValue(
        keyCtx->key,
        ppbCrtExponents, pcbCrtExponents, nCrtExponents,
        pbCrtCoefficient, cbCrtCoefficient,
        pbPrivateExponent, cbPrivateExponent,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetCrtValue failed", scError);
        goto cleanup;
    }

    // Convert buffers to BIGNUMs and set parameters
    if (paramPrivateExponent != NULL)
    {
        if (BN_lebin2bn(pbPrivateExponent, cbPrivateExponent, bnPrivateExponent) == NULL ||
            !OSSL_PARAM_set_BN(paramPrivateExponent, bnPrivateExponent))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramCrtExp1 != NULL)
    {
        if (BN_lebin2bn(ppbCrtExponents[0], pcbCrtExponents[0], bnCrtExp1) == NULL ||
            !OSSL_PARAM_set_BN(paramCrtExp1, bnCrtExp1))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramCrtExp2 != NULL)
    {
        if (BN_lebin2bn(ppbCrtExponents[1], pcbCrtExponents[1], bnCrtExp2) == NULL ||
            !OSSL_PARAM_set_BN(paramCrtExp2, bnCrtExp2))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    if (paramCoefficient != NULL)
    {
        if (BN_lebin2bn(pbCrtCoefficient, cbCrtCoefficient, bnCoefficient) == NULL ||
            !OSSL_PARAM_set_BN(paramCoefficient, bnCoefficient))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            goto cleanup;
        }
    }

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbPrivateExponent, cbPrivateExponent);
    OPENSSL_secure_clear_free(ppbCrtExponents[0], pcbCrtExponents[0]);
    OPENSSL_secure_clear_free(ppbCrtExponents[1], pcbCrtExponents[1]);
    OPENSSL_secure_clear_free(pbCrtCoefficient, cbCrtCoefficient);

    BN_clear_free(bnPrivateExponent);
    BN_clear_free(bnCrtExp1);
    BN_clear_free(bnCrtExp2);
    BN_clear_free(bnCoefficient);

    return ret;
}

static SCOSSL_STATUS p_scossl_rsa_keymgmt_get_params(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_uint32(p, SymCryptRsakeyModulusBits(keyCtx->key)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, p_scossl_rsa_get_security_bits(keyCtx->key)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_uint32(p, SymCryptRsakeySizeofModulus(keyCtx->key)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    // This parameter gets ignored for restricted PSS keys
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL &&
         keyCtx->pssRestrictions == NULL &&
         !OSSL_PARAM_set_utf8_string(p, SCOSSL_RSA_DEFAULT_DIGEST))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    if (p_scossl_rsa_keymgmt_get_keydata(keyCtx, params) != SCOSSL_SUCCESS)
    {
        return SCOSSL_FAILURE;
    }

    return p_scossl_rsa_keymgmt_get_crt_keydata(keyCtx, params);
}

static const OSSL_PARAM *p_scossl_rsa_keymgmt_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_rsa_keymgmt_gettable_param_types;
}

static BOOL p_scossl_rsa_keymgmt_has(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, int selection)
{
    BOOL ret = TRUE;
    if (keyCtx->key == NULL)
    {
        return FALSE;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        ret = ret && SymCryptRsakeyHasPrivateKey(keyCtx->key);
    }
    return ret;
}

// Perform enhanced miller-rabin primality test on w. 
// This is based on OpenSSL's implementation from crypto/bn/bn_prime.c
static int p_scossl_rsa_keymgmt_miller_rabin_enhanced(_In_ BIGNUM *w, _In_ BN_CTX *bnCtx,
                                                      int iterations)
{
    int status = SCOSSL_RSA_MR_STATUS_ERROR;
    int a;
    int i;
    int j;
    BIGNUM *m;
    BIGNUM *w1;
    BIGNUM *w3;
    BIGNUM *b;
    BIGNUM *g;
    BIGNUM *z;
    BIGNUM *x;
    BOOL composite;
    BN_MONT_CTX *bnMontCtx = NULL;

    // w must be odd
    if (!BN_is_odd(w))
    {
        return SCOSSL_RSA_MR_STATUS_ERROR;
    }

    BN_CTX_start(bnCtx);
    m = BN_CTX_get(bnCtx);
    w1 = BN_CTX_get(bnCtx);
    w3 = BN_CTX_get(bnCtx); // Used for generating b
    b = BN_CTX_get(bnCtx);
    g = BN_CTX_get(bnCtx);
    z = BN_CTX_get(bnCtx);
    x = BN_CTX_get(bnCtx);

    if (x == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // Pre-compute w-1 and w-3
    if (!BN_copy(w1, w) || !BN_sub_word(w1, 1) ||
        !BN_copy(w3, w) || !BN_sub_word(w3, 3))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
        goto cleanup;
    }

    if (BN_is_zero(w3) || BN_is_negative(w3))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return SCOSSL_RSA_MR_STATUS_PRIME;
    }

    // 1. a = largest integest such that 2^a divides w-1
    for (a = 1; !BN_is_bit_set(w1, a); a++);

    // 2. m = (w - 1) / 2^a
    if (!BN_rshift(m, w1, a))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
        goto cleanup;
    }

    if ((bnMontCtx = BN_MONT_CTX_new()) == NULL ||
        !BN_MONT_CTX_set(bnMontCtx, w, bnCtx))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    for (i = 0; i < iterations; i++)
    {
        // 4.1 generate random b in 1 < b < w-1
        if (!BN_priv_rand_range_ex(b, w3, 0, bnCtx) || !BN_add_word(b, 2))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
            goto cleanup;
        }

        // 4.3 g = GCD(b, w)
        if (!BN_gcd(g, b, w, bnCtx))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
            goto cleanup;
        }

        // 4.4 If g > 1, return probably composite with factor
        if (!BN_is_one(g))
        {
            status = SCOSSL_RSA_MR_STATUS_COMPOSITE_WITH_FACTOR;
            goto cleanup;
        }

        // 4.5 z = b^m mod w
        if (!BN_mod_exp_mont(z, b, m, w, bnCtx, bnMontCtx))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
            goto cleanup;
        }

        // 4.6 if z == 1 or z == w-1, continue
        if (BN_is_one(z) || BN_cmp(z, w1) == 0)
        {
            continue;
        }

        composite = TRUE;
        for (j = 1; j < a; j++)
        {
            // 4.7.1 x = x
            if (!BN_copy(x, z) || 
            // 4.7.2 z = x^2 mod w
                !BN_mod_sqr(z, x, w, bnCtx))
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
                goto cleanup;
            }

            // 4.7.3 If z = w - 1, continue
            if (BN_cmp(z, w1) == 0)
            {
                composite = FALSE;
                break;
            }
            
            // 4.7.4 If z = 1, go to 4.12
            if (BN_is_one(z))
            {
                break;
            }
        }

        if (composite)
        {
            // Reached the end of the inner loop, so z != 1
            if (j == a)
            {
                // 4.8 x = z;   x = b^((w-1)/2) mod w and x != w-1
                if (!BN_copy(x, z) || 
                // 4.9 z = x^2 mod w
                    !BN_mod_sqr(z, x, w, bnCtx) ||
                // 4.10 if z == 1, go to 4.12                
                    (!BN_is_one(z) &&
                // 4.11 x = z;  x = b^(w-1) mod w and x != 1
                     !BN_copy(x, z)))
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
                    goto cleanup;
                }
            }

            // 4.12 g = GCD(x - 1, w)
            if (!BN_sub_word(x, 1) ||
                !BN_gcd(g, x, w, bnCtx))
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
                goto cleanup;
            }

            // 4.14 If g == 1, return probably composite and not a power of a prime
            if (BN_is_one(g))
            {
                status = SCOSSL_RSA_MR_STATUS_COMPOSITE_NOT_POWER;
            }
            // 4.13 If g > 1, return probably composite with factor
            else
            {
                status = SCOSSL_RSA_MR_STATUS_COMPOSITE_WITH_FACTOR;
            }
            
            goto cleanup;
        }
    }

    // 5. Return probably prime
    status = SCOSSL_RSA_MR_STATUS_PRIME;

cleanup:
    BN_CTX_end(bnCtx);
    BN_MONT_CTX_free(bnMontCtx);

    return status;
}

// Validate keypair according to SP800-56B 6.4.1.3.3 (rsakpv2-crt)
// Not all checks from the spec are included, as some are already
// guaranteed by SymCrypt during private key import and generation.
static BOOL p_scossl_rsa_keymgmt_validate_keypair(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx)
{
    BOOL ret = FALSE;
    PBYTE pbModulus = NULL;
    UINT32 cbModulus = 0;
    PBYTE ppbPrimes[2] = {0};
    SIZE_T pcbPrimes[2] = {0};
    UINT64 pubExp = 0;
    BN_CTX *bnCtx = NULL;
    BIGNUM *bnPrime1 = NULL;
    BIGNUM *bnPrime2 = NULL;
    BIGNUM *bnDiff = NULL;
    SYMCRYPT_ERROR scError;
    
    if (!keyCtx->initialized || !SymCryptRsakeyHasPrivateKey(keyCtx->key))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        goto cleanup;
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    pcbPrimes[0] = SymCryptRsakeySizeofPrime(keyCtx->key, 0);
    pcbPrimes[1] = SymCryptRsakeySizeofPrime(keyCtx->key, 1);

    pbModulus = OPENSSL_malloc(cbModulus);
    ppbPrimes[0] = OPENSSL_secure_malloc(pcbPrimes[0]);
    ppbPrimes[1] = OPENSSL_secure_malloc(pcbPrimes[1]);
    bnCtx = BN_CTX_secure_new();
    if (pbModulus == NULL || 
        ppbPrimes[0] == NULL ||
        ppbPrimes[1] == NULL ||
        bnCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    BN_CTX_start(bnCtx);

    // 1a. 112 <= security bits (log a warning but don't fail for compatability)
    if (p_scossl_rsa_get_security_bits(keyCtx->key) < SCOSSL_RSA_FIPS_MIN_SECURITY_BITS)
    {
        SCOSSL_PROV_LOG_INFO(SCOSSL_ERR_R_NOT_FIPS_ALGORITHM,
            "RSA keypair security bits less than 112 which is not FIPS compliant");
    }

    scError = SymCryptRsakeyGetValue(
        keyCtx->key,
        pbModulus, cbModulus,
        &pubExp, 1,
        ppbPrimes, pcbPrimes, 2,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    // 1c. 2^16 < pubExp < 2^256, pubExp is odd. pubExp < 2^256 is guaranteed by the size of UINT64
    if (pubExp <= (1 << 16) || (pubExp & 1) == 0)
    {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        goto cleanup;
    }
    
    bnPrime1 = BN_CTX_get(bnCtx);
    bnPrime2 = BN_CTX_get(bnCtx);
    bnDiff = BN_CTX_get(bnCtx);
    if (bnDiff == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    BN_set_flags(bnPrime1, BN_FLG_CONSTTIME);
    BN_set_flags(bnPrime2, BN_FLG_CONSTTIME);
    BN_set_flags(bnDiff, BN_FLG_CONSTTIME);
    
    // 5c. Check |p – q| <= 2^(nBits/2−100)
    if (BN_lebin2bn(ppbPrimes[0], pcbPrimes[0], bnPrime1) == NULL ||
        BN_lebin2bn(ppbPrimes[1], pcbPrimes[1], bnPrime2) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
        goto cleanup;
    }

    if (!BN_sub(bnDiff, bnPrime1, bnPrime2))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
        goto cleanup;
    }

    if (!BN_is_zero(bnDiff))
    {
        BN_set_negative(bnDiff, 0);
        
        if (!BN_sub_word(bnDiff, 1))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_BN_LIB);
            goto cleanup;
        }

        if ((UINT32) BN_num_bits(bnDiff) > ((SymCryptRsakeyModulusBits(keyCtx->key) >> 1) - 100))
        {
            goto cleanup;
        }
    }

    ret = TRUE;

cleanup:
    OPENSSL_free(pbModulus);
    OPENSSL_secure_clear_free(ppbPrimes[0], pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbPrimes[1], pcbPrimes[1]);
    BN_clear(bnPrime1);
    BN_clear(bnPrime2);
    BN_clear(bnDiff);
    BN_CTX_end(bnCtx);
    BN_CTX_free(bnCtx);

    return ret;
}

// Validate the 0 < d < n
static BOOL p_scossl_rsa_keymgmt_validate_private_key(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx)
{
    BOOL ret = FALSE;
    SYMCRYPT_ERROR scError;
    PBYTE pbPrivateExponent = NULL;
    PBYTE pbModulus = NULL;
    UINT32 cbModulus;
    BN_CTX *bnCtx = NULL;
    BIGNUM *bnModulus = NULL;
    BIGNUM *bnPrivateExponent = NULL;

    if (!keyCtx->initialized || !SymCryptRsakeyHasPrivateKey(keyCtx->key))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        goto cleanup;
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);

    bnCtx = BN_CTX_new();
    pbModulus = OPENSSL_malloc(cbModulus);
    pbPrivateExponent = OPENSSL_secure_malloc(cbModulus);
    if (bnCtx == NULL || 
        pbModulus == NULL || 
        pbPrivateExponent == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    BN_CTX_start(bnCtx);

    scError = SymCryptRsakeyGetValue(
        keyCtx->key,
        pbModulus, cbModulus,
        NULL, 0,
        NULL, NULL, 0,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    scError = SymCryptRsakeyGetCrtValue(
        keyCtx->key,
        NULL, NULL, 0,
        NULL, 0,
        pbPrivateExponent, cbModulus,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetCrtValue failed", scError);
        goto cleanup;
    }

    bnModulus = BN_CTX_get(bnCtx);
    bnPrivateExponent = BN_CTX_get(bnCtx);

    if (bnPrivateExponent == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (BN_lebin2bn(pbModulus, cbModulus, bnModulus) == NULL ||
        BN_lebin2bn(pbPrivateExponent, cbModulus,  bnPrivateExponent) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    ret = BN_cmp(bnPrivateExponent, BN_value_one()) >= 0 &&
          BN_cmp(bnPrivateExponent, bnModulus) < 0;

cleanup:
    OPENSSL_free(pbModulus);
    OPENSSL_secure_clear_free(pbPrivateExponent, cbModulus);
    BN_clear(bnPrivateExponent);
    BN_CTX_end(bnCtx);
    BN_CTX_free(bnCtx);

    return ret;
}

// Validate public key according to SP800-89 5.3.3
static BOOL p_scossl_rsa_keymgmt_validate_public_key(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx)
{
    BOOL ret = FALSE;
    int mrStatus = SCOSSL_RSA_MR_STATUS_ERROR;
    UINT64 pubExp = 0;
    PBYTE pbModulus = NULL;
    UINT32 cbModulus = 0;
    BN_CTX *bnCtx = NULL;
    BIGNUM *bnModulus;
    BIGNUM *bnSmallestPrimes;
    BIGNUM *gcd;
    SYMCRYPT_ERROR scError;

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        goto cleanup;
    }

    cbModulus = SymCryptRsakeySizeofModulus(keyCtx->key);
    bnCtx = BN_CTX_new();
    pbModulus = OPENSSL_malloc(cbModulus);
    if (pbModulus == NULL || bnCtx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    BN_CTX_start(bnCtx);
    bnModulus = BN_CTX_get(bnCtx);
    bnSmallestPrimes = BN_CTX_get(bnCtx);
    gcd = BN_CTX_get(bnCtx);
    if (gcd == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    
    scError = SymCryptRsakeyGetValue(
        keyCtx->key,
        pbModulus, cbModulus,
        &pubExp, 1,
        NULL, NULL, 0,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    // Convert to BIGNUM for validation checks
    if (BN_lebin2bn(pbModulus, cbModulus, bnModulus) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // 1. Modulus size check (checked by SymCrypt during key generation/import)
    // 2. 2^16 < pubExp < 2^256, pubExp is odd. pubExp < 2^256 is guaranteed by the size of UINT64
    if (pubExp <= (1 << 16) || (pubExp & 1) == 0)
    {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        goto cleanup;
    }

    // 3. Modulus is odd
    if (!BN_is_odd(bnModulus))
    {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto cleanup;
    }

    // 4. Modulus is composite, but not a power of a prime. Check using Miller-Rabin test
    mrStatus = p_scossl_rsa_keymgmt_miller_rabin_enhanced(bnModulus, bnCtx, SCOSSL_RSA_MR_DEFAULT_ITERATIONS);
    if (mrStatus != SCOSSL_RSA_MR_STATUS_COMPOSITE_NOT_POWER)
    {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto cleanup;
    }

    // 5. Modulus has no factors smaller than 752
    if (BN_bin2bn(p_scossl_rsa_small_primes_product, sizeof(p_scossl_rsa_small_primes_product), bnSmallestPrimes) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (!BN_gcd(gcd, bnModulus, bnSmallestPrimes, bnCtx) ||
        !BN_is_one(gcd))
    {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto cleanup;
    }    

    ret = TRUE;

cleanup:
    OPENSSL_free(pbModulus);
    BN_CTX_end(bnCtx);
    BN_CTX_free(bnCtx);

    return ret;
}

// Validates the RSA key according to SP800-89
static BOOL p_scossl_rsa_keymgmt_validate(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
    {
        return p_scossl_rsa_keymgmt_validate_keypair(keyCtx);
    }
    else if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        return p_scossl_rsa_keymgmt_validate_private_key(keyCtx); 
    }
    else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        return p_scossl_rsa_keymgmt_validate_public_key(keyCtx);
    } 

    return TRUE;
}

static BOOL p_scossl_rsa_keymgmt_match(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx1, _In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx2,
                                       int selection)
{
    BOOL ret = FALSE;
    UINT64 pubExp1 = 0;
    UINT64 pubExp2 = 0;
    PBYTE pbModulus1 = NULL;
    PBYTE pbModulus2 = NULL;
    PBYTE pbPrivateExponent1 = NULL;
    PBYTE pbPrivateExponent2 = NULL;
    SYMCRYPT_ERROR scError;

    UINT32 cbModulus = SymCryptRsakeySizeofModulus(keyCtx1->key);

    if (cbModulus != SymCryptRsakeySizeofModulus(keyCtx2->key))
    {
        goto cleanup;
    }

    if (((pbModulus1 = OPENSSL_malloc(cbModulus)) == NULL) ||
        ((pbModulus2 = OPENSSL_malloc(cbModulus)) == NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    scError = SymCryptRsakeyGetValue(
        keyCtx1->key,
        pbModulus1, cbModulus,
        &pubExp1, 1,
        NULL, NULL, 0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    scError = SymCryptRsakeyGetValue(
        keyCtx2->key,
        pbModulus2, cbModulus,
        &pubExp2, 1,
        NULL, NULL, 0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetValue failed", scError);
        goto cleanup;
    }

    // Public exponent should be checked regardless of selection
    if (pubExp1 != pubExp2)
    {
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) &&
        (memcmp(pbModulus1, pbModulus2, cbModulus) != 0))
    {
        goto cleanup;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        if ((pbPrivateExponent1 = OPENSSL_secure_malloc(cbModulus)) == NULL ||
            (pbPrivateExponent2 = OPENSSL_secure_malloc(cbModulus)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        scError = SymCryptRsakeyGetCrtValue(
            keyCtx1->key,
            NULL, NULL, 0,
            NULL, 0,
            pbPrivateExponent1, cbModulus,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
            {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetCrtValue failed", scError);
            goto cleanup;
        }

        scError = SymCryptRsakeyGetCrtValue(
            keyCtx2->key,
            NULL, NULL, 0,
            NULL, 0,
            pbPrivateExponent2, cbModulus,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeyGetCrtValue failed", scError);
            goto cleanup;
        }

        if (memcmp(pbPrivateExponent1, pbPrivateExponent1, cbModulus) != 0)
        {
            goto cleanup;
        }
    }

    ret = TRUE;
cleanup:
    OPENSSL_free(pbModulus1);
    OPENSSL_free(pbModulus2);
    OPENSSL_secure_clear_free(pbPrivateExponent1, cbModulus);
    OPENSSL_secure_clear_free(pbPrivateExponent2, cbModulus);

    return ret;
}

//
// Key import/export
//
static const OSSL_PARAM *p_scossl_rsa_keymgmt_impexp_types(int selection){
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 ?
        p_scossl_rsa_keymgmt_impexp_param_types :
        NULL;
}

static SCOSSL_STATUS p_scossl_rsa_keymgmt_import(_Inout_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, int selection, _In_ const OSSL_PARAM params[])
{
    BOOL include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    const OSSL_PARAM *p;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    UINT64 pubExp64;
    PBYTE pbModulus = NULL;
    SIZE_T cbModulus = SCOSSL_RSA_DEFAULT_BITS / 8;
    PBYTE pbPrivateExponent = NULL;
    SIZE_T cbPrivateExponent = 0;
    PBYTE ppbPrimes[2] = {0};
    SIZE_T pcbPrimes[2] = {0};
    SIZE_T nPrimes = 0;
    SYMCRYPT_RSA_PARAMS symcryptRsaParam;
    BIGNUM *bn = NULL;

    if (keyCtx == NULL ||
        (selection & SCOSSL_RSA_POSSIBLE_SELECTIONS) == 0)
    {
        return SCOSSL_FAILURE;
    }

    if ((bn = BN_new()) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N)) != NULL)
        {
            if (!OSSL_PARAM_get_BN(p, &bn))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
            
            cbModulus = BN_num_bytes(bn);
            pbModulus = OPENSSL_malloc(cbModulus);
            if (pbModulus == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }
            
            if (!BN_bn2bin(bn, pbModulus))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                goto cleanup;
            }
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) == NULL ||
            !OSSL_PARAM_get_uint64(p, &pubExp64))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }

        if (include_private)
        {
            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1)) != NULL)
            {
                if (!OSSL_PARAM_get_BN(p, &bn))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
                
                pcbPrimes[0] = BN_num_bytes(bn);
                ppbPrimes[0] = OPENSSL_secure_malloc(pcbPrimes[0]);
                if (ppbPrimes[0] == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    goto cleanup;
                }
                
                if (!BN_bn2bin(bn, ppbPrimes[0]))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
                nPrimes++;
            }

            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2)) != NULL)
            {
                if (!OSSL_PARAM_get_BN(p, &bn))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
                
                pcbPrimes[1] = BN_num_bytes(bn);
                ppbPrimes[1] = OPENSSL_secure_malloc(pcbPrimes[1]);
                if(ppbPrimes[1] == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    goto cleanup;
                }
                
                if (!BN_bn2bin(bn, ppbPrimes[1]))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
                nPrimes++;
            }

            // Only try to import private key from private exponent if primes are not provided
            if (nPrimes == 0 &&
                (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D)) != NULL)
            {
                if (!OSSL_PARAM_get_BN(p, &bn))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
                
                cbPrivateExponent = BN_num_bytes(bn);
                pbPrivateExponent = OPENSSL_secure_malloc(cbPrivateExponent);
                if(pbPrivateExponent == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    goto cleanup;
                }
                
                if (!BN_bn2bin(bn, pbPrivateExponent))
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                    goto cleanup;
                }
            }
        }

        if (nPrimes != 0 && nPrimes != 2)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            goto cleanup;
        }

        if (keyCtx->key != NULL)
        {
            SymCryptRsakeyFree(keyCtx->key);
        }

#ifdef KEYSINUSE_ENABLED
        // Reset keysinuse in case new key material is overwriting existing
        p_scossl_rsa_reset_keysinuse(keyCtx);
#endif

        symcryptRsaParam.version = 1;
        symcryptRsaParam.nBitsOfModulus = cbModulus * 8;
        symcryptRsaParam.nPrimes = pbPrivateExponent == NULL ? nPrimes : 2;
        symcryptRsaParam.nPubExp = 1;
        keyCtx->key = SymCryptRsakeyAllocate(&symcryptRsaParam, 0);
        if (keyCtx->key == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (pbPrivateExponent != NULL)
        {
            scError = SymCryptRsakeySetValueFromPrivateExponent(
                pbModulus, cbModulus,
                pubExp64,
                pbPrivateExponent, cbPrivateExponent,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
                keyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeySetValueFromPrivateExponent failed", scError);
                goto cleanup;
            }
        }
        else
        {
            scError = SymCryptRsakeySetValue(
                pbModulus, cbModulus,
                &pubExp64, 1,
                (PCBYTE *)ppbPrimes, (SIZE_T *)pcbPrimes, nPrimes,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
                keyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptRsakeySetValue failed", scError);
                goto cleanup;
            }
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        keyCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS &&
        !p_scossl_rsa_pss_restrictions_from_params(keyCtx->libctx, params, &keyCtx->pssRestrictions))
    {
        goto cleanup;
    }

    keyCtx->initialized = TRUE;
#ifdef KEYSINUSE_ENABLED
    keyCtx->isImported = TRUE;
#endif

    ret = SCOSSL_SUCCESS;

cleanup:
    OPENSSL_secure_clear_free(pbPrivateExponent, cbPrivateExponent);
    OPENSSL_secure_clear_free(ppbPrimes[0], pcbPrimes[0]);
    OPENSSL_secure_clear_free(ppbPrimes[1], pcbPrimes[1]);
    OPENSSL_free(pbModulus);
    BN_free(bn);

    return ret;
}

static SCOSSL_STATUS p_scossl_rsa_keymgmt_export(_In_ SCOSSL_PROV_RSA_KEY_CTX *keyCtx, int selection,
                                                 _In_ OSSL_CALLBACK *param_cb, _In_ void *cbarg)
{
    BOOL includePrivate = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    SCOSSL_RSA_EXPORT_PARAMS *rsaParams = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    if (keyCtx == NULL ||
        (selection & SCOSSL_RSA_POSSIBLE_SELECTIONS) == 0)
    {
        return ret;
    }

    rsaParams = scossl_rsa_new_export_params(includePrivate);
    if (rsaParams == NULL ||
        !scossl_rsa_export_key((PCSYMCRYPT_RSAKEY)keyCtx->key, rsaParams))
    {
        goto cleanup;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, rsaParams->n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, rsaParams->e) ||
        (includePrivate &&
         (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, rsaParams->privateParams->p) ||
          !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, rsaParams->privateParams->q) ||
          !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, rsaParams->privateParams->dmp1) ||
          !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, rsaParams->privateParams->dmq1) ||
          !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, rsaParams->privateParams->iqmp) ||
          !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, rsaParams->privateParams->d))))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        keyCtx->keyType == RSA_FLAG_TYPE_RSASSAPSS &&
        keyCtx->pssRestrictions != NULL &&
        !p_scossl_rsa_pss_restrictions_to_params(keyCtx->pssRestrictions, bld))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }

    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        goto cleanup;
    }
    ret = param_cb(params, cbarg);

cleanup:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    scossl_rsa_free_export_params(rsaParams, TRUE);

    return ret;
}

static const char *p_scossl_rsa_query_operation_name(ossl_unused int operation_id)
{
    return "RSA";
}

const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_rsa_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_rsa_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_rsa_keymgmt_free_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_rsa_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_rsa_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_rsa_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_rsa_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_rsa_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))p_scossl_rsa_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_rsa_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_rsa_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_rsa_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_rsa_keymgmt_export},
    {0, NULL}};

const OSSL_DISPATCH p_scossl_rsapss_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p_scossl_rsapss_keymgmt_new_ctx},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))p_scossl_rsa_keymgmt_dup_ctx},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p_scossl_rsa_keymgmt_free_ctx},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))p_scossl_rsa_keygen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))p_scossl_rsapss_keygen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p_scossl_rsa_keygen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p_scossl_rsapss_keygen_init},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p_scossl_rsa_keygen},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))p_scossl_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))p_scossl_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p_scossl_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))p_scossl_rsa_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p_scossl_rsa_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p_scossl_rsa_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p_scossl_rsa_keymgmt_impexp_types},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p_scossl_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p_scossl_rsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))p_scossl_rsa_query_operation_name},
    {0, NULL}};

#ifdef __cplusplus
}
#endif