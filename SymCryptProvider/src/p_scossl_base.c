//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/proverr.h>

#include "scossl_helpers.h"
#include "p_scossl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALG(names, funcs) {names, "provider="P_SCOSSL_NAME, funcs, NULL}
#define ALG_TABLE_END { NULL, NULL, NULL, NULL}

static int scossl_prov_initialized = 0;

static OSSL_FUNC_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_FUNC_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_FUNC_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_FUNC_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;

// Digest
extern const OSSL_DISPATCH p_scossl_md5_functions[];
extern const OSSL_DISPATCH p_scossl_sha1_functions[];
extern const OSSL_DISPATCH p_scossl_sha256_functions[];
extern const OSSL_DISPATCH p_scossl_sha384_functions[];
extern const OSSL_DISPATCH p_scossl_sha512_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_256_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_384_functions[];
extern const OSSL_DISPATCH p_scossl_sha3_512_functions[];

static const OSSL_ALGORITHM p_scossl_digest[] = {
    ALG("MD5:SSL3-MD5:1.2.840.113549.2.5", p_scossl_md5_functions),
    ALG("SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", p_scossl_sha1_functions),
    ALG("SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", p_scossl_sha256_functions),
    ALG("SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", p_scossl_sha384_functions),
    ALG("SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", p_scossl_sha512_functions),
    ALG("SHA3-256:2.16.840.1.101.3.4.2.8", p_scossl_sha3_256_functions),
    ALG("SHA3-384:2.16.840.1.101.3.4.2.9", p_scossl_sha3_384_functions),
    ALG("SHA3-512:2.16.840.1.101.3.4.2.10", p_scossl_sha3_512_functions),
    ALG_TABLE_END};

// Cipher
extern const OSSL_DISPATCH p_scossl_aes128cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cbc_functions[];
extern const OSSL_DISPATCH p_scossl_aes128ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes192ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes256ecb_functions[];
extern const OSSL_DISPATCH p_scossl_aes128cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cfb_functions[];
extern const OSSL_DISPATCH p_scossl_aes128cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes192cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes256cfb8_functions[];
extern const OSSL_DISPATCH p_scossl_aes128gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256gcm_functions[];
extern const OSSL_DISPATCH p_scossl_aes128ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes192ccm_functions[];
extern const OSSL_DISPATCH p_scossl_aes256ccm_functions[];

// Disabling XTS for now, also disabled in engine pending
// the same dependencies.
// Need to push the FIPS mode XTS flag into the SymCrypt API,
// and expose an XTS key copy method.
// extern const OSSL_DISPATCH p_scossl_aes256xts_functions[];
// extern const OSSL_DISPATCH p_scossl_aes128xts_functions[];

static const OSSL_ALGORITHM p_scossl_cipher[] = {
    ALG("AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2", p_scossl_aes128cbc_functions),
    ALG("AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22", p_scossl_aes192cbc_functions),
    ALG("AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42", p_scossl_aes256cbc_functions),
    ALG("AES-128-ECB:2.16.840.1.101.3.4.1.1", p_scossl_aes128ecb_functions),
    ALG("AES-192-ECB:2.16.840.1.101.3.4.1.21", p_scossl_aes192ecb_functions),
    ALG("AES-256-ECB:2.16.840.1.101.3.4.1.41", p_scossl_aes256ecb_functions),
    ALG("AES-128-CFB:2.16.840.1.101.3.4.1.4", p_scossl_aes128cfb_functions),
    ALG("AES-192-CFB:2.16.840.1.101.3.4.1.24", p_scossl_aes192cfb_functions),
    ALG("AES-256-CFB:2.16.840.1.101.3.4.1.44", p_scossl_aes256cfb_functions),
    ALG("AES-128-CFB8", p_scossl_aes128cfb8_functions),
    ALG("AES-192-CFB8", p_scossl_aes192cfb8_functions),
    ALG("AES-256-CFB8", p_scossl_aes256cfb8_functions),
    ALG("AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", p_scossl_aes128gcm_functions),
    ALG("AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26", p_scossl_aes192gcm_functions),
    ALG("AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", p_scossl_aes256gcm_functions),
    ALG("AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7", p_scossl_aes128ccm_functions),
    ALG("AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27", p_scossl_aes192ccm_functions),
    ALG("AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47", p_scossl_aes256ccm_functions),
    // ALG("AES-128-XTS:1.3.111.2.1619.0.1.1", p_scossl_aes256xts_functions),
    // ALG("AES-256-XTS:1.3.111.2.1619.0.1.2", p_scossl_aes128xts_functions),
    ALG_TABLE_END};

// MAC
extern const OSSL_DISPATCH p_scossl_hmac_functions[];

static const OSSL_ALGORITHM p_scossl_mac[] = {
    // ALG("HMAC", p_scossl_hmac_functions),
    ALG_TABLE_END};

// KDF
extern const OSSL_DISPATCH p_scossl_sshkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_hkdf_kdf_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_kdf_functions[];

static const OSSL_ALGORITHM p_scossl_kdf[] = {
    // ALG("SSHKDF", p_scossl_sshkdf_kdf_functions),
    // ALG("HKDF", p_scossl_hkdf_kdf_functions),
    // ALG("TLS1-PRF", p_scossl_tls1prf_kdf_functions),
    ALG_TABLE_END};

// Rand
extern const OSSL_DISPATCH p_scossl_rand_functions[];

static const OSSL_ALGORITHM p_scossl_rand[] = {
    ALG("CTR-DRBG", p_scossl_rand_functions),
    ALG_TABLE_END};

// Key management
extern const OSSL_DISPATCH p_scossl_dh_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p_scossl_ecc_keymgmt_functions[];

static const OSSL_ALGORITHM p_scossl_keymgmt[] = {
    // ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", p_scossl_dh_keymgmt_functions),
    // ALG("RSA:rsaEncryption:1.2.840.113549.1.1.1:", p_scossl_rsa_keymgmt_functions),
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", p_scossl_rsa_keymgmt_functions),
    // ALG("EC:id-ecPublicKey:1.2.840.10045.2.1", p_scossl_ecc_keymgmt_functions),
    ALG_TABLE_END};

// Key exchange
extern const OSSL_DISPATCH p_scossl_dh_functions[];
extern const OSSL_DISPATCH p_scossl_ecdh_functions[];
extern const OSSL_DISPATCH p_scossl_x25519_functions[];
extern const OSSL_DISPATCH p_scossl_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH p_scossl_tls1prf_keyexch_functions[];

static const OSSL_ALGORITHM p_scossl_keyexch[] = {
    // ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", p_scossl_dh_functions),
    // ALG("ECDH", p_scossl_ecdh_functions),
    // ALG("X25519:1.3.101.110", p_scossl_x25519_functions),
    // ALG("HKDF", p_scossl_hkdf_keyexch_functions),
    // ALG("TLS1-PRF", p_scossl_tls1prf_keyexch_functions),
    ALG_TABLE_END};

// Signature
extern const OSSL_DISPATCH p_scossl_rsa_signature_functions[];
extern const OSSL_DISPATCH p_scossl_ecdsa_signature_functions[];

static const OSSL_ALGORITHM p_scossl_signature[] = {
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", p_scossl_rsa_signature_functions),
    // ALG("EC:id-ecPublicKey:1.2.840.10045.2.1", p_scossl_ecdsa_signature_functions),
    ALG_TABLE_END};

// Asymmetric Cipher
extern const OSSL_DISPATCH p_scossl_rsa_asym_cipher_functions[];

static const OSSL_ALGORITHM p_scossl_asym_cipher[] = {
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", p_scossl_rsa_asym_cipher_functions),
    ALG_TABLE_END};

static int p_scossl_get_status()
{
    return scossl_prov_initialized;
}

static void p_scossl_teardown(_Inout_ SCOSSL_PROVCTX *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *p_scossl_gettable_params(ossl_unused void *provctx)
{
    return p_scossl_param_types;
}

static SCOSSL_STATUS p_scossl_get_params(ossl_unused void *provctx, _Inout_ OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_NAME))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, P_SCOSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, p_scossl_get_status()))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

static const OSSL_ALGORITHM *p_scossl_query_operation(ossl_unused void *provctx, int operation_id, _Out_ int *no_store)
{
    // Dispatch tables do not change and may be cached
    *no_store = 0;
    switch (operation_id)
    {
    case OSSL_OP_DIGEST:
        return p_scossl_digest;
    case OSSL_OP_CIPHER:
        return p_scossl_cipher;
    case OSSL_OP_MAC:
        return p_scossl_mac;
    case OSSL_OP_KDF:
        return p_scossl_kdf;
    case OSSL_OP_RAND:
        return p_scossl_rand;
    case OSSL_OP_KEYMGMT:
        return p_scossl_keymgmt;
    case OSSL_OP_KEYEXCH:
        return p_scossl_keyexch;
    case OSSL_OP_SIGNATURE:
        return p_scossl_signature;
    case OSSL_OP_ASYM_CIPHER:
        return p_scossl_asym_cipher;
    }

    return NULL;
}

static const OSSL_DISPATCH p_scossl_base_dispatch[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_scossl_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))p_scossl_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p_scossl_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_scossl_query_operation},
    {0, NULL}};

SCOSSL_STATUS OSSL_provider_init(_In_ const OSSL_CORE_HANDLE *handle,
                                 _In_ const OSSL_DISPATCH *in,
                                 _Out_ const OSSL_DISPATCH **out,
                                 _Out_ void **provctx)
{
    SCOSSL_PROVCTX *p_ctx = OPENSSL_malloc(sizeof(SCOSSL_PROVCTX));
    if (p_ctx != NULL)
    {
        p_ctx->handle = handle;
        *provctx = p_ctx;
    }

    *out = p_scossl_base_dispatch;

    if (!scossl_prov_initialized)
    {
        SYMCRYPT_MODULE_INIT();
        scossl_prov_initialized = 1;
    }

    scossl_setup_logging();

    for (; in->function_id != 0; in++)
    {
        switch(in->function_id)
        {
            case OSSL_FUNC_CRYPTO_MALLOC:
                c_CRYPTO_malloc = OSSL_FUNC_CRYPTO_malloc(in);
                break;
            case OSSL_FUNC_CRYPTO_ZALLOC:
                c_CRYPTO_zalloc = OSSL_FUNC_CRYPTO_zalloc(in);
                break;
            case OSSL_FUNC_CRYPTO_FREE:
                c_CRYPTO_free = OSSL_FUNC_CRYPTO_free(in);
                break;
            case OSSL_FUNC_CRYPTO_CLEAR_FREE:
                c_CRYPTO_clear_free = OSSL_FUNC_CRYPTO_clear_free(in);
                break;
        }
    }

    return SCOSSL_SUCCESS;
}

// Functions from in dispatch table
void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_malloc(num, file, line);
}
void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_zalloc(num, file, line);
}
void CRYPTO_free(void *ptr, const char *file, int line)
{
    return c_CRYPTO_free(ptr, file, line);
}
void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)
{
    return c_CRYPTO_clear_free(ptr, num, file, line);
}

#ifdef __cplusplus
}
#endif