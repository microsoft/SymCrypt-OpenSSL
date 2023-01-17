#include "scossl_prov_base.h"

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

#define ALG(names, funcs) {names, "provider="SCOSSL_NAME, funcs, NULL}
#define ALG_TABLE_END { NULL, NULL, NULL, NULL}

// Digest
extern const OSSL_DISPATCH scossl_prov_Md5_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha1_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha256_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha384_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha512_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha3_256_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha3_384_functions[];
extern const OSSL_DISPATCH scossl_prov_Sha3_512_functions[];

static const OSSL_ALGORITHM scossl_prov_digest[] = {
    ALG("MD5:SSL3-MD5:1.2.840.113549.2.5", scossl_prov_Md5_functions),
    ALG("SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", scossl_prov_Sha1_functions),
    ALG("SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", scossl_prov_Sha256_functions),
    ALG("SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", scossl_prov_Sha384_functions),
    ALG("SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", scossl_prov_Sha512_functions),
    ALG("SHA3-256:2.16.840.1.101.3.4.2.8", scossl_prov_Sha3_256_functions),
    ALG("SHA3-384:2.16.840.1.101.3.4.2.9", scossl_prov_Sha3_384_functions),
    ALG("SHA3-512:2.16.840.1.101.3.4.2.10", scossl_prov_Sha3_512_functions),
    ALG_TABLE_END
};

// Cipher
extern const OSSL_DISPATCH scossl_prov_aes128cbc_functions[];
extern const OSSL_DISPATCH scossl_prov_aes192cbc_functions[];
extern const OSSL_DISPATCH scossl_prov_aes256cbc_functions[];
extern const OSSL_DISPATCH scossl_prov_aes128ecb_functions[];
extern const OSSL_DISPATCH scossl_prov_aes192ecb_functions[];
extern const OSSL_DISPATCH scossl_prov_aes256ecb_functions[];
extern const OSSL_DISPATCH scossl_prov_aes128gcm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes192gcm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes256gcm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes128ccm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes192ccm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes256ccm_functions[];
extern const OSSL_DISPATCH scossl_prov_aes256xts_functions[];
extern const OSSL_DISPATCH scossl_prov_aes128xts_functions[];

static const OSSL_ALGORITHM scossl_prov_cipher[] = {
    // ALG("AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2", scossl_prov_aes128cbc_functions),
    // ALG("AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22", scossl_prov_aes192cbc_functions),
    // ALG("AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42", scossl_prov_aes256cbc_functions),
    // ALG("AES-128-ECB:2.16.840.1.101.3.4.1.1", scossl_prov_aes128ecb_functions),
    // ALG("AES-192-ECB:2.16.840.1.101.3.4.1.21", scossl_prov_aes192ecb_functions),
    // ALG("AES-256-ECB:2.16.840.1.101.3.4.1.41", scossl_prov_aes256ecb_functions),
    // ALG("AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", scossl_prov_aes128gcm_functions),
    // ALG("AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26", scossl_prov_aes192gcm_functions),
    // ALG("AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", scossl_prov_aes256gcm_functions),
    // ALG("AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7", scossl_prov_aes128ccm_functions),
    // ALG("AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27", scossl_prov_aes192ccm_functions),
    // ALG("AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47", scossl_prov_aes256ccm_functions),
    // ALG("AES-128-XTS:1.3.111.2.1619.0.1.1", scossl_prov_aes256xts_functions),
    // ALG("AES-256-XTS:1.3.111.2.1619.0.1.2", scossl_prov_aes128xts_functions),
    ALG_TABLE_END
};

// MAC
extern const OSSL_DISPATCH scossl_prov_hmac_functions[];

static const OSSL_ALGORITHM scossl_prov_mac[] = {
    // ALG("HMAC", scossl_prov_hmac_functions),
    ALG_TABLE_END
};

// KDF
extern const OSSL_DISPATCH scossl_prov_sshkdf_kdf_functions[];
extern const OSSL_DISPATCH scossl_prov_hkdf_kdf_functions[];
extern const OSSL_DISPATCH scossl_prov_tls1prf_kdf_functions[];

static const OSSL_ALGORITHM scossl_prov_kdf[] = {
    // ALG("SSHKDF", scossl_prov_sshkdf_kdf_functions),
    // ALG("HKDF", scossl_prov_hkdf_kdf_functions),
    // ALG("TLS1-PRF", scossl_prov_tls1prf_kdf_functions),
    ALG_TABLE_END
};

// Rand
extern const OSSL_DISPATCH scossl_prov_rand_functions[];

static const OSSL_ALGORITHM scossl_prov_rand[] = {
    // ALG("CTR-DRBG", scossl_prov_rand_functions),
    ALG_TABLE_END
};

// Key management
extern const OSSL_DISPATCH scossl_prov_dh_keymgmt_functions[];
extern const OSSL_DISPATCH scossl_prov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH scossl_prov_ecc_keymgmt_functions[];

static const OSSL_ALGORITHM scossl_prov_keymgmt[] = {
    // ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", scossl_prov_dh_keymgmt_functions),
    // ALG("RSA:rsaEncryption:1.2.840.113549.1.1.1:", scossl_prov_rsa_keymgmt_functions),
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", scossl_prov_rsa_keymgmt_functions),
    // ALG("EC:id-ecPublicKey:1.2.840.10045.2.1", scossl_prov_ecc_keymgmt_functions),
    ALG_TABLE_END
};

// Key exchange
extern const OSSL_DISPATCH scossl_prov_dh_functions[];
extern const OSSL_DISPATCH scossl_prov_ecdh_functions[];
extern const OSSL_DISPATCH scossl_prov_x25519_functions[];
extern const OSSL_DISPATCH scossl_prov_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH scossl_prov_tls1prf_keyexch_functions[];

static const OSSL_ALGORITHM scossl_prov_keyexch[] = {
    // ALG("DH:dhKeyAgreement:1.2.840.113549.1.3.1", scossl_prov_dh_functions),
    // ALG("ECDH", scossl_prov_ecdh_functions),
    // ALG("X25519:1.3.101.110", scossl_prov_x25519_functions),
    // ALG("HKDF", scossl_prov_hkdf_keyexch_functions),
    // ALG("TLS1-PRF", scossl_prov_tls1prf_keyexch_functions),
    ALG_TABLE_END
};

// Signature
extern const OSSL_DISPATCH scossl_prov_rsa_signature_functions[];
extern const OSSL_DISPATCH scossl_prov_ecdsa_signature_functions[];

static const OSSL_ALGORITHM scossl_prov_signature[] = {
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", scossl_prov_rsa_signature_functions),
    // ALG("EC:id-ecPublicKey:1.2.840.10045.2.1", scossl_prov_ecdsa_signature_functions),
    ALG_TABLE_END
};

// Asymmetric Cipher
extern const OSSL_DISPATCH scossl_prov_rsa_asym_cipher_functions[];

static const OSSL_ALGORITHM scossl_prov_asym_cipher[] = {
    // ALG("RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", scossl_prov_rsa_asym_cipher_functions),
    ALG_TABLE_END
};


static int scossl_prov_get_status()
{
    return 1;
}

static void scossl_prov_teardown(PSCOSSL_PROV_CTX *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *scossl_prov_gettable_params(PSCOSSL_PROV_CTX *provctx)
{
    return scossl_prov_param_types;
}

static int scossl_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SCOSSL_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, scossl_prov_get_status()))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *scossl_prov_query_operation(void *provctx, int operation_id, int *no_store)
{
    switch (operation_id)
    {
        case OSSL_OP_DIGEST:
            return scossl_prov_digest;
        case OSSL_OP_CIPHER:
            return scossl_prov_cipher;
        case OSSL_OP_MAC:
            return scossl_prov_mac;
        case OSSL_OP_KDF:
            return scossl_prov_kdf;
        case OSSL_OP_RAND:
            return scossl_prov_rand;
        case OSSL_OP_KEYMGMT:
            return scossl_prov_keymgmt;
        case OSSL_OP_KEYEXCH:
            return scossl_prov_keyexch;
        case OSSL_OP_SIGNATURE:
            return scossl_prov_signature;
        case OSSL_OP_ASYM_CIPHER:
            return scossl_prov_asym_cipher;
    }

    return NULL;
}

static const OSSL_DISPATCH scossl_prov_base_dispatch[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))scossl_prov_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))scossl_prov_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))scossl_prov_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))scossl_prov_query_operation},
    {0, NULL}};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    PSCOSSL_PROV_CTX p_ctx = OPENSSL_malloc(sizeof(SCOSSL_PROV_CTX));
    if (p_ctx != NULL)
    {
        p_ctx->handle = handle;
        *provctx = p_ctx;
    }

    *out = scossl_prov_base_dispatch;

    return 1;
}