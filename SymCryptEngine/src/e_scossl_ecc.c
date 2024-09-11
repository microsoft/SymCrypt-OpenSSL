//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_ecc.h"
#include "e_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*PFN_eckey_sign)(
                            int type, const unsigned char* dgst, int dlen,
                            unsigned char* sig, unsigned int* siglen,
                            const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey);
typedef int (*PFN_eckey_sign_setup)(
                            EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp,
                            BIGNUM** rp);
typedef ECDSA_SIG* (*PFN_eckey_sign_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const BIGNUM* in_kinv, const BIGNUM* in_r,
                            EC_KEY* eckey);
typedef int (*PFN_eckey_verify)(
                            int type, const unsigned char* dgst, int dgst_len,
                            const unsigned char* sigbuf, int sig_len, EC_KEY* eckey);
typedef int (*PFN_eckey_verify_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const ECDSA_SIG* sig, EC_KEY* eckey);

typedef int (*PFN_eckey_keygen)(EC_KEY *key);
typedef int (*PFN_eckey_compute_key)(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh);

typedef struct _SCOSSL_ECC_KEY_CONTEXT {
    int initialized;
    PSYMCRYPT_ECKEY key;
} SCOSSL_ECC_KEY_CONTEXT;

int e_scossl_eckey_idx = -1;

// Largest supported curve is P521 => 66 * 2 byte Public key
#define SCOSSL_ECDH_MAX_PUBLIC_KEY_LEN (132)

void e_scossl_ecc_free_key_context(_Inout_ SCOSSL_ECC_KEY_CONTEXT *keyCtx)
{
    keyCtx->initialized = 0;
    if( keyCtx->key )
    {
        SymCryptEckeyFree(keyCtx->key);
    }
    return;
}

void e_scossl_eckey_finish(_Inout_ EC_KEY *key)
{
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = EC_KEY_get_ex_data(key, e_scossl_eckey_idx);
    if( keyCtx )
    {
        if( keyCtx->initialized == 1 )
        {
            e_scossl_ecc_free_key_context(keyCtx);
        }
        OPENSSL_free(keyCtx);
        EC_KEY_set_ex_data(key, e_scossl_eckey_idx, NULL);
    }
}

// Generates a new keypair using pCurve, storing the new keypair in eckey and pKeyCtx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_ecc_generate_keypair(_Inout_ SCOSSL_ECC_KEY_CONTEXT* pKeyCtx, _In_ PCSYMCRYPT_ECURVE pCurve,
                                        _In_ const EC_GROUP* ecgroup, _Inout_ EC_KEY* eckey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    BIGNUM*   ec_privkey = NULL;
    EC_POINT* ec_pubkey = NULL;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;

    int res = SCOSSL_FAILURE;

    pKeyCtx->key = SymCryptEckeyAllocate(pCurve);
    if( pKeyCtx->key == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyAllocate returned NULL.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptEckeySizeofPrivateKey(pKeyCtx->key);
    cbPublicKey = SymCryptEckeySizeofPublicKey(pKeyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL.");
        goto cleanup;
    }

    scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pKeyCtx->key );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeySetRandom failed", scError);
        goto cleanup;
    }

    pbPrivateKey = pbData;
    pbPublicKey = pbData + cbPrivateKey;

    scError = SymCryptEckeyGetValue(
        pKeyCtx->key,
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0 );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyGetValue failed", scError);
        goto cleanup;
    }

    if( (bn_ctx = BN_CTX_new()) == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_CTX_new returned NULL.");
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);

    if( ((ec_privkey = BN_secure_new()) == NULL) ||
        ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if( (ec_pubkey = EC_POINT_new(ecgroup)) == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "EC_POINT_new returned NULL.");
        goto cleanup;
    }

    if( (BN_bin2bn(pbPrivateKey, cbPrivateKey, ec_privkey) == NULL) ||
        (BN_bin2bn(pbPublicKey, cbPublicKey/2, ec_pub_x) == NULL) ||
        (BN_bin2bn(pbPublicKey + (cbPublicKey/2), cbPublicKey/2, ec_pub_y) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_bin2bn failed.");
        goto cleanup;
    }

    if( EC_KEY_set_private_key(eckey, ec_privkey) == 0)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_KEY_set_private_key failed.");
        goto cleanup;
    }

    if( EC_POINT_set_affine_coordinates(ecgroup, ec_pubkey, ec_pub_x, ec_pub_y, bn_ctx) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_POINT_set_affine_coordinates failed.");
        goto cleanup;

    }
    if( EC_KEY_set_public_key(eckey, ec_pubkey) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_KEY_set_public_key failed.");
        goto cleanup;
    }

    pKeyCtx->initialized = 1;
    res = SCOSSL_SUCCESS;

cleanup:
    if( res != SCOSSL_SUCCESS )
    {
        // On error free the partially constructed key context
        e_scossl_ecc_free_key_context(pKeyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    // Always free the temporary BIGNUMs, EC_POINT, and BN_CTX
    BN_clear_free(ec_privkey);
    EC_POINT_free(ec_pubkey);
    BN_free(ec_pub_x);
    BN_free(ec_pub_y);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return res;
}

// Imports key using eckey, ecgroup, and pCurve into pKeyCtx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_ecc_import_keypair(_In_ const EC_KEY* eckey, _In_ const EC_GROUP* ecgroup,
                                        _Inout_ SCOSSL_ECC_KEY_CONTEXT* pKeyCtx, _In_ PCSYMCRYPT_ECURVE pCurve)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    const BIGNUM*   ec_privkey = NULL;
    const EC_POINT* ec_pubkey = NULL;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;

    int res = SCOSSL_FAILURE;

    pKeyCtx->key = SymCryptEckeyAllocate(pCurve);
    if( pKeyCtx->key == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyAllocate returned NULL.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptEckeySizeofPrivateKey(pKeyCtx->key);
    cbPublicKey = SymCryptEckeySizeofPublicKey(pKeyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

    ec_privkey = EC_KEY_get0_private_key(eckey);
    ec_pubkey = EC_KEY_get0_public_key(eckey);

    if( ec_pubkey == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_KEY_get0_public_key returned NULL.");
        goto cleanup;
    }

    if( ec_privkey == NULL )
    {
        cbPrivateKey = 0;
    }

    if( (bn_ctx = BN_CTX_new()) == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_CTX_new returned NULL.");
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);

    if( ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if( EC_POINT_get_affine_coordinates(ecgroup, ec_pubkey, ec_pub_x, ec_pub_y, bn_ctx) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "EC_POINT_get_affine_coordinates failed.");
        goto cleanup;
    }

    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL.");
        goto cleanup;
    }

    if( cbPrivateKey != 0 )
    {
        pbPrivateKey = pbData;
        if( (SIZE_T) BN_bn2binpad(ec_privkey, pbPrivateKey, cbPrivateKey) != cbPrivateKey )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
                "BN_bn2binpad did not write expected number of private key bytes.");
            goto cleanup;
        }
    }

    pbPublicKey = pbData + cbPrivateKey;
    if( ((SIZE_T) BN_bn2binpad(ec_pub_x, pbPublicKey, cbPublicKey/2) != cbPublicKey/2) ||
        ((SIZE_T) BN_bn2binpad(ec_pub_y, pbPublicKey + (cbPublicKey/2), cbPublicKey/2) != cbPublicKey/2) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_bn2binpad did not write expected number of public key bytes.");
        goto cleanup;
    }

    scError = SymCryptEckeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH,
        pKeyCtx->key );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECC_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeySetValue failed", scError);
        goto cleanup;
    }

    pKeyCtx->initialized = 1;
    res = SCOSSL_SUCCESS;

cleanup:
    if( res != SCOSSL_SUCCESS )
    {
        // On error free the partially constructed key context
        e_scossl_ecc_free_key_context(pKeyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    // Always free the temporary BIGNUMs and BN_CTX
    BN_free(ec_pub_x);
    BN_free(ec_pub_y);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return res;
}

SCOSSL_STATUS e_scossl_ecc_init_static()
{
    return scossl_ecc_init_static();
}

// returns SCOSSL_FALLBACK when the eckey is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_ECC_KEY_CONTEXT on success
SCOSSL_STATUS e_scossl_get_ecc_context_ex(_Inout_ EC_KEY* eckey, _Out_ SCOSSL_ECC_KEY_CONTEXT** ppKeyCtx, BOOL generate)
{
    const EC_GROUP* ecgroup = EC_KEY_get0_group(eckey);

    PCSYMCRYPT_ECURVE pCurve = scossl_ecc_group_to_symcrypt_curve(ecgroup);

    if( pCurve == NULL )
    {
        return SCOSSL_FALLBACK;
    }

    *ppKeyCtx = (SCOSSL_ECC_KEY_CONTEXT*) EC_KEY_get_ex_data(eckey, e_scossl_eckey_idx);

    if( *ppKeyCtx == NULL )
    {
        SCOSSL_ECC_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
        if( !keyCtx )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_GET_ECC_CONTEXT_EX, ERR_R_MALLOC_FAILURE,
                "OPENSSL_zalloc failed");
            return SCOSSL_FAILURE;
        }

        if( EC_KEY_set_ex_data(eckey, e_scossl_eckey_idx, keyCtx) == 0)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_GET_ECC_CONTEXT_EX, ERR_R_OPERATION_FAIL,
                "EC_KEY_set_ex_data failed");
            OPENSSL_free(keyCtx);
            return SCOSSL_FAILURE;
        }

        *ppKeyCtx = keyCtx;
    }

    // If we are asked to generate a key - make sure to free any existing key
    if( generate )
    {
        e_scossl_ecc_free_key_context(*ppKeyCtx);
    }

    if( (*ppKeyCtx)->initialized == 1 )
    {
        return SCOSSL_SUCCESS;
    }

    if( generate )
    {
        return e_scossl_ecc_generate_keypair(*ppKeyCtx, pCurve, ecgroup, eckey);
    }
    else
    {
        return e_scossl_ecc_import_keypair(eckey, ecgroup, *ppKeyCtx, pCurve);
    }
}

// returns SCOSSL_FALLBACK when the eckey is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_ECC_KEY_CONTEXT on success
SCOSSL_STATUS e_scossl_get_ecc_context(_Inout_ EC_KEY* eckey, _Out_ SCOSSL_ECC_KEY_CONTEXT** ppKeyCtx)
{
    return e_scossl_get_ecc_context_ex(eckey, ppKeyCtx, FALSE);
}

SCOSSL_STATUS e_scossl_eckey_sign(int type,
                        _In_reads_bytes_(dlen) const unsigned char* dgst,
                        int dlen,
                        _Out_writes_bytes_(*siglen) unsigned char* sig,
                        _Out_ unsigned int* siglen,
                        _In_opt_ const BIGNUM* kinv,
                        _In_opt_ const BIGNUM* r,
                        _In_ EC_KEY* eckey)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;

    switch( e_scossl_get_ecc_context(eckey, &keyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign pfn_eckey_sign = NULL;
        EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
        if( !pfn_eckey_sign )
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return SCOSSL_FAILURE;
    }

    // SymCrypt does not support taking kinv or r parameters. Fallback to OpenSSL.
    if( kinv != NULL || r != NULL )
    {
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_ENG_ECKEY_SIGN, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "SymCrypt engine does not yet support explicit setting kinv or r parameters. Falling back to OpenSSL");
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign pfn_eckey_sign = NULL;
        EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
        if( !pfn_eckey_sign )
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
    }

    return scossl_ecdsa_sign(keyCtx->key, keyCtx->key->pCurve, dgst, dlen, sig, siglen);
}

SCOSSL_STATUS e_scossl_eckey_sign_setup(_In_ EC_KEY* eckey, _In_ BN_CTX* ctx_in, _Out_ BIGNUM** kinvp, _Out_ BIGNUM** rp)
{
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign_setup pfn_eckey_sign_setup = NULL;

    switch( e_scossl_get_ecc_context(eckey, &keyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SETUP, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
    case SCOSSL_SUCCESS:
        SCOSSL_LOG_INFO(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SETUP, SCOSSL_ERR_R_OPENSSL_FALLBACK,
            "SymCrypt engine does not yet support explicit getting kinv or r parameters. Falling back to OpenSSL");
        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, &pfn_eckey_sign_setup, NULL);
        if( !pfn_eckey_sign_setup )
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_sign_setup(eckey, ctx_in, kinvp, rp);
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SETUP, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return SCOSSL_FAILURE;
    }
}

ECDSA_SIG* e_scossl_eckey_sign_sig(_In_reads_bytes_(dgstlen) const unsigned char* dgst, int dgst_len,
                                   _In_opt_ const BIGNUM* in_kinv, _In_opt_ const BIGNUM* in_r,
                                   _In_ EC_KEY* eckey)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;
    ECDSA_SIG* returnSignature = NULL;
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;
    BYTE buf[SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    switch( e_scossl_get_ecc_context(eckey, &keyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return NULL;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign_sig pfn_eckey_sign_sig = NULL;
        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, NULL, &pfn_eckey_sign_sig);
        if( !pfn_eckey_sign_sig )
        {
            return NULL;
        }
        return pfn_eckey_sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return NULL;
    }

    scError = SymCryptEckeyExtendKeyUsage(keyCtx->key, SYMCRYPT_FLAG_ECKEY_ECDSA);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyExtendKeyUsage failed", scError);
        return NULL;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );
    scError = SymCryptEcDsaSign(
        keyCtx->key,
        dgst,
        dgst_len,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        buf,
        cbSymCryptSig);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEcDsaSign failed", scError);
        return NULL;
    }

    returnSignature = ECDSA_SIG_new();
    if( returnSignature == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, ERR_R_MALLOC_FAILURE,
            "ECDSA_SIG_new returned NULL.");
        return NULL;
    }

    if( ((r = BN_new()) == NULL) ||
        ((s = BN_new()) == NULL) )
    {
        BN_free(r);
        BN_free(s);
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        return NULL;
    }

    if( (BN_bin2bn(buf, cbSymCryptSig/2, r) == NULL) ||
        (BN_bin2bn(buf + cbSymCryptSig/2, cbSymCryptSig/2, s) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_SIGN_SIG, ERR_R_OPERATION_FAIL,
            "BN_bin2bn failed.");
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    if( ECDSA_SIG_set0(returnSignature, r, s) == 0 )
    {
        if( returnSignature == NULL )
        {
            BN_free(r);
            BN_free(s);
        }
        else
        {
            ECDSA_SIG_free(returnSignature);
        }
        return NULL;
    }

    return returnSignature;
}

SCOSSL_STATUS e_scossl_eckey_verify(int type, _In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len,
                          _In_reads_bytes_(sig_len) const unsigned char* sigbuf, int sig_len, _In_ EC_KEY* eckey)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;

    switch( e_scossl_get_ecc_context(eckey, &keyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_VERIFY, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_verify pfn_eckey_verify = NULL;
        EC_KEY_METHOD_get_verify(ossl_eckey_method, &pfn_eckey_verify, NULL);
        if (!pfn_eckey_verify)
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_verify(type, dgst, dgst_len, sigbuf, sig_len, eckey);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_VERIFY, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return SCOSSL_FAILURE;
    }

    return scossl_ecdsa_verify(keyCtx->key, keyCtx->key->pCurve, dgst, dgst_len, sigbuf, sig_len);
}

SCOSSL_STATUS e_scossl_eckey_verify_sig(_In_reads_bytes_(dgst_len) const unsigned char* dgst, int dgst_len,
                              _In_ const ECDSA_SIG* sig, _In_ EC_KEY* eckey)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SCOSSL_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;

    switch( e_scossl_get_ecc_context(eckey, &keyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_VERIFY_SIG, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_verify_sig pfn_eckey_verify_sig = NULL;
        EC_KEY_METHOD_get_verify(ossl_eckey_method, NULL, &pfn_eckey_verify_sig);
        if (!pfn_eckey_verify_sig)
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_verify_sig(dgst, dgst_len, sig, eckey);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_VERIFY_SIG, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return SCOSSL_FAILURE;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );

    ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, buf, cbSymCryptSig/2);
    BN_bn2binpad(s, buf + (cbSymCryptSig/2), cbSymCryptSig/2);

    scError = SymCryptEcDsaVerify(
        keyCtx->key,
        dgst,
        dgst_len,
        buf,
        cbSymCryptSig,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0);
    if( scError != SYMCRYPT_NO_ERROR )
    {
        if( scError != SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE )
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECKEY_VERIFY_SIG, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptEcDsaVerify returned unexpected error", scError);
        }
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS e_scossl_eckey_keygen(_Inout_ EC_KEY *key)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;

    switch( e_scossl_get_ecc_context_ex(key, &keyCtx, TRUE) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_KEYGEN, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context_ex failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_keygen pfn_eckey_keygen = NULL;
        EC_KEY_METHOD_get_keygen(ossl_eckey_method, &pfn_eckey_keygen);
        if (!pfn_eckey_keygen)
        {
            return SCOSSL_FAILURE;
        }
        return pfn_eckey_keygen(key);
    case SCOSSL_SUCCESS:
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_KEYGEN, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context_ex value");
        return SCOSSL_FAILURE;
    }
}

SCOSSL_RETURNLENGTH e_scossl_eckey_compute_key(_Out_writes_bytes_(*pseclen) unsigned char **psec,
                                                _Out_ size_t *pseclen,
                                                _In_ const EC_POINT *pub_key,
                                                _In_ const EC_KEY *ecdh)
{
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SCOSSL_ECDH_MAX_PUBLIC_KEY_LEN] = { 0 };

    const EC_GROUP* ecgroup = NULL;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;
    UINT32 cbPublicKey = 0;
    PSYMCRYPT_ECKEY pkPublic = NULL;

    int res = -1; // fail

    switch( e_scossl_get_ecc_context((EC_KEY*)ecdh, &keyCtx) ) // removing const cast as code path in this instance will not alter ecdh. TODO: refactor e_scossl_get_ecc_context
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "e_scossl_get_ecc_context failed.");
        return -1;
    case SCOSSL_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_compute_key pfn_eckey_compute_key = NULL;
        EC_KEY_METHOD_get_compute_key(ossl_eckey_method, &pfn_eckey_compute_key);
        if( !pfn_eckey_compute_key )
        {
            return -1;
        }
        return pfn_eckey_compute_key(psec, pseclen, pub_key, ecdh);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_INTERNAL_ERROR,
            "Unexpected e_scossl_get_ecc_context value");
        return -1;
    }

    ecgroup = EC_KEY_get0_group(ecdh);
    if( ecgroup == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "EC_KEY_get0_group returned NULL.");
        goto cleanup;
    }

    cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
    pkPublic = SymCryptEckeyAllocate(keyCtx->key->pCurve);
    if( pkPublic == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeyAllocate returned NULL.");
        goto cleanup;
    }

    if( (bn_ctx = BN_CTX_new()) == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "BN_CTX_new returned NULL.");
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);

    if( ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if( EC_POINT_get_affine_coordinates(ecgroup, pub_key, ec_pub_x, ec_pub_y, bn_ctx) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "EC_POINT_get_affine_coordinates failed.");
        goto cleanup;
    }

    if( (BN_bn2binpad(ec_pub_x, buf, cbPublicKey/2) != (int) cbPublicKey/2) ||
        (BN_bn2binpad(ec_pub_y, buf + (cbPublicKey/2), cbPublicKey/2) != (int) cbPublicKey/2) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "BN_bn2binpad did not write expected number of public key bytes.");
        goto cleanup;
    }

    scError = SymCryptEckeySetValue(
        NULL, 0,
        buf, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDH,
        pkPublic );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEckeySetValue failed", scError);
        goto cleanup;
    }

    *pseclen = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    *psec = OPENSSL_zalloc(*pseclen);
    if( *psec == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc failed");
        goto cleanup;
    }

    scError = SymCryptEcDhSecretAgreement(
        keyCtx->key,
        pkPublic,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        *psec,
        *pseclen );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_ENG_ECKEY_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptEcDhSecretAgreement failed", scError);
        goto cleanup;
    }

    res = *pseclen;

cleanup:

    if (res == -1)
    {
        if( *psec )
        {
            OPENSSL_free(*psec);
            *psec = NULL;
        }
        *pseclen = 0;
    }

    // Always free the temporary pkPublic, BIGNUMs and BN_CTX
    if( pkPublic )
    {
        SymCryptEckeyFree(pkPublic);
    }
    BN_free(ec_pub_x);
    BN_free(ec_pub_y);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return res;
}

void e_scossl_destroy_ecc_curves(void)
{
    scossl_ecc_destroy_ecc_curves();
}

#ifdef __cplusplus
}
#endif
