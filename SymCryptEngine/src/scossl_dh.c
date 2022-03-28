//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

int scossl_dh_idx = -1;

// Largest supported safe-prime group is 4096b => 512 byte Public key
#define SCOSSL_DH_MAX_PUBLIC_KEY_LEN (512)

typedef int (*PFN_DH_meth_generate_key) (DH*);
typedef int (*PFN_DH_meth_compute_key)(unsigned char* key, const BIGNUM* pub_key, DH* dh);
typedef int (*PFN_DH_meth_bn_mod_exp)(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
typedef int (*PFN_DH_meth_init)(DH* dh);
typedef int (*PFN_DH_meth_finish)(DH* dh);

typedef struct _SCOSSL_DH_KEY_CONTEXT {
    int initialized;
    PSYMCRYPT_DLKEY dlkey;
} SCOSSL_DH_KEY_CONTEXT;
typedef       SCOSSL_DH_KEY_CONTEXT * PSCOSSL_DH_KEY_CONTEXT;

void scossl_dh_free_key_context(_Inout_ PSCOSSL_DH_KEY_CONTEXT pKeyCtx)
{
    pKeyCtx->initialized = 0;
    if( pKeyCtx->dlkey )
    {
        SymCryptDlkeyFree(pKeyCtx->dlkey);
    }
    return;
}

static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp4096 = NULL;
static BIGNUM* _hidden_bignum_modp2048 = NULL;
static BIGNUM* _hidden_bignum_modp3072 = NULL;
static BIGNUM* _hidden_bignum_modp4096 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe4096 = NULL;

// Generates a new keypair using pDlgroup, storing the new keypair in dh and pKeyCtx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS scossl_dh_generate_keypair(
    _Inout_ PSCOSSL_DH_KEY_CONTEXT pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup, _Inout_ DH* dh)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    UINT32 nBitsPriv = 0;

    BIGNUM* dh_privkey = NULL;
    BIGNUM* dh_pubkey = NULL;

    int res = SCOSSL_FAILURE;

    pKeyCtx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if( pKeyCtx->dlkey == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pKeyCtx->dlkey);
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);

    nBitsPriv = DH_get_length(dh);
    if( nBitsPriv != 0 )
    {
        scError = SymCryptDlkeySetPrivateKeyLength( pKeyCtx->dlkey, nBitsPriv, 0 );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptDlkeySetPrivateKeyLength failed", scError);
            goto cleanup;
        }
    }

    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL.");
        goto cleanup;
    }

    scError = SymCryptDlkeyGenerate(
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION | SYMCRYPT_FLAG_DLKEY_SELFTEST_DH,
        pKeyCtx->dlkey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeyGenerate failed", scError);
        goto cleanup;
    }

    pbPrivateKey = pbData;
    pbPublicKey = pbData + cbPrivateKey;

    scError = SymCryptDlkeyGetValue(
        pKeyCtx->dlkey,
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0 );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeyGetValue failed", scError);
        goto cleanup;
    }

    if( ((dh_privkey = BN_secure_new()) == NULL) ||
        ((dh_pubkey = BN_new()) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "BN_new returned NULL.");
        goto cleanup;
    }

    if( (BN_bin2bn(pbPrivateKey, cbPrivateKey, dh_privkey) == NULL) ||
        (BN_bin2bn(pbPublicKey, cbPublicKey, dh_pubkey) == NULL) )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "BN_bin2bn failed.");
        goto cleanup;
    }

    if( DH_set0_key(dh, dh_pubkey, dh_privkey) == 0 )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, ERR_R_OPERATION_FAIL,
            "DH_set0_key failed.");
        goto cleanup;
    }
    // Do not free the temporary BIGNUMs now, as DH manages them after success
    dh_privkey = NULL;
    dh_pubkey = NULL;

    pKeyCtx->initialized = 1;
    res = SCOSSL_SUCCESS;

cleanup:
    if( res != SCOSSL_SUCCESS )
    {
        // On error free the partially constructed key context
        scossl_dh_free_key_context(pKeyCtx);
    }

    BN_clear_free(dh_privkey);
    BN_free(dh_pubkey);

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return res;
}

// Imports key using dh and dlGroup, into pKeyCtx.
// Also populates the public key of dh if it only currently has a private key specified.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS scossl_dh_import_keypair(
    _Inout_ DH* dh, _Inout_ PSCOSSL_DH_KEY_CONTEXT pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    UINT32 nBitsPriv = 0;

    const BIGNUM*   dh_privkey = NULL;
    const BIGNUM*   dh_pubkey = NULL;
    BIGNUM*   generated_dh_pubkey = NULL;

    int res = SCOSSL_FAILURE;

    pKeyCtx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if( pKeyCtx->dlkey == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    nBitsPriv = DH_get_length(dh);
    if( nBitsPriv != 0 )
    {
        scError = SymCryptDlkeySetPrivateKeyLength( pKeyCtx->dlkey, nBitsPriv, 0 );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptDlkeySetPrivateKeyLength failed", scError);
            goto cleanup;
        }
    }

    DH_get0_key(dh, &dh_pubkey, &dh_privkey);

    if( dh_pubkey == NULL && dh_privkey == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
            "DH_get0_key returned NULL for public and private key.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pKeyCtx->dlkey);
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
    // For simplicity, always allocate enough space for a private key and a public key, even if we may only use one
    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL.");
        goto cleanup;
    }

    if( dh_pubkey == NULL )
    {
        cbPublicKey = 0;
    }
    if( dh_privkey == NULL )
    {
        cbPrivateKey = 0;
    }

    if( cbPrivateKey != 0 )
    {
        pbPrivateKey = pbData;
        if( (SIZE_T) BN_bn2binpad(dh_privkey, pbPrivateKey, cbPrivateKey) != cbPrivateKey )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
                "BN_bn2binpad did not write expected number of private key bytes.");
            goto cleanup;
        }
    }
    if( cbPublicKey != 0 )
    {
        pbPublicKey = pbData + cbPrivateKey;
        if( (SIZE_T) BN_bn2binpad(dh_pubkey, pbPublicKey, cbPublicKey) != cbPublicKey )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
                "BN_bn2binpad did not write expected number of public key bytes.");
            goto cleanup;
        }
    }

    scError = SymCryptDlkeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION | SYMCRYPT_FLAG_KEY_KEYPAIR_REGENERATION_VALIDATION | SYMCRYPT_FLAG_DLKEY_SELFTEST_DH,
        pKeyCtx->dlkey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeySetValue failed", scError);
        goto cleanup;
    }

    // If the dh object we are importing from only had a private key, populate the public key with
    // the value we just generated in SymCrypt
    if( cbPublicKey == 0 )
    {
        cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
        pbPublicKey = pbData + cbPrivateKey;

        scError = SymCryptDlkeyGetValue(
            pKeyCtx->dlkey,
            NULL, 0,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0 );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptDlkeyGetValue failed", scError);
            goto cleanup;
        }

        if( (generated_dh_pubkey = BN_new()) == NULL )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
                "BN_new returned NULL.");
            goto cleanup;
        }

        if( BN_bin2bn(pbPublicKey, cbPublicKey, generated_dh_pubkey) == NULL )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
                "BN_bin2bn failed.");
            goto cleanup;
        }

        if( DH_set0_key(dh, generated_dh_pubkey, NULL) == 0 )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_OPERATION_FAIL,
                "DH_set0_key failed.");
            goto cleanup;
        }
        // Do not free the temporary BIGNUM now, as DH manages it after success
        generated_dh_pubkey = NULL;
    }

    pKeyCtx->initialized = 1;
    res = SCOSSL_SUCCESS;

cleanup:
    if( res != SCOSSL_SUCCESS )
    {
        // On error free the partially constructed key context
        scossl_dh_free_key_context(pKeyCtx);
    }

    BN_free(generated_dh_pubkey);

    if( pbData )
    {
        OPENSSL_clear_free( pbData, cbData );
    }

    return res;
}

PSYMCRYPT_DLGROUP scossl_initialize_safeprime_dlgroup(_Inout_ PSYMCRYPT_DLGROUP* ppDlgroup,
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE dhSafePrimeType, UINT32 nBitsOfP )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    *ppDlgroup = SymCryptDlgroupAllocate( nBitsOfP, nBitsOfP-1 );
    if( *ppDlgroup == NULL )
    {
        goto cleanup;
    }

    scError = SymCryptDlgroupSetValueSafePrime(dhSafePrimeType, *ppDlgroup);

cleanup:
    if( *ppDlgroup != NULL && scError != SYMCRYPT_NO_ERROR )
    {
        SymCryptDlgroupFree(*ppDlgroup);
        *ppDlgroup = NULL;
    }
    return *ppDlgroup;
}

SCOSSL_STATUS scossl_dh_init_static()
{
    if( (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe2048, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 2048 ) == NULL) ||
        (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe3072, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 3072 ) == NULL) ||
        (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe4096, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 4096 ) == NULL) ||
        (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp2048, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 2048 ) == NULL) ||
        (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp3072, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 3072 ) == NULL) ||
        (scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp4096, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 4096 ) == NULL) ||
        ((_hidden_bignum_modp2048 = BN_get_rfc3526_prime_2048(NULL)) == NULL) ||
        ((_hidden_bignum_modp3072 = BN_get_rfc3526_prime_3072(NULL)) == NULL) ||
        ((_hidden_bignum_modp4096 = BN_get_rfc3526_prime_4096(NULL)) == NULL) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

// returns SCOSSL_FALLBACK when the dh is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS scossl_get_dh_context_ex(_Inout_ DH* dh, _Out_ PSCOSSL_DH_KEY_CONTEXT* ppKeyCtx, BOOL generate)
{
    PSYMCRYPT_DLGROUP pDlgroup = NULL;

    const BIGNUM* p = NULL;
    const BIGNUM* g = NULL;
    const BIGNUM* dh_privkey = NULL;

    DH_get0_pqg(dh, &p, NULL, &g);

    // All named safe-prime groups supported by SCOSSL have a generator of 2
    if( !BN_is_word( g, 2 ) )
    {
        return SCOSSL_FALLBACK;
    }

    // OpenSSL is a bit inconsistent with how it handles different named safe-prime groups
    // We can get OpenSSL to return a nid for ffdhe groups we support
    int dlgroupNid = DH_get_nid(dh);

    switch( dlgroupNid )
    {
    case NID_ffdhe2048:
        pDlgroup = _hidden_dlgroup_ffdhe2048;
        break;
    case NID_ffdhe3072:
        pDlgroup = _hidden_dlgroup_ffdhe3072;
        break;
    case NID_ffdhe4096:
        pDlgroup = _hidden_dlgroup_ffdhe4096;
        break;
    default:
        // Not one of the supported ffdhe groups, but may still be a supported MODP group
        // Given we know the generator is 2, we can now check whether P corresponds to a MODP group
        if( BN_cmp( p, _hidden_bignum_modp2048 ) == 0 )
        {
            pDlgroup = _hidden_dlgroup_modp2048;
            break;
        }
        else if( BN_cmp( p, _hidden_bignum_modp3072 ) == 0 )
        {
            pDlgroup = _hidden_dlgroup_modp3072;
        }
        else if( BN_cmp( p, _hidden_bignum_modp4096 ) == 0 )
        {
            pDlgroup = _hidden_dlgroup_modp4096;
        }
        else
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                "SymCrypt engine does not support this DH dlgroup - falling back to OpenSSL.");
            return SCOSSL_FALLBACK; // <-- early return
        }
        break;
    }

    if( pDlgroup == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, ERR_R_INTERNAL_ERROR,
            "_hidden_dlgroup_* is NULL.");
        return SCOSSL_FAILURE;
    }

    *ppKeyCtx = (PSCOSSL_DH_KEY_CONTEXT) DH_get_ex_data(dh, scossl_dh_idx);

    if( *ppKeyCtx == NULL )
    {
        PSCOSSL_DH_KEY_CONTEXT pKeyCtx = OPENSSL_zalloc(sizeof(*pKeyCtx));
        if( !pKeyCtx )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, ERR_R_MALLOC_FAILURE,
                "OPENSSL_zalloc failed");
            return SCOSSL_FAILURE;
        }

        if( DH_set_ex_data(dh, scossl_dh_idx, pKeyCtx) == 0)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, ERR_R_OPERATION_FAIL,
                "DH_set_ex_data failed");
            OPENSSL_free(pKeyCtx);
            return SCOSSL_FAILURE;
        }

        *ppKeyCtx = pKeyCtx;
    }

    if( (*ppKeyCtx)->initialized == 1 )
    {
        return SCOSSL_SUCCESS;
    }

    // In DH it is valid for caller to set the private key then call generate to "generate" the public key
    // This is handled as an import in SymCrypt
    DH_get0_key(dh, NULL, &dh_privkey);

    if( generate && (dh_privkey == NULL) )
    {
        return scossl_dh_generate_keypair(*ppKeyCtx, pDlgroup, dh);
    }
    else
    {
        return scossl_dh_import_keypair(dh, *ppKeyCtx, pDlgroup);
    }
}

// returns SCOSSL_FALLBACK when the dh is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS scossl_get_dh_context(_Inout_ DH* dh, _Out_ PSCOSSL_DH_KEY_CONTEXT* ppKeyCtx)
{
    return scossl_get_dh_context_ex(dh, ppKeyCtx, FALSE);
}

SCOSSL_STATUS scossl_dh_generate_key(_Inout_ DH* dh)
{
    PFN_DH_meth_generate_key pfn_dh_meth_generate_key = NULL;
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = NULL;

    switch( scossl_get_dh_context_ex(dh, &pKeyCtx, TRUE) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEY, ERR_R_OPERATION_FAIL,
            "scossl_get_dh_context_ex failed.");
        return SCOSSL_FAILURE;
    case SCOSSL_FALLBACK:
        pfn_dh_meth_generate_key = DH_meth_get_generate_key(DH_OpenSSL());
        if (pfn_dh_meth_generate_key == NULL)
        {
            return SCOSSL_FAILURE;
        }
        return pfn_dh_meth_generate_key(dh);
    case SCOSSL_SUCCESS:
        return SCOSSL_SUCCESS;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR,
            "Unexpected scossl_get_dh_context_ex value");
        return SCOSSL_FAILURE;
    }
}

SCOSSL_RETURNLENGTH scossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key,
                                            _In_ const BIGNUM* pub_key,
                                            _In_ DH* dh)
{
    PFN_DH_meth_compute_key pfn_dh_meth_compute_key = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = NULL;
    BYTE buf[SCOSSL_DH_MAX_PUBLIC_KEY_LEN] = { 0 };

    UINT32 cbPublicKey = 0;
    PSYMCRYPT_DLKEY pkPublic = NULL;

    int res = -1; // fail

    switch( scossl_get_dh_context(dh, &pKeyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "scossl_get_dh_context failed.");
        return res;
    case SCOSSL_FALLBACK:
        pfn_dh_meth_compute_key = DH_meth_get_compute_key(DH_OpenSSL());
        if (pfn_dh_meth_compute_key == NULL)
        {
            return res;
        }
        return pfn_dh_meth_compute_key(key, pub_key, dh);
    case SCOSSL_SUCCESS:
        break;
    default:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR,
            "Unexpected scossl_get_dh_context_ex value");
        return res;
    }

    // DH_size(dh) == SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey)
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
    pkPublic = SymCryptDlkeyAllocate(pKeyCtx->dlkey->pDlgroup);
    if( pkPublic == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    if( (SIZE_T) BN_bn2binpad(pub_key, buf, cbPublicKey) != cbPublicKey )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR,
            "BN_bn2binpad did not write expected number of public key bytes.");
        goto cleanup;
    }

    scError = SymCryptDlkeySetValue(
        NULL, 0,
        buf, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION | SYMCRYPT_FLAG_DLKEY_SELFTEST_DH,
        pkPublic );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDlkeySetValue failed", scError);
        goto cleanup;
    }

    scError = SymCryptDhSecretAgreement(
        pKeyCtx->dlkey,
        pkPublic,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        key,
        cbPublicKey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptDhSecretAgreement failed", scError);
        goto cleanup;
    }

    res = DH_size(dh);

cleanup:

    // Always free the temporary pkPublic
    if( pkPublic )
    {
        SymCryptDlkeyFree(pkPublic);
    }

    return res;
}

SCOSSL_STATUS scossl_dh_finish(_Inout_ DH* dh)
{
    PFN_DH_meth_finish pfn_dh_meth_finish = DH_meth_get_finish(DH_OpenSSL());
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = DH_get_ex_data(dh, scossl_dh_idx);
    if( pKeyCtx )
    {
        if( pKeyCtx->initialized == 1 )
        {
            scossl_dh_free_key_context(pKeyCtx);
        }
        OPENSSL_free(pKeyCtx);
        DH_set_ex_data(dh, scossl_dh_idx, NULL);
    }

    // Ensure any buffers initialized by DH_OpenSSL are freed
    if( pfn_dh_meth_finish == NULL )
    {
        return SCOSSL_FAILURE;
    }
    return pfn_dh_meth_finish(dh);
}

void scossl_destroy_safeprime_dlgroups(void)
{
    if( _hidden_dlgroup_ffdhe2048 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe2048);
        _hidden_dlgroup_ffdhe2048 = NULL;
    }
    if( _hidden_dlgroup_ffdhe3072 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe3072);
        _hidden_dlgroup_ffdhe3072 = NULL;
    }
    if( _hidden_dlgroup_ffdhe4096 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_ffdhe4096);
        _hidden_dlgroup_ffdhe4096 = NULL;
    }
    if( _hidden_dlgroup_modp2048 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp2048);
        _hidden_dlgroup_modp2048 = NULL;
    }
    if( _hidden_dlgroup_modp3072 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp3072);
        _hidden_dlgroup_modp3072 = NULL;
    }
    if( _hidden_dlgroup_modp4096 )
    {
        SymCryptDlgroupFree(_hidden_dlgroup_modp4096);
        _hidden_dlgroup_modp4096 = NULL;
    }
    BN_free(_hidden_bignum_modp2048);
    _hidden_bignum_modp2048 = NULL;
    BN_free(_hidden_bignum_modp3072);
    _hidden_bignum_modp3072 = NULL;
    BN_free(_hidden_bignum_modp4096);
    _hidden_bignum_modp4096 = NULL;
}

#ifdef __cplusplus
}
#endif

