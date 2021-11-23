//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

int dh_sc_ossl_idx = -1;

// Largest supported safe-prime group is 4096b => 512 byte Public key
#define SC_OSSL_DH_MAX_PUBLIC_KEY_LEN (512)

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

#define SC_OSSL_DH_GET_CONTEXT_FALLBACK (-1)
#define SC_OSSL_DH_GET_CONTEXT_ERROR    (0)
#define SC_OSSL_DH_GET_CONTEXT_SUCCESS  (1)

static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_modp4096 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe2048 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe3072 = NULL;
static PSYMCRYPT_DLGROUP _hidden_dlgroup_ffdhe4096 = NULL;

// Generates a new keypair using pDlgroup, storing the new keypair in dh and pKeyCtx.
// Returns SC_OSSL_DH_GET_CONTEXT_SUCCESS on success or SC_OSSL_DH_GET_CONTEXT_ERROR on error.
SCOSSL_STATUS scossl_dh_generate_keypair(
    _Inout_ PSCOSSL_DH_KEY_CONTEXT pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup, _Inout_ DH* dh)
{
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    BIGNUM* dh_privkey = NULL;
    BIGNUM* dh_pubkey = NULL;

    int res = SC_OSSL_DH_GET_CONTEXT_ERROR;

    pKeyCtx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if( pKeyCtx->dlkey == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pKeyCtx->dlkey);
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
    
    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc returned NULL.");
        goto cleanup;
    }

    symError = SymCryptDlkeyGenerate(
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION,
        pKeyCtx->dlkey );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDlkeyGenerate failed", symError);
        goto cleanup;
    }

    pbPrivateKey = pbData;
    pbPublicKey = pbData + cbPrivateKey;

    symError = SymCryptDlkeyGetValue(
        pKeyCtx->dlkey,
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0 );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDlkeyGetValue failed", symError);
        goto cleanup;
    }
    
    if( ((dh_privkey = BN_secure_new()) == NULL) ||
        ((dh_pubkey = BN_new()) == NULL) )
    {
        SC_OSSL_LOG_ERROR("BN_new returned NULL.");
        goto cleanup;
    }
    
    BN_bin2bn(pbPrivateKey, cbPrivateKey, dh_privkey);
    BN_bin2bn(pbPublicKey, cbPublicKey, dh_pubkey);

    if( DH_set0_key(dh, dh_pubkey, dh_privkey) == 0 )
    {
        SC_OSSL_LOG_ERROR("DH_set0_key failed.");
        BN_clear_free(dh_privkey);
        BN_free(dh_pubkey);
        goto cleanup;
    }
    // Do not free the temporary BIGNUMs now, as DH manages them after success

    pKeyCtx->initialized = 1;
    res = SC_OSSL_DH_GET_CONTEXT_SUCCESS;

cleanup:
    if( res != SC_OSSL_DH_GET_CONTEXT_SUCCESS )
    {
        // On error free the partially constructed key context
        scossl_dh_free_key_context(pKeyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free(pbData, cbData);
    }

    return res;
}

// Imports key using dh and dlGroup, into pKeyCtx.
// Also populates the public key of dh if it only currently has a private key specified.
// Returns SC_OSSL_DH_GET_CONTEXT_SUCCESS on success or SC_OSSL_DH_GET_CONTEXT_ERROR on error.
SCOSSL_STATUS scossl_dh_import_keypair(
    _Inout_ DH* dh, _Inout_ PSCOSSL_DH_KEY_CONTEXT pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup )
{
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    const BIGNUM*   dh_privkey = NULL;
    const BIGNUM*   dh_pubkey = NULL;
    BIGNUM*   generated_dh_pubkey = NULL;

    int res = SC_OSSL_DH_GET_CONTEXT_ERROR;

    pKeyCtx->dlkey = SymCryptDlkeyAllocate(pDlgroup);
    if( pKeyCtx->dlkey == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    DH_get0_key(dh, &dh_pubkey, &dh_privkey);

    if( dh_pubkey == NULL && dh_privkey == NULL )
    {
        SC_OSSL_LOG_ERROR("DH_get0_key returned NULL for public and private key.");
        goto cleanup;
    }

    cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pKeyCtx->dlkey);
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
    // For simplicity, always allocate enough space for a private key and a public key, even if we may only use one
    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SC_OSSL_LOG_ERROR("OPENSSL_zalloc returned NULL.");
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
        if( BN_bn2binpad(dh_privkey, pbPrivateKey, cbPrivateKey) != cbPrivateKey )
        {
            SC_OSSL_LOG_ERROR("BN_bn2binpad did not write expected number of private key bytes.");
            goto cleanup;
        }
    }
    if( cbPublicKey != 0 )
    {
        pbPublicKey = pbData + cbPrivateKey;
        if( BN_bn2binpad(dh_pubkey, pbPublicKey, cbPublicKey) != cbPublicKey )
        {
            SC_OSSL_LOG_ERROR("BN_bn2binpad did not write expected number of public key bytes.");
            goto cleanup;
        }
    }

    symError = SymCryptDlkeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION | SYMCRYPT_FLAG_KEY_KEYPAIR_REGENERATION_VALIDATION,
        pKeyCtx->dlkey );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDlkeySetValue failed", symError);
        goto cleanup;
    }

    // If the dh object we are importing from only had a private key, populate the public key with
    // the value we just generated in SymCrypt
    if( cbPublicKey == 0 )
    {
        cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
        pbPublicKey = pbData + cbPrivateKey;

        symError = SymCryptDlkeyGetValue(
            pKeyCtx->dlkey,
            NULL, 0,
            pbPublicKey, cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0 );
        if( symError != SYMCRYPT_NO_ERROR )
        {
            SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDlkeyGetValue failed", symError);
            goto cleanup;
        }
        
        if( (generated_dh_pubkey = BN_new()) == NULL )
        {
            SC_OSSL_LOG_ERROR("BN_new returned NULL.");
            goto cleanup;
        }
        
        BN_bin2bn(pbPublicKey, cbPublicKey, generated_dh_pubkey);

        if( DH_set0_key(dh, generated_dh_pubkey, NULL) == 0 )
        {
            SC_OSSL_LOG_ERROR("DH_set0_key failed.");
            BN_free(generated_dh_pubkey);
            goto cleanup;
        }
        // Do not free the temporary BIGNUM now, as DH manages them after success
    }

    pKeyCtx->initialized = 1;
    res = SC_OSSL_DH_GET_CONTEXT_SUCCESS;

cleanup:
    if( res != SC_OSSL_DH_GET_CONTEXT_SUCCESS )
    {
        // On error free the partially constructed key context
        scossl_dh_free_key_context(pKeyCtx);
    }

    if( pbData )
    {
        OPENSSL_clear_free( pbData, cbData );
    }

    return res;
}

PSYMCRYPT_DLGROUP scossl_initialize_safeprime_dlgroup(_Inout_ PSYMCRYPT_DLGROUP* ppDlgroup,
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE dhSafePrimeType, UINT32 nBitsOfP )
{
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;

    if( *ppDlgroup == NULL )
    {
        *ppDlgroup = SymCryptDlgroupAllocate( nBitsOfP, nBitsOfP-1 );
        if( *ppDlgroup == NULL )
        {
            goto cleanup;
        }

        symError = SymCryptDlgroupSetValueSafePrime(dhSafePrimeType, *ppDlgroup);
    }

cleanup:
    if( *ppDlgroup != NULL && symError != SYMCRYPT_NO_ERROR )
    {
        SymCryptDlgroupFree(*ppDlgroup);
        *ppDlgroup = NULL;
    }
    return *ppDlgroup;
}

// returns SC_OSSL_DH_GET_CONTEXT_FALLBACK when the dh is not supported by the engine, so we
// should fallback to OpenSSL
// returns SC_OSSL_DH_GET_CONTEXT_ERROR on an error
// returns SC_OSSL_DH_GET_CONTEXT_SUCCESS and sets pKeyCtx to a pointer to an initialized
// SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS sc_ossl_get_dh_context_ex(_Inout_ DH* dh, _Out_ PSCOSSL_DH_KEY_CONTEXT* ppKeyCtx, BOOL generate)
{
    SCOSSL_STATUS status = SC_OSSL_DH_GET_CONTEXT_SUCCESS;

    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pDlkey = NULL;

    const BIGNUM* p = NULL;
    const BIGNUM* g = NULL;
    const BIGNUM* dh_privkey = NULL;

    DH_get0_pqg(dh, &p, NULL, &g);

    // All named safe-prime groups supported by SCOSSL have a generator of 2
    if( !BN_is_word( g, 2 ) )
    {
        return SC_OSSL_DH_GET_CONTEXT_FALLBACK;
    }

    // OpenSSL is a bit inconsistent with how it handles different named safe-prime groups
    // We can get OpenSSL to return a nid for ffdhe groups we support
    int dlgroupNid = DH_get_nid(dh);

    switch( dlgroupNid )
    {
    case NID_ffdhe2048:
        pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe2048, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 2048 );
        break;
    case NID_ffdhe3072:
        pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe3072, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 3072 );
        break;
    case NID_ffdhe4096:
        pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_ffdhe4096, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919, 4096 );
        break;
    default:
        // Not one of the supported ffdhe groups, but may still be a supported MODP group
        // Given we know the generator is 2, we can now check whether P corresponds to a MODP group
        if( BN_cmp( p, BN_get_rfc3526_prime_2048(NULL) ) == 0 )
        {
            pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp2048, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 2048 );
        }
        else if( BN_cmp( p, BN_get_rfc3526_prime_3072(NULL) ) == 0 )
        {
            pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp3072, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 3072 );
        }
        else if( BN_cmp( p, BN_get_rfc3526_prime_4096(NULL) ) == 0 )
        {
            pDlgroup = scossl_initialize_safeprime_dlgroup( &_hidden_dlgroup_modp4096, SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526, 4096 );
        }
        else
        {
            SC_OSSL_LOG_INFO("SymCrypt engine does not support this DH dlgroup - falling back to OpenSSL.");
            return SC_OSSL_DH_GET_CONTEXT_FALLBACK; // <-- early return
        }
        break;
    }

    if( pDlgroup == NULL )
    {
        SC_OSSL_LOG_ERROR("scossl_initialize_safeprime_dlgroup failed.");
        return SC_OSSL_DH_GET_CONTEXT_ERROR;
    }

    *ppKeyCtx = (PSCOSSL_DH_KEY_CONTEXT) DH_get_ex_data(dh, dh_sc_ossl_idx);

    if( *ppKeyCtx == NULL )
    {
        PSCOSSL_DH_KEY_CONTEXT pKeyCtx = OPENSSL_zalloc(sizeof(*pKeyCtx));
        if( !pKeyCtx )
        {
            SC_OSSL_LOG_ERROR("OPENSSL_zalloc failed");
            return SC_OSSL_DH_GET_CONTEXT_ERROR;
        }

        if( DH_set_ex_data(dh, dh_sc_ossl_idx, pKeyCtx) == 0)
        {
            SC_OSSL_LOG_ERROR("DH_set_ex_data failed");
            OPENSSL_free(pKeyCtx);
            return SC_OSSL_DH_GET_CONTEXT_ERROR;
        }

        *ppKeyCtx = pKeyCtx;
    }

    if( (*ppKeyCtx)->initialized == 1 )
    {
        return SC_OSSL_DH_GET_CONTEXT_SUCCESS;
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

// returns SC_OSSL_DH_GET_CONTEXT_FALLBACK when the dh is not supported by the engine, so we
// should fallback to OpenSSL
// returns SC_OSSL_DH_GET_CONTEXT_ERROR on an error
// returns SC_OSSL_DH_GET_CONTEXT_SUCCESS and sets pKeyCtx to a pointer to an initialized
// SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS sc_ossl_get_dh_context(_Inout_ DH* dh, _Out_ PSCOSSL_DH_KEY_CONTEXT* ppKeyCtx)
{
    return sc_ossl_get_dh_context_ex(dh, ppKeyCtx, FALSE);
}

SCOSSL_STATUS sc_ossl_dh_generate_key(_Inout_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = NULL;

    switch( sc_ossl_get_dh_context_ex(dh, &pKeyCtx, TRUE) )
    {
    case SC_OSSL_DH_GET_CONTEXT_ERROR:
        SC_OSSL_LOG_ERROR("sc_ossl_get_dh_context_ex failed.");
        return 0;
    case SC_OSSL_DH_GET_CONTEXT_FALLBACK:
        ossl_dh_meth = DH_OpenSSL();
        PFN_DH_meth_generate_key pfn_dh_meth_generate_key = DH_meth_get_generate_key(ossl_dh_meth);
        if (pfn_dh_meth_generate_key == NULL)
        {
            return 0;
        }
        return pfn_dh_meth_generate_key(dh);
    case SC_OSSL_DH_GET_CONTEXT_SUCCESS:
        return 1;
    default:
        SC_OSSL_LOG_ERROR("Unexpected sc_ossl_get_dh_context_ex value");
        return 0;
    }
}

SCOSSL_RETURNLENGTH sc_ossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key,
                                            _In_ const BIGNUM* pub_key,
                                            _In_ DH* dh)
{
    const DH_METHOD* ossl_dh_meth = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = NULL;
    BYTE buf[SC_OSSL_DH_MAX_PUBLIC_KEY_LEN] = { 0 };

    UINT32 cbPublicKey = 0;
    PSYMCRYPT_DLKEY pkPublic = NULL;

    int res = -1; // fail

    switch( sc_ossl_get_dh_context(dh, &pKeyCtx) )
    {
    case SC_OSSL_DH_GET_CONTEXT_ERROR:
        SC_OSSL_LOG_ERROR("sc_ossl_get_dh_context failed.");
        return res;
    case SC_OSSL_DH_GET_CONTEXT_FALLBACK:
        ossl_dh_meth = DH_OpenSSL();
        PFN_DH_meth_compute_key pfn_dh_meth_compute_key = DH_meth_get_compute_key(ossl_dh_meth);
        if (pfn_dh_meth_compute_key == NULL)
        {
            return res;
        }
        return pfn_dh_meth_compute_key(key, pub_key, dh);
    case SC_OSSL_DH_GET_CONTEXT_SUCCESS:
        break;
    default:
        SC_OSSL_LOG_ERROR("Unexpected sc_ossl_get_dh_context_ex value");
        return res;
    }

    // DH_size(dh) == SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey)
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
    pkPublic = SymCryptDlkeyAllocate(pKeyCtx->dlkey->pDlgroup);
    if( pkPublic == NULL )
    {
        SC_OSSL_LOG_ERROR("SymCryptDlkeyAllocate returned NULL.");
        goto cleanup;
    }

    if( BN_bn2binpad(pub_key, buf, cbPublicKey) != cbPublicKey )
    {
        SC_OSSL_LOG_ERROR("BN_bn2binpad did not write expected number of public key bytes.");
        goto cleanup;
    }

    symError = SymCryptDlkeySetValue(
        NULL, 0,
        buf, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION,
        pkPublic );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDlkeySetValue failed", symError);
        goto cleanup;
    }

    symError = SymCryptDhSecretAgreement(
        pKeyCtx->dlkey,
        pkPublic,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        key,
        cbPublicKey );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SC_OSSL_LOG_SYMERROR_ERROR("SymCryptDhSecretAgreement failed", symError);
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

SCOSSL_STATUS sc_ossl_dh_finish(_Inout_ DH* dh)
{
    PSCOSSL_DH_KEY_CONTEXT pKeyCtx = DH_get_ex_data(dh, dh_sc_ossl_idx);
    if( pKeyCtx )
    {
        if( pKeyCtx->initialized == 1 )
        {
            scossl_dh_free_key_context(pKeyCtx);
        }
        OPENSSL_free(pKeyCtx);
        DH_set_ex_data(dh, dh_sc_ossl_idx, NULL);
    }
    return 1;
}

void sc_ossl_destroy_safeprime_dlgroups(void)
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
}

#ifdef __cplusplus
}
#endif

