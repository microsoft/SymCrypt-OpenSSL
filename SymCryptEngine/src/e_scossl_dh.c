//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_dh.h"
#include "e_scossl_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

int e_scossl_dh_idx = -1;

// Largest supported safe-prime group is 4096b => 512 byte Public key
#define SCOSSL_DH_MAX_PUBLIC_KEY_LEN (512)

typedef int (*PFN_DH_meth_generate_key) (DH*);
typedef int (*PFN_DH_meth_compute_key)(unsigned char* key, const BIGNUM* pub_key, DH* dh);
typedef int (*PFN_DH_meth_bn_mod_exp)(const DH* dh, BIGNUM* r,
    const BIGNUM* a, const BIGNUM* p,
    const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
typedef int (*PFN_DH_meth_init)(DH* dh);
typedef int (*PFN_DH_meth_finish)(DH* dh);

// Generates a new keypair using pDlgroup, storing the new keypair in dh and pKeyCtx.
// Returns SCOSSL_SUCCESS on success or SCOSSL_FAILURE on error.
SCOSSL_STATUS e_scossl_dh_generate_keypair(
    _Inout_ SCOSSL_DH_KEY_CTX* pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup, _Inout_ DH* dh)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbData = NULL;
    SIZE_T cbData = 0;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    BIGNUM* dh_privkey = NULL;
    BIGNUM* dh_pubkey = NULL;

    int res = SCOSSL_FAILURE;

    if (!scossl_dh_generate_keypair(pKeyCtx, DH_get_length(dh), pDlgroup))
    {
        goto cleanup;
    }

    cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pKeyCtx->dlkey);
    cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);

    cbData = cbPublicKey + cbPrivateKey;
    pbData = OPENSSL_zalloc(cbData);
    if( pbData == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEYPAIR, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc returned NULL.");
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

    res = SCOSSL_SUCCESS;

cleanup:
    if( res != SCOSSL_SUCCESS )
    {
        // On error free the partially constructed key context
        if (pKeyCtx->dlkey != NULL)
        {
            SymCryptDlkeyFree(pKeyCtx->dlkey);
            pKeyCtx->dlkey = NULL;
        }
        pKeyCtx->initialized = FALSE;
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
SCOSSL_STATUS e_scossl_dh_import_keypair(
    _Inout_ DH* dh, _Inout_ SCOSSL_DH_KEY_CTX* pKeyCtx, _In_ PCSYMCRYPT_DLGROUP pDlgroup )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    const BIGNUM*   dh_privkey = NULL;
    const BIGNUM*   dh_pubkey = NULL;
    BIGNUM*   generated_dh_pubkey = NULL;

    int res = SCOSSL_FAILURE;

    DH_get0_key(dh, &dh_pubkey, &dh_privkey);

    if( dh_pubkey == NULL && dh_privkey == NULL )
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_INTERNAL_ERROR,
            "DH_get0_key returned NULL for public and private key.");
        goto cleanup;
    }

    if (!scossl_dh_import_keypair(pKeyCtx, DH_get_length(dh), pDlgroup, FALSE, dh_privkey, dh_pubkey))
    {
        goto cleanup;
    }

    // If the dh object we are importing from only had a private key, populate the public key with
    // the value we just generated in SymCrypt
    if( cbPublicKey == 0 )
    {
        cbPublicKey = SymCryptDlkeySizeofPublicKey(pKeyCtx->dlkey);
        if( (pbPublicKey = OPENSSL_zalloc(cbPublicKey)) == NULL )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_IMPORT_KEYPAIR, ERR_R_MALLOC_FAILURE,
                            "OPENSSL_zalloc returned NULL.");
            goto cleanup;
        }

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

    res = SCOSSL_SUCCESS;

cleanup:
    // Key only needs to be cleanup up by this function if we fail to populate the public key with
    // the generated value. scossl_dh_import_keypair will clean up in case of import failure.
    if ( res != SCOSSL_SUCCESS && cbPublicKey != 0 )
    {
        if (pKeyCtx->dlkey != NULL)
        {
            SymCryptDlkeyFree(pKeyCtx->dlkey);
            pKeyCtx->dlkey = NULL;
        }
        pKeyCtx->initialized = FALSE;
    }

    BN_free(generated_dh_pubkey);
    OPENSSL_free(pbPublicKey);

    return res;
}

SCOSSL_STATUS e_scossl_dh_init_static()
{
    return scossl_dh_init_static();
}

// returns SCOSSL_FALLBACK when the dh is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS e_scossl_get_dh_context_ex(_Inout_ DH* dh, _Out_ SCOSSL_DH_KEY_CTX** ppKeyCtx, BOOL generate)
{
    SCOSSL_STATUS status;
    PCSYMCRYPT_DLGROUP pDlgroup = NULL;

    const BIGNUM* p = NULL;
    const BIGNUM* g = NULL;
    const BIGNUM* dh_privkey = NULL;

    DH_get0_pqg(dh, &p, NULL, &g);

    // All named safe-prime groups supported by SCOSSL have a generator of 2
    if( !BN_is_word( g, 2 ) )
    {
        return SCOSSL_FALLBACK;
    }

    if ( (status = scossl_dh_get_group_by_nid(DH_get_nid(dh), p, &pDlgroup)) != SCOSSL_SUCCESS )
    {
        if (status == SCOSSL_FALLBACK)
        {
            SCOSSL_LOG_INFO(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, SCOSSL_ERR_R_OPENSSL_FALLBACK,
                "SymCrypt engine does not support this DH dlgroup - falling back to OpenSSL.");
        }
        return status;
    }

    *ppKeyCtx = (SCOSSL_DH_KEY_CTX*) DH_get_ex_data(dh, e_scossl_dh_idx);

    if( *ppKeyCtx == NULL )
    {
        SCOSSL_DH_KEY_CTX* pKeyCtx = scossl_dh_new_key_ctx();
        if( !pKeyCtx )
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_DH_CONTEXT_EX, ERR_R_MALLOC_FAILURE,
                "OPENSSL_zalloc failed");
            return SCOSSL_FAILURE;
        }

        if( DH_set_ex_data(dh, e_scossl_dh_idx, pKeyCtx) == 0)
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
        return e_scossl_dh_generate_keypair(*ppKeyCtx, pDlgroup, dh);
    }
    else
    {
        return e_scossl_dh_import_keypair(dh, *ppKeyCtx, pDlgroup);
    }
}

// returns SCOSSL_FALLBACK when the dh is not supported by the engine, so we should fallback to OpenSSL
// returns SCOSSL_FAILURE on an error
// returns SCOSSL_SUCCESS and sets pKeyCtx to a pointer to an initialized SCOSSL_DH_KEY_CONTEXT on success
SCOSSL_STATUS e_scossl_get_dh_context(_Inout_ DH* dh, _Out_ SCOSSL_DH_KEY_CTX** ppKeyCtx)
{
    return e_scossl_get_dh_context_ex(dh, ppKeyCtx, FALSE);
}

SCOSSL_STATUS e_scossl_dh_generate_key(_Inout_ DH* dh)
{
    PFN_DH_meth_generate_key pfn_dh_meth_generate_key = NULL;
    SCOSSL_DH_KEY_CTX* pKeyCtx = NULL;

    switch( e_scossl_get_dh_context_ex(dh, &pKeyCtx, TRUE) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_GENERATE_KEY, ERR_R_OPERATION_FAIL,
            "e_scossl_get_dh_context_ex failed.");
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
            "Unexpected e_scossl_get_dh_context_ex value");
        return SCOSSL_FAILURE;
    }
}

SCOSSL_RETURNLENGTH e_scossl_dh_compute_key(_Out_writes_bytes_(DH_size(dh)) unsigned char* key,
                                            _In_ const BIGNUM* pub_key,
                                            _In_ DH* dh)
{
    PFN_DH_meth_compute_key pfn_dh_meth_compute_key = NULL;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SCOSSL_DH_KEY_CTX* pKeyCtx = NULL;
    BYTE buf[SCOSSL_DH_MAX_PUBLIC_KEY_LEN] = { 0 };

    UINT32 cbPublicKey = 0;
    PSYMCRYPT_DLKEY pkPublic = NULL;

    int res = -1; // fail

    switch( e_scossl_get_dh_context(dh, &pKeyCtx) )
    {
    case SCOSSL_FAILURE:
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_DH_COMPUTE_KEY, ERR_R_OPERATION_FAIL,
            "e_scossl_get_dh_context failed.");
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
            "Unexpected e_scossl_get_dh_context_ex value");
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
        SYMCRYPT_FLAG_DLKEY_DH,
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

SCOSSL_STATUS e_scossl_dh_finish(_Inout_ DH* dh)
{
    PFN_DH_meth_finish pfn_dh_meth_finish = DH_meth_get_finish(DH_OpenSSL());
    SCOSSL_DH_KEY_CTX* pKeyCtx = DH_get_ex_data(dh, e_scossl_dh_idx);
    if( pKeyCtx )
    {
        scossl_dh_free_key_ctx(pKeyCtx);
        DH_set_ex_data(dh, e_scossl_dh_idx, NULL);
    }

    // Ensure any buffers initialized by DH_OpenSSL are freed
    if( pfn_dh_meth_finish == NULL )
    {
        return SCOSSL_FAILURE;
    }
    return pfn_dh_meth_finish(dh);
}

void e_scossl_destroy_safeprime_dlgroups(void)
{
    scossl_destroy_safeprime_dlgroups();
}

#ifdef __cplusplus
}
#endif

