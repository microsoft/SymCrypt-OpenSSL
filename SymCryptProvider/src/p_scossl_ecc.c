//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

_Use_decl_annotations_
SIZE_T p_scossl_ecc_get_encoded_key_size(SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    SYMCRYPT_ECPOINT_FORMAT pointFormat;

    if (!keyCtx->initialized)
    {
        return 0;
    }
    
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        return SymCryptEckeySizeofPrivateKey(keyCtx->key);
    }
    else if (keyCtx->isX25519)
    {
        return SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    }

    pointFormat = keyCtx->conversionFormat == POINT_CONVERSION_COMPRESSED ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;

    return SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat) + 1;
}

// Gets the public key as an encoded octet string
// For x25519, the encoding rules defined in RFC 7748 are used
// Otherwise, the encoding rules defined in SECG SEC 1 are used, according to the conversion format of keyCtx
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_get_encoded_public_key(const SCOSSL_ECC_KEY_CTX *keyCtx,
                                                  PBYTE *ppbPublicKey, SIZE_T *pcbPublicKey)
{
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT pointFormat;
    PBYTE pbPublicKeyStart = NULL;
    PBYTE pbPublicKey = NULL;
    SIZE_T cbPublicKey;
    BOOL allocatedKey = FALSE;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    if (keyCtx->isX25519)
    {
        numFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        pointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat);
    }
    else
    {
        numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        pointFormat = keyCtx->conversionFormat == POINT_CONVERSION_COMPRESSED ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;

        // Allocate one extra byte for point compression type
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat) + 1;
    }

    if (*ppbPublicKey == NULL)
    {
        if ((pbPublicKeyStart = OPENSSL_malloc(cbPublicKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        allocatedKey = TRUE;
    }
    else if (*pcbPublicKey >= cbPublicKey)
    {
        pbPublicKeyStart = *ppbPublicKey;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto cleanup;
    }

    pbPublicKey = pbPublicKeyStart;

    if (!keyCtx->isX25519)
    {
        pbPublicKey++;
        cbPublicKey--;
    }

    scError = SymCryptEckeyGetValue(
            keyCtx->key,
            NULL, 0,
            pbPublicKey, cbPublicKey,
            numFormat,
            pointFormat,
            0);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
        goto cleanup;
    }

    if (!keyCtx->isX25519)
    {
        pbPublicKeyStart[0] = keyCtx->conversionFormat;

        // There are three possible point conversion formats based on SECG SEC 1 2.3.3:
        // - COMPRESSED: The point is encoded as z||x, where z is 2 if y is even, and 3 if y is odd
        // - UNCOMPRESSED: The point is encoded as 0x04||x||y
        // - HYBRID: The point is encoded as z||x||y, where z is 6 if y is even, and 7 if y is odd
        // Note that the z value for COMPRESSED and HYBRID is only the values above for prime finite
        // fields.  SymCrypt only supports named, prime finite field curves.
        if (keyCtx->conversionFormat != POINT_CONVERSION_UNCOMPRESSED)
        {
            if (pbPublicKey[cbPublicKey-1] & 1)
            {
                pbPublicKeyStart[0]++;
            }
        }

        cbPublicKey++;
    }

    if (allocatedKey)
    {
        *ppbPublicKey = pbPublicKeyStart;
    }
    *pcbPublicKey = cbPublicKey;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret && allocatedKey)
    {
        OPENSSL_free(pbPublicKeyStart);
    }

    return ret;
}

SCOSSL_STATUS p_scossl_ecc_get_private_key(_In_ SCOSSL_ECC_KEY_CTX *keyCtx,
                                           _Out_writes_bytes_(*pcbPrivateKey) PBYTE *ppbPrivateKey, _Out_ SIZE_T *pcbPrivateKey)
{
    PBYTE pbPrivateKey = NULL;
    SIZE_T cbPrivateKey;
    SYMCRYPT_NUMBER_FORMAT numFormat = keyCtx->isX25519 ? SYMCRYPT_NUMBER_FORMAT_LSB_FIRST : SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    SYMCRYPT_ECPOINT_FORMAT pointFormat = keyCtx->isX25519 ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;
    BOOL allocatedKey = FALSE;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    
    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return SCOSSL_FAILURE;
    }

    cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);

    if (*ppbPrivateKey == NULL)
    {
        if ((pbPrivateKey = OPENSSL_malloc(cbPrivateKey)) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        allocatedKey = TRUE;
    }
    else if (*pcbPrivateKey >= cbPrivateKey)
    {
        pbPrivateKey = *ppbPrivateKey;

    }
    else
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto cleanup;
    }
    
    scError = SymCryptEckeyGetValue(
        keyCtx->key,
        pbPrivateKey, cbPrivateKey,
        NULL, 0,
        numFormat,
        pointFormat,
        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
        goto cleanup;
    }

    if (keyCtx->isX25519)
    {
        pbPrivateKey[0] = (keyCtx->modifiedPrivateBits & 0x07) | (pbPrivateKey[0] & 0xf8);
        pbPrivateKey[cbPrivateKey-1] = (keyCtx->modifiedPrivateBits & 0xc0) | (pbPrivateKey[cbPrivateKey-1] & 0x3f);
    }

    if (allocatedKey)
    {
        *ppbPrivateKey = pbPrivateKey;
    }
    *pcbPrivateKey = cbPrivateKey;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS && allocatedKey)
    {
        OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    }

    return ret;
}

// Gets the ECC Key following the proper encoding rules.  If *ppbKey is non-NULL, then the key material
// is written directly to the supplied buffer. Otherwise, a new buffer is allocated to contain the key.
// The caller is responsible for freeing *ppbKey.
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_get_encoded_key(SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                           PBYTE *ppbKey, SIZE_T *pcbKey)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        return p_scossl_ecc_get_private_key(keyCtx, ppbKey, pcbKey);
    }

    return p_scossl_ecc_get_encoded_public_key(keyCtx, ppbKey, pcbKey);
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_set_encoded_key(SCOSSL_ECC_KEY_CTX *keyCtx, int selection,
                                           PCBYTE pbEncodedPublicKey, SIZE_T cbEncodedPublicKey,
                                           PCBYTE pbPrivateKey, SIZE_T cbPrivateKey)
{
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ecPoint = NULL;
    BN_CTX *bnCtx = NULL;

    PBYTE pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

#ifdef KEYSINUSE_ENABLED
    // Reset keysinuse in case new key material is overwriting existing
    p_scossl_ecc_reset_keysinuse(keyCtx);
#endif

    if ((keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
        if (((ecPoint = EC_POINT_new(ecGroup))    == NULL) ||
            ((bnCtx = BN_CTX_new_ex(keyCtx->libctx))      == NULL) ||
            ((pbPublicKey = OPENSSL_malloc(cbPublicKey))  == NULL))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        if (!EC_POINT_oct2point(ecGroup, ecPoint, pbEncodedPublicKey, cbEncodedPublicKey, bnCtx) ||
            !scossl_ec_point_to_pubkey(ecPoint, ecGroup, bnCtx, pbPublicKey, cbPublicKey))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            goto cleanup;
        }
    }

    scError = SymCryptEckeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDH,
        keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeySetValue failed", scError);
        goto cleanup;
    }

    keyCtx->initialized = TRUE;
    ret = SCOSSL_SUCCESS;

cleanup:
    if (ret != SCOSSL_SUCCESS &&
        keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

    EC_GROUP_free(ecGroup);
    OPENSSL_free(pbPublicKey);
    EC_POINT_free(ecPoint);
    BN_CTX_free(bnCtx);

    return ret;
}

#ifdef KEYSINUSE_ENABLED
_Use_decl_annotations_
void p_scossl_ecc_init_keysinuse(SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx->isImported &&
        CRYPTO_THREAD_write_lock(keyCtx->keysinuseLock))
    {
        if (keyCtx->keysinuseInfo == NULL)
        {
            // Initialize keysinuse for private keys. Generated keys are
            // ignored to avoid noise from ephemeral keys.
            PBYTE pbPublicKey;
            SIZE_T cbPublicKey;

            // KeysInUse related errors shouldn't surface to caller
            ERR_set_mark();

            if (p_scossl_ecc_get_encoded_public_key(keyCtx, &pbPublicKey, &cbPublicKey))
            {
                keyCtx->keysinuseInfo = p_scossl_keysinuse_info_new(pbPublicKey, cbPublicKey);
            }
            else
            {
                SCOSSL_PROV_LOG_DEBUG(SCOSSL_ERR_R_KEYSINUSE_FAILURE,
                    "p_scossl_ecc_get_encoded_public_key failed: %s", ERR_error_string(ERR_get_error(), NULL));
            }

            ERR_pop_to_mark();

            OPENSSL_free(pbPublicKey);
        }
        CRYPTO_THREAD_unlock(keyCtx->keysinuseLock);
    }
}

_Use_decl_annotations_
void p_scossl_ecc_reset_keysinuse(SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx->keysinuseLock != NULL &&
        CRYPTO_THREAD_write_lock(keyCtx->keysinuseLock))
    {
        p_scossl_keysinuse_info_free(keyCtx->keysinuseInfo);
        keyCtx->keysinuseInfo = NULL;
        CRYPTO_THREAD_unlock(keyCtx->keysinuseLock);
    }
}
#endif

#ifdef __cplusplus
}
#endif