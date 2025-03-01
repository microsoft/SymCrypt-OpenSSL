//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "scossl_ecc.h"
#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCOSSL_X25519_MAX_SIZE (32)

_Use_decl_annotations_
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_new_ctx(SCOSSL_PROVCTX *provctx)
{
    SCOSSL_ECC_KEY_CTX *keyCtx = OPENSSL_zalloc(sizeof(SCOSSL_ECC_KEY_CTX));
    if (keyCtx != NULL)
    {
        keyCtx->libctx = provctx->libctx;
        keyCtx->includePublic = 1;
        keyCtx->conversionFormat = POINT_CONVERSION_UNCOMPRESSED;
    }
    return keyCtx;
}

_Use_decl_annotations_
void p_scossl_ecc_free_ctx(SCOSSL_ECC_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }
#ifdef KEYSINUSE_ENABLED
    p_scossl_ecc_reset_keysinuse(keyCtx);
    CRYPTO_THREAD_lock_free(keyCtx->keysinuseLock);
#endif

    OPENSSL_free(keyCtx);
}

_Use_decl_annotations_
SCOSSL_ECC_KEY_CTX *p_scossl_ecc_dup_ctx(SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    PBYTE pbData = NULL;
    PBYTE pbPrivateKey = NULL;
    PBYTE pbPublicKey = NULL;
    SIZE_T cbData = 0;
    SIZE_T cbPublicKey = 0;
    SIZE_T cbPrivateKey = 0;
    SCOSSL_STATUS success = SCOSSL_FAILURE;
    SYMCRYPT_ECPOINT_FORMAT pointFormat = keyCtx->isX25519 ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SCOSSL_ECC_KEY_CTX *copyCtx = OPENSSL_malloc(sizeof(SCOSSL_ECC_KEY_CTX));

    if (copyCtx != NULL)
    {
#ifdef KEYSINUSE_ENABLED
        copyCtx->isImported = keyCtx->isImported;
        copyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();

        if (keyCtx->keysinuseInfo == NULL ||
            p_scossl_keysinuse_upref(keyCtx->keysinuseInfo, NULL))
        {
            copyCtx->keysinuseInfo = keyCtx->keysinuseInfo;
        }
#endif

        copyCtx->isX25519 = keyCtx->isX25519;
        copyCtx->libctx = keyCtx->libctx;
        copyCtx->modifiedPrivateBits = keyCtx->modifiedPrivateBits;
        copyCtx->conversionFormat = keyCtx->conversionFormat;

        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        {
            copyCtx->curve = keyCtx->curve;
        }
        else
        {
            copyCtx->curve = NULL;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 && keyCtx->initialized)
        {
            if (copyCtx->curve == NULL)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
                goto cleanup;
            }

            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
                SymCryptEckeyHasPrivateKey(keyCtx->key))
            {
                cbPrivateKey = SymCryptEckeySizeofPrivateKey(keyCtx->key);
            }

            if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            {
                cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat);
            }

            cbData = cbPrivateKey + cbPublicKey;
            if ((pbData = OPENSSL_secure_malloc(cbData)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            pbPrivateKey = cbPrivateKey != 0 ? pbData : NULL;
            pbPublicKey = cbPublicKey != 0 ? pbData + cbPrivateKey : NULL;

            scError = SymCryptEckeyGetValue(
                keyCtx->key,
                pbPrivateKey, cbPrivateKey,
                pbPublicKey, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pointFormat,
                0);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeyGetValue failed", scError);
                goto cleanup;
            }

            if ((copyCtx->key = SymCryptEckeyAllocate(keyCtx->curve)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            // Default ECDH only. If the key is used for ECDSA then we call SymCryptEckeyExtendKeyUsage
            scError = SymCryptEckeySetValue(
                pbPrivateKey, cbPrivateKey,
                pbPublicKey, cbPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                pointFormat,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                copyCtx->key);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeySetValue failed", scError);
                goto cleanup;
            }

            copyCtx->initialized = 1;
            copyCtx->includePublic = keyCtx->includePublic;
        }
        else
        {
            copyCtx->key = NULL;
            copyCtx->initialized = 0;
            copyCtx->includePublic = 1;
        }
    }

    success = SCOSSL_SUCCESS;

cleanup:
    if (pbData != NULL)
    {
        OPENSSL_secure_clear_free(pbData, cbData);
    }

    if (!success)
    {
        p_scossl_ecc_free_ctx(copyCtx);
        copyCtx = NULL;
    }

    return copyCtx;
}

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_set_group(SCOSSL_ECC_KEY_CTX *keyCtx, const char *groupName)
{
    PCSYMCRYPT_ECURVE curve;
    int nid = OBJ_sn2nid(groupName);

    if (nid == NID_X25519)
    {
        keyCtx->isX25519 = TRUE;
        curve = scossl_ecc_get_x25519_curve();
    }
    else
    {
        keyCtx->isX25519 = FALSE;
        curve = scossl_ecc_nid_to_symcrypt_curve(nid);

        if (curve == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return SCOSSL_FAILURE;
        }
    }

    keyCtx->curve = curve;

    return SCOSSL_SUCCESS;
}

SCOSSL_STATUS p_scossl_ecc_gen(_Inout_ SCOSSL_ECC_KEY_CTX *keyCtx)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

#ifdef KEYSINUSE_ENABLED
    keyCtx->isImported = FALSE;
    keyCtx->keysinuseLock = CRYPTO_THREAD_lock_new();
    keyCtx->keysinuseInfo = NULL;
#endif

    if (keyCtx->key != NULL)
    {
        SymCryptEckeyFree(keyCtx->key);
    }

    keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve);
    if (keyCtx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return SCOSSL_FAILURE;
    }

    // Default ECDH only. If the key is used for ECDSA then we call SymCryptEckeyExtendKeyUsage
    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, keyCtx->key);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        SCOSSL_PROV_LOG_SYMCRYPT_ERROR("SymCryptEckeySetRandom failed", scError);
        return SCOSSL_FAILURE;
    }

    keyCtx->initialized = TRUE;

    return SCOSSL_SUCCESS;
}

SIZE_T p_scossl_ecc_get_max_size(_In_ SCOSSL_ECC_KEY_CTX *keyCtx, BOOL isEcdh)
{
    if (keyCtx->isX25519)
    {
        return SCOSSL_X25519_MAX_SIZE;
    }
    else if (isEcdh)
    {
        return keyCtx->key == NULL ? 0 : SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    }
    else if (keyCtx->curve == NULL)
    {
        return 0;
    }

    return scossl_ecdsa_size(keyCtx->curve);
}

_Use_decl_annotations_
SIZE_T p_scossl_ecc_get_encoded_key_size(SCOSSL_ECC_KEY_CTX *keyCtx, int selection)
{
    SIZE_T cbKey;

    if (keyCtx->curve == NULL)
    {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        return SymCryptEcurveSizeofScalarMultiplier(keyCtx->curve);
    }
    else if (keyCtx->isX25519)
    {
        return SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    }

    cbKey = SymCryptEcurveSizeofFieldElement(keyCtx->curve);
    if (!keyCtx->isX25519)
    {
        if (keyCtx->conversionFormat != POINT_CONVERSION_COMPRESSED)
        {
            cbKey *= 2;
        }

        cbKey++;
    }

    return cbKey;
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
        0,
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
SCOSSL_STATUS p_scossl_ecc_set_encoded_key(SCOSSL_ECC_KEY_CTX *keyCtx,
                                           PCBYTE pbEncodedPublicKey, SIZE_T cbEncodedPublicKey,
                                           PCBYTE pbEncodedPrivateKey, SIZE_T cbEncodedPrivateKey)
{
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT pointFormat;
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ecPoint = NULL;
    BN_CTX *bnCtx = NULL;
    PBYTE pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;
    PBYTE pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
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

    if (keyCtx->isX25519)
    {
        numFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        pointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
    }
    else
    {
        numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        pointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
    }

    if ((keyCtx->key = SymCryptEckeyAllocate(keyCtx->curve)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (pbEncodedPublicKey != NULL)
    {
        if (keyCtx->isX25519)
        {
            pbPublicKey = (PBYTE) pbEncodedPublicKey;
            cbPublicKey = cbEncodedPublicKey;
        }
        else
        {
            cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
            if (((ecGroup = scossl_ecc_symcrypt_curve_to_ecc_group(keyCtx->curve)) == NULL) ||
                ((ecPoint = EC_POINT_new(ecGroup))            == NULL) ||
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
    }

    if (pbEncodedPrivateKey != NULL)
    {
        if (keyCtx->isX25519)
        {
            if ((pbPrivateKey = OPENSSL_secure_malloc(cbEncodedPrivateKey)) == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                goto cleanup;
            }

            memcpy(pbPrivateKey, pbEncodedPrivateKey, cbEncodedPrivateKey);

            // Preserve original bits for export
            keyCtx->modifiedPrivateBits = pbPrivateKey[0] & 0x07;
            keyCtx->modifiedPrivateBits |= pbPrivateKey[cbPrivateKey-1] & 0xc0;

            pbPrivateKey[0] &= 0xf8;
            pbPrivateKey[cbPrivateKey-1] &= 0x7f;
            pbPrivateKey[cbPrivateKey-1] |= 0x40;
        }
        else
        {
            pbPrivateKey = (PBYTE) pbEncodedPrivateKey;
            cbPrivateKey = cbEncodedPrivateKey;
        }
    }

    scError = SymCryptEckeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        numFormat,
        pointFormat,
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
        keyCtx->key = NULL;
    }

    // X25519 needs to copy and decode the private key, other ECC needs
    // to copy and decode the public key.
    if (keyCtx->isX25519)
    {
        OPENSSL_secure_clear_free(pbPrivateKey, cbPrivateKey);
    }
    else
    {
        OPENSSL_free(pbPublicKey);
    }

    EC_GROUP_free(ecGroup);
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