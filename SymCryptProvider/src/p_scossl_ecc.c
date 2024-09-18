//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/proverr.h>

#include "p_scossl_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

// Gets the public key as an encoded octet string
// For x25519, the encoding rules defined in RFC 7748 are used
// Otherwise, the encoding rules defined in SECG SEC 1 are used, according to the conversion format of keyCtx
_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_get_encoded_public_key(const SCOSSL_ECC_KEY_CTX *keyCtx,
                                                  PBYTE *ppbEncodedKey, SIZE_T *pcbEncodedKey)
{
    SYMCRYPT_NUMBER_FORMAT numFormat;
    SYMCRYPT_ECPOINT_FORMAT pointFormat;
    PBYTE pbPublicKey, pbPublicKeyStart;
    SIZE_T cbPublicKey;
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
        pointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;

        // Allocate one extra byte for point compression type
        cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat) + 1;
    }

    if ((pbPublicKeyStart = OPENSSL_malloc(cbPublicKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
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
            SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_PROV_ECC_GET_ENCODED_PUBLIC_KEY, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
                "SymCryptEckeyGetValue failed", scError);
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

            if (keyCtx->conversionFormat == POINT_CONVERSION_COMPRESSED)
            {
                // We only need the X coordinate, so copy that and the format byte for return.
                // Copy to pbPublicKey in case OPENSSL_memdup fails so we still free the original buffer
                if ((pbPublicKey = OPENSSL_memdup(pbPublicKeyStart, (cbPublicKey/2) + 1)) == NULL)
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    goto cleanup;
                }
                OPENSSL_free(pbPublicKeyStart);
                pbPublicKeyStart = pbPublicKey;
            }
        }

        cbPublicKey++;
    }

    *ppbEncodedKey = pbPublicKeyStart;
    *pcbEncodedKey = cbPublicKey;
    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        OPENSSL_free(pbPublicKeyStart);
    }

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
                SCOSSL_LOG_DEBUG(SCOSSL_ERR_F_PROV_ECC_INIT_KEYSINUSE, SCOSSL_ERR_R_KEYSINUSE_FAILURE,
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