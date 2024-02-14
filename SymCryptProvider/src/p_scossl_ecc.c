#include <openssl/proverr.h>

#include "p_scossl_ecc.h"

_Use_decl_annotations_
SCOSSL_STATUS p_scossl_ecc_get_encoded_public_key(const SCOSSL_ECC_KEY_CTX *keyCtx,
                                                  PBYTE *ppbEncodedKey, SIZE_T *pcbEncodedKey)
{
    // In the general ECC case, 0x04 must be prepended to the public key to
    // indicate this is an uncompressed point. This is not added for x25519
    SYMCRYPT_NUMBER_FORMAT numFormat = keyCtx->isX25519 ? SYMCRYPT_NUMBER_FORMAT_LSB_FIRST : SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    SYMCRYPT_ECPOINT_FORMAT pointFormat = keyCtx->isX25519 ? SYMCRYPT_ECPOINT_FORMAT_X : SYMCRYPT_ECPOINT_FORMAT_XY;
    PBYTE pbEncodedKey;
    SIZE_T cbEncodedKey = SymCryptEckeySizeofPublicKey(keyCtx->key, pointFormat);
    SYMCRYPT_ERROR scError;
    SCOSSL_STATUS ret = SCOSSL_FAILURE;

    if (!keyCtx->initialized)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto cleanup;
    }

    if (!keyCtx->isX25519)
    {
        cbEncodedKey++;
    }

    if ((pbEncodedKey = OPENSSL_malloc(cbEncodedKey)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    // pbPublicKeyTmp = *ppbEncodedPublicKey;

    if (!keyCtx->isX25519)
    {
        pbEncodedKey[0] = 0x04;
        pbEncodedKey++;
        cbEncodedKey--;
    }

    scError = SymCryptEckeyGetValue(
            keyCtx->key,
            NULL, 0,
            pbEncodedKey, cbEncodedKey,
            numFormat,
            pointFormat,
            0);

    if (!keyCtx->isX25519)
    {
        pbEncodedKey--;
        cbEncodedKey++;
    }

    if (scError != SYMCRYPT_NO_ERROR)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    *ppbEncodedKey = pbEncodedKey;
    *pcbEncodedKey = cbEncodedKey;

    ret = SCOSSL_SUCCESS;

cleanup:
    if (!ret)
    {
        *ppbEncodedKey = NULL;
        *pcbEncodedKey = 0;
        OPENSSL_free(pbEncodedKey);
    }

    return ret;
}
