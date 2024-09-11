//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_aes_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES-GCM Common Functions
 */
_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_init_ctx(SCOSSL_CIPHER_GCM_CTX *ctx, const unsigned char *iv)
{
    ctx->operationInProgress = 0;
    ctx->taglen = SCOSSL_GCM_MAX_TAG_LENGTH;
    ctx->tlsAadSet = 0;
    ctx->ivInvocation = 0;
    ctx->useInvocation = 0;
    ctx->ivlen = SCOSSL_GCM_DEFAULT_IV_LENGTH;

    if (iv != NULL && (ctx->iv = OPENSSL_memdup(iv, ctx->ivlen)) == NULL)
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_init_key(SCOSSL_CIPHER_GCM_CTX *ctx,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *iv, size_t ivlen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    ctx->operationInProgress = 0;
    if (iv != NULL)
    {
        if (!scossl_aes_gcm_set_iv_len(ctx, ivlen) ||
            (ctx->iv = OPENSSL_memdup(iv, ctx->ivlen)) == NULL)
        {
            return SCOSSL_FAILURE;
        }

        ctx->ivlen = ivlen;
    }
    if (key != NULL)
    {
        scError = SymCryptGcmExpandKey(&ctx->key, SymCryptAesBlockCipher, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_gcm_tls(_Inout_ SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                        _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl,
                                        _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE pbPayload = NULL;
    SIZE_T cbPayload = 0;

    // For TLS we only support in-place en/decryption of an ESP taking the form:
    // IV (8B) || Ciphertext (variable) || ICV (Auth Tag) (16B)

    // When encrypting, the space for the IV and ICV should be provided by the caller with the
    // plaintext starting 8B from the start of the buffer and ending 16B from the end
    if (in != out)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-GCM TLS does not support out-of-place operation");
        goto cleanup;
    }
    if (inl < EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-GCM TLS buffer too small");
        goto cleanup;
    }
    if (ctx->operationInProgress)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-GCM TLS operation cannot be multi-stage");
        goto cleanup;
    }
    if (ctx->taglen != EVP_GCM_TLS_TAG_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-GCM TLS taglen must be %d", EVP_GCM_TLS_TAG_LEN);
        goto cleanup;
    }

    pbPayload = out + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    cbPayload = inl - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);

    if (encrypt)
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Generate it using the IV invocation field to ensure distinct IVs are used
        if (scossl_aes_gcm_iv_gen(ctx, out, EVP_GCM_TLS_EXPLICIT_IV_LEN) != SCOSSL_SUCCESS)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_TLS, ERR_R_INTERNAL_ERROR,
                "AES-GCM TLS failed to generate IV");
            goto cleanup;
        }

        // Encrypt payload
        SymCryptGcmEncrypt(
            &ctx->key,
            ctx->iv, ctx->ivlen,
            ctx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload + cbPayload, EVP_GCM_TLS_TAG_LEN);

        *outl = inl;
    }
    else
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it to the context
        memcpy(ctx->iv + ctx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN, out, EVP_GCM_TLS_EXPLICIT_IV_LEN);

        // Check ICV
        scError = SymCryptGcmDecrypt(
            &ctx->key,
            ctx->iv, ctx->ivlen,
            ctx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload + cbPayload, EVP_GCM_TLS_TAG_LEN);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }

        *outl = cbPayload;
    }

    return SCOSSL_SUCCESS;
cleanup:
    OPENSSL_cleanse(out, inl);
    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_cipher(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                    unsigned char *out, size_t *outl,
                                    const unsigned char *in, size_t inl)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (ctx->iv == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_CIPHER, ERR_R_PASSED_INVALID_ARGUMENT,
            "IV must be set before calling cipher");
        return SCOSSL_FAILURE;
    }

    if (ctx->tlsAadSet)
    {
        return scossl_aes_gcm_tls(ctx, encrypt, out, outl, in, inl);
    }

    if (!ctx->operationInProgress)
    {
        SymCryptGcmInit(&ctx->state, &ctx->key, ctx->iv, ctx->ivlen);
        ctx->operationInProgress = 1;
    }

    if (out == NULL && in != NULL && inl > 0)
    {
        // Auth Data Passed in
        SymCryptGcmAuthPart(&ctx->state, in, inl);
        *outl = 0;
        return SCOSSL_SUCCESS;
    }

    if (encrypt)
    {
        if (in != NULL)
        {
            // Encrypt Part
            SymCryptGcmEncryptPart(&ctx->state, in, out, inl);
            *outl = inl;
        }
        else
        {
            // Final Encrypt Call
            SymCryptGcmEncryptFinal(&ctx->state, ctx->tag, ctx->taglen);
            *outl = 0;
        }
    }
    else
    {
        if (in != NULL)
        {
            // Decrypt Part
            SymCryptGcmDecryptPart(&ctx->state, in, out, inl);
            *outl = inl;
        }
        else
        {
            // Final Decrypt Call
            scError = SymCryptGcmDecryptFinal(&ctx->state, ctx->tag, ctx->taglen);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
            *outl = 0;
        }
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_get_aead_tag(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *tag, size_t taglen)
{
    if (taglen < SCOSSL_GCM_MIN_TAG_LENGTH || taglen > SCOSSL_GCM_MAX_TAG_LENGTH ||
        taglen > ctx->taglen || !encrypt)
    {
        return SCOSSL_FAILURE;
    }
    memcpy(tag, ctx->tag, taglen);
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_set_aead_tag(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *tag, size_t taglen)
{
    if (taglen < SCOSSL_GCM_MIN_TAG_LENGTH || taglen > SCOSSL_GCM_MAX_TAG_LENGTH ||
        encrypt)
    {
        return SCOSSL_FAILURE;
    }
    memcpy(ctx->tag, tag, taglen);
    ctx->taglen = taglen;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_iv_gen(SCOSSL_CIPHER_GCM_CTX *ctx,
                                    unsigned char *out, size_t outsize)
{
    if (ctx->useInvocation == 0)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->iv == NULL &&
        (ctx->iv = OPENSSL_zalloc(ctx->ivlen)) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_IV_GEN, ERR_R_MALLOC_FAILURE,
            "Failed to allocate IV");
        return SCOSSL_FAILURE;
    }

    // Place invocation field into IV
    SYMCRYPT_STORE_MSBFIRST64(ctx->iv + ctx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN, ctx->ivInvocation);
    if (outsize == 0 || outsize > ctx->ivlen)
    {
        outsize = ctx->ivlen;
    }
    memcpy(out, ctx->iv + ctx->ivlen - outsize, outsize);
    // Increment invocation counter
    ctx->ivInvocation++;
    ctx->operationInProgress = 0; // Flag ctx->state to be reinitialized

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_set_iv_len(SCOSSL_CIPHER_GCM_CTX *ctx, size_t ivlen)
{
    if (ivlen < SCOSSL_GCM_MIN_IV_LENGTH)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_IV_LEN, ERR_R_PASSED_INVALID_ARGUMENT,
            "GCM IV length must be at least 1 byte");
        return SCOSSL_FAILURE;
    }

    ctx->ivlen = ivlen;

    if (ctx->iv != NULL)
    {
        OPENSSL_free(ctx->iv);
        ctx->iv = NULL;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_set_iv_fixed(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *iv, size_t ivlen)
{
    if (ctx->ivlen != EVP_GCM_TLS_IV_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_IV_FIXED, ERR_R_PASSED_INVALID_ARGUMENT,
            "set_iv_fixed only works with TLS IV length");
        return SCOSSL_FAILURE;
    }

    if (ctx->iv == NULL &&
        (ctx->iv = OPENSSL_zalloc(ctx->ivlen)) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_IV_FIXED, ERR_R_MALLOC_FAILURE,
            "Failed to allocate IV");
        return SCOSSL_FAILURE;
    }

    if (ivlen == (size_t)-1)
    {
        // Set entire initial IV
        memcpy(ctx->iv, iv, ctx->ivlen);
        // Initialize our invocation counter from the IV
        ctx->ivInvocation = SYMCRYPT_LOAD_MSBFIRST64(ctx->iv + ctx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN);
        ctx->useInvocation = 1;
        return SCOSSL_SUCCESS;
    }
    if (ivlen > 4)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_IV_FIXED, ERR_R_PASSED_INVALID_ARGUMENT,
            "set_iv_fixed incorrect length");
        return SCOSSL_FAILURE;
    }
    // Set first up to 4B of IV
    memcpy(ctx->iv, iv, ivlen);
    // If encrypting, randomly set the invocation field
    if (encrypt &&
        (RAND_bytes(ctx->iv + ivlen, EVP_GCM_TLS_IV_LEN - ivlen) <= 0))
    {
        return SCOSSL_FAILURE;
    }
    // Initialize our invocation counter from the IV
    ctx->ivInvocation = SYMCRYPT_LOAD_MSBFIRST64(ctx->iv + ctx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx->useInvocation = 1;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_gcm_set_iv_inv(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                        unsigned char *iv, size_t ivlen)
{
    if (ctx->useInvocation == 0 ||
        encrypt ||
        ivlen == 0 ||
        ivlen > (size_t)ctx->ivlen)
    {
        return SCOSSL_FAILURE;
    }

    if (ctx->iv == NULL &&
        (ctx->iv = OPENSSL_zalloc(ctx->ivlen)) == NULL)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_IV_INV, ERR_R_MALLOC_FAILURE,
            "Failed to allocate IV");
        return SCOSSL_FAILURE;
    }

    // Place provided invocation field into IV
    memcpy(ctx->iv + ctx->ivlen - ivlen, iv, ivlen);
    // Initialize our invocation counter from the IV
    ctx->ivInvocation = SYMCRYPT_LOAD_MSBFIRST64(ctx->iv + ctx->ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx->operationInProgress = 0; // Flag ctx->state to be reinitialized
    return SCOSSL_SUCCESS;
}

// Returns the tag length on success, and 0 (SCOSSL_FAILURE) on failure
_Use_decl_annotations_
UINT16 scossl_aes_gcm_set_tls1_aad(SCOSSL_CIPHER_GCM_CTX *ctx, INT32 encrypt,
                                   unsigned char *aad, size_t aadlen)
{
    UINT16 tls_buffer_len = 0;
    UINT16 min_tls_buffer_len = 0;

    if (aadlen != EVP_AEAD_TLS1_AAD_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_TLS1_AAD, ERR_R_PASSED_INVALID_ARGUMENT,
            "tls1_aad only works with TLS1 AAD length");
        return SCOSSL_FAILURE;
    }
    memcpy(ctx->tlsAad, aad, EVP_AEAD_TLS1_AAD_LEN);
    ctx->tlsAadSet = 1;

    if (encrypt)
    {
        // Provided AAD contains len of plaintext + IV (8B)
        min_tls_buffer_len = EVP_GCM_TLS_EXPLICIT_IV_LEN;
    }
    else
    {
        // Provided AAD contains len of ciphertext + IV (8B) + ICV (16B)
        min_tls_buffer_len = EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    }

    tls_buffer_len = SYMCRYPT_LOAD_MSBFIRST16(ctx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2);
    if (tls_buffer_len < min_tls_buffer_len)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_GCM_SET_TLS1_AAD, ERR_R_PASSED_INVALID_ARGUMENT,
            "tls_buffer_len too short");
        return SCOSSL_FAILURE;
    }
    tls_buffer_len -= min_tls_buffer_len;
    SYMCRYPT_STORE_MSBFIRST16(ctx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2, tls_buffer_len);

    return EVP_GCM_TLS_TAG_LEN; // <-- Special case return
}

/*
 * AES-CCM Common Functions
 */
_Use_decl_annotations_
void scossl_aes_ccm_init_ctx(SCOSSL_CIPHER_CCM_CTX *ctx,
                             const unsigned char *iv)
{
    ctx->ivlen = SCOSSL_CCM_MIN_IV_LENGTH;
    if (iv)
    {
        memcpy(ctx->iv, iv, ctx->ivlen);
    }
    ctx->taglen = SCOSSL_CCM_MAX_TAG_LENGTH;
    ctx->tlsAadSet = 0;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_init_key(SCOSSL_CIPHER_CCM_CTX *ctx,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *iv, size_t ivlen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    ctx->ccmStage = SCOSSL_CCM_STAGE_INIT;
    ctx->cbData = 0;
    if (iv)
    {
        if (!scossl_aes_ccm_set_iv_len(ctx, ivlen))
        {
            return SCOSSL_FAILURE;
        }

        ctx->ivlen = ivlen;
        memcpy(ctx->iv, iv, ctx->ivlen);
    }
    if (key)
    {
        scError = SymCryptAesExpandKey(&ctx->key, key, keylen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            return SCOSSL_FAILURE;
        }
    }
    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_aes_ccm_tls(_Inout_ SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                        _Out_writes_bytes_opt_(*outl) unsigned char *out, _Out_ size_t *outl,
                                        _In_reads_bytes_(inl) const unsigned char *in, size_t inl)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PBYTE pbPayload = NULL;
    SIZE_T cbPayload = 0;

    // For TLS we only support in-place en/decryption of an ESP taking the form:
    // IV (8B) || Ciphertext (variable) || ICV (Auth Tag) (8 or 16B)

    // When encrypting, the space for the IV and ICV should be provided by the caller with the
    // plaintext starting 8B from the start of the buffer and ending 8 or 16B from the end
    if (in != out)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-CCM TLS does not support out-of-place operation");
        goto cleanup;
    }
    if (inl < (SIZE_T)EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->taglen)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-CCM TLS buffer too small");
        goto cleanup;
    }
    if (ctx->ccmStage != SCOSSL_CCM_STAGE_INIT)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
            "AES-CCM TLS operation cannot be multi-stage");
        goto cleanup;
    }
    if (ctx->ivlen != EVP_CCM_TLS_IV_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
                         "AES-CCM TLS operation with incorrect IV length");
        goto cleanup;
    }
    if (ctx->taglen != EVP_CCM_TLS_TAG_LEN && ctx->taglen != EVP_CCM8_TLS_TAG_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_TLS, ERR_R_PASSED_INVALID_ARGUMENT,
                         "AES-CCM TLS operation with incorrect tag length");
        goto cleanup;
    }

    pbPayload = out + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    cbPayload = inl - (EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->taglen);

    if (encrypt)
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it from the context
        memcpy(out, ctx->iv + ctx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, EVP_CCM_TLS_EXPLICIT_IV_LEN);

        // Encrypt payload
        SymCryptCcmEncrypt(
            SymCryptAesBlockCipher,
            &ctx->key,
            ctx->iv, ctx->ivlen,
            ctx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload + cbPayload, ctx->taglen);

        *outl = inl;
    }
    else
    {
        // First 8B of ESP payload data are the variable part of the IV (last 8B)
        // Copy it to the context
        memcpy(ctx->iv + ctx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, out, EVP_CCM_TLS_EXPLICIT_IV_LEN);

        // Check ICV
        scError = SymCryptCcmDecrypt(
            SymCryptAesBlockCipher,
            &ctx->key,
            ctx->iv, ctx->ivlen,
            ctx->tlsAad, EVP_AEAD_TLS1_AAD_LEN,
            pbPayload, pbPayload, cbPayload,
            pbPayload + cbPayload, ctx->taglen);
        if (scError != SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }

        *outl = cbPayload;
    }

    return SCOSSL_SUCCESS;
cleanup:
    OPENSSL_cleanse(out, inl);
    return SCOSSL_FAILURE;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_cipher(SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                    unsigned char *out, size_t *outl,
                                    const unsigned char *in, size_t inl)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCBYTE pbAuthData = NULL;
    SIZE_T cbAuthdata = 0;

    if (ctx->tlsAadSet)
    {
        return scossl_aes_ccm_tls(ctx, encrypt, out, outl, in, inl);
    }

    // See SCOSSL_CCM_STAGE definition above - callers to CCM must use the API in a very particular way
    if (ctx->ccmStage == SCOSSL_CCM_STAGE_COMPLETE)
    {
        if (in == NULL)
        {
            if (out != NULL)
            {
                // Expected redundant Finalize call - allow context to be reused but do nothing else
                ctx->ccmStage = SCOSSL_CCM_STAGE_INIT;
            }
            else
            {
                // Special case for openssl speed encrypt loop - set cbData
                ctx->cbData = inl;
                ctx->ccmStage = SCOSSL_CCM_STAGE_SET_CBDATA;
            }
            *outl = 0;
            return SCOSSL_SUCCESS;
        }
        else
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_CIPHER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                "Data provided to CCM after CCM operation is complete");
            return SCOSSL_FAILURE;
        }
    }
    else if (ctx->ccmStage == SCOSSL_CCM_STAGE_INIT)
    {
        if (in != NULL && out == NULL)
        {
            SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_CIPHER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                "AAD provided to CCM before cbData has been set");
            return SCOSSL_FAILURE;
        }

        ctx->cbData = inl;
        ctx->ccmStage = SCOSSL_CCM_STAGE_SET_CBDATA;

        if (in == NULL)
        {
            // Setting cbData for following call which may provide AAD
            *outl = 0;
            return SCOSSL_SUCCESS;
        }
        // otherwise continue so we can perform the en/decryption with no AAD
    }

    if (ctx->ccmStage == SCOSSL_CCM_STAGE_SET_CBDATA)
    {
        if (out == NULL)
        {
            // Auth Data Passed in
            pbAuthData = in;
            cbAuthdata = inl;
        }

        SymCryptCcmInit(
            &ctx->state,
            SymCryptAesBlockCipher,
            &ctx->key,
            ctx->iv, ctx->ivlen,
            pbAuthData, cbAuthdata,
            ctx->cbData,
            ctx->taglen);
        ctx->ccmStage = SCOSSL_CCM_STAGE_SET_AAD;

        if (out == NULL)
        {
            // Auth Data Passed in
            *outl = 0;
            return SCOSSL_SUCCESS;
        }
    }

    if (ctx->ccmStage == SCOSSL_CCM_STAGE_SET_AAD)
    {
        if (encrypt)
        {
            // Encryption
            if (in != NULL)
            {
                SymCryptCcmEncryptPart(&ctx->state, in, out, inl);
            }
            SymCryptCcmEncryptFinal(&ctx->state, ctx->tag, ctx->taglen);
            ctx->ccmStage = SCOSSL_CCM_STAGE_COMPLETE;
        }
        else
        {
            // Decryption
            if (in != NULL)
            {
                SymCryptCcmDecryptPart(&ctx->state, in, out, inl);
            }
            scError = SymCryptCcmDecryptFinal(&ctx->state, ctx->tag, ctx->taglen);
            ctx->ccmStage = SCOSSL_CCM_STAGE_COMPLETE;
            if (scError != SYMCRYPT_NO_ERROR)
            {
                return SCOSSL_FAILURE;
            }
        }
        *outl = inl;
    }

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_get_aead_tag(SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *tag, size_t taglen)
{
    if ((taglen & 1) || taglen < SCOSSL_CCM_MIN_TAG_LENGTH || taglen > SCOSSL_CCM_MAX_TAG_LENGTH ||
        taglen > ctx->taglen || !encrypt)
    {
        return SCOSSL_FAILURE;
    }
    memcpy(tag, ctx->tag, taglen);
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_set_aead_tag(SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *tag, size_t taglen)
{
    if ((taglen & 1) || taglen < SCOSSL_CCM_MIN_TAG_LENGTH || taglen > SCOSSL_CCM_MAX_TAG_LENGTH ||
        (encrypt && tag != NULL))
    {
        return SCOSSL_FAILURE;
    }
    if (tag != NULL)
    {
        memcpy(ctx->tag, tag, taglen);
    }
    ctx->taglen = taglen;

    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_set_iv_len(SCOSSL_CIPHER_CCM_CTX *ctx, size_t ivlen)
{
    if (ivlen < SCOSSL_CCM_MIN_IV_LENGTH || ivlen > SCOSSL_CCM_MAX_IV_LENGTH)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_IV_LEN, ERR_R_PASSED_INVALID_ARGUMENT,
            "SCOSSL only supports [%d-%d] byte IVs for AES-CCM",
            SCOSSL_CCM_MIN_IV_LENGTH, SCOSSL_CCM_MAX_IV_LENGTH);
        return SCOSSL_FAILURE;
    }

    ctx->ivlen = ivlen;
    return SCOSSL_SUCCESS;
}

_Use_decl_annotations_
SCOSSL_STATUS scossl_aes_ccm_set_iv_fixed(SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                          unsigned char *iv, size_t ivlen)
{
    if (ctx->ivlen != EVP_CCM_TLS_IV_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_IV_LEN, ERR_R_PASSED_INVALID_ARGUMENT,
            "set_iv_fixed only works with TLS IV length");
        return SCOSSL_FAILURE;
    }
    if (ivlen == (size_t)-1)
    {
        memcpy(ctx->iv, iv, ctx->ivlen);
        return SCOSSL_SUCCESS;
    }
    if (ivlen != ctx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_IV_FIXED, ERR_R_PASSED_INVALID_ARGUMENT,
            "set_iv_fixed incorrect length");
        return SCOSSL_FAILURE;
    }
    // Set first 4B of IV
    memcpy(ctx->iv, iv, ctx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN);
    // If encrypting, randomly set the last 8B of IV
    if (encrypt &&
        (RAND_bytes(ctx->iv + ctx->ivlen - EVP_CCM_TLS_EXPLICIT_IV_LEN, EVP_CCM_TLS_EXPLICIT_IV_LEN) <= 0))
    {
        return SCOSSL_FAILURE;
    }

    return SCOSSL_SUCCESS;
}

// Returns the tag length on success, and 0 (SCOSSL_FAILURE) on failure
_Use_decl_annotations_
UINT16 scossl_aes_ccm_set_tls1_aad(SCOSSL_CIPHER_CCM_CTX *ctx, INT32 encrypt,
                                   unsigned char *aad, size_t aadlen)
{
    UINT16 tls_buffer_len = 0;
    UINT16 min_tls_buffer_len = 0;
    if (aadlen != EVP_AEAD_TLS1_AAD_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_TLS1_AAD, ERR_R_PASSED_INVALID_ARGUMENT,
            "tls1_aad only works with TLS1 AAD length");
        return SCOSSL_FAILURE;
    }
    if (ctx->taglen != EVP_CCM_TLS_TAG_LEN && ctx->taglen != EVP_CCM8_TLS_TAG_LEN)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_TLS1_AAD, ERR_R_PASSED_INVALID_ARGUMENT,
            "Invalid taglen for TLS");
        return SCOSSL_FAILURE;
    }
    memcpy(ctx->tlsAad, aad, EVP_AEAD_TLS1_AAD_LEN);
    ctx->tlsAadSet = 1;

    if (encrypt)
    {
        // Provided AAD contains len of plaintext + IV (8B)
        min_tls_buffer_len = EVP_CCM_TLS_EXPLICIT_IV_LEN;
    }
    else
    {
        // Provided AAD contains len of ciphertext + IV (8B) + ICV (16B)
        min_tls_buffer_len = EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->taglen;
    }

    tls_buffer_len = SYMCRYPT_LOAD_MSBFIRST16(ctx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2);
    if (tls_buffer_len < min_tls_buffer_len)
    {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_AES_CCM_SET_TLS1_AAD, ERR_R_PASSED_INVALID_ARGUMENT,
            "tls_buffer_len too short");
        return SCOSSL_FAILURE;
    }
    tls_buffer_len -= min_tls_buffer_len;
    SYMCRYPT_STORE_MSBFIRST16(ctx->tlsAad + EVP_AEAD_TLS1_AAD_LEN - 2, tls_buffer_len);

    return ctx->taglen;
}

#ifdef __cplusplus
}
#endif