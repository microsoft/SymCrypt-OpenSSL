//
// SslPlay.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <iostream>
#include <stdio.h>
#include <string.h>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>
#include "sc_ossl.h"

BIO *bio_err = NULL;

void printOpenSSLError(const char* description)
{
    printf("Failure:%s:\n", description);
    BIO_printf(bio_err, "OpenSSL Error:\n");
    ERR_print_errors(bio_err);
    return;
}

const char SeparatorLine[] = "-----------------------------------------------------------------------------------------\n";

void printBytes(char* data, int len, const char* header)
{
     printf("\n%s (%d bytes): ", header, len);
    for (int i = 0; i < len; i++)
    {
         printf("%X",data[i]);
    }
     printf("\n\n");
}

// Largest supported curve is P521 => 66 * 2 + 4 (int headers) + 3 (seq header)
#define SC_OSSL_ECDSA_MAX_DER_SIGNATURE_LEN 139

void TestEcdsa(EC_KEY* key)
{
    unsigned char testHash[] = {
        0x1, 0x54, 0xF, 0x2, 0xC9, 0xC, 0xFF, 0x31,
        0x1, 0x54, 0xF, 0x2, 0xC9, 0xC, 0xFF, 0x31,
        0x1, 0x54, 0xF, 0x2, 0xC9, 0xC, 0xFF, 0x31,
        0x1, 0x54, 0xF, 0x2, 0xC9, 0xC, 0xFF, 0x31
    };
    unsigned char resultBytes[SC_OSSL_ECDSA_MAX_DER_SIGNATURE_LEN] = { 0 };
    bool result = true;
    int currentIteration = 0;
    unsigned int signatureBytesCount = sizeof(resultBytes);
    ECDSA_SIG* ecdsaSig = NULL;
    printf("Command ECDSA_sign\n");
    if( !ECDSA_sign(0, testHash, sizeof(testHash), resultBytes, &signatureBytesCount, key) )
    {
        printOpenSSLError("ECDSA_sign failed\n");
        goto end;
    }
    printf("Command ECDSA_verify\n");
    if( ECDSA_verify(0, testHash, sizeof(testHash), resultBytes, signatureBytesCount, key) != 1 )
    {
        printOpenSSLError("ECDSA_verify failed\n");
        goto end;
    }
    else
    {
        printf("ECDSA_verify Succeeded\n");
    }
    printf("Command ECDSA_do_sign\n");
    ecdsaSig = ECDSA_do_sign(testHash, sizeof(testHash), key);
    if( ecdsaSig == NULL )
    {
        printOpenSSLError("ECDSA_do_sign failed\n");
        goto end;
    }
    printf("Command ECDSA_do_verify\n");
    if( ECDSA_do_verify(testHash, sizeof(testHash), ecdsaSig, key) != 1 ){
        printOpenSSLError("ECDSA_do_verify failed\n");
        goto end;
    }
    else
    {
        printf("ECDSA_do_verify Succeeded\n");
    }
end:
    if( ecdsaSig )
        ECDSA_SIG_free(ecdsaSig);
    return;
}

void TestEccCurve(int nid)
{
    EC_KEY* key = NULL;
    printf("Command EC_KEY_new_by_curve_name\n");
    key = EC_KEY_new_by_curve_name(nid);
    printf("Command EC_KEY_generate_key\n");
    EC_KEY_generate_key(key);
    TestEcdsa(key);
    EC_KEY_free(key);
    return;
}

void TestEcc()
{
    TestEccCurve(NID_X9_62_prime256v1);
    TestEccCurve(NID_secp384r1);
    TestEccCurve(NID_secp521r1);
}

/*
 * Read whole contents of a BIO into an allocated memory buffer and return
 * it.
 */
int bio_to_mem(unsigned char **out, int maxlen, BIO *in)
{
    BIO *mem;
    int len, ret;
    unsigned char tbuf[1024];

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
        return -1;
    for (;;) {
        if ((maxlen != -1) && maxlen < 1024)
            len = maxlen;
        else
            len = 1024;
        len = BIO_read(in, tbuf, len);
        if (len < 0) {
            BIO_free(mem);
            return -1;
        }
        if (len == 0)
            break;
        if (BIO_write(mem, tbuf, len) != len) {
            BIO_free(mem);
            return -1;
        }
        maxlen -= len;

        if (maxlen == 0)
            break;
    }
    ret = BIO_get_mem_data(mem, (char **)out);
    BIO_set_flags(mem, BIO_FLAGS_MEM_RDONLY);
    BIO_free(mem);
    return ret;
}

void TestRsaEncryptDecrypt(
        EVP_PKEY *encryptionKey,
        EVP_PKEY *decryptionKey,
        const char* paddingStr,
        int padding)
{
    printf("\nTesting EVP_PKEY Encrypt/Decrypt Functions: Padding: %s(%d)\n", paddingStr, padding);
    unsigned char plaintext[512];
    size_t plaintext_len = 0;

    EVP_PKEY_CTX *pEncryptContext = NULL;
    unsigned char *encryptedtext = NULL;
    size_t encryptedtext_len = 0;

    EVP_PKEY_CTX *pDecryptContext = NULL;
    unsigned char *decryptedtext = NULL;
    size_t decryptedtext_len = 0;

    if (padding == RSA_NO_PADDING) {
        // PlainText has to be size of modulus of the key
        plaintext_len = EVP_PKEY_size(encryptionKey);
    }
    else
    {
        plaintext_len = 42; // Choosen at whim
    }

    while(!RAND_bytes(plaintext, plaintext_len));

    //
    // Encrypt
    //
    printf("\nTesting EVP_PKEY_encrypt* Functions\n\n");
    printf("Command EVP_PKEY_CTX_new\n");
    pEncryptContext = EVP_PKEY_CTX_new(encryptionKey, NULL);
    if (pEncryptContext == NULL)
    {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_encrypt_init\n");
    if (EVP_PKEY_encrypt_init(pEncryptContext) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
    if (EVP_PKEY_CTX_set_rsa_padding(pEncryptContext, padding) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    /* Determine buffer length */
    printf("Command EVP_PKEY_encrypt\n");
    if (EVP_PKEY_encrypt(
            pEncryptContext,
            NULL,
            &encryptedtext_len,
            plaintext,
            plaintext_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    encryptedtext = (unsigned char *)OPENSSL_zalloc(encryptedtext_len);
    printf("Command EVP_PKEY_encrypt\n");
    if (EVP_PKEY_encrypt(
            pEncryptContext,
            encryptedtext,
            &encryptedtext_len,
            plaintext,
            plaintext_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }

    printf("PlainText:\n");
    BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
    printf("EncryptedText:\n");
    BIO_dump_fp (stdout, (const char *)encryptedtext, encryptedtext_len);

    //
    // Decrypt with Private Key
    //

    printf("\nTesting EVP_PKEY_decrypt* Functions\n\n");

    printf("Command EVP_PKEY_encrypt\n");
    pDecryptContext = EVP_PKEY_CTX_new(decryptionKey, NULL);
    if (pDecryptContext == NULL) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_decrypt_init\n");
    if (EVP_PKEY_decrypt_init(pDecryptContext) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
    if (EVP_PKEY_CTX_set_rsa_padding(pDecryptContext, padding) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    /* Determine buffer length */
    printf("Command EVP_PKEY_decrypt\n");
    if (EVP_PKEY_decrypt(pDecryptContext, NULL, &decryptedtext_len, (const unsigned char*)encryptedtext, encryptedtext_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    decryptedtext = (unsigned char *)OPENSSL_zalloc(decryptedtext_len);
    printf("Command EVP_PKEY_decrypt\n");
    if (EVP_PKEY_decrypt(pDecryptContext, decryptedtext, &decryptedtext_len, (const unsigned char*)encryptedtext, encryptedtext_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("DecryptedText:\n");
    BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

    if (decryptedtext_len != plaintext_len ||
        memcmp(plaintext, decryptedtext, decryptedtext_len) != 0)
    {
        printf("PlainText and DecryptedText don't match\n");
        goto end;
    }
    else
    {
        printf("PlainText and DecryptedText match\n");
    }

end:
    if (encryptedtext)
        OPENSSL_free(encryptedtext);
    if (decryptedtext)
        OPENSSL_free(decryptedtext);
    if (pEncryptContext)
        EVP_PKEY_CTX_free(pEncryptContext);
    if (pDecryptContext)
        EVP_PKEY_CTX_free(pDecryptContext);
    printf("%s", SeparatorLine);
    return;
}

void TestRsaSignVerify(
        EVP_PKEY *signingKey,
        EVP_PKEY *verificationKey,
        const char* paddingStr,
        int padding,
        const char* digestStr,
        const EVP_MD *digest,
        size_t digest_length
        )
{
    printf("\nTesting EVP_PKEY Sign/Verify Functions: Padding: %s(%d), digest: %s\n", paddingStr, padding, digestStr);
    EVP_PKEY_CTX *pSignContext = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    EVP_PKEY_CTX *pVerifyContext = NULL;
    unsigned char message_digest[64];
    size_t message_digest_len = digest_length;
    int ret = 0;

    while(!RAND_bytes(message_digest, digest_length));

    printf("\nTesting EVP_PKEY_sign* Functions - PKCS1 PADDING\n\n");
    printf("Command EVP_PKEY_CTX_new\n");
    pSignContext = EVP_PKEY_CTX_new(signingKey, NULL);
    if (pSignContext == NULL) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_sign_init\n");
    if (EVP_PKEY_sign_init(pSignContext) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
    if (EVP_PKEY_CTX_set_rsa_padding(pSignContext, padding) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_signature_md\n");
    if (EVP_PKEY_CTX_set_signature_md(pSignContext, digest) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    if (padding == RSA_PKCS1_PSS_PADDING)
    {
        printf("Command EVP_PKEY_CTX_set_rsa_pss_saltlen RSA_PSS_SALTLEN_DIGEST\n");
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pSignContext, RSA_PSS_SALTLEN_DIGEST) <= 0)
        {
            printOpenSSLError("");
            goto end;
        }
    }
    /* Determine buffer length */
    printf("Command EVP_PKEY_sign\n");
    if (EVP_PKEY_sign(pSignContext, NULL, &signature_len, message_digest, message_digest_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    signature = (unsigned char *)OPENSSL_zalloc(signature_len);
    if (!signature) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_sign\n");
    if (EVP_PKEY_sign(pSignContext, signature, &signature_len, message_digest, message_digest_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }

    printf("Message Digest:\n");
    BIO_dump_fp (stdout, (const char *)message_digest, message_digest_len);

    printf("Signature:\n");
    BIO_dump_fp (stdout, (const char *)signature, signature_len);

    //
    // Verify with Public Key
    //

    printf("\nTesting EVP_PKEY_verify* Functions\n\n");

    printf("Command EVP_PKEY_sign\n");
    pVerifyContext = EVP_PKEY_CTX_new(verificationKey, NULL);
    if (pVerifyContext == NULL) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_verify_init\n");
    if (EVP_PKEY_verify_init(pVerifyContext) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
    if (EVP_PKEY_CTX_set_rsa_padding(pVerifyContext, padding) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_PKEY_CTX_set_signature_md\n");
    if (EVP_PKEY_CTX_set_signature_md(pVerifyContext, digest) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    if (padding == RSA_PKCS1_PSS_PADDING)
    {
        printf("Command EVP_PKEY_CTX_set_rsa_pss_saltlen RSA_PSS_SALTLEN_DIGEST\n");
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pVerifyContext, RSA_PSS_SALTLEN_DIGEST) <= 0)
        {
            printOpenSSLError("");
            goto end;
        }
    }
    printf("Command EVP_PKEY_verify\n");
    ret = EVP_PKEY_verify(pVerifyContext, signature, signature_len, message_digest, message_digest_len);
    if (ret != 1)
    {
        printf("EVP_PKEY_verify failed\n");
        goto end;
    } else {
        printf("EVP_PKEY_verify succeeded\n");
    }

end:
    if (pSignContext)
        EVP_PKEY_CTX_free(pSignContext);
    if (pVerifyContext)
        EVP_PKEY_CTX_free(pVerifyContext);
    if (signature)
        OPENSSL_free(signature);
    printf("%s", SeparatorLine);
    return;
}

void TestRsaDigestSignVerify(
        EVP_PKEY *signingKey,
        EVP_PKEY *verificationKey,
        const char* paddingStr,
        int padding,
        const char* digestStr,
        const EVP_MD *digest
        )
{
    printf("\nTesting EVP_PKEY DigestSign/DigestVerify Functions: digest: %s\n", digestStr);
    EVP_MD_CTX* RSASignCtx = NULL;
    EVP_MD_CTX* RSAVerifyCtx = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    const unsigned char plaintext[] =
        "Message for testing EVP_PKEY_Encrypt* APIs for encryption/decryption";
    size_t plaintext_len = sizeof(plaintext);
    const char message[] = "My EVP_DigestSign Message";
    size_t message_len = sizeof(message);
    bool authentic = false;
    int AuthStatus = 0;
    EVP_PKEY_CTX *pSigningKeyContext = NULL;
    EVP_PKEY_CTX *pVerificationKeyContext = NULL;

    printf("\nTesting DigestSign* Functions\n\n");

    printf("Command EVP_MD_CTX_new\n");
    RSASignCtx = EVP_MD_CTX_new();
    printf("Command EVP_DigestSignInit\n");
    if (EVP_DigestSignInit(RSASignCtx,&pSigningKeyContext, digest, NULL, signingKey)<=0) {
        printOpenSSLError("");
        goto end;
    }

    if (paddingStr) {
        printf("Setting Padding: %s(%d)\n", paddingStr, padding);
        printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
        if (EVP_PKEY_CTX_set_rsa_padding(pSigningKeyContext, padding)<=0) {
            printOpenSSLError("");
            goto end;
        }
        // if (EVP_PKEY_CTX_set_rsa_mgf1_md(pSigningKeyContext, EVP_sha512())<=0) {
        //     printOpenSSLError("");
        //     goto end;
        // }
    }

    printf("Command EVP_DigestSignUpdate\n");
    if (EVP_DigestSignUpdate(RSASignCtx, message, message_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_DigestSignFinal\n");
    if (EVP_DigestSignFinal(RSASignCtx, NULL, &signature_len) <=0) {
        printOpenSSLError("");
        goto end;
    }
    printf("signature_length= %ld\n", signature_len);
    signature = (unsigned char*)OPENSSL_zalloc(signature_len);
    printf("Command EVP_DigestSignFinal\n");
    if (EVP_DigestSignFinal(RSASignCtx, signature, &signature_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }

    printf("Message:\n");
    BIO_dump_fp (stdout, (const char *)message, message_len);

    printf("Signature:\n");
    BIO_dump_fp (stdout, (const char *)signature, signature_len);

    //
    // DigestVerify
    //
    printf("\nTesting EVP_DigestVerify* Functions\n\n");
    printf("Command EVP_MD_CTX_new\n");
    RSAVerifyCtx = EVP_MD_CTX_new();
    printf("Verify Signature\n");
    printf("Command EVP_DigestVerifyInit\n");
    if (EVP_DigestVerifyInit(RSAVerifyCtx,&pVerificationKeyContext, digest,NULL,verificationKey)<=0) {
        printOpenSSLError("");
        goto end;
    }
    if (paddingStr) {
        printf("Setting Padding: %s(%d)\n", paddingStr, padding);
        printf("Command EVP_PKEY_CTX_set_rsa_padding\n");
        if (EVP_PKEY_CTX_set_rsa_padding(pVerificationKeyContext, padding)<=0) {
            printOpenSSLError("");
            goto end;
        }
        // if (EVP_PKEY_CTX_set_rsa_mgf1_md(pVerificationKeyContext, EVP_sha512())<=0) {
        //     printOpenSSLError("");
        //     goto end;
        // }
    }
    printf("Command EVP_DigestVerifyUpdate\n");
    if (EVP_DigestVerifyUpdate(RSAVerifyCtx, message, message_len) <= 0) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_DigestVerifyFinal\n");
    AuthStatus = EVP_DigestVerifyFinal(RSAVerifyCtx, signature, signature_len);
    if (AuthStatus==1) {
        authentic = true;
    } else if(AuthStatus==0){
        authentic = false;
    } else{
        authentic = false;
    }
    if (authentic) {
         printf("Signature Verified\n");
    } else {
         printf("Signature Not Verified\n");
    }

end:
    if (RSASignCtx)
        EVP_MD_CTX_free(RSASignCtx);
    if (RSAVerifyCtx)
        EVP_MD_CTX_free(RSAVerifyCtx);
    if (signature)
        OPENSSL_free(signature);
    return;
}

void TestRsaSealOpen(
        EVP_PKEY *sealKey,
        EVP_PKEY *openKey,
        const char* cipherStr,
        const EVP_CIPHER *cipher
        )
{
    printf("\nTesting EVP_PKEY Seal/Open Functions: Cipher: %s\n", cipherStr);
    EVP_CIPHER_CTX *rsaSealCtx = NULL;
    EVP_CIPHER_CTX *rsaOpenCtx = NULL;
    static const unsigned char message[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t message_len = sizeof(message);
    unsigned char *encKey = NULL;
    int encKey_len = 0;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char ciphertext[32], plaintext[16];
    int ciphertext_len = 0;
    int encryptedBlockLen = 0;

    int decryptedMessageLen = 0;
    int decryptedBlockLen = 0;
    unsigned char *decryptedMessage = NULL;

    memset(iv, 0, EVP_MAX_IV_LENGTH);
    memset(ciphertext, 0, 32);
    memset(plaintext, 0, 16);

    printf("\nTesting EVP_Seal* Functions\n\n");

    printf("Command EVP_CIPHER_CTX_new\n");
    rsaSealCtx = EVP_CIPHER_CTX_new();

    printf("Command EVP_CIPHER_CTX_init\n");
    if (EVP_CIPHER_CTX_init(rsaSealCtx) != 1) {
        printOpenSSLError("");
        goto end;
    }
    encKey = (unsigned char *) OPENSSL_zalloc(EVP_PKEY_size(sealKey));
    printf("Command EVP_SealInit\n");
    if (EVP_SealInit(rsaSealCtx, cipher, &encKey, &encKey_len, iv, &sealKey, 1) != 1) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_SealUpdate\n");
    if (EVP_SealUpdate(rsaSealCtx, ciphertext, &ciphertext_len, message, message_len) != 1) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_SealFinal\n");
    if (EVP_SealFinal(rsaSealCtx, ciphertext + ciphertext_len, &encryptedBlockLen) != 1) {
        printOpenSSLError("");
        goto end;
    }
    ciphertext_len += encryptedBlockLen;

    printf("Message:\n");
    BIO_dump_fp (stdout, (const char *)message, message_len);

    printf("Sealed output:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    //
    // Open
    //

    printf("\nTesting EVP_Open* Functions\n\n");
    printf("Command EVP_CIPHER_CTX_new\n");
    rsaOpenCtx = EVP_CIPHER_CTX_new();

    printf("Command EVP_CIPHER_CTX_init\n");
    if (EVP_CIPHER_CTX_init(rsaOpenCtx) != 1) {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_OpenInit\n");
    if (EVP_OpenInit(rsaOpenCtx, cipher, encKey, encKey_len, iv, openKey) != 1) {
        printOpenSSLError("");
        goto end;
    }
    decryptedMessage = (unsigned char *) OPENSSL_zalloc(ciphertext_len + EVP_MAX_IV_LENGTH);
    // the length of the encrypted message
    decryptedMessageLen = 0;
    decryptedBlockLen = 0;
    // decrypt message with AES secret
    printf("Command EVP_OpenUpdate\n");
    if (EVP_OpenUpdate(rsaOpenCtx, decryptedMessage, &decryptedMessageLen, ciphertext, ciphertext_len) != 1) {
        printOpenSSLError("");
        goto end;
    }
    // finalize by decrypting padding
    printf("Command EVP_OpenFinal\n");
    EVP_OpenFinal(rsaOpenCtx, decryptedMessage + decryptedMessageLen, &decryptedBlockLen);
    decryptedMessageLen += decryptedBlockLen;

    printf("Opened Bytes:\n");
    BIO_dump_fp (stdout, (const char *)decryptedMessage, decryptedMessageLen);

    if (message_len != decryptedMessageLen ||
        memcmp(message,decryptedMessage, decryptedMessageLen) != 0)
    {
        printf("Decrypted/Opened text don't match original message\n");
    }
    else
    {
        printf("Decrypted/Opened text match original message\n");
    }

end:
    if (encKey)
        OPENSSL_free(encKey);
    if (rsaSealCtx)
        EVP_CIPHER_CTX_free(rsaSealCtx);
    if (rsaOpenCtx)
        EVP_CIPHER_CTX_free(rsaOpenCtx);
    if (decryptedMessage)
        OPENSSL_free(decryptedMessage);
    printf("%s", SeparatorLine);
    return;
}

int CreateKeys(int id, int modulus, uint32_t exponent, char* publicFileName, char* privateFileName, EVP_PKEY** publicKey, EVP_PKEY** privateKey)
{
    BIGNUM* exponent_bn = NULL;
    EVP_PKEY* pKey = NULL;
    EVP_PKEY_CTX* pKeyContext = NULL;
    BIO *privateBIO = NULL;
    BIO *publicBIO = NULL;
    FILE *fp = NULL;
    int ret = 0;

    //
    // Generate RSA Key
    //
    printf("Command EVP_PKEY_CTX_new_id\n");
    pKeyContext = EVP_PKEY_CTX_new_id(id, NULL);
    if (pKeyContext == NULL) {
        printOpenSSLError("");
        goto err;
    }
    printf("Command EVP_PKEY_keygen_init\n");
    if (EVP_PKEY_keygen_init(pKeyContext) <= 0) {
        printOpenSSLError("");
        goto err;
    }
    printf("Command EVP_PKEY_CTX_set_rsa_keygen_bits\n");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pKeyContext, modulus) <= 0) {
        printOpenSSLError("");
        goto err;
    }
    exponent_bn = BN_new();
    BN_set_word(exponent_bn, exponent);
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(pKeyContext, exponent_bn) <= 0) {
        printOpenSSLError("");
        goto err;
    }
    printf("Command EVP_PKEY_keygen\n");
    if (EVP_PKEY_keygen(pKeyContext, &pKey) != 1) {
        printOpenSSLError("");
        goto err;
    }

    printf("%s", SeparatorLine);

    //
    // Export Public Key
    //
    printf("\nTesting Exporting Public Key\n\n");
    publicBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBIO, pKey);
    fp = fopen(publicFileName, "w");
    PEM_write_PUBKEY(fp, pKey);
    PEM_write_PUBKEY(stdout, pKey);
    fflush(fp);
    fclose(fp);
    BIO_free(publicBIO);
    printf("%s", SeparatorLine);

    //
    // Export Private Key
    //
    printf("\nTesting Exporting Private Key\n\n");
    privateBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateBIO, pKey, NULL, NULL, 0, 0, NULL);
    fp = fopen(privateFileName, "w");
    PEM_write_PrivateKey(fp, pKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_PrivateKey(stdout, pKey, NULL, NULL, 0, NULL, NULL);
    fflush(fp);
    fclose(fp);
    BIO_free(privateBIO);
    printf("%s", SeparatorLine);

    //
    // Import Public Key
    //
    printf("\nTesting Importing Public Key\n\n");
    fp = fopen(publicFileName, "r");
    *publicKey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fflush(fp);
    fclose(fp);
    printf("%s", SeparatorLine);

    //
    // Import Private Key
    //
    printf("\nTesting Importing Private Key\n\n");
    fp = fopen(privateFileName, "r");
    *privateKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fflush(fp);
    fclose(fp);
    printf("%s", SeparatorLine);

    end:

    if (pKeyContext)
        EVP_PKEY_CTX_free(pKeyContext);
    if (pKey)
        EVP_PKEY_free(pKey);
    return ret;

    err:
    ret = -1;
    goto end;
}

void TestRsaEvp(int modulus, uint32_t exponent)
{
    printf("\nTest RSA: Modulus: %d, Exponent: %d\n\n", modulus, exponent);
    EVP_PKEY *privateKey = NULL;
    EVP_PKEY *privateKeyPss = NULL;
    EVP_PKEY *publicKey = NULL;
    EVP_PKEY *publicKeyPss = NULL;
    char publicFileName[1024];
    char publicPssFileName[1024];
    char privateFileName[1024];
    char privatePssFileName[1024];

    // Initialize Data
    sprintf(publicFileName, "%s_%d.pem", "public",  modulus);
    sprintf(privateFileName, "%s_%d.pem", "private",  modulus);
    sprintf(publicPssFileName, "%s_pss_%d.pem", "public",  modulus);
    sprintf(privatePssFileName, "%s_pss_%d.pem", "private",  modulus);

    printf("\nTesting EVP_PKEY_keygen* Functions\n\n");
    if( CreateKeys(EVP_PKEY_RSA, modulus, exponent, publicFileName, privateFileName, &publicKey, &privateKey) )
    {
        goto end;
    }
    if( CreateKeys(EVP_PKEY_RSA_PSS, modulus, exponent, publicPssFileName, privatePssFileName, &publicKeyPss, &privateKeyPss) )
    {
        goto end;
    }

    //
    // Encrypt/Decrypt
    //
    TestRsaEncryptDecrypt(publicKey, privateKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING);
    TestRsaEncryptDecrypt(publicKey, privateKey, "RSA_PKCS1_OAEP_PADDING", RSA_PKCS1_OAEP_PADDING);
    TestRsaEncryptDecrypt(publicKey, privateKey, "RSA_SSLV23_PADDING", RSA_SSLV23_PADDING);
    TestRsaEncryptDecrypt(publicKey, privateKey, "RSA_NO_PADDING", RSA_NO_PADDING);
    printf("%s", SeparatorLine);

    //
    // Sign/Verify
    //
    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_MD5", EVP_md5(), 16);
    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha1", EVP_sha1(), 20);
    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha256", EVP_sha256(), 32);
    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha384", EVP_sha384(), 48);
    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha512", EVP_sha512(), 64);
    printf("%s", SeparatorLine);

    TestRsaSignVerify(privateKey, publicKey, "RSA_PKCS1_PSS_PADDING", RSA_PKCS1_PSS_PADDING, "EVP_sha256", EVP_sha256(), 32);
    TestRsaSignVerify(privateKeyPss, publicKeyPss, "RSA_PKCS1_PSS_PADDING", RSA_PKCS1_PSS_PADDING, "EVP_sha256", EVP_sha256(), 32);
    printf("%s", SeparatorLine);

    //
    // DigestSign/DigestVerify
    //
    TestRsaDigestSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_MD5", EVP_md5());
    TestRsaDigestSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha1", EVP_sha1());
    TestRsaDigestSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha256", EVP_sha256());
    TestRsaDigestSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha384", EVP_sha384());
    TestRsaDigestSignVerify(privateKey, publicKey, "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING, "EVP_sha512", EVP_sha512());

    printf("%s", SeparatorLine);

    //
    // Seal/Open
    //
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_128_cbc", EVP_aes_128_cbc());
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_192_cbc", EVP_aes_192_cbc());
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_256_cbc", EVP_aes_256_cbc());
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_128_ecb", EVP_aes_128_ecb());
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_192_ecb", EVP_aes_192_ecb());
    TestRsaSealOpen(publicKey, privateKey, "EVP_aes_256_ecb", EVP_aes_256_ecb());
    printf("%s", SeparatorLine);

    printf("\nCompleted Test RSA: Modulus: %d, Exponent: %d\n\n", modulus, exponent);
    printf("%s", SeparatorLine);

end:

    if (publicKey)
        EVP_PKEY_free(publicKey);
    if (privateKey)
        EVP_PKEY_free(privateKey);
    if (publicKeyPss)
        EVP_PKEY_free(publicKeyPss);
    if (privateKeyPss)
        EVP_PKEY_free(privateKeyPss);
    printf("%s", SeparatorLine);
    return;
}

void TestRsaEvpAll()
{
    TestRsaEvp(1024, 65537);
    TestRsaEvp(2048, 65537);
    TestRsaEvp(3072, 65537);
    TestRsaEvp(4096, 65537);
    printf("%s", SeparatorLine);

}

bool TestDigest(const char* digestname)
{
    bool result = false;
    EVP_MD_CTX *mdctx;
    char mess1[] = "Test Message1234567";
    char mess2[] = "Hello World";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

     printf("\nTestDigest: %s\n\n", digestname);

    const EVP_MD *md = EVP_get_digestbyname(digestname);
    if (md == NULL)
    {
         printf("No Digest found for %s\n", digestname);
        goto end;
    }

    printf("Command EVP_MD_CTX_new\n");
    mdctx = EVP_MD_CTX_new();
    printf("Command EVP_DigestInit_ex\n");
    EVP_DigestInit_ex(mdctx, md, NULL);
    printf("Command EVP_DigestUpdate\n");
    EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
    printf("Command EVP_DigestUpdate\n");
    EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
    printf("Command EVP_DigestFinal_ex\n");
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    printf("Command EVP_MD_CTX_free\n");
    EVP_MD_CTX_free(mdctx);

    printf("Digest (%s)  : \t", digestname);
    for (i = 0; i < md_len; i++)
         printf("%02x", md_value[i]);
    printf("\n");
    result = true;
end:
    printf("%s", SeparatorLine);
    return result;
}

void TestDigests()
{
    EVP_MD *md = NULL;
    char mess1[] = "Test Message1234567";
    char mess2[] = "Hello World";
    unsigned int md_len=32, i;

    TestDigest("MD5");
    TestDigest("SHA1");
    TestDigest("SHA224");
    TestDigest("SHA256");
    TestDigest("SHA384");
    TestDigest("SHA512");

    unsigned char md1[SHA256_DIGEST_LENGTH]; // 32 bytes
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, mess1, strlen(mess1));
    SHA256_Update(&context, mess2, strlen(mess2));
    SHA256_Final(md1, &context);
    printf("\nSHA256 Digest using Lower level API's is: ");
    for (i = 0; i < md_len; i++)
         printf("%02x", md1[i]);
    printf("\n");
    printf("%s", SeparatorLine);
    return;
}

int encrypt(const EVP_CIPHER *cipher, unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    printf("Command EVP_CIPHER_CTX_new\n");
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_EncryptInit_ex\n");
    if(!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_EncryptUpdate\n");
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        printOpenSSLError("");
        goto end;
    }
    ciphertext_len = len;
    printf("Command EVP_EncryptFinal_ex\n");
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printOpenSSLError("");
        goto end;
    }
    printf("len %d\n", len);
    ciphertext_len += len;
end:
    EVP_CIPHER_CTX_free(ctx);
    printf("%s", SeparatorLine);
    return ciphertext_len;
}

int decrypt(const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    printf("Command EVP_CIPHER_CTX_new\n");
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_DecryptInit_ex\n");
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        printOpenSSLError("");
        goto end;
    }
    printf("Command EVP_DecryptUpdate\n");
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        printOpenSSLError("");
        goto end;
    }
    plaintext_len = len;
    printf("Command EVP_DecryptFinal_ex\n");
    if(!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        printOpenSSLError("");
        goto end;
    }
    plaintext_len += len;

end:
    EVP_CIPHER_CTX_free(ctx);
    printf("%s", SeparatorLine);
    return plaintext_len;
}

bool TestAesCipher(
    const char* ciphername,
    const EVP_CIPHER *cipher,
    unsigned char *key,
    int key_length,
    unsigned char *iv,
    int iv_length,
    unsigned char* plaintext,
    int plaintext_len)
{
    bool result = false;
    unsigned char ciphertext[8192];
    int ciphertext_len = 0;
    unsigned char decryptedtext[8300];
    int decryptedtext_len = 0;

    printf("\nTestAesCipher: %s\n\n", ciphername);

    printf("Key Bytes:\n");
    BIO_dump_fp (stdout, (const char *)key, key_length);

    printf("IV:\n");
    BIO_dump_fp (stdout, (const char *)iv, iv_length);

    printf("PlainText:\n");
    BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(cipher, plaintext, plaintext_len, key, iv, ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(cipher, ciphertext, ciphertext_len, key, iv,
        decryptedtext);

    /* Show the decrypted text */
     printf("DecryptedText:\n");
    BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

    if (decryptedtext_len != plaintext_len ||
        memcmp(plaintext, decryptedtext, decryptedtext_len) != 0)
    {
        printf("PlainText and DecryptedText don't match\n");
        goto end;
    }
    else
    {
        printf("PlainText and DecryptedText match\n");
    }

    result = true;
end:
    /* Clean up */
    EVP_cleanup();
    printf("%s", SeparatorLine);
    return result;
}

void TestAesCbc()
{
    unsigned char plaintext[8192];
    int plaintext_len = 70;
    unsigned char iv[16];
    unsigned char key[32];

    while(!RAND_bytes(key, 32));
    while(!RAND_bytes(iv, 16));
    while(!RAND_bytes(plaintext, plaintext_len));

    TestAesCipher("EVP_aes_128_cbc", EVP_aes_128_cbc(), key, 16, iv, 16, plaintext, plaintext_len);
    TestAesCipher("EVP_aes_192_cbc", EVP_aes_192_cbc(), key, 24, iv, 16, plaintext, plaintext_len);
    TestAesCipher("EVP_aes_256_cbc", EVP_aes_256_cbc(), key, 32, iv, 16, plaintext, plaintext_len);


    printf("%s", SeparatorLine);
    return;
}

void TestAesEcb()
{
    unsigned char plaintext[8192];
    int plaintext_len = 70;
    unsigned char iv[16];
    unsigned char key[32];

    while(!RAND_bytes(key, 32));
    while(!RAND_bytes(iv, 16));
    while(!RAND_bytes(plaintext, plaintext_len));

    TestAesCipher("EVP_aes_128_ecb", EVP_aes_128_ecb(), key, 16, iv, 16, plaintext, plaintext_len);
    TestAesCipher("EVP_aes_192_ecb", EVP_aes_192_ecb(), key, 24, iv, 16, plaintext, plaintext_len);
    TestAesCipher("EVP_aes_256_ecb", EVP_aes_256_ecb(), key, 32, iv, 16, plaintext, plaintext_len);


    printf("%s", SeparatorLine);
    return;
}

void TestAesXts()
{
    unsigned char plaintext[8192];
    int plaintext_len = 64;
    unsigned char iv[8];
    unsigned char key[64];

    while(!RAND_bytes(key, 64));
    while(!RAND_bytes(iv, 8));
    while(!RAND_bytes(plaintext, plaintext_len));

    TestAesCipher("EVP_aes_128_xts", EVP_aes_128_xts(), key, 32, iv, 8, plaintext, plaintext_len);
    TestAesCipher("EVP_aes_256_xts", EVP_aes_256_xts(), key, 64, iv, 8, plaintext, plaintext_len);

    printf("%s", SeparatorLine);
    return;
}


/* AES-GCM test data from NIST public test vectors */

static unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
    0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};
static unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};
static unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b, 0xf2, 0xa5
};
static unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde
};
static unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e, 0xb9, 0xf2, 0x17, 0x36
};
static unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62, 0x98, 0xf7, 0x7e, 0x0c
};

int encrypt_gcm(
    const EVP_CIPHER *cipher, unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
    unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len=0, ciphertext_len=0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printOpenSSLError("");
        goto end;
    }
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        printOpenSSLError("");
        goto end;
    }
    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printOpenSSLError("");
        goto end;
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary */
    /* encrypt in block lengths of 16 bytes */
    while(ciphertext_len <= plaintext_len-16) {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, 16))
        {
            printOpenSSLError("");
            goto end;
        }
        ciphertext_len+=len;
    }
    if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, plaintext_len-ciphertext_len)) {
        printOpenSSLError("");
        goto end;
    }
    ciphertext_len+=len;
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        printOpenSSLError("");
        goto end;
    }
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        printOpenSSLError("");
        goto end;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
end:
    printf("%s", SeparatorLine);
    return ciphertext_len;
}

int decrypt_gcm(
    const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
    unsigned char *key, unsigned char *iv, unsigned char *decryptedtext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len=0, decryptedtext_len=0, ret;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printOpenSSLError("");
        goto end;
    }
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        printOpenSSLError("");
        goto end;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printOpenSSLError("");
        goto end;
    }
    /* Provide the message to be decrypted, and obtain the decryptedtext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
     while(decryptedtext_len <= ciphertext_len-16)
     {
        if(1!=EVP_DecryptUpdate(ctx, decryptedtext+decryptedtext_len, &len, ciphertext+decryptedtext_len, 16))
        {
            printOpenSSLError("");
            goto end;
        }
        decryptedtext_len+=len;
    }
    if(1!=EVP_DecryptUpdate(ctx, decryptedtext+decryptedtext_len, &len, ciphertext+decryptedtext_len, ciphertext_len-decryptedtext_len))
    {
        printOpenSSLError("");
        goto end;
    }
    decryptedtext_len+=len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        printOpenSSLError("");
        goto end;
    }
    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, decryptedtext + decryptedtext_len, &len);
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0)
    {
        /* Success */
        //decryptedtext_len += len;
        return decryptedtext_len;
    } else {
        /* Verify failed */
        return -1;
    }
end:

    printf("%s", SeparatorLine);
    return 0;
}

void TestAesGcmCipher(
    const char* ciphername, const EVP_CIPHER *cipher, unsigned char *key, int key_length,
    unsigned char *iv, int iv_length, unsigned char *aad, int aad_length, unsigned char* plaintext,
    int plaintext_len)
{
    unsigned char ciphertext[8192];
    int ciphertext_len = 0;
    unsigned char decryptedtext[8300];
    int decryptedtext_len = 0;
    unsigned char tag[100];
    printf("\nTestAesGcmCipher: %s\n\n", ciphername);
    printf("Key Bytes:\n");
    BIO_dump_fp (stdout, (const char *)key, key_length);
    printf("IV:\n");
    BIO_dump_fp (stdout, (const char *)iv, iv_length);
    printf("AAD:\n");
    BIO_dump_fp (stdout, (const char *)aad, aad_length);
    printf("PlainText:\n");
    BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
    /* Encrypt the plaintext */
    ciphertext_len = encrypt_gcm(cipher, plaintext, plaintext_len, aad, aad_length, key, iv, ciphertext, tag);
    /* Do something useful with the ciphertext here */
    printf("Ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    printf("Tag:\n");
    BIO_dump_fp (stdout, (const char *)tag, 16);
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt_gcm(cipher, ciphertext, ciphertext_len, aad, aad_length, key, iv, decryptedtext, tag);
    /* Show the decrypted text */
    printf("DecryptedText:\n");
    BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);
    if (decryptedtext_len != plaintext_len ||
        memcmp(plaintext, decryptedtext, decryptedtext_len) != 0)
    {
         printf("PlainText and DecryptedText don't match\n");
    }
    else
    {
         printf("PlainText and DecryptedText match\n");
    }

    printf("%s", SeparatorLine);
    return;
}

void
TestAesGcmGeneric()
{
    unsigned char plaintext[8192];
    int plaintext_len = 70;
    unsigned char iv[12]; // Symcrypt only support 12 byte Nonce for GCM
    unsigned char key[32];
    unsigned char aad[32];

    while(!RAND_bytes(key, 32));
    while(!RAND_bytes(iv, 12));
    while(!RAND_bytes(aad, 32));
    while(!RAND_bytes(plaintext, plaintext_len));

    TestAesGcmCipher("EVP_aes_128_gcm", EVP_aes_128_gcm(), key, 16, iv, 12, aad, 16, plaintext, plaintext_len);
    TestAesGcmCipher("EVP_aes_192_gcm", EVP_aes_192_gcm(), key, 24, iv, 12, aad, 16, plaintext, plaintext_len);
    TestAesGcmCipher("EVP_aes_256_gcm", EVP_aes_256_gcm(), key, 32, iv, 12, aad, 16, plaintext, plaintext_len);

    // Test Nist Curves
    TestAesGcmCipher("EVP_aes_256_gcm", EVP_aes_256_gcm(), gcm_key, 32, gcm_iv, 12, gcm_aad, 16, gcm_pt, 16);

    printf("%s", SeparatorLine);
    return;
}

void TestCiphers()
{
    TestAesCbc();
    TestAesEcb();
    TestAesGcmGeneric();
    TestAesXts();
    printf("%s", SeparatorLine);

}

void TestHKDF(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[20];
    size_t outlen;
    int i;
    unsigned char salt[] = "0123456789";
    unsigned char key[] = "012345678901234567890123456789";
    unsigned char info[] = "infostring";
    const unsigned char expected[] = {
        0xe5, 0x07, 0x70, 0x7f, 0xc6, 0x78, 0xd6, 0x54, 0x32, 0x5f, 0x7e, 0xc5,
        0x7b, 0x59, 0x3e, 0xd8, 0x03, 0x6b, 0xed, 0xca
    };
    size_t expectedlen = sizeof(expected);

    printf("\n Testing HKDF \n\n");

    printf("Command EVP_PKEY_CTX_new_id\n");
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        printOpenSSLError("");
        goto end;
    }

    /* We do this twice to test reuse of the EVP_PKEY_CTX */
    for (i = 0; i < 2; i++) {
        outlen = sizeof(out);
        memset(out, 0, outlen);

        printf("Command EVP_PKEY_derive_init\n");
        if (EVP_PKEY_derive_init(pctx) <= 0)
        {
            printOpenSSLError("EVP_PKEY_derive_init");
            goto end;
        }
        printf("Command EVP_PKEY_CTX_set_hkdf_md\n");
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_set_hkdf_md");
            goto end;
        }
        printf("Command EVP_PKEY_CTX_set1_hkdf_salt\n");
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt) - 1) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt");
            goto end;
        }
        printf("Command EVP_PKEY_CTX_set1_hkdf_key\n");
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, sizeof(key) - 1) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key");
            goto end;
        }
        printf("Command EVP_PKEY_CTX_add1_hkdf_info\n");
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info");
            goto end;
        }
        printf("Command EVP_PKEY_derive\n");
        if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
            printOpenSSLError("EVP_PKEY_derive");
            goto end;
        }

        printBytes((char *)out, outlen, "Output KDF");
        printBytes((char *)expected, expectedlen, "Expected KDF");

        if ((outlen != expectedlen) ||
            (memcmp(out, expected, expectedlen) != 0)) {
            printf("\n KDF didn't derive the expected values\n");
        }
        else {
            printf("KDF produced the right value\n");
        }
    }

 end:
    EVP_PKEY_CTX_free(pctx);
    printf("%s", SeparatorLine);
    return;
}

void TestTls1Prf(void)
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[16];
    size_t outlen = sizeof(out);
    int i;
    const unsigned char expected[sizeof(out)] = {
        0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
        0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
    };
    size_t expectedlen = sizeof(expected);

    printf("\n Testing TLS1PRF \n\n");

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);

    /* We do this twice to test reuse of the EVP_PKEY_CTX */
    for (i = 0; i < 2; i++) {
        outlen = sizeof(out);
        memset(out, 0, outlen);

        if (EVP_PKEY_derive_init(pctx) <= 0) {
            printOpenSSLError("EVP_PKEY_derive_init");
            goto end;
        }
        if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md");
            goto end;
        }
        if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, "secret", 6) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret");
            goto end;
        }
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, "seed", 4) <= 0) {
            printOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed");
            goto end;
        }
        if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
            printOpenSSLError("EVP_PKEY_derive");
            goto end;
        }

        if ((outlen != expectedlen) ||
            (memcmp(out, expected, expectedlen) != 0)) {
            printf("TLS1Prf didn't derive the expected values\n");
        }
        else {
            printf("TLS1Prf derived the expected value\n");
        }
    }

end:
    EVP_PKEY_CTX_free(pctx);
    printf("%s", SeparatorLine);
    return;
}

int main(int argc, char** argv)
{
    int sc_ossl_log_level_debug = SC_OSSL_LOG_LEVEL_ERROR;
    if (argc >= 2) {
         sc_ossl_log_level_debug = atoi(argv[1]);
        SC_OSSL_ENGINE_set_trace_level(sc_ossl_log_level_debug);
    }
    SC_OSSL_ENGINE_Initialize();
    bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);

    TestDigests();
    TestCiphers();
    TestHKDF();
    TestTls1Prf();
    TestRsaEvpAll();
    TestEcc();

    BIO_free(bio_err);
    return 1;
}
