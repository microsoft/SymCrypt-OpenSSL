//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_helpers.h"
#include <openssl/rsa.h>
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rsa_sc_ossl_idx;

// Public Encryption
// Encrypts flen bytes at from using public key rsa and stores ciphertext in to.
// Same parameters as RSA_public_encrypt
// - flen must not be more than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes, not more than RSA_size(rsa) - 42
//   for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING
// - from and to may overlap
// - padding is ones of RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, or RSA_NO_PADDING
// Returns size of encrypted data (RSA_size(rsa)), or -1 on error
SCOSSL_RETURNLENGTH sc_ossl_rsa_pub_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                         _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
                         int padding);

// Private Decryption
// Decrypts flen bytes at from using private key rsa and stores plaintext in to.
// Same parameters as RSA_private_decrypt
// - flen should be equal to RSA_size(rsa) but may be smaller, when leading zero bytes are in the ciphertext
// - from and to may overlap
// - padding is the mode used to encrypt the data
// Returns size of recovered plaintext, or -1 on error.
SCOSSL_RETURNLENGTH sc_ossl_rsa_priv_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                          _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding);

// Private Encryption
// Signs flen bytes at from using private key rsa and stores signature in to.
// Returns size of signature, or -1 on error
SCOSSL_RETURNLENGTH sc_ossl_rsa_priv_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                          _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding);

// Public Decryption
// Recovers message digest from flen-bytes long signature at from using public key rsa and stores result in to.
// Returns size of recovered message digest, or -1 on error.
SCOSSL_RETURNLENGTH sc_ossl_rsa_pub_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                         _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
                         int padding);

// Used for CRT computations, used by default RSA implementations
// ctx is a temporary BIGNUM variable
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_rsa_mod_exp(_Out_ BIGNUM* r0, _In_ const BIGNUM* i, _In_ RSA* rsa, _In_ BN_CTX* ctx);

// Used for CRT computations, used by default RSA implementations
// r = a ^ p mod m
// ctx is a temporary BIGNUM variable, while m_ctx is a Montgomery multiplication structure
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_rsa_bn_mod_exp(_Out_ BIGNUM* r, _In_ const BIGNUM* a, _In_ const BIGNUM* p, 
                                      _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx);

// Signs the message digest m of size m_len using private key rsa using PKCS1-v1_5 and stores signature in sigret and
// signature size in siglen. Type denotes the message digest algorithm used to generate m.
// Returns 1 on success
SCOSSL_STATUS sc_ossl_rsa_sign(int type, _In_reads_bytes_(m_length) const unsigned char* m, unsigned int m_length,
                                _Out_writes_bytes_(siglen) unsigned char* sigret, _Out_ unsigned int* siglen,
                                _In_ const RSA* rsa);

// Verifies that the signature sigbuf of size siglen matches a given message digest m of size m_len.
// dtype denotes the message digest algorithm that was used to generate the signature. rsa is the signer's
// public key.
// Returns 1 on successful verification
SCOSSL_STATUS sc_ossl_rsa_verify(int dtype, _In_reads_bytes_(m_length) const unsigned char* m,
                                  unsigned int m_length,
                                  _In_reads_bytes_(siglen) const unsigned char* sigbuf,
                                  unsigned int siglen, _In_ const RSA* rsa);

// Generates a 2-prime RSA key pair and stores it in rsa. Modulus will be of length bits,
// the number of primes to form the modulus will be primes, and the public exponent will be e.
// cb is an optional callback for progress of key generation that is unused in our implementation.
// Returns 1 on success or 0 on error.
SCOSSL_STATUS sc_ossl_rsa_keygen(_Out_ RSA* rsa, int bits, _In_ BIGNUM* e, _In_opt_ BN_GENCB* cb);

// Initializes a new RSA instance.
// Returns 1 on success, or 0 on error
SCOSSL_STATUS sc_ossl_rsa_init(_Inout_ RSA *rsa);

// Destroys instance of RSA object. The memory for rsa is not freed by this function.
// Returns 1 on success
SCOSSL_STATUS sc_ossl_rsa_finish(_Inout_ RSA *rsa);

typedef struct _SC_OSSL_RSA_KEY_CONTEXT {
    int initialized;
    // Pointer to memory buffer holding private/public key data as it is transferred between OpenSSL
    // and SymCrypt formats
    // Must be cleared before freeing (using OPENSSL_clear_free)
    PBYTE data;
    SIZE_T cbData;
    PSYMCRYPT_RSAKEY key;
} SC_OSSL_RSA_KEY_CONTEXT;

// Initializes keyCtx from key rsa.
// Returns 1 on success, or 0 on error.
SCOSSL_STATUS sc_ossl_initialize_rsa_key(_In_ RSA* rsa, _Out_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx);

// Frees data and key of keyCtx
void sc_ossl_rsa_free_key_context(_In_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx);

#ifdef __cplusplus
}
#endif
