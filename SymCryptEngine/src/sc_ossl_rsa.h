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

_Success_(return >= 0)
int sc_ossl_rsa_pub_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                         _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa,
                         int padding);

_Success_(return >= 0)
int sc_ossl_rsa_priv_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                          _Out_ unsigned char* to, _In_ RSA* rsa, int padding);

_Success_(return >= 0)
int sc_ossl_rsa_priv_enc(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                          _Out_writes_bytes_(RSA_size(rsa)) unsigned char* to, _In_ RSA* rsa, int padding);

_Success_(return >= 0)
int sc_ossl_rsa_pub_dec(int flen, _In_reads_bytes_(flen) const unsigned char* from,
                         _Out_ unsigned char* to, _In_ RSA* rsa,
                         int padding);

SCOSSL_STATUS sc_ossl_rsa_mod_exp(_Out_ BIGNUM* r0, _In_ const BIGNUM* i, _In_ RSA* rsa, _In_ BN_CTX* ctx);

SCOSSL_STATUS sc_ossl_rsa_bn_mod_exp(_Out_ BIGNUM* r, _In_ const BIGNUM* a, _In_ const BIGNUM* p, 
                                      _In_ const BIGNUM* m, _In_ BN_CTX* ctx, _In_ BN_MONT_CTX* m_ctx);

SCOSSL_STATUS sc_ossl_rsa_sign(int type, _In_reads_bytes_(m_length) const unsigned char* m, unsigned int m_length,
                                _Out_writes_bytes_(siglen) unsigned char* sigret, _Out_ unsigned int* siglen,
                                _In_ const RSA* rsa);

SCOSSL_STATUS sc_ossl_rsa_verify(int dtype, _In_reads_bytes_(m_length) const unsigned char* m,
                                  unsigned int m_length,
                                  _In_reads_bytes_(siglen) const unsigned char* sigbuf,
                                  unsigned int siglen, _In_ const RSA* rsa);

SCOSSL_STATUS sc_ossl_rsa_keygen(_Out_ RSA* rsa, int bits, _In_ BIGNUM* e, _In_opt_ BN_GENCB* cb);
SCOSSL_STATUS sc_ossl_rsa_init(_Inout_ RSA *rsa);
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

SCOSSL_STATUS sc_ossl_initialize_rsa_key(_In_ RSA* rsa, _Out_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx);
void sc_ossl_rsa_free_key_context(_In_ SC_OSSL_RSA_KEY_CONTEXT *keyCtx);

#ifdef __cplusplus
}
#endif
