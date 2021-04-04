#include "e_symcrypt.h"
#include <openssl/rsa.h>
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rsa_symcrypt_idx;

int symcrypt_rsa_pub_enc(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

int symcrypt_rsa_pub_dec(int flen, const unsigned char* from,
                         unsigned char* to, RSA* rsa,
                         int padding);

int symcrypt_rsa_priv_enc(int flen, const unsigned char* from,
                          unsigned char* to, RSA* rsa, int padding);

int symcrypt_rsa_priv_dec(int flen, const unsigned char* from,
                          unsigned char* to, RSA* rsa, int padding);

int symcrypt_rsa_mod_exp(BIGNUM* r0, const BIGNUM* i, RSA* rsa, BN_CTX* ctx);

int symcrypt_rsa_bn_mod_exp(BIGNUM* r,
                            const BIGNUM* a,
                            const BIGNUM* p,
                            const BIGNUM* m,
                            BN_CTX* ctx,
                            BN_MONT_CTX* m_ctx);

int symcrypt_rsa_sign(int type, const unsigned char* m,
                      unsigned int m_length,
                      unsigned char* sigret, unsigned int* siglen,
                      const RSA* rsa);

int symcrypt_rsa_verify(int dtype, const unsigned char* m,
                        unsigned int m_length,
                        const unsigned char* sigbuf,
                        unsigned int siglen, const RSA* rsa);

int symcrypt_rsa_keygen(RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb);
int symcrypt_rsa_init(RSA *rsa);
int symcrypt_rsa_finish(RSA *rsa);

#ifdef __cplusplus
}
#endif
