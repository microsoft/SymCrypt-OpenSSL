//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int eckey_symcrypt_idx;

typedef int (*PFN_eckey_copy)(EC_KEY *dest, const EC_KEY *src);
typedef int (*PFN_eckey_set_group)(EC_KEY *key, const EC_GROUP *grp);
typedef int (*PFN_eckey_set_private)(EC_KEY *key, const BIGNUM *priv_key);
typedef int (*PFN_eckey_set_public)(EC_KEY *key, const EC_POINT *pub_key);

int symcrypt_eckey_init(EC_KEY *key);
void symcrypt_eckey_finish(EC_KEY *key);
// int symcrypt_eckey_copy(EC_KEY *dest, const EC_KEY *src);
// int symcrypt_eckey_set_group(EC_KEY *key, const EC_GROUP *grp);
// int symcrypt_eckey_set_private(EC_KEY *key, const BIGNUM *priv_key);
// int symcrypt_eckey_set_public(EC_KEY *key, const EC_POINT *pub_key);
int symcrypt_eckey_keygen(EC_KEY *key);
int symcrypt_eckey_compute_key(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh);
int symcrypt_eckey_sign(int type,
                        const unsigned char* dgst,
                        int dlen,
                        unsigned char* sig,
                        unsigned int* siglen,
                        const BIGNUM* kinv,
                        const BIGNUM* r,
                        EC_KEY* eckey);
int symcrypt_eckey_sign_setup(EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);
ECDSA_SIG* symcrypt_eckey_sign_sig(const unsigned char* dgst, int dgst_len,
                                   const BIGNUM* in_kinv, const BIGNUM* in_r,
                                   EC_KEY* eckey);
int symcrypt_eckey_verify(int type, const unsigned char* dgst, int dgst_len,
                          const unsigned char* sigbuf, int sig_len, EC_KEY* eckey);
int symcrypt_eckey_verify_sig(const unsigned char* dgst, int dgst_len,
                              const ECDSA_SIG* sig, EC_KEY* eckey);

void symcrypt_destroy_ecc_curves(void);

#ifdef __cplusplus
}
#endif
