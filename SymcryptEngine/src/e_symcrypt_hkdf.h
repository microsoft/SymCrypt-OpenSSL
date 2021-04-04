#include "e_symcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_hkdf_init(EVP_PKEY_CTX *ctx);
void symcrypt_hkdf_cleanup(EVP_PKEY_CTX *ctx);
int symcrypt_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int symcrypt_hkdf_derive_init(EVP_PKEY_CTX *ctx);
int symcrypt_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

#ifdef __cplusplus
}
#endif
