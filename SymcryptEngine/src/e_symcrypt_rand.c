#include "e_symcrypt.h"
#include "e_symcrypt_ecc.h"
#include "e_symcrypt_rsa.h"
#include "e_symcrypt_dsa.h"
#include "e_symcrypt_dh.h"
#include "e_symcrypt_digests.h"
#include "e_symcrypt_ciphers.h"
#include "e_symcrypt_pkey_meths.h"
#include "e_symcrypt_rand.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

static int symcrypt_rand_seed(const void *buf, int num)
{
    //SYMCRYPT_LOG_DEBUG(NULL);
    RAND_METHOD *ossl_rand = RAND_OpenSSL();
    return ossl_rand->seed(buf, num);
}

static int symcrypt_rand_bytes(unsigned char *buf, int num)
{
    //SYMCRYPT_LOG_DEBUG(NULL);
    RAND_METHOD *ossl_rand = RAND_OpenSSL();
    return ossl_rand->bytes(buf, num);
}

static int symcrypt_rand_add(const void *buf, int num, double randomness)
{
    //SYMCRYPT_LOG_DEBUG(NULL);
    RAND_METHOD *ossl_rand = RAND_OpenSSL();
    return ossl_rand->add(buf, num, randomness);
}

static int symcrypt_rand_pseudorand(unsigned char *buf, int num)
{
    //SYMCRYPT_LOG_DEBUG(NULL);
    RAND_METHOD *ossl_rand = RAND_OpenSSL();
    return ossl_rand->pseudorand(buf, num);
}

static int symcrypt_rand_status(void)
{
    //SYMCRYPT_LOG_DEBUG(NULL);
    RAND_METHOD *ossl_rand = RAND_OpenSSL();
    return ossl_rand->status();
}

RAND_METHOD _symcrypt_rand_meth = {
    symcrypt_rand_seed,
    symcrypt_rand_bytes,
    NULL,
    symcrypt_rand_add,
    symcrypt_rand_pseudorand,
    symcrypt_rand_status
};

RAND_METHOD *symcrypt_rand_method(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    return &_symcrypt_rand_meth;
}

#ifdef __cplusplus
}
#endif


