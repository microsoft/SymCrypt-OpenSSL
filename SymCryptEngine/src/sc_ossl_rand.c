//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

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

// RAND_seed() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static int symcrypt_rand_seed(const void *buf, int num)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_bytes() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static int symcrypt_rand_bytes(unsigned char *buf, int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_add() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static int symcrypt_rand_add(const void *buf, int num, double randomness)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_pseudo_bytes() returns 1 if the bytes generated are cryptographically strong, 0 otherwise.
// Since an error internally is fatal, we always return 1 here.
static int symcrypt_rand_pseudorand(unsigned char *buf, int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_status() returns 1 if the PRNG has been seeded with enough data, 0 otherwise. Since we guarantee this, we return 1.
static int symcrypt_rand_status(void)
{
    return 1;
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
    return &_symcrypt_rand_meth;
}

#ifdef __cplusplus
}
#endif


