//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_ecc.h"
#include "sc_ossl_rsa.h"
#include "sc_ossl_dsa.h"
#include "sc_ossl_dh.h"
#include "sc_ossl_digests.h"
#include "sc_ossl_ciphers.h"
#include "sc_ossl_pkey_meths.h"
#include "sc_ossl_rand.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

// RAND_seed() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS sc_ossl_rand_seed(_In_reads_bytes_(num) const void *buf, _In_ int num)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_bytes() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS sc_ossl_rand_bytes(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_add() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS sc_ossl_rand_add(_In_reads_bytes_(num) const void *buf, _In_ int num, _In_ double randomness)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_pseudo_bytes() returns 1 if the bytes generated are cryptographically strong, 0 otherwise.
// Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS sc_ossl_rand_pseudorand(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_status() returns 1 if the PRNG has been seeded with enough data, 0 otherwise. Since we guarantee this, we return 1.
static SCOSSL_STATUS sc_ossl_rand_status(void)
{
    return 1;
}

RAND_METHOD _sc_ossl_rand_meth = {
    sc_ossl_rand_seed,
    sc_ossl_rand_bytes,
    NULL,
    sc_ossl_rand_add,
    sc_ossl_rand_pseudorand,
    sc_ossl_rand_status
};

RAND_METHOD *sc_ossl_rand_method(void)
{
    return &_sc_ossl_rand_meth;
}

#ifdef __cplusplus
}
#endif


