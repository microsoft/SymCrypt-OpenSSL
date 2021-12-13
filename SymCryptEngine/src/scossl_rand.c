//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_rand.h"

#ifdef __cplusplus
extern "C" {
#endif

// RAND_seed() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS scossl_rand_seed(_In_reads_bytes_(num) const void *buf, _In_ int num)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_bytes() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS scossl_rand_bytes(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_add() returns 1 on success, 0 otherwise. Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS scossl_rand_add(_In_reads_bytes_(num) const void *buf, _In_ int num, _In_ double randomness)
{
    SymCryptProvideEntropy(buf, num);
    return 1;
}

// RAND_pseudo_bytes() returns 1 if the bytes generated are cryptographically strong, 0 otherwise.
// Since an error internally is fatal, we always return 1 here.
static SCOSSL_STATUS scossl_rand_pseudorand(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return 1;
}

// RAND_status() returns 1 if the PRNG has been seeded with enough data, 0 otherwise. Since we guarantee this, we return 1.
static SCOSSL_STATUS scossl_rand_status(void)
{
    return 1;
}

RAND_METHOD _scossl_rand_meth = {
    scossl_rand_seed,
    scossl_rand_bytes,
    NULL,
    scossl_rand_add,
    scossl_rand_pseudorand,
    scossl_rand_status
};

RAND_METHOD *scossl_rand_method(void)
{
    return &_scossl_rand_meth;
}

#ifdef __cplusplus
}
#endif


