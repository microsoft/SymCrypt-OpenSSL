//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl_rand.h"

#ifdef __cplusplus
extern "C" {
#endif

// RAND_seed() returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE otherwise.
// Since an error internally is fatal, we always return SCOSSL_SUCCESS here.
static SCOSSL_STATUS scossl_rand_seed(_In_reads_bytes_(num) const void *buf, _In_ int num)
{
    SymCryptProvideEntropy(buf, num);
    return SCOSSL_SUCCESS;
}

// RAND_bytes() returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE otherwise.
// Since an error internally is fatal, we always return SCOSSL_SUCCESS here.
static SCOSSL_STATUS scossl_rand_bytes(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return SCOSSL_SUCCESS;
}

// RAND_add() returns SCOSSL_SUCCESS on success, SCOSSL_FAILURE otherwise.
// Since an error internally is fatal, we always return SCOSSL_SUCCESS here.
static SCOSSL_STATUS scossl_rand_add(_In_reads_bytes_(num) const void *buf, _In_ int num, _In_ double randomness)
{
    SymCryptProvideEntropy(buf, num);
    return SCOSSL_SUCCESS;
}

// RAND_pseudo_bytes() returns SCOSSL_SUCCESS if the bytes generated are cryptographically strong,
// SCOSSL_FAILURE otherwise.
// Since an error internally is fatal, we always return SCOSSL_SUCCESS here.
static SCOSSL_STATUS scossl_rand_pseudorand(_Out_writes_bytes_(num) unsigned char *buf, _In_ int num)
{
    SymCryptRandom(buf, num);
    return SCOSSL_SUCCESS;
}

// RAND_status() returns SCOSSL_SUCCESS if the PRNG has been seeded with enough data, SCOSSL_FAILURE
// otherwise.
// Since we guarantee this, we return always return SCOSSL_SUCCESS here.
static SCOSSL_STATUS scossl_rand_status(void)
{
    return SCOSSL_SUCCESS;
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


