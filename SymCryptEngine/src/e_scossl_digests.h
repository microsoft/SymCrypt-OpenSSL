//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl.h"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/md2.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize all of the _hidden_* digests variables
SCOSSL_STATUS e_scossl_digests_init_static();

/*
 * Returns either the digest for 'nid', or a list of supported 'nids'.
 * If the framework wants the EVP_MD for 'nid', it will call
 * e_scossl_digests(e, &p_evp_digest, NULL, nid); (return zero for failure)
 * If the framework wants a list of supported 'nid's, it will call
 * e_scossl_digests(e, NULL, &p_nids, 0); (returns number of 'nids' or -1 for error)
 */
_Success_(return > 0)
int e_scossl_digests(_Inout_ ENGINE *e, _Out_opt_ const EVP_MD **digest,
                     _Out_opt_ const int **nids, int nid);

void e_scossl_destroy_digests(void);

#ifdef __cplusplus
}
#endif
