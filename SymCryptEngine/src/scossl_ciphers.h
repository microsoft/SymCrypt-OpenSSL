//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize all of the _hidden_* cipher variables
SCOSSL_STATUS e_scossl_ciphers_init_static();

// Using ENGINE e, populate cipher with the one asked for by nid.
// If cipher is NULL, return a list of supported nids in the nids parameter.
// Returns 1 on success, or 0 on error for cipher case, and number of nids in nids list case.
_Success_(return > 0)
int e_scossl_ciphers(_Inout_ ENGINE *e, _Out_ const EVP_CIPHER **cipher,
                    _Out_ const int **nids, int nid);

void e_scossl_destroy_ciphers(void);

#ifdef __cplusplus
}
#endif
