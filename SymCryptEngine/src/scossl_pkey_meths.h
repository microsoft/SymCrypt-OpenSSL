//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_helpers.h"
#include <openssl/dh.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize all of the _hidden_* pkey method variables
SCOSSL_STATUS scossl_pkey_methods_init_static();

// Return a list of supported nids if pmeth is NULL, or a particular pkey
// method in pmeth determined by nid. Returns number of supported nids in the first case.
// Returns 1 on success in second case, or 0 on failure.
_Success_(return > 0)
int scossl_pkey_methods(_Inout_ ENGINE *e, _Out_opt_ EVP_PKEY_METHOD **pmeth,
                               _Out_opt_ const int **nids, int nid);

// Destroys internal methods
void scossl_destroy_pkey_methods(void);

#ifdef __cplusplus
}
#endif
