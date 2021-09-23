//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include <symcrypt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


// Using ENGINE e, populate cipher with the one asked for by nid.
// If cipher is NULL, return a list of supported nids in the nids parameter.
// Returns 1 on success, or 0 on error for cipher case, and number of nids in nids list case.
_Success_(return > 0)
int sc_ossl_ciphers(_Inout_ ENGINE *e, _Out_ const EVP_CIPHER **cipher,
                            _Out_ const int **nids, int nid);


void sc_ossl_destroy_ciphers(void);

#ifdef __cplusplus
}
#endif
