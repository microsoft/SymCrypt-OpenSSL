//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"
#include "p_scossl_mldsa_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// "Pure" ML-DSA backend descriptor, shared by the signature, keymgmt, decoder
// and encoder translation units for this family.
extern const SCOSSL_MLDSA_BACKEND p_scossl_mldsa_backend;

SCOSSL_STATUS p_scossl_mldsa_register_algorithms();

#ifdef __cplusplus
}
#endif
