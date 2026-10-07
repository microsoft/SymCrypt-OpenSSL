//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include "p_scossl_base.h"
#include "p_scossl_mldsa.h"

#ifdef __cplusplus
extern "C" {
#endif

// Composite-ML-DSA backend descriptor, shared across this family's translation units.
extern const SCOSSL_MLDSA_BACKEND p_scossl_composite_mldsa_backend;

SCOSSL_STATUS p_scossl_composite_mldsa_register_algorithms();

#ifdef __cplusplus
}
#endif
