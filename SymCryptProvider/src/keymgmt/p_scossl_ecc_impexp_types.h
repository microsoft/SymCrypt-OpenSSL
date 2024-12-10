//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_names.h>
#include <openssl/params.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parameter types for import/export depend on the selection
// passed by the caller. These can be any combination of:
//   OSSL_KEYMGMT_SELECT_PRIVATE_KEY
//   OSSL_KEYMGMT_SELECT_PUBLIC_KEY
//   OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
//   OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
// Rather than constructing the parameter array each time
// a caller queries supported parameters, these values
// are hardcoded here. This follows the same pattern as
// the default provider.

#define SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),

#define SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),

#define SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0), \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),

#define SCOSSL_ECC_IMPEXP_OTHER_PARAMS \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL), \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL), \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x01[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x02[] = {
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x03[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x04[] = {
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x05[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x06[] = {
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x07[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x08[] = {
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x09[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0a[] = {
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0b[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0c[] = {
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0d[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0e[] = {
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

// OSSL_KEYMGMT_SELECT_PRIVATE_KEY
// OSSL_KEYMGMT_SELECT_PUBLIC_KEY
// OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
// OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
static const OSSL_PARAM p_scossl_ecc_impexp_types_0x0f[] = {
    SCOSSL_ECC_IMPEXP_PRIV_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_PUB_KEY_PARAMS
    SCOSSL_ECC_IMPEXP_DOMAIN_PARAMS
    SCOSSL_ECC_IMPEXP_OTHER_PARAMS
    OSSL_PARAM_END};

const OSSL_PARAM *p_scossl_ecc_keymgmt_impexp_param_types[] = {
    NULL,
    p_scossl_ecc_impexp_types_0x01,
    p_scossl_ecc_impexp_types_0x02,
    p_scossl_ecc_impexp_types_0x03,
    p_scossl_ecc_impexp_types_0x04,
    p_scossl_ecc_impexp_types_0x05,
    p_scossl_ecc_impexp_types_0x06,
    p_scossl_ecc_impexp_types_0x07,
    p_scossl_ecc_impexp_types_0x08,
    p_scossl_ecc_impexp_types_0x09,
    p_scossl_ecc_impexp_types_0x0a,
    p_scossl_ecc_impexp_types_0x0b,
    p_scossl_ecc_impexp_types_0x0c,
    p_scossl_ecc_impexp_types_0x0d,
    p_scossl_ecc_impexp_types_0x0e,
    p_scossl_ecc_impexp_types_0x0f};

#ifdef __cplusplus
}
#endif