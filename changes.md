# Changes: WI-60680024 + WI-60680110 — Error Messaging and NULL Checks

## Work Items
- ADO 60680024: "Improve error messaging in the SymCrypt provider"
- ADO 60680110: "Add NULL checks in keymgmt functions"

## Summary of Changes

### Error Messaging (`SymCryptProvider/src/kdf/p_scossl_kbkdf.c`)
- Fixed cipher fetch failure error: `PROV_R_INVALID_DIGEST` → `PROV_R_MISSING_CIPHER`
  (was using a digest error code for a cipher operation)
- Fixed unsupported CMAC cipher error: `PROV_R_INVALID_MODE` → `PROV_R_UNSUPPORTED_CEK_ALG`
  (was reporting "invalid mode" when the issue is an unsupported cipher algorithm)

### NULL Checks (6 keymgmt files)
Added `keyCtx == NULL` guards at the beginning of keymgmt functions to prevent crashes
when an uninitialized or empty key is passed:
- **DH** (`p_scossl_dh_keymgmt.c`): set_params, get_params, match
- **ECC** (`p_scossl_ecc_keymgmt.c`): get_params, set_params, match
- **RSA** (`p_scossl_rsa_keymgmt.c`): has, get_params, match
- **ML-KEM** (`p_scossl_mlkem_keymgmt.c`): get_params, set_params
- **ML-KEM hybrid** (`p_scossl_mlkem_hybrid_keymgmt.c`): get_params, set_params
- **KDF** (`p_scossl_kdf_keymgmt.c`): has (return FALSE for NULL)

Also fixed declaration-after-statement in DH get_params to maintain C90 compatibility.

## Thought Process
The error messaging fixes address specific testing feedback: setting an unsupported
CMAC cipher in KBKDF errored as "invalid mode" instead of indicating an unsupported
algorithm. The NULL checks follow a defensive programming pattern — while passing NULL
to these functions is technically undefined, testing revealed calling patterns where
empty keys can reach these functions and crash. Functions now fail gracefully instead.

## Review Process
- Reviewer identified 3 additional issues: missing RSA has/get_params NULL checks
  and a C90-incompatible declaration-after-statement in DH get_params — all fixed
- Reviewer questioned the `PROV_R_UNSUPPORTED_CEK_ALG` error code choice; retained
  as it's the closest match for "unsupported cipher algorithm" in the available codes

## Testing Done
All 16 QA tests passed:
- Clean build with no warnings
- RSA, EC (P-256/P-384), DH (ffdhe2048), X25519, RSA-PSS keygen
- RSA and EC key checks (pkey -check)
- X25519 and DH key exchange with shared secret verification
- ECDSA sign/verify
- KBKDF error code verification
- SslPlay full integration test
