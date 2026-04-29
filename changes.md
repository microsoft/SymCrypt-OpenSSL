# Changes: WI-60679775 — Make SymCrypt provider the default rand provider

## Work Item
ADO 60679775: "Make SymCrypt provider the default rand provider in AZL4"

## Summary of Changes

### Code Changes (`SymCryptProvider/src/p_scossl_base.c`)
- Added `p_scossl_provider_random_bytes()` function implementing the OpenSSL 3.5
  `OSSL_FUNC_PROVIDER_RANDOM_BYTES` dispatch (function ID 1032)
- Registered the function in `p_scossl_base_dispatch` so the SymCrypt provider can
  be designated as the system-wide random provider via the `random_provider` config option
- The function calls `SymCryptRandom(buf, n)` for all random generation, both public
  and private (SymCrypt uses a single CSPRNG for both)
- Strength validation rejects requests exceeding 256 bits with `PROV_R_INSUFFICIENT_DRBG_STRENGTH`
- Both function and dispatch entry are guarded with `#ifdef OSSL_FUNC_PROVIDER_RANDOM_BYTES`
  for backward compatibility with OpenSSL 3.0–3.4

### Config Documentation (`SymCryptProvider/symcrypt_prov.cnf`)
- Added documentation explaining how to configure `random_provider = symcryptprovider`
  in the `[random]` section of `openssl.cnf`

## Thought Process
OpenSSL 3.5 introduced `OSSL_FUNC_PROVIDER_RANDOM_BYTES` which allows a provider to
completely bypass the DRBG chain for RAND_bytes()/RAND_priv_bytes() calls. The FIPS
provider in OpenSSL already implements this pattern. For SymCrypt, the implementation
is straightforward since SymCrypt internally manages all RNG state — we simply delegate
to `SymCryptRandom()`. The `which` parameter (public vs private) is intentionally ignored
since SymCrypt's CSPRNG provides the same security level for both use cases.

## Review Process
- **Finding 1 (bug):** Reviewer identified missing `ERR_raise` on strength check failure.
  Fixed by adding `ERR_raise(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH)`.
- **Finding 2 (nit):** Missing trailing newline in symcrypt_prov.cnf. Fixed.
- **Finding 3 (suggestion):** Added comment explaining why `which` parameter is unused.
- All findings adopted and incorporated.

## Testing Done
All 16 QA tests passed:
- Build: Clean compilation with `-Wall -Wextra`, no warnings
- Provider loading: SymCrypt provider activates correctly
- Random provider: `openssl rand` works with `random_provider = symcryptprovider`
- Uniqueness: 5 sequential random generations all produce distinct values
- TLS handshake: TLSv1.3 connection to google.com:443 succeeds
- Crypto operations: AES-256-CBC speed benchmark completes
- Edge cases: 0-byte, 1-byte, and 1MB random generation all succeed
- Negative tests: Invalid provider name falls back gracefully; missing config works normally
- Integration: RSA and EC key generation succeed with random provider
- API test: Custom C test verifying RAND_bytes/RAND_priv_bytes via provider
- Regression: SslPlay test suite passes (digests, DH, ECDH, HMAC)
- Binary verification: Symbol present in built .so
