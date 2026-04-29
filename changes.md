# Changes: WI-60680059 + WI-60680065 — XOF Parameter Improvements

## Work Items
- ADO 60680059: "Update SymCrypt provider XOFs to return the xoflen for the OSSL_DIGEST_PARAM_SIZE parameter"
- ADO 60680065: "Expose the OSSL_DIGEST_PARAM_XOFLEN from SymCrypt-OpenSSL XOFs"

## Summary of Changes

### `SymCryptProvider/src/digests/p_scossl_shake.c`
- Added `p_scossl_shake_gettable_ctx_param_types` array advertising `OSSL_DIGEST_PARAM_XOFLEN`
  and `OSSL_DIGEST_PARAM_SIZE` as gettable context parameters
- Added `p_scossl_shake_gettable_ctx_params()` function returning the array
- Added `p_scossl_shake_get_ctx_params()` function that returns the current `ctx->xofLen`
  for both `OSSL_DIGEST_PARAM_XOFLEN` and `OSSL_DIGEST_PARAM_SIZE` queries
- Registered both dispatch entries in the `IMPLEMENT_SCOSSL_SHAKE` macro for SHAKE128/256

## Thought Process
SHAKE XOFs have a configurable output length (xofLen) that callers set via
`OSSL_DIGEST_PARAM_XOFLEN`. However, there was no way to read it back — the settable
param existed but no gettable counterpart. Additionally, `OSSL_DIGEST_PARAM_SIZE`
(queried by `EVP_MD_CTX_get_size()`) was only available via static `get_params` which
returned the default hash size. For XOFs, the ctx-level SIZE should reflect the
currently configured xofLen. This matches OpenSSL's default provider behavior.

## Review Process
- Review found no issues — dispatch registration, return values, SAL annotations,
  and macro integration all correct
- Style matches existing settable params pattern exactly

## Testing Done
All 28 QA tests passed including:
- SHAKE128/256 default and custom xoflen digests
- API tests: get/set XOFLEN, get SIZE, gettable_ctx_params listing
- Edge cases: xoflen=1, 256, 1MB, re-init reset, dupctx preservation
- NIST FIPS 202 known-answer tests for SHAKE128/256
- Full regression: SHA256, RSA/EC keygen, AES, CSHAKE, TLS, SslPlay
