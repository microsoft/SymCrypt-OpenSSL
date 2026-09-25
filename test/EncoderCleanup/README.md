# Encoder cipher cleanup regression

The common encoder context owns the reference returned by `EVP_CIPHER_fetch`
when a caller selects an encryption cipher. Replacing or clearing that cipher
already releases the old reference; freeing the context must also release its
remaining reference.

This standalone Linux ASan/LSan test exercises the public OpenSSL encoder API
against an existing SCOSSL provider build. It covers context destruction without
a cipher, with a selected cipher, after clearing it, and after a failed fetch.
All three existing ML-DSA and all three ML-KEM parameter sets exercise these
context-lifetime paths. ML-DSA additionally covers repeated encrypted PKCS#8
DER/PEM round trips and cipher replacement. ML-KEM key decoding is not part of
this cleanup regression.

Build the provider normally following the repository's build instructions, then
run from the repository root (substitute the actual dependency/module paths):

```sh
cmake -S test/EncoderCleanup -B build/encoder-cleanup -DOPENSSL_ROOT_DIR=/path/to/openssl -DSCOSSL_PROVIDER_DIR=/path/to/provider
cmake --build build/encoder-cleanup -j4
ctest --test-dir build/encoder-cleanup --output-on-failure
```

Requires OpenSSL 3.5+, a working SymCrypt-backed provider, and a compiler with
ASan/LSan support. The provider may also use the existing `Sanitize` build type.
The standalone driver is instrumented independently; a normal provider build
can still reproduce the leaked OpenSSL allocations.

The test unloads its providers and calls `OPENSSL_cleanup` before leak detection,
so OpenSSL's algorithm caches cannot conceal leaked references. No sanitizer
suppressions or provider-residency workarounds are used.

On Ubuntu 24.04 with OpenSSL 3.5.8, unmodified upstream
`d73b1e9ebf589f5c0098810e74e9556b2bef776a` passes all functional checks but leaks
748 bytes in eight allocations. The context cleanup fix must make the same
test pass with no leaks. This test requires neither composite algorithms nor
the separate SymCrypt curve-cache teardown change.
