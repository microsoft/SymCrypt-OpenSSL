
# SymCrypt Engine
The SymCrypt engine leverages the [OpenSSL engine interface](https://www.openssl.org/docs/man1.0.2/man3/engine.html) to override the 
cryptographic implementations in OpenSSL's libcrypto.so with SymCrypt's implementations. 

Where possible the SymCrypt engine will direct OpenSSL API calls to the SymCrypt FIPS module. In cases where SymCrypt cannot (currently) 
support anOpenSSL API, the best effort is made to fall-back to the default OpenSSL implementation of the given function. In a few cases 
the enginewill instead fail the call completely, as re-routing to OpenSSL's implementation is not always easy, and as with any project 
we have to prioritize!

**Important note:** The code in this repository is currently undergoing validation for use in Microsoft-internal products. At this time, it
has not been tested for use in other environments and should not be considered production-ready.

## Algorithms that will be routed to a FIPS certifiable SymCrypt module with this version

The following list is not necessarily exhaustive, and will be updated as more functionality is added to SCOSSL.
Note that just because an algorithm is FIPS certifiable, does not mean it is recommended for use. SSH-KDF implementation is disabled by default and can be enabled by adding `-DSCOSSL_SSHKDF=1` argument to CMake. This algorithm also requires OpenSSL source code in the build process.

 + Key derivation
   + HKDF (SHA1, SHA2-256, SHA2-384, SHA2-512)
   + TLS 1.2 KDF (SHA1, SHA2-256, SHA2-384, SHA2-512)
   + SSH-KDF (SHA1, SHA2-256, SHA2-384, SHA2-512)
 + Key Agreement
   + ECDH (P256, P384, P521)
   + Finite Field DH (ffdhe2048, ffdhe3072, ffdhe4096, modp2048, modp3072, modp4096)
 + Hashing
   + SHA1
   + SHA2-256
   + SHA2-384
   + SHA2-512
 + Message Authentication
   + HMAC (SHA1, SHA2-256, SHA2-384, SHA2-512)
 + Symmetric
   + AES (128, 192, 256)
     + CBC, CCM, ECB, GCM
 + Asymmetric
   + RSA (2048, 3072, 4096)
     + PKCS1, OAEP, PSS
   + ECDSA (P256, P384, P521)

## Known cases where SCOSSL will fail rather than fallback to default OpenSSL

1. Use of unsupported digests in RSA signatures, TLS PRF, and HMAC
2. Use of multi-prime (more than 2-prime) RSA