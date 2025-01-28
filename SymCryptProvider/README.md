# SymCrypt Provider
The SymCrypt provider implements the [OpenSSL provider interface](https://docs.openssl.org/3.0/man7/provider/) to supply cryptographic
operations from SymCrypt to OpenSSL's libcrypto.so. The provider interface was added in OpenSSL 3 and has largely replaced the functionality
of the engine interface.

For algorithms that the SymCrypt provider supports, the SymCrypt provider will handle and forward the cryptographic operation to SymCrypt
in it's entirety. Unlike the engine, the SymCrypt provider is in charge of the entire cryptographic operation, and will not fallback to
the default OpenSSL implementation in some cases where the engine did. For example, the SymCrypt provider supports ECDH for a set of named 
curves. The SymCrypt provider will fail for ECDH using an unsupported curve. 

For any algorithms the SymCrypt provider doesn't support, 
a different provider may be selected to handle the algorithm instead. This provider may be loaded at the same time as the SymCrypt provider.
For example, the SymCrypt provider does not support ED25519. If the default provider is enabled, it can handle the operation

## Algorithms supported by the SymCrypt provider

The following list is not necessarily exhaustive, and will be updated as more functionality is added to SCOSSL.
Note that just because an algorithm is FIPS certifiable, does not mean it is recommended for use.

+ Hashing
    + MD5
    + SHA1
    + SHA224, SHA256, SHA384, SHA512, SHA-512/224, SHA-512/256
    + SHA3-224, SHA3-256, SHA3-384, SHA3-512
    + SHAKE128, SHAKE256
    + CSHAKE128, CSHAKE256
+ Symmetric Cipher
    + AES-CBC (128, 192, 256)
    + AES-ECB (128, 192, 256)
    + AES-CFB (128, 192, 256)
    + AES-CFB8 (128, 192, 256)
    + AES-GCM (128, 192, 256)
    + AES-CCM (128, 192, 256)
    + AES-XTS (128, 256)
+ Message Authentication
    + CMAC
    + HMAC
    + KMAC (128, 256)
+ Key Derivation
    + HKDF
    + KBKDF
    + SRTPKDF
    + SSHKDF
    + SSKDF
    + TLS1-PRF
+ Random Number Generation
    + CTR-DRGB
+ Key Exchange
    + DH (Named groups only)
        + ffdhe2048, ffdhe3072, ffdhe4096
        + modp2048, modp3072, modp4096
    + ECDH (Named curves only)
        + P-192, P-224, P-256, P-384, P-521
    + X25519
+ Signature
    + RSA
        + PKCS1, PSS
    + ECDSA (Named curves only)
        + P-192, P-224, P-256, P-384, P-521
+ Asymmetric Cipher
    + RSA
        + PKCS1, OAEP