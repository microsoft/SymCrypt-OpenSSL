# SCOSSL - The SymCrypt engine for OpenSSL

The SymCrypt engine for OpenSSL (SCOSSL) allows the use of OpenSSL with [SymCrypt](https://github.com/Microsoft/SymCrypt) as the provider
for core cryptographic operations. It leverages the [OpenSSL engine interface](https://www.openssl.org/docs/man1.0.2/man3/engine.html) to
override the cryptographic implementations in OpenSSL's libcrypto.so with SymCrypt's implementations. The primary motivation for this is to
support FIPS certification, as vanilla OpenSSL 1.1.1 does not have a FIPS-certified cryptographic module.

Where possible the SCOSSL will direct OpenSSL API calls to the SymCrypt FIPS module. In cases where SymCrypt cannot (currently) support an
OpenSSL API, the best effort is made to fall-back to the default OpenSSL implementation of the given function. In a few cases the engine
will instead fail the call completely, as re-routing to OpenSSL's implementation is not always easy, and as with any project we have to
prioritize!

**Important note:** The code in this repository is currently undergoing validation for use in Microsoft-internal products. At this time, it
has not been tested for use in other environments and should not be considered production-ready.

## Algorithms that will be routed to a FIPS certifiable SymCrypt module with this version

The following list is not necessarily exhaustive, and will be updated as more functionality is added to SCOSSL.
Note that just because an algorithm is FIPS certifiable, does not mean it is recommended for use.

 + Key derivation
   + HKDF (SHA1, SHA2-256, SHA2-384, SHA2-512)
   + TLS 1.2 KDF (SHA1, SHA2-256, SHA2-384, SHA2-512)
 + Key Agreement
   + ECDH (P256, P384, P521)
   + Finite Field DH (ffdhe2048, ffdhe3072, ffdhe4096, modp2048, modp3072, modp4096)
 + Hashing
   + SHA-1
   + SHA2-256
   + SHA2-384
   + SHA2-512
 + Symmetric
   + AES (128, 192, 256)
     + CBC, CCM, ECB, GCM
 + Asymmetric
   + RSA (2048, 3072, 4096)
     + PKCS1, OAEP, PSS
   + ECDSA (P256, P384, P521)

## Known cases where SCOSSL will fail rather than fallback to default OpenSSL

1. Use of an AES-GCM IV which is not 12-bytes (192-bits)
2. Use of unsupported digests in RSA signatures and TLS PRF
3. Use of multi-prime (more than 2-prime) RSA

# Building Instructions
## Compilation Instructions
## Prerequisite, need libssl installed to compile

Follow Linux build instructions from SymCrypt repository [SymCrypt](https://github.com/Microsoft/SymCrypt) to build the Linux SymCrypt module.

```
cp <SymCryptRepo>/bin/module/<arch>/LinuxUserMode/<module_name>/libsymcrypt.so ./
mkdir bin; cd bin
cmake .. -DSYMCRYPT_ROOT_DIR=<SymCryptRepo> -DOPENSSL_ROOT_DIR=<OpensslInstallDirectory> -DCMAKE_TOOLCHAIN_FILE=../cmake-toolchain/LinuxUserMode-<arch>.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Run Samples
```
./SslPlay/SslPlay
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
