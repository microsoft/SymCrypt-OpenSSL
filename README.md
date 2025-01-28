# SCOSSL - The SymCrypt engine and provider for OpenSSL

The SymCrypt engine and provider for OpenSSL (SCOSSL) allow the use of OpenSSL with [SymCrypt](https://github.com/Microsoft/SymCrypt) as the provider
for core cryptographic operations. The primary motivation for this is to support FIPS certification, as vanilla OpenSSL 1.1.1 does not have a FIPS-certified
cryptographic module, and the OpenSSL 3 fips module is not certified on the FIPS 140-3 standard.

- [SymCrypt Engine](./SymCryptEngine/) 
- [SymCrypt Provider](./SymCryptProvider/) (OpenSSL 3)

## Versioning and Servicing

As of version 1.0.0, SCOSSL uses the versioning scheme defined by the [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) specification. This means:

- Major version changes introduce ABI and/or API breaking changes
- Minor version changes introduce backwards compatible additional functionality or improvements, and/or bug fixes
- Patch version changes introduce backwards compatible bug fixes

Regarding servicing, our strong recommendation is that distro vendors and application developers regularly
update to the latest version of SymCrypt and SymCrypt engine/provider for both security fixes and
functionality/performance improvements.

We will support long-term servicing of specific releases for security fixes. Details of this plan will be
released publicly in the future.

# Building Instructions
## Compilation Instructions

1. Install libssl, or compile and install OpenSSL from source
2. Follow Linux build instructions from SymCrypt repository [SymCrypt](https://github.com/Microsoft/SymCrypt) to build the Linux SymCrypt module
    * You can either install the Linux SymCrypt module (i.e libsymcrypt.so* to /usr/lib/, and inc/* to /usr/include/), or
    * Copy the built module to the root of the SymCrypt-OpenSSL repo `cp <SymCryptRepo>/bin/module/<arch>/LinuxUserMode/<module_name>/libsymcrypt.so ./`
3. `mkdir bin; cd bin`
4. `cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake-toolchain/LinuxUserMode-<arch>.cmake`
    * If you have not installed SymCrypt header files, you can also specify the root directory `-DSYMCRYPT_ROOT_DIR=<SymCryptRepo>`
    * If you want to link to a specific OpenSSL installation, you can also specify `-DOPENSSL_ROOT_DIR=<OpensslInstallDirectory>`
    * Optionally, for a release build, specify `-DCMAKE_BUILD_TYPE=Release`
5. `cmake --build .`
    * Optionally specify `-jN` where N is the number of processes you wish to spawn for the build

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
