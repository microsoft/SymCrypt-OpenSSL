# SymCrypt Engine for OpenSSL

The SymCrypt Engine for OpenSSL allows the use of OpenSSL with [SymCrypt](https://github.com/Microsoft/SymCrypt) as the provider for core cryptographic operations. It leverages the [OpenSSL engine interface](https://www.openssl.org/docs/man1.0.2/man3/engine.html) to override the cryptographic implementations in OpenSSL's libcrypto.so with SymCrypt's implementations. The primary motivation for this is to support FIPS certification, as vanilla OpenSSL 1.1.1 does not have a FIPS-certified cryptographic module.

# Building Instructions
## Comple Instructions
```
cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl -DOPENSSL_LIBRARIES=/usr/local/ssl/lib .
make
```

## Run Samples
```
cd SslPlay
./SslPlay
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