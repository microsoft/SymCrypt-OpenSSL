# SymCrypt Provider
The SymCrypt provider implements the [OpenSSL provider interface](https://docs.openssl.org/3.0/man7/provider/) to supply cryptographic
operations from SymCrypt to OpenSSL's libcrypto.so. The provider interface was added in OpenSSL 3 and has largely replaced the functionality
of the engine interface.

For algorithms that the SymCrypt provider supports, the SymCrypt provider will handle and forward the cryptographic operation to SymCrypt
in it's entirety. Unlike the engine, there is no fallback logic for algorithms the SymCrypt provider supports. For example, the SymCrypt provider 
supports ECDH for a set of named curves. The SymCrypt provider will fail for ECDH using an unsupported curve. For any algorithms the SymCrypt 
provider doesn't support, a different provider may be selected to handle the algorithm instead. For example, the SymCrypt provider does not
support ED25519. If the default provider is enabled, it will handle the operation.

## Algorithms supported by the SymCrypt provider

The following list is not necessarily exhaustive, and will be updated as more functionality is added to SCOSSL.
Note that just because an algorithm is FIPS certifiable, does not mean it is recommended for use.

### Hashing
| Algorithm | Block         | FIPS certifiable      |
| ---       | ---           | ---                   |
| AES-CBC   | 128, 192, 256 | :white_check_mark:    |
| AES-ECB   | 128, 192, 256 | :white_check_mark:    |
| AES-CFB   | 128, 192, 256 | :white_check_mark:    |
| AES-CFB8  | 128, 192, 256 | :white_check_mark:    |
| AES-GCM   | 128, 192, 256 | :white_check_mark:    |
| AES-CCM   | 128, 192, 256 | :white_check_mark:    |
| AES-XTS   | 128, 256      | :white_check_mark:    |

### Symmetric Cipher

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Message Authentication

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Key Derivation

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Random Number Generation

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Key Exchange

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Signature

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |

### Asymmetric Cipher

| Algorithm | Parameters | FIPS certified |
| --- | --- | --- |