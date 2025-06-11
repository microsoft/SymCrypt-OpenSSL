# SymCrypt Provider
The SymCrypt provider implements the [OpenSSL provider interface](https://docs.openssl.org/3.0/man7/provider/) to supply cryptographic
operations from SymCrypt to OpenSSL's libcrypto.so. The provider interface was added in OpenSSL 3 and has largely replaced the functionality
of the engine interface. For OpenSSL 1.1.1 and legacy function support in OpenSSL 3, see the [SymCrypt engine](../SymCryptEngine/).

All cryptographic operations using the EVP APIs in OpenSSL 3 are handled by a provider. The deprecated legacy APIs, hardcoded with a specific
algorithm name (e.g., RSA_*) will not use providers, and should not be used in OpenSSL 3. The OpenSSL implementations are found in the default
provider, or the FIPS provider when OpenSSL is compiled with FIPS mode. 

Multiple providers can be loaded at once, with the same set of
algorithms and/or new algorithms. When multiple providers support the same algorithm, OpenSSL's 
[algorithm fetching rules](https://docs.openssl.org/3.3/man7/ossl-guide-libcrypto-introduction/#algorithm-fetching) are used to select
which provider (if any) will handle a particular operation. Once selected, OpenSSL expects the provider to handle the operation entirely.
If a provider does not support a requested algorithm, it will be ignored for that particular algorithm. This means, that if the SymCrypt
provider does not support an algorithm, other providers can be used if loaded.

Providers' implementations may differ, and are not guaranteed to have the same behavior. We attempt to make the SymCrypt provider behave as
close to the default provider for compatibility, but some differences still exist. The SymCrypt provider does not have a reliable and 
performant way of falling through to a different provider. If the caller uses a parameter set the SymCrypt provider does not support, for
an algorithm the SymCrypt provider does support, the operation will fail. For example, the SymCrypt provider only supports a set of named 
curves for ECDH and ECDSA. Attempting to use a curve other than those listed below will fail with the SymCrypt provider.

_Compatibility between the default provider and SymCrypt provider is not guaranteed. Please test your application with the SymCrypt provider.
Any undocumented or unexpected incompatibilities should be raised in the issue tracker._

## Algorithms Supported by the SymCrypt Provider
The following list is not necessarily exhaustive, and will be updated as more functionality is added to SCOSSL.
Note that just because an algorithm is FIPS certifiable, does not mean it is recommended for use.

### Hashing
- MD5
- SHA1
- SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- SHAKE128, SHAKE256
- CSHAKE128, CSHAKE256

### Symmetric Cipher
- AES-CBC (128, 192, 256)
- AES-ECB (128, 192, 256)
- AES-CFB (128, 192, 256)
- AES-CFB8 (128, 192, 256)
- AES-GCM (128, 192, 256)
- AES-CCM (128, 192, 256)
- AES-XTS (128, 256)

### Message Authentication
- CMAC
- HMAC
- KMAC (128, 256)

### Key Derivation
- HKDF
- KBKDF
- SRTPKDF
- SSHKDF
- SSKDF
- TLS1-PRF

### Random Number Generation
- CTR-DRBG

### Key Exchange
- DH (Named groups only)
    - ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
    - modp2048, modp3072, modp4096
- ECDH (Named curves only)
    - P-192, P-224, P-256, P-384, P-521
- X25519

### Signature
- RSA
    - PKCS1, PSS
- ECDSA (Named curves only)
    - P-192, P-224, P-256, P-384, P-521

### Asymmetric Cipher
- RSA
    - PKCS1, OAEP

## Installation
We maintain the SymCrypt-OpenSSL packages with the SymCrypt provider for a set of Linux distributions. If your platform isn't listed here, 
please see [Build From Scratch](#build-from-scratch).

### Azure Linux 3
The SymCrypt provider is available in Azure Linux 3 and enabled by default. 

### Debian package
The SymCrypt provider is available as an optional package on [packages.microsoft.com](https://learn.microsoft.com/en-us/linux/packages)
for the following distributions:
- Ubuntu 22.04 (jammy)
- Ubuntu 24.04 (noble)
- Debian 12 (bookworm)

The packages installs the SymCrypt provider and a baseline configuration to `/etc/symcrypt-openssl/symcrypt_prov.cnf`, but does not enable 
the provider. The OpenSSL config must be updated to include the SymCrypt provider config, or the SymCrypt provider can be loaded
programmatically with the [OPENSSL_PROVIDER](https://docs.openssl.org/master/man3/OSSL_PROVIDER/) API.

#### Example `openssl.cnf`
```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
symcrypt_provider = symcrypt_prov_sect

[default_sect]
activate=1

.include /etc/symcrypt-openssl/symcrypt_provider.cnf

...
```

### Build From Scratch
See [Building Instructions](../README.md#building-instructions) for building the SymCrypt provider. The SymCrypt provider is built to
`bin/SymCryptProvider/symcryptprovider.so`. It should be installed to the OpenSSL modules directory (`openssl version -m`). The provider can
either be enabled by the [OpenSSL config](https://docs.openssl.org/master/man5/config/#provider-configuration) or programmatically with the
[OPENSSL_PROVIDER](https://docs.openssl.org/master/man3/OSSL_PROVIDER/) API. The [example configuration](symcrypt_prov.cnf) can be used as a
reference or included in the OpenSSL config using the `.include` keyword.

## Configuration
The SymCrypt provider can be configured in the SymCrypt provider section of the OpenSSL config (`symcrypt_prov_sect` by default). See the 
[example configuration](symcrypt_prov.cnf) for reference.

### Debug Logging
| Key           | Description                                                                                                                                   | Default   |
| -             | -                                                                                                                                             | -         |
| logging_file  | Location to write debug logging events to.                                                                                                    | NULL      |
| logging_level | Maximum level to log to logging file. In order, can be <ul><li>off</li><li>error</li><li>info</li><li>debug</li></ul>                         | off       |
| error_level   | Maximum level to push logging events to OpenSSL error stack. In order, can be <ul><li>off</li><li>error</li><li>info</li><li>debug</li></ul>  | error     |

### KeysInUse Logging
The SymCrypt provider optionally supports [KeysInUse logging](../KeysInUse/README.md) for monitoring private key usage.
The primary motivation is for application owners to keep inventory of which certificates and keys are actively being used on their machine.
The feature is off by default and must be enabled by config. If you are building the SymCrypt provider from scratch, the feature also needs
to be enabled at compile time by adding the `-DKEYSINUSE_ENABLED=1` to the cmake configuration step. KeysInUse configuration is placed in a
separate section. This section must be referenced in the symcrypt provider section with the `keysinuse` key.
| Key                   | Description                                                                                                                                   | Default   |
| -                     | -                                                                                                                                             | -         |
| enabled               | 0 or 1 to disable or enable keysinuse logging.                                                                                                | 0         |
| max_file_size         | Maximum size of the file events are written to. May be written as raw byte size or suffixed with KB/MB/GB                                     | 5KB       |
| logging_delay_seconds | Duration in seconds between events being written to the file. Any events that happen in between will be aggregate and logged as one event.    | 3600      |