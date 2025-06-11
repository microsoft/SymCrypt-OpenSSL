# KeysInUse
KeysInUse logging allows application owners to keep inventory of which certificates and keys are actively being used on their machine.
This functionality is built into the SymCrypt provider (see [KeysInUse Logging](../SymCryptProvider/README.md#keysinuse-logging)) and
exported as an API for other providers and applications to optionally use. KeysInUse can optionally be  built as a standalone library
for use independent of the SymCrypt provider. If SymCrypt is not found, the project will still build the standalone KeysInUse library
and tests.

KeysInUse was originally implemented as the [KeysInUse engine for OpenSSL 1.1.1](https://github.com/microsoft/KeysInUse-OpenSSL), but
has been moved here to support scenarios for OpenSSL 3.

If you want KeysInUse to log to syslog instead of `/var/log/keysinuse`, you can specify `-DKEYSINUSE_LOG_SYSLOG=1` in the CMake
configuration step. Syslog logging depends on libsystemd.

## Testing
The KeysInUse tests test both the KeysInUse API, and optionally any providers or engines that use KeysInUse. The test assumes any
supplied engines or providers are using the KeysInUse API found here, and not a custom solution.
```
Usage: KeysInUseTest <options>
Options:
  --engine-path <engine_path>       Specify the path of an engine to test.
  --engine <engine_name>            Specify an engine to use for key operations
  --provider-dir <provider_path>    Specify a directory to locate providers with with keysinuse. Must come before provider
  --provider <provider_name>        Specify a provider with keysinuse to test by name
  --verbose                         Enable verbose output
```