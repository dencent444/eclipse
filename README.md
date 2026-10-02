# Eclipse Token (experimental)

The repository currently contains a block-header serialization exercise and
an isolated ML-DSA signature wrapper. There is no transaction or consensus
integration yet.

## Build and test

Requires CMake and OpenSSL 3.5 or later with ML-DSA support.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## ML-DSA module

`src/core/crypto/ml_dsa.h` exposes ML-DSA-44, ML-DSA-65, and ML-DSA-87
key generation, public-key import/export, message signing, and verification.
OpenSSL implements the FIPS 204 cryptography; this module only handles the
application-facing API and input checks. Generated private keys currently live
in memory only. Wallet key storage and backup are future work.

`src/core/crypto/ml_dsa_math.h` contains small, readable reference utilities
for arithmetic modulo q = 8,380,417 and polynomials modulo X^256 + 1. This is
for learning the algebra in FIPS 204. The polynomial multiplier is quadratic
and not constant time. It is not used by signing and must not be used for
production cryptography.

Signatures use **Pure ML-DSA** with OpenSSL's default randomized signing. The
caller provides a context string (up to 255 bytes) for domain separation.
A future transaction protocol must specify the exact scheme, context, signed
message bytes, and key format. The enum numbers in this module are local API
values, not committed consensus identifiers.
