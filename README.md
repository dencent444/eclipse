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

## Logging

`src/core/log.h` provides `ECLIPSE_LOG_ERROR`, `ECLIPSE_LOG_WARNING`,
`ECLIPSE_LOG_SECURITY`, and `ECLIPSE_LOG_INFO(level, ...)`. INFO levels run
from 1 (essential) to 5 (most detailed). The default INFO setting is 1; set
it to 0 to suppress INFO or 5 to enable every INFO message. ERROR, WARNING,
and SECURITY are always emitted. SECURITY is reserved for future security
events and has no production call sites yet.

Suggested INFO use: 1 for node lifecycle and chain-tip changes, 2 for peer and
block events, 3 for synchronization details, 4 for validation decisions, and
5 for very detailed diagnostics. These levels control logging volume only;
they must never change consensus behavior.

Block header serialization and ML-DSA math utilities report successful calls
at INFO 5. ML-DSA key generation and signing report at INFO 3; verification
decisions and rejected serialized input report at INFO 4. Invalid caller
arguments produce WARNING messages, while cryptographic provider failures
produce ERROR messages. These modules do not log key material, signatures,
messages, or serialized bytes.

```c
eclipse_log_set_info_level(3);
ECLIPSE_LOG_INFO(1, "node started");
ECLIPSE_LOG_INFO(3, "connected to %zu peers", peer_count);
ECLIPSE_LOG_WARNING("peer sent an invalid block");
eclipse_log_set_file("node.log"); /* append; logger owns this file */
```

Each line contains a UTC timestamp, severity, source file, line, function,
and message. The logger uses a mutex so concurrent calls do not interleave.
Messages over 4095 bytes are marked as truncated. Line breaks and control
characters in a message are replaced with spaces. Never log private keys,
seeds, or other wallet secrets. A file opened by `eclipse_log_set_file` is
closed by `eclipse_log_shutdown` or when the destination changes. Newly
created log files are restricted to the current user (mode 0600, subject to
the process umask).
