# Eclipse Token (experimental)

The repository currently contains a block-header serialization exercise,
ML-DSA wrappers, and an in-memory wallet key skeleton. There is no transaction
or consensus integration yet.

## Build and test

Requires CMake, ncurses development headers, and OpenSSL 3.5 or later with
ML-DSA support.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Developer CLI

`eclipse-cli` only calls APIs already implemented in this repository. It does
not create blocks, transactions, wallets, or network state. Run
`./build/eclipse-cli` for the ncurses menu, or use `serialize` and
`deserialize` without arguments for step-by-step ncurses input. Enter and
Backspace edit fields; invalid fields stay on screen for correction and Esc
cancels. Long results scroll with Up/Down and are
also printed to stdout after leaving the interface.

The argument forms work without a terminal and print only the result to
stdout. Logs go to stderr by default:

```sh
HASH=$(printf '%064d' 0)
./build/eclipse-cli serialize 1 2 3 4 "$HASH" "$HASH"
./build/eclipse-cli "serialize(1,2,3,4,$HASH,$HASH)"
HEX=$(./build/eclipse-cli --log-level 0 serialize 1 2 3 4 "$HASH" "$HASH")
./build/eclipse-cli deserialize "$HEX"
./build/eclipse-cli math mod -1
./build/eclipse-cli ml-dsa self-test 44 "development message" "eclipse-cli"
```

The header has six fields in the order `version`, `timestamp`, `difficulty`,
`nonce`, `prev_block_hash`, `merkle_root`. Numeric fields accept decimal or
`0x`-prefixed hexadecimal; hashes require exactly 64 hex digits each.
`deserialize` accepts exactly 176 hex digits. The ML-DSA self-test creates an
ephemeral key, exports and imports its public key, signs the given message,
then verifies it. It does not write a private key to disk.

Use `--log-level 0..5` to control detail and `--log-file PATH` to append logs
to a file. The CLI never logs raw arguments, header bytes, messages, keys, or
signatures.

## ML-DSA module

`src/core/crypto/ml_dsa.h` exposes ML-DSA-44, ML-DSA-65, and ML-DSA-87
key generation, public-key import/export, message signing, and verification.
OpenSSL implements the FIPS 204 cryptography; this module only handles the
application-facing API and input checks. Generated private keys currently live
in memory only.

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

## Wallet key skeleton

`src/core/wallet/keypair.h` contains a standalone `generate_keypair` wrapper.
`src/core/wallet/wallet.h` builds one receive master and one spend master,
plus 24 independently random child ML-DSA key pairs for each role. Each master
signs its own child public keys with a context, role, scheme, and index; the
wallet can verify these bindings. A separate public verifier rejects a wrong
master, role, or index. Binding signatures are not part of the network key
packet: publishing several under one master would reveal a link between keys.
There is no wallet seed or deterministic child derivation. OpenSSL does use
random input internally for each ML-DSA
key-generation call, as described in its
[ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/).

The two *master private keys* can be exported separately as Base92 strings
through `eclipse_wallet_export_master_base92`. They are unencrypted secrets.
The Base92 codec follows the published
[thenoviceoof/base92 format](https://github.com/thenoviceoof/base92/blob/master/python/docs/encoding.md)
and rejects noncanonical strings when decoding. The export packet is `EWMS`,
version 1, role byte, scheme byte, two-byte big-endian private-key length,
expanded FIPS 204 private bytes, and a 32-byte SHA-256 checksum. The checksum
only detects accidental corruption; it does not protect against deliberate
changes. No import, backup, or disk storage is implemented. Exporting a master
does not preserve or recreate the 24 independent child private keys.

For a future network transport, `eclipse_wallet_public_serialize` encodes one
public key as `EWPK`, version 1, scheme byte, two-byte big-endian length, and
the public key bytes. Its Base92 form carries the same packet. This is a
provisional developer format, not a consensus object. It includes no role,
index, master public key, or master signature, so it does not link the pools
through this packet. There is no receive or spend transaction logic yet. The
separation of master keys alone cannot enforce spending permissions; future
consensus rules must define and check them.

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
