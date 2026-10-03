# Eclipse Token (experimental)

The repository currently contains a block-header serialization exercise,
ML-DSA wrappers, an in-memory wallet key skeleton, and an eclipse-particle
commitment prototype. There is no transaction or consensus integration yet.

## Build and test

Requires CMake, ncurses development headers, and OpenSSL 3.5 or later with
ML-DSA support. The current implementation targets POSIX systems (Linux,
macOS, and BSD). CMake selects the target compiler and libraries; the C
compiler selects the CPU architecture at build time. The project does not add
`-march=native`, so a binary is not accidentally tied to the build machine.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/eclipse-cli build-info
```

`build-info` prints the architecture, pointer width, byte order, and OS baked
into the binary. It uses target compiler macros, which also work when building
with a CMake cross-compilation toolchain. A cross build still needs OpenSSL and
ncurses libraries for the target system. The existing block, wallet packet,
and particle encodings use explicit byte layouts rather than native C structs.

## Developer CLI

`eclipse-cli` only calls APIs already implemented in this repository. It does
not create blocks, transactions, or network state. Run
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
./build/eclipse-cli keypair generate 44
./build/eclipse-cli base92 encode 68656c6c6f
./build/eclipse-cli particle create 10 "$HASH" "$HASH"
./build/eclipse-cli particle commit 10 "$HASH" "$HASH" "$HASH"
./build/eclipse-cli 'serialize(1,2,3,4,0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000000) // deserialize // !grep version'
./build/eclipse-cli shell
./build/eclipse-cli shell-info
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

The CLI also exposes `ml-dsa derive-public`, `math add|sub|mul`, Base92
decode, `particle verify`, and wallet creation, domain export, public-key
derivation, public packet decoding, and child binding verification. See
`./build/eclipse-cli help` for the complete argument forms. `wallet create`
prints an **unencrypted recovery root** to stdout; `wallet domain` prints an
unencrypted role secret. Treat either output as private.

`shell` is a line-oriented developer REPL; the ncurses menu also offers it.
`pipe 'STAGE // STAGE'` runs one pipeline, and a quoted pipeline expression can
be passed directly as shown above. `//` connects stdout to the next stage;
`!grep version` explicitly runs the external `grep` program. External stages
use `execvp`, with no shell expansion or implicit commands. Use `-` as an
input value for commands that accept one piped value, such as
`wallet create 44 // wallet domain - receive`. The CLI writes logs to stderr
by default, so they do not enter the data pipe. Logs omit keys, wallet roots,
particle openings, and serialized values. Shell history and process arguments
can still expose secrets supplied on the command line; keep secret commands
in a private development environment.

At every launch, the CLI identifies the invoking shell from the Linux parent
process when possible and otherwise uses `SHELL` as a hint. `shell-info` and
`help` show guidance for bash, zsh, fish, PowerShell, and POSIX shells; the
ncurses menu displays the detected profile. Unknown shells get a safe generic
path. The compiled binary is the same for every shell. The outer shell parses
its command line before the CLI starts, so quoting cannot be repaired after
the fact. Enter raw `()`, `!`, and `//` inside `eclipse-cli shell`, or use
`eclipse-cli pipe -` to read one expression from stdin. For example, a file
containing `math mod -1 // !cat` can be run with
`./build/eclipse-cli pipe - < commands.txt`.

The provisional particle fields and exact commitment bytes are in
[`protocol.md`](protocol.md). A particle opening is private, while its derived
SHA3-256 commitment can be shared. The CLI's `particle create` intentionally
prints the opening for development inspection only.

## ML-DSA module

`src/core/crypto/ml_dsa.h` exposes ML-DSA-44, ML-DSA-65, and ML-DSA-87
random or seeded key generation, public-key import/export, private-key export,
message signing, and verification.
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

`src/core/wallet/keypair.h` retains a standalone random `generate_keypair`
wrapper for experiments. The recoverable wallet in `src/core/wallet/wallet.h`
uses one randomly generated 32-byte root. HKDF-SHA256 derives separate receive
and spend domain secrets using fixed dev-wallet labels, scheme, and role. Each
domain deterministically derives a certificate-master ML-DSA pair and 24 child
pairs with separate labels and indices. OpenSSL accepts a 32-byte seed for
deterministic ML-DSA key generation, as documented in its
[ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/).
The derivation is HKDF extract-and-expand with salt
`ECLIPSE/DEV/WALLET/V1/HKDF-SHA256`. Domain `info` is the literal label
`ECLIPSE/DEV/WALLET/V1/DOMAIN`, one scheme byte, then one role byte. Key
`info` is the literal label `ECLIPSE/DEV/WALLET/V1/KEY`,
scheme byte, role byte, key-kind byte (master or child), and a four-byte
big-endian index. Changing any of these bytes changes every affected key.

`eclipse_wallet_create(scheme, &root, &wallet)` returns the root **separately**
from the full wallet. `eclipse_wallet_open(root, &wallet)` rebuilds both pools;
`eclipse_wallet_derive_domain(root, role, &domain)` and
`eclipse_wallet_open_domain(domain, &wallet)` build a role-only wallet without
the other domain or the root. A receive-only object cannot return spend keys.
The full wallet contains both domains' derived private keys, so it is not a
view-only object. Free root/domain objects when no longer needed; their owned
buffers are cleansed. There is no automatic backup or disk persistence.

The root and each role domain have separate explicit Base92 export/import
functions. The text is an **unencrypted secret** and caller-owned text buffers
must be cleansed. Root exports can rebuild both roles; receive-domain exports
can rebuild only receive, and spend-domain exports only spend. Packet formats
are `EWRT || version || scheme || root || SHA-256` and
`EWDM || version || scheme || role || domain secret || SHA-256`. The checksum
detects accidental damage, not malicious modification. The codec follows the
[thenoviceoof/base92 format](https://github.com/thenoviceoof/base92/blob/master/python/docs/encoding.md)
and rejects noncanonical text. An older `EWMS` master-private export cannot
restore the old independently random children and is no longer used.

Each role master signs its child public keys with a context, role, scheme, and
index; the wallet can verify these bindings. A separate public verifier rejects
a wrong master, role, or index. Binding signatures are not part of the network
key packet: publishing several under one master would reveal a link between
keys. The 24 receive ML-DSA keys currently represent only a key-management
prototype, **not** a working private-note discovery mechanism. Actual viewing
keys depend on the future transaction format. The KDF's dev labels and fixed
24-slot pools are not mainnet consensus specifications.

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
