# Eclipse protocol sketch (developer v0)

This document records implemented bytes and the intended boundaries of the
experiment. It is **not** a mainnet consensus specification. Changing a
commitment or transaction encoding requires a new version and test vectors.

## Local developer chain (block v1)

The empty genesis is the fixed SHA3-256 digest of ASCII
`ECLIPSE/DEV/GENESIS/V1`. It has height zero and **zero spendable supply**.
Height one is the first mined block. The chain can run in memory or replay
an append-only local journal. Developer nodes can exchange validated data over
the provisional P2P protocol below; this is not a public mainnet.

A block has at most eight signed `ETX0` transactions. Its exact wire form is:

```text
ASCII("EBL1")
|| header[88]
|| transaction_count_u8
|| reward_amount_u64be || reward_scheme_u8 || reward_key_length_u16be || reward_public_key
|| for each transaction: length_u32be || signed_transaction_bytes
```

The 88-byte header layout is documented in `src/core/block/block.h`. Its
version is exactly 1. A block hash is
`SHA3-256(ASCII("ECLIPSE/DEV/BLOCK/ID/V1") || header[88])`. Every block links
to its parent hash; height one links to the fixed genesis digest. The header
`merkle_root` commits to the **reward claim and ordered signed transactions**:

```text
reward leaf = SHA3-256(ASCII("ECLIPSE/DEV/BLOCK/REWARD/V1") || reward wire fields)
tx leaf     = SHA3-256(ASCII("ECLIPSE/DEV/BLOCK/TX/V1") || transaction_id[32])
parent      = SHA3-256(ASCII("ECLIPSE/DEV/BLOCK/NODE/V1") || left[32] || right[32])
```

At each tree level the last leaf is duplicated if the width is odd. One
reward leaf alone is already the root. The reward outpoint has index zero and
ID `SHA3-256(ASCII("ECLIPSE/DEV/REWARD/ID/V1") || block_hash[32])`. It can be
spent from the next block; a transaction in its own block cannot spend it.
The fixed vector in `tests/chain_test.c` uses the ML-DSA-44 public key from
seed `01 || 00×31`, height-one reward 5,000,000,000, timestamp 1, difficulty
8, nonce 0 and no ordinary transactions. Its genesis digest is
`b0d1787f93b82fbf52777889c17bb15fd52b241fcc2d05047d36b585b4faf20a`,
root is `f796ed7acf0a489adb15a2d567e6fbbad489b3a21aa78259037ad57fd2fd4648`,
and pre-mining block hash is
`661399fe4e59ce3ccc59357f972c531187152fdcd8d8eb168581e24149de6d29`.

The developer subsidy is 5,000,000,000 smallest units at height 1 and halves
every 210,000 blocks. A valid reward amount is **exactly** subsidy at that
height plus the sum of this block's transaction fees. `ETX0` transactions
cannot mint value. A block applies its transactions in their listed order,
then inserts the reward output. This permits an ordinary output from an
earlier transaction in the same block to be spent later in that block.

Current PoW difficulty is a fixed **8 leading zero bits** in the block hash.
The difficulty header field must equal 8. The timestamp must be greater than
its parent's and no more than 7,200 seconds later. These checks depend only
on chain data, not on the validating machine's clock. Each accepted block adds
`2^8` units of dev work. The canonical branch has the greatest accumulated
work; equal-work tips use the lexicographically smaller block hash. Every
candidate is validated against a snapshot of its own parent's UTXO state, so
changing the canonical tip changes the visible state without editing a shared
state in place.

The implementation retains validated side branches and per-block UTXO
snapshots in memory. Each snapshot keeps only live outputs in a dense array
with a locally seeded hash lookup index; spent outputs are removed when a
transaction applies. Snapshot cloning still copies every live output for
each accepted block, so long chains and many side branches can consume large
amounts of RAM. The optional disk journal retains every accepted block,
including side branches, and replays them through the same validator on open.
It does not yet adjust difficulty or enforce wall-clock future-time limits.
The developer P2P transport accepts untrusted peer bytes, but its resource
controls are not sufficient for a public network. A block decoder checks the
packet and root; only chain acceptance checks parent, PoW, reward, signatures,
and UTXO rules. Fixed 8-bit work is intentionally cheap for local experiments.

## Local chain journal and mempool

`eclipse-node run DATA_DIR` owns one journal writer and one Unix socket
`DATA_DIR/node.sock`. Its `ctl` commands are local developer control calls,
not consensus messages or peer networking. The process replays the journal
before listening, validates incoming transaction and block wire bytes using
the core APIs, refreshes the mempool after tip changes, and removes its socket
on a clean stop. A killed process may leave a stale socket, which a new owner
of the locked journal removes at startup. No wallet secret enters node storage.

`eclipse_chain_open(path)` creates or opens an exclusive-writer local journal.
The file starts with ASCII `ECS1` followed by the 32-byte dev genesis hash.
Each record is `block_length_u32be || canonical_block_wire ||
SHA3-256(canonical_block_wire)`. The journal checksum detects damaged bytes;
it is **not** a substitute for consensus checks. Loading decodes and validates
every complete block, including parent, PoW, reward, transaction signatures,
and UTXO transitions. A truncated final record is discarded and the file is
truncated to the last complete record. A complete record with an invalid
checksum or block makes opening fail. Appending a validated block is flushed
with `fsync` before it becomes visible in memory. There is no snapshot,
compaction, or concurrent-write support yet. Files contain public transparent
chain data, never wallet private keys. A locally replaced *valid* journal
cannot be detected without comparing to independent peers or checkpoints.

The in-memory mempool is **local policy, not consensus**. It accepts only
transactions valid against the canonical UTXOs plus earlier pending
transactions, so unconfirmed parent/child transfers can be queued in order.
It rejects duplicates, conflicting inputs, bad signatures and malformed
packets. Current limits are 64 pending transactions and 1 MiB of combined
wire bytes; block candidates take the first eight. On a canonical-tip change,
it rebuilds against the new state, removes confirmed/conflicting transfers,
and reconsiders transactions from disconnected blocks in block order.
Pending transactions are not stored in the chain journal and are lost on
process exit. There is no fee prioritization, replacement-by-fee, expiry,
or mempool persistence yet. The developer P2P layer relays pending transfers.

## Developer P2P wire protocol (EPN1)

P2P runs on a **separate TCP listener** when `--p2p-listen HOST PORT` is
supplied. The Unix control socket is never shared with peers. `--peer HOST
PORT` configures one static outbound peer; the node reconnects periodically.
For onion peers, `--tor-socks HOST PORT` routes the connection through SOCKS5
using domain-name mode, so the onion hostname is sent to Tor without local DNS
resolution. With `--auto-onion CONTROL_PORT COOKIE_FILE VIRTUAL_PORT`, the node
binds its P2P listener to IPv4 loopback (or requires an existing loopback
listener), authenticates to Tor's local ControlPort using SAFECOOKIE, and
registers `ADD_ONION` for the virtual TCP port. It verifies Tor's server HMAC
before sending its own authentication proof. Tor generates the v3 service key;
the node writes it to mode-0600 `onion.key` in its mode-0700 data directory and
reuses it after restarts. The control connection stays open while the service
is active; a worker restores it after a Tor restart. `status` exposes only the
public address and port. No UDP or automatic peer discovery is implemented.

Each P2P frame is `ASCII("EPN1") || type_u8 || length_u32be || payload`.
Payloads are capped at `ECLIPSE_BLOCK_MAX_WIRE_SIZE`; oversized frames are
rejected before allocating from their lengths. Types are `HELLO=1`,
`LOCATORS=2`, `BLOCK=3`, `TRANSACTION=4`, `END=5`. A session has a 20-second
monotonic deadline checked between I/O operations and a three-second socket
I/O timeout. A HELLO contains protocol version 1, dev network ID `EVD1`, the
fixed genesis hash, advertised height and tip hash, and a random 16-byte
process ID. Version/network/genesis mismatches and self-connections are
rejected. Advertised heights and hashes are hints, not trusted state.

A locator payload has one count byte (1–32), then entries of `height_u64be ||
block_hash[32]`. A node sends its recent canonical ancestors with exponential
backoff to genesis and may prepend its last downloaded side-branch block.
The peer chooses the first locator that matches its own canonical history.
It sends up to 128 successive canonical block packets and an `END` frame.
The two sides repeat this in the opposite direction, then each sends up to 64
pending signed transactions and `END`. Later sessions continue partial sync.

The receiver independently decodes and validates each new block through
`eclipse_chain_accept`. A new canonical tip triggers mempool reconciliation.
Every relayed transaction goes through `eclipse_mempool_submit`; duplicates and
conflicts are not admitted. Peers provide data, never consensus authority.
Current limits still allow algorithmic and storage denial of service on an
open network: every accepted block retains a UTXO snapshot, difficulty is
fixed at eight bits, and there is no peer reputation, orphan cache, snapshot
sync, or production-grade ingress scheduling.

## Transparent transaction (developer v0)

This first transaction format is deliberately transparent and independent of
the private `eclipse-particle` experiment below. It transfers existing UTXOs;
it does not create money. `eclipse_utxo_set_seed_dev` inserts local test funds
for standalone UTXO tests. It is never used to initialize a chain and is not
a consensus minting rule.

All integers below are unsigned big-endian. No C struct padding or native
endianness is serialized. A signed transaction is exactly:

| Part | Encoding |
| --- | --- |
| Header | ASCII `ETX0` (4), version `0` (1), network ID ASCII `EVD1` (4), input count (1), output count (1), fee (8) |
| Each input | previous transaction ID (32), previous output index (4), ML-DSA signature length (2), signature bytes (that length) |
| Each output | amount (8), scheme ID (1: 44→1, 65→2, 87→3), public-key length (2), public-key bytes (that length) |

Counts must each be 1–8. Every output amount is positive. Key and signature
lengths must match one of the supported ML-DSA parameter sets; an input's
signature must specifically match the scheme of its referenced UTXO. Unknown
versions, network IDs, schemes, repeated inputs, truncated packets and trailing
bytes are rejected. A complete signed transaction is at most 58,163 bytes.

For input `i`, the Pure ML-DSA signature context is ASCII
`ECLIPSE/DEV/TX/V0`. The signed message is:

```text
ASCII("ECLIPSE/DEV/TX/SIGN/V0")
|| header above
|| for each input: previous_txid[32] || previous_index_u32be
|| for each output: amount_u64be || scheme_u8 || key_length_u16be || public_key
|| input_index_u8
```

Signatures are excluded from this message, so no signature signs its own
bytes. The message binds **all** inputs, outputs, the fee, the dev network ID,
and the input index. The transaction ID is
`SHA3-256(ASCII("ECLIPSE/DEV/TX/ID/V0") || complete_signed_wire_bytes)`.
ML-DSA signing is randomized, so re-signing may change the transaction ID.
The fixed signing-message vector in `tests/tx_test.c` uses a 100-unit input,
outputs of 60 and 39, a fee of 1, and ML-DSA-44 public keys derived from
32-byte seeds `01 || 00×31` and `02 || 00×31`. Its message has 2,724 bytes;
SHA3-256 of those bytes is
`06a9ab9472e038284d94025b5b45f0bff79730917095fbee01c2530a45c3ee52`.

Validation against an independent UTXO set checks that every input is present
and unspent, its signature verifies under that output's public key, sums fit
in `uint64_t`, and `sum(inputs) == sum(outputs) + fee`. Applying a transaction
first validates and reserves memory, then marks inputs spent and inserts
outputs under `(transaction ID, output index)`. The standalone in-memory set
has no disk persistence or concurrent access. The chain applies ordered
transfers on parent snapshots and adds block rewards; its optional journal
stores blocks and reconstructs this state on replay. `eclipse-cli tx decode`
only checks the format because it has no
independently validated UTXO set.

The wallet helper signs with a child of the **spend** domain. An output must
name that child's public key to be spendable by it. The separate receive
domain currently has no transaction discovery or recipient encryption role.
This transparent v0 does not provide sender, receiver, amount, or graph privacy.
The wallet API's role separation is local; this format does not cryptographically
distinguish a receive public key from a spend public key.

## Eclipse-particle

An **eclipse-particle** is the current name for a private note opening:

| Field | Size | Meaning at this stage |
| --- | ---: | --- |
| `amount` | 8 bytes | Unsigned integer in smallest units; supply limits are not defined yet. |
| `receive_material` | 32 bytes | Opaque receiver material; discovery semantics are not defined yet. |
| `spend_authority` | 32 bytes | Opaque authority identifier; spending rules are not defined yet. |
| `randomness` | 32 bytes | Fresh random secret for this particle. |

`eclipse_particle_create` generates `randomness` through OpenSSL
`RAND_priv_bytes`. All four fields form the private **opening**. They must not
be published as a plain network note. The 32-byte **commitment** is derived
from this opening; it is not an input field and is not hashed into itself.

For this developer version, the exact commitment is:

```text
SHA3-256(
    ASCII("ECLIPSE/PARTICLE/COMMIT/V1")
    || amount as unsigned 64-bit big-endian
    || receive_material[32]
    || spend_authority[32]
    || randomness[32]
)
```

There are no padding bytes, delimiters, NUL terminators, or struct-memory
copies in the preimage. It is 130 bytes total. A commitment is 32 bytes.
The fixed vector in `tests/particle_test.c` uses amount
`0x0102030405060708`, receive bytes `00..1f`, spend bytes `20..3f`, and
randomness bytes `40..5f`; its digest is
`cbadd903974ab7eb94d7a9790cb606c02169be1f11eeda6c1f839a361c8cc702`.

The commitment may be published. Its opening, especially `amount` and
`randomness`, remains private. Randomness must be fresh and secret: publishing
it alongside the other fields destroys the intended hiding. Recomputing the
commitment shows that an opening matches a digest. **This alone does not prove**
ownership, permitted creation, value conservation, or absence of double spends.

Future private transactions would need recipient encryption, a commitment
tree, nullifiers, and a proof that binds a valid spend to a prior commitment
while hiding its opening. The eventual proof system may require replacing this
hash with a different, reviewed commitment construction. `receive_material`
and `spend_authority` deliberately do not yet encode the wallet's ML-DSA keys.

Design references: [Zcash notes and commitments](https://zips.z.cash/protocol/protocol.pdf),
[NIST SHA-3 / FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
