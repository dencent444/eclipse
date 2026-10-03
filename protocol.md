# Eclipse protocol sketch (developer v0)

This document records implemented bytes and the intended boundaries of the
experiment. It is **not** a mainnet consensus specification. Changing a
commitment or transaction encoding requires a new version and test vectors.

## Local developer chain (block v1)

The empty genesis is the fixed SHA3-256 digest of ASCII
`ECLIPSE/DEV/GENESIS/V1`. It has height zero and **zero spendable supply**.
Height one is the first mined block. This is still an in-memory developer
protocol, not a public mainnet or a networked full node.

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
snapshots in memory. It does not yet persist the chain, adjust difficulty,
accept untrusted peers, synchronize over P2P, maintain a mempool, or enforce
wall-clock future-time limits. A block decoder checks the packet and root;
only chain acceptance checks parent, PoW, reward, signatures, and UTXO rules.
Fixed 8-bit work is intentionally cheap for local experiments.

## Transparent transaction (developer v0)

This first transaction format is deliberately transparent and independent of
the private `eclipse-particle` experiment below. It transfers existing UTXOs;
it does not create money. `eclipse_utxo_set_seed_dev` inserts local test funds
until coinbase rewards and validated blocks exist. Calling that function is
not a consensus minting rule.

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
transfers on parent snapshots and adds block rewards, but has no mempool or
disk state. `eclipse-cli tx decode` only checks the format because it has no
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
