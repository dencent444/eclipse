# Eclipse shielded transactions: design proposal

This is a design document, **not active consensus**. An experimental `ESX1`
implementation now lives in `rust/shielded`; `EBL1`, the C node, mempool, and
P2P still accept only transparent `ETX0`. The current `ETX0` format
publishes outpoints, amounts, and output keys. Tor affects peer transport, not
those ledger bytes. The existing `eclipse-particle` SHA3 commitment checks an
opening but does not prove ownership, conservation, or absence of double spend.

## Security target

A node must independently verify that every private spend consumes previously
created value exactly once, has valid authorization, pays its public fee, and
cannot inflate supply. A chain observer should not learn the spent commitment,
recipient, individual amounts, wallet balance, or transaction graph. The chain
will still expose time, fee, size bucket, anchor, nullifiers, output
commitments, ciphertexts, and inclusion. The sender knows their own payment;
wallet compromise and network timing are separate leak channels.

| Property | Public validation | Hidden data |
| --- | --- | --- |
| Existing value | Proof of membership under a valid commitment-tree anchor | Spent note and Merkle path |
| One spend | Unique nullifier on the candidate branch | Note-to-nullifier link |
| Authorization | Transaction-bound spend proof and signature | Spend secret and note identity |
| Conservation | Bounded input sum equals output sum plus fee | Individual values |
| Discovery | Bounded encrypted output accompanies each commitment | View key detects/decrypts notes |
| Reorganization | Tree, nullifiers, and supply follow the chosen branch | Wallet refreshes witnesses locally |

## New private pool

`ETX0` will not be reinterpreted. A shielded transaction needs a new type,
version, network ID, canonical encoding, resource limits, transaction ID, and
an explicit activation rule. The semantic envelope is:

```text
network_id | version | commitment_tree_anchor | public_fee | padded_action_count
actions[]: nullifier | output_commitment | value_commitment
           | ephemeral_view_key | encrypted_note
proof | spend_authorization | balance_binding_signature
```

These are **not final wire offsets**. The selected proof implementation must
fix byte encodings, canonical field elements, proof and ciphertext lengths,
and test vectors before a validator accepts the format. Counts should be
padded into buckets, starting with two actions and later four/eight. Dummy
actions must be constrained to zero value so they cannot mint spendable notes.
Visible bucket size still leaks a coarse activity measure.

### Proof statement

For each real input, a proof must show that its private opening forms a note
commitment in the public anchor tree; that its public nullifier is derived
from that same note and an authorized secret; and that authorization binds
the entire transaction. For each output, it must show a well-formed hiding
and binding commitment to a nonnegative bounded value. It must enforce:

```text
sum(real inputs) + permitted public input
    = sum(real outputs) + public fee + permitted public output
```

All values need range constraints. Equality in a finite field alone can
wrap and falsely pass conservation. The maximum value and action count must
make the integer sum bound explicit. Duplicate nullifiers within one bundle
are invalid even before checking chain state. Failed validation cannot
change any state.

The ciphertext must authenticate its network, version, commitment, and output
position. A wallet checks AEAD authenticity and recomputes the commitment
after decryption before showing a note. A full node cannot generally prove
that the sender encrypted a useful opening for the intended recipient; a
malicious sender can burn their own value with undecipherable ciphertext.
Consensus proves that any created note is value-balanced.

## Keys and proof implementation

The existing wallet has separate recovery-derived receive and spend domains,
but both currently hold ML-DSA signing keys. They are not yet viewing or
shielded-spend keys. New versioned HKDF branches must keep these roles
separate: a receive-only export detects notes, while the spend domain
authorizes spends and derives nullifiers. A first implementation based on
Orchard should retain its reviewed note-encryption path and classical key
assumptions. ML-KEM recipient encryption is a separate versioned experiment:
changing the address, ciphertext, and wallet scan protocol requires its own
security review and test vectors. OpenSSL can derive ML-KEM keys from a
64-byte seed for wallet recovery. Neither ML-KEM nor encrypted notes alone
make the ledger shielded.

For the first fully shielded **developer** version, evaluate reusing an
existing Orchard/Halo 2 implementation for commitments, nullifiers, proofs,
value balance, and authorization. This avoids inventing a circuit. The first
version would have classical proof and spend-authorization assumptions.
ML-DSA cannot simply replace Orchard authorization: a sound proof must link
the hidden note to the ML-DSA key without revealing a reusable spend identity.
Post-quantum authorization and post-quantum privacy proofs are distinct future
versions. Pinning any dependency requires a fresh review of its security
history, exact version, Rust/C boundary, and upgrade behavior.

For a C node, the first prototype can expose a small Rust `staticlib` verifier
through a C ABI that accepts bounded canonical bytes and returns a validation
result. It must not receive wallet secrets. Rust panics must not unwind across
the ABI. The proving/verifying-key or circuit identifier is consensus data,
fixed by private-version and activation height; accepting a changed upstream
circuit under the same version would split the network. A separate wallet-side
prover handles secret witnesses.

The present `eclipse-particle` SHA3 commitment must not be inserted into the
private pool until its opening and binding can be proved efficiently by the
selected system. Its four fields are educational placeholders, not a frozen
note layout.

## Node state and fork handling

Each branch has an append-only commitment tree, a nullifier set, eligible
historical roots, and a public supply counter. Validation checks bounded
canonical bytes, version/network, anchor, nullifier uniqueness, signatures,
and proof before atomically applying tree/nullifier/supply changes. Branches
cannot share mutable private-pool state. On reorganization, the selected
branch determines the root and spent-nullifier set; wallets roll back
confirmations and refresh witnesses. Old unspent notes stay usable by
reanchoring their witness to a recent accepted root.

The mempool reserves nullifiers as local policy, not consensus. Journal replay
and P2P acceptance must call the same verifier and state transition as live
block acceptance. Resource bounds must apply before proof parsing or large
allocations.

## Rewards and migration

The permitted public input for a block equals its subsidy plus validated
fees. A proof creates encrypted miner reward notes of that exact total.
Genesis still has zero spendable supply. Any transition from existing `ETX0`
UTXOs must explicitly prove a one-way move into the private pool; the old
outpoint and moved amount remain observable at this boundary. After a
privacy-by-default activation, new rewards and normal transfers should enter
the private pool. Transparent history cannot be anonymized retroactively.

## Gates before activation

1. Freeze the primitive suite, exact wire encoding, domain tags, proving and
   verifying keys, security assumptions, bounds, and test vectors.
2. Prototype the prover/verifier and test forged authority, changed fee,
   out-of-range value, inflation, duplicate nullifier, wrong anchor, malformed
   ciphertext, and wrong network.
3. Compare roots and supply across independent nodes on valid chains and
   adversarial forks; test rollback, journal replay, and mempool conflicts.
4. Fuzz the new parser, proof-length handling, decryption, and state
   transitions with ASan/UBSan, then obtain external cryptographic review.

The C libFuzzer harness covers `ETX0` and `EBL1`. The Rust `esx1_decode`
target fuzzes canonical decoding and byte-for-byte round trips. The Rust
unit tests construct actual Orchard proofs and check value conservation,
recipient decryption, spend authorization, double spends, fee and network
mutation, and branch isolation. They do not establish production security.

## Experimental ESX1 status (October 2026)

The prototype pins `orchard = 0.16.0` and explicitly uses
`BundleVersion::orchard_v2()` with the fixed post-NU6.2 circuit. This permits
ordinary cross-address payments. The Rust module uses Orchard's own builder,
Halo 2 prover/verifier, RedPallas spend and binding signatures, nullifiers,
note encryption, and Merkle commitments. It does not implement those
cryptographic primitives itself. `ESX1` is an Eclipse envelope, **not** a
Zcash transaction.

The current wire layout is:

```text
"ESX1" | network_id:u32 BE | fee:u64 BE | public_input:u64 BE | n:u8
n * Orchard-v5 action fields (820 bytes each)
flags:u8 | value_balance:i64 BE | anchor:32 bytes
canonical Orchard proof for n actions | n * spend signature:64 bytes
binding signature:64 bytes
```

`n` is 2..8, and total wire length is bounded to 32,000 bytes before parsing.
There is no variable proof length field: Orchard's expected size is fixed by
`n`. The signing digest is SHA3-256 over the versioned Eclipse domain,
network ID, fee, public input, and Orchard v5 bundle commitment. The full
signed packet has a separate domain-separated SHA3-256 transaction ID.

`ShieldedState` performs a branch-local atomic transition with historical
roots, nullifier uniqueness, commitment append, and public supply accounting.
For a transfer, `public_input=0` and `value_balance=fee`. For a reward, the
node must calculate `subsidy + validated fees`, require an output-only proof,
and match the packet's `public_input` exactly. The state currently keeps a
complete in-memory tree with a 65,536-leaf developer limit. It is unsuitable
for an unbounded network and does not persist across node restarts.

The optional C ABI (`ECLIPSE_BUILD_SHIELDED`) checks canonical bytes, proof,
signatures, value balance, and network ID and returns only public fields.
It does **not** itself check a branch root, reserve nullifiers, or grant public
issuance. These checks remain necessary when `ESX1` is integrated with a new
block version and chain state. No mainnet or privacy guarantee follows from
this prototype.

The next implementation sequence is: define a versioned `EBL2` block whose
PoW root commits to `ESX1` reward and transfers; call the verifier and
branch-local state transition from block acceptance and journal replay; add
nullifier-aware mempool/P2P handling; then derive Orchard wallet keys from a
new recovery branch, export a receive-only viewing key, scan outputs and keep
witnesses across reorganizations. The existing `EBL1` and `ETX0` history must
retain its own explicit validation rules.

## Primary references

- [Zcash Orchard protocol](https://zips.z.cash/zip-0224) and the
  [Zcash protocol specification](https://zips.z.cash/protocol/protocol.pdf).
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and
  [OpenSSL ML-KEM key generation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/).
- [Orchard implementation](https://github.com/zcash/orchard) and a recent
  [circuit security advisory](https://github.com/zcash/zcash/security/advisories/GHSA-ghc3-g8w4-whf9).
