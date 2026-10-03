# Eclipse protocol sketch (developer v0)

This document records implemented bytes and the intended boundaries of the
experiment. It is **not** a mainnet consensus specification. Changing any
commitment input or encoding requires a new version and new test vectors.

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
