//! ESX1: bounded, canonical wire encoding for one Orchard v2 bundle.
//! The field ordering follows the upstream Orchard v5 action codec, while the
//! Eclipse envelope commits to network, fee, and explicitly permitted input.

use std::sync::OnceLock;

use nonempty::NonEmpty;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, BatchValidator, Bundle, BundleVersion, Flags, TxVersion},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::{NoteBytesData, ENC_CIPHERTEXT_SIZE},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerklePath},
    value::{NoteValue, ValueCommitment},
    Action, Address, Note, Proof,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sha3::{Digest, Sha3_256};

pub const MAX_ACTIONS: usize = 8;
pub const MAX_WIRE_SIZE: usize = 32_000;
const ACTION_BYTES: usize = 32 * 5 + ENC_CIPHERTEXT_SIZE + 80;
const MAGIC: &[u8; 4] = b"ESX1";
const SIGN_DOMAIN: &[u8] = b"ECLIPSE/DEV/SHIELDED/SIGN/V1";
const ID_DOMAIN: &[u8] = b"ECLIPSE/DEV/SHIELDED/ID/V1";

fn version() -> BundleVersion {
    BundleVersion::orchard_v2()
}
fn proving_key() -> &'static ProvingKey {
    static KEY: OnceLock<ProvingKey> = OnceLock::new();
    KEY.get_or_init(|| ProvingKey::build(version().circuit_version()))
}
fn verifying_key() -> &'static VerifyingKey {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    KEY.get_or_init(|| VerifyingKey::build(version().circuit_version()))
}

#[derive(Clone, Debug)]
pub struct ShieldedTx {
    pub network_id: u32,
    pub fee: u64,
    /// Must be exactly the block subsidy plus fees for an issuance transaction.
    /// It is zero for normal transfers. The network must never trust this claim.
    pub public_input: u64,
    pub bundle: Bundle<Authorized, i64>,
}

impl ShieldedTx {
    /// Build an output-only reward. Consensus must match `public_input` to the
    /// independently computed subsidy and fees before applying the result.
    pub fn issue(network_id: u32, recipient: Address, amount: u64) -> Result<Self, String> {
        if amount == 0 || amount > i64::MAX as u64 {
            return Err("invalid amount".into());
        }
        // This flag lets the Orchard circuit prove every spend is dummy.
        let flags = Flags::SPENDS_DISABLED;
        let mut builder = Builder::new(BundleType::DEFAULT, version(), flags, Anchor::empty_tree())
            .map_err(|e| format!("builder: {e:?}"))?;
        builder
            .add_output(None, recipient, NoteValue::from_raw(amount), [0u8; 512])
            .map_err(|e| format!("output: {e:?}"))?;
        Self::finish(network_id, 0, amount, builder, &[])
    }

    /// Spend one note into a payment and optional change. The caller supplies a
    /// witness against a root in its validated chain, never one from an RPC alone.
    pub fn transfer(
        network_id: u32,
        owner: &SpendingKey,
        note: Note,
        path: MerklePath,
        recipient: Address,
        amount: u64,
        fee: u64,
    ) -> Result<Self, String> {
        let input = note.value().inner();
        if amount == 0 || amount > i64::MAX as u64 || fee > i64::MAX as u64 {
            return Err("invalid amount or fee".into());
        }
        let needed = amount.checked_add(fee).ok_or("amount overflow")?;
        if needed > input {
            return Err("insufficient note value".into());
        }
        let fvk = FullViewingKey::from(owner);
        let anchor = path.root(note.commitment().into());
        let mut builder = Builder::new(BundleType::DEFAULT, version(), Flags::ENABLED, anchor)
            .map_err(|e| format!("builder: {e:?}"))?;
        builder
            .add_spend(fvk.clone(), note, path)
            .map_err(|e| format!("spend: {e:?}"))?;
        let ovk = Some(fvk.to_ovk(Scope::External));
        builder
            .add_output(
                ovk.clone(),
                recipient,
                NoteValue::from_raw(amount),
                [0u8; 512],
            )
            .map_err(|e| format!("payment: {e:?}"))?;
        if input > needed {
            builder
                .add_output(
                    ovk,
                    fvk.address_at(1u32, Scope::Internal),
                    NoteValue::from_raw(input - needed),
                    [0u8; 512],
                )
                .map_err(|e| format!("change: {e:?}"))?;
        }
        let ask = SpendAuthorizingKey::from(owner);
        Self::finish(network_id, fee, 0, builder, &[ask])
    }

    fn finish(
        network_id: u32,
        fee: u64,
        public_input: u64,
        builder: Builder,
        signing_keys: &[SpendAuthorizingKey],
    ) -> Result<Self, String> {
        let mut rng = UnwrapErr(SysRng);
        let (bundle, _) = builder
            .build::<i64>(&mut rng)
            .map_err(|e| format!("build: {e:?}"))?
            .ok_or("empty bundle")?;
        if bundle.actions().len() > MAX_ACTIONS {
            return Err("too many actions".into());
        }
        let proved = bundle
            .create_proof(proving_key(), &mut rng)
            .map_err(|e| format!("proof: {e:?}"))?;
        let sighash = signing_digest(&proved, network_id, fee, public_input)?;
        let bundle = proved
            .apply_signatures(rng, sighash, signing_keys)
            .map_err(|e| format!("signature: {e:?}"))?;
        Ok(Self {
            network_id,
            fee,
            public_input,
            bundle,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.bundle.bundle_version() != version() {
            return Err("circuit version".into());
        }
        if self.bundle.actions().len() < 2 || self.bundle.actions().len() > MAX_ACTIONS {
            return Err("action count".into());
        }
        if self.fee > i64::MAX as u64 || self.public_input > i64::MAX as u64 {
            return Err("value limit".into());
        }
        // `v_balance = spends - outputs`; permitted public input covers the
        // deficit, and all remaining public value is the fee.
        let balance = *self.bundle.value_balance() as i128;
        if balance + self.public_input as i128 != self.fee as i128 {
            return Err("value conservation".into());
        }
        let sighash = signing_digest(&self.bundle, self.network_id, self.fee, self.public_input)?;
        let mut validator = BatchValidator::new(verifying_key());
        validator
            .add_bundle(&self.bundle, sighash)
            .map_err(|e| format!("flags: {e}"))?;
        if !validator.validate(UnwrapErr(SysRng)) {
            return Err("invalid proof or signature".into());
        }
        Ok(())
    }

    pub fn id(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hash = Sha3_256::new();
        hash.update(ID_DOMAIN);
        hash.update(bytes);
        hash.finalize().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.bundle.actions().len();
        let proof = self.bundle.authorization().proof().as_ref();
        let mut out = Vec::with_capacity(
            4 + 4 + 8 + 8 + 1 + n * (ACTION_BYTES + 64) + 1 + 8 + 32 + proof.len() + 64,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.fee.to_be_bytes());
        out.extend_from_slice(&self.public_input.to_be_bytes());
        out.push(n as u8);
        for action in self.bundle.actions().iter() {
            out.extend_from_slice(&action.cv_net().to_bytes());
            out.extend_from_slice(&action.nullifier().to_bytes());
            out.extend_from_slice(&<[u8; 32]>::from(action.rk()));
            out.extend_from_slice(&action.cmx().to_bytes());
            let enc = action.encrypted_note();
            out.extend_from_slice(&enc.epk_bytes);
            out.extend_from_slice(&enc.enc_ciphertext.0);
            out.extend_from_slice(&enc.out_ciphertext);
        }
        out.push(self.bundle.flag_byte());
        out.extend_from_slice(&self.bundle.value_balance().to_be_bytes());
        out.extend_from_slice(&self.bundle.anchor().to_bytes());
        out.extend_from_slice(proof);
        for action in self.bundle.actions().iter() {
            out.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
        }
        out.extend_from_slice(&<[u8; 64]>::from(
            self.bundle.authorization().binding_signature(),
        ));
        out
    }

    /// Parse exact ESX1 bytes. No allocation depends on an unchecked length.
    /// Cryptographic verification is intentionally a separate mandatory step.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_WIRE_SIZE {
            return Err("oversize ESX1".into());
        }
        let mut r = Reader { bytes, at: 0 };
        if r.take::<4>()? != *MAGIC {
            return Err("ESX1 magic".into());
        }
        let network_id = u32::from_be_bytes(r.take()?);
        let fee = u64::from_be_bytes(r.take()?);
        let public_input = u64::from_be_bytes(r.take()?);
        let n = r.take::<1>()?[0] as usize;
        if !(2..=MAX_ACTIONS).contains(&n) {
            return Err("action count".into());
        }
        let expected = 4
            + 4
            + 8
            + 8
            + 1
            + n * ACTION_BYTES
            + 1
            + 8
            + 32
            + Proof::expected_proof_size(n)
            + n * 64
            + 64;
        if bytes.len() != expected {
            return Err("noncanonical length".into());
        }
        let mut actions = Vec::with_capacity(n);
        for _ in 0..n {
            let cv: ValueCommitment = Option::from(ValueCommitment::from_bytes(&r.take()?))
                .ok_or("invalid value commitment")?;
            let nf: Nullifier =
                Option::from(Nullifier::from_bytes(&r.take()?)).ok_or("invalid nullifier")?;
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(r.take::<32>()?)
                .map_err(|_| "invalid spend key")?;
            let cmx: ExtractedNoteCommitment =
                Option::from(ExtractedNoteCommitment::from_bytes(&r.take()?))
                    .ok_or("invalid commitment")?;
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: r.take()?,
                enc_ciphertext: NoteBytesData(r.take()?),
                out_ciphertext: r.take()?,
            };
            actions.push(
                Action::from_parts(nf, rk, cmx, encrypted_note, cv, ())
                    .map_err(|e| format!("invalid action: {e}"))?,
            );
        }
        let flags = Flags::from_byte(r.take::<1>()?[0], version()).ok_or("invalid flags")?;
        let balance = i64::from_be_bytes(r.take()?);
        let anchor: Anchor = Option::from(Anchor::from_bytes(r.take()?)).ok_or("invalid anchor")?;
        let proof = Proof::new(r.slice(Proof::expected_proof_size(n))?.to_vec());
        let mut signed = Vec::with_capacity(n);
        for action in actions {
            let sig = redpallas::Signature::<SpendAuth>::from(r.take::<64>()?);
            signed.push(action.map(|_| sig));
        }
        let binding_sig = redpallas::Signature::<Binding>::from(r.take::<64>()?);
        if r.at != bytes.len() {
            return Err("trailing bytes".into());
        }
        let bundle = Bundle::try_from_parts(
            NonEmpty::from_vec(signed).ok_or("empty bundle")?,
            flags,
            balance,
            anchor,
            Authorized::from_parts(proof, binding_sig),
            version(),
        )
        .map_err(|e| format!("invalid bundle: {e}"))?;
        Ok(Self {
            network_id,
            fee,
            public_input,
            bundle,
        })
    }
}

fn signing_digest<T: orchard::bundle::Authorization>(
    bundle: &Bundle<T, i64>,
    network_id: u32,
    fee: u64,
    public_input: u64,
) -> Result<[u8; 32], String> {
    let commitment: [u8; 32] = bundle
        .commitment(TxVersion::V5)
        .map_err(|e| format!("bundle commitment: {e:?}"))?
        .into();
    let mut hash = Sha3_256::new();
    hash.update(SIGN_DOMAIN);
    hash.update(network_id.to_be_bytes());
    hash.update(fee.to_be_bytes());
    hash.update(public_input.to_be_bytes());
    hash.update(commitment);
    Ok(hash.finalize().into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn slice(&mut self, len: usize) -> Result<&[u8], String> {
        let end = self.at.checked_add(len).ok_or("length overflow")?;
        let part = self.bytes.get(self.at..end).ok_or("truncated ESX1")?;
        self.at = end;
        Ok(part)
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.slice(N)?
            .try_into()
            .map_err(|_| "truncated ESX1".into())
    }
}
