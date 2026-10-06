//! Branch-local commitment tree and nullifier set. This deliberately keeps a
//! complete in-memory tree for a bounded developer pool; a production node
//! needs persistent, indexed frontier/witness storage and pruning rules.

use std::collections::HashSet;

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
};

use crate::tx::ShieldedTx;

const TREE_DEPTH: usize = 32;
const MAX_LEAVES: usize = 65_536;

#[derive(Clone, Debug)]
pub struct ShieldedState {
    network_id: u32,
    leaves: Vec<MerkleHashOrchard>,
    nullifiers: HashSet<[u8; 32]>,
    accepted_roots: HashSet<[u8; 32]>,
    total_issued: u64,
}

impl ShieldedState {
    pub fn new(network_id: u32) -> Self {
        let mut accepted_roots = HashSet::new();
        accepted_roots.insert(Anchor::empty_tree().to_bytes());
        Self {
            network_id,
            leaves: Vec::new(),
            nullifiers: HashSet::new(),
            accepted_roots,
            total_issued: 0,
        }
    }

    pub fn root(&self) -> Anchor {
        if self.leaves.is_empty() {
            Anchor::empty_tree()
        } else {
            self.levels()[TREE_DEPTH][0].into()
        }
    }

    pub fn total_issued(&self) -> u64 {
        self.total_issued
    }
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
    pub fn has_nullifier(&self, nf: &[u8; 32]) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Witness a note already found by local wallet scanning. The caller must
    /// check that the note's commitment equals the leaf at `position`.
    pub fn witness(
        &self,
        position: usize,
        cmx: ExtractedNoteCommitment,
    ) -> Result<MerklePath, String> {
        if self.leaves.get(position) != Some(&MerkleHashOrchard::from_cmx(&cmx)) {
            return Err("note does not match leaf".into());
        }
        let levels = self.levels();
        let path = std::array::from_fn(|l| {
            let sibling = (position >> l) ^ 1;
            levels[l]
                .get(sibling)
                .copied()
                .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(l as u8)))
        });
        Ok(MerklePath::from_parts(position as u32, path))
    }

    /// Validates a complete block as one atomic state transition. `subsidy` is
    /// supplied by the PoW chain's emission rule, never from the shielded tx.
    /// A zero subsidy plus zero fees has no reward transaction: issuing a
    /// zero-valued note would add meaningless commitments and nullifiers.
    /// A failed proof, repeated nullifier, or incorrect reward changes nothing.
    pub fn apply_block(
        &mut self,
        subsidy: u64,
        reward: Option<&ShieldedTx>,
        transfers: &[ShieldedTx],
    ) -> Result<(), String> {
        let fees = transfers
            .iter()
            .try_fold(0u64, |sum, tx| sum.checked_add(tx.fee))
            .ok_or("fee overflow")?;
        let allowed_reward = subsidy.checked_add(fees).ok_or("reward overflow")?;
        match (allowed_reward, reward) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err("invalid shielded reward".into()),
            (value, Some(tx)) => {
                if tx.network_id != self.network_id
                    || tx.fee != 0
                    || tx.public_input != value
                    || tx.bundle.flags().spends_enabled()
                {
                    return Err("invalid shielded reward".into());
                }
            }
        }
        let mut next = self.clone();
        for tx in transfers {
            if tx.network_id != self.network_id
                || tx.public_input != 0
                || !tx.bundle.flags().spends_enabled()
            {
                return Err("invalid shielded transfer".into());
            }
            next.apply_one(tx)?;
        }
        if let Some(reward) = reward {
            next.apply_one(reward)?;
        }
        next.total_issued = next
            .total_issued
            .checked_add(subsidy)
            .ok_or("supply overflow")?;
        *self = next;
        Ok(())
    }

    fn apply_one(&mut self, tx: &ShieldedTx) -> Result<(), String> {
        if !self.accepted_roots.contains(&tx.bundle.anchor().to_bytes()) {
            return Err("unknown anchor".into());
        }
        if self
            .leaves
            .len()
            .checked_add(tx.bundle.actions().len())
            .ok_or("tree overflow")?
            > MAX_LEAVES
        {
            return Err("developer tree limit".into());
        }
        let mut within_tx = HashSet::new();
        for action in tx.bundle.actions().iter() {
            let nf = action.nullifier().to_bytes();
            if self.nullifiers.contains(&nf) || !within_tx.insert(nf) {
                return Err("duplicate nullifier".into());
            }
        }
        tx.verify()?;
        for action in tx.bundle.actions().iter() {
            self.nullifiers.insert(action.nullifier().to_bytes());
            self.leaves.push(MerkleHashOrchard::from_cmx(action.cmx()));
        }
        self.accepted_roots.insert(self.root().to_bytes());
        Ok(())
    }

    fn levels(&self) -> Vec<Vec<MerkleHashOrchard>> {
        let mut levels = Vec::with_capacity(TREE_DEPTH + 1);
        levels.push(self.leaves.clone());
        for l in 0..TREE_DEPTH {
            let previous = &levels[l];
            let level = Level::from(l as u8);
            let next = previous
                .chunks(2)
                .map(|pair| {
                    let right = pair
                        .get(1)
                        .copied()
                        .unwrap_or_else(|| MerkleHashOrchard::empty_root(level));
                    MerkleHashOrchard::combine(level, &pair[0], &right)
                })
                .collect();
            levels.push(next);
        }
        levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    fn key(byte: u8) -> SpendingKey {
        SpendingKey::from_bytes([byte; 32]).unwrap()
    }

    #[test]
    fn private_payment_round_trip_and_branch_isolation() {
        let sender = key(7);
        let recipient = key(9);
        let sender_fvk = FullViewingKey::from(&sender);
        let recipient_fvk = FullViewingKey::from(&recipient);
        let miner_address = sender_fvk.address_at(0u32, Scope::External);
        let pay_address = recipient_fvk.address_at(0u32, Scope::External);
        let mut state = ShieldedState::new(44);
        let genesis_reward = ShieldedTx::issue(44, miner_address, 5000).unwrap();
        let wire = genesis_reward.to_bytes();
        let parsed = ShieldedTx::from_bytes(&wire).unwrap();
        assert_eq!(parsed.to_bytes(), wire);
        assert_eq!(parsed.id(), genesis_reward.id());
        assert!(parsed.verify().is_ok());
        state.apply_block(5000, Some(&parsed), &[]).unwrap();
        assert_eq!(state.total_issued(), 5000);
        let found = parsed
            .bundle
            .decrypt_outputs_with_keys(&[sender_fvk.to_ivk(Scope::External)]);
        assert_eq!(found.len(), 1);
        let action_index = found[0].0;
        let note = found[0].2;
        assert_eq!(note.value().inner(), 5000);
        let cmx = note.commitment().into();
        let path = state.witness(action_index, cmx).unwrap();
        assert_eq!(path.root(cmx), state.root());
        let zero_fee_payment = ShieldedTx::transfer(
            44,
            &sender,
            note,
            state.witness(action_index, cmx).unwrap(),
            pay_address,
            3000,
            0,
        )
        .unwrap();
        let mut no_reward_fork = state.clone();
        no_reward_fork
            .apply_block(0, None, &[zero_fee_payment])
            .unwrap();
        assert_eq!(no_reward_fork.total_issued(), 5000);
        assert_ne!(no_reward_fork.root(), state.root());
        let payment =
            ShieldedTx::transfer(44, &sender, note, path, pay_address, 3000, 100).unwrap();
        assert_eq!(payment.public_input, 0);
        assert_eq!(*payment.bundle.value_balance(), 100);
        let payment_wire = payment.to_bytes();
        let mut verified_receipt = std::mem::MaybeUninit::<crate::ffi::ShieldedReceipt>::uninit();
        let status = unsafe {
            crate::ffi::eclipse_shielded_verify_esx1(
                payment_wire.as_ptr(),
                payment_wire.len(),
                44,
                verified_receipt.as_mut_ptr(),
            )
        };
        assert_eq!(status, 0);
        let verified_receipt = unsafe { verified_receipt.assume_init() };
        assert_eq!(verified_receipt.flags, 0b11);
        let payment = ShieldedTx::from_bytes(&payment_wire).unwrap();
        assert!(payment.verify().is_ok());
        let received = payment
            .bundle
            .decrypt_outputs_with_keys(&[recipient_fvk.to_ivk(Scope::External)]);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].2.value().inner(), 3000);
        let change = payment
            .bundle
            .decrypt_outputs_with_keys(&[sender_fvk.to_ivk(Scope::Internal)]);
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].2.value().inner(), 1900);
        let fee_reward = ShieldedTx::issue(44, miner_address, 100).unwrap();
        let doubled_fee_reward = ShieldedTx::issue(44, miner_address, 200).unwrap();
        let before = state.root();
        let mut fork = state.clone();
        assert!(fork
            .apply_block(
                0,
                Some(&doubled_fee_reward),
                &[payment.clone(), payment.clone()]
            )
            .is_err());
        assert_eq!(fork.root(), before);
        let mut unrelated = ShieldedState::new(44);
        assert!(unrelated
            .apply_block(0, Some(&fee_reward), std::slice::from_ref(&payment))
            .is_err());
        assert_eq!(unrelated.leaf_count(), 0);
        state
            .apply_block(0, Some(&fee_reward), std::slice::from_ref(&payment))
            .unwrap();
        assert_eq!(state.total_issued(), 5000);
        assert_ne!(state.root(), before);
        let accepted_root = state.root();
        assert!(state.apply_block(0, Some(&fee_reward), &[payment]).is_err());
        assert_eq!(state.root(), accepted_root);
        assert_eq!(fork.root(), before);
    }

    #[test]
    fn malformed_wire_and_public_values_are_rejected() {
        let owner = key(7);
        let fvk = FullViewingKey::from(&owner);
        let tx = ShieldedTx::issue(44, fvk.address_at(0u32, Scope::External), 5).unwrap();
        let wire = tx.to_bytes();
        assert!(ShieldedTx::from_bytes(&wire[..wire.len() - 1]).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(ShieldedTx::from_bytes(&trailing).is_err());
        let mut wrong_network = tx.clone();
        wrong_network.network_id = 45;
        assert!(wrong_network.verify().is_err());
        let mut wrong_fee = tx.clone();
        wrong_fee.fee = 1;
        assert!(wrong_fee.verify().is_err());
        let mut wrong_input = tx.clone();
        wrong_input.public_input = 6;
        assert!(wrong_input.verify().is_err());
        let proof_at = 4 + 4 + 8 + 8 + 1 + 2 * 820 + 1 + 8 + 32;
        let mut forged_proof = wire.clone();
        forged_proof[proof_at] ^= 1;
        assert!(ShieldedTx::from_bytes(&forged_proof)
            .unwrap()
            .verify()
            .is_err());
        let mut forged_signature = wire.clone();
        let last = forged_signature.len() - 1;
        forged_signature[last] ^= 1;
        assert!(ShieldedTx::from_bytes(&forged_signature)
            .unwrap()
            .verify()
            .is_err());
        let mut state = ShieldedState::new(44);
        assert!(state.apply_block(6, Some(&tx), &[]).is_err());
        assert!(state.apply_block(5, None, &[]).is_err());
        assert!(state.apply_block(0, Some(&tx), &[]).is_err());
        assert_eq!(state.leaf_count(), 0);
        state.apply_block(0, None, &[]).unwrap();
        assert_eq!(state.total_issued(), 0);
        assert_eq!(state.leaf_count(), 0);
    }
}
