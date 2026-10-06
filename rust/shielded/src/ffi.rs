//! Small verifier-only C ABI. Wallet secrets and proving APIs stay in Rust.
//! The caller must still check branch anchor/nullifier state and issuance
//! against independently computed block consensus rules.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

use crate::{ShieldedTx, MAX_ACTIONS, MAX_WIRE_SIZE};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShieldedReceipt {
    pub network_id: u32,
    pub fee: u64,
    pub public_input: u64,
    pub value_balance: i64,
    pub action_count: u8,
    /// Verified Orchard v2 flag byte. Bit 0 controls real spends; bit 1
    /// controls real outputs. Consensus must require bit 0 clear for rewards.
    pub flags: u8,
    pub anchor: [u8; 32],
    pub nullifiers: [[u8; 32]; MAX_ACTIONS],
    pub commitments: [[u8; 32]; MAX_ACTIONS],
}

impl ShieldedReceipt {
    fn from_tx(tx: &ShieldedTx) -> Self {
        let mut receipt = Self {
            network_id: tx.network_id,
            fee: tx.fee,
            public_input: tx.public_input,
            value_balance: *tx.bundle.value_balance(),
            action_count: tx.bundle.actions().len() as u8,
            flags: tx.bundle.flag_byte(),
            anchor: tx.bundle.anchor().to_bytes(),
            nullifiers: [[0; 32]; MAX_ACTIONS],
            commitments: [[0; 32]; MAX_ACTIONS],
        };
        for (i, action) in tx.bundle.actions().iter().enumerate() {
            receipt.nullifiers[i] = action.nullifier().to_bytes();
            receipt.commitments[i] = action.cmx().to_bytes();
        }
        receipt
    }
}

/// Returns 0 on valid proof and signatures; 1 for invalid transaction; -1 for
/// invalid pointers or overlarge input; -2 if an internal panic was caught.
/// The output is written only on success. This does not accept the transaction
/// into any branch; C consensus must inspect and apply the receipt separately.
#[no_mangle]
pub unsafe extern "C" fn eclipse_shielded_verify_esx1(
    wire: *const u8,
    length: usize,
    expected_network_id: u32,
    out: *mut ShieldedReceipt,
) -> i32 {
    if wire.is_null() || out.is_null() || length == 0 || length > MAX_WIRE_SIZE {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: C callers promise that `wire` points to `length` readable
        // bytes and `out` points to one writable receipt. No ABI can verify
        // arbitrary pointer provenance, so this contract is documented here.
        let bytes = unsafe { std::slice::from_raw_parts(wire, length) };
        let tx = match ShieldedTx::from_bytes(bytes) {
            Ok(tx) if tx.network_id == expected_network_id => tx,
            _ => return 1,
        };
        if tx.verify().is_err() {
            return 1;
        }
        let receipt = ShieldedReceipt::from_tx(&tx);
        unsafe {
            ptr::write(out, receipt);
        }
        0
    }))
    .unwrap_or(-2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    #[test]
    fn ffi_writes_receipt_only_after_validating() {
        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let tx = ShieldedTx::issue(44, fvk.address_at(0u32, Scope::External), 42).unwrap();
        let wire = tx.to_bytes();
        let mut receipt = ShieldedReceipt::from_tx(&tx);
        let wrong =
            unsafe { eclipse_shielded_verify_esx1(wire.as_ptr(), wire.len(), 45, &mut receipt) };
        assert_eq!(wrong, 1);
        let valid =
            unsafe { eclipse_shielded_verify_esx1(wire.as_ptr(), wire.len(), 44, &mut receipt) };
        assert_eq!(valid, 0);
        assert_eq!(receipt.public_input, 42);
        assert_eq!(receipt.action_count, 2);
        assert_eq!(receipt.flags, 0b10);
        let invalid =
            unsafe { eclipse_shielded_verify_esx1(std::ptr::null(), 1, 44, &mut receipt) };
        assert_eq!(invalid, -1);
    }
}
