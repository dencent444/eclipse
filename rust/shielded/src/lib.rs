//! Experimental Orchard based shielded pool for Eclipse.
//!
//! Nothing here is active in the C node's consensus yet. In particular, an
//! arbitrary caller must never be allowed to supply a public issuance budget.
//! `ShieldedState::apply_block` is the only state transition exposed here.

mod ffi;
mod ledger;
mod tx;

pub use ledger::ShieldedState;
pub use tx::{ShieldedTx, MAX_ACTIONS, MAX_WIRE_SIZE};
