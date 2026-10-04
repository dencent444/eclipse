use eclipse_shielded::ShieldedTx;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use std::io::{self, Write};

fn main() {
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let tx = ShieldedTx::issue(44, fvk.address_at(0u32, Scope::External), 5000).unwrap();
    io::stdout().write_all(&tx.to_bytes()).unwrap();
}
