#![no_main]
use libfuzzer_sys::fuzz_target;
use eclipse_shielded::ShieldedTx;

fuzz_target!(|data: &[u8]| {
    // A valid canonical encoding must round-trip byte-for-byte. Parsing does
    // not run the expensive proof verifier; consensus must invoke verify().
    if let Ok(tx) = ShieldedTx::from_bytes(data) {
        assert_eq!(tx.to_bytes(), data);
    }
});
