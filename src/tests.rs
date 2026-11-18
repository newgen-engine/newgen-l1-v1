//! Minimal integrity/smoke tests.
//!
//! Goal: ensure core modules link and basic invariants hold, without touching
//! networking, disk, or consensus runtime state.

use std::sync::{Mutex, MutexGuard, OnceLock};

pub(crate) fn test_process_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

use crate::{block, chain_identity, crypto, p2p, state, transaction};

#[test]
fn integrity_check() {
    // --- Chain identity (used for domain separation) ---
    let nid = chain_identity::network_id();
    assert!(!nid.trim().is_empty(), "network_id must be non-empty");

    // --- State (toy module, but should remain deterministic) ---
    let mut st = state::State::new();
    st.update_balance("alice", 1.0);
    assert_eq!(st.get_balance("alice"), 1.0);

    // --- Transaction hashing must be deterministic ---
    let tx = transaction::Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        1,
        1,
        0,
        "".to_string(),
        false,
        None,
    );
    assert_eq!(tx.hash, tx.calculate_hash());

    // --- Crypto domain-separated sign/verify sanity ---
    let sk = crypto::generate_signing_key();
    let vk = crypto::verifying_key(&sk);
    let msg = b"newgen_integrity";
    let sig64 = crypto::sign_ds_bytes(&sk, b"INTEGRITY_V1", msg);
    crypto::verify_ds_bytes(&vk, b"INTEGRITY_V1", msg, &sig64)
        .expect("signature verify must succeed");

    // --- Core types should link (no heavy init) ---
    assert!(std::mem::size_of::<block::Block>() > 0);
    assert!(std::mem::size_of::<p2p::P2pControl>() > 0);
}
