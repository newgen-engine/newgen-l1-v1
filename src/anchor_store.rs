//! Anchor store (checkpoint cert) — disk persistence and deterministic selection.
//!
//! In mainnet/public mode, nodes need a cryptographic trust anchor (CheckpointCert).
//! This module provides:
//! - default cache path under the node data dir
//! - atomic save/load
//! - deterministic "best cert" selection
//! - SHA256 helpers for gossip/diagnostics

use crate::checkpoint::CheckpointCert;
use crate::node_paths::NodePaths;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Default cache path: <data_dir>/anchors/checkpoint_cert_latest.json
pub fn default_anchor_cache_path(paths: &NodePaths) -> PathBuf {
    paths
        .data_dir
        .join("anchors")
        .join("checkpoint_cert_latest.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// SHA256 of the canonical JSON bytes of a cert.
pub fn checkpoint_cert_sha256_hex(cert: &CheckpointCert) -> String {
    // This hash is used for diagnostics / gossip metadata. Serialization errors should never be silent:
    // they indicate a schema drift or corruption.
    let bytes = match serde_json::to_vec(cert) {
        Ok(b) => b,
        Err(e) => {
            ng_error!(
                target: "anchor_store",
                "checkpoint_cert_sha256_hex: cannot serialize cert (using empty bytes as fallback): {e}"
            );
            Vec::new()
        }
    };
    sha256_hex(&bytes)
}

/// Load a checkpoint cert from disk (best-effort). Returns None on missing/invalid file.
pub fn load_checkpoint_cert(path: &Path) -> Option<CheckpointCert> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice::<CheckpointCert>(&bytes).ok()
}

/// Save a checkpoint cert atomically (write tmp then rename).
pub fn save_checkpoint_cert(path: &Path, cert: &CheckpointCert) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "anchor cache path has no parent".to_string())?;
    fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create anchor dir {}: {e}", dir.display()))?;

    let bytes = serde_json::to_vec_pretty(cert)
        .map_err(|e| format!("cannot serialize checkpoint cert: {e}"))?;

    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes).map_err(|e| format!("cannot write tmp anchor file: {e}"))?;
    crate::utils::atomic_replace_file_v1(&tmp, path)
        .map_err(|e| format!("cannot atomically replace anchor file: {e}"))?;
    Ok(())
}

/// Deterministic comparison: return true if `a` is better (newer/stronger) than `b`.
///
/// Ordering (in this order):
/// 1) higher checkpoint.height
/// 2) higher checkpoint.ts (deterministic block timestamp)
/// 3) lexicographically higher block_hash (tie-break)
/// 4) more signatures
pub fn is_better_checkpoint_cert(a: &CheckpointCert, b: &CheckpointCert) -> bool {
    if a.checkpoint.height != b.checkpoint.height {
        return a.checkpoint.height > b.checkpoint.height;
    }
    if a.checkpoint.ts != b.checkpoint.ts {
        return a.checkpoint.ts > b.checkpoint.ts;
    }
    if a.checkpoint.block_hash != b.checkpoint.block_hash {
        return a.checkpoint.block_hash > b.checkpoint.block_hash;
    }
    a.sigs.len() > b.sigs.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{build_checkpoint_cert, sign_checkpoint, Checkpoint};
    use ed25519_dalek::SigningKey;
    use std::collections::{HashMap, HashSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!(
            "newgen_anchor_store_{tag}_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample_cert(height: u64, ts: u64, block_hash: &str, sig_count: usize) -> CheckpointCert {
        let ckpt = Checkpoint {
            height,
            block_hash: block_hash.to_string(),
            chain_id: "newgen-mainnet".to_string(),
            genesis_hash: "genesis".to_string(),
            validator_set_hash: "validators".to_string(),
            ts,
        };
        let mut by_pk = HashMap::new();
        let mut allowed = HashSet::new();
        for i in 0..sig_count {
            let sk = SigningKey::from_bytes(&[(i as u8) + 1; 32]);
            let sig = sign_checkpoint(&sk, &ckpt).unwrap();
            allowed.insert(hex::encode(sk.verifying_key().to_bytes()));
            by_pk.insert(sig.signer_pk_b64.clone(), sig);
        }
        build_checkpoint_cert(ckpt, &by_pk, sig_count.max(1), &allowed).unwrap()
    }

    #[test]
    fn default_anchor_cache_path_is_under_data_dir() {
        let paths = NodePaths::from_data_dir("/tmp/newgen-node-A");
        let p = default_anchor_cache_path(&paths);
        assert!(p.ends_with(Path::new("anchors/checkpoint_cert_latest.json")));
    }

    #[test]
    fn save_load_and_hash_are_deterministic() {
        let dir = temp_dir("save_load");
        let path = dir.join("anchors").join("checkpoint_cert_latest.json");
        let cert = sample_cert(10, 100, "aaa", 1);

        save_checkpoint_cert(&path, &cert).unwrap();
        let loaded = load_checkpoint_cert(&path).unwrap();
        assert_eq!(loaded, cert);
        assert_eq!(
            checkpoint_cert_sha256_hex(&loaded),
            checkpoint_cert_sha256_hex(&cert)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn better_cert_prefers_height_then_ts_then_hash_then_sig_count() {
        let base = sample_cert(10, 100, "aaa", 1);
        let higher = sample_cert(11, 1, "aaa", 1);
        assert!(is_better_checkpoint_cert(&higher, &base));

        let newer_ts = sample_cert(10, 101, "aaa", 1);
        assert!(is_better_checkpoint_cert(&newer_ts, &base));

        let higher_hash = sample_cert(10, 100, "bbb", 1);
        assert!(is_better_checkpoint_cert(&higher_hash, &base));

        let more_sigs = sample_cert(10, 100, "aaa", 2);
        assert!(is_better_checkpoint_cert(&more_sigs, &base));
    }
}
