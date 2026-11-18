// src/chain_identity.rs
//
// Single source of truth for BOTH:
// - chain_id (P2P identity)
// - network_id (TX/domain separation + wallet payload)
//
// Rule: network_id == chain_id, and it MUST come from genesis/config in public deployments.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static CHAIN_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainIdentityError {
    MissingGenesisChainIdInPublicMode,
    EnvGenesisMismatch { env: String, genesis: String },
    ChainIdMismatch { existing: String, new_value: String },
}

impl std::fmt::Display for ChainIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingGenesisChainIdInPublicMode => write!(f,
                "Missing genesis chain_id in public_mode: expected config/genesis.json (or ../config/genesis.json) to contain chain_id"),
            Self::EnvGenesisMismatch { env, genesis } => write!(f,
                "Public-mode chain identity mismatch: NEWGEN_NETWORK_ID='{}' but genesis chain_id='{}'", env, genesis),
            Self::ChainIdMismatch { existing, new_value } => write!(f,
                "CHAIN_ID mismatch: existing='{}' new='{}' (check config/genesis.json and working directory)", existing, new_value),
        }
    }
}

impl std::error::Error for ChainIdentityError {}

/// Initialize chain/network id from genesis chain_id.
/// If already initialized with a DIFFERENT value, this is a fatal misconfiguration.
pub fn init_chain_id(chain_id: &str) -> Result<(), ChainIdentityError> {
    let cid = chain_id.trim();
    if cid.is_empty() {
        return Ok(());
    }

    if let Some(existing) = CHAIN_ID.get() {
        if existing != cid {
            if cfg!(test) {
                eprintln!(
                    "[TEST] CHAIN_ID mismatch ignored: existing='{}' new='{}'",
                    existing, cid
                );
                return Ok(());
            }
            return Err(ChainIdentityError::ChainIdMismatch {
                existing: existing.clone(),
                new_value: cid.to_string(),
            });
        }
        return Ok(());
    }

    let _ = CHAIN_ID.set(cid.to_string());
    Ok(())
}

fn trimmed_env_override(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn resolve_chain_id_from_sources(
    public_mode: bool,
    env_override: Option<&str>,
    genesis_chain_id: Option<String>,
) -> Result<String, ChainIdentityError> {
    let env_override = env_override.map(str::trim).filter(|v| !v.is_empty());

    if public_mode {
        let genesis_chain_id =
            genesis_chain_id.ok_or(ChainIdentityError::MissingGenesisChainIdInPublicMode)?;

        if let Some(env_value) = env_override {
            if env_value != genesis_chain_id {
                return Err(ChainIdentityError::EnvGenesisMismatch {
                    env: env_value.to_string(),
                    genesis: genesis_chain_id,
                });
            }
        }

        return Ok(genesis_chain_id);
    }

    if let Some(env_value) = env_override {
        return Ok(env_value.to_string());
    }

    Ok(genesis_chain_id.unwrap_or_else(|| "newgen-devnet".to_string()))
}

fn resolve_chain_id(public_mode: bool) -> Result<String, ChainIdentityError> {
    let env_override = trimmed_env_override("NEWGEN_NETWORK_ID");
    let genesis_chain_id = read_chain_id_from_genesis("config/genesis.json")
        .or_else(|| read_chain_id_from_genesis("../config/genesis.json"));
    resolve_chain_id_from_sources(public_mode, env_override.as_deref(), genesis_chain_id)
}

pub fn try_chain_id() -> Result<&'static str, ChainIdentityError> {
    if let Some(existing) = CHAIN_ID.get() {
        return Ok(existing.as_str());
    }

    let resolved = resolve_chain_id(crate::runtime_mode::public_mode_enabled())?;
    init_chain_id(&resolved)?;

    Ok(CHAIN_ID
        .get()
        .expect("CHAIN_ID must be initialized after successful init_chain_id")
        .as_str())
}

/// Returns the canonical chain_id (and also network_id).
pub fn chain_id() -> &'static str {
    match try_chain_id() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ [BOOT] Chain identity resolution failed: {}", e);
            std::process::exit(2);
        }
    }
}

/// Alias: network_id MUST equal chain_id.
#[inline]
pub fn network_id() -> &'static str {
    chain_id()
}

fn read_chain_id_from_genesis(path: &str) -> Option<String> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }
    let raw = fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    let cid = v.get("chain_id")?.as_str()?.trim();
    if cid.is_empty() {
        None
    } else {
        Some(cid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_process_lock;
    use std::fs;
    use std::path::PathBuf;

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            let saved = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "newgen-chain-identity-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn read_chain_id_from_missing_genesis_returns_none() {
        let _lock = test_process_lock();
        let p = unique_temp_path("missing");
        assert_eq!(read_chain_id_from_genesis(p.to_str().unwrap()), None);
    }

    #[test]
    fn read_chain_id_from_genesis_reads_trimmed_value() {
        let _lock = test_process_lock();
        let dir = unique_temp_path("trimmed");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("genesis.json");
        fs::write(&file, r#"{"chain_id":"  alpha-net  "}"#).unwrap();

        assert_eq!(
            read_chain_id_from_genesis(file.to_str().unwrap()),
            Some("alpha-net".to_string())
        );
    }

    #[test]
    fn read_chain_id_from_genesis_rejects_empty_value() {
        let _lock = test_process_lock();
        let dir = unique_temp_path("empty");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("genesis.json");
        fs::write(&file, r#"{"chain_id":"   "}"#).unwrap();

        assert_eq!(read_chain_id_from_genesis(file.to_str().unwrap()), None);
    }

    #[test]
    fn resolve_chain_id_in_dev_mode_prefers_env_override() {
        let _lock = test_process_lock();
        let got = resolve_chain_id_from_sources(
            false,
            Some("override-net"),
            Some("genesis-net".to_string()),
        );
        assert_eq!(got.unwrap(), "override-net");
    }

    #[test]
    fn resolve_chain_id_in_dev_mode_falls_back_to_genesis_then_default() {
        let _lock = test_process_lock();
        let from_genesis =
            resolve_chain_id_from_sources(false, None, Some("genesis-net".to_string()));
        assert_eq!(from_genesis.unwrap(), "genesis-net");

        let from_default = resolve_chain_id_from_sources(false, None, None);
        assert_eq!(from_default.unwrap(), "newgen-devnet");
    }

    #[test]
    fn resolve_chain_id_in_public_mode_requires_genesis_and_allows_matching_env() {
        let _lock = test_process_lock();
        let got = resolve_chain_id_from_sources(
            true,
            Some("mainnet-alpha"),
            Some("mainnet-alpha".to_string()),
        );
        assert_eq!(got.unwrap(), "mainnet-alpha");
    }

    #[test]
    fn resolve_chain_id_in_public_mode_rejects_mismatched_env_override() {
        let _lock = test_process_lock();
        let res = resolve_chain_id_from_sources(
            true,
            Some("override-net"),
            Some("genesis-net".to_string()),
        );
        assert!(
            res.is_err(),
            "public_mode must reject mismatched NEWGEN_NETWORK_ID"
        );
    }

    #[test]
    fn resolve_chain_id_in_public_mode_rejects_missing_genesis() {
        let _lock = test_process_lock();
        let res = resolve_chain_id_from_sources(true, None, None);
        assert!(
            res.is_err(),
            "public_mode must require genesis-backed chain_id"
        );
    }

    #[test]
    fn network_id_is_alias_of_chain_id() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");
        assert_eq!(network_id(), chain_id());
    }

    #[test]
    fn init_chain_id_tolerates_mismatch_in_tests() {
        let _lock = test_process_lock();
        init_chain_id("chain-a").unwrap();
        init_chain_id("chain-b").unwrap();
    }
}
