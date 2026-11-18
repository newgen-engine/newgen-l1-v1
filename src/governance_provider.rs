use crate::governance::{Council, GovernanceParams, GovernanceState, ValidatorSet};
use crate::node_paths::NodePaths;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, serde::Deserialize)]
struct GovernanceBootstrapConfig {
    protocol_council: Council,
    economy_council: Council,
    emergency_council: Council,
    params: GovernanceParams,
    initial_validator_set: ValidatorSet,
}

#[derive(Clone)]
enum CacheEntry {
    Hit(Arc<GovernanceState>),
    Fail(String),
}

static GOVERNANCE_BOOTSTRAP_CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();

fn cache_map() -> &'static Mutex<HashMap<String, CacheEntry>> {
    GOVERNANCE_BOOTSTRAP_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key_for_path(path: &Path) -> String {
    match fs::canonicalize(path) {
        Ok(abs) => abs.to_string_lossy().to_string(),
        Err(_) => path.to_string_lossy().to_string(),
    }
}

fn candidate_paths(path: &str) -> Vec<PathBuf> {
    vec![NodePaths::resolve_config_path(path)]
}

fn parse_governance_file(candidate: &Path, verbose: bool) -> Result<Arc<GovernanceState>, String> {
    let raw = fs::read_to_string(candidate)
        .map_err(|e| format!("Lettura governance.json fallita da {:?}: {}", candidate, e))?;

    let cfg: GovernanceBootstrapConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("Parsing governance.json fallito per {:?}: {}", candidate, e))?;

    crate::governance::validate_nft_governance_policy_v1(&cfg.params)
        .map_err(|e| format!("Governance NFT policy invalid in {:?}: {}", candidate, e))?;

    if verbose {
        ng_info!(
            target: "gov.bootstrap",
            "Governance bootstrap OK: validator_set.version={} validators={}",
            cfg.initial_validator_set.version,
            cfg.initial_validator_set.entries.len()
        );
    }

    Ok(Arc::new(GovernanceState::new(
        cfg.protocol_council,
        cfg.economy_council,
        cfg.emergency_council,
        cfg.params,
        cfg.initial_validator_set,
    )))
}

fn load_governance_bootstrap_arc_cached_impl(
    path: &str,
    verbose: bool,
) -> Result<Arc<GovernanceState>, String> {
    // 1) Cache hit/negative-cache hit
    for candidate in candidate_paths(path) {
        let key = cache_key_for_path(&candidate);
        if let Ok(guard) = cache_map().lock() {
            if let Some(entry) = guard.get(&key) {
                return match entry {
                    CacheEntry::Hit(hit) => Ok(Arc::clone(hit)),
                    CacheEntry::Fail(err) => Err(err.clone()),
                };
            }
        }
    }

    // 2) Parse candidates
    for candidate in candidate_paths(path) {
        if verbose {
            ng_debug!(
                target: "gov.bootstrap",
                "Tentativo di caricare governance bootstrap da: {:?}",
                candidate
            );
        }

        if !candidate.exists() {
            if verbose {
                ng_debug!(
                    target: "gov.bootstrap",
                    "File governance non trovato in {:?}",
                    candidate
                );
            }
            continue;
        }

        let key = cache_key_for_path(&candidate);
        let parsed = parse_governance_file(&candidate, verbose);

        // 3) Store in cache (positive or negative)
        if let Ok(mut guard) = cache_map().lock() {
            match &parsed {
                Ok(gs) => {
                    // Keep the first successful parse for this canonical path.
                    let entry = guard
                        .entry(key)
                        .or_insert_with(|| CacheEntry::Hit(Arc::clone(gs)));
                    return match entry {
                        CacheEntry::Hit(hit) => Ok(Arc::clone(hit)),
                        CacheEntry::Fail(err) => Err(err.clone()),
                    };
                }
                Err(err) => {
                    guard.insert(key, CacheEntry::Fail(err.clone()));
                }
            }
        }

        return parsed;
    }

    let msg = format!(
        "Nessun governance.json trovato. Candidate={:?}",
        candidate_paths(path)
    );

    if verbose {
        ng_debug!(target: "gov.bootstrap", "{msg}");
    }
    Err(msg)
}

/// API legacy: restituisce GovernanceState by-value.
/// Nota: il provider cache-izza Arc<GovernanceState>; qui cloni solo quando serve davvero.
pub fn load_governance_bootstrap_from_disk(path: &str) -> Option<GovernanceState> {
    match load_governance_bootstrap_arc_cached_impl(path, true) {
        Ok(gs) => Some((*gs).clone()),
        Err(e) => {
            ng_error!(target: "gov.bootstrap", "{e}");
            None
        }
    }
}

/// Variante quiet: sopprime i log info/debug, ma NON nasconde gli errori reali.
pub fn load_governance_bootstrap_from_disk_quiet(path: &str) -> Option<GovernanceState> {
    match load_governance_bootstrap_arc_cached_impl(path, false) {
        Ok(gs) => Some((*gs).clone()),
        Err(e) => {
            ng_error!(target: "gov.bootstrap", "{e}");
            None
        }
    }
}

/// Required (fail-closed): ritorna Err se non riesce a caricare.
pub fn load_governance_bootstrap_required(path: &str) -> Result<GovernanceState, String> {
    load_governance_bootstrap_arc_cached_impl(path, true).map(|gs| (*gs).clone())
}

/// Required + quiet: ritorna Err se non riesce a caricare (nessun log info/debug).
pub fn load_governance_bootstrap_required_quiet(path: &str) -> Result<GovernanceState, String> {
    load_governance_bootstrap_arc_cached_impl(path, false).map(|gs| (*gs).clone())
}

/// API nuova (mainnet-grade): ritorna Arc cache-izzata (zero clone).
#[allow(dead_code)]
pub fn load_governance_bootstrap_arc(path: &str) -> Result<Arc<GovernanceState>, String> {
    load_governance_bootstrap_arc_cached_impl(path, true)
}

#[allow(dead_code)]
pub fn load_governance_bootstrap_arc_quiet(path: &str) -> Result<Arc<GovernanceState>, String> {
    load_governance_bootstrap_arc_cached_impl(path, false)
}

#[allow(dead_code)]
pub fn clear_governance_bootstrap_cache_for_tests() {
    if let Ok(mut guard) = cache_map().lock() {
        guard.clear();
    }
}
