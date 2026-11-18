// src/tx_policy.rs
use crate::node_paths::NodePaths;
use crate::transaction::Transaction;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TxOrderingMode {
    None,
    #[default]
    CanonicalV1,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TxPriorityPolicy {
    #[serde(default)]
    pub enabled: bool,

    /// Da quale height (index del blocco) diventa consensus-critical.
    /// Importante: mettila uguale su A e B.
    #[serde(default)]
    pub activation_height: u64,

    /// Max TX per sender nello stesso blocco (anti monopolio).
    #[serde(default = "default_max_sender_per_block")]
    pub max_txs_per_sender_per_block: usize,

    /// Quota minima di TX "normali" da includere, se disponibili.
    #[serde(default = "default_min_normal_per_block")]
    pub min_normal_per_block: usize,

    /// Soglia "normal": max_fee_per_tx <= base_fee * (mult_bps/10_000)
    /// Esempio: 12_000 = 1.2x base_fee.
    #[serde(default = "default_normal_fee_mult_bps")]
    pub normal_fee_max_multiplier_bps: u64,

    #[serde(default)]
    pub ordering_mode: TxOrderingMode,

    #[serde(default = "default_true")]
    pub enforce_ordering: bool,

    #[serde(default = "default_true")]
    pub log_suspicious: bool,
}

fn default_true() -> bool {
    true
}

fn default_max_sender_per_block() -> usize {
    3
}

fn default_min_normal_per_block() -> usize {
    20
}

fn default_normal_fee_mult_bps() -> u64 {
    12_000
}

impl Default for TxPriorityPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            activation_height: u64::MAX, // di default “mai”
            max_txs_per_sender_per_block: default_max_sender_per_block(),
            min_normal_per_block: default_min_normal_per_block(),
            normal_fee_max_multiplier_bps: default_normal_fee_mult_bps(),
            ordering_mode: TxOrderingMode::CanonicalV1,
            enforce_ordering: true,
            log_suspicious: true,
        }
    }
}

impl TxPriorityPolicy {
    fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn load_from_paths(
        paths: &NodePaths,
        public_mode: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let p = paths.tx_policy_path();

        if public_mode && !p.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Missing tx policy in public_mode: {}", p.display()),
            )
            .into());
        }

        if p.exists() {
            return Self::load_from_file(&p);
        }

        Ok(TxPriorityPolicy::default())
    }
    /// Carica la policy dal config root effettivo (NEWGEN_CONFIG_DIR oppure layout di nodo).
    /// Se il file manca o e' invalido, usa i default hardcoded in dev-mode.
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let p = NodePaths::resolve_config_path("config/tx_policy.toml");

        let base = config::Config::builder()
            .add_source(config::Environment::with_prefix("NEWGEN_TXPOL").separator("__"));

        if p.exists() {
            match base
                .clone()
                .add_source(config::File::from(p.clone()))
                .build()
            {
                Ok(cfg) => match cfg.try_deserialize::<TxPriorityPolicy>() {
                    Ok(pol) => {
                        ng_info!(target: "boot.txpol", "TxPriorityPolicy caricata da: {}", p.display());
                        return Ok(pol);
                    }
                    Err(e) => {
                        ng_warn!(target: "boot.txpol", "Policy malformata in {}: {}", p.display(), e);
                    }
                },
                Err(e) => {
                    ng_warn!(target: "boot.txpol", "Impossibile leggere {}: {}", p.display(), e);
                }
            }
        }

        ng_warn!(target: "boot.txpol", "Nessuna tx_policy.toml valida trovata in {}. Uso default.", p.display());
        Ok(TxPriorityPolicy::default())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.enabled && height >= self.activation_height
    }

    pub fn normal_fee_cap(&self, base_fee: u64) -> u64 {
        if base_fee == 0 {
            return 0;
        }
        let mult = self.normal_fee_max_multiplier_bps.max(10_000);
        ((base_fee as u128) * (mult as u128) / 10_000u128) as u64
    }

    pub fn is_normal_tx(&self, tx: &Transaction, base_fee: u64) -> bool {
        if tx.is_coinbase {
            return false;
        }
        tx.max_fee_per_tx <= self.normal_fee_cap(base_fee)
    }
}

// --------- Canonical ordering helpers (deterministici) ----------

fn tx_size_bytes_deterministic(tx: &Transaction) -> u64 {
    // Deterministico e stabile: usa NGBIN v1 (niente serde_json)
    (crate::ngbin::tx_size_bytes_v1(tx) as u64).max(1)
}

/// fee-per-byte DESC, senza float (u128 cross-multiply).
fn cmp_fee_per_byte_desc(a: &Transaction, b: &Transaction) -> Ordering {
    let fa = a.max_fee_per_tx as u128;
    let fb = b.max_fee_per_tx as u128;
    let sa = tx_size_bytes_deterministic(a) as u128;
    let sb = tx_size_bytes_deterministic(b) as u128;

    let left = fa.saturating_mul(sb);
    let right = fb.saturating_mul(sa);

    if left > right {
        Ordering::Less // a prima di b
    } else if left < right {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn deterministic_key_u64(prev_hash: &str, tx_hash: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"NEWGEN_TX_ORDER_V1|");
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(tx_hash.as_bytes());
    let out = h.finalize();
    u64::from_be_bytes(out[0..8].try_into().unwrap())
}

/// Sorting canonico:
// 1) tier: PRIORITY prima (fee > normal_cap), poi NORMAL
// 2) fee-per-byte desc
// 3) deterministic shuffle key asc (seed=prev_hash)
// 4) tx.hash asc (tie-break stabile)
pub fn sort_user_txs_canonical(
    prev_hash: &str,
    txs: &mut [Transaction],
    policy: &TxPriorityPolicy,
    base_fee: u64,
) {
    if matches!(policy.ordering_mode, TxOrderingMode::None) {
        return;
    }

    txs.sort_by(|a, b| {
        let a_normal = policy.is_normal_tx(a, base_fee);
        let b_normal = policy.is_normal_tx(b, base_fee);

        // PRIORITY prima: normal=false => tier 0, normal=true => tier 1
        let ta = if a_normal { 1u8 } else { 0u8 };
        let tb = if b_normal { 1u8 } else { 0u8 };
        if ta != tb {
            return ta.cmp(&tb);
        }

        let fee_cmp = cmp_fee_per_byte_desc(a, b);
        if fee_cmp != Ordering::Equal {
            return fee_cmp;
        }

        let ka = deterministic_key_u64(prev_hash, &a.hash);
        let kb = deterministic_key_u64(prev_hash, &b.hash);
        if ka != kb {
            return ka.cmp(&kb);
        }

        a.hash.cmp(&b.hash)
    });
}

pub fn check_sender_cap(user_txs: &[Transaction], cap: usize) -> Result<(), String> {
    if cap == 0 {
        return Ok(());
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for tx in user_txs {
        let c = counts.entry(tx.sender.as_str()).or_insert(0);
        *c += 1;
        if *c > cap {
            return Err(format!(
                "tx policy violated: sender {} has {} txs in block (cap={})",
                tx.sender, *c, cap
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(sender: &str, amount: u64, fee: u64, nonce: u64, memo: Option<&str>) -> Transaction {
        Transaction::new(
            sender.to_string(),
            "receiver".to_string(),
            amount,
            nonce,
            fee,
            String::new(),
            false,
            memo.map(|s| s.to_string()),
        )
    }

    #[test]
    fn normal_fee_cap_and_is_normal_tx_follow_policy() {
        let pol = TxPriorityPolicy {
            enabled: true,
            normal_fee_max_multiplier_bps: 12_000,
            ..TxPriorityPolicy::default()
        };
        assert_eq!(pol.normal_fee_cap(100), 120);
        assert!(pol.is_normal_tx(&tx("a", 1, 120, 1, None), 100));
        assert!(!pol.is_normal_tx(&tx("a", 1, 121, 1, None), 100));
    }

    #[test]
    fn canonical_sort_puts_priority_before_normal() {
        let pol = TxPriorityPolicy::default();
        let mut txs = vec![
            tx("alice", 1, 100, 1, Some("normal")),
            tx("bob", 1, 1_000, 1, Some("priority")),
        ];
        sort_user_txs_canonical("prev-hash", &mut txs, &pol, 100);
        assert_eq!(txs[0].sender, "bob");
        assert_eq!(txs[1].sender, "alice");
    }

    #[test]
    fn sender_cap_detects_excess() {
        let txs = vec![
            tx("alice", 1, 10, 1, None),
            tx("alice", 1, 10, 2, None),
            tx("bob", 1, 10, 1, None),
        ];
        assert!(check_sender_cap(&txs, 2).is_ok());
        assert!(check_sender_cap(&txs, 1).is_err());
    }
}
