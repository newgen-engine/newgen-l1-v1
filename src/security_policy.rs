// in: src/security_policy.rs
use crate::node_paths::NodePaths;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScoreConfig {
    pub initial: i64,
    pub decay_hours: u64,
    pub decay_percent: u64,
    pub min_decay: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ThresholdsConfig {
    pub probation: i64,
    pub ban: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WeightsConfig {
    pub tx_valid: i64,
    pub block_valid: i64,
    pub tx_invalid: i64,
    pub block_invalid: i64,
    pub flood_penalty: i64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FloodConfig {
    pub txs_per_10s_threshold: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    pub duration_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityPolicy {
    pub score: ScoreConfig,
    pub thresholds: ThresholdsConfig,
    pub weights: WeightsConfig,
    pub flood: FloodConfig,
    pub ban: BanConfig,

    // 🔐 Step 53 – Firewall economico di sicurezza
    #[serde(default)]
    pub min_fee_per_tx: u64, // minimo assoluto per TX
    #[serde(default)]
    pub min_fee_per_byte: u64, // minimo per byte (mempool/DoS)
    #[serde(default = "default_max_block_size_v1")]
    pub max_block_size: u64, // limite “hard” dimensione blocco
}

const DEFAULT_MAX_BLOCK_SIZE_V1: u64 = 1_000_000;

fn default_max_block_size_v1() -> u64 {
    DEFAULT_MAX_BLOCK_SIZE_V1
}

static SECURITY_POLICY_CACHE: OnceLock<SecurityPolicy> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct SecurityPolicyLoadError {
    pub path: Option<PathBuf>,
    pub message: String,
}

impl std::fmt::Display for SecurityPolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}: {}", path.display(), self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for SecurityPolicyLoadError {}

impl SecurityPolicy {
    fn load_from_file(path: &Path) -> Result<Self, SecurityPolicyLoadError> {
        let raw = std::fs::read_to_string(path).map_err(|e| SecurityPolicyLoadError {
            path: Some(path.to_path_buf()),
            message: e.to_string(),
        })?;
        let pol = toml::from_str::<SecurityPolicy>(&raw).map_err(|e| SecurityPolicyLoadError {
            path: Some(path.to_path_buf()),
            message: e.to_string(),
        })?;
        pol.validate_contract_v1()
            .map_err(|e| SecurityPolicyLoadError {
                path: Some(path.to_path_buf()),
                message: e,
            })?;
        Ok(pol)
    }

    pub fn load_from_paths(
        paths: &NodePaths,
        public_mode: bool,
    ) -> Result<Self, SecurityPolicyLoadError> {
        let p = paths.security_policy_path();

        if public_mode && !p.exists() {
            return Err(SecurityPolicyLoadError {
                path: Some(p.clone()),
                message: "Missing security policy in public_mode".to_string(),
            });
        }

        if p.exists() {
            return Self::load_from_file(&p);
        }

        // dev-mode fallback (default)
        Ok(SecurityPolicy::default())
    }

    /// Inizializza il cache globale con i path del nodo.
    ///
    /// - In public_mode: fail-closed se manca/è invalida.
    /// - In dev_mode: fallback a default.
    pub fn init_from_paths(
        paths: &NodePaths,
        public_mode: bool,
    ) -> Result<SecurityPolicy, SecurityPolicyLoadError> {
        let pol = match Self::load_from_paths(paths, public_mode) {
            Ok(p) => p,
            Err(e) => {
                if public_mode {
                    return Err(e);
                }
                SecurityPolicy::default()
            }
        };
        let _ = SECURITY_POLICY_CACHE.set(pol.clone());
        Ok(pol)
    }
    /// Compat API legacy.
    ///
    /// - In public_mode: non degrada silenziosamente a default; fallisce fail-closed con exit esplicito.
    /// - In dev_mode: mantiene il fallback conservativo a default per tool/test locali.
    pub fn global() -> SecurityPolicy {
        match Self::try_global() {
            Ok(pol) => pol,
            Err(e) => {
                if crate::runtime_mode::public_mode_enabled() {
                    eprintln!("❌ [BOOT] SecurityPolicy global unavailable in public_mode: {e}");
                    std::process::exit(2);
                }
                ng_warn!(target: "boot.sec", "SecurityPolicy global fallback (dev-mode): {}. Uso default conservativo.", e);
                SecurityPolicy::default()
            }
        }
    }

    pub fn try_global() -> Result<SecurityPolicy, SecurityPolicyLoadError> {
        if let Some(pol) = SECURITY_POLICY_CACHE.get() {
            return Ok(pol.clone());
        }
        Self::load()
    }

    /// Carica una volta sola e poi riusa sempre la stessa policy.
    ///
    /// - In public_mode: richiede una policy valida, ma non panic-a se la cache non è ancora inizializzata.
    /// - In dev_mode: puo' caricare da cwd con fallback a default.
    pub fn load_cached() -> SecurityPolicy {
        if let Some(pol) = SECURITY_POLICY_CACHE.get() {
            return pol.clone();
        }
        let pol = Self::global();
        let _ = SECURITY_POLICY_CACHE.set(pol.clone());
        pol
    }

    /// Carica la policy cercando, in ordine:
    /// 1) ./config/security_policy.toml   (RUN_X)
    /// 2) ../config/security_policy.toml  (master CODE_ASSETS)
    ///
    /// In public_mode fallisce se non trova una policy valida.
    /// In dev_mode usa il default hardcoded come fallback.
    pub fn load() -> Result<Self, SecurityPolicyLoadError> {
        let cwd = std::env::current_dir().map_err(|e| SecurityPolicyLoadError {
            path: None,
            message: e.to_string(),
        })?;
        let try_paths = [
            cwd.join("config").join("security_policy.toml"),
            cwd.join("..").join("config").join("security_policy.toml"),
        ];
        let public_mode = crate::runtime_mode::public_mode_enabled();

        // base builder con override via env: es. NEWGEN_SEC__THRESHOLDS__BAN=-8
        let base = config::Config::builder()
            .add_source(config::Environment::with_prefix("NEWGEN_SEC").separator("__"));

        let mut last_err: Option<String> = None;

        for p in &try_paths {
            if p.exists() {
                match base
                    .clone()
                    .add_source(config::File::from(p.clone()))
                    .build()
                {
                    Ok(cfg) => match cfg.try_deserialize::<SecurityPolicy>() {
                        Ok(pol) => match pol.validate_contract_v1() {
                            Ok(()) => {
                                ng_info!(target: "boot.sec", "SecurityPolicy caricata da: {}", p.display());
                                return Ok(pol);
                            }
                            Err(e) => {
                                let msg =
                                    format!("SecurityPolicy non valida in {}: {}", p.display(), e);
                                ng_warn!(target: "boot.sec", "{}", msg);
                                last_err = Some(msg);
                            }
                        },
                        Err(e) => {
                            let msg =
                                format!("SecurityPolicy malformata in {}: {}", p.display(), e);
                            ng_warn!(target: "boot.sec", "{}", msg);
                            last_err = Some(msg);
                        }
                    },
                    Err(e) => {
                        let msg = format!("Impossibile leggere {}: {}", p.display(), e);
                        ng_warn!(target: "boot.sec", "{}", msg);
                        last_err = Some(msg);
                    }
                }
            }
        }

        if public_mode {
            let err = last_err.unwrap_or_else(|| {
                format!(
                    "Missing security_policy.toml in public_mode: searched '{}' and '{}'",
                    try_paths[0].display(),
                    try_paths[1].display()
                )
            });
            return Err(SecurityPolicyLoadError {
                path: None,
                message: err,
            });
        }

        ng_warn!(target: "boot.sec", "Nessuna security_policy.toml valida trovata. Uso default.");
        Ok(SecurityPolicy::default())
    }
}

impl SecurityPolicy {
    /// Contract validation for security/reputation policy files.
    ///
    /// This is intentionally strict for public/mainnet-grade operation: a malformed
    /// policy must fail closed instead of silently falling back to internal defaults.
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        const SCORE_MIN_ALLOWED: i64 = 0;
        const SCORE_MAX_ALLOWED: i64 = 1000;
        const MAX_BAN_SECS: u64 = 60 * 60 * 24 * 30;
        const MAX_DECAY_HOURS: u64 = 24 * 365;
        const MAX_EVENT_ABS_WEIGHT: i64 = 10_000;

        if !(SCORE_MIN_ALLOWED..=SCORE_MAX_ALLOWED).contains(&self.score.initial) {
            return Err(format!(
                "score.initial fuori range {}..{}: {}",
                SCORE_MIN_ALLOWED, SCORE_MAX_ALLOWED, self.score.initial
            ));
        }
        if self.score.decay_hours == 0 || self.score.decay_hours > MAX_DECAY_HOURS {
            return Err(format!(
                "score.decay_hours fuori range 1..{}: {}",
                MAX_DECAY_HOURS, self.score.decay_hours
            ));
        }
        if self.score.decay_percent > 100 {
            return Err(format!(
                "score.decay_percent fuori range 0..100: {}",
                self.score.decay_percent
            ));
        }
        if !(SCORE_MIN_ALLOWED..=SCORE_MAX_ALLOWED).contains(&self.score.min_decay) {
            return Err(format!(
                "score.min_decay fuori range {}..{}: {}",
                SCORE_MIN_ALLOWED, SCORE_MAX_ALLOWED, self.score.min_decay
            ));
        }
        if !(SCORE_MIN_ALLOWED..=SCORE_MAX_ALLOWED).contains(&self.thresholds.probation) {
            return Err(format!(
                "thresholds.probation fuori range {}..{}: {}",
                SCORE_MIN_ALLOWED, SCORE_MAX_ALLOWED, self.thresholds.probation
            ));
        }
        if !(SCORE_MIN_ALLOWED..=SCORE_MAX_ALLOWED).contains(&self.thresholds.ban) {
            return Err(format!(
                "thresholds.ban fuori range {}..{}: {}",
                SCORE_MIN_ALLOWED, SCORE_MAX_ALLOWED, self.thresholds.ban
            ));
        }
        if !(self.score.initial > self.thresholds.probation
            && self.thresholds.probation > self.thresholds.ban)
        {
            return Err(format!(
                "soglie reputazione non coerenti: require score.initial > thresholds.probation > thresholds.ban, got initial={} probation={} ban={}",
                self.score.initial, self.thresholds.probation, self.thresholds.ban
            ));
        }

        if self.weights.tx_valid < 0 || self.weights.block_valid < 0 {
            return Err("weights.tx_valid/block_valid devono essere non negativi".to_string());
        }
        if self.weights.tx_invalid > 0
            || self.weights.block_invalid > 0
            || self.weights.flood_penalty > 0
        {
            return Err(
                "weights.tx_invalid/block_invalid/flood_penalty devono essere non positivi"
                    .to_string(),
            );
        }
        for (name, value) in [
            ("weights.tx_valid", self.weights.tx_valid),
            ("weights.block_valid", self.weights.block_valid),
            ("weights.tx_invalid", self.weights.tx_invalid),
            ("weights.block_invalid", self.weights.block_invalid),
            ("weights.flood_penalty", self.weights.flood_penalty),
        ] {
            if value.abs() > MAX_EVENT_ABS_WEIGHT {
                return Err(format!(
                    "{} fuori range assoluto <= {}: {}",
                    name, MAX_EVENT_ABS_WEIGHT, value
                ));
            }
        }

        if self.flood.txs_per_10s_threshold == 0 {
            return Err("flood.txs_per_10s_threshold deve essere > 0".to_string());
        }
        if self.ban.duration_secs == 0 || self.ban.duration_secs > MAX_BAN_SECS {
            return Err(format!(
                "ban.duration_secs fuori range 1..{}: {}",
                MAX_BAN_SECS, self.ban.duration_secs
            ));
        }
        if self.max_block_size == 0 {
            return Err("max_block_size deve essere > 0".to_string());
        }
        Ok(())
    }

    pub fn reputation_initial_score_i32(&self) -> i32 {
        self.score
            .initial
            .clamp(SCORE_MIN_ALLOWED_I64, SCORE_MAX_ALLOWED_I64) as i32
    }
}

const SCORE_MIN_ALLOWED_I64: i64 = 0;
const SCORE_MAX_ALLOWED_I64: i64 = 1000;

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            // Config della reputazione
            score: ScoreConfig {
                // punteggio iniziale/base del peer sulla scala canonica 0..1000.
                // 600 = identità nuova/base; 1000 resta massimo teorico/trusted raro.
                initial: 600,
                // ogni 24h applichi un decay percentuale
                decay_hours: 24,
                // es. -5% al giorno
                decay_percent: 5,
                // ma non scendi mai sotto 0 con il decay
                min_decay: 0,
            },
            // Soglie per gli stati (good / probation / banned)
            thresholds: ThresholdsConfig {
                // sotto questa soglia il peer entra in probation locale.
                // Deve restare sotto la fascia base/new worker (500..600), non nella fascia buona/stabile.
                probation: 500,
                // sotto questa soglia il peer viene bannato/quarantinato localmente.
                ban: 200,
            },
            // Pesi degli eventi di reputazione
            weights: WeightsConfig {
                tx_valid: 1,
                block_valid: 5,
                tx_invalid: -50,
                block_invalid: -200,
                // Penalty extra per flood/spam
                flood_penalty: -10,
            },
            // Config flood/spam lato P2P
            flood: FloodConfig {
                // soglia di TX per 10 secondi oltre la quale consideri flood
                txs_per_10s_threshold: 500,
            },
            // Config ban temporale
            ban: BanConfig {
                // durata default del ban in secondi (1h)
                duration_secs: 3600,
            },
            // ⚙️ Parametri economici di sicurezza
            min_fee_per_tx: 0,
            min_fee_per_byte: 0,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE_V1,
        }
    }
}

impl SecurityPolicy {
    pub fn reputation_threshold(&self) -> i32 {
        self.thresholds.ban as i32
    }
    pub fn probation_threshold(&self) -> i32 {
        self.thresholds.probation as i32
    }
    pub fn ban_duration_secs(&self) -> u64 {
        self.ban.duration_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_process_lock;
    use std::fs;
    use std::path::{Path, PathBuf};

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

    struct CwdGuard {
        prev: PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &Path) -> Self {
            let prev = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { prev }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.prev).unwrap();
        }
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "newgen-security-policy-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_policy_file(path: &Path) {
        fs::write(
            path,
            r#"
min_fee_per_tx = 7
min_fee_per_byte = 3
max_block_size = 654321

[score]
initial = 600
decay_hours = 24
decay_percent = 5
min_decay = 0

[thresholds]
probation = 500
ban = 200

[weights]
tx_valid = 1
block_valid = 5
tx_invalid = -50
block_invalid = -200
flood_penalty = -10

[flood]
txs_per_10s_threshold = 321

[ban]
duration_secs = 99
"#,
        )
        .unwrap();
    }

    #[test]
    fn init_from_paths_returns_default_in_dev_when_file_is_missing() {
        let _lock = test_process_lock();
        let dir = unique_temp_dir("dev-missing");
        let paths = NodePaths::from_data_dir(&dir);

        let pol = SecurityPolicy::init_from_paths(&paths, false).unwrap();
        let def = SecurityPolicy::default();
        assert_eq!(pol.min_fee_per_tx, def.min_fee_per_tx);
        assert_eq!(pol.max_block_size, def.max_block_size);
    }

    #[test]
    fn init_from_paths_fails_in_public_when_file_is_missing() {
        let _lock = test_process_lock();
        let dir = unique_temp_dir("public-missing");
        let paths = NodePaths::from_data_dir(&dir);

        let res = SecurityPolicy::init_from_paths(&paths, true);
        assert!(
            res.is_err(),
            "public_mode must fail closed when security policy is missing"
        );
    }

    #[test]
    fn init_from_paths_fails_in_public_when_file_is_malformed() {
        let _lock = test_process_lock();
        let dir = unique_temp_dir("public-malformed");
        let paths = NodePaths::from_data_dir(&dir);
        fs::create_dir_all(&paths.config_dir).unwrap();
        fs::write(
            paths.security_policy_path(),
            "[score
not-valid",
        )
        .unwrap();

        let res = SecurityPolicy::init_from_paths(&paths, true);
        assert!(
            res.is_err(),
            "public_mode must fail closed on malformed security policy"
        );
    }

    #[test]
    fn load_returns_default_in_dev_when_no_file_exists() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        let dir = unique_temp_dir("load-dev-missing");
        let _cwd = CwdGuard::change_to(&dir);

        let pol = SecurityPolicy::load().unwrap();
        let def = SecurityPolicy::default();
        assert_eq!(
            pol.flood.txs_per_10s_threshold,
            def.flood.txs_per_10s_threshold
        );
        assert_eq!(pol.max_block_size, def.max_block_size);
    }

    #[test]
    fn load_fails_closed_in_public_when_no_valid_file_exists() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::set_var("NEWGEN_PUBLIC", "1");
        std::env::set_var("NEWGEN_PUBLIC_MODE", "1");
        std::env::set_var("NEWGEN_NETWORK_MODE", "public");

        let dir = unique_temp_dir("load-public-missing");
        let _cwd = CwdGuard::change_to(&dir);

        let res = SecurityPolicy::load();
        assert!(
            res.is_err(),
            "public_mode load() must not fall back to default"
        );
    }

    #[test]
    fn load_reads_valid_file_from_cwd_config() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        let dir = unique_temp_dir("load-valid");
        let config_dir = dir.join("config");
        fs::create_dir_all(&config_dir).unwrap();
        write_policy_file(&config_dir.join("security_policy.toml"));
        let _cwd = CwdGuard::change_to(&dir);

        let pol = SecurityPolicy::load().unwrap();
        assert_eq!(pol.score.initial, 600);
        assert_eq!(pol.flood.txs_per_10s_threshold, 321);
        assert_eq!(pol.min_fee_per_tx, 7);
        assert_eq!(pol.max_block_size, 654321);
    }

    #[test]
    fn try_global_respects_cache_or_fails_closed_in_public_mode_when_missing() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::set_var("NEWGEN_PUBLIC", "1");
        std::env::set_var("NEWGEN_PUBLIC_MODE", "1");
        std::env::set_var("NEWGEN_NETWORK_MODE", "public");

        let dir = unique_temp_dir("try-global-public-missing");
        let _cwd = CwdGuard::change_to(&dir);

        let cached = SECURITY_POLICY_CACHE.get().cloned();
        let res = SecurityPolicy::try_global();
        match cached {
            Some(expected) => {
                let pol = res.expect("try_global must return the cached policy once initialized");
                assert_eq!(pol.max_block_size, expected.max_block_size);
                assert_eq!(pol.min_fee_per_tx, expected.min_fee_per_tx);
                assert_eq!(pol.min_fee_per_byte, expected.min_fee_per_byte);
            }
            None => {
                assert!(
                    res.is_err(),
                    "public_mode uncached global path must fail closed when no policy file exists"
                );
            }
        }
    }

    #[test]
    fn security_policy_rejects_incoherent_reputation_thresholds() {
        let mut pol = SecurityPolicy::default();
        pol.score.initial = 450;
        pol.thresholds.probation = 500;
        pol.thresholds.ban = 200;
        let err = pol
            .validate_contract_v1()
            .expect_err("initial below probation must be rejected");
        assert!(err.contains("score.initial > thresholds.probation > thresholds.ban"));
    }

    #[test]
    fn security_policy_rejects_bad_weight_direction() {
        let mut pol = SecurityPolicy::default();
        pol.weights.tx_invalid = 1;
        let err = pol
            .validate_contract_v1()
            .expect_err("positive invalid-tx weight must be rejected");
        assert!(err.contains("devono essere non positivi"));
    }

    #[test]
    fn security_policy_missing_legacy_max_block_size_uses_safe_default() {
        let raw = r#"
min_fee_per_tx = 7
min_fee_per_byte = 3

[score]
initial = 600
decay_hours = 24
decay_percent = 5
min_decay = 0

[thresholds]
probation = 500
ban = 200

[weights]
tx_valid = 1
block_valid = 5
tx_invalid = -50
block_invalid = -200
flood_penalty = -10

[flood]
txs_per_10s_threshold = 321

[ban]
duration_secs = 99
"#;
        let pol: SecurityPolicy =
            toml::from_str(raw).expect("legacy policy without max_block_size must deserialize");
        assert_eq!(pol.max_block_size, DEFAULT_MAX_BLOCK_SIZE_V1);
        pol.validate_contract_v1()
            .expect("legacy policy must remain valid with safe default max_block_size");
    }

    #[test]
    fn security_policy_rejects_explicit_zero_max_block_size() {
        let mut pol = SecurityPolicy::default();
        pol.max_block_size = 0;
        let err = pol
            .validate_contract_v1()
            .expect_err("explicit disabled max_block_size must be rejected by policy contract");
        assert!(err.contains("max_block_size deve essere > 0"));
    }

    #[test]
    fn security_policy_rejects_explicit_zero_max_block_size_from_toml() {
        let raw = r#"
min_fee_per_tx = 7
min_fee_per_byte = 3
max_block_size = 0

[score]
initial = 600
decay_hours = 24
decay_percent = 5
min_decay = 0

[thresholds]
probation = 500
ban = 200

[weights]
tx_valid = 1
block_valid = 5
tx_invalid = -50
block_invalid = -200
flood_penalty = -10

[flood]
txs_per_10s_threshold = 321

[ban]
duration_secs = 99
"#;
        let pol: SecurityPolicy = toml::from_str(raw)
            .expect("explicit zero max_block_size must deserialize before validation");
        assert_eq!(pol.max_block_size, 0);
        let err = pol
            .validate_contract_v1()
            .expect_err("explicit zero max_block_size must be rejected by validation");
        assert!(err.contains("max_block_size deve essere > 0"));
    }

    #[test]
    fn load_from_file_accepts_legacy_missing_max_block_size_with_safe_default() {
        let dir = unique_temp_dir("load-file-legacy-missing-max-block-size");
        let path = dir.join("security_policy.toml");
        fs::write(
            &path,
            r#"
min_fee_per_tx = 7
min_fee_per_byte = 3

[score]
initial = 600
decay_hours = 24
decay_percent = 5
min_decay = 0

[thresholds]
probation = 500
ban = 200

[weights]
tx_valid = 1
block_valid = 5
tx_invalid = -50
block_invalid = -200
flood_penalty = -10

[flood]
txs_per_10s_threshold = 321

[ban]
duration_secs = 99
"#,
        )
        .unwrap();

        let pol = SecurityPolicy::load_from_file(&path)
            .expect("legacy policy file without max_block_size must remain accepted");
        assert_eq!(pol.max_block_size, DEFAULT_MAX_BLOCK_SIZE_V1);
        assert_eq!(pol.min_fee_per_tx, 7);
        assert_eq!(pol.min_fee_per_byte, 3);
    }

    #[test]
    fn load_from_file_rejects_explicit_zero_max_block_size() {
        let dir = unique_temp_dir("load-file-zero-max-block-size");
        let path = dir.join("security_policy.toml");
        fs::write(
            &path,
            r#"
min_fee_per_tx = 7
min_fee_per_byte = 3
max_block_size = 0

[score]
initial = 600
decay_hours = 24
decay_percent = 5
min_decay = 0

[thresholds]
probation = 500
ban = 200

[weights]
tx_valid = 1
block_valid = 5
tx_invalid = -50
block_invalid = -200
flood_penalty = -10

[flood]
txs_per_10s_threshold = 321

[ban]
duration_secs = 99
"#,
        )
        .unwrap();

        let err = SecurityPolicy::load_from_file(&path)
            .expect_err("explicit zero max_block_size must fail closed during file load");
        assert!(err.message.contains("max_block_size deve essere > 0"));
    }

    #[test]
    fn global_uses_dev_fallback_without_panic() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        let dir = unique_temp_dir("global-dev-fallback");
        let _cwd = CwdGuard::change_to(&dir);

        let pol = SecurityPolicy::global();
        assert_eq!(pol.max_block_size, SecurityPolicy::default().max_block_size);
    }
}
