use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SyncPolicyLoadError {
    pub path: Option<PathBuf>,
    pub message: String,
}

impl std::fmt::Display for SyncPolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}: {}", path.display(), self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for SyncPolicyLoadError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncPolicy {
    // headers-first
    pub max_headers_per_response: usize,
    pub headers_rr_rate_per_sec: u32,
    pub headers_rr_burst: u32,
    pub max_inflight_headers_rr: u32,

    // RR v3 hardening
    pub rr_v3_request_timeout_ms: u64,
    pub rr_v3_max_inflight_global: u32,
    pub rr_v3_global_rate_per_sec: u32,
    pub rr_v3_global_burst: u32,
    pub rr_v3_max_frame_bytes: usize,

    // Snapshot RRv3 transfer policy (V222): snapshot chunks are large data-plane
    // payloads and must not be forced through the small steady-state RR frame cap.
    // The codec uses max(rr_v3_max_frame_bytes, snapshot_rr_v3_max_frame_bytes),
    // while non-snapshot messages remain bounded by rr_v3_max_frame_bytes.
    pub snapshot_rr_v3_max_frame_bytes: usize,
    pub snapshot_rr_v3_serve_budget_ms: u64,
    pub snapshot_rr_v3_global_rate_per_sec: u32,
    pub snapshot_rr_v3_global_burst: u32,
    pub snapshot_rr_v3_peer_rate_per_sec: u32,
    pub snapshot_rr_v3_peer_burst: u32,
    pub snapshot_rr_v3_max_inflight_global: u32,
    pub snapshot_rr_v3_max_concurrent_serve: u32,

    // RR v3 serving budgets / backpressure (BLOCKER #3)
    pub rr_v3_peer_rate_per_sec: u32,
    pub rr_v3_peer_burst: u32,
    pub rr_v3_max_concurrent_serve: u32,
    pub rr_v3_serve_budget_ms: u64,

    // RR v3 circuit breaker (per-peer)
    pub rr_v3_peer_strike_window_ms: u64,
    pub rr_v3_peer_max_strikes: u32,
    pub rr_v3_peer_cooldown_ms: u64,
    pub rr_v3_disconnect_on_trip: bool,

    // RR v3 headers cache (encoded payload)
    pub rr_v3_headers_cache_items: usize,
    pub rr_v3_headers_cache_ttl_ms: u64,

    // Treasury/governance recompute hardening (coalesce + throttle + chunked snapshot)
    pub treasury_recompute_min_interval_sec: u64,
    pub treasury_recompute_chunk_size: usize,

    // checkpoints
    pub checkpoint_interval: u64,
    pub checkpoint_quorum_k: usize,
    pub checkpoint_retention: usize,

    // snapshot
    pub snapshot_enabled: bool,
    pub snapshot_interval: u64,
    pub max_snapshot_bytes: usize,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            max_headers_per_response: 1024,
            headers_rr_rate_per_sec: 4,
            headers_rr_burst: 8,
            max_inflight_headers_rr: 1,

            rr_v3_request_timeout_ms: 5_000,
            rr_v3_max_inflight_global: 32,
            rr_v3_global_rate_per_sec: 64,
            rr_v3_global_burst: 128,
            rr_v3_max_frame_bytes: 262_144,
            snapshot_rr_v3_max_frame_bytes: 8 * 1024 * 1024,
            snapshot_rr_v3_serve_budget_ms: 1_500,
            snapshot_rr_v3_global_rate_per_sec: 8,
            snapshot_rr_v3_global_burst: 16,
            snapshot_rr_v3_peer_rate_per_sec: 2,
            snapshot_rr_v3_peer_burst: 4,
            snapshot_rr_v3_max_inflight_global: 4,
            snapshot_rr_v3_max_concurrent_serve: 2,

            rr_v3_peer_rate_per_sec: 8,
            rr_v3_peer_burst: 16,
            rr_v3_max_concurrent_serve: 8,
            rr_v3_serve_budget_ms: 35,

            rr_v3_peer_strike_window_ms: 60_000,
            rr_v3_peer_max_strikes: 80,
            rr_v3_peer_cooldown_ms: 120_000,
            rr_v3_disconnect_on_trip: false,

            rr_v3_headers_cache_items: 512,
            rr_v3_headers_cache_ttl_ms: 2_500,

            treasury_recompute_min_interval_sec: 5,
            treasury_recompute_chunk_size: 250,

            checkpoint_interval: 256,
            checkpoint_quorum_k: 2,
            checkpoint_retention: 64,

            snapshot_enabled: false,
            snapshot_interval: 256,
            max_snapshot_bytes: 50_000_000,
        }
    }
}

impl SyncPolicy {
    /// Carica da:
    ///  - ./config/sync_policy.toml
    ///  - ../config/sync_policy.toml
    ///  - fallback a default se manca o parse fallisce in dev_mode.
    pub fn try_load() -> Result<Self, SyncPolicyLoadError> {
        let candidates = ["config/sync_policy.toml", "../config/sync_policy.toml"];
        let public_mode = crate::runtime_mode::public_mode_enabled();
        let mut last_err: Option<SyncPolicyLoadError> = None;

        for p in candidates {
            match fs::read_to_string(p) {
                Ok(s) => match toml::from_str::<SyncPolicy>(&s) {
                    Ok(mut pol) => {
                        pol.harden();
                        return Ok(pol);
                    }
                    Err(e) => {
                        let err = SyncPolicyLoadError {
                            path: Some(PathBuf::from(p)),
                            message: format!("sync_policy.toml malformata: {}", e),
                        };
                        if public_mode {
                            return Err(err);
                        }
                        ng_warn!(
                            target: "boot.sync",
                            "{}. Uso default.",
                            err
                        );
                        last_err = Some(err);
                    }
                },
                Err(_) => continue,
            }
        }

        if public_mode {
            return Err(last_err.unwrap_or_else(|| SyncPolicyLoadError {
                path: None,
                message: "Missing sync_policy.toml in public_mode (searched config/sync_policy.toml and ../config/sync_policy.toml)".to_string(),
            }));
        }

        Ok(Self::default())
    }

    pub fn load() -> Self {
        match Self::try_load() {
            Ok(pol) => pol,
            Err(e) => {
                ng_warn!(target: "boot.sync", "{}. Uso default fail-closed conservativo.", e);
                let mut pol = Self::default();
                pol.harden();
                pol
            }
        }
    }

    pub fn load_or_exit() -> Self {
        match Self::try_load() {
            Ok(pol) => pol,
            Err(e) => {
                eprintln!("❌ [BOOT] SyncPolicy load failed: {}", e);
                std::process::exit(2);
            }
        }
    }

    fn harden(&mut self) {
        // clamps difensivi
        if self.max_headers_per_response == 0 {
            self.max_headers_per_response = 1024;
        } else if self.max_headers_per_response > 4096 {
            self.max_headers_per_response = 4096;
        }

        if self.headers_rr_rate_per_sec == 0 {
            self.headers_rr_rate_per_sec = 4;
        }
        if self.headers_rr_burst == 0 {
            self.headers_rr_burst = 8;
        }
        if self.max_inflight_headers_rr == 0 {
            self.max_inflight_headers_rr = 1;
        }

        // V230: snapshot chunk requests still share the RRv3 request-response
        // behaviour with normal RRv3 messages. Keep the normal frame cap small,
        // but do not allow a sub-5s request timeout because external bootstrap
        // chunk responses can legitimately take longer than LAN/local tests.
        self.rr_v3_request_timeout_ms = self.rr_v3_request_timeout_ms.clamp(5_000, 30_000);

        if self.rr_v3_max_inflight_global == 0 {
            self.rr_v3_max_inflight_global = 16;
        } else if self.rr_v3_max_inflight_global > 256 {
            self.rr_v3_max_inflight_global = 256;
        }

        if self.rr_v3_global_rate_per_sec == 0 {
            self.rr_v3_global_rate_per_sec = 32;
        }
        if self.rr_v3_global_burst == 0 {
            self.rr_v3_global_burst = 64;
        }

        // frame cap: minimo 64KiB, massimo 4MiB (evita valori assurdi)
        self.rr_v3_max_frame_bytes = self.rr_v3_max_frame_bytes.clamp(65_536, 4_194_304);

        // Snapshot data-plane cap: keep steady-state RR small, but allow bootstrap
        // snapshot chunks to use a much larger transport frame. Missing legacy TOML
        // fields deserialize to 0 and are lifted here to a safe 8MiB default.
        if self.snapshot_rr_v3_max_frame_bytes == 0 {
            self.snapshot_rr_v3_max_frame_bytes = 8 * 1024 * 1024;
        }
        self.snapshot_rr_v3_max_frame_bytes = self
            .snapshot_rr_v3_max_frame_bytes
            .clamp(self.rr_v3_max_frame_bytes.max(1_048_576), 16 * 1024 * 1024);

        if self.snapshot_rr_v3_serve_budget_ms == 0 {
            // V278: 2MiB raw snapshot chunks can legitimately require more
            // disk read/hash/base64/JSON time than the old 500ms budget on a
            // busy validator. Keep this scoped to the snapshot lane only.
            self.snapshot_rr_v3_serve_budget_ms = 1_500;
        }
        self.snapshot_rr_v3_serve_budget_ms =
            self.snapshot_rr_v3_serve_budget_ms.clamp(1_000, 5_000);

        // Snapshot data-plane backpressure: separated from normal RRv3 so a
        // cold-start node downloading a large snapshot cannot consume the
        // steady-state headers/checkpoint request budget used by A/B/C.
        if self.snapshot_rr_v3_global_rate_per_sec == 0 {
            self.snapshot_rr_v3_global_rate_per_sec = 8;
        } else if self.snapshot_rr_v3_global_rate_per_sec > 128 {
            self.snapshot_rr_v3_global_rate_per_sec = 128;
        }
        if self.snapshot_rr_v3_global_burst == 0 {
            self.snapshot_rr_v3_global_burst = 16;
        } else if self.snapshot_rr_v3_global_burst > 512 {
            self.snapshot_rr_v3_global_burst = 512;
        }
        if self.snapshot_rr_v3_peer_rate_per_sec == 0 {
            self.snapshot_rr_v3_peer_rate_per_sec = 2;
        } else if self.snapshot_rr_v3_peer_rate_per_sec > 64 {
            self.snapshot_rr_v3_peer_rate_per_sec = 64;
        }
        if self.snapshot_rr_v3_peer_burst == 0 {
            self.snapshot_rr_v3_peer_burst = 4;
        } else if self.snapshot_rr_v3_peer_burst > 256 {
            self.snapshot_rr_v3_peer_burst = 256;
        }
        if self.snapshot_rr_v3_max_inflight_global == 0 {
            self.snapshot_rr_v3_max_inflight_global = 4;
        } else if self.snapshot_rr_v3_max_inflight_global > 64 {
            self.snapshot_rr_v3_max_inflight_global = 64;
        }
        if self.snapshot_rr_v3_max_concurrent_serve == 0 {
            self.snapshot_rr_v3_max_concurrent_serve = 2;
        } else if self.snapshot_rr_v3_max_concurrent_serve > 32 {
            self.snapshot_rr_v3_max_concurrent_serve = 32;
        }

        // per-peer serve caps (defensive)
        if self.rr_v3_peer_rate_per_sec == 0 {
            self.rr_v3_peer_rate_per_sec = 4;
        } else if self.rr_v3_peer_rate_per_sec > 512 {
            self.rr_v3_peer_rate_per_sec = 512;
        }
        if self.rr_v3_peer_burst == 0 {
            self.rr_v3_peer_burst = 8;
        } else if self.rr_v3_peer_burst > 2048 {
            self.rr_v3_peer_burst = 2048;
        }

        if self.rr_v3_max_concurrent_serve == 0 {
            self.rr_v3_max_concurrent_serve = 4;
        } else if self.rr_v3_max_concurrent_serve > 256 {
            self.rr_v3_max_concurrent_serve = 256;
        }

        self.rr_v3_serve_budget_ms = self.rr_v3_serve_budget_ms.clamp(5, 500);

        self.rr_v3_peer_strike_window_ms = self.rr_v3_peer_strike_window_ms.clamp(5_000, 600_000);

        self.rr_v3_peer_max_strikes = self.rr_v3_peer_max_strikes.clamp(5, 10_000);

        self.rr_v3_peer_cooldown_ms = self.rr_v3_peer_cooldown_ms.clamp(5_000, 3_600_000);

        // cache bounds
        if self.rr_v3_headers_cache_items == 0 {
            self.rr_v3_headers_cache_items = 128;
        } else if self.rr_v3_headers_cache_items > 50_000 {
            self.rr_v3_headers_cache_items = 50_000;
        }

        self.rr_v3_headers_cache_ttl_ms = self.rr_v3_headers_cache_ttl_ms.clamp(100, 60_000);

        // recompute throttle
        if self.treasury_recompute_min_interval_sec == 0 {
            self.treasury_recompute_min_interval_sec = 2;
        } else if self.treasury_recompute_min_interval_sec > 60 {
            self.treasury_recompute_min_interval_sec = 60;
        }

        self.treasury_recompute_chunk_size = self.treasury_recompute_chunk_size.clamp(10, 5_000);

        if self.checkpoint_interval == 0 {
            self.checkpoint_interval = 256;
        }
        if self.snapshot_interval == 0 {
            self.snapshot_interval = 256;
        }
        if self.max_snapshot_bytes < 1_000_000 {
            self.max_snapshot_bytes = 1_000_000;
        }
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
            "newgen-sync-policy-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn harden_clamps_extreme_values() {
        let mut pol = SyncPolicy {
            max_headers_per_response: 0,
            rr_v3_request_timeout_ms: 1,
            rr_v3_max_inflight_global: 0,
            rr_v3_max_frame_bytes: 1,
            rr_v3_peer_rate_per_sec: 9_999,
            rr_v3_peer_burst: 0,
            rr_v3_max_concurrent_serve: 9_999,
            rr_v3_serve_budget_ms: 1,
            rr_v3_peer_strike_window_ms: 1,
            rr_v3_peer_max_strikes: 0,
            rr_v3_peer_cooldown_ms: 99_999_999,
            rr_v3_headers_cache_items: 0,
            rr_v3_headers_cache_ttl_ms: 1,
            treasury_recompute_min_interval_sec: 0,
            treasury_recompute_chunk_size: 1,
            snapshot_interval: 0,
            max_snapshot_bytes: 1,
            ..SyncPolicy::default()
        };

        pol.harden();

        assert_eq!(pol.max_headers_per_response, 1024);
        assert_eq!(pol.rr_v3_request_timeout_ms, 5_000);
        assert_eq!(pol.rr_v3_max_inflight_global, 16);
        assert_eq!(pol.rr_v3_max_frame_bytes, 65_536);
        assert_eq!(pol.snapshot_rr_v3_max_frame_bytes, 8 * 1024 * 1024);
        assert_eq!(pol.snapshot_rr_v3_serve_budget_ms, 1_500);
        assert_eq!(pol.snapshot_rr_v3_global_rate_per_sec, 8);
        assert_eq!(pol.snapshot_rr_v3_global_burst, 16);
        assert_eq!(pol.snapshot_rr_v3_peer_rate_per_sec, 2);
        assert_eq!(pol.snapshot_rr_v3_peer_burst, 4);
        assert_eq!(pol.snapshot_rr_v3_max_inflight_global, 4);
        assert_eq!(pol.snapshot_rr_v3_max_concurrent_serve, 2);
        assert_eq!(pol.rr_v3_peer_rate_per_sec, 512);
        assert_eq!(pol.rr_v3_peer_burst, 8);
        assert_eq!(pol.rr_v3_max_concurrent_serve, 256);
        assert_eq!(pol.rr_v3_serve_budget_ms, 5);
        assert_eq!(pol.rr_v3_peer_strike_window_ms, 5_000);
        assert_eq!(pol.rr_v3_peer_max_strikes, 5);
        assert_eq!(pol.rr_v3_peer_cooldown_ms, 3_600_000);
        assert_eq!(pol.rr_v3_headers_cache_items, 128);
        assert_eq!(pol.rr_v3_headers_cache_ttl_ms, 100);
        assert_eq!(pol.treasury_recompute_min_interval_sec, 2);
        assert_eq!(pol.treasury_recompute_chunk_size, 10);
        assert_eq!(pol.snapshot_interval, 256);
        assert_eq!(pol.max_snapshot_bytes, 1_000_000);
    }

    #[test]
    fn load_returns_defaults_when_file_is_missing_in_dev_mode() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        let dir = unique_temp_dir("missing");
        let _cwd = CwdGuard::change_to(&dir);

        let pol = SyncPolicy::load();
        let def = SyncPolicy::default();

        assert_eq!(pol.max_headers_per_response, def.max_headers_per_response);
        assert_eq!(pol.rr_v3_request_timeout_ms, def.rr_v3_request_timeout_ms);
        assert_eq!(pol.snapshot_enabled, def.snapshot_enabled);
        assert_eq!(pol.max_snapshot_bytes, def.max_snapshot_bytes);
    }

    #[test]
    fn load_panics_on_malformed_file_in_public_mode() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::set_var("NEWGEN_PUBLIC", "1");
        std::env::set_var("NEWGEN_PUBLIC_MODE", "1");
        std::env::set_var("NEWGEN_NETWORK_MODE", "public");

        let dir = unique_temp_dir("malformed");
        let config_dir = dir.join("config");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("sync_policy.toml"), "not = [valid").unwrap();
        let _cwd = CwdGuard::change_to(&dir);

        let res = SyncPolicy::try_load();
        assert!(
            res.is_err(),
            "public_mode must fail closed on malformed sync_policy.toml"
        );
    }

    #[test]
    fn load_valid_file_applies_hardening() {
        let _lock = test_process_lock();
        let _env =
            EnvGuard::capture(&["NEWGEN_PUBLIC", "NEWGEN_PUBLIC_MODE", "NEWGEN_NETWORK_MODE"]);
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        let dir = unique_temp_dir("valid");
        let config_dir = dir.join("config");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("sync_policy.toml"),
            r#"
max_headers_per_response = 999999
rr_v3_request_timeout_ms = 1
rr_v3_max_frame_bytes = 1
rr_v3_peer_max_strikes = 0
snapshot_enabled = true
max_snapshot_bytes = 12
"#,
        )
        .unwrap();
        let _cwd = CwdGuard::change_to(&dir);

        let pol = SyncPolicy::load();
        assert_eq!(pol.max_headers_per_response, 4096);
        assert_eq!(pol.rr_v3_request_timeout_ms, 5_000);
        assert_eq!(pol.rr_v3_max_frame_bytes, 65_536);
        assert_eq!(pol.rr_v3_peer_max_strikes, 5);
        assert!(pol.snapshot_enabled);
        assert_eq!(pol.max_snapshot_bytes, 1_000_000);
    }

    #[test]
    fn snapshot_rr_v3_policy_keeps_large_snapshot_cap_separate_from_normal_rr() {
        let mut pol = SyncPolicy::default();
        pol.rr_v3_max_frame_bytes = 262_144;
        pol.snapshot_rr_v3_max_frame_bytes = 4 * 1024 * 1024;
        pol.snapshot_rr_v3_serve_budget_ms = 1_000;
        pol.snapshot_rr_v3_global_rate_per_sec = 20;
        pol.snapshot_rr_v3_global_burst = 40;
        pol.snapshot_rr_v3_peer_rate_per_sec = 5;
        pol.snapshot_rr_v3_peer_burst = 10;
        pol.snapshot_rr_v3_max_inflight_global = 6;
        pol.snapshot_rr_v3_max_concurrent_serve = 3;
        pol.harden();

        assert_eq!(pol.rr_v3_max_frame_bytes, 262_144);
        assert_eq!(pol.snapshot_rr_v3_max_frame_bytes, 4 * 1024 * 1024);
        assert_eq!(pol.snapshot_rr_v3_serve_budget_ms, 1_000);
        assert_eq!(pol.snapshot_rr_v3_global_rate_per_sec, 20);
        assert_eq!(pol.snapshot_rr_v3_global_burst, 40);
        assert_eq!(pol.snapshot_rr_v3_peer_rate_per_sec, 5);
        assert_eq!(pol.snapshot_rr_v3_peer_burst, 10);
        assert_eq!(pol.snapshot_rr_v3_max_inflight_global, 6);
        assert_eq!(pol.snapshot_rr_v3_max_concurrent_serve, 3);
    }
}
