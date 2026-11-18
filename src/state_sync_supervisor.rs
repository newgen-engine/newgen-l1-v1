// src/state_sync_supervisor.rs
//
// Phase 5 — Runtime State-Sync Supervisor (mainnet-grade)
//
// Goals:
// - Single-flight: at most one state-sync attempt at a time
// - Dedup/coalesce triggers: multiple triggers collapse into one pending attempt
// - Exponential backoff with jitter on failure (5s -> ... -> 10m)
// - Circuit breaker: if >=N failures within a rolling window, pause attempts for a cooldown
// - Designed to be wired to snapshot-v2 state-sync (anchor-verified, fail-closed in --public)
//
// This module only orchestrates retries/limits. The actual sync logic is provided by `StateSyncAction`.

use crate::error::{ErrorKind, NgError};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};

#[derive(Debug, Clone)]
pub enum StateSyncReason {
    NoOverlap {
        peer: Option<String>,
    },
    GapStall {
        detail: String,
        /// Local tip observed by the trigger.  Optional for legacy/manual triggers.
        local_height: Option<u64>,
        /// Best peer/cluster height observed by the trigger.  Used as a stale-snapshot
        /// upper reference by RestartCatchup state-sync so a snapshot that only moves
        /// one block forward cannot be accepted when peers are thousands of blocks
        /// ahead.
        peer_height: Option<u64>,
    },
    LocalConsensusWedged {
        detail: String,
    },
    Manual {
        detail: String,
    },
}

impl StateSyncReason {
    pub fn gap_stall(detail: impl Into<String>) -> Self {
        Self::GapStall {
            detail: detail.into(),
            local_height: None,
            peer_height: None,
        }
    }

    pub fn gap_stall_with_heights(
        detail: impl Into<String>,
        local_height: u64,
        peer_height: u64,
    ) -> Self {
        Self::GapStall {
            detail: detail.into(),
            local_height: Some(local_height),
            peer_height: Some(peer_height),
        }
    }

    pub fn local_height_hint(&self) -> Option<u64> {
        match self {
            Self::GapStall { local_height, .. } => *local_height,
            _ => None,
        }
    }

    pub fn reference_peer_height(&self) -> Option<u64> {
        match self {
            Self::GapStall { peer_height, .. } => *peer_height,
            _ => None,
        }
    }

    /// Preserve the original trigger semantics across supervisor auto-retries.
    ///
    /// RestartCatchup large-gap protection depends on the GapStall local/peer height
    /// hints.  A retry must therefore not downgrade a structured GapStall into a
    /// legacy text-only reason, otherwise the stale-snapshot upper bound is lost.
    pub fn retry_after_failure(&self, err_msg: impl AsRef<str>) -> Self {
        let err_msg = err_msg.as_ref();
        match self {
            Self::GapStall {
                detail,
                local_height,
                peer_height,
            } => Self::GapStall {
                detail: format!("auto-retry after failure: {}; original={}", err_msg, detail),
                local_height: *local_height,
                peer_height: *peer_height,
            },
            Self::NoOverlap { peer } => Self::NoOverlap { peer: peer.clone() },
            Self::LocalConsensusWedged { detail } => Self::LocalConsensusWedged {
                detail: format!("auto-retry after failure: {}; original={}", err_msg, detail),
            },
            Self::Manual { detail } => Self::Manual {
                detail: format!("auto-retry after failure: {}; original={}", err_msg, detail),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateSyncSupervisorConfig {
    /// Initial backoff after first failure (default 5s)
    pub base_backoff_ms: u64,
    /// Max backoff (default 10m)
    pub max_backoff_ms: u64,

    /// Circuit-breaker rolling window (default 10m)
    pub breaker_window_ms: u64,
    /// Failures within window to open breaker (default 5)
    pub breaker_failures: usize,
    /// Cooldown while breaker is open (default 15m)
    pub breaker_cooldown_ms: u64,

    /// Max trigger queue depth (default 64)
    pub trigger_queue: usize,

    /// If true, keep attempting while there is a pending trigger (auto-retry).
    pub auto_retry_on_failure: bool,
}

impl Default for StateSyncSupervisorConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 5_000,
            max_backoff_ms: 600_000,
            breaker_window_ms: 600_000,
            breaker_failures: 5,
            breaker_cooldown_ms: 900_000,
            trigger_queue: 64,
            auto_retry_on_failure: true,
        }
    }
}

impl StateSyncSupervisorConfig {
    /// Build config from environment variables (all optional).
    ///
    /// Env vars:
    /// - NEWGEN_STATESYNC_SUP_BASE_BACKOFF_MS
    /// - NEWGEN_STATESYNC_SUP_MAX_BACKOFF_MS
    /// - NEWGEN_STATESYNC_SUP_BREAKER_WINDOW_MS
    /// - NEWGEN_STATESYNC_SUP_BREAKER_FAILURES
    /// - NEWGEN_STATESYNC_SUP_BREAKER_COOLDOWN_MS
    /// - NEWGEN_STATESYNC_SUP_TRIGGER_QUEUE
    /// - NEWGEN_STATESYNC_SUP_AUTO_RETRY
    pub fn from_env() -> Self {
        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(default)
        }
        fn env_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(default)
        }
        fn env_bool(name: &str, default: bool) -> bool {
            std::env::var(name)
                .ok()
                .map(|v| {
                    let t = v.trim();
                    !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
                })
                .unwrap_or(default)
        }

        let mut cfg = Self::default();

        cfg.base_backoff_ms = env_u64("NEWGEN_STATESYNC_SUP_BASE_BACKOFF_MS", cfg.base_backoff_ms)
            .clamp(100, 600_000);

        cfg.max_backoff_ms = env_u64("NEWGEN_STATESYNC_SUP_MAX_BACKOFF_MS", cfg.max_backoff_ms)
            .clamp(cfg.base_backoff_ms, 3_600_000);

        cfg.breaker_window_ms = env_u64(
            "NEWGEN_STATESYNC_SUP_BREAKER_WINDOW_MS",
            cfg.breaker_window_ms,
        )
        .clamp(10_000, 7_200_000);

        cfg.breaker_failures = env_usize(
            "NEWGEN_STATESYNC_SUP_BREAKER_FAILURES",
            cfg.breaker_failures,
        )
        .clamp(1, 10_000);

        cfg.breaker_cooldown_ms = env_u64(
            "NEWGEN_STATESYNC_SUP_BREAKER_COOLDOWN_MS",
            cfg.breaker_cooldown_ms,
        )
        .clamp(10_000, 14_400_000);

        cfg.trigger_queue =
            env_usize("NEWGEN_STATESYNC_SUP_TRIGGER_QUEUE", cfg.trigger_queue).clamp(1, 4096);

        cfg.auto_retry_on_failure =
            env_bool("NEWGEN_STATESYNC_SUP_AUTO_RETRY", cfg.auto_retry_on_failure);

        cfg
    }
}

pub trait StateSyncAction: Send + Sync + 'static {
    fn run(
        &self,
        reason: StateSyncReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), NgError>> + Send>>;
}

// Blanket impl for async closures
impl<F, Fut> StateSyncAction for F
where
    F: Fn(StateSyncReason) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), NgError>> + Send + 'static,
{
    fn run(
        &self,
        reason: StateSyncReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), NgError>> + Send>> {
        Box::pin((self)(reason))
    }
}

#[derive(Clone)]
pub struct StateSyncSupervisorHandle {
    tx: mpsc::Sender<StateSyncReason>,
}

impl StateSyncSupervisorHandle {
    /// Trigger a sync attempt (coalesced). Non-blocking.
    ///
    /// Returns `true` only when the trigger was actually enqueued. Callers that
    /// mirror supervisor state into their own local pending flags must not mark
    /// recovery as pending when the supervisor is not reachable or the queue is
    /// full, otherwise a later retry can be suppressed without any real
    /// StateSync attempt being scheduled.
    pub fn trigger(&self, reason: StateSyncReason) -> bool {
        self.tx.try_send(reason).is_ok()
    }
}

/// Spawn the supervisor task and return a handle to trigger it.
pub fn spawn_state_sync_supervisor(
    cfg: StateSyncSupervisorConfig,
    action: Arc<dyn StateSyncAction>,
) -> StateSyncSupervisorHandle {
    let (tx, mut rx) = mpsc::channel::<StateSyncReason>(cfg.trigger_queue);

    tokio::spawn(async move {
        let mut pending: Option<StateSyncReason> = None;

        let mut backoff_ms: u64 = 0;

        // Circuit breaker: track failure timestamps (rolling window).
        let mut failures: VecDeque<Instant> = VecDeque::new();
        let mut breaker_until: Option<Instant> = None;

        // Jitter RNG: deterministic seed from time.
        let seed = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ 0x9e3779b97f4a7c15u128) as u64;
        let mut rng = StdRng::seed_from_u64(seed);

        loop {
            // If breaker is open, sleep until it closes (or until a trigger arrives, which we coalesce).
            if let Some(until) = breaker_until {
                let now = Instant::now();
                if now < until {
                    tokio::select! {
                        maybe = rx.recv() => {
                            if let Some(r) = maybe { pending = Some(r); continue; } else { break; }
                        }
                        _ = sleep(until - now) => {
                            breaker_until = None;
                            // Do not clear pending; we may attempt immediately after breaker closes.
                        }
                    }
                } else {
                    breaker_until = None;
                }
            }

            // If nothing is pending, wait for a trigger.
            if pending.is_none() {
                match rx.recv().await {
                    Some(r) => pending = Some(r),
                    None => break,
                }
            }

            // Coalesce additional triggers without spawning concurrent work.
            while let Ok(r) = rx.try_recv() {
                pending = Some(r);
            }

            // Nothing pending after coalesce -> loop back to wait.
            let reason = match pending.take() {
                Some(r) => r,
                None => continue,
            };

            // Backoff before attempting.
            if backoff_ms > 0 {
                // Jitter: +-10%
                let jitter_pct: i64 = rng.gen_range(-10..=10);
                let jittered = ((backoff_ms as i64) * (100 + jitter_pct) / 100).max(0) as u64;
                sleep(Duration::from_millis(jittered)).await;
            }

            ng_warn!(target: "state_sync.supervisor", "attempt start | reason={:?}", reason);

            let res = action.run(reason.clone()).await;

            match res {
                Ok(()) => {
                    ng_info!(target: "state_sync.supervisor", "attempt success");
                    backoff_ms = 0;
                    failures.clear();
                    // If triggers arrived during the attempt, they are already queued; we coalesce next loop.
                }
                Err(e) => {
                    ng_error!(
                        target: "state_sync.supervisor",
                        "attempt failed | kind={:?} msg={}",
                        e.kind,
                        e.msg
                    );

                    // Track rolling failures
                    let now = Instant::now();
                    failures.push_back(now);
                    // Drop old
                    let window = Duration::from_millis(cfg.breaker_window_ms);
                    while let Some(front) = failures.front() {
                        if now.duration_since(*front) > window {
                            failures.pop_front();
                        } else {
                            break;
                        }
                    }
                    if failures.len() >= cfg.breaker_failures {
                        let until = now + Duration::from_millis(cfg.breaker_cooldown_ms);
                        ng_error!(
                            target: "state_sync.supervisor",
                            "circuit breaker OPEN | failures_in_window={} cooldown_ms={}",
                            failures.len(),
                            cfg.breaker_cooldown_ms
                        );
                        breaker_until = Some(until);
                        backoff_ms = 0;
                    } else {
                        // Exponential backoff
                        backoff_ms = if backoff_ms == 0 {
                            cfg.base_backoff_ms
                        } else {
                            (backoff_ms.saturating_mul(2)).min(cfg.max_backoff_ms)
                        };
                    }

                    // Auto-retry if configured: mark pending so next loop will attempt again.
                    // Preserve structured GapStall height hints; otherwise RestartCatchup
                    // retries can lose the peer-height freshness gate and accept stale
                    // barely-progressive snapshots.
                    if cfg.auto_retry_on_failure {
                        pending = Some(reason.retry_after_failure(&e.msg));
                    }
                }
            }
        }

        ng_warn!(target: "state_sync.supervisor", "terminated");
    });

    StateSyncSupervisorHandle { tx }
}

/// Helper: build a consistent NgError for supervisor-level failures.
pub fn supervisor_error(msg: impl Into<String>) -> NgError {
    NgError::new(ErrorKind::Internal, msg)
}

#[inline]
pub fn runtime_statesync_rescue_needed(
    runtime_bootstrap_complete: bool,
    runtime_sync_caught_up: bool,
) -> bool {
    !(runtime_bootstrap_complete && runtime_sync_caught_up)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_process_lock;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

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

    fn run_async_test<F>(fut: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut);
    }

    #[test]
    fn from_env_clamps_and_parses_bool() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&[
            "NEWGEN_STATESYNC_SUP_BASE_BACKOFF_MS",
            "NEWGEN_STATESYNC_SUP_MAX_BACKOFF_MS",
            "NEWGEN_STATESYNC_SUP_BREAKER_WINDOW_MS",
            "NEWGEN_STATESYNC_SUP_BREAKER_FAILURES",
            "NEWGEN_STATESYNC_SUP_BREAKER_COOLDOWN_MS",
            "NEWGEN_STATESYNC_SUP_TRIGGER_QUEUE",
            "NEWGEN_STATESYNC_SUP_AUTO_RETRY",
        ]);

        std::env::set_var("NEWGEN_STATESYNC_SUP_BASE_BACKOFF_MS", "0");
        std::env::set_var("NEWGEN_STATESYNC_SUP_MAX_BACKOFF_MS", "1");
        std::env::set_var("NEWGEN_STATESYNC_SUP_BREAKER_WINDOW_MS", "2");
        std::env::set_var("NEWGEN_STATESYNC_SUP_BREAKER_FAILURES", "0");
        std::env::set_var("NEWGEN_STATESYNC_SUP_BREAKER_COOLDOWN_MS", "3");
        std::env::set_var("NEWGEN_STATESYNC_SUP_TRIGGER_QUEUE", "0");
        std::env::set_var("NEWGEN_STATESYNC_SUP_AUTO_RETRY", "off");

        let cfg = StateSyncSupervisorConfig::from_env();
        assert_eq!(cfg.base_backoff_ms, 100);
        assert_eq!(cfg.max_backoff_ms, 100);
        assert_eq!(cfg.breaker_window_ms, 10_000);
        assert_eq!(cfg.breaker_failures, 1);
        assert_eq!(cfg.breaker_cooldown_ms, 10_000);
        assert_eq!(cfg.trigger_queue, 1);
        assert!(!cfg.auto_retry_on_failure);
    }

    #[test]
    fn supervisor_single_trigger_without_auto_retry_runs_once() {
        run_async_test(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_action = calls.clone();
            let action: Arc<dyn StateSyncAction> = Arc::new(move |_reason: StateSyncReason| {
                let calls = calls_action.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(supervisor_error("boom"))
                }
            });

            let cfg = StateSyncSupervisorConfig {
                base_backoff_ms: 5,
                max_backoff_ms: 20,
                breaker_window_ms: 1_000,
                breaker_failures: 10,
                breaker_cooldown_ms: 200,
                trigger_queue: 8,
                auto_retry_on_failure: false,
            };

            let handle = spawn_state_sync_supervisor(cfg, action);
            handle.trigger(StateSyncReason::Manual {
                detail: "once".to_string(),
            });

            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            drop(handle);
        });
    }

    #[test]
    fn supervisor_auto_retry_hits_breaker_and_stops_retrying_until_cooldown() {
        run_async_test(async {
            async fn wait_for_calls(calls: &AtomicUsize, expected_min: usize, timeout_ms: u64) {
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                loop {
                    if calls.load(Ordering::SeqCst) >= expected_min {
                        return;
                    }
                    if Instant::now() >= deadline {
                        panic!(
                            "timed out waiting for {} calls; observed {}",
                            expected_min,
                            calls.load(Ordering::SeqCst)
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }

            let calls = Arc::new(AtomicUsize::new(0));
            let calls_action = calls.clone();
            let action: Arc<dyn StateSyncAction> = Arc::new(move |_reason: StateSyncReason| {
                let calls = calls_action.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(supervisor_error("boom"))
                }
            });

            let cfg = StateSyncSupervisorConfig {
                base_backoff_ms: 0,
                max_backoff_ms: 0,
                breaker_window_ms: 1_000,
                breaker_failures: 2,
                breaker_cooldown_ms: 500,
                trigger_queue: 8,
                auto_retry_on_failure: true,
            };

            let handle = spawn_state_sync_supervisor(cfg, action);
            handle.trigger(StateSyncReason::gap_stall("test"));

            // The first retry should happen immediately, and the second failure should
            // open the breaker.
            wait_for_calls(calls.as_ref(), 2, 500).await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            // While the breaker is open no further attempts may start. Sleep for less than
            // the configured cooldown to ensure the third attempt is still suppressed.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            // After cooldown expires, the pending auto-retry may proceed again. Use a wider
            // timeout here because task scheduling on CI/current-thread runtimes can be noisy,
            // but keep the functional contract strict: no progress before cooldown, progress
            // after cooldown.
            wait_for_calls(calls.as_ref(), 3, 1_000).await;
            assert!(calls.load(Ordering::SeqCst) >= 3);
            drop(handle);
        });
    }

    #[test]
    fn supervisor_auto_retry_preserves_gap_stall_height_hints_v201() {
        use std::sync::Mutex;

        run_async_test(async {
            async fn wait_for_calls(calls: &AtomicUsize, expected_min: usize, timeout_ms: u64) {
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                loop {
                    if calls.load(Ordering::SeqCst) >= expected_min {
                        return;
                    }
                    if Instant::now() >= deadline {
                        panic!(
                            "timed out waiting for {} calls; observed {}",
                            expected_min,
                            calls.load(Ordering::SeqCst)
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }

            let calls = Arc::new(AtomicUsize::new(0));
            let seen: Arc<Mutex<Vec<StateSyncReason>>> = Arc::new(Mutex::new(Vec::new()));
            let calls_action = calls.clone();
            let seen_action = seen.clone();
            let action: Arc<dyn StateSyncAction> = Arc::new(move |reason: StateSyncReason| {
                let calls = calls_action.clone();
                let seen = seen_action.clone();
                async move {
                    seen.lock().unwrap().push(reason);
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(supervisor_error("boom"))
                }
            });

            let cfg = StateSyncSupervisorConfig {
                base_backoff_ms: 0,
                max_backoff_ms: 0,
                breaker_window_ms: 1_000,
                breaker_failures: 10,
                breaker_cooldown_ms: 500,
                trigger_queue: 8,
                auto_retry_on_failure: true,
            };

            let handle = spawn_state_sync_supervisor(cfg, action);
            handle.trigger(StateSyncReason::gap_stall_with_heights(
                "large gap",
                42_174,
                50_180,
            ));

            wait_for_calls(calls.as_ref(), 2, 500).await;
            let seen = seen.lock().unwrap();
            assert!(seen.len() >= 2);
            assert_eq!(seen[0].local_height_hint(), Some(42_174));
            assert_eq!(seen[0].reference_peer_height(), Some(50_180));
            assert_eq!(seen[1].local_height_hint(), Some(42_174));
            assert_eq!(seen[1].reference_peer_height(), Some(50_180));
            drop(seen);
            drop(handle);
        });
    }

    #[test]
    fn supervisor_error_uses_internal_kind() {
        let err = supervisor_error("x");
        assert_eq!(err.kind, ErrorKind::Internal);
        assert_eq!(err.msg, "x");
    }

    #[test]
    fn runtime_statesync_rescue_needed_requires_both_runtime_gates() {
        assert!(runtime_statesync_rescue_needed(false, false));
        assert!(runtime_statesync_rescue_needed(true, false));
        assert!(runtime_statesync_rescue_needed(false, true));
        assert!(!runtime_statesync_rescue_needed(true, true));
    }
}
