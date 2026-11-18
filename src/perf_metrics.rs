// src/perf_metrics.rs
//
// Minimal, dependency-light performance & DoS-hardening telemetry.
// Goals:
//  - measure lock wait/hold times (approx p99 via histogram)
//  - track P2P RRv3 serving drops + inflight (backpressure health)
//  - expose gauges for queue depth (outbox) and backlog ratio (RRv3 inflight saturation)
//
// NOTE: All metrics are best-effort and must never become consensus-critical.

use serde::Serialize;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const HIST_BUCKETS_US: &[u64] = &[
    10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000,
    500_000, 1_000_000,
];

#[derive(Clone, Copy, Debug)]
pub enum LockKind {
    Api,
    Chain,
}

#[derive(Debug)]
struct Hist {
    counts: Vec<u64>, // len = HIST_BUCKETS_US.len() + 1 (overflow)
    total: u64,
    sum_us: u128,
    max_us: u64,
}

impl Hist {
    fn new() -> Self {
        Self {
            counts: vec![0u64; HIST_BUCKETS_US.len() + 1],
            total: 0,
            sum_us: 0,
            max_us: 0,
        }
    }

    fn observe_us(&mut self, us: u64) {
        self.total = self.total.saturating_add(1);
        self.sum_us = self.sum_us.saturating_add(us as u128);
        if us > self.max_us {
            self.max_us = us;
        }
        let mut idx = HIST_BUCKETS_US.len(); // overflow
        for (i, b) in HIST_BUCKETS_US.iter().enumerate() {
            if us <= *b {
                idx = i;
                break;
            }
        }
        self.counts[idx] = self.counts[idx].saturating_add(1);
    }

    fn p99_us(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let target = ((self.total as f64) * 0.99).ceil() as u64;
        let mut cum: u64 = 0;
        for (i, c) in self.counts.iter().enumerate() {
            cum = cum.saturating_add(*c);
            if cum >= target {
                if i < HIST_BUCKETS_US.len() {
                    return HIST_BUCKETS_US[i];
                } else {
                    return self.max_us;
                }
            }
        }
        self.max_us
    }

    fn avg_us(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        (self.sum_us / (self.total as u128)) as u64
    }
}

#[derive(Debug)]
struct Metrics {
    // Lock metrics
    api_wait: Mutex<Hist>,
    api_hold: Mutex<Hist>,
    chain_wait: Mutex<Hist>,
    chain_hold: Mutex<Hist>,

    // RRv3 counters/gauges
    rrv3_served: AtomicU64,
    rrv3_cache_hit: AtomicU64,
    rrv3_inflight: AtomicU64,
    rrv3_backlog_ratio_ppm: AtomicU64,

    rrv3_drop_decode: AtomicU64,
    rrv3_drop_oversize: AtomicU64,
    rrv3_drop_rate: AtomicU64,
    rrv3_drop_inflight: AtomicU64,
    rrv3_drop_semaphore: AtomicU64,
    rrv3_drop_circuit: AtomicU64,
    rrv3_drop_budget: AtomicU64,

    // P2P outbox gauges
    outbox_len: AtomicU64,
    outbox_bytes: AtomicU64,

    // P2P inbound NewBlock telemetry
    p2p_new_block_received_total: AtomicU64,
    p2p_new_block_applied_total: AtomicU64,
    p2p_new_block_deferred_total: AtomicU64,
    p2p_new_block_rejected_permanent_total: AtomicU64,
    p2p_new_block_rejected_transient_total: AtomicU64,
    p2p_deferred_block_queue_size: AtomicU64,
    p2p_deferred_block_retry_total: AtomicU64,

    // FT API telemetry (best-effort, non-consensus)
    ft_api_token_reads: AtomicU64,
    ft_api_balance_reads: AtomicU64,
    ft_api_allowance_reads: AtomicU64,
    ft_api_frozen_reads: AtomicU64,
    ft_api_metrics_reads: AtomicU64,

    nft_api_collection_reads: AtomicU64,
    nft_api_token_reads: AtomicU64,
    nft_api_owner_of_reads: AtomicU64,
    nft_api_approval_reads: AtomicU64,
    nft_api_operator_approval_reads: AtomicU64,
    nft_api_wallet_reads: AtomicU64,
    nft_api_owner_collection_reads: AtomicU64,
    nft_api_collection_token_reads: AtomicU64,
    nft_api_metrics_reads: AtomicU64,

    // Cognitive registry telemetry (best-effort, non-consensus)
    cognitive_registry_object_reads: AtomicU64,
    cognitive_registry_claim_reads: AtomicU64,
    cognitive_registry_status_reads: AtomicU64,
    cognitive_registry_events_reads: AtomicU64,
    cognitive_registry_meta_reads: AtomicU64,
    cognitive_tx_applied_total: AtomicU64,
    cognitive_tx_rejected_total: AtomicU64,
    cognitive_registry_entries_total: AtomicU64,
    cognitive_registry_contested_total: AtomicU64,
    cognitive_registry_revoked_total: AtomicU64,
    cognitive_registry_superseded_total: AtomicU64,

    // Consensus liveness / quorum overrides (best-effort, non-consensus)
    liveness_override_total: AtomicU64,
    liveness_override_validator_set_total: AtomicU64,
    liveness_override_committee_total: AtomicU64,
    downtime_jail_skipped_below_quorum_total: AtomicU64,

    liveness_validator_set_active_current: AtomicU64,
    liveness_validator_set_effective_current: AtomicU64,
    liveness_validator_set_non_revoked_current: AtomicU64,
    liveness_validator_set_quorum_current: AtomicU64,
    liveness_validator_set_override_active_current: AtomicU64,

    liveness_committee_active_members_current: AtomicU64,
    liveness_committee_effective_members_current: AtomicU64,
    liveness_committee_non_revoked_members_current: AtomicU64,
    liveness_committee_active_stake_current: AtomicU64,
    liveness_committee_effective_stake_current: AtomicU64,
    liveness_committee_quorum_stake_current: AtomicU64,
    liveness_committee_override_active_current: AtomicU64,

    liveness_override_validator_set_last_height: AtomicU64,
    liveness_override_committee_last_height: AtomicU64,

    // Reset marker
    start_unix: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        let start_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            api_wait: Mutex::new(Hist::new()),
            api_hold: Mutex::new(Hist::new()),
            chain_wait: Mutex::new(Hist::new()),
            chain_hold: Mutex::new(Hist::new()),

            rrv3_served: AtomicU64::new(0),
            rrv3_cache_hit: AtomicU64::new(0),
            rrv3_inflight: AtomicU64::new(0),
            rrv3_backlog_ratio_ppm: AtomicU64::new(0),

            rrv3_drop_decode: AtomicU64::new(0),
            rrv3_drop_oversize: AtomicU64::new(0),
            rrv3_drop_rate: AtomicU64::new(0),
            rrv3_drop_inflight: AtomicU64::new(0),
            rrv3_drop_semaphore: AtomicU64::new(0),
            rrv3_drop_circuit: AtomicU64::new(0),
            rrv3_drop_budget: AtomicU64::new(0),

            outbox_len: AtomicU64::new(0),
            outbox_bytes: AtomicU64::new(0),

            p2p_new_block_received_total: AtomicU64::new(0),
            p2p_new_block_applied_total: AtomicU64::new(0),
            p2p_new_block_deferred_total: AtomicU64::new(0),
            p2p_new_block_rejected_permanent_total: AtomicU64::new(0),
            p2p_new_block_rejected_transient_total: AtomicU64::new(0),
            p2p_deferred_block_queue_size: AtomicU64::new(0),
            p2p_deferred_block_retry_total: AtomicU64::new(0),

            ft_api_token_reads: AtomicU64::new(0),
            ft_api_balance_reads: AtomicU64::new(0),
            ft_api_allowance_reads: AtomicU64::new(0),
            ft_api_frozen_reads: AtomicU64::new(0),
            ft_api_metrics_reads: AtomicU64::new(0),

            nft_api_collection_reads: AtomicU64::new(0),
            nft_api_token_reads: AtomicU64::new(0),
            nft_api_owner_of_reads: AtomicU64::new(0),
            nft_api_approval_reads: AtomicU64::new(0),
            nft_api_operator_approval_reads: AtomicU64::new(0),
            nft_api_wallet_reads: AtomicU64::new(0),
            nft_api_owner_collection_reads: AtomicU64::new(0),
            nft_api_collection_token_reads: AtomicU64::new(0),
            nft_api_metrics_reads: AtomicU64::new(0),

            cognitive_registry_object_reads: AtomicU64::new(0),
            cognitive_registry_claim_reads: AtomicU64::new(0),
            cognitive_registry_status_reads: AtomicU64::new(0),
            cognitive_registry_events_reads: AtomicU64::new(0),
            cognitive_registry_meta_reads: AtomicU64::new(0),
            cognitive_tx_applied_total: AtomicU64::new(0),
            cognitive_tx_rejected_total: AtomicU64::new(0),
            cognitive_registry_entries_total: AtomicU64::new(0),
            cognitive_registry_contested_total: AtomicU64::new(0),
            cognitive_registry_revoked_total: AtomicU64::new(0),
            cognitive_registry_superseded_total: AtomicU64::new(0),

            liveness_override_total: AtomicU64::new(0),
            liveness_override_validator_set_total: AtomicU64::new(0),
            liveness_override_committee_total: AtomicU64::new(0),
            downtime_jail_skipped_below_quorum_total: AtomicU64::new(0),

            liveness_validator_set_active_current: AtomicU64::new(0),
            liveness_validator_set_effective_current: AtomicU64::new(0),
            liveness_validator_set_non_revoked_current: AtomicU64::new(0),
            liveness_validator_set_quorum_current: AtomicU64::new(0),
            liveness_validator_set_override_active_current: AtomicU64::new(0),

            liveness_committee_active_members_current: AtomicU64::new(0),
            liveness_committee_effective_members_current: AtomicU64::new(0),
            liveness_committee_non_revoked_members_current: AtomicU64::new(0),
            liveness_committee_active_stake_current: AtomicU64::new(0),
            liveness_committee_effective_stake_current: AtomicU64::new(0),
            liveness_committee_quorum_stake_current: AtomicU64::new(0),
            liveness_committee_override_active_current: AtomicU64::new(0),

            liveness_override_validator_set_last_height: AtomicU64::new(u64::MAX),
            liveness_override_committee_last_height: AtomicU64::new(u64::MAX),

            start_unix: AtomicU64::new(start_unix),
        }
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

fn m() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

fn dur_to_us(d: Duration) -> u64 {
    let us = d.as_micros();
    if us >= (u64::MAX as u128) {
        u64::MAX
    } else {
        us as u64
    }
}

// --------------------
// Lock instrumentation
// --------------------

pub fn observe_lock(kind: LockKind, wait: Duration, hold: Duration) {
    let wait_us = dur_to_us(wait);
    let hold_us = dur_to_us(hold);

    let mm = m();
    match kind {
        LockKind::Api => {
            if let Ok(mut h) = mm.api_wait.lock() {
                h.observe_us(wait_us);
            }
            if let Ok(mut h) = mm.api_hold.lock() {
                h.observe_us(hold_us);
            }
        }
        LockKind::Chain => {
            if let Ok(mut h) = mm.chain_wait.lock() {
                h.observe_us(wait_us);
            }
            if let Ok(mut h) = mm.chain_hold.lock() {
                h.observe_us(hold_us);
            }
        }
    }
}

/// Wrapper guard that records lock-hold time on Drop.
/// Intended for API mutex guards (warp handlers) where we can't easily scope-instrument.
pub struct TimedMutexGuard<'a, T> {
    guard: std::sync::MutexGuard<'a, T>,
    kind: LockKind,
    acquired_at: Instant,
    wait: Duration,
}

impl<'a, T> TimedMutexGuard<'a, T> {
    pub fn new_api(guard: std::sync::MutexGuard<'a, T>, wait: Duration) -> Self {
        Self {
            guard,
            kind: LockKind::Api,
            acquired_at: Instant::now(),
            wait,
        }
    }
}

impl<'a, T> Deref for TimedMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<'a, T> DerefMut for TimedMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<'a, T> Drop for TimedMutexGuard<'a, T> {
    fn drop(&mut self) {
        let hold = self.acquired_at.elapsed();
        observe_lock(self.kind, self.wait, hold);
    }
}

// --------------------
// RRv3 metrics helpers
// --------------------

pub fn rrv3_inc_served() {
    m().rrv3_served.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_inc_cache_hit() {
    m().rrv3_cache_hit.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_set_inflight(v: u64) {
    m().rrv3_inflight.store(v, Ordering::Relaxed);
}

pub fn rrv3_set_backlog_ratio_ppm(ppm: u64) {
    m().rrv3_backlog_ratio_ppm.store(ppm, Ordering::Relaxed);
}

pub fn rrv3_drop_decode() {
    m().rrv3_drop_decode.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_oversize() {
    m().rrv3_drop_oversize.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_rate() {
    m().rrv3_drop_rate.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_inflight() {
    m().rrv3_drop_inflight.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_semaphore() {
    m().rrv3_drop_semaphore.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_circuit() {
    m().rrv3_drop_circuit.fetch_add(1, Ordering::Relaxed);
}

pub fn rrv3_drop_budget() {
    m().rrv3_drop_budget.fetch_add(1, Ordering::Relaxed);
}

// --------------------
// P2P outbox gauges
// --------------------

pub fn outbox_set(len: usize, bytes: usize) {
    m().outbox_len.store(len as u64, Ordering::Relaxed);
    m().outbox_bytes.store(bytes as u64, Ordering::Relaxed);
}

pub fn p2p_new_block_received() {
    m().p2p_new_block_received_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn p2p_new_block_applied() {
    m().p2p_new_block_applied_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn p2p_new_block_deferred() {
    m().p2p_new_block_deferred_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn p2p_new_block_rejected_permanent() {
    m().p2p_new_block_rejected_permanent_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn p2p_new_block_rejected_transient() {
    m().p2p_new_block_rejected_transient_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn p2p_deferred_block_queue_set(v: usize) {
    m().p2p_deferred_block_queue_size
        .store(v as u64, Ordering::Relaxed);
}

pub fn p2p_deferred_block_retry() {
    m().p2p_deferred_block_retry_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn ft_api_token_read() {
    m().ft_api_token_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn ft_api_balance_read() {
    m().ft_api_balance_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn ft_api_allowance_read() {
    m().ft_api_allowance_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn ft_api_frozen_read() {
    m().ft_api_frozen_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn ft_api_metrics_read() {
    m().ft_api_metrics_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_collection_read() {
    m().nft_api_collection_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_token_read() {
    m().nft_api_token_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_owner_of_read() {
    m().nft_api_owner_of_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_approval_read() {
    m().nft_api_approval_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_operator_approval_read() {
    m().nft_api_operator_approval_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_wallet_read() {
    m().nft_api_wallet_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_owner_collection_read() {
    m().nft_api_owner_collection_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_collection_token_read() {
    m().nft_api_collection_token_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn nft_api_metrics_read() {
    m().nft_api_metrics_reads.fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_object_read() {
    m().cognitive_registry_object_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_claim_read() {
    m().cognitive_registry_claim_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_status_read() {
    m().cognitive_registry_status_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_events_read() {
    m().cognitive_registry_events_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_meta_read() {
    m().cognitive_registry_meta_reads
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_tx_applied(n: u64) {
    m().cognitive_tx_applied_total
        .fetch_add(n, Ordering::Relaxed);
}

pub fn cognitive_tx_rejected() {
    m().cognitive_tx_rejected_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_entry_created() {
    m().cognitive_registry_entries_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_mark_contested() {
    m().cognitive_registry_contested_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_mark_revoked() {
    m().cognitive_registry_revoked_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn cognitive_registry_mark_superseded() {
    m().cognitive_registry_superseded_total
        .fetch_add(1, Ordering::Relaxed);
}

pub fn liveness_override_validator_set_observed(
    height: u64,
    active_validators: usize,
    effective_validators: usize,
    non_revoked_validators: usize,
    quorum_validators: usize,
    override_active: bool,
) {
    let mm = m();
    mm.liveness_validator_set_active_current
        .store(active_validators as u64, Ordering::Relaxed);
    mm.liveness_validator_set_effective_current
        .store(effective_validators as u64, Ordering::Relaxed);
    mm.liveness_validator_set_non_revoked_current
        .store(non_revoked_validators as u64, Ordering::Relaxed);
    mm.liveness_validator_set_quorum_current
        .store(quorum_validators as u64, Ordering::Relaxed);
    mm.liveness_validator_set_override_active_current
        .store(u64::from(override_active), Ordering::Relaxed);

    if override_active {
        let prev = mm
            .liveness_override_validator_set_last_height
            .swap(height, Ordering::Relaxed);
        if prev != height {
            mm.liveness_override_total.fetch_add(1, Ordering::Relaxed);
            mm.liveness_override_validator_set_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn liveness_override_committee_observed(
    height: u64,
    active_members: usize,
    effective_members: usize,
    non_revoked_members: usize,
    active_stake: u64,
    effective_stake: u64,
    quorum_stake: u64,
    override_active: bool,
) {
    let mm = m();
    mm.liveness_committee_active_members_current
        .store(active_members as u64, Ordering::Relaxed);
    mm.liveness_committee_effective_members_current
        .store(effective_members as u64, Ordering::Relaxed);
    mm.liveness_committee_non_revoked_members_current
        .store(non_revoked_members as u64, Ordering::Relaxed);
    mm.liveness_committee_active_stake_current
        .store(active_stake, Ordering::Relaxed);
    mm.liveness_committee_effective_stake_current
        .store(effective_stake, Ordering::Relaxed);
    mm.liveness_committee_quorum_stake_current
        .store(quorum_stake, Ordering::Relaxed);
    mm.liveness_committee_override_active_current
        .store(u64::from(override_active), Ordering::Relaxed);

    if override_active {
        let prev = mm
            .liveness_override_committee_last_height
            .swap(height, Ordering::Relaxed);
        if prev != height {
            mm.liveness_override_total.fetch_add(1, Ordering::Relaxed);
            mm.liveness_override_committee_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn downtime_jail_skipped_below_quorum() {
    m().downtime_jail_skipped_below_quorum_total
        .fetch_add(1, Ordering::Relaxed);
}

// --------------------
// Snapshot for API
// --------------------

#[derive(Debug, Clone, Serialize)]
pub struct PerfSnapshot {
    pub since_unix: u64,

    pub lock_api_wait_p99_us: u64,
    pub lock_api_wait_avg_us: u64,
    pub lock_api_hold_p99_us: u64,
    pub lock_api_hold_avg_us: u64,

    pub lock_chain_wait_p99_us: u64,
    pub lock_chain_wait_avg_us: u64,
    pub lock_chain_hold_p99_us: u64,
    pub lock_chain_hold_avg_us: u64,

    pub rrv3_inflight: u64,
    pub rrv3_backlog_ratio_ppm: u64,
    pub rrv3_served: u64,
    pub rrv3_cache_hit: u64,

    pub rrv3_drop_decode: u64,
    pub rrv3_drop_oversize: u64,
    pub rrv3_drop_rate: u64,
    pub rrv3_drop_inflight: u64,
    pub rrv3_drop_semaphore: u64,
    pub rrv3_drop_circuit: u64,
    pub rrv3_drop_budget: u64,

    pub outbox_len: u64,
    pub outbox_bytes: u64,

    pub p2p_new_block_received_total: u64,
    pub p2p_new_block_applied_total: u64,
    pub p2p_new_block_deferred_total: u64,
    pub p2p_new_block_rejected_permanent_total: u64,
    pub p2p_new_block_rejected_transient_total: u64,
    pub p2p_deferred_block_queue_size: u64,
    pub p2p_deferred_block_retry_total: u64,

    pub ft_api_token_reads: u64,
    pub ft_api_balance_reads: u64,
    pub ft_api_allowance_reads: u64,
    pub ft_api_frozen_reads: u64,
    pub ft_api_metrics_reads: u64,

    pub nft_api_collection_reads: u64,
    pub nft_api_token_reads: u64,
    pub nft_api_owner_of_reads: u64,
    pub nft_api_approval_reads: u64,
    pub nft_api_operator_approval_reads: u64,
    pub nft_api_wallet_reads: u64,
    pub nft_api_owner_collection_reads: u64,
    pub nft_api_collection_token_reads: u64,
    pub nft_api_metrics_reads: u64,

    pub cognitive_registry_object_reads: u64,
    pub cognitive_registry_claim_reads: u64,
    pub cognitive_registry_status_reads: u64,
    pub cognitive_registry_events_reads: u64,
    pub cognitive_registry_meta_reads: u64,
    pub cognitive_tx_applied_total: u64,
    pub cognitive_tx_rejected_total: u64,
    pub cognitive_registry_entries_total: u64,
    pub cognitive_registry_contested_total: u64,
    pub cognitive_registry_revoked_total: u64,
    pub cognitive_registry_superseded_total: u64,

    pub liveness_override_total: u64,
    pub liveness_override_validator_set_total: u64,
    pub liveness_override_committee_total: u64,
    pub downtime_jail_skipped_below_quorum_total: u64,

    pub liveness_validator_set_active_current: u64,
    pub liveness_validator_set_effective_current: u64,
    pub liveness_validator_set_non_revoked_current: u64,
    pub liveness_validator_set_quorum_current: u64,
    pub liveness_validator_set_override_active_current: u64,

    pub liveness_committee_active_members_current: u64,
    pub liveness_committee_effective_members_current: u64,
    pub liveness_committee_non_revoked_members_current: u64,
    pub liveness_committee_active_stake_current: u64,
    pub liveness_committee_effective_stake_current: u64,
    pub liveness_committee_quorum_stake_current: u64,
    pub liveness_committee_override_active_current: u64,
}

pub fn snapshot() -> PerfSnapshot {
    let mm = m();

    let (api_wait_p99, api_wait_avg, api_hold_p99, api_hold_avg) = {
        let w = mm.api_wait.lock().ok();
        let h = mm.api_hold.lock().ok();
        let w_p99 = w.as_ref().map(|x| x.p99_us()).unwrap_or(0);
        let w_avg = w.as_ref().map(|x| x.avg_us()).unwrap_or(0);
        let h_p99 = h.as_ref().map(|x| x.p99_us()).unwrap_or(0);
        let h_avg = h.as_ref().map(|x| x.avg_us()).unwrap_or(0);
        (w_p99, w_avg, h_p99, h_avg)
    };

    let (ch_wait_p99, ch_wait_avg, ch_hold_p99, ch_hold_avg) = {
        let w = mm.chain_wait.lock().ok();
        let h = mm.chain_hold.lock().ok();
        let w_p99 = w.as_ref().map(|x| x.p99_us()).unwrap_or(0);
        let w_avg = w.as_ref().map(|x| x.avg_us()).unwrap_or(0);
        let h_p99 = h.as_ref().map(|x| x.p99_us()).unwrap_or(0);
        let h_avg = h.as_ref().map(|x| x.avg_us()).unwrap_or(0);
        (w_p99, w_avg, h_p99, h_avg)
    };

    PerfSnapshot {
        since_unix: mm.start_unix.load(Ordering::Relaxed),

        lock_api_wait_p99_us: api_wait_p99,
        lock_api_wait_avg_us: api_wait_avg,
        lock_api_hold_p99_us: api_hold_p99,
        lock_api_hold_avg_us: api_hold_avg,

        lock_chain_wait_p99_us: ch_wait_p99,
        lock_chain_wait_avg_us: ch_wait_avg,
        lock_chain_hold_p99_us: ch_hold_p99,
        lock_chain_hold_avg_us: ch_hold_avg,

        rrv3_inflight: mm.rrv3_inflight.load(Ordering::Relaxed),
        rrv3_backlog_ratio_ppm: mm.rrv3_backlog_ratio_ppm.load(Ordering::Relaxed),
        rrv3_served: mm.rrv3_served.load(Ordering::Relaxed),
        rrv3_cache_hit: mm.rrv3_cache_hit.load(Ordering::Relaxed),

        rrv3_drop_decode: mm.rrv3_drop_decode.load(Ordering::Relaxed),
        rrv3_drop_oversize: mm.rrv3_drop_oversize.load(Ordering::Relaxed),
        rrv3_drop_rate: mm.rrv3_drop_rate.load(Ordering::Relaxed),
        rrv3_drop_inflight: mm.rrv3_drop_inflight.load(Ordering::Relaxed),
        rrv3_drop_semaphore: mm.rrv3_drop_semaphore.load(Ordering::Relaxed),
        rrv3_drop_circuit: mm.rrv3_drop_circuit.load(Ordering::Relaxed),
        rrv3_drop_budget: mm.rrv3_drop_budget.load(Ordering::Relaxed),

        outbox_len: mm.outbox_len.load(Ordering::Relaxed),
        outbox_bytes: mm.outbox_bytes.load(Ordering::Relaxed),

        p2p_new_block_received_total: mm.p2p_new_block_received_total.load(Ordering::Relaxed),
        p2p_new_block_applied_total: mm.p2p_new_block_applied_total.load(Ordering::Relaxed),
        p2p_new_block_deferred_total: mm.p2p_new_block_deferred_total.load(Ordering::Relaxed),
        p2p_new_block_rejected_permanent_total: mm
            .p2p_new_block_rejected_permanent_total
            .load(Ordering::Relaxed),
        p2p_new_block_rejected_transient_total: mm
            .p2p_new_block_rejected_transient_total
            .load(Ordering::Relaxed),
        p2p_deferred_block_queue_size: mm.p2p_deferred_block_queue_size.load(Ordering::Relaxed),
        p2p_deferred_block_retry_total: mm.p2p_deferred_block_retry_total.load(Ordering::Relaxed),

        ft_api_token_reads: mm.ft_api_token_reads.load(Ordering::Relaxed),
        ft_api_balance_reads: mm.ft_api_balance_reads.load(Ordering::Relaxed),
        ft_api_allowance_reads: mm.ft_api_allowance_reads.load(Ordering::Relaxed),
        ft_api_frozen_reads: mm.ft_api_frozen_reads.load(Ordering::Relaxed),
        ft_api_metrics_reads: mm.ft_api_metrics_reads.load(Ordering::Relaxed),

        nft_api_collection_reads: mm.nft_api_collection_reads.load(Ordering::Relaxed),
        nft_api_token_reads: mm.nft_api_token_reads.load(Ordering::Relaxed),
        nft_api_owner_of_reads: mm.nft_api_owner_of_reads.load(Ordering::Relaxed),
        nft_api_approval_reads: mm.nft_api_approval_reads.load(Ordering::Relaxed),
        nft_api_operator_approval_reads: mm.nft_api_operator_approval_reads.load(Ordering::Relaxed),
        nft_api_wallet_reads: mm.nft_api_wallet_reads.load(Ordering::Relaxed),
        nft_api_owner_collection_reads: mm.nft_api_owner_collection_reads.load(Ordering::Relaxed),
        nft_api_collection_token_reads: mm.nft_api_collection_token_reads.load(Ordering::Relaxed),
        nft_api_metrics_reads: mm.nft_api_metrics_reads.load(Ordering::Relaxed),

        cognitive_registry_object_reads: mm.cognitive_registry_object_reads.load(Ordering::Relaxed),
        cognitive_registry_claim_reads: mm.cognitive_registry_claim_reads.load(Ordering::Relaxed),
        cognitive_registry_status_reads: mm.cognitive_registry_status_reads.load(Ordering::Relaxed),
        cognitive_registry_events_reads: mm.cognitive_registry_events_reads.load(Ordering::Relaxed),
        cognitive_registry_meta_reads: mm.cognitive_registry_meta_reads.load(Ordering::Relaxed),
        cognitive_tx_applied_total: mm.cognitive_tx_applied_total.load(Ordering::Relaxed),
        cognitive_tx_rejected_total: mm.cognitive_tx_rejected_total.load(Ordering::Relaxed),
        cognitive_registry_entries_total: mm
            .cognitive_registry_entries_total
            .load(Ordering::Relaxed),
        cognitive_registry_contested_total: mm
            .cognitive_registry_contested_total
            .load(Ordering::Relaxed),
        cognitive_registry_revoked_total: mm
            .cognitive_registry_revoked_total
            .load(Ordering::Relaxed),
        cognitive_registry_superseded_total: mm
            .cognitive_registry_superseded_total
            .load(Ordering::Relaxed),

        liveness_override_total: mm.liveness_override_total.load(Ordering::Relaxed),
        liveness_override_validator_set_total: mm
            .liveness_override_validator_set_total
            .load(Ordering::Relaxed),
        liveness_override_committee_total: mm
            .liveness_override_committee_total
            .load(Ordering::Relaxed),
        downtime_jail_skipped_below_quorum_total: mm
            .downtime_jail_skipped_below_quorum_total
            .load(Ordering::Relaxed),

        liveness_validator_set_active_current: mm
            .liveness_validator_set_active_current
            .load(Ordering::Relaxed),
        liveness_validator_set_effective_current: mm
            .liveness_validator_set_effective_current
            .load(Ordering::Relaxed),
        liveness_validator_set_non_revoked_current: mm
            .liveness_validator_set_non_revoked_current
            .load(Ordering::Relaxed),
        liveness_validator_set_quorum_current: mm
            .liveness_validator_set_quorum_current
            .load(Ordering::Relaxed),
        liveness_validator_set_override_active_current: mm
            .liveness_validator_set_override_active_current
            .load(Ordering::Relaxed),

        liveness_committee_active_members_current: mm
            .liveness_committee_active_members_current
            .load(Ordering::Relaxed),
        liveness_committee_effective_members_current: mm
            .liveness_committee_effective_members_current
            .load(Ordering::Relaxed),
        liveness_committee_non_revoked_members_current: mm
            .liveness_committee_non_revoked_members_current
            .load(Ordering::Relaxed),
        liveness_committee_active_stake_current: mm
            .liveness_committee_active_stake_current
            .load(Ordering::Relaxed),
        liveness_committee_effective_stake_current: mm
            .liveness_committee_effective_stake_current
            .load(Ordering::Relaxed),
        liveness_committee_quorum_stake_current: mm
            .liveness_committee_quorum_stake_current
            .load(Ordering::Relaxed),
        liveness_committee_override_active_current: mm
            .liveness_committee_override_active_current
            .load(Ordering::Relaxed),
    }
}
