use crate::governance::MempoolPolicyDelta;
use crate::nft;
use crate::security_policy::SecurityPolicy;
use crate::staking;
use crate::transaction::Transaction;
use serde::Serialize;
use serde_json;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Entry della Mempool: TX + timestamp di arrivo + size stimata in byte
#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Transaction,
    received_at: Instant,
    size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct MempoolLimits {
    pub max_size: usize,
    pub max_tx_per_sender: usize,
    pub max_bytes: usize,
    pub tx_ttl: Duration,
    /// Token bucket per-sender: capacità massima (burst).
    pub sender_bucket_capacity: u64,
    /// Token bucket per-sender: refill (token/secondo).
    pub sender_bucket_refill_per_sec: u64,
    /// Costo addizionale in token per 512B di payload stimato (oltre al costo base=1).
    pub sender_bucket_cost_per_512b: u64,
    /// Numero massimo di sender tracciati (anti-OOM da spam di indirizzi).
    pub sender_bucket_max_entries: usize,
    /// TTL di inattività per ripulire lo stato rate-limit per sender.
    pub sender_bucket_idle_ttl: Duration,
    /// Backoff deterministico: cooldown base (raddoppia per strike).
    pub sender_cooldown_base: Duration,
    /// Backoff deterministico: cooldown massimo (cap).
    pub sender_cooldown_max: Duration,
    /// Backoff deterministico: massimo esponente (2^exp).
    pub sender_cooldown_exp_max: u32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MempoolDropCounters {
    pub accepted_total: u64,
    pub drop_coinbase_total: u64,
    pub drop_fee_too_low_total: u64,
    pub drop_duplicate_hash_total: u64,
    pub drop_sender_cap_total: u64,
    pub drop_low_priority_total: u64,
    pub drop_rate_limited_total: u64,
    pub drop_hash_mismatch_total: u64,
    pub drop_stake_invalid_total: u64,
    pub drop_nft_invalid_total: u64,
    pub drop_oversize_total: u64,
    pub evicted_total: u64,
    pub expired_pruned_total: u64,
    pub pruned_fee_too_low_total: u64,
    pub sender_bucket_evicted_total: u64,
}

impl MempoolDropCounters {
    pub fn drop_total(&self) -> u64 {
        self.drop_coinbase_total
            .saturating_add(self.drop_fee_too_low_total)
            .saturating_add(self.drop_duplicate_hash_total)
            .saturating_add(self.drop_sender_cap_total)
            .saturating_add(self.drop_low_priority_total)
            .saturating_add(self.drop_rate_limited_total)
            .saturating_add(self.drop_hash_mismatch_total)
            .saturating_add(self.drop_stake_invalid_total)
            .saturating_add(self.drop_nft_invalid_total)
            .saturating_add(self.drop_oversize_total)
            .saturating_add(self.pruned_fee_too_low_total)
    }
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_size: 20_000,
            max_tx_per_sender: 256,
            max_bytes: 67_108_864,
            tx_ttl: Duration::from_secs(21_600),
            sender_bucket_capacity: 10_000,
            sender_bucket_refill_per_sec: 5_000,
            sender_bucket_cost_per_512b: 1,
            sender_bucket_max_entries: 10_000,
            sender_bucket_idle_ttl: Duration::from_secs(15 * 60),
            sender_cooldown_base: Duration::from_millis(0),
            sender_cooldown_max: Duration::from_millis(0),
            sender_cooldown_exp_max: 0,
        }
    }
}
/// Mempool con priorità basata su fee-per-byte (Step 51-ready)
#[derive(Debug, Default)]
pub struct Mempool {
    txs: HashMap<String, MempoolEntry>,
    total_bytes: usize,
    limits: MempoolLimits,
    /// Base fee per TX (hint) per coerenza admission/ordering; aggiornabile dal chain head.
    base_fee_per_tx_hint: u64,
    /// Snapshot esplicito della SecurityPolicy usata per admission/pruning.
    min_fee_per_tx_policy: u64,
    min_fee_per_byte_policy: u64,
    /// Stato rate-limit per sender (token bucket + backoff).
    sender_buckets: HashMap<String, SenderBucket>,
    counters: MempoolDropCounters,
    /// Local-only throttle for repeated invalid coinbase submissions.
    /// Coinbase transactions are never valid mempool/gossip payloads; this only
    /// prevents a malformed peer/reorg path from turning a correct reject into
    /// log spam or CPU-visible work.
    last_coinbase_reject_log_at: Option<Instant>,
    coinbase_reject_log_suppressed: u64,
}

#[derive(Debug)]
pub struct FeeError {
    pub required_min_fee: u64,
    pub provided_max_fee: u64,
    pub tx_size_bytes: u64,
}

/// Rate limit per sender (anti-DoS): token bucket + backoff deterministico.
#[derive(Debug, Clone)]
struct SenderBucket {
    tokens: u64,
    last_refill: Instant,
    strikes: u32,
    cooldown_until: Option<Instant>,
    last_seen: Instant,
}

#[derive(Debug)]
struct SenderRateLimitError {
    cooldown_ms: u64,
    tokens_needed: u64,
    tokens_available: u64,
    strikes: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum MempoolAddResult {
    Accepted,
    HashMismatch {
        given_hash: String,
        expected_hash: String,
    },
    CoinbaseNotAllowed,
    StakeSyntaxInvalid {
        detail: String,
    },
    NftSyntaxInvalid {
        detail: String,
    },
    FeeTooLow {
        required_min_fee: u64,
        provided_max_fee: u64,
        tx_size_bytes: u64,
    },
    DuplicateHash {
        tx_hash: String,
    },
    Oversize {
        tx_size_bytes: usize,
        max_bytes: usize,
    },
    SenderRateLimited {
        cooldown_ms: u64,
        tokens_needed: u64,
        tokens_available: u64,
        strikes: u32,
    },
    SenderCap {
        sender: String,
        pending_for_sender: usize,
        max_tx_per_sender: usize,
    },
    LowPriority {
        score_new: f64,
        score_worst: f64,
        mempool_size: usize,
        mempool_total_bytes: usize,
        max_mempool_size: usize,
        max_mempool_bytes: usize,
    },
}

impl MempoolAddResult {
    pub fn accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

impl SenderBucket {
    fn new(now: Instant, capacity: u64) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            strikes: 0,
            cooldown_until: None,
            last_seen: now,
        }
    }
}

impl Mempool {
    /// Crea una nuova mempool vuota.
    pub fn new() -> Self {
        // Default esplicito per test/tool locali; il runtime di produzione deve usare from_security_policy(...)
        Self::from_security_policy(&SecurityPolicy::default())
    }

    pub fn from_security_policy(policy: &SecurityPolicy) -> Self {
        Self {
            txs: HashMap::new(),
            total_bytes: 0,
            limits: MempoolLimits::default(),
            base_fee_per_tx_hint: policy.min_fee_per_tx,
            min_fee_per_tx_policy: policy.min_fee_per_tx,
            min_fee_per_byte_policy: policy.min_fee_per_byte,
            sender_buckets: HashMap::new(),
            counters: MempoolDropCounters::default(),
            last_coinbase_reject_log_at: None,
            coinbase_reject_log_suppressed: 0,
        }
    }

    /// Svuota completamente la mempool: TX pendenti + stato rate-limit per sender.
    /// Mantiene invariati i limiti e il base_fee_per_tx_hint (hint non-consensus).
    pub fn clear(&mut self) {
        self.txs.clear();
        self.total_bytes = 0;
        self.sender_buckets.clear();
    }

    pub fn apply_governance_overrides(&mut self, delta: &MempoolPolicyDelta) {
        if let Some(v) = delta.max_mempool_size {
            self.limits.max_size = (v as usize).max(100);
        }
        if let Some(v) = delta.max_tx_per_sender {
            self.limits.max_tx_per_sender = (v as usize).max(1);
        }
        if let Some(v) = delta.max_mempool_bytes {
            self.limits.max_bytes = (v as usize).max(100_000);
        }
        if let Some(v) = delta.tx_ttl_secs {
            self.limits.tx_ttl = Duration::from_secs(v.max(60));
        }

        // Applica subito l'effetto dei nuovi limiti
        self.prune_expired();
        self.enforce_sender_caps_now(); // 👈 nuovo: cap per sender retroattivo
        self.enforce_caps_now(); // 👈 già ce l’hai: cap globali count/bytes
    }

    /// Aggiorna l'hint di base_fee_per_tx usato da mempool per admission/ordering.
    /// Nota: è *non-consensus* (mempool), ma deve essere coerente col chain head per ridurre fork / spam.
    pub fn set_base_fee_per_tx_hint(&mut self, base_fee_per_tx: u64) {
        self.base_fee_per_tx_hint = base_fee_per_tx;
        // Rimuovi TX che non coprono più i minimi (base fee o min_fee_per_byte).
        self.prune_underpriced_now();
        // Dopo prune, riapplica cap per stabilità (deterministico).
        self.enforce_sender_caps_now();
        self.enforce_caps_now();
    }

    fn fee_eligible_entry(
        min_fee_per_tx: u64,
        min_fee_per_byte: u64,
        base: u64,
        entry: &MempoolEntry,
    ) -> bool {
        let required_by_tx = std::cmp::max(min_fee_per_tx, base);
        let required_by_byte = min_fee_per_byte.saturating_mul((entry.size_bytes.max(1)) as u64);
        let required_min_fee = std::cmp::max(required_by_tx, required_by_byte);
        entry.tx.max_fee_per_tx >= required_min_fee
    }

    fn prune_underpriced_now(&mut self) {
        let min_fee_per_tx = self.min_fee_per_tx_policy;
        let min_fee_per_byte = self.min_fee_per_byte_policy;
        let base = self.base_fee_per_tx_hint;
        let before = self.txs.len();
        let mut new_total_bytes = 0usize;

        self.txs.retain(|_, entry| {
            let ok = Self::fee_eligible_entry(min_fee_per_tx, min_fee_per_byte, base, entry);
            if ok {
                new_total_bytes += entry.size_bytes;
            }
            ok
        });

        self.total_bytes = new_total_bytes;
        let pruned = before.saturating_sub(self.txs.len());
        if pruned > 0 {
            self.mark_pruned_fee_too_low(pruned);
        }
    }

    fn sender_bucket_cost_tokens(&self, size_bytes: usize) -> u64 {
        // costo base = 1 token, +k per ogni 512B (arrotondato per eccesso).
        let per = self.limits.sender_bucket_cost_per_512b.max(1);
        let blocks = (size_bytes.max(1) as u64).div_ceil(512);
        1 + blocks.saturating_sub(1).saturating_mul(per)
    }

    fn sender_has_pending_txs(&self, sender: &str) -> bool {
        self.txs.values().any(|e| e.tx.sender == sender)
    }

    fn enforce_sender_rate_limit(
        &mut self,
        sender: &str,
        size_bytes: usize,
    ) -> Result<(), SenderRateLimitError> {
        let now = Instant::now();

        // TTL idle + cap memoria hard per la tabella dei sender (anti-Sybil cache poisoning)
        self.prune_sender_buckets_idle();
        if !self.sender_buckets.contains_key(sender) {
            while self.sender_buckets.len() >= self.limits.sender_bucket_max_entries {
                let mut victim_key: Option<String> = None;
                let mut victim_has_pending = true;
                let mut victim_last_seen = now;
                for (k, st) in self.sender_buckets.iter() {
                    let has_pending = self.sender_has_pending_txs(k);
                    let better = match &victim_key {
                        None => true,
                        Some(_) => {
                            if victim_has_pending && !has_pending {
                                true
                            } else if victim_has_pending == has_pending {
                                let ord = st.last_seen.cmp(&victim_last_seen);
                                ord == Ordering::Less
                                    || (ord == Ordering::Equal && Some(k) < victim_key.as_ref())
                            } else {
                                false
                            }
                        }
                    };
                    if better {
                        victim_key = Some(k.clone());
                        victim_has_pending = has_pending;
                        victim_last_seen = st.last_seen;
                    }
                }
                if let Some(oldest_key) = victim_key {
                    self.sender_buckets.remove(&oldest_key);
                    self.mark_sender_bucket_evicted();
                } else {
                    break;
                }
            }
        }

        let cap = self.limits.sender_bucket_capacity.max(1);
        let refill_per_sec = self.limits.sender_bucket_refill_per_sec;
        let base_cd = self.limits.sender_cooldown_base;
        let max_cd = self.limits.sender_cooldown_max;
        let exp_max = self.limits.sender_cooldown_exp_max;

        let cost = self.sender_bucket_cost_tokens(size_bytes);

        let bucket = self
            .sender_buckets
            .entry(sender.to_string())
            .or_insert_with(|| SenderBucket::new(now, cap));

        bucket.last_seen = now;

        if let Some(until) = bucket.cooldown_until {
            if now < until {
                let cd_ms = until.duration_since(now).as_millis() as u64;
                return Err(SenderRateLimitError {
                    cooldown_ms: cd_ms,
                    tokens_needed: 0,
                    tokens_available: bucket.tokens,
                    strikes: bucket.strikes,
                });
            }
            bucket.cooldown_until = None;
        }

        if refill_per_sec > 0 {
            let elapsed = now.duration_since(bucket.last_refill);
            let add = elapsed.as_secs().saturating_mul(refill_per_sec);
            if add > 0 {
                bucket.tokens = std::cmp::min(cap, bucket.tokens.saturating_add(add));
                bucket.last_refill = now;
                if elapsed.as_secs() >= 30 {
                    bucket.strikes = bucket.strikes.saturating_sub(1);
                }
            }
        }

        if bucket.tokens < cost {
            bucket.strikes = bucket.strikes.saturating_add(1);
            let exp = std::cmp::min(bucket.strikes, exp_max);
            let shift = std::cmp::min(exp, 63);
            let mult = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
            let mult32: u32 = if mult > u32::MAX as u64 {
                u32::MAX
            } else {
                mult as u32
            };
            let mut cd = base_cd.saturating_mul(mult32);
            if cd > max_cd {
                cd = max_cd;
            }
            bucket.cooldown_until = Some(now + cd);

            return Err(SenderRateLimitError {
                cooldown_ms: cd.as_millis() as u64,
                tokens_needed: cost,
                tokens_available: bucket.tokens,
                strikes: bucket.strikes,
            });
        }

        bucket.tokens = bucket.tokens.saturating_sub(cost);
        Ok(())
    }

    fn prune_sender_buckets_idle(&mut self) {
        let now = Instant::now();
        let idle_ttl = self.limits.sender_bucket_idle_ttl;
        if idle_ttl.is_zero() {
            return;
        }

        // Mantieni bucket solo per sender che hanno TX pendenti o che sono stati visti di recente.
        let mut has_pending: HashMap<String, bool> = HashMap::new();
        for e in self.txs.values() {
            has_pending.insert(e.tx.sender.clone(), true);
        }

        self.sender_buckets.retain(|sender, b| {
            if has_pending.get(sender).copied().unwrap_or(false) {
                return true;
            }
            now.duration_since(b.last_seen) <= idle_ttl
        });
    }

    fn cmp_priority_fee_per_byte_asc(
        a_hash: &str,
        a_max_fee: u64,
        a_size: usize,
        b_hash: &str,
        b_max_fee: u64,
        b_size: usize,
        base_fee_per_tx: u64,
    ) -> Ordering {
        let a_fee = a_max_fee.saturating_sub(base_fee_per_tx) as u128;
        let b_fee = b_max_fee.saturating_sub(base_fee_per_tx) as u128;
        let a_size = (a_size.max(1)) as u128;
        let b_size = (b_size.max(1)) as u128;

        let left = a_fee.saturating_mul(b_size);
        let right = b_fee.saturating_mul(a_size);

        if left != right {
            left.cmp(&right)
        } else {
            a_hash.cmp(b_hash)
        }
    }

    fn cmp_priority_fee_per_byte_desc(
        a_hash: &str,
        a_max_fee: u64,
        a_size: usize,
        b_hash: &str,
        b_max_fee: u64,
        b_size: usize,
        base_fee_per_tx: u64,
    ) -> Ordering {
        let ord = Self::cmp_priority_fee_per_byte_asc(
            a_hash,
            a_max_fee,
            a_size,
            b_hash,
            b_max_fee,
            b_size,
            base_fee_per_tx,
        );
        if ord == Ordering::Equal {
            ord
        } else {
            ord.reverse()
        }
    }

    fn score_priority_fee_per_byte(
        max_fee_per_tx: u64,
        size_bytes: usize,
        base_fee_per_tx: u64,
    ) -> f64 {
        let size = size_bytes.max(1) as f64;
        let prio = max_fee_per_tx.saturating_sub(base_fee_per_tx).max(1) as f64;
        prio / size
    }

    /// Enforce retroattivo: se un sender ha più TX del limite, evict le peggiori (per priority_score).
    /// Enforce retroattivo: se un sender ha più TX del limite, evict le peggiori (per priority_fee-per-byte).
    fn enforce_sender_caps_now(&mut self) {
        let cap = self.limits.max_tx_per_sender;
        if cap == 0 {
            return;
        }

        loop {
            // Conta quante TX ha ogni sender
            let mut counts: HashMap<String, usize> = HashMap::new();
            for entry in self.txs.values() {
                *counts.entry(entry.tx.sender.clone()).or_insert(0) += 1;
            }

            // Trova un sender fuori cap
            let offender = counts.into_iter().find(|(_, c)| *c > cap).map(|(s, _)| s);
            let Some(sender) = offender else { break };

            let base = self.base_fee_per_tx_hint;
            // Evict una TX (la peggiore) di quel sender
            let worst_hash = self
                .txs
                .iter()
                .filter(|(_, e)| e.tx.sender == sender)
                .min_by(|(ha, a), (hb, b)| {
                    Self::cmp_priority_fee_per_byte_asc(
                        ha,
                        a.tx.max_fee_per_tx,
                        a.size_bytes,
                        hb,
                        b.tx.max_fee_per_tx,
                        b.size_bytes,
                        base,
                    )
                })
                .map(|(h, _)| h.clone());

            if let Some(h) = worst_hash {
                if let Some(removed) = self.txs.remove(&h) {
                    self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);
                }
            } else {
                break;
            }
        }
    }

    /// Enforce retroattivo: rientra nei cap globali (count/bytes),
    /// evictando le TX peggiori per priority_score finché siamo sotto i limiti.
    /// Enforce retroattivo: se superiamo i cap globali (count/bytes), evictando le TX peggiori per priority_fee-per-byte.
    fn enforce_caps_now(&mut self) {
        loop {
            let over_count = self.txs.len() > self.limits.max_size;
            let over_bytes = self.total_bytes > self.limits.max_bytes;

            if !over_count && !over_bytes {
                break;
            }

            let base = self.base_fee_per_tx_hint;
            let worst_hash = self
                .txs
                .iter()
                .min_by(|(ha, a), (hb, b)| {
                    Self::cmp_priority_fee_per_byte_asc(
                        ha,
                        a.tx.max_fee_per_tx,
                        a.size_bytes,
                        hb,
                        b.tx.max_fee_per_tx,
                        b.size_bytes,
                        base,
                    )
                })
                .map(|(h, _)| h.clone());

            let Some(h) = worst_hash else {
                self.total_bytes = 0;
                break;
            };

            if let Some(removed) = self.txs.remove(&h) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);
                self.mark_evicted();
            }
        }
    }

    /// Stima della dimensione in byte di una TX.
    /// Per ora usiamo la serializzazione JSON; è sufficiente per policy anti-DoS.
    fn estimate_tx_size_bytes(tx: &Transaction) -> usize {
        match serde_json::to_vec(tx) {
            Ok(v) => v.len().max(1),
            Err(_) => 250, // fallback conservativo
        }
    }

    /// Step 53 – Controlla che la TX rispetti i minimi di sicurezza.
    /// Usa i parametri da SecurityPolicy (min_fee_per_tx / min_fee_per_byte).
    pub fn enforce_min_fee_for_tx(tx: &Transaction) -> Result<(), FeeError> {
        // Compat legacy/test-only: default esplicito, non globale implicito.
        Self::enforce_min_fee_for_tx_with_policy(tx, &SecurityPolicy::default(), 0)
    }

    /// Variante coerente con base_fee_per_tx (hint) per admission/ordering end-to-end.
    /// Compat legacy/test-only: default esplicito, non globale implicito.
    pub fn enforce_min_fee_for_tx_with_base_fee(
        tx: &Transaction,
        base_fee_per_tx: u64,
    ) -> Result<(), FeeError> {
        Self::enforce_min_fee_for_tx_with_policy(tx, &SecurityPolicy::default(), base_fee_per_tx)
    }

    /// Variante fully-explicit basata su floor runtime già risolti dal callsite.
    pub fn enforce_min_fee_for_tx_with_fee_floors(
        tx: &Transaction,
        min_fee_per_tx: u64,
        min_fee_per_byte: u64,
        base_fee_per_tx: u64,
    ) -> Result<(), FeeError> {
        let tx_size_bytes = Self::estimate_tx_size_bytes(tx) as u64;
        let required_by_tx = std::cmp::max(min_fee_per_tx, base_fee_per_tx);
        let required_by_byte = min_fee_per_byte.saturating_mul(tx_size_bytes);
        let required_min_fee = std::cmp::max(required_by_tx, required_by_byte);
        let provided = tx.max_fee_per_tx;
        if provided < required_min_fee {
            Err(FeeError {
                required_min_fee,
                provided_max_fee: provided,
                tx_size_bytes,
            })
        } else {
            Ok(())
        }
    }

    pub fn enforce_min_fee_for_tx_with_policy(
        tx: &Transaction,
        policy: &SecurityPolicy,
        base_fee_per_tx: u64,
    ) -> Result<(), FeeError> {
        Self::enforce_min_fee_for_tx_with_fee_floors(
            tx,
            policy.min_fee_per_tx,
            policy.min_fee_per_byte,
            base_fee_per_tx,
        )
    }

    /// Torna il numero di TX attualmente in mempool.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Ritorna true se la mempool è vuota.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
        // oppure: self.len() == 0
    }

    /// Numero di TX ancora eleggibili rispetto ai floor fee correnti della mempool.
    /// Telemetria locale/non-consensus: il controller fee la usa per evitare di
    /// trattare backlog sotto-fee o stale come domanda pagante reale.
    pub fn fee_eligible_len(&self) -> usize {
        let min_fee_per_tx = self.min_fee_per_tx_policy;
        let min_fee_per_byte = self.min_fee_per_byte_policy;
        let base = self.base_fee_per_tx_hint;
        self.txs
            .values()
            .filter(|entry| Self::fee_eligible_entry(min_fee_per_tx, min_fee_per_byte, base, entry))
            .count()
    }

    /// Calcola i byte totali stimati in mempool.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn drop_counters_snapshot(&self) -> MempoolDropCounters {
        self.counters.clone()
    }

    /// Records a fee-low rejection performed by a gateway/API path before the
    /// transaction reaches normal mempool admission. This is local telemetry
    /// only: it does not affect consensus state, tx ordering, balances, or
    /// canonical block validity. The adaptive fee controller consumes this
    /// counter as ingress pressure on the next block observation.
    pub fn record_fee_low_rejection_from_gateway(&mut self) {
        self.mark_drop_fee_too_low();
    }

    fn mark_drop_coinbase(&mut self) {
        self.counters.drop_coinbase_total = self.counters.drop_coinbase_total.saturating_add(1);
    }

    /// Log invalid coinbase mempool submissions at a bounded rate.
    ///
    /// The reject itself is intentionally fast and unconditional. The log is
    /// telemetry only; it must never become the hot path when a buggy peer,
    /// rollback, or replay path repeatedly attempts to submit coinbase TXs.
    fn maybe_log_coinbase_reject_throttled(&mut self) {
        const COINBASE_REJECT_LOG_EVERY: Duration = Duration::from_secs(30);
        let now = Instant::now();
        let should_log = self
            .last_coinbase_reject_log_at
            .map(|last| now.duration_since(last) >= COINBASE_REJECT_LOG_EVERY)
            .unwrap_or(true);

        if should_log {
            let suppressed = self.coinbase_reject_log_suppressed;
            self.coinbase_reject_log_suppressed = 0;
            self.last_coinbase_reject_log_at = Some(now);
            eprintln!(
                "⚠️ [MEMPOOL] TX rifiutata: coinbase non ammessa in mempool event=mempool_coinbase_rejected action=drop_fast suppressed={}",
                suppressed
            );
        } else {
            self.coinbase_reject_log_suppressed =
                self.coinbase_reject_log_suppressed.saturating_add(1);
        }
    }
    fn mark_drop_fee_too_low(&mut self) {
        self.counters.drop_fee_too_low_total =
            self.counters.drop_fee_too_low_total.saturating_add(1);
    }
    fn mark_drop_duplicate_hash(&mut self) {
        self.counters.drop_duplicate_hash_total =
            self.counters.drop_duplicate_hash_total.saturating_add(1);
    }
    fn mark_drop_sender_cap(&mut self) {
        self.counters.drop_sender_cap_total = self.counters.drop_sender_cap_total.saturating_add(1);
    }
    fn mark_drop_low_priority(&mut self) {
        self.counters.drop_low_priority_total =
            self.counters.drop_low_priority_total.saturating_add(1);
    }
    fn mark_drop_rate_limited(&mut self) {
        self.counters.drop_rate_limited_total =
            self.counters.drop_rate_limited_total.saturating_add(1);
    }
    fn mark_drop_hash_mismatch(&mut self) {
        self.counters.drop_hash_mismatch_total =
            self.counters.drop_hash_mismatch_total.saturating_add(1);
    }
    fn mark_drop_stake_invalid(&mut self) {
        self.counters.drop_stake_invalid_total =
            self.counters.drop_stake_invalid_total.saturating_add(1);
    }
    fn mark_drop_nft_invalid(&mut self) {
        self.counters.drop_nft_invalid_total =
            self.counters.drop_nft_invalid_total.saturating_add(1);
    }
    fn mark_drop_oversize(&mut self) {
        self.counters.drop_oversize_total = self.counters.drop_oversize_total.saturating_add(1);
    }
    fn mark_accepted(&mut self) {
        self.counters.accepted_total = self.counters.accepted_total.saturating_add(1);
    }
    fn mark_evicted(&mut self) {
        self.counters.evicted_total = self.counters.evicted_total.saturating_add(1);
    }
    fn mark_expired_pruned(&mut self, n: usize) {
        self.counters.expired_pruned_total =
            self.counters.expired_pruned_total.saturating_add(n as u64);
    }
    fn mark_pruned_fee_too_low(&mut self, n: usize) {
        self.counters.pruned_fee_too_low_total = self
            .counters
            .pruned_fee_too_low_total
            .saturating_add(n as u64);
    }
    fn mark_sender_bucket_evicted(&mut self) {
        self.counters.sender_bucket_evicted_total =
            self.counters.sender_bucket_evicted_total.saturating_add(1);
    }

    pub fn limits_snapshot(&self) -> (usize, usize, usize, u64) {
        (
            self.limits.max_size,
            self.limits.max_tx_per_sender,
            self.limits.max_bytes,
            self.limits.tx_ttl.as_secs(),
        )
    }

    /// Snapshot esplicita dei floor fee runtime usati da admission/pruning.
    /// Ritorna: (min_fee_per_tx_policy, min_fee_per_byte_policy, base_fee_per_tx_hint)
    pub fn fee_policy_snapshot(&self) -> (u64, u64, u64) {
        (
            self.min_fee_per_tx_policy,
            self.min_fee_per_byte_policy,
            self.base_fee_per_tx_hint,
        )
    }

    /// Ritorna una snapshot di tutte le TX (per API/debug).
    pub fn get_all(&self) -> Vec<Transaction> {
        self.txs.values().map(|entry| entry.tx.clone()).collect()
    }

    /// Ritorna una snapshot bounded delle TX per endpoint pubblici/UI.
    /// Evita di clonare e serializzare l'intera mempool sotto pressione.
    pub fn get_limited(&self, limit: usize) -> Vec<Transaction> {
        self.txs
            .values()
            .take(limit)
            .map(|entry| entry.tx.clone())
            .collect()
    }

    /// Pulisce le TX scadute in base al TTL.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let mut new_total_bytes = 0usize;
        let mut removed_count = 0usize;

        self.txs.retain(|_, entry| {
            let alive = now.duration_since(entry.received_at) <= self.limits.tx_ttl;
            if alive {
                new_total_bytes += entry.size_bytes;
            } else {
                removed_count = removed_count.saturating_add(1);
            }
            alive
        });

        self.total_bytes = new_total_bytes;
        if removed_count > 0 {
            self.mark_expired_pruned(removed_count);
        }

        self.prune_sender_buckets_idle();
    }

    /// Aggiunge una TX alla mempool se passa tutti i controlli.
    pub fn add_detailed(&mut self, mut tx: Transaction) -> MempoolAddResult {
        // V187 hardening: coinbase transactions are consensus block rewards, not
        // mempool/gossip payloads. Reject them before pruning, hashing, sender
        // accounting, or fee work so a repeated malformed path cannot create a
        // livelock/log-spam loop.
        if tx.is_coinbase {
            self.mark_drop_coinbase();
            self.maybe_log_coinbase_reject_throttled();
            return MempoolAddResult::CoinbaseNotAllowed;
        }

        // 1) Prima di tutto: pulisci le TX scadute
        self.prune_expired();

        // 🧷 HARDENING (world-grade): txid coerente obbligatorio.
        // - Se la TX è stata costruita localmente e l'hash è vuoto, lo calcoliamo.
        // - Se l'hash è presente ma incoerente => rifiutiamo (tampering/bug).
        if tx.hash.is_empty() {
            tx.hash = tx.calculate_hash();
        } else {
            let expected = tx.calculate_hash();
            if tx.hash != expected {
                eprintln!(
                    "⚠️ [MEMPOOL] TX rifiutata: hash incoerente (given={} expected={})",
                    tx.hash, expected
                );
                self.mark_drop_hash_mismatch();
                return MempoolAddResult::HashMismatch {
                    given_hash: tx.hash.clone(),
                    expected_hash: expected,
                };
            }
        }

        // Firewall STAKE receiver: evita burn/lock involontari
        if let Err(e) = staking::validate_stake_tx_syntax(&tx) {
            eprintln!(
                "⚠️ [MEMPOOL] TX rifiutata: STAKE memo/semantica invalida: {}",
                e
            );
            self.mark_drop_stake_invalid();
            return MempoolAddResult::StakeSyntaxInvalid { detail: e };
        }
        // Firewall NFT receiver: asset ops consensus-critical.
        if let Err(e) = nft::validate_nft_tx_syntax(&tx) {
            eprintln!(
                "⚠️ [MEMPOOL] TX rifiutata: NFT memo/semantica invalida: {}",
                e
            );
            self.mark_drop_nft_invalid();
            return MempoolAddResult::NftSyntaxInvalid { detail: e };
        }

        // 1bis) Step 53 – firewall fee minimo di sicurezza
        if let Err(fee_err) =
            Self::enforce_min_fee_for_tx_with_base_fee(&tx, self.base_fee_per_tx_hint)
        {
            eprintln!(
            "⚠️ [MEMPOOL] TX rifiutata per fee troppo bassa: provided={} required={} (size={} B)",
            fee_err.provided_max_fee,
            fee_err.required_min_fee,
            fee_err.tx_size_bytes
        );
            self.mark_drop_fee_too_low();
            return MempoolAddResult::FeeTooLow {
                required_min_fee: fee_err.required_min_fee,
                provided_max_fee: fee_err.provided_max_fee,
                tx_size_bytes: fee_err.tx_size_bytes,
            };
        }

        // 2) Deduplica per hash (una sola volta)
        if self.txs.contains_key(&tx.hash) {
            self.mark_drop_duplicate_hash();
            return MempoolAddResult::DuplicateHash {
                tx_hash: tx.hash.clone(),
            };
        }

        let size_bytes = Self::estimate_tx_size_bytes(&tx);

        // 2bis) Se una singola TX supera il cap bytes, non potrà mai entrare
        if size_bytes > self.limits.max_bytes {
            eprintln!(
                "⚠️ [MEMPOOL] TX rifiutata: size_bytes={} supera max_bytes={}",
                size_bytes, self.limits.max_bytes
            );
            self.mark_drop_oversize();
            return MempoolAddResult::Oversize {
                tx_size_bytes: size_bytes,
                max_bytes: self.limits.max_bytes,
            };
        }

        // 2ter) Rate limit per sender (token bucket + backoff deterministico).
        // Non è consensus-critical, ma protegge RAM/CPU e riduce spam a basso costo.
        if let Err(r) = self.enforce_sender_rate_limit(&tx.sender, size_bytes) {
            eprintln!(
                "⚠️ [MEMPOOL] Rate limit sender={} cooldown_ms={} needed={} available={} strikes={} size_bytes={}",
                tx.sender, r.cooldown_ms, r.tokens_needed, r.tokens_available, r.strikes, size_bytes
            );
            self.mark_drop_rate_limited();
            return MempoolAddResult::SenderRateLimited {
                cooldown_ms: r.cooldown_ms,
                tokens_needed: r.tokens_needed,
                tokens_available: r.tokens_available,
                strikes: r.strikes,
            };
        }
        // 3) Limite per sender (anti-spam da un singolo indirizzo)
        let pending_for_sender = self
            .txs
            .values()
            .filter(|entry| entry.tx.sender == tx.sender)
            .count();

        if pending_for_sender >= self.limits.max_tx_per_sender {
            eprintln!(
                "⚠️ [MEMPOOL] Troppe TX pendenti per sender {} (cap={})",
                tx.sender, self.limits.max_tx_per_sender
            );
            self.mark_drop_sender_cap();
            return MempoolAddResult::SenderCap {
                sender: tx.sender.clone(),
                pending_for_sender,
                max_tx_per_sender: self.limits.max_tx_per_sender,
            };
        }

        // 4) Se siamo sotto tutti i limiti → inseriamo senza eviction
        let under_count_cap = self.txs.len() < self.limits.max_size;
        let under_bytes_cap = self.total_bytes.saturating_add(size_bytes) <= self.limits.max_bytes;

        if under_count_cap && under_bytes_cap {
            let entry = MempoolEntry {
                tx,
                received_at: Instant::now(),
                size_bytes,
            };
            self.total_bytes = self.total_bytes.saturating_add(entry.size_bytes);
            self.txs.insert(entry.tx.hash.clone(), entry);
            self.mark_accepted();
            return MempoolAddResult::Accepted;
        }

        // 5) Se superiamo i limiti → eviction basata su priority_score (fee-per-byte)
        let new_entry = MempoolEntry {
            tx,
            received_at: Instant::now(),
            size_bytes,
        };
        let new_score = Self::score_priority_fee_per_byte(
            new_entry.tx.max_fee_per_tx,
            new_entry.size_bytes,
            self.base_fee_per_tx_hint,
        );

        // Evict finché rientriamo nei limiti, ma SOLO se la nuova TX è migliore della peggiore
        while self.txs.len() >= self.limits.max_size
            || self.total_bytes.saturating_add(new_entry.size_bytes) > self.limits.max_bytes
        {
            let Some((worst_hash, worst_entry)) = self.txs.iter().min_by(|(ha, a), (hb, b)| {
                Self::cmp_priority_fee_per_byte_asc(
                    ha,
                    a.tx.max_fee_per_tx,
                    a.size_bytes,
                    hb,
                    b.tx.max_fee_per_tx,
                    b.size_bytes,
                    self.base_fee_per_tx_hint,
                )
            }) else {
                // Mempool vuota: usciamo dal loop e inseriamo sotto
                break;
            };

            let worst_score = Self::score_priority_fee_per_byte(
                worst_entry.tx.max_fee_per_tx,
                worst_entry.size_bytes,
                self.base_fee_per_tx_hint,
            );

            // Se la nuova non è meglio della peggiore → rifiuta (non facciamo eviction “a caso”)
            let cmp = Self::cmp_priority_fee_per_byte_asc(
                &new_entry.tx.hash,
                new_entry.tx.max_fee_per_tx,
                new_entry.size_bytes,
                worst_hash,
                worst_entry.tx.max_fee_per_tx,
                worst_entry.size_bytes,
                self.base_fee_per_tx_hint,
            );
            if cmp != Ordering::Greater {
                eprintln!(
                "⚠️ [MEMPOOL] TX rifiutata per bassa priorità (score_new={:.6}, score_worst={:.6}, size={}, total_bytes={}, cap_count={}, cap_bytes={})",
                new_score, worst_score, self.txs.len(), self.total_bytes, self.limits.max_size, self.limits.max_bytes
            );
                self.mark_drop_low_priority();
                return MempoolAddResult::LowPriority {
                    score_new: new_score,
                    score_worst: worst_score,
                    mempool_size: self.txs.len(),
                    mempool_total_bytes: self.total_bytes,
                    max_mempool_size: self.limits.max_size,
                    max_mempool_bytes: self.limits.max_bytes,
                };
            }

            // Rimuovi la peggiore e libera spazio
            let worst_hash = worst_hash.clone();
            if let Some(removed) = self.txs.remove(&worst_hash) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);
                self.mark_evicted();
            }
        }

        // Inserimento finale (a questo punto dovremmo rientrare nei cap, oppure mempool era vuota)
        self.total_bytes = self.total_bytes.saturating_add(new_entry.size_bytes);
        let hash = new_entry.tx.hash.clone();
        self.txs.insert(hash, new_entry);
        self.mark_accepted();
        MempoolAddResult::Accepted
    }

    /// Compat wrapper: true = accettata, false = rifiutata.
    pub fn add(&mut self, tx: Transaction) -> bool {
        self.add_detailed(tx).accepted()
    }

    /// Seleziona un batch di TX ordinate per priorità (fee-per-byte).
    ///
    /// 🔹 Non applica limiti per sender-per-blocco: quella logica vive nel block builder.
    pub fn get_batch(&self, max_items: usize) -> Vec<Transaction> {
        let mut entries: Vec<&MempoolEntry> = self.txs.values().collect();

        // Ordina per priority_score decrescente
        // Ordine canonico mempool: priority_fee-per-byte decrescente (tie-break su hash).
        let base = self.base_fee_per_tx_hint;
        entries.sort_by(|a, b| {
            Self::cmp_priority_fee_per_byte_desc(
                &a.tx.hash,
                a.tx.max_fee_per_tx,
                a.size_bytes,
                &b.tx.hash,
                b.tx.max_fee_per_tx,
                b.size_bytes,
                base,
            )
        });

        entries
            .into_iter()
            .take(max_items)
            .map(|entry| entry.tx.clone())
            .collect()
    }

    /// Rimuove un batch di TX (tipicamente quelle selezionate per il blocco).
    pub fn remove_batch(&mut self, txs: &[Transaction]) {
        for tx in txs {
            if let Some(entry) = self.txs.remove(&tx.hash) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
            }
        }
    }

    /// Trova l'ultimo nonce *in attesa* (nella mempool) per un indirizzo.
    pub fn get_last_nonce(&self, address: &str) -> u64 {
        let mut last_nonce = 0;
        for entry in self.txs.values() {
            if !entry.tx.is_coinbase && entry.tx.sender == address && entry.tx.nonce > last_nonce {
                last_nonce = entry.tx.nonce;
            }
        }
        last_nonce
    }

    /// Somma il valore già riservato in mempool per un sender:
    /// amount + max_fee_per_tx per ogni TX pendente non-coinbase.
    ///
    /// Questa metrica è volutamente fail-closed: usa il cap fee della TX,
    /// non la base fee corrente, per evitare overspend lato admission.
    pub fn sender_pending_reserved_total(&self, address: &str) -> u64 {
        self.txs
            .values()
            .filter(|entry| !entry.tx.is_coinbase && entry.tx.sender == address)
            .fold(0u64, |acc, entry| {
                let tx_reserved = entry.tx.amount.saturating_add(entry.tx.max_fee_per_tx);
                acc.saturating_add(tx_reserved)
            })
    }

    /// Numero di TX pendenti in mempool per il sender.
    pub fn sender_pending_count(&self, address: &str) -> usize {
        self.txs
            .values()
            .filter(|entry| !entry.tx.is_coinbase && entry.tx.sender == address)
            .count()
    }

    /// Saldo disponibile residuo dopo aver riservato tutte le TX pendenti del sender.
    pub fn sender_available_balance_after_pending(&self, address: &str, chain_balance: u64) -> u64 {
        chain_balance.saturating_sub(self.sender_pending_reserved_total(address))
    }

    /// Cerca una TX in mempool per (sender, nonce).
    /// Serve all'API per evitare conflitti di nonce nello stesso sender.
    pub fn find_by_sender_nonce(&self, sender: &str, nonce: u64) -> Option<&Transaction> {
        self.txs
            .values()
            .find(|entry| {
                !entry.tx.is_coinbase && entry.tx.sender == sender && entry.tx.nonce == nonce
            })
            .map(|entry| &entry.tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx(sender: &str, nonce: u64, amount: u64, max_fee_per_tx: u64) -> Transaction {
        Transaction {
            sender: sender.to_string(),
            receiver: sender.to_string(),
            amount,
            max_fee_per_tx,
            nonce,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: None,
        }
    }

    #[test]
    fn nft_invalid_memo_is_rejected_before_admission() {
        let mut mp = Mempool::new();
        let sender = crate::keyfmt::pk_b64_from_bytes(&[9u8; 32]);
        let mut tx = Transaction {
            sender,
            receiver: crate::nft::NFT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 100,
            nonce: 1,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(
                serde_json::json!({
                    "v": 1,
                    "ctx": crate::nft::CTX_NFT_MINT,
                    "op": "mint",
                    "collection_id": "1",
                    "to": crate::keyfmt::pk_b64_from_bytes(&[10u8; 32]),
                    "token_uri": "ipfs://token/1",
                    "metadata_hash_hex": "aa".repeat(32)
                })
                .to_string(),
            ),
        };
        tx.hash = tx.calculate_hash();
        match mp.add_detailed(tx) {
            MempoolAddResult::NftSyntaxInvalid { .. } => {}
            other => panic!("expected NftSyntaxInvalid, got {other:?}"),
        }
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.drop_counters_snapshot().drop_nft_invalid_total, 1);
    }

    #[test]
    fn sender_pending_reserved_total_is_fail_closed_sum_of_amount_plus_fee_cap() {
        let mut mp = Mempool::new();
        let sender = "sender-a";
        let mut tx1 = sample_tx(sender, 1, 10, 7);
        tx1.hash = tx1.calculate_hash();
        let mut tx2 = sample_tx(sender, 2, 5, 3);
        tx2.hash = tx2.calculate_hash();
        assert!(mp.add(tx1));
        assert!(mp.add(tx2));
        assert_eq!(mp.sender_pending_count(sender), 2);
        assert_eq!(mp.sender_pending_reserved_total(sender), 25);
        assert_eq!(mp.sender_available_balance_after_pending(sender, 40), 15);
    }

    #[test]
    fn sender_pending_helpers_ignore_other_senders_and_coinbase() {
        let mut mp = Mempool::new();
        let sender = "sender-a";
        let mut tx1 = sample_tx(sender, 1, 8, 2);
        tx1.hash = tx1.calculate_hash();
        let mut tx2 = sample_tx("sender-b", 1, 100, 50);
        tx2.hash = tx2.calculate_hash();
        let mut coinbase = sample_tx(sender, 99, 500, 0);
        coinbase.is_coinbase = true;
        coinbase.hash = coinbase.calculate_hash();
        assert!(mp.add(tx1));
        assert!(mp.add(tx2));
        assert!(!mp.add(coinbase));
        assert_eq!(mp.sender_pending_count(sender), 1);
        assert_eq!(mp.sender_pending_reserved_total(sender), 10);
    }

    #[test]
    fn mempool_coinbase_reject_is_fast_and_bounded_v187() {
        let mut mp = Mempool::new();
        let mut coinbase = sample_tx("COINBASE", 0, 500, 0);
        coinbase.is_coinbase = true;
        // Leave hash empty on purpose: a fast-path coinbase reject must not need
        // to calculate or normalize txid before returning.
        assert!(coinbase.hash.is_empty());

        let before = mp.drop_counters_snapshot();
        let result = mp.add_detailed(coinbase);
        assert!(matches!(result, MempoolAddResult::CoinbaseNotAllowed));
        assert_eq!(mp.len(), 0);

        let after = mp.drop_counters_snapshot();
        assert_eq!(
            after.drop_coinbase_total,
            before.drop_coinbase_total.saturating_add(1)
        );
        assert_eq!(after.expired_pruned_total, before.expired_pruned_total);
        assert_eq!(
            after.drop_hash_mismatch_total,
            before.drop_hash_mismatch_total
        );
        assert_eq!(after.accepted_total, before.accepted_total);
    }

    #[test]
    fn mempool_coinbase_reject_log_is_throttled_v188() {
        let mut mp = Mempool::new();
        let mut coinbase = sample_tx("COINBASE", 0, 500, 0);
        coinbase.is_coinbase = true;

        assert!(mp.last_coinbase_reject_log_at.is_none());
        assert_eq!(mp.coinbase_reject_log_suppressed, 0);

        assert!(matches!(
            mp.add_detailed(coinbase.clone()),
            MempoolAddResult::CoinbaseNotAllowed
        ));
        assert!(mp.last_coinbase_reject_log_at.is_some());
        assert_eq!(mp.coinbase_reject_log_suppressed, 0);

        assert!(matches!(
            mp.add_detailed(coinbase),
            MempoolAddResult::CoinbaseNotAllowed
        ));
        assert_eq!(mp.coinbase_reject_log_suppressed, 1);
        assert_eq!(mp.drop_counters_snapshot().drop_coinbase_total, 2);
    }

    #[test]
    fn gateway_fee_low_rejection_increments_fee_low_counter_without_admission() {
        let mut mp = Mempool::new();
        let before = mp.drop_counters_snapshot();
        assert_eq!(before.drop_fee_too_low_total, 0);
        assert_eq!(before.accepted_total, 0);
        assert_eq!(mp.len(), 0);

        mp.record_fee_low_rejection_from_gateway();

        let after = mp.drop_counters_snapshot();
        assert_eq!(after.drop_fee_too_low_total, 1);
        assert_eq!(after.accepted_total, 0);
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn base_fee_hint_update_prunes_underpriced_txs_and_counts_them_separately() {
        let mut mp = Mempool::new();

        let mut low = sample_tx("sender-low", 1, 1, 100);
        low.hash = low.calculate_hash();
        let mut high = sample_tx("sender-high", 1, 1, 300);
        high.hash = high.calculate_hash();

        assert!(mp.add(low));
        assert!(mp.add(high));
        assert_eq!(mp.len(), 2);
        assert_eq!(mp.fee_eligible_len(), 2);

        mp.set_base_fee_per_tx_hint(250);

        let counters = mp.drop_counters_snapshot();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.fee_eligible_len(), 1);
        assert_eq!(counters.pruned_fee_too_low_total, 1);
        assert_eq!(counters.drop_fee_too_low_total, 0);
    }
}
