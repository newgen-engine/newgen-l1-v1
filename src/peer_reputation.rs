use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::governance::ReputationPolicyDelta;
use crate::security_policy::SecurityPolicy;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Punteggio minimo/massimo e neutro
const SCORE_MIN: i32 = 0;
const SCORE_MAX: i32 = 1000;
const SCORE_NEUTRAL: i32 = 600;
const PENDING_WALLET_EVIDENCE_CAP: usize = 4096;

/// Helper interno: timestamp in secondi
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// Tier di fiducia: usato per ecosistemi 2/3
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TrustTier {
    #[default]
    Tier0,
    Tier1,
    Tier2,
    Tier3,
}

/// Stato reputazionale visto dal P2P (compatibile con il tuo p2p.rs)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReputationState {
    /// Peer “buono” / normale
    Good,
    /// Peer in “probation”: lo tieni d’occhio
    Probation,
    /// Peer bannato fino a una certa scadenza
    Banned { until: u64 },
}

#[derive(Debug, Clone, Copy)]
pub enum ReputationEvent {
    ValidTx,
    InvalidTx,
    ValidBlock,
    InvalidBlock,
    /// Generic legacy spam signal. Kept for compatibility, but treated as soft.
    Spam,
    /// Legacy topic-specific spam signals. Kept soft; hard faults must use typed events.
    SpamTooManyTx,
    SpamTooManyBlocks,
    /// Rate-limit/backpressure hit. Drop/throttle signal, not a hard reputation fault.
    RateLimitedSoft,
    /// Sustained rate-limit/flood after a bounded window. Still not recidive-amplified.
    RateLimitedSustained,
    /// Protocol-level spam or malformed/misrouted traffic. This is distinct from
    /// physiological rate-limit/backpressure and may be recidive-amplified.
    ProtocolSpam,
    Disconnect,
    Slashed,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReputationSummary {
    pub total_peers: u64,
    pub good: u64,
    pub probation: u64,
    pub banned: u64,
    pub avg_score: f64,
}

/// Metriche aggregate per API di sicurezza (Step 50A)
#[derive(Clone, Debug, Serialize)]
pub struct SecurityMetrics {
    pub total_peers: u64,
    pub good: u64,
    pub probation: u64,
    pub banned: u64,
    pub avg_score: f64,
    pub events_invalid_block: u64,
    pub events_spam: u64,
    pub events_disconnect: u64,
    pub events_slashed: u64,
    pub total_ban_events: u64,
    pub total_unban_events: u64,
    pub wallet_bound_peers: u64,
    pub wallet_subjects: u64,
    pub pending_wallet_evidence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunWalletBinding {
    pub wallet_pubkey: String,
    pub source: String,
    pub bound_at_secs: u64,
    pub last_confirmed_at_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunWalletReputationEvidence {
    #[serde(default)]
    pub claim_id: String,
    #[serde(default)]
    pub evidence_id: String,
    #[serde(default)]
    pub source_node_id: String,
    #[serde(default)]
    pub source_attester_pubkey: String,
    #[serde(default)]
    pub source_attester_sig_b64: String,
    pub wallet_pubkey: String,
    pub peer_id: String,
    pub event: String,
    pub score_before: i32,
    pub score_after: i32,
    pub applied_delta: i32,
    pub trust_tier: TrustTier,
    pub observed_at_secs: u64,
    pub binding_source: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunWalletReputationSummary {
    pub total_wallets: u64,
    pub total_bound_peers: u64,
    pub pending_evidence: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunWalletReputationView {
    pub wallet_pubkey: String,
    pub peers_bound: u64,
    pub avg_score: f64,
    pub best_tier: TrustTier,
    pub has_banned_peer: bool,
    pub last_active_secs: u64,
}

/// Configurazione del motore reputazione.
/// In futuro puoi caricarla da TOML; per ora puoi usare Default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Sotto questa soglia → Probation
    pub warn_threshold: i32,
    /// Sotto questa soglia → Banned
    pub ban_threshold: i32,

    /// Score iniziale dei peer nuovi e target neutro del decay.
    /// Deve essere derivato dalla SecurityPolicy runtime in produzione.
    pub initial_score: i32,

    /// Ogni quanti secondi facciamo decay verso lo score neutro
    pub decay_interval_secs: u64,

    /// Percentuale del delta da applicare verso il neutro ad ogni tick
    /// Esempio: 1.0 = 1% della distanza da 500 per tick
    pub decay_percent: f32,
    /// Passo minimo di decay (per evitare step troppo piccoli)
    pub min_decay_step: i32,

    /// Finestra di tempo per considerare recidiva (secondi)
    pub recidive_window_secs: u64,
    /// Moltiplicatore per recidiva (penalità cresce)
    pub recidive_multiplier: f32,

    /// Dopo quanti secondi di inattività il peer viene “raffreddato”
    pub inactive_demotion_secs: u64,

    /// Durata del ban (secondi)
    pub ban_duration_secs: u64,

    /// Pesi per gli eventi (derivati da SecurityPolicy::weights)
    pub delta_tx_valid: i32,
    pub delta_block_valid: i32,
    pub delta_tx_invalid: i32,
    pub delta_block_invalid: i32,

    /// Percorso file di persistenza
    pub persist_path: String,

    /// Max numero di peer tracciati in memoria (bounded map anti-OOM).
    pub max_tracked_peers: usize,
    /// Prune di peer non visti da troppo (secondi).
    pub prune_stale_after_secs: u64,
    /// Intervallo minimo tra persistenze su disco (secondi).
    pub persist_min_interval_secs: u64,

    /// Pesi extra governabili (prima erano hardcoded in on_event)
    pub delta_spam: i32,
    pub delta_rate_limited_soft: i32,
    pub delta_rate_limited_sustained: i32,
    pub delta_protocol_spam: i32,
    pub delta_disconnect: i32,
    pub delta_slashed: i32,

    /// TTL massimo di un binding peer->wallet confermato da telemetria runtime.
    /// Oltre questa finestra, il binding non viene più usato per emettere evidenze
    /// né per aggregare il run-plane wallet view, finché non viene riconfermato.
    pub wallet_binding_max_age_secs: u64,

    /// Identità locale diagnostica del run/node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_source_node_id: Option<String>,

    /// Attester canonico locale usato per rendere source-scoped gli evidence_id.
    /// Deve essere una identità on-chain verificabile (oggi: validator pubkey canonico).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_source_attester_pubkey: Option<String>,

    /// Seed della chiave di signing dell'attester locale usata per firmare le evidenze.
    #[serde(skip)]
    pub local_source_attester_signing_seed_32: Option<[u8; 32]>,

    /// (Opzionale ma utile) soglia "Good" separata dalla warn_threshold
    /// Nota: warn_threshold = probation_threshold (sotto = Probation)
    pub good_threshold: i32,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            // soglie
            good_threshold: 550, // >=550 => Good; coerente con base/new score 600
            warn_threshold: 500, // <=500 => Probation locale conservativa
            ban_threshold: 200,  // <=200 => Banned / hard quarantine
            initial_score: SCORE_NEUTRAL,

            // decay “vecchio stile”: ogni 5 minuti, ~1% della distanza, min 5 punti
            decay_interval_secs: 300, // 5 minuti
            decay_percent: 1.0,
            min_decay_step: 5,

            recidive_window_secs: 3600, // 1 ora
            recidive_multiplier: 2.0,
            inactive_demotion_secs: 30 * 24 * 3600, // 30 giorni
            ban_duration_secs: 24 * 3600,           // 1 giorno

            // Pesi di default equivalenti ai tuoi hardcoded
            delta_tx_valid: 1,
            delta_block_valid: 2,
            delta_tx_invalid: -10,
            delta_block_invalid: -40,

            // ✅ nuovi pesi (prima hardcoded in on_event). Generic spam and
            // rate-limit/backpressure stay soft; protocol spam is the typed hard path.
            delta_spam: -2,
            delta_rate_limited_soft: 0,
            delta_rate_limited_sustained: -10,
            delta_protocol_spam: -50,
            delta_disconnect: -1,
            delta_slashed: -50,
            wallet_binding_max_age_secs: 5 * 60,
            local_source_node_id: None,
            local_source_attester_pubkey: None,
            local_source_attester_signing_seed_32: None,

            persist_path: "reputation.json".to_string(),

            // bounded tracking + persistence policy
            max_tracked_peers: 50_000,
            prune_stale_after_secs: 7 * 24 * 3600,
            persist_min_interval_secs: 60,
        }
    }
}

impl ReputationConfig {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        const MAX_BAN_SECS: u64 = 60 * 60 * 24 * 30;
        const MAX_DECAY_INTERVAL_SECS: u64 = 60 * 60 * 24 * 365;
        const MAX_EVENT_ABS_WEIGHT: i32 = 10_000;

        if !(SCORE_MIN..=SCORE_MAX).contains(&self.initial_score) {
            return Err(format!(
                "initial_score fuori range {}..{}: {}",
                SCORE_MIN, SCORE_MAX, self.initial_score
            ));
        }
        if !(SCORE_MIN..=SCORE_MAX).contains(&self.good_threshold)
            || !(SCORE_MIN..=SCORE_MAX).contains(&self.warn_threshold)
            || !(SCORE_MIN..=SCORE_MAX).contains(&self.ban_threshold)
        {
            return Err(format!(
                "thresholds fuori range {}..{}: good={} probation={} banned={}",
                SCORE_MIN, SCORE_MAX, self.good_threshold, self.warn_threshold, self.ban_threshold
            ));
        }
        if !(self.good_threshold > self.warn_threshold && self.warn_threshold > self.ban_threshold)
        {
            return Err(format!(
                "soglie reputazione runtime non coerenti: require good_threshold > warn_threshold > ban_threshold, got good={} probation={} banned={}",
                self.good_threshold, self.warn_threshold, self.ban_threshold
            ));
        }
        if self.initial_score <= self.warn_threshold {
            return Err(format!(
                "initial_score deve essere sopra warn/probation threshold: initial={} probation={}",
                self.initial_score, self.warn_threshold
            ));
        }
        if self.initial_score <= self.ban_threshold {
            return Err(format!(
                "initial_score deve essere sopra ban_threshold: initial={} banned={}",
                self.initial_score, self.ban_threshold
            ));
        }
        if self.decay_interval_secs == 0 || self.decay_interval_secs > MAX_DECAY_INTERVAL_SECS {
            return Err(format!(
                "decay_interval_secs fuori range 1..{}: {}",
                MAX_DECAY_INTERVAL_SECS, self.decay_interval_secs
            ));
        }
        if !(0.0..=100.0).contains(&self.decay_percent) || !self.decay_percent.is_finite() {
            return Err(format!(
                "decay_percent fuori range 0..100: {}",
                self.decay_percent
            ));
        }
        if self.min_decay_step < 0 || self.min_decay_step > SCORE_MAX {
            return Err(format!(
                "min_decay_step fuori range 0..{}: {}",
                SCORE_MAX, self.min_decay_step
            ));
        }
        if self.ban_duration_secs == 0 || self.ban_duration_secs > MAX_BAN_SECS {
            return Err(format!(
                "ban_duration_secs fuori range 1..{}: {}",
                MAX_BAN_SECS, self.ban_duration_secs
            ));
        }
        if self.max_tracked_peers == 0 {
            return Err("max_tracked_peers deve essere > 0".to_string());
        }
        for (name, value) in [
            ("delta_tx_valid", self.delta_tx_valid),
            ("delta_block_valid", self.delta_block_valid),
            ("delta_tx_invalid", self.delta_tx_invalid),
            ("delta_block_invalid", self.delta_block_invalid),
            ("delta_spam", self.delta_spam),
            ("delta_rate_limited_soft", self.delta_rate_limited_soft),
            (
                "delta_rate_limited_sustained",
                self.delta_rate_limited_sustained,
            ),
            ("delta_protocol_spam", self.delta_protocol_spam),
            ("delta_disconnect", self.delta_disconnect),
            ("delta_slashed", self.delta_slashed),
        ] {
            if value.abs() > MAX_EVENT_ABS_WEIGHT {
                return Err(format!(
                    "{} fuori range assoluto <= {}: {}",
                    name, MAX_EVENT_ABS_WEIGHT, value
                ));
            }
        }
        if self.delta_tx_valid < 0 || self.delta_block_valid < 0 {
            return Err("delta_tx_valid/delta_block_valid devono essere non negativi".to_string());
        }
        if self.delta_tx_invalid > 0
            || self.delta_block_invalid > 0
            || self.delta_spam > 0
            || self.delta_rate_limited_soft > 0
            || self.delta_rate_limited_sustained > 0
            || self.delta_protocol_spam > 0
            || self.delta_disconnect > 0
            || self.delta_slashed > 0
        {
            return Err("delta negativi di sicurezza devono essere non positivi".to_string());
        }
        if self.delta_spam < -10 {
            return Err("delta_spam deve restare soft: range consentito -10..0".to_string());
        }
        if self.delta_rate_limited_soft < -1 {
            return Err(
                "delta_rate_limited_soft deve restare drop/throttle-only: range consentito -1..0"
                    .to_string(),
            );
        }
        if self.delta_rate_limited_sustained < -20 {
            return Err(
                "delta_rate_limited_sustained deve restare bounded: range consentito -20..0"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn from_security_policy_v1(
        policy: &SecurityPolicy,
        persist_path: String,
        local_source_node_id: Option<String>,
    ) -> Result<Self, String> {
        policy.validate_contract_v1()?;
        let initial_score = policy
            .score
            .initial
            .clamp(SCORE_MIN as i64, SCORE_MAX as i64) as i32;
        let warn_threshold = policy
            .thresholds
            .probation
            .clamp(SCORE_MIN as i64, SCORE_MAX as i64) as i32;
        let ban_threshold = policy
            .thresholds
            .ban
            .clamp(SCORE_MIN as i64, SCORE_MAX as i64) as i32;
        let midpoint =
            warn_threshold.saturating_add((initial_score.saturating_sub(warn_threshold)) / 2);
        let good_threshold = midpoint
            .max(warn_threshold.saturating_add(1))
            .min(SCORE_MAX);

        let cfg = Self {
            initial_score,
            good_threshold,
            warn_threshold,
            ban_threshold,
            decay_interval_secs: policy.score.decay_hours.saturating_mul(3600),
            decay_percent: policy.score.decay_percent as f32,
            min_decay_step: policy.score.min_decay.clamp(0, SCORE_MAX as i64) as i32,
            delta_tx_valid: policy.weights.tx_valid as i32,
            delta_block_valid: policy.weights.block_valid as i32,
            delta_tx_invalid: policy.weights.tx_invalid as i32,
            delta_block_invalid: policy.weights.block_invalid as i32,
            // Runtime P2P `Spam` is a generic/flood signal and is frequently produced by
            // rate-limit/backpressure paths during bootstrap. Keep it soft here; hard faults
            // must use typed events such as InvalidBlock/Slashed instead of generic Spam.
            delta_spam: (policy.weights.flood_penalty as i32).max(-10),
            ban_duration_secs: policy.ban.duration_secs,
            persist_path,
            local_source_node_id,
            ..Self::default()
        };
        cfg.validate_contract_v1()?;
        Ok(cfg)
    }
}

/// Stato reputazionale di un singolo peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    pub base_score: i32,
    pub trust_tier: TrustTier,

    /// Strike generici per recidiva (ogni volta che c’è una penalità)
    pub strikes_negative: u8,

    pub last_penalty_reset: u64,
    pub last_decay_tick: u64,
    pub last_active: u64,

    /// Se Some, peer bannato fino a quel timestamp
    pub banned_until: Option<u64>,

    /// Last time this peer propagated/proposed a block that we accepted as valid.
    /// This is local run-plane evidence used only to avoid classifying healthy
    /// validators/bootstrap peers as hard-ban candidates for generic flood noise.
    #[serde(default)]
    pub last_valid_block_secs: u64,

    /// Count of valid block events seen from this peer in the local run-plane.
    #[serde(default)]
    pub valid_block_count: u64,

    /// Start of the current rate-limit/backpressure accounting window. This is
    /// intentionally local and non-canonical; it prevents physiological bursts from
    /// being modeled as protocol spam while still catching sustained abuse.
    #[serde(default)]
    pub rate_limit_window_start_secs: u64,

    /// Number of rate-limit/backpressure hits in the current accounting window.
    #[serde(default)]
    pub rate_limit_window_hits: u32,

    /// Flag per future override manuali / stake / whitelist
    pub manual_override: bool,
}

impl PeerScore {
    fn new(now: u64, initial_score: i32) -> Self {
        Self {
            base_score: initial_score.clamp(SCORE_MIN, SCORE_MAX),
            trust_tier: TrustTier::Tier0,
            strikes_negative: 0,
            last_penalty_reset: now,
            last_decay_tick: now,
            last_active: now,
            banned_until: None,
            last_valid_block_secs: 0,
            valid_block_count: 0,
            rate_limit_window_start_secs: now,
            rate_limit_window_hits: 0,
            manual_override: false,
        }
    }
    fn clamp(&mut self) {
        self.base_score = self.base_score.clamp(SCORE_MIN, SCORE_MAX);
    }
}

/// Rappresentazione persistita per il file JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPeer {
    peer_id: String,
    score: PeerScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedBinding {
    peer_id: String,
    wallet_pubkey: String,
    source: String,
    bound_at_secs: u64,
    last_confirmed_at_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedReputationV2 {
    peers: Vec<PersistedPeer>,
    #[serde(default)]
    wallet_bindings: Vec<PersistedBinding>,
    #[serde(default)]
    pending_wallet_evidence: Vec<RunWalletReputationEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedReputationState {
    Legacy(Vec<PersistedPeer>),
    V2(PersistedReputationV2),
}

/// Gestore globale della reputazione (compatibile col tuo P2P)
#[derive(Debug)]
pub struct PeerReputationManager {
    /// Stato reputazione per ogni peer P2P
    peers: HashMap<PeerId, PeerScore>,
    /// Configurazione dei delta di punteggio ecc.
    cfg: ReputationConfig,

    /// Persistenza: salva solo quando dirty e non più spesso di persist_min_interval_secs.
    dirty: bool,
    last_persist: u64,

    /// Contatori aggregati per telemetria di sicurezza (Step 50A/50C)
    events_invalid_block: u64,
    events_spam: u64,
    events_disconnect: u64,
    events_slashed: u64,
    total_ban_events: u64,
    total_unban_events: u64,
    peer_wallet_bindings: HashMap<PeerId, RunWalletBinding>,
    pending_wallet_evidence: VecDeque<RunWalletReputationEvidence>,
}

impl PeerReputationManager {
    /// Costruisce il manager, caricando eventuale stato dal file JSON.
    /// N.B. rispetto alla versione vecchia, qui NON usiamo più SecurityPolicy.
    pub fn new(cfg: ReputationConfig) -> Self {
        let (peers, peer_wallet_bindings, mut pending_wallet_evidence) = Self::load_from_file(&cfg);
        Self::fill_missing_evidence_ids(&cfg, &mut pending_wallet_evidence);
        Self {
            peers,
            cfg,
            dirty: false,
            last_persist: now_secs(),
            events_invalid_block: 0,
            events_spam: 0,
            events_disconnect: 0,
            events_slashed: 0,
            total_ban_events: 0,
            total_unban_events: 0,
            peer_wallet_bindings,
            pending_wallet_evidence,
        }
    }

    /// Configura l'identità attester locale usata per firmare evidenze run-plane.
    ///
    /// Questa API evita l'accesso diretto al config interno e mantiene atomico
    /// l'aggiornamento della coppia (pubkey attestatore, seed di signing).
    /// Se uno dei due valori manca, il manager entra in modalità fail-closed e
    /// non emette evidenze firmate canoniche locali.
    pub fn set_local_source_attester_identity(
        &mut self,
        attester_pubkey_hex: Option<String>,
        signing_seed_32: Option<[u8; 32]>,
    ) {
        match (attester_pubkey_hex, signing_seed_32) {
            (Some(pubkey), Some(seed)) => {
                self.cfg.local_source_attester_pubkey = Some(pubkey);
                self.cfg.local_source_attester_signing_seed_32 = Some(seed);
            }
            _ => {
                self.cfg.local_source_attester_pubkey = None;
                self.cfg.local_source_attester_signing_seed_32 = None;
            }
        }
    }

    /// Applica gli override votati dalla governance al config runtime.
    /// Nota: applichiamo solo i campi "Some(...)".
    pub fn apply_governance_overrides(&mut self, delta: &ReputationPolicyDelta) {
        if let Err(e) = delta.validate_contract_v1() {
            ng_warn!(target: "p2p.reputation", "reputation governance override rejected: {}", e);
            return;
        }

        let mut next = self.cfg.clone();

        // Soglie
        if let Some(v) = delta.good_threshold {
            next.good_threshold = v;
        }
        if let Some(v) = delta.probation_threshold {
            next.warn_threshold = v;
        }
        if let Some(v) = delta.banned_threshold {
            next.ban_threshold = v;
        }

        // Ban / tick
        if let Some(v) = delta.ban_duration_secs {
            next.ban_duration_secs = v;
        }
        if let Some(v) = delta.tick_secs {
            next.decay_interval_secs = v;
        }

        // Decay: nel runtime è "percent + min step".
        // Manteniamo compatibilità: decay_per_tick governa il passo minimo.
        if let Some(v) = delta.decay_per_tick {
            next.min_decay_step = v.max(1);
        }

        // Pesi eventi (mappati 1:1)
        if let Some(v) = delta.w_valid_tx {
            next.delta_tx_valid = v;
        }
        if let Some(v) = delta.w_invalid_tx {
            next.delta_tx_invalid = v;
        }
        if let Some(v) = delta.w_valid_block {
            next.delta_block_valid = v;
        }
        if let Some(v) = delta.w_invalid_block {
            next.delta_block_invalid = v;
        }

        // Extra pesi governabili. Runtime P2P spam is generic flood/backpressure
        // noise; keep it soft even if an older/governance payload requests a
        // heavier value. Hard faults must use typed events, not generic Spam.
        if let Some(v) = delta.w_spam {
            next.delta_spam = v.max(-10);
        }
        if let Some(v) = delta.w_disconnect {
            next.delta_disconnect = v;
        }
        if let Some(v) = delta.w_slashed {
            next.delta_slashed = v;
        }

        if let Err(e) = next.validate_contract_v1() {
            ng_warn!(target: "p2p.reputation", "reputation governance override rejected after merge: {}", e);
            return;
        }

        self.cfg = next;
        ng_debug!(target: "p2p.reputation", "🏛️ [REPUTATION] Governance overrides applicati al runtime config.");
    }

    /// Carica lo stato da disco (se esiste), altrimenti mappa vuota.
    fn load_from_file(
        cfg: &ReputationConfig,
    ) -> (
        HashMap<PeerId, PeerScore>,
        HashMap<PeerId, RunWalletBinding>,
        VecDeque<RunWalletReputationEvidence>,
    ) {
        let path = Path::new(&cfg.persist_path);
        let mut map = HashMap::new();
        let mut bindings = HashMap::new();
        let mut pending = VecDeque::new();

        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(state) = serde_json::from_str::<PersistedReputationState>(&data) {
                match state {
                    PersistedReputationState::Legacy(list) => {
                        for p in list {
                            if let Ok(pid) = p.peer_id.parse::<PeerId>() {
                                map.insert(pid, p.score);
                            }
                        }
                    }
                    PersistedReputationState::V2(v2) => {
                        for p in v2.peers {
                            if let Ok(pid) = p.peer_id.parse::<PeerId>() {
                                map.insert(pid, p.score);
                            }
                        }
                        for b in v2.wallet_bindings {
                            if let Ok(pid) = b.peer_id.parse::<PeerId>() {
                                bindings.insert(
                                    pid,
                                    RunWalletBinding {
                                        wallet_pubkey: b.wallet_pubkey,
                                        source: b.source,
                                        bound_at_secs: b.bound_at_secs,
                                        last_confirmed_at_secs: b.last_confirmed_at_secs,
                                    },
                                );
                            }
                        }
                        for ev in v2.pending_wallet_evidence {
                            pending.push_back(ev);
                        }
                    }
                }
            }
        }
        if map.len() > cfg.max_tracked_peers {
            let mut items: Vec<(PeerId, PeerScore)> = map.into_iter().collect();
            items.sort_by_key(|(_, ps)| std::cmp::Reverse(ps.last_active));
            items.truncate(cfg.max_tracked_peers);
            map = items.into_iter().collect();
            bindings.retain(|peer_id, _| map.contains_key(peer_id));
        }
        while pending.len() > PENDING_WALLET_EVIDENCE_CAP {
            pending.pop_front();
        }

        (map, bindings, pending)
    }

    /// Aggiusta lo score di un peer di un certo delta.
    fn adjust_score(&mut self, peer: &PeerId, delta: i32) {
        self.adjust_score_with_options(peer, delta, true, true);
    }

    /// Score update with explicit recidive/ban policy. Generic rate-limit and
    /// backpressure events must not share the same hard-fault path as invalid blocks
    /// or typed protocol abuse.
    fn adjust_score_with_options(
        &mut self,
        peer: &PeerId,
        delta: i32,
        allow_recidive: bool,
        allow_ban: bool,
    ) {
        let now = now_secs();
        let cfg = self.cfg.clone();

        let ps = self.get_or_create(peer, now);
        ps.last_active = now;

        // Positive evidence must break the recidive chain. Without this, a peer that
        // just delivered a valid block can still be punished with amplified generic
        // spam penalties and hard-banned during normal bootstrap/gossip bursts.
        if delta > 0 {
            ps.strikes_negative = 0;
            ps.last_penalty_reset = now;
        }

        // Recidiva: only hard negative evidence may be amplified. Rate-limit,
        // disconnect and generic backpressure are intentionally excluded.
        let mut eff_delta = delta;
        if delta < 0 && allow_recidive {
            if now.saturating_sub(ps.last_penalty_reset) > cfg.recidive_window_secs {
                ps.strikes_negative = 0;
                ps.last_penalty_reset = now;
            }
            if ps.strikes_negative > 0 {
                let scaled = (delta as f32 * cfg.recidive_multiplier).round() as i32;
                eff_delta = scaled.min(-1);
            }
            ps.strikes_negative = ps.strikes_negative.saturating_add(1);
        } else if delta < 0 && !allow_recidive {
            // Soft negatives must not poison the hard-fault recidive chain.
            ps.strikes_negative = 0;
            ps.last_penalty_reset = now;
        }

        ps.base_score = ps.base_score.saturating_add(eff_delta);

        if !allow_ban && ps.base_score <= cfg.ban_threshold {
            // Soft/backpressure signals may lower local scheduler confidence, but
            // must not cross the hard-ban boundary. True ban-capable evidence must
            // use typed hard events such as ProtocolSpam, InvalidBlock or Slashed.
            ps.base_score = cfg.ban_threshold.saturating_add(1).min(SCORE_MAX);
            ps.banned_until = None;
        }

        if allow_ban && eff_delta < 0 && ps.base_score <= cfg.ban_threshold {
            ps.banned_until = Some(now + cfg.ban_duration_secs);
        }

        ps.clamp();
        self.dirty = true;
    }

    /// Salva lo stato su disco (best-effort, errori ignorati)
    /// Ritorna (o crea) il PeerScore per un peer
    /// Ritorna (o crea) il PeerScore per un peer (bounded).
    fn get_or_create(&mut self, peer: &PeerId, now: u64) -> &mut PeerScore {
        if !self.peers.contains_key(peer) {
            self.ensure_capacity(now, 1);
            self.dirty = true;
        }
        let initial_score = self.cfg.initial_score;
        self.peers
            .entry(*peer)
            .or_insert_with(|| PeerScore::new(now, initial_score))
    }

    fn canonical_wallet_pubkey(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(
            crate::keyfmt::pk_hex_from_any(trimmed)
                .unwrap_or_else(|_| trimmed.to_ascii_lowercase()),
        )
    }

    fn fill_missing_evidence_ids(
        cfg: &ReputationConfig,
        items: &mut VecDeque<RunWalletReputationEvidence>,
    ) {
        for ev in items.iter_mut() {
            if ev.source_node_id.trim().is_empty() {
                ev.source_node_id = cfg
                    .local_source_node_id
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "local".to_string());
            }
            let attester = if ev.source_attester_pubkey.trim().is_empty() {
                cfg.local_source_attester_pubkey
                    .as_ref()
                    .and_then(|s| crate::governance::canonical_wallet_reputation_source_attester(s))
                    .or_else(|| {
                        crate::governance::canonical_wallet_reputation_source_attester(
                            &ev.source_node_id,
                        )
                    })
                    .unwrap_or_else(|| "local".to_string())
            } else {
                crate::governance::canonical_wallet_reputation_source_attester(
                    &ev.source_attester_pubkey,
                )
                .unwrap_or_else(|| "local".to_string())
            };
            ev.source_attester_pubkey = attester.clone();
            ev.claim_id = crate::governance::wallet_reputation_claim_id_v1_fields(
                &ev.wallet_pubkey,
                &ev.peer_id,
                &ev.event,
                ev.score_before,
                ev.score_after,
                ev.applied_delta,
                &format!("{:?}", ev.trust_tier),
                ev.observed_at_secs,
                &ev.binding_source,
            );
            ev.evidence_id = crate::governance::wallet_reputation_evidence_id_v1_fields(
                &ev.claim_id,
                &ev.source_attester_pubkey,
            );
            let can_resign_locally = cfg.local_source_attester_signing_seed_32.filter(|seed32| {
                crate::keyfmt::pk_hex_from_any(&ev.source_attester_pubkey)
                    .ok()
                    .as_deref()
                    == Some(&hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(seed32)
                            .verifying_key()
                            .to_bytes(),
                    ))
            });
            if ev.source_attester_sig_b64.trim().is_empty() {
                ev.source_attester_sig_b64.clear();
            }
            if let Some(seed32) = can_resign_locally {
                let sign_item = crate::governance::WalletReputationEvidenceIngestItem {
                    claim_id: ev.claim_id.clone(),
                    evidence_id: ev.evidence_id.clone(),
                    source_node_id: Some(ev.source_node_id.clone()),
                    source_attester_pubkey: Some(ev.source_attester_pubkey.clone()),
                    source_attester_sig_b64: None,
                    wallet_pubkey: ev.wallet_pubkey.clone(),
                    peer_id: ev.peer_id.clone(),
                    event: ev.event.clone(),
                    score_before: ev.score_before,
                    score_after: ev.score_after,
                    applied_delta: ev.applied_delta,
                    trust_tier: format!("{:?}", ev.trust_tier),
                    observed_at_secs: ev.observed_at_secs,
                    binding_source: ev.binding_source.clone(),
                };
                if let Ok(msg) =
                    crate::governance::wallet_reputation_evidence_signing_bytes_v1(&sign_item)
                {
                    let sk = ed25519_dalek::SigningKey::from_bytes(&seed32);
                    let sig_b64 =
                        base64::engine::general_purpose::STANDARD.encode(sk.sign(&msg).to_bytes());
                    ev.source_attester_sig_b64 = sig_b64;
                }
            }
        }
    }

    fn binding_is_fresh_at(&self, binding: &RunWalletBinding, now: u64) -> bool {
        now.saturating_sub(binding.last_confirmed_at_secs) <= self.cfg.wallet_binding_max_age_secs
    }

    fn prune_stale_wallet_bindings(&mut self, now: u64) {
        let ttl = self.cfg.wallet_binding_max_age_secs;
        let before = self.peer_wallet_bindings.len();
        self.peer_wallet_bindings
            .retain(|_, binding| now.saturating_sub(binding.last_confirmed_at_secs) <= ttl);
        if self.peer_wallet_bindings.len() != before {
            self.dirty = true;
        }
    }

    fn event_allows_wallet_evidence(event: ReputationEvent) -> bool {
        matches!(
            event,
            ReputationEvent::InvalidTx
                | ReputationEvent::InvalidBlock
                | ReputationEvent::ProtocolSpam
                | ReputationEvent::Slashed
        )
    }

    pub fn bind_peer_wallet(&mut self, peer: &PeerId, wallet_pubkey_any: &str, source: &str) {
        let Some(wallet_pubkey) = Self::canonical_wallet_pubkey(wallet_pubkey_any) else {
            return;
        };
        let now = now_secs();
        self.get_or_create(peer, now);
        match self.peer_wallet_bindings.get_mut(peer) {
            Some(binding) if binding.wallet_pubkey == wallet_pubkey => {
                binding.source = source.to_string();
                binding.last_confirmed_at_secs = now;
            }
            Some(binding) => {
                let fresh = now.saturating_sub(binding.last_confirmed_at_secs)
                    <= self.cfg.wallet_binding_max_age_secs;
                if fresh {
                    ng_warn!(
                        target: "p2p.reputation",
                        "[REPUTATION] refusing fresh peer->wallet rebind peer={} old_wallet={} new_wallet={} source={}",
                        peer,
                        binding.wallet_pubkey,
                        wallet_pubkey,
                        source
                    );
                    return;
                }
                binding.wallet_pubkey = wallet_pubkey;
                binding.source = source.to_string();
                binding.bound_at_secs = now;
                binding.last_confirmed_at_secs = now;
            }
            None => {
                self.peer_wallet_bindings.insert(
                    *peer,
                    RunWalletBinding {
                        wallet_pubkey,
                        source: source.to_string(),
                        bound_at_secs: now,
                        last_confirmed_at_secs: now,
                    },
                );
            }
        }
        self.dirty = true;
    }

    // ─────────────────────────────────────────
    // Metodi COMPATIBILI con il tuo P2P / blockchain
    // ─────────────────────────────────────────

    /// Chiamato quando appare un nuovo peer in P2P
    pub fn add_peer_if_new(&mut self, peer: &PeerId) {
        let now = now_secs();
        self.get_or_create(peer, now);
    }

    /// Chiamato quando un peer si disconnette
    pub fn peer_disconnected(&mut self, peer: &PeerId) {
        // The run-plane reputation should observe disconnects as a weak negative signal,
        // but keep history and let freshness/decay handle recovery.
        self.on_event(peer, ReputationEvent::Disconnect);
    }

    fn note_valid_block_consensus_signal(&mut self, peer: &PeerId) {
        let now = now_secs();
        let ps = self.get_or_create(peer, now);
        ps.last_valid_block_secs = now;
        ps.valid_block_count = ps.valid_block_count.saturating_add(1);
        ps.strikes_negative = 0;
        ps.last_penalty_reset = now;
        self.dirty = true;
    }

    fn soft_spam_delta_for_peer(&self, peer: &PeerId, cfg: &ReputationConfig) -> (i32, bool) {
        const RECENT_VALID_BLOCK_SPAM_GRACE_SECS: u64 = 120;
        let now = now_secs();
        let recently_consensus_positive = self
            .peers
            .get(peer)
            .map(|ps| {
                ps.last_valid_block_secs > 0
                    && now.saturating_sub(ps.last_valid_block_secs)
                        <= RECENT_VALID_BLOCK_SPAM_GRACE_SECS
            })
            .unwrap_or(false);

        if recently_consensus_positive {
            // A peer that has just delivered a block we accepted is not a hard-ban
            // candidate for generic Spam/rate-limit noise. Drop/throttle at the
            // transport layer if needed, but do not reduce reputation here.
            (0, true)
        } else {
            (cfg.delta_spam, false)
        }
    }

    fn clear_negative_strikes_for_soft_spam(&mut self, peer: &PeerId) {
        let now = now_secs();
        let ps = self.get_or_create(peer, now);
        ps.strikes_negative = 0;
        ps.last_penalty_reset = now;
        self.dirty = true;
    }

    fn rate_limit_delta_for_peer(&mut self, peer: &PeerId, cfg: &ReputationConfig) -> (i32, bool) {
        const RATE_LIMIT_WINDOW_SECS: u64 = 30;
        const DROP_ONLY_HITS: u32 = 3;
        const SOFT_HITS_MAX: u32 = 10;

        let now = now_secs();
        let hits = {
            let ps = self.get_or_create(peer, now);
            if ps.rate_limit_window_start_secs == 0
                || now.saturating_sub(ps.rate_limit_window_start_secs) > RATE_LIMIT_WINDOW_SECS
            {
                ps.rate_limit_window_start_secs = now;
                ps.rate_limit_window_hits = 0;
            }
            ps.rate_limit_window_hits = ps.rate_limit_window_hits.saturating_add(1);
            ps.rate_limit_window_hits
        };
        self.dirty = true;

        if hits <= DROP_ONLY_HITS {
            (0, false)
        } else if hits <= SOFT_HITS_MAX {
            (cfg.delta_rate_limited_soft, false)
        } else {
            (cfg.delta_rate_limited_sustained, true)
        }
    }

    /// Applica un evento reputazionale ad un peer.
    /// Aggiorna punteggio, contatori di telemetria e stampa un log strutturato.
    pub fn on_event(&mut self, peer: &PeerId, event: ReputationEvent) {
        use ReputationEvent::*;

        let cfg = self.cfg.clone();
        let before_state = self.get_peer_state(peer);
        let before_snapshot = self.score_tier_banned_snapshot(peer);
        let score_before = before_snapshot
            .map(|(score, _, _)| score)
            .unwrap_or(SCORE_NEUTRAL);

        match event {
            ValidTx => {
                self.adjust_score(peer, cfg.delta_tx_valid);
            }
            ValidBlock => {
                self.adjust_score(peer, cfg.delta_block_valid);
                self.note_valid_block_consensus_signal(peer);
            }
            InvalidTx => {
                self.adjust_score(peer, cfg.delta_tx_invalid);
            }
            InvalidBlock => {
                self.adjust_score(peer, cfg.delta_block_invalid);
                self.events_invalid_block = self.events_invalid_block.saturating_add(1);
            }
            Spam | SpamTooManyTx | SpamTooManyBlocks => {
                let (delta, soft_consensus_peer) = self.soft_spam_delta_for_peer(peer, &cfg);
                self.adjust_score_with_options(peer, delta, false, false);
                if soft_consensus_peer {
                    self.clear_negative_strikes_for_soft_spam(peer);
                }
                self.events_spam = self.events_spam.saturating_add(1);
            }
            RateLimitedSoft => {
                let (delta, _sustained) = self.rate_limit_delta_for_peer(peer, &cfg);
                self.adjust_score_with_options(peer, delta, false, false);
            }
            RateLimitedSustained => {
                self.adjust_score_with_options(
                    peer,
                    cfg.delta_rate_limited_sustained,
                    false,
                    false,
                );
            }
            ProtocolSpam => {
                self.adjust_score_with_options(peer, cfg.delta_protocol_spam, true, true);
                self.events_spam = self.events_spam.saturating_add(1);
            }
            Disconnect => {
                self.adjust_score_with_options(peer, cfg.delta_disconnect, false, false);
                self.events_disconnect = self.events_disconnect.saturating_add(1);
            }
            Slashed => {
                self.adjust_score(peer, cfg.delta_slashed);
                self.events_slashed = self.events_slashed.saturating_add(1);
            }
        }

        self.maybe_clear_temporary_ban_after_positive_consensus(peer, event, &cfg);

        let after_state = self.get_peer_state(peer);
        let now = now_secs();
        let info = self.get_or_create(peer, now);
        let score = info.base_score;
        let trust_tier = info.trust_tier;
        let applied_delta = score.saturating_sub(score_before);

        let wallet_evidence_allowed =
            applied_delta != 0 && Self::event_allows_wallet_evidence(event);
        let fresh_binding = if wallet_evidence_allowed {
            self.peer_wallet_bindings
                .get(peer)
                .cloned()
                .filter(|binding| self.binding_is_fresh_at(binding, now))
        } else {
            None
        };
        if !wallet_evidence_allowed {
            ng_debug!(
                target: "p2p.reputation",
                "[REPUTATION] skipping wallet evidence for local/zero-delta event peer={} event={:?} applied_delta={}",
                peer,
                event,
                applied_delta
            );
        }
        if let Some(binding) = fresh_binding {
            let event_name = format!("{:?}", event);
            let trust_tier_name = format!("{:?}", trust_tier);
            if let (Some(source_attester_pubkey), Some(source_attester_signing_seed_32)) = (
                self.cfg
                    .local_source_attester_pubkey
                    .as_ref()
                    .and_then(|s| {
                        crate::governance::canonical_wallet_reputation_source_attester(s)
                    }),
                self.cfg.local_source_attester_signing_seed_32,
            ) {
                let claim_id = crate::governance::wallet_reputation_claim_id_v1_fields(
                    &binding.wallet_pubkey,
                    &peer.to_string(),
                    &event_name,
                    score_before,
                    score,
                    applied_delta,
                    &trust_tier_name,
                    now,
                    &binding.source,
                );
                let source_node_id = self
                    .cfg
                    .local_source_node_id
                    .clone()
                    .unwrap_or_else(|| "local".to_string());
                let evidence_id = crate::governance::wallet_reputation_evidence_id_v1_fields(
                    &claim_id,
                    &source_attester_pubkey,
                );
                let mut sign_item = crate::governance::WalletReputationEvidenceIngestItem {
                    claim_id: claim_id.clone(),
                    evidence_id: evidence_id.clone(),
                    source_node_id: Some(source_node_id.clone()),
                    source_attester_pubkey: Some(source_attester_pubkey.clone()),
                    source_attester_sig_b64: None,
                    wallet_pubkey: binding.wallet_pubkey.clone(),
                    peer_id: peer.to_string(),
                    event: event_name.clone(),
                    score_before,
                    score_after: score,
                    applied_delta,
                    trust_tier: trust_tier_name.clone(),
                    observed_at_secs: now,
                    binding_source: binding.source.clone(),
                };
                let source_attester_sig_b64 =
                    crate::governance::wallet_reputation_evidence_signing_bytes_v1(&sign_item)
                        .ok()
                        .and_then(|msg| {
                            let sk = ed25519_dalek::SigningKey::from_bytes(
                                &source_attester_signing_seed_32,
                            );
                            if crate::keyfmt::pk_hex_from_any(&source_attester_pubkey)
                                .ok()
                                .as_deref()
                                != Some(&hex::encode(sk.verifying_key().to_bytes()))
                            {
                                return None;
                            }
                            Some(
                                base64::engine::general_purpose::STANDARD
                                    .encode(sk.sign(&msg).to_bytes()),
                            )
                        });
                if let Some(source_attester_sig_b64) = source_attester_sig_b64 {
                    sign_item.source_attester_sig_b64 = Some(source_attester_sig_b64.clone());
                    let new_ev = RunWalletReputationEvidence {
                        claim_id,
                        evidence_id,
                        source_node_id,
                        source_attester_pubkey,
                        source_attester_sig_b64,
                        wallet_pubkey: binding.wallet_pubkey.clone(),
                        peer_id: peer.to_string(),
                        event: event_name,
                        score_before,
                        score_after: score,
                        applied_delta,
                        trust_tier,
                        observed_at_secs: now,
                        binding_source: binding.source.clone(),
                    };
                    if let Some(existing) = self
                        .pending_wallet_evidence
                        .iter_mut()
                        .find(|ev| ev.evidence_id == new_ev.evidence_id)
                    {
                        *existing = new_ev;
                    } else {
                        self.pending_wallet_evidence.push_back(new_ev);
                        while self.pending_wallet_evidence.len() > PENDING_WALLET_EVIDENCE_CAP {
                            self.pending_wallet_evidence.pop_front();
                        }
                    }
                } else {
                    ng_warn!(target: "p2p.reputation", "[REPUTATION] skipping wallet evidence emission due to source attester signing failure for peer={}", peer);
                }
            } else {
                ng_debug!(target: "p2p.reputation", "[REPUTATION] skipping wallet evidence emission without canonical local source attester for peer={}", peer);
            }
        }

        let banned_before = matches!(before_state, ReputationState::Banned { .. });
        let banned_after = matches!(after_state, ReputationState::Banned { .. });
        if !banned_before && banned_after {
            self.total_ban_events = self.total_ban_events.saturating_add(1);
        } else if banned_before && !banned_after {
            self.total_unban_events = self.total_unban_events.saturating_add(1);
        }

        let tier_changed = before_snapshot.map(|(_, tier, _)| tier) != Some(trust_tier);
        let state_changed =
            std::mem::discriminant(&before_state) != std::mem::discriminant(&after_state);

        if state_changed || tier_changed {
            ng_info!(
                target: "p2p.reputation",
                "[REPUTATION] peer={:?} event={:?} score={} tier={:?} state_before={:?} state_after={:?}",
                peer,
                event,
                score,
                trust_tier,
                before_state,
                after_state
            );
        } else {
            ng_debug!(
                target: "p2p.security",
                "[SEC-REPUTATION] peer={:?} event={:?} score={} state={:?}",
                peer,
                event,
                score,
                after_state
            );
        }
    }

    fn maybe_clear_temporary_ban_after_positive_consensus(
        &mut self,
        peer: &PeerId,
        event: ReputationEvent,
        cfg: &ReputationConfig,
    ) {
        if !matches!(event, ReputationEvent::ValidBlock) {
            return;
        }
        let now = now_secs();
        let Some(ps) = self.peers.get_mut(peer) else {
            return;
        };
        let Some(until) = ps.banned_until else {
            return;
        };
        if now >= until {
            return;
        }
        if ps.base_score > cfg.warn_threshold {
            ps.banned_until = None;
            self.dirty = true;
            ng_info!(
                target: "p2p.reputation",
                "[REPUTATION] clearing temporary ban after positive consensus recovery peer={:?} score={} previous_until={}",
                peer,
                ps.base_score,
                until
            );
        }
    }

    /// Stato aggregato per un peer (usato in p2p.rs)
    /// Stato aggregato per un peer (usato in p2p.rs). Non alloca stato per peer sconosciuti.
    pub fn get_peer_state(&mut self, peer: &PeerId) -> ReputationState {
        let now = now_secs();
        let cfg = self.cfg.clone();

        let Some(ps) = self.peers.get_mut(peer) else {
            return ReputationState::Good;
        };

        if let Some(until) = ps.banned_until {
            if now < until {
                return ReputationState::Banned { until };
            }
        }

        if ps.base_score <= cfg.ban_threshold {
            let until = now + cfg.ban_duration_secs;
            ps.banned_until = Some(until);
            self.dirty = true;
            return ReputationState::Banned { until };
        }

        if ps.base_score <= cfg.warn_threshold {
            ReputationState::Probation
        } else {
            ReputationState::Good
        }
    }

    /// Snapshot (no-mutation) of a peer's score/tier/ban status.
    /// This is used for ops-only integrations (e.g., peerbook protection) without mutating ban timers.
    pub fn score_tier_banned_snapshot(&self, peer: &PeerId) -> Option<(i32, TrustTier, bool)> {
        let ps = self.peers.get(peer)?;
        let now = now_secs();
        let banned_active = ps.banned_until.map(|u| now < u).unwrap_or(false);
        let banned_by_score = ps.base_score <= self.cfg.ban_threshold;
        Some((
            ps.base_score,
            ps.trust_tier,
            banned_active || banned_by_score,
        ))
    }

    /// No-mutation hard-ban snapshot used by P2P enforcement/logging.
    /// Returns the active expiry if present. If the score is already below the
    /// ban threshold but no expiry has been materialized yet, returns the
    /// deterministic effective expiry that `get_peer_state()` would set.
    pub fn hard_ban_until_snapshot(&self, peer: &PeerId) -> Option<u64> {
        let ps = self.peers.get(peer)?;
        let now = now_secs();
        if let Some(until) = ps.banned_until {
            if now < until {
                return Some(until);
            }
        }
        if ps.base_score <= self.cfg.ban_threshold {
            return Some(now.saturating_add(self.cfg.ban_duration_secs));
        }
        None
    }

    pub fn is_hard_banned_snapshot(&self, peer: &PeerId) -> bool {
        self.hard_ban_until_snapshot(peer).is_some()
    }

    /// Prune peers not seen for too long.
    fn prune_stale(&mut self, now: u64) {
        let stale_after = self.cfg.prune_stale_after_secs;
        if stale_after == 0 {
            return;
        }
        let before = self.peers.len();
        self.peers.retain(|_, ps| {
            now.saturating_sub(ps.last_active) <= stale_after || ps.manual_override
        });
        if self.peers.len() != before {
            self.peer_wallet_bindings
                .retain(|peer_id, _| self.peers.contains_key(peer_id));
            self.dirty = true;
        }
    }

    /// Ensure bounded memory: evict old/low-quality peers when capacity exceeded.
    fn ensure_capacity(&mut self, now: u64, needed: usize) {
        self.prune_stale(now);

        let max = self.cfg.max_tracked_peers.max(1);
        while self.peers.len().saturating_add(needed) > max {
            let mut victim: Option<PeerId> = None;
            let mut best_age: u64 = 0;
            let mut best_score: i32 = i32::MAX;

            for (pid, ps) in self.peers.iter() {
                if ps.manual_override {
                    continue;
                }
                let age = now.saturating_sub(ps.last_active);
                if victim.is_none()
                    || age > best_age
                    || (age == best_age && ps.base_score < best_score)
                {
                    victim = Some(*pid);
                    best_age = age;
                    best_score = ps.base_score;
                }
            }

            if let Some(v) = victim {
                self.peers.remove(&v);
                self.peer_wallet_bindings.remove(&v);
                self.dirty = true;
            } else {
                break;
            }
        }
    }

    /// Persist best-effort: salva solo se dirty e con un rate limit; atomic write.
    fn maybe_persist(&mut self, now: u64) {
        if !self.dirty {
            return;
        }
        if now.saturating_sub(self.last_persist) < self.cfg.persist_min_interval_secs {
            return;
        }

        let path = Path::new(&self.cfg.persist_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let peers: Vec<PersistedPeer> = self
            .peers
            .iter()
            .map(|(pid, score)| PersistedPeer {
                peer_id: pid.to_string(),
                score: score.clone(),
            })
            .collect();
        let wallet_bindings: Vec<PersistedBinding> = self
            .peer_wallet_bindings
            .iter()
            .map(|(pid, binding)| PersistedBinding {
                peer_id: pid.to_string(),
                wallet_pubkey: binding.wallet_pubkey.clone(),
                source: binding.source.clone(),
                bound_at_secs: binding.bound_at_secs,
                last_confirmed_at_secs: binding.last_confirmed_at_secs,
            })
            .collect();
        let pending_wallet_evidence: Vec<RunWalletReputationEvidence> =
            self.pending_wallet_evidence.iter().cloned().collect();

        let state = PersistedReputationV2 {
            peers,
            wallet_bindings,
            pending_wallet_evidence,
        };

        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let tmp = path.with_extension("json.tmp");
            let write_ok = (|| -> std::io::Result<()> {
                use std::io::Write;
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(json.as_bytes())?;
                f.sync_all()?;
                crate::utils::atomic_replace_file_v1(&tmp, path)
            })();
            if write_ok.is_ok() {
                self.dirty = false;
                self.last_persist = now;
            } else {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }

    /// Ritorna un riassunto compatto dello stato reputazionale attuale,
    /// pensato proprio per le API / Explorer.
    pub fn summary(&self) -> ReputationSummary {
        let total_peers = self.peers.len() as u64;

        let mut good = 0u64;
        let mut probation = 0u64;
        let mut banned = 0u64;
        let mut total_score: i64 = 0;

        let now = now_secs();
        let cfg = &self.cfg;

        for (_peer_id, ps) in self.peers.iter() {
            // Stato come in get_peer_state, ma senza creare mutabili
            let state = if let Some(until) = ps.banned_until {
                if now < until {
                    ReputationState::Banned { until }
                } else if ps.base_score <= cfg.ban_threshold {
                    ReputationState::Banned {
                        until: now + cfg.ban_duration_secs,
                    }
                } else if ps.base_score <= cfg.warn_threshold {
                    ReputationState::Probation
                } else {
                    ReputationState::Good
                }
            } else if ps.base_score <= cfg.ban_threshold {
                ReputationState::Banned {
                    until: now + cfg.ban_duration_secs,
                }
            } else if ps.base_score <= cfg.warn_threshold {
                ReputationState::Probation
            } else {
                ReputationState::Good
            };

            match state {
                ReputationState::Good => good += 1,
                ReputationState::Probation => probation += 1,
                ReputationState::Banned { .. } => banned += 1,
            }

            total_score += ps.base_score as i64;
        }

        let avg_score = if total_peers > 0 {
            total_score as f64 / total_peers as f64
        } else {
            0.0
        };

        ReputationSummary {
            total_peers,
            good,
            probation,
            banned,
            avg_score,
        }
    }

    /// Stato reputazionale visto dalla chiave del miner (usato da blockchain.rs)
    /// Restituisce lo score corrente per una chiave miner (per pesare consenso, ecc.)
    /// Da chiamare periodicamente (es. nel tuo loop P2P/Pulse)
    /// Da chiamare periodicamente (es. nel tuo loop P2P/Pulse)
    pub fn on_tick(&mut self) {
        let now = now_secs();
        let cfg = self.cfg.clone();
        let mut changed_any = false;

        for (_peer, ps) in self.peers.iter_mut() {
            let before_score = ps.base_score;
            let before_tier = ps.trust_tier;

            // Decadimento verso il baseline configurato.
            // In produzione deriva da SecurityPolicy.score.initial; non deve restare hardcoded
            // e deve restare coerente con la scala 0..1000/base_score=600.
            if now.saturating_sub(ps.last_decay_tick) >= cfg.decay_interval_secs {
                let neutral_score = cfg.initial_score.clamp(SCORE_MIN, SCORE_MAX);
                let distance = if ps.base_score < neutral_score {
                    neutral_score - ps.base_score
                } else {
                    ps.base_score - neutral_score
                };

                if distance > 0 {
                    let step = ((distance as f32 * cfg.decay_percent / 100.0).round() as i32)
                        .max(cfg.min_decay_step)
                        .max(1);

                    if ps.base_score < neutral_score {
                        ps.base_score = (ps.base_score + step).clamp(SCORE_MIN, neutral_score);
                    } else if ps.base_score > neutral_score {
                        ps.base_score = (ps.base_score - step).clamp(neutral_score, SCORE_MAX);
                    }
                }

                ps.last_decay_tick = now;
            }

            // Inattività: raffredda il tier se il peer sparisce per troppo
            let inactive_for = now.saturating_sub(ps.last_active);
            if inactive_for > cfg.inactive_demotion_secs {
                ps.trust_tier = TrustTier::Tier0;
            } else if ps.base_score >= 700 {
                ps.trust_tier = TrustTier::Tier2;
            } else if ps.base_score >= cfg.good_threshold {
                ps.trust_tier = TrustTier::Tier1;
            }

            if ps.base_score != before_score || ps.trust_tier != before_tier {
                changed_any = true;
            }
        }

        if changed_any {
            self.dirty = true;
        }

        // bounded prune + persist (best-effort)
        self.prune_stale(now);
        self.prune_stale_wallet_bindings(now);
        self.maybe_persist(now);
    }

    /// Snapshot "verbose": lista dei peer con score, tier, stato, inattività.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<(String, i32, TrustTier, ReputationState, u64)> {
        let now = now_secs();
        let cfg = self.cfg.clone();

        self.peers
            .iter()
            .map(|(pid, ps)| {
                let state = if let Some(until) = ps.banned_until {
                    if now < until {
                        ReputationState::Banned { until }
                    } else if ps.base_score <= cfg.ban_threshold {
                        ReputationState::Banned {
                            until: now + cfg.ban_duration_secs,
                        }
                    } else if ps.base_score <= cfg.warn_threshold {
                        ReputationState::Probation
                    } else {
                        ReputationState::Good
                    }
                } else if ps.base_score <= cfg.ban_threshold {
                    ReputationState::Banned {
                        until: now + cfg.ban_duration_secs,
                    }
                } else if ps.base_score <= cfg.warn_threshold {
                    ReputationState::Probation
                } else {
                    ReputationState::Good
                };

                let inactive_for = now.saturating_sub(ps.last_active);

                (
                    pid.to_string(),
                    ps.base_score,
                    ps.trust_tier,
                    state,
                    inactive_for,
                )
            })
            .collect()
    }

    /// Bounded verbose snapshot for public/security APIs.
    ///
    /// Returns `(total_peers_available, peers)` and never materializes more than
    /// `limit` peer rows. This keeps public read endpoints from holding the
    /// reputation lock while allocating/serializing the full peer table.
    pub fn snapshot_limited(
        &self,
        limit: usize,
    ) -> (usize, Vec<(String, i32, TrustTier, ReputationState, u64)>) {
        let now = now_secs();
        let cfg = self.cfg.clone();
        let total = self.peers.len();
        let limit = limit.min(total);

        let peers = self
            .peers
            .iter()
            .take(limit)
            .map(|(pid, ps)| {
                let state = if let Some(until) = ps.banned_until {
                    if now < until {
                        ReputationState::Banned { until }
                    } else if ps.base_score <= cfg.ban_threshold {
                        ReputationState::Banned {
                            until: now + cfg.ban_duration_secs,
                        }
                    } else if ps.base_score <= cfg.warn_threshold {
                        ReputationState::Probation
                    } else {
                        ReputationState::Good
                    }
                } else if ps.base_score <= cfg.ban_threshold {
                    ReputationState::Banned {
                        until: now + cfg.ban_duration_secs,
                    }
                } else if ps.base_score <= cfg.warn_threshold {
                    ReputationState::Probation
                } else {
                    ReputationState::Good
                };

                let inactive_for = now.saturating_sub(ps.last_active);

                (
                    pid.to_string(),
                    ps.base_score,
                    ps.trust_tier,
                    state,
                    inactive_for,
                )
            })
            .collect();

        (total, peers)
    }

    /// Snapshot ridotto per API di sicurezza (Step 50A).
    pub fn snapshot_security_metrics(&self) -> SecurityMetrics {
        let summary = self.summary();

        SecurityMetrics {
            total_peers: summary.total_peers,
            good: summary.good,
            probation: summary.probation,
            banned: summary.banned,
            avg_score: summary.avg_score,
            events_invalid_block: self.events_invalid_block,
            events_spam: self.events_spam,
            events_disconnect: self.events_disconnect,
            events_slashed: self.events_slashed,
            total_ban_events: self.total_ban_events,
            total_unban_events: self.total_unban_events,
            wallet_bound_peers: self.wallet_snapshot_summary().total_bound_peers,
            wallet_subjects: self.wallet_snapshot_summary().total_wallets,
            pending_wallet_evidence: self.pending_wallet_evidence.len() as u64,
        }
    }

    pub fn wallet_snapshot_summary(&self) -> RunWalletReputationSummary {
        let now = now_secs();
        let mut wallets = std::collections::BTreeSet::new();
        let mut bound_peers = 0u64;
        for binding in self.peer_wallet_bindings.values() {
            if self.binding_is_fresh_at(binding, now) {
                wallets.insert(binding.wallet_pubkey.clone());
                bound_peers = bound_peers.saturating_add(1);
            }
        }
        RunWalletReputationSummary {
            total_wallets: wallets.len() as u64,
            total_bound_peers: bound_peers,
            pending_evidence: self.pending_wallet_evidence.len() as u64,
        }
    }

    pub fn wallet_snapshot(&self) -> Vec<RunWalletReputationView> {
        let mut by_wallet: std::collections::BTreeMap<String, Vec<(&PeerId, &PeerScore)>> =
            std::collections::BTreeMap::new();
        let now = now_secs();
        for (peer_id, binding) in self.peer_wallet_bindings.iter() {
            if !self.binding_is_fresh_at(binding, now) {
                continue;
            }
            if let Some(score) = self.peers.get(peer_id) {
                by_wallet
                    .entry(binding.wallet_pubkey.clone())
                    .or_default()
                    .push((peer_id, score));
            }
        }
        let cfg = &self.cfg;
        by_wallet
            .into_iter()
            .map(|(wallet_pubkey, items)| {
                let peers_bound = items.len() as u64;
                let mut total_score: i64 = 0;
                let mut best_tier = TrustTier::Tier0;
                let mut has_banned_peer = false;
                let mut last_active_secs = 0u64;
                for (_, ps) in items.iter() {
                    total_score += ps.base_score as i64;
                    best_tier = best_tier.max(ps.trust_tier);
                    let banned = ps.banned_until.map(|u| now < u).unwrap_or(false)
                        || ps.base_score <= cfg.ban_threshold;
                    has_banned_peer |= banned;
                    last_active_secs = last_active_secs.max(ps.last_active);
                }
                RunWalletReputationView {
                    wallet_pubkey,
                    peers_bound,
                    avg_score: if peers_bound > 0 {
                        total_score as f64 / peers_bound as f64
                    } else {
                        0.0
                    },
                    best_tier,
                    has_banned_peer,
                    last_active_secs,
                }
            })
            .collect()
    }

    pub fn pending_wallet_evidence_snapshot(
        &self,
        max_items: usize,
    ) -> Vec<RunWalletReputationEvidence> {
        let max_items = max_items.max(1);
        self.pending_wallet_evidence
            .iter()
            .rev()
            .take(max_items)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn acknowledge_wallet_evidence_ids(&mut self, evidence_ids: &[String]) -> usize {
        if evidence_ids.is_empty() {
            return 0;
        }
        let wanted: std::collections::BTreeSet<&str> =
            evidence_ids.iter().map(|s| s.as_str()).collect();
        let before = self.pending_wallet_evidence.len();
        self.pending_wallet_evidence
            .retain(|ev| !wanted.contains(ev.evidence_id.as_str()));
        let removed = before.saturating_sub(self.pending_wallet_evidence.len());
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{identity, PeerId};

    fn mk_peer() -> PeerId {
        let kp = identity::Keypair::generate_ed25519();
        PeerId::from_public_key(&kp.public())
    }

    #[test]
    fn t46_01_good_peer_score_goes_up() {
        // Config separata per non toccare il file reale
        let cfg = ReputationConfig {
            persist_path: "reputation_test_good.json".into(),
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();

        // Creiamo il peer dentro la mappa
        rep.add_peer_if_new(&peer);

        let before = {
            let ps = rep.peers.get(&peer).expect("peer mancante");
            ps.base_score
        };

        // Il peer si comporta bene: blocchi validi
        for _ in 0..5 {
            rep.on_event(&peer, ReputationEvent::ValidBlock);
        }

        let after = {
            let ps = rep.peers.get(&peer).expect("peer mancante");
            ps.base_score
        };

        assert!(
            after > before,
            "score non aumentato come atteso: before={}, after={}",
            before,
            after
        );
    }

    #[test]
    fn t46_02_bad_peer_gets_banned_after_many_invalid_blocks() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_bad.json".into(),
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();

        rep.add_peer_if_new(&peer);

        // Peer che continua a proporre blocchi invalidi (recidiva)
        for _ in 0..20 {
            rep.on_event(&peer, ReputationEvent::InvalidBlock);
        }

        match rep.get_peer_state(&peer) {
            ReputationState::Banned { .. } => {
                // ok: il motore arriva davvero al ban
            }
            other => {
                panic!("atteso stato Banned, ottenuto invece: {:?}", other);
            }
        }
    }

    #[test]
    fn t46_03_valid_blocks_clear_temporary_ban_once_score_recovers_above_warn_threshold() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_unban_on_valid_block.json".into(),
            // Default reputation now starts at the canonical base/new score (600),
            // with ban at 200 and probation/warn at 500. This fixture must drive
            // the peer below the ban threshold with one hard fault, then recover
            // above warn only after two valid consensus events.
            delta_block_invalid: -450,
            delta_block_valid: 200,
            ban_duration_secs: 24 * 3600,
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);

        rep.on_event(&peer, ReputationEvent::InvalidBlock);
        assert!(matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));

        rep.on_event(&peer, ReputationEvent::ValidBlock);
        assert!(matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));

        rep.on_event(&peer, ReputationEvent::ValidBlock);
        assert!(!matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));
        let ps = rep.peers.get(&peer).expect("peer mancante");
        assert!(
            ps.banned_until.is_none(),
            "temporary ban should be cleared after sustained valid blocks"
        );
    }

    #[test]
    fn t48_reputation_overrides_keep_generic_spam_soft() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_overrides.json".into(),
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);

        let before = rep.peers.get(&peer).unwrap().base_score;

        // Governance must not be able to turn generic runtime Spam into a hard
        // fault. Heavy penalties belong to typed invalid-block/slash evidence.
        let delta = ReputationPolicyDelta {
            w_spam: Some(-99),
            ..Default::default()
        };

        rep.apply_governance_overrides(&delta);
        rep.on_event(&peer, ReputationEvent::Spam);

        let after = rep.peers.get(&peer).unwrap().base_score;
        assert_eq!(
            after,
            before - 2,
            "invalid heavy w_spam override must be rejected; only the default soft spam delta may apply"
        );
    }
    #[test]
    fn t49_recidive_amplifies_penalty() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_recidive.json".into(),
            recidive_window_secs: 3600,
            recidive_multiplier: 2.0,
            delta_tx_invalid: -10,
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();

        rep.on_event(&peer, ReputationEvent::InvalidTx);
        let s1 = rep.peers.get(&peer).unwrap().base_score;

        rep.on_event(&peer, ReputationEvent::InvalidTx);
        let s2 = rep.peers.get(&peer).unwrap().base_score;

        assert_eq!(s2, s1 - 20, "recidiva non ha amplificato la penalità");
    }

    #[test]
    fn t49_valid_block_resets_negative_recidive_chain() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_valid_block_resets_recidive.json".into(),
            delta_tx_invalid: -10,
            delta_block_valid: 5,
            recidive_window_secs: 3600,
            recidive_multiplier: 2.0,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();

        rep.on_event(&peer, ReputationEvent::InvalidTx);
        let after_first = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::ValidBlock);
        let after_valid = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::InvalidTx);
        let after_second_invalid = rep.peers.get(&peer).unwrap().base_score;

        assert_eq!(after_valid, after_first + 5);
        assert_eq!(
            after_second_invalid,
            after_valid - 10,
            "valid block must reset recidive amplification"
        );
    }

    #[test]
    fn t49_recent_valid_block_makes_generic_spam_reputation_neutral() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_recent_valid_block_soft_spam.json".into(),
            delta_spam: -100,
            delta_block_valid: 5,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);
        let before = rep.peers.get(&peer).unwrap().base_score;

        rep.on_event(&peer, ReputationEvent::ValidBlock);
        let after_valid = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::Spam);
        let after_spam = rep.peers.get(&peer).unwrap().base_score;

        assert!(after_valid > before);
        assert_eq!(
            after_spam, after_valid,
            "generic spam after accepted valid block must not lower reputation"
        );
        assert!(!matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));
    }

    #[test]
    fn t49_rate_limit_soft_is_drop_only_then_bounded_without_recidive() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_rate_limit_soft.json".into(),
            delta_rate_limited_soft: -1,
            delta_rate_limited_sustained: -10,
            recidive_multiplier: 2.0,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);
        let before = rep.peers.get(&peer).unwrap().base_score;

        for _ in 0..3 {
            rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        }
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, before);

        rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, before - 1);

        for _ in 0..7 {
            rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        }
        let after_sustained = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        assert_eq!(
            rep.peers.get(&peer).unwrap().base_score,
            after_sustained - 10
        );
        assert!(!matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));
    }

    #[test]
    fn t49_rate_limit_sustained_cannot_cross_hard_ban_boundary() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_rate_limit_no_hard_ban.json".into(),
            delta_rate_limited_sustained: -20,
            ban_threshold: 200,
            warn_threshold: 500,
            good_threshold: 550,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);

        for _ in 0..100 {
            rep.on_event(&peer, ReputationEvent::RateLimitedSustained);
        }

        let score = rep.peers.get(&peer).unwrap().base_score;
        assert_eq!(score, 201);
        assert!(!matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));
        assert!(matches!(
            rep.get_peer_state(&peer),
            ReputationState::Probation
        ));
    }

    #[test]
    fn t49_soft_events_do_not_amplify_next_hard_fault() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_soft_no_recidive_poison.json".into(),
            delta_protocol_spam: -50,
            delta_rate_limited_sustained: -10,
            recidive_multiplier: 2.0,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);

        rep.on_event(&peer, ReputationEvent::RateLimitedSustained);
        let after_soft = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, after_soft - 50);

        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, after_soft - 150);
    }

    #[test]
    fn t49_protocol_spam_is_typed_hard_path_but_generic_spam_is_soft() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_protocol_spam_typed.json".into(),
            delta_spam: -10,
            delta_protocol_spam: -50,
            recidive_multiplier: 2.0,
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);
        let before = rep.peers.get(&peer).unwrap().base_score;

        rep.on_event(&peer, ReputationEvent::Spam);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, before - 10);
        rep.on_event(&peer, ReputationEvent::Spam);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, before - 20);

        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        let after_protocol_1 = rep.peers.get(&peer).unwrap().base_score;
        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        assert_eq!(
            rep.peers.get(&peer).unwrap().base_score,
            after_protocol_1 - 100
        );
    }

    #[test]
    fn t50_bounded_map_evicts_and_get_state_does_not_allocate() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_bounded.json".into(),
            max_tracked_peers: 50,
            prune_stale_after_secs: 0, // no time-prune; only cap
            persist_min_interval_secs: 999999,
            ..ReputationConfig::default()
        };

        let mut rep = PeerReputationManager::new(cfg);

        let p0 = mk_peer();
        let _ = rep.get_peer_state(&p0);
        assert_eq!(
            rep.peers.len(),
            0,
            "get_peer_state ha allocato peer sconosciuto"
        );

        for _ in 0..200 {
            let p = mk_peer();
            rep.add_peer_if_new(&p);
        }
        assert!(
            rep.peers.len() <= 50,
            "mappa peers non bounded: {}",
            rep.peers.len()
        );
    }
    #[test]
    fn wallet_evidence_acknowledge_removes_pending_ids() {
        let signing_seed = [5u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let cfg = ReputationConfig {
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..ReputationConfig::default()
        };
        let mut rep = PeerReputationManager::new(cfg);
        let peer = mk_peer();
        rep.bind_peer_wallet(&peer, "abcd", "test");
        rep.on_event(&peer, ReputationEvent::InvalidTx);
        let ids = rep
            .pending_wallet_evidence_snapshot(8)
            .into_iter()
            .map(|ev| ev.evidence_id)
            .collect::<Vec<_>>();
        assert!(!ids.is_empty());
        let removed = rep.acknowledge_wallet_evidence_ids(&ids);
        assert_eq!(removed, ids.len());
        assert!(rep.pending_wallet_evidence_snapshot(8).is_empty());
    }

    #[test]
    fn stale_wallet_bindings_do_not_emit_evidence_or_count_in_snapshot() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_stale_binding.json".into(),
            wallet_binding_max_age_secs: 1,
            ..ReputationConfig::default()
        });
        let peer = PeerId::random();
        rep.add_peer_if_new(&peer);
        rep.bind_peer_wallet(&peer, "abcd", "test");
        if let Some(binding) = rep.peer_wallet_bindings.get_mut(&peer) {
            binding.last_confirmed_at_secs = binding.last_confirmed_at_secs.saturating_sub(10);
        }
        rep.on_event(&peer, ReputationEvent::Spam);
        assert!(rep.pending_wallet_evidence_snapshot(8).is_empty());
        let summary = rep.wallet_snapshot_summary();
        assert_eq!(summary.total_bound_peers, 0);
        assert_eq!(summary.total_wallets, 0);
    }

    #[test]
    fn wallet_evidence_coalesces_same_source_scoped_claim_in_pending_queue() {
        let signing_seed = [9u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_coalesce.json".into(),
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..Default::default()
        });
        let peer = PeerId::random();
        rep.bind_peer_wallet(&peer, "abcd", "pulse");
        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        let pending = rep.pending_wallet_evidence_snapshot(8);
        assert_eq!(pending.len(), 1);
        let only = pending.first().unwrap();
        assert_eq!(only.event, "ProtocolSpam");
        assert_eq!(only.source_node_id, "node-A");
        assert!(!only.source_attester_sig_b64.is_empty());
    }

    #[test]
    fn rate_limit_events_do_not_emit_wallet_evidence_even_with_fresh_binding() {
        let signing_seed = [11u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_rate_limit_no_wallet_evidence.json".into(),
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..Default::default()
        });
        let peer = PeerId::random();
        rep.bind_peer_wallet(&peer, "abcd", "pulse");
        for _ in 0..16 {
            rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        }
        rep.on_event(&peer, ReputationEvent::RateLimitedSustained);
        assert!(rep.pending_wallet_evidence_snapshot(8).is_empty());
    }

    #[test]
    fn zero_delta_events_do_not_emit_wallet_evidence() {
        let signing_seed = [12u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_zero_delta_no_wallet_evidence.json".into(),
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..Default::default()
        });
        let peer = PeerId::random();
        rep.bind_peer_wallet(&peer, "abcd", "pulse");
        rep.on_event(&peer, ReputationEvent::RateLimitedSoft);
        assert!(rep.pending_wallet_evidence_snapshot(8).is_empty());
    }

    #[test]
    fn soft_legacy_spam_does_not_emit_wallet_evidence() {
        let signing_seed = [13u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_soft_spam_no_wallet_evidence.json".into(),
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..Default::default()
        });
        let peer = PeerId::random();
        rep.bind_peer_wallet(&peer, "abcd", "pulse");
        rep.on_event(&peer, ReputationEvent::Spam);
        assert!(rep.pending_wallet_evidence_snapshot(8).is_empty());
    }

    #[test]
    fn hard_reputation_events_still_emit_wallet_evidence() {
        let signing_seed = [14u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_hard_events_wallet_evidence.json".into(),
            local_source_node_id: Some("node-A".into()),
            local_source_attester_pubkey: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            local_source_attester_signing_seed_32: Some(signing_seed),
            ..Default::default()
        });
        let peer = PeerId::random();
        rep.bind_peer_wallet(&peer, "abcd", "pulse");
        rep.on_event(&peer, ReputationEvent::InvalidTx);
        rep.on_event(&peer, ReputationEvent::ProtocolSpam);
        rep.on_event(&peer, ReputationEvent::InvalidBlock);
        let pending = rep.pending_wallet_evidence_snapshot(8);
        let events = pending
            .iter()
            .map(|ev| ev.event.as_str())
            .collect::<Vec<_>>();
        assert!(events.contains(&"InvalidTx"));
        assert!(events.contains(&"ProtocolSpam"));
        assert!(events.contains(&"InvalidBlock"));
        assert!(pending.iter().all(|ev| ev.applied_delta != 0));
    }

    #[test]
    fn legacy_pending_wallet_evidence_is_resigned_when_local_attester_matches() {
        let mut cfg = ReputationConfig::default();
        let signing_seed = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        cfg.local_source_node_id = Some("node-A".to_string());
        cfg.local_source_attester_pubkey =
            Some(hex::encode(signing_key.verifying_key().to_bytes()));
        cfg.local_source_attester_signing_seed_32 = Some(signing_seed);

        let mut items = VecDeque::from([RunWalletReputationEvidence {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: String::new(),
            source_attester_pubkey: String::new(),
            source_attester_sig_b64: String::new(),
            wallet_pubkey: "wallet-1".to_string(),
            peer_id: "peer-1".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: TrustTier::Tier2,
            observed_at_secs: 123,
            binding_source: "hello_runtime_telemetry".to_string(),
        }]);

        PeerReputationManager::fill_missing_evidence_ids(&cfg, &mut items);
        let item = items.front().unwrap();
        assert_eq!(item.source_node_id, "node-A");
        assert!(!item.claim_id.is_empty());
        assert!(!item.evidence_id.is_empty());
        assert!(!item.source_attester_sig_b64.is_empty());
    }

    #[test]
    fn reputation_config_rejects_initial_below_probation_threshold() {
        let cfg = ReputationConfig {
            persist_path: "reputation_test_bad_initial.json".into(),
            initial_score: 450,
            good_threshold: 550,
            warn_threshold: 500,
            ban_threshold: 200,
            ..ReputationConfig::default()
        };
        let err = cfg
            .validate_contract_v1()
            .expect_err("initial score below probation must be rejected");
        assert!(err.contains("initial_score deve essere sopra warn/probation threshold"));
    }

    #[test]
    fn reputation_config_from_security_policy_applies_thresholds_and_initial_score() {
        let mut pol = SecurityPolicy::default();
        pol.score.initial = 600;
        pol.thresholds.probation = 500;
        pol.thresholds.ban = 200;
        pol.weights.tx_valid = 3;
        pol.weights.block_valid = 7;
        pol.weights.tx_invalid = -55;
        pol.weights.block_invalid = -201;
        pol.weights.flood_penalty = -88;
        pol.ban.duration_secs = 1234;

        let cfg = ReputationConfig::from_security_policy_v1(
            &pol,
            "rep.json".into(),
            Some("node-A".into()),
        )
        .expect("valid security policy must map to reputation config");

        assert_eq!(cfg.initial_score, 600);
        assert_eq!(cfg.warn_threshold, 500);
        assert_eq!(cfg.ban_threshold, 200);
        assert_eq!(cfg.good_threshold, 550);
        assert_eq!(cfg.delta_tx_valid, 3);
        assert_eq!(cfg.delta_block_valid, 7);
        assert_eq!(cfg.delta_tx_invalid, -55);
        assert_eq!(cfg.delta_block_invalid, -201);
        assert_eq!(cfg.delta_spam, -10);
        assert_eq!(cfg.ban_duration_secs, 1234);
    }

    #[test]
    fn new_peer_uses_configured_initial_score() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_initial_score.json".into(),
            initial_score: 600,
            warn_threshold: 500,
            ban_threshold: 200,
            good_threshold: 550,
            ..ReputationConfig::default()
        });
        let peer = mk_peer();
        rep.add_peer_if_new(&peer);
        assert_eq!(rep.peers.get(&peer).unwrap().base_score, 600);
    }

    #[test]
    fn invalid_governance_threshold_override_is_rejected_at_runtime() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_invalid_override.json".into(),
            good_threshold: 550,
            warn_threshold: 500,
            ban_threshold: 200,
            ..ReputationConfig::default()
        });
        let delta = ReputationPolicyDelta {
            good_threshold: Some(450),
            probation_threshold: Some(500),
            banned_threshold: Some(200),
            ..Default::default()
        };
        rep.apply_governance_overrides(&delta);
        assert_eq!(rep.cfg.good_threshold, 550);
        assert_eq!(rep.cfg.warn_threshold, 500);
        assert_eq!(rep.cfg.ban_threshold, 200);
    }

    #[test]
    fn fresh_conflicting_wallet_rebind_is_rejected_until_binding_stales() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_rebind_guard.json".into(),
            wallet_binding_max_age_secs: 60,
            ..ReputationConfig::default()
        });
        let peer = PeerId::random();
        rep.add_peer_if_new(&peer);
        rep.bind_peer_wallet(&peer, "abcd", "hello");
        rep.bind_peer_wallet(&peer, "ef01", "pulse");
        assert_eq!(
            rep.peer_wallet_bindings.get(&peer).unwrap().wallet_pubkey,
            "abcd"
        );
        if let Some(binding) = rep.peer_wallet_bindings.get_mut(&peer) {
            binding.last_confirmed_at_secs = binding.last_confirmed_at_secs.saturating_sub(120);
        }
        rep.bind_peer_wallet(&peer, "ef01", "pulse");
        assert_eq!(
            rep.peer_wallet_bindings.get(&peer).unwrap().wallet_pubkey,
            "ef01"
        );
    }

    #[test]
    fn hard_ban_snapshot_reports_materialized_ban_without_mutating_unknown_peer() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_hard_ban_snapshot.json".into(),
            delta_tx_invalid: -500,
            ban_threshold: 250,
            ..ReputationConfig::default()
        });
        let unknown = PeerId::random();
        assert!(rep.hard_ban_until_snapshot(&unknown).is_none());
        assert_eq!(
            rep.peers.len(),
            0,
            "snapshot must not allocate unknown peers"
        );

        let peer = PeerId::random();
        rep.add_peer_if_new(&peer);
        rep.on_event(&peer, ReputationEvent::InvalidTx);
        assert!(matches!(
            rep.get_peer_state(&peer),
            ReputationState::Banned { .. }
        ));
        assert!(rep.hard_ban_until_snapshot(&peer).is_some());
        assert!(rep.is_hard_banned_snapshot(&peer));
    }

    #[test]
    fn hard_ban_snapshot_treats_score_below_threshold_as_enforceable() {
        let mut rep = PeerReputationManager::new(ReputationConfig {
            persist_path: "reputation_test_hard_ban_score_threshold.json".into(),
            ban_threshold: 250,
            ..ReputationConfig::default()
        });
        let peer = PeerId::random();
        rep.add_peer_if_new(&peer);
        rep.peers.get_mut(&peer).unwrap().base_score = 200;
        rep.peers.get_mut(&peer).unwrap().banned_until = None;

        assert!(
            rep.hard_ban_until_snapshot(&peer).is_some(),
            "score below ban threshold must be treated as hard-ban enforceable"
        );
        assert!(
            rep.peers.get(&peer).unwrap().banned_until.is_none(),
            "snapshot checks must not materialize or persist a ban timer"
        );
    }
}
