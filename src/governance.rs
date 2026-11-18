use crate::block::Block;
use crate::checkpoint::{Checkpoint, CheckpointSig};
use crate::keyfmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{OnceLock, RwLock};

/// Governance (on-chain) — hardened validator operations:
/// - Validator keys are treated as Ed25519 public keys (32 bytes) in hex/base64 input forms.
/// - Canonical on-chain identity for validators is **HEX** (lowercase, 64 chars) to match `Block.miner_pub_key`.
/// - Council membership accepts either hex or base64 and is compared by decoded bytes (not string equality).
///
/// Signatures:
/// - `TxGovernanceProposal.signature` is base64(64 bytes ed25519) over domain-separated `proposal_signing_bytes_v1(...)`.
/// - `TxGovernanceVote.signature` is base64(64 bytes ed25519) over domain-separated `vote_signing_bytes_for_tx_v1(...)`.
///
/// NOTE (legacy/dev):
/// - Legacy/debug governance signatures are accepted only in cfg(test), or when
///   NEWGEN_ALLOW_LEGACY_GOV=1 is set and public mode is not enabled.
/// - Debug builds alone must not bypass governance signature verification.
// ----------------------
// Council & ruoli
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Council {
    /// Lista di chiavi pubbliche (ed25519) che fanno parte del council (base64 o hex).
    pub members: Vec<String>,
    /// Soglia M-of-N (quanti membri devono essere d'accordo). `0` = DISABILITATO (fail-closed).
    pub threshold: u8,
}

impl Council {
    /// Ritorna true se `pk_any` è un membro del council (confronto per bytes).
    pub fn is_member(&self, pk_any: &str) -> bool {
        if pk_any.trim().is_empty() {
            return false;
        }
        for m in &self.members {
            if keyfmt::eq_pk_any(m, pk_any) {
                return true;
            }
        }
        false
    }

    /// Ritorna l'insieme canonico (HEX) dei membri validi.
    pub fn members_hex_set(&self) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        for m in &self.members {
            if let Ok(h) = keyfmt::pk_hex_from_any(m) {
                set.insert(h);
            }
        }
        set
    }

    /// Normalizza la configurazione del council (fail-closed):
    /// - 0 membri => threshold=0
    /// - threshold=0 => DISABILITATO (non viene forzato a 1)
    /// - threshold > n_membri => clamp a n_membri
    pub fn normalize(&mut self, label: &str) {
        if self.members.is_empty() {
            eprintln!("[GOV] Council '{label}' ha 0 membri; threshold=0 (disabilitato).");
            self.threshold = 0;
            return;
        }

        if self.threshold == 0 {
            eprintln!(
                "[GOV] Council '{label}' ha threshold=0; governance DISABILITATA (fail-closed)."
            );
            return;
        }

        let max = self.members.len() as u8;
        if self.threshold > max {
            eprintln!(
                "[GOV] Council '{label}' aveva threshold={} > members={}; imposto threshold={}",
                self.threshold, max, max
            );
            self.threshold = max;
        }
    }
}

// ----------------------
// Tipi di proposta
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovProposalKind {
    UpdateValidators,
    UpdateEconomyPolicy,
    UpdateSecurityPolicy,
    BumpProtocolVersion,
    EmergencySafeModeOn,
    EmergencySafeModeOff,
    /// Modifica dei parametri di governance (timelock, quorum, ecc.)
    UpdateGovernanceParams,
    /// Aggiorna i parametri della reputazione (pesi eventi, soglie, ban, ecc.)
    UpdateReputationPolicy,
    /// Ingerisce in modo governato le evidenze run-plane nel wallet reputation plane canonico.
    IngestWalletReputationEvidence,
    /// Ingerisce in modo governato le evidenze E2 worker nel piano reputazionale canonico L1.
    IngestE2WorkerReputationEvidence,
    /// Lega una chiave tecnica worker E2 al wallet economico/canonico dell'operatore.
    ///
    /// Questo è un path governato/privilegiato. Il path ordinario per worker pubblici
    /// deve essere una self-registration L1 non-governance seguita da PROBATION/evidence.
    BindE2WorkerOperatorWallet,
    /// Concede a un worker E2 già registrato/bindato il privilegio Cloud Unit.
    GrantE2WorkerCloudUnit,
    /// Revoca il privilegio Cloud Unit a un worker E2.
    RevokeE2WorkerCloudUnit,
    /// Concede a un worker E2 già registrato/bindato il privilegio GPU/high-risk.
    GrantE2WorkerGpuCapability,
    /// Revoca il privilegio GPU/high-risk a un worker E2.
    RevokeE2WorkerGpuCapability,
    /// Concede a un worker E2 già registrato/bindato il privilegio critical workload.
    GrantE2WorkerCriticalWorkload,
    /// Revoca il privilegio critical workload a un worker E2.
    RevokeE2WorkerCriticalWorkload,
    /// Ingerisce proof di settlement fiat/simulated per compute job, senza muovere euro on-chain.
    IngestComputeFiatSettlementProof,
    /// Aggiorna i parametri della mempool (cap count/bytes, per-sender, TTL, ecc.)
    UpdateMempoolPolicy,

    // --- Validator ops hardened (BLOCKER #4) ---
    /// Ruota la chiave di un validator (old -> new), deterministica on-chain.
    RotateValidatorKey,
    /// Revoca un validator (temporanea o permanente) deterministica on-chain.
    RevokeValidator,
    /// Riammette un validator precedentemente revocato (se consentito).
    UnrevokeValidator,
    /// Operator Role Model V2: richiesta canonica validator -> compute-only con quorum guard.
    RequestValidatorComputeTransition,
    /// Operator Role Model V2: cancella una transition pending prima della finalizzazione.
    CancelValidatorComputeTransition,
}

/// Quale council è responsabile di una certa proposta.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceCouncilKind {
    Protocol,
    Economy,
    Emergency,
}

fn kind_tag(kind: &GovProposalKind) -> &'static str {
    match kind {
        GovProposalKind::UpdateValidators => "UpdateValidators",
        GovProposalKind::UpdateEconomyPolicy => "UpdateEconomyPolicy",
        GovProposalKind::UpdateSecurityPolicy => "UpdateSecurityPolicy",
        GovProposalKind::BumpProtocolVersion => "BumpProtocolVersion",
        GovProposalKind::EmergencySafeModeOn => "EmergencySafeModeOn",
        GovProposalKind::EmergencySafeModeOff => "EmergencySafeModeOff",
        GovProposalKind::UpdateGovernanceParams => "UpdateGovernanceParams",
        GovProposalKind::UpdateReputationPolicy => "UpdateReputationPolicy",
        GovProposalKind::IngestWalletReputationEvidence => "IngestWalletReputationEvidence",
        GovProposalKind::IngestE2WorkerReputationEvidence => "IngestE2WorkerReputationEvidence",
        GovProposalKind::BindE2WorkerOperatorWallet => "BindE2WorkerOperatorWallet",
        GovProposalKind::GrantE2WorkerCloudUnit => "GrantE2WorkerCloudUnit",
        GovProposalKind::RevokeE2WorkerCloudUnit => "RevokeE2WorkerCloudUnit",
        GovProposalKind::GrantE2WorkerGpuCapability => "GrantE2WorkerGpuCapability",
        GovProposalKind::RevokeE2WorkerGpuCapability => "RevokeE2WorkerGpuCapability",
        GovProposalKind::GrantE2WorkerCriticalWorkload => "GrantE2WorkerCriticalWorkload",
        GovProposalKind::RevokeE2WorkerCriticalWorkload => "RevokeE2WorkerCriticalWorkload",
        GovProposalKind::IngestComputeFiatSettlementProof => "IngestComputeFiatSettlementProof",
        GovProposalKind::UpdateMempoolPolicy => "UpdateMempoolPolicy",
        GovProposalKind::RotateValidatorKey => "RotateValidatorKey",
        GovProposalKind::RevokeValidator => "RevokeValidator",
        GovProposalKind::UnrevokeValidator => "UnrevokeValidator",
        GovProposalKind::RequestValidatorComputeTransition => "RequestValidatorComputeTransition",
        GovProposalKind::CancelValidatorComputeTransition => "CancelValidatorComputeTransition",
    }
}

fn council_tag(c: &GovernanceCouncilKind) -> &'static str {
    match c {
        GovernanceCouncilKind::Protocol => "Protocol",
        GovernanceCouncilKind::Economy => "Economy",
        GovernanceCouncilKind::Emergency => "Emergency",
    }
}

// ----------------------
// Downtime / jailing policy (minimal but deterministic)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DowntimePolicy {
    /// Se disabilitata, non si applicano jail/downtime (ma i campi restano per audit).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Quanti turni consecutivi mancati portano al jail.
    #[serde(default = "default_downtime_threshold")]
    pub consecutive_missed_turns_threshold: u64,
    /// Durata jail in blocchi.
    #[serde(default = "default_downtime_jail_blocks")]
    pub jail_duration_blocks: u64,
    /// Inactivity leak (penalità progressiva): accumula "debt" di slashing,
    /// che verrà tagliato dalle reward future e mandato a treasury.
    #[serde(default = "default_true")]
    pub inactivity_leak_enabled: bool,
    /// Base: bps per miss, scalata linearmente con `downtime_consecutive_missed_turns`.
    #[serde(default = "default_inactivity_leak_bps_per_miss")]
    pub inactivity_leak_bps_per_miss: u32, // 0..10_000
    /// Cap: massimo bps per singolo miss (evita runaway).
    #[serde(default = "default_inactivity_leak_bps_cap")]
    pub inactivity_leak_bps_cap: u32, // 0..10_000
}

fn default_true() -> bool {
    true
}
fn default_downtime_threshold() -> u64 {
    3
}
fn default_downtime_jail_blocks() -> u64 {
    120
}

// Inactivity leak (soft slashing) defaults.
// Units are basis points (bps). 10 bps = 0.10%.
fn default_inactivity_leak_bps_per_miss() -> u32 {
    10
}

fn default_inactivity_leak_bps_cap() -> u32 {
    200
}

impl Default for DowntimePolicy {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            consecutive_missed_turns_threshold: default_downtime_threshold(),
            jail_duration_blocks: default_downtime_jail_blocks(),
            inactivity_leak_enabled: default_true(),
            inactivity_leak_bps_per_miss: default_inactivity_leak_bps_per_miss(),
            inactivity_leak_bps_cap: default_inactivity_leak_bps_cap(),
        }
    }
}

// ----------------------
// Parametri globali di governance
// ----------------------

fn default_ft_activation_height() -> u64 {
    u64::MAX
}

fn default_ft_max_tokens_per_owner() -> u32 {
    100
}

fn default_ft_create_cooldown_blocks() -> u64 {
    0
}

fn default_ft_create_fee_native() -> u64 {
    0
}

fn default_nft_activation_height() -> u64 {
    u64::MAX
}

fn default_nft_max_collections_per_owner() -> u32 {
    100
}

fn default_nft_create_cooldown_blocks() -> u64 {
    0
}

fn default_nft_create_fee_native() -> u64 {
    0
}

fn default_nft_enabled() -> bool {
    false
}

fn default_nft_public_create_enabled() -> bool {
    false
}

fn default_nft_public_mint_enabled() -> bool {
    false
}

fn default_nft_public_transfer_enabled() -> bool {
    false
}

fn default_nft_public_approval_enabled() -> bool {
    false
}

fn default_nft_public_burn_enabled() -> bool {
    false
}

fn default_nft_public_revoke_enabled() -> bool {
    false
}

fn default_nft_public_metadata_update_enabled() -> bool {
    false
}

fn default_nft_public_freeze_enabled() -> bool {
    false
}

fn default_nft_public_policy_update_enabled() -> bool {
    false
}

fn default_nft_public_issuer_update_enabled() -> bool {
    false
}

fn default_nft_public_pause_enabled() -> bool {
    false
}

fn default_nft_metadata_hash_required() -> bool {
    true
}

fn default_nft_max_memo_bytes() -> u32 {
    crate::nft::NFTV1_MEMO_MAX_BYTES as u32
}

fn default_nft_max_uri_bytes() -> u32 {
    crate::nft::NFTV1_URI_MAX_BYTES as u32
}

fn default_nft_max_name_bytes() -> u32 {
    crate::nft::NFTV1_NAME_MAX_BYTES as u32
}

fn default_nft_max_symbol_bytes() -> u32 {
    crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32
}

fn default_nft_max_tokens_per_collection() -> u64 {
    0
}

fn default_nft_max_tokens_per_owner() -> u64 {
    0
}

fn default_nft_mint_fee_native() -> u64 {
    0
}

fn default_nft_transfer_fee_native() -> u64 {
    0
}

fn default_nft_approval_fee_native() -> u64 {
    0
}

fn default_nft_burn_fee_native() -> u64 {
    0
}

fn default_nft_revoke_fee_native() -> u64 {
    0
}

fn default_nft_metadata_update_fee_native() -> u64 {
    0
}

fn default_nft_freeze_fee_native() -> u64 {
    0
}

fn default_nft_policy_update_fee_native() -> u64 {
    0
}

fn default_nft_issuer_update_fee_native() -> u64 {
    0
}

fn default_nft_pause_fee_native() -> u64 {
    0
}

fn default_wallet_reputation_promotion_quorum() -> u32 {
    2
}

fn default_e2_worker_admission_activation_height() -> u64 {
    0
}

fn default_governance_proposal_max_lifetime_blocks_v1() -> u64 {
    // Mainnet-grade default: a proposal cannot remain Pending forever.
    // This is intentionally large enough for public validator operations while
    // still bounding WAL/replay/state growth and stale approval risk.
    100_000
}

fn default_validator_compute_transition_min_active_validators() -> usize {
    2
}

fn default_validator_compute_transition_min_finality_quorum() -> usize {
    2
}

fn default_validator_compute_transition_validator_quality_floor() -> u32 {
    600
}

fn default_validator_compute_transition_exit_cooldown_blocks() -> u64 {
    10
}

fn default_validator_compute_transition_max_finality_lag_blocks() -> u64 {
    2
}

fn default_validator_compute_transition_max_recent_missed_slots() -> u64 {
    3
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Timelock minimo per tutte le proposte "normali"
    /// effective_height >= current_height + min_timelock_blocks
    pub min_timelock_blocks: u64,

    /// Maximum number of blocks a proposal may remain Pending after creation.
    /// Zero/legacy values are normalized to a safe default.
    #[serde(default = "default_governance_proposal_max_lifetime_blocks_v1")]
    pub max_proposal_lifetime_blocks: u64,

    /// Durata massima della modalità emergenza (in blocchi).
    /// Dopo questo limite, anche senza proposta "Off", la rete rientra in regime normale.
    pub max_emergency_duration_blocks: u64,

    /// Quante fonti canoniche distinte devono supportare lo stesso claim run-plane
    /// prima della promozione nel wallet-plane canonico. Fail-closed: valori legacy/invalidi
    /// vengono normalizzati al default sicuro.
    #[serde(default = "default_wallet_reputation_promotion_quorum")]
    pub wallet_reputation_promotion_quorum: u32,

    /// Height from which E2 worker order-claim admission consumes the canonical L1 reputation surface.
    /// Default 0 = enforce from genesis on new networks. Governance may move it forward for legacy chains.
    #[serde(default = "default_e2_worker_admission_activation_height")]
    pub e2_worker_admission_activation_height: u64,

    /// Operator Role Model V2: minimum active validators that must remain after a validator exits to compute-only.
    #[serde(
        default = "default_validator_compute_transition_min_active_validators",
        alias = "min_active_validators"
    )]
    pub validator_compute_transition_min_active_validators: usize,

    /// Operator Role Model V2: minimum finality quorum capacity that must remain after validator exit.
    #[serde(
        default = "default_validator_compute_transition_min_finality_quorum",
        alias = "min_finality_quorum"
    )]
    pub validator_compute_transition_min_finality_quorum: usize,

    /// Operator Role Model V2: minimum quality score required for every remaining validator.
    #[serde(
        default = "default_validator_compute_transition_validator_quality_floor",
        alias = "validator_quality_floor"
    )]
    pub validator_compute_transition_validator_quality_floor: u32,

    /// Operator Role Model V2: mandatory cooldown before pending validator exit can finalize.
    #[serde(
        default = "default_validator_compute_transition_exit_cooldown_blocks",
        alias = "validator_exit_cooldown_blocks"
    )]
    pub validator_compute_transition_exit_cooldown_blocks: u64,

    /// Operator Role Model V2: maximum allowed chain tip - finalized height lag at final check.
    #[serde(
        default = "default_validator_compute_transition_max_finality_lag_blocks",
        alias = "max_finality_lag_blocks"
    )]
    pub validator_compute_transition_max_finality_lag_blocks: u64,

    /// Operator Role Model V2: maximum consecutive missed slots allowed for remaining validators.
    #[serde(
        default = "default_validator_compute_transition_max_recent_missed_slots",
        alias = "max_recent_missed_slots"
    )]
    pub validator_compute_transition_max_recent_missed_slots: u64,

    /// FT v1 activation height (Gate 4). u64::MAX = disabled
    #[serde(default = "default_ft_activation_height")]
    pub ft_activation_height: u64,

    /// Anti-spam: max tokens creati per owner (soft cap).
    #[serde(default = "default_ft_max_tokens_per_owner")]
    pub ft_max_tokens_per_owner: u32,

    /// Anti-spam: cooldown blocks tra create_token dello stesso owner.
    #[serde(default = "default_ft_create_cooldown_blocks")]
    pub ft_create_cooldown_blocks: u64,

    /// Anti-spam: additional native fee charged on CreateToken.
    /// 0 = disabled.
    #[serde(default = "default_ft_create_fee_native")]
    pub ft_create_fee_native: u64,

    /// NFT v1 activation height. u64::MAX = disabled.
    #[serde(default = "default_nft_activation_height")]
    pub nft_activation_height: u64,

    /// Anti-spam: max collections created per owner.
    #[serde(default = "default_nft_max_collections_per_owner")]
    pub nft_max_collections_per_owner: u32,

    /// Anti-spam: cooldown blocks between create_collection by same owner.
    #[serde(default = "default_nft_create_cooldown_blocks")]
    pub nft_create_cooldown_blocks: u64,

    /// Anti-spam: additional native fee charged on CreateCollection.
    #[serde(default = "default_nft_create_fee_native")]
    pub nft_create_fee_native: u64,

    /// Master gate. Even if activation height is reached, NFT state mutations remain disabled unless true.
    #[serde(default = "default_nft_enabled")]
    pub nft_enabled: bool,

    /// Public create_collection gate.
    #[serde(default = "default_nft_public_create_enabled")]
    pub nft_public_create_enabled: bool,

    /// Public mint gate.
    #[serde(default = "default_nft_public_mint_enabled")]
    pub nft_public_mint_enabled: bool,

    /// Public transfer gate.
    #[serde(default = "default_nft_public_transfer_enabled")]
    pub nft_public_transfer_enabled: bool,

    /// Public approve / approve_all gate.
    #[serde(default = "default_nft_public_approval_enabled")]
    pub nft_public_approval_enabled: bool,

    /// Public burn gate.
    #[serde(default = "default_nft_public_burn_enabled")]
    pub nft_public_burn_enabled: bool,

    /// Public issuer revoke gate. Revoke is issuer-driven and intentionally separate from user burn.
    #[serde(default = "default_nft_public_revoke_enabled")]
    pub nft_public_revoke_enabled: bool,

    /// Public metadata update gate for token/collection URI+metadata hash updates.
    #[serde(default = "default_nft_public_metadata_update_enabled")]
    pub nft_public_metadata_update_enabled: bool,

    /// Public issuer freeze/unfreeze gate.
    #[serde(default = "default_nft_public_freeze_enabled")]
    pub nft_public_freeze_enabled: bool,

    /// Public collection policy update gate.
    #[serde(default = "default_nft_public_policy_update_enabled")]
    pub nft_public_policy_update_enabled: bool,

    /// Public issuer rotation gate.
    #[serde(default = "default_nft_public_issuer_update_enabled")]
    pub nft_public_issuer_update_enabled: bool,

    /// Public pause/unpause gate.
    #[serde(default = "default_nft_public_pause_enabled")]
    pub nft_public_pause_enabled: bool,

    /// Mainnet-grade metadata policy. Current NFT v1 keeps this true; governance may not disable it.
    #[serde(default = "default_nft_metadata_hash_required")]
    pub nft_metadata_hash_required: bool,

    /// Policy upper bound for NFT memo bytes. Must be <= NFTV1_MEMO_MAX_BYTES.
    #[serde(default = "default_nft_max_memo_bytes")]
    pub nft_max_memo_bytes: u32,

    /// Policy upper bound for base_uri/token_uri bytes. Must be <= NFTV1_URI_MAX_BYTES.
    #[serde(default = "default_nft_max_uri_bytes")]
    pub nft_max_uri_bytes: u32,

    /// Policy upper bound for collection name bytes. Must be <= NFTV1_NAME_MAX_BYTES.
    #[serde(default = "default_nft_max_name_bytes")]
    pub nft_max_name_bytes: u32,

    /// Policy upper bound for collection symbol bytes. Must be <= NFTV1_SYMBOL_MAX_BYTES.
    #[serde(default = "default_nft_max_symbol_bytes")]
    pub nft_max_symbol_bytes: u32,

    /// Global cap per collection. 0 = disabled, collection max_supply still applies.
    #[serde(default = "default_nft_max_tokens_per_collection")]
    pub nft_max_tokens_per_collection: u64,

    /// Global cap per owner wallet. 0 = disabled. Enforced on mint and inbound transfer.
    #[serde(default = "default_nft_max_tokens_per_owner")]
    pub nft_max_tokens_per_owner: u64,

    /// Additional native fee charged on Mint.
    #[serde(default = "default_nft_mint_fee_native")]
    pub nft_mint_fee_native: u64,

    /// Additional native fee charged on Transfer.
    #[serde(default = "default_nft_transfer_fee_native")]
    pub nft_transfer_fee_native: u64,

    /// Additional native fee charged on Approve/ApproveAll.
    #[serde(default = "default_nft_approval_fee_native")]
    pub nft_approval_fee_native: u64,

    /// Additional native fee charged on Burn.
    #[serde(default = "default_nft_burn_fee_native")]
    pub nft_burn_fee_native: u64,

    /// Additional native fee charged on issuer Revoke.
    #[serde(default = "default_nft_revoke_fee_native")]
    pub nft_revoke_fee_native: u64,

    /// Additional native fee charged on token/collection metadata updates.
    #[serde(default = "default_nft_metadata_update_fee_native")]
    pub nft_metadata_update_fee_native: u64,

    /// Additional native fee charged on FreezeToken/UnfreezeToken.
    #[serde(default = "default_nft_freeze_fee_native")]
    pub nft_freeze_fee_native: u64,

    /// Additional native fee charged on collection policy updates.
    #[serde(default = "default_nft_policy_update_fee_native")]
    pub nft_policy_update_fee_native: u64,

    /// Additional native fee charged on issuer rotation.
    #[serde(default = "default_nft_issuer_update_fee_native")]
    pub nft_issuer_update_fee_native: u64,

    /// Additional native fee charged on Pause/Unpause.
    #[serde(default = "default_nft_pause_fee_native")]
    pub nft_pause_fee_native: u64,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_timelock_blocks: 0,
            max_proposal_lifetime_blocks: default_governance_proposal_max_lifetime_blocks_v1(),
            max_emergency_duration_blocks: 0,
            wallet_reputation_promotion_quorum: default_wallet_reputation_promotion_quorum(),
            e2_worker_admission_activation_height: default_e2_worker_admission_activation_height(),
            validator_compute_transition_min_active_validators:
                default_validator_compute_transition_min_active_validators(),
            validator_compute_transition_min_finality_quorum:
                default_validator_compute_transition_min_finality_quorum(),
            validator_compute_transition_validator_quality_floor:
                default_validator_compute_transition_validator_quality_floor(),
            validator_compute_transition_exit_cooldown_blocks:
                default_validator_compute_transition_exit_cooldown_blocks(),
            validator_compute_transition_max_finality_lag_blocks:
                default_validator_compute_transition_max_finality_lag_blocks(),
            validator_compute_transition_max_recent_missed_slots:
                default_validator_compute_transition_max_recent_missed_slots(),
            ft_activation_height: u64::MAX,
            ft_max_tokens_per_owner: default_ft_max_tokens_per_owner(),
            ft_create_cooldown_blocks: default_ft_create_cooldown_blocks(),
            ft_create_fee_native: default_ft_create_fee_native(),
            nft_activation_height: default_nft_activation_height(),
            nft_max_collections_per_owner: default_nft_max_collections_per_owner(),
            nft_create_cooldown_blocks: default_nft_create_cooldown_blocks(),
            nft_create_fee_native: default_nft_create_fee_native(),
            nft_enabled: default_nft_enabled(),
            nft_public_create_enabled: default_nft_public_create_enabled(),
            nft_public_mint_enabled: default_nft_public_mint_enabled(),
            nft_public_transfer_enabled: default_nft_public_transfer_enabled(),
            nft_public_approval_enabled: default_nft_public_approval_enabled(),
            nft_public_burn_enabled: default_nft_public_burn_enabled(),
            nft_public_revoke_enabled: default_nft_public_revoke_enabled(),
            nft_public_metadata_update_enabled: default_nft_public_metadata_update_enabled(),
            nft_public_freeze_enabled: default_nft_public_freeze_enabled(),
            nft_public_policy_update_enabled: default_nft_public_policy_update_enabled(),
            nft_public_issuer_update_enabled: default_nft_public_issuer_update_enabled(),
            nft_public_pause_enabled: default_nft_public_pause_enabled(),
            nft_metadata_hash_required: default_nft_metadata_hash_required(),
            nft_max_memo_bytes: default_nft_max_memo_bytes(),
            nft_max_uri_bytes: default_nft_max_uri_bytes(),
            nft_max_name_bytes: default_nft_max_name_bytes(),
            nft_max_symbol_bytes: default_nft_max_symbol_bytes(),
            nft_max_tokens_per_collection: default_nft_max_tokens_per_collection(),
            nft_max_tokens_per_owner: default_nft_max_tokens_per_owner(),
            nft_mint_fee_native: default_nft_mint_fee_native(),
            nft_transfer_fee_native: default_nft_transfer_fee_native(),
            nft_approval_fee_native: default_nft_approval_fee_native(),
            nft_burn_fee_native: default_nft_burn_fee_native(),
            nft_revoke_fee_native: default_nft_revoke_fee_native(),
            nft_metadata_update_fee_native: default_nft_metadata_update_fee_native(),
            nft_freeze_fee_native: default_nft_freeze_fee_native(),
            nft_policy_update_fee_native: default_nft_policy_update_fee_native(),
            nft_issuer_update_fee_native: default_nft_issuer_update_fee_native(),
            nft_pause_fee_native: default_nft_pause_fee_native(),
        }
    }
}

// ----------------------
// Validator set & reputazione on-chain
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// Chiave pubblica / address del validator (canonico: HEX per consensus).
    pub pub_key: String,

    /// Nome leggibile (accetta sia "alias" che "label" dal JSON)
    #[serde(default, alias = "label")]
    pub alias: Option<String>,

    /// Peso (per futuro PoA weighted). Default=1 se assente.
    #[serde(default = "default_validator_weight")]
    pub weight: u32,
}

fn default_validator_weight() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ValidatorSet {
    pub entries: Vec<ValidatorEntry>,
    /// Versione del set (incrementata a ogni aggiornamento via governance)
    pub version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSetPayload {
    /// Nuova lista di validator proposta
    pub entries: Vec<ValidatorEntry>,
    /// Nuova versione del set (deve essere > current.version)
    pub version: u32,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ValidatorGovReputation {
    /// Punti di misbehavior accumulati (eventi oggettivi on-chain)
    pub misbehavior_points: u32,
    /// Quante volte è stato "slashed" / punito
    pub slashed_count: u32,
    /// Altezza dell'ultimo evento di slashing
    pub last_slash_height: u64,
    /// Se true, il validator è revocato dal set (deterministico on-chain).
    pub temporarily_revoked: bool,
    /// Se Some(h), non può rientrare prima di quella height (revoca temporanea).
    /// Se None e temporarily_revoked=true => revoca permanente.
    pub banned_until_height: Option<u64>,

    // --- downtime/jail (deterministico; enforcement in blockchain.rs) ---
    #[serde(default)]
    pub jailed_until_height: Option<u64>,
    /// Altezza da cui il jail è attivo (inclusiva). Se None, compatibilità legacy: jail attivo da 0.
    #[serde(default)]
    pub jailed_from_height: Option<u64>,
    #[serde(default)]
    pub downtime_missed_turns_total: u64,
    #[serde(default)]
    pub downtime_consecutive_missed_turns: u64,
    /// Ultima altezza in cui il validator ha effettivamente prodotto un blocco.
    #[serde(default)]
    pub last_produced_height: u64,
    /// Ultima altezza in cui il validator è stato osservato valido nel flusso chain/consensus.
    #[serde(default)]
    pub last_seen_height: u64,
    #[serde(default)]
    pub accepted_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_positive_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_negative_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_run_evidence_delta_total: i64,
    #[serde(default)]
    pub timeout_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    #[serde(default)]
    pub recent_window_start_height: u64,
    #[serde(default)]
    pub recent_timeout_count: u64,
    #[serde(default)]
    pub recent_failure_count: u64,
    #[serde(default)]
    pub recent_invalid_output_count: u64,
    #[serde(default)]
    pub consecutive_failures: u64,
    #[serde(default)]
    pub consecutive_timeouts: u64,
    #[serde(default)]
    pub last_hard_fault_height: Option<u64>,
    #[serde(default)]
    pub failed_recovery_probe_count: u64,
    #[serde(default)]
    pub last_run_evidence_height: Option<u64>,
    #[serde(default)]
    pub last_run_evidence_id: Option<String>,
    #[serde(default)]
    pub promoted_run_claim_count: u64,
    #[serde(default)]
    pub promoted_positive_run_claim_count: u64,
    #[serde(default)]
    pub promoted_negative_run_claim_count: u64,
    #[serde(default)]
    pub promoted_run_claim_delta_total: i64,
    #[serde(default)]
    pub last_promoted_run_claim_height: Option<u64>,
    #[serde(default)]
    pub last_promoted_run_claim_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
struct ValidatorGovReputationWire {
    #[serde(default)]
    misbehavior_points: u32,
    #[serde(default)]
    slashed_count: u32,
    #[serde(default)]
    last_slash_height: u64,
    #[serde(default)]
    temporarily_revoked: bool,
    #[serde(default)]
    banned_until_height: Option<u64>,
    #[serde(default)]
    jailed_until_height: Option<u64>,
    #[serde(default)]
    jailed_from_height: Option<u64>,
    #[serde(default)]
    downtime_missed_turns_total: u64,
    #[serde(default)]
    downtime_consecutive_missed_turns: u64,
    #[serde(default)]
    last_produced_height: Option<u64>,
    #[serde(default)]
    last_seen_height: Option<u64>,
    #[serde(default)]
    accepted_run_evidence_count: u64,
    #[serde(default)]
    accepted_positive_run_evidence_count: u64,
    #[serde(default)]
    accepted_negative_run_evidence_count: u64,
    #[serde(default)]
    accepted_run_evidence_delta_total: i64,
    #[serde(default)]
    timeout_count: u64,
    #[serde(default)]
    failure_count: u64,
    #[serde(default)]
    recent_window_start_height: u64,
    #[serde(default)]
    recent_timeout_count: u64,
    #[serde(default)]
    recent_failure_count: u64,
    #[serde(default)]
    recent_invalid_output_count: u64,
    #[serde(default)]
    consecutive_failures: u64,
    #[serde(default)]
    consecutive_timeouts: u64,
    #[serde(default)]
    last_hard_fault_height: Option<u64>,
    #[serde(default)]
    failed_recovery_probe_count: u64,
    #[serde(default)]
    last_run_evidence_height: Option<u64>,
    #[serde(default)]
    last_run_evidence_id: Option<String>,
    #[serde(default)]
    promoted_run_claim_count: u64,
    #[serde(default)]
    promoted_positive_run_claim_count: u64,
    #[serde(default)]
    promoted_negative_run_claim_count: u64,
    #[serde(default)]
    promoted_run_claim_delta_total: i64,
    #[serde(default)]
    last_promoted_run_claim_height: Option<u64>,
    #[serde(default)]
    last_promoted_run_claim_id: Option<String>,
}

impl<'de> Deserialize<'de> for ValidatorGovReputation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ValidatorGovReputationWire::deserialize(deserializer)?;
        let last_produced_height = wire
            .last_produced_height
            .or(wire.last_seen_height)
            .unwrap_or(0);
        let last_seen_height = wire
            .last_seen_height
            .or(wire.last_produced_height)
            .unwrap_or(0)
            .max(last_produced_height);

        Ok(Self {
            misbehavior_points: wire.misbehavior_points,
            slashed_count: wire.slashed_count,
            last_slash_height: wire.last_slash_height,
            temporarily_revoked: wire.temporarily_revoked,
            banned_until_height: wire.banned_until_height,
            jailed_until_height: wire.jailed_until_height,
            jailed_from_height: wire.jailed_from_height,
            downtime_missed_turns_total: wire.downtime_missed_turns_total,
            downtime_consecutive_missed_turns: wire.downtime_consecutive_missed_turns,
            last_produced_height,
            last_seen_height,
            accepted_run_evidence_count: wire.accepted_run_evidence_count,
            accepted_positive_run_evidence_count: wire.accepted_positive_run_evidence_count,
            accepted_negative_run_evidence_count: wire.accepted_negative_run_evidence_count,
            accepted_run_evidence_delta_total: wire.accepted_run_evidence_delta_total,
            timeout_count: wire.timeout_count,
            failure_count: wire.failure_count,
            recent_window_start_height: wire.recent_window_start_height,
            recent_timeout_count: wire.recent_timeout_count,
            recent_failure_count: wire.recent_failure_count,
            recent_invalid_output_count: wire.recent_invalid_output_count,
            consecutive_failures: wire.consecutive_failures,
            consecutive_timeouts: wire.consecutive_timeouts,
            last_hard_fault_height: wire.last_hard_fault_height,
            failed_recovery_probe_count: wire.failed_recovery_probe_count,
            last_run_evidence_height: wire.last_run_evidence_height,
            last_run_evidence_id: wire.last_run_evidence_id,
            promoted_run_claim_count: wire.promoted_run_claim_count,
            promoted_positive_run_claim_count: wire.promoted_positive_run_claim_count,
            promoted_negative_run_claim_count: wire.promoted_negative_run_claim_count,
            promoted_run_claim_delta_total: wire.promoted_run_claim_delta_total,
            last_promoted_run_claim_height: wire.last_promoted_run_claim_height,
            last_promoted_run_claim_id: wire.last_promoted_run_claim_id,
        })
    }
}

impl ValidatorGovReputation {
    pub fn record_seen_at_height(&mut self, height: u64) {
        self.last_seen_height = self.last_seen_height.max(height);
    }

    pub fn record_produced_block_at_height(&mut self, height: u64) {
        self.last_produced_height = self.last_produced_height.max(height);
        self.record_seen_at_height(height);
    }

    pub fn reset_recent_reputation_window_if_stale(&mut self, height: u64) {
        if self.recent_window_start_height == 0 {
            self.recent_window_start_height = height;
            return;
        }
        if height.saturating_sub(self.recent_window_start_height)
            > crate::e2_worker_evidence::E2_WORKER_REPUTATION_RECENT_WINDOW_BLOCKS_V1
        {
            self.recent_window_start_height = height;
            self.recent_timeout_count = 0;
            self.recent_failure_count = 0;
            self.recent_invalid_output_count = 0;
        }
    }

    pub fn is_revoked_at(&self, h: u64) -> bool {
        if !self.temporarily_revoked {
            return false;
        }
        match self.banned_until_height {
            Some(until) => h < until,
            None => true,
        }
    }

    pub fn is_jailed_at(&self, h: u64) -> bool {
        match (self.jailed_from_height, self.jailed_until_height) {
            (Some(from), Some(until)) => h >= from && h < until,
            // Compatibilità legacy: se esiste solo `until`, considera jail attivo "da sempre" fino a `until`.
            (None, Some(until)) => h < until,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletMisconductKindV1 {
    InvalidGovernanceProposalSpam,
    MaliciousEvidenceSubmission,
    SignatureFraud,
    DoubleClaim,
    ReplayProven,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletMisconductSeverityV1 {
    Light,
    Medium,
    HardGovernanceCandidate,
}

impl WalletMisconductKindV1 {
    pub fn severity_v1(&self) -> WalletMisconductSeverityV1 {
        match self {
            WalletMisconductKindV1::InvalidGovernanceProposalSpam => {
                WalletMisconductSeverityV1::Light
            }
            WalletMisconductKindV1::ReplayProven => WalletMisconductSeverityV1::Medium,
            WalletMisconductKindV1::MaliciousEvidenceSubmission
            | WalletMisconductKindV1::SignatureFraud
            | WalletMisconductKindV1::DoubleClaim => {
                WalletMisconductSeverityV1::HardGovernanceCandidate
            }
        }
    }

    pub fn misbehavior_points_v1(&self) -> u32 {
        match self {
            WalletMisconductKindV1::InvalidGovernanceProposalSpam => 5,
            WalletMisconductKindV1::ReplayProven => 20,
            WalletMisconductKindV1::MaliciousEvidenceSubmission => 35,
            WalletMisconductKindV1::SignatureFraud => 50,
            WalletMisconductKindV1::DoubleClaim => 50,
        }
    }
}

pub const WALLET_GOVERNANCE_INVALID_PROPOSAL_WINDOW_BLOCKS_V1: u64 = 10_000;
pub const WALLET_GOVERNANCE_INVALID_PROPOSAL_SPAM_THRESHOLD_V1: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WalletGovernanceInvalidProposalWindowV1 {
    pub window_start_height: u64,
    pub invalid_governance_proposal_count: u32,
    pub recent_invalid_governance_proposal_count: u32,
    pub last_invalid_governance_proposal_height: u64,
    #[serde(default)]
    pub spam_misconduct_applied_in_window: bool,
}

impl WalletGovernanceInvalidProposalWindowV1 {
    pub fn reset_if_stale(&mut self, height: u64) {
        if self.window_start_height == 0 {
            self.window_start_height = height;
            return;
        }
        if height.saturating_sub(self.window_start_height)
            > WALLET_GOVERNANCE_INVALID_PROPOSAL_WINDOW_BLOCKS_V1
        {
            self.window_start_height = height;
            self.recent_invalid_governance_proposal_count = 0;
            self.spam_misconduct_applied_in_window = false;
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WalletGovReputation {
    /// Wallet / validator identity in canonical lowercase HEX when available.
    pub wallet_pubkey: String,
    /// If this wallet currently corresponds to a validator entry, keep the canonical binding explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    #[serde(default)]
    pub validator_set_member: bool,
    /// Legacy/advisory height where worker_node_pubkey -> operator_wallet_pubkey binding became canonical.
    /// New worker eligibility must consume GovernanceState::e2_worker_operator_bindings instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_operator_binding_height: Option<u64>,
    /// Legacy/primary operator-wallet mirror of the first active worker binding.
    ///
    /// Operator Role Model V2 allows one operator wallet to own multiple worker
    /// node bindings. This field is kept as a backwards-compatible primary worker
    /// mirror for older dashboards/tests/clients that still expect a single worker.
    /// New eligibility/admission must read GovernanceState::e2_worker_operator_bindings
    /// or operator_bound_worker_pubkeys instead of treating this field as unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_bound_worker_pubkey: Option<String>,
    /// Canonical mirror of all active worker bindings owned by this operator wallet.
    /// Values are normalized lowercase HEX pubkeys. The vector is sorted/deduped by
    /// update helpers and is advisory; the authoritative registry remains
    /// GovernanceState::e2_worker_operator_bindings keyed by worker pubkey.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operator_bound_worker_pubkeys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_binding_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_binding_status: Option<String>,
    pub misbehavior_points: u32,
    pub slashed_count: u32,
    pub last_slash_height: u64,
    pub temporarily_revoked: bool,
    pub banned_until_height: Option<u64>,
    #[serde(default)]
    pub jailed_until_height: Option<u64>,
    #[serde(default)]
    pub jailed_from_height: Option<u64>,
    #[serde(default)]
    pub downtime_missed_turns_total: u64,
    #[serde(default)]
    pub downtime_consecutive_missed_turns: u64,
    #[serde(default)]
    pub last_produced_height: u64,
    #[serde(default)]
    pub last_seen_height: u64,
    #[serde(default)]
    pub accepted_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_positive_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_negative_run_evidence_count: u64,
    #[serde(default)]
    pub accepted_run_evidence_delta_total: i64,
    #[serde(default)]
    pub timeout_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    #[serde(default)]
    pub recent_window_start_height: u64,
    #[serde(default)]
    pub recent_timeout_count: u64,
    #[serde(default)]
    pub recent_failure_count: u64,
    #[serde(default)]
    pub recent_invalid_output_count: u64,
    #[serde(default)]
    pub consecutive_failures: u64,
    #[serde(default)]
    pub consecutive_timeouts: u64,
    #[serde(default)]
    pub last_hard_fault_height: Option<u64>,
    #[serde(default)]
    pub failed_recovery_probe_count: u64,
    #[serde(default)]
    pub last_run_evidence_height: Option<u64>,
    #[serde(default)]
    pub last_run_evidence_id: Option<String>,
    #[serde(default)]
    pub promoted_run_claim_count: u64,
    #[serde(default)]
    pub promoted_positive_run_claim_count: u64,
    #[serde(default)]
    pub promoted_negative_run_claim_count: u64,
    #[serde(default)]
    pub promoted_run_claim_delta_total: i64,
    #[serde(default)]
    pub last_promoted_run_claim_height: Option<u64>,
    #[serde(default)]
    pub last_promoted_run_claim_id: Option<String>,
}

impl WalletGovReputation {
    pub fn record_seen_at_height(&mut self, height: u64) {
        self.last_seen_height = self.last_seen_height.max(height);
    }

    pub fn note_operator_worker_binding_v2(&mut self, worker_hex: impl Into<String>, height: u64) {
        let worker_hex = worker_hex.into();
        if self.operator_bound_worker_pubkey.is_none() {
            self.operator_bound_worker_pubkey = Some(worker_hex.clone());
        }
        if let Some(primary) = self.operator_bound_worker_pubkey.clone() {
            if !self
                .operator_bound_worker_pubkeys
                .iter()
                .any(|pk| pk == &primary)
            {
                self.operator_bound_worker_pubkeys.push(primary);
            }
        }
        if !self
            .operator_bound_worker_pubkeys
            .iter()
            .any(|pk| pk == &worker_hex)
        {
            self.operator_bound_worker_pubkeys.push(worker_hex);
        }
        self.operator_bound_worker_pubkeys.sort();
        self.operator_bound_worker_pubkeys.dedup();
        self.operator_binding_height = self.operator_binding_height.or(Some(height));
        self.operator_binding_status = Some("ACTIVE".to_string());
        self.worker_operator_binding_height = None;
        self.last_seen_height = self.last_seen_height.max(height);
    }

    pub fn reset_recent_reputation_window_if_stale(&mut self, height: u64) {
        if self.recent_window_start_height == 0 {
            self.recent_window_start_height = height;
            return;
        }
        if height.saturating_sub(self.recent_window_start_height)
            > crate::e2_worker_evidence::E2_WORKER_REPUTATION_RECENT_WINDOW_BLOCKS_V1
        {
            self.recent_window_start_height = height;
            self.recent_timeout_count = 0;
            self.recent_failure_count = 0;
            self.recent_invalid_output_count = 0;
        }
    }

    pub fn from_validator_reputation(
        wallet_pubkey: &str,
        validator_pubkey: Option<String>,
        validator_set_member: bool,
        rep: &ValidatorGovReputation,
    ) -> Self {
        Self {
            wallet_pubkey: wallet_pubkey.to_string(),
            validator_pubkey,
            validator_set_member,
            worker_operator_binding_height: None,
            operator_bound_worker_pubkey: None,
            operator_bound_worker_pubkeys: Vec::new(),
            operator_binding_height: None,
            operator_binding_status: None,
            misbehavior_points: rep.misbehavior_points,
            slashed_count: rep.slashed_count,
            last_slash_height: rep.last_slash_height,
            temporarily_revoked: rep.temporarily_revoked,
            banned_until_height: rep.banned_until_height,
            jailed_until_height: rep.jailed_until_height,
            jailed_from_height: rep.jailed_from_height,
            downtime_missed_turns_total: rep.downtime_missed_turns_total,
            downtime_consecutive_missed_turns: rep.downtime_consecutive_missed_turns,
            last_produced_height: rep.last_produced_height,
            last_seen_height: rep.last_seen_height,
            accepted_run_evidence_count: rep.accepted_run_evidence_count,
            accepted_positive_run_evidence_count: rep.accepted_positive_run_evidence_count,
            accepted_negative_run_evidence_count: rep.accepted_negative_run_evidence_count,
            accepted_run_evidence_delta_total: rep.accepted_run_evidence_delta_total,
            timeout_count: rep.timeout_count,
            failure_count: rep.failure_count,
            recent_window_start_height: rep.recent_window_start_height,
            recent_timeout_count: rep.recent_timeout_count,
            recent_failure_count: rep.recent_failure_count,
            recent_invalid_output_count: rep.recent_invalid_output_count,
            consecutive_failures: rep.consecutive_failures,
            consecutive_timeouts: rep.consecutive_timeouts,
            last_hard_fault_height: rep.last_hard_fault_height,
            failed_recovery_probe_count: rep.failed_recovery_probe_count,
            last_run_evidence_height: rep.last_run_evidence_height,
            last_run_evidence_id: rep.last_run_evidence_id.clone(),
            promoted_run_claim_count: rep.promoted_run_claim_count,
            promoted_positive_run_claim_count: rep.promoted_positive_run_claim_count,
            promoted_negative_run_claim_count: rep.promoted_negative_run_claim_count,
            promoted_run_claim_delta_total: rep.promoted_run_claim_delta_total,
            last_promoted_run_claim_height: rep.last_promoted_run_claim_height,
            last_promoted_run_claim_id: rep.last_promoted_run_claim_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletReputationEvidenceIngestItem {
    #[serde(default)]
    pub claim_id: String,
    #[serde(default)]
    pub evidence_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_attester_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_attester_sig_b64: Option<String>,
    pub wallet_pubkey: String,
    pub peer_id: String,
    pub event: String,
    pub score_before: i32,
    pub score_after: i32,
    pub applied_delta: i32,
    pub trust_tier: String,
    pub observed_at_secs: u64,
    pub binding_source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletReputationEvidenceIngestPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_attester_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tip_height: Option<u64>,
    pub evidences: Vec<WalletReputationEvidenceIngestItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletReputationCanonicalEvidence {
    pub claim_id: String,
    pub evidence_id: String,
    pub wallet_pubkey: String,
    pub peer_id: String,
    pub event: String,
    pub score_before: i32,
    pub score_after: i32,
    pub applied_delta: i32,
    pub trust_tier: String,
    pub observed_at_secs: u64,
    pub binding_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_attester_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_attester_sig_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tip_height: Option<u64>,
    /// Payload-level telemetry copied from the bridge. This is intentionally advisory-only and
    /// is not part of the source-attester signature or promotion quorum semantics.
    #[serde(default)]
    pub source_tip_height_advisory: bool,
    pub proposal_id: String,
    pub ingested_at_height: u64,
    pub council: GovernanceCouncilKind,
}

const WALLET_REPUTATION_CLAIM_WINDOW_SECS: u64 = 30;

pub fn canonical_wallet_reputation_source_attester(attester_any: &str) -> Option<String> {
    let trimmed = attester_any.trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::keyfmt::pk_hex_from_any(trimmed).ok().or_else(|| {
        let lower = trimmed.to_ascii_lowercase();
        if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(lower)
        } else {
            None
        }
    })
}

pub fn wallet_reputation_claim_id_v1_fields(
    wallet_pubkey_any: &str,
    peer_id: &str,
    event: &str,
    _score_before: i32,
    _score_after: i32,
    applied_delta: i32,
    _trust_tier: &str,
    observed_at_secs: u64,
    _binding_source: &str,
) -> String {
    let wallet_hex = keyfmt::pk_hex_from_any(wallet_pubkey_any)
        .unwrap_or_else(|_| wallet_pubkey_any.trim().to_ascii_lowercase());
    let peer_canon = peer_id.trim();
    let event_canon = event.trim();
    let delta_sign = applied_delta.signum();
    let observed_bucket_start = observed_at_secs
        .saturating_div(WALLET_REPUTATION_CLAIM_WINDOW_SECS)
        .saturating_mul(WALLET_REPUTATION_CLAIM_WINDOW_SECS);
    let canonical = format!(
        "wallet-reputation-claim-v2{}{}{}{}{}",
        wallet_hex, peer_canon, event_canon, delta_sign, observed_bucket_start,
    );
    sha256_hex(canonical.as_bytes())
}

pub fn wallet_reputation_claim_id_v1(item: &WalletReputationEvidenceIngestItem) -> String {
    wallet_reputation_claim_id_v1_fields(
        &item.wallet_pubkey,
        &item.peer_id,
        &item.event,
        item.score_before,
        item.score_after,
        item.applied_delta,
        &item.trust_tier,
        item.observed_at_secs,
        &item.binding_source,
    )
}

pub fn wallet_reputation_evidence_id_v1_fields(
    claim_id: &str,
    source_attester_pubkey: &str,
) -> String {
    let canonical = format!(
        "wallet-reputation-evidence-v3{}{}",
        claim_id.trim(),
        source_attester_pubkey.trim(),
    );
    sha256_hex(canonical.as_bytes())
}

pub fn wallet_reputation_evidence_id_v1(item: &WalletReputationEvidenceIngestItem) -> String {
    let claim_id = if item.claim_id.trim().is_empty() {
        wallet_reputation_claim_id_v1(item)
    } else {
        item.claim_id.trim().to_string()
    };
    let source_attester_pubkey = item
        .source_attester_pubkey
        .as_ref()
        .and_then(|s| canonical_wallet_reputation_source_attester(s))
        .unwrap_or_else(|| "local".to_string());
    wallet_reputation_evidence_id_v1_fields(&claim_id, &source_attester_pubkey)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletReputationEvidenceSignatureVersion {
    LegacyV2,
    CurrentV3,
}

impl WalletReputationEvidenceSignatureVersion {
    pub fn label(self) -> &'static str {
        match self {
            Self::LegacyV2 => "v2",
            Self::CurrentV3 => "v3",
        }
    }
}

pub fn wallet_reputation_evidence_signing_bytes_for_version(
    item: &WalletReputationEvidenceIngestItem,
    version: WalletReputationEvidenceSignatureVersion,
) -> Result<Vec<u8>, String> {
    let claim_id = if item.claim_id.trim().is_empty() {
        wallet_reputation_claim_id_v1(item)
    } else {
        item.claim_id.trim().to_string()
    };
    let evidence_id = if item.evidence_id.trim().is_empty() {
        wallet_reputation_evidence_id_v1(item)
    } else {
        item.evidence_id.trim().to_string()
    };
    let source_attester_pubkey = item
        .source_attester_pubkey
        .as_ref()
        .and_then(|s| canonical_wallet_reputation_source_attester(s))
        .ok_or_else(|| "missing source_attester_pubkey".to_string())?;
    let wallet_hex = crate::keyfmt::pk_hex_from_any(&item.wallet_pubkey)
        .unwrap_or_else(|_| item.wallet_pubkey.trim().to_ascii_lowercase());
    let source_node_id = item.source_node_id.as_deref().map(str::trim).unwrap_or("");
    let s = match version {
        WalletReputationEvidenceSignatureVersion::LegacyV2 => format!(
            "ngrep|wallet-evidence|v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            claim_id,
            evidence_id,
            source_attester_pubkey,
            wallet_hex,
            item.peer_id.trim(),
            item.event.trim(),
            item.score_before,
            item.score_after,
            item.applied_delta,
            item.trust_tier.trim(),
            item.observed_at_secs,
            item.binding_source.trim(),
        ),
        WalletReputationEvidenceSignatureVersion::CurrentV3 => format!(
            "ngrep|wallet-evidence|v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            claim_id,
            evidence_id,
            source_attester_pubkey,
            source_node_id,
            wallet_hex,
            item.peer_id.trim(),
            item.event.trim(),
            item.score_before,
            item.score_after,
            item.applied_delta,
            item.trust_tier.trim(),
            item.observed_at_secs,
            item.binding_source.trim(),
        ),
    };
    Ok(s.into_bytes())
}

pub fn wallet_reputation_evidence_signing_bytes_legacy_v2(
    item: &WalletReputationEvidenceIngestItem,
) -> Result<Vec<u8>, String> {
    wallet_reputation_evidence_signing_bytes_for_version(
        item,
        WalletReputationEvidenceSignatureVersion::LegacyV2,
    )
}

pub fn wallet_reputation_evidence_signing_bytes_v1(
    item: &WalletReputationEvidenceIngestItem,
) -> Result<Vec<u8>, String> {
    wallet_reputation_evidence_signing_bytes_for_version(
        item,
        WalletReputationEvidenceSignatureVersion::CurrentV3,
    )
}

pub fn verify_wallet_reputation_evidence_signature(
    source_attester_pubkey_any: &str,
    source_attester_sig_b64: &str,
    item: &WalletReputationEvidenceIngestItem,
    allow_legacy_v2: bool,
) -> Result<WalletReputationEvidenceSignatureVersion, String> {
    let source_attester_pubkey =
        canonical_wallet_reputation_source_attester(source_attester_pubkey_any)
            .ok_or_else(|| "missing source_attester_pubkey".to_string())?;
    let current = wallet_reputation_evidence_signing_bytes_v1(item)?;
    if verify_ed25519_sig_b64(&source_attester_pubkey, source_attester_sig_b64, &current).is_ok() {
        return Ok(WalletReputationEvidenceSignatureVersion::CurrentV3);
    }
    let source_node_bound = item
        .source_node_id
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if allow_legacy_v2 && !source_node_bound {
        let legacy = wallet_reputation_evidence_signing_bytes_legacy_v2(item)?;
        if verify_ed25519_sig_b64(&source_attester_pubkey, source_attester_sig_b64, &legacy).is_ok()
        {
            return Ok(WalletReputationEvidenceSignatureVersion::LegacyV2);
        }
    }
    Err("invalid source attester signature".to_string())
}

fn normalize_wallet_reputation_batch_source_node_id(
    payload_source_node_id: Option<String>,
    evidences: &[WalletReputationEvidenceIngestItem],
) -> Result<String, String> {
    let batch_source_node_id = payload_source_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mut unique_item_source_node_id: Option<String> = None;
    for item in evidences {
        let item_source_node_id = item
            .source_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(item_source_node_id) = item_source_node_id {
            match unique_item_source_node_id.as_ref() {
                Some(expected) if expected != &item_source_node_id => {
                    return Err("source_node_id mismatch within batch".to_string());
                }
                None => unique_item_source_node_id = Some(item_source_node_id),
                _ => {}
            }
        }
    }
    if let (Some(batch_source_node_id), Some(item_source_node_id)) = (
        batch_source_node_id.as_ref(),
        unique_item_source_node_id.as_ref(),
    ) {
        if batch_source_node_id != item_source_node_id {
            return Err("source_node_id mismatch within batch".to_string());
        }
    }
    batch_source_node_id
        .or(unique_item_source_node_id)
        .ok_or_else(|| "missing source_node_id".to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletReputationCanonicalClaimAggregate {
    pub claim_id: String,
    pub wallet_pubkey: String,
    pub peer_id: String,
    pub event: String,
    pub score_before: i32,
    pub score_after: i32,
    pub applied_delta: i32,
    pub trust_tier: String,
    pub observed_at_secs: u64,
    pub binding_source: String,
    #[serde(default)]
    pub source_node_ids: BTreeSet<String>,
    #[serde(default)]
    pub source_attester_pubkeys: BTreeSet<String>,
    #[serde(default)]
    pub evidence_ids: BTreeSet<String>,
    #[serde(default)]
    pub support_count: u32,
    #[serde(default)]
    pub promoted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_at_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_source_tip_height: Option<u64>,
    /// Advisory-only aggregate mirror of the latest batch source_tip_height.
    #[serde(default)]
    pub last_source_tip_height_advisory: bool,
    #[serde(default)]
    pub last_ingested_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernedE2WorkerReputationEvidenceApplyRequestV1 {
    pub proposal_id: String,
    pub evidence: crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernedE2WorkerOperatorBindingApplyRequestV1 {
    pub proposal_id: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
}

/// Canonical E2 worker -> operator wallet binding.
///
/// This is the authoritative registry consumed by Compute Hub worker eligibility.
/// Wallet reputation may mirror parts of this relationship for compatibility, but
/// eligibility/admission must resolve through this registry and a finalized height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerOperatorBindingRecordV1 {
    pub format_version: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    pub bound_at_height: u64,
    pub status: String,
    #[serde(default = "default_e2_worker_registration_source_v1")]
    pub registration_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities_commitment_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl E2WorkerOperatorBindingRecordV1 {
    pub const FORMAT_VERSION: &'static str = "e2-worker-operator-binding-record-v1";

    pub fn active(
        worker_node_pubkey: String,
        operator_wallet_pubkey: String,
        bound_at_height: u64,
        proposal_id: Option<String>,
    ) -> Self {
        Self::active_with_source(
            worker_node_pubkey,
            operator_wallet_pubkey,
            bound_at_height,
            proposal_id,
            E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_BIND_V1.to_string(),
        )
    }

    pub fn active_with_source(
        worker_node_pubkey: String,
        operator_wallet_pubkey: String,
        bound_at_height: u64,
        proposal_id: Option<String>,
        registration_source: String,
    ) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION.to_string(),
            worker_node_pubkey,
            operator_wallet_pubkey,
            bound_at_height,
            status: "ACTIVE".to_string(),
            registration_source,
            proposal_id,
            capabilities_commitment_hash: None,
            runtime_class: None,
            region: None,
            country: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status.trim().eq_ignore_ascii_case("ACTIVE")
    }

    pub fn registration_source_is_valid(&self) -> bool {
        matches!(
            self.registration_source.trim(),
            E2_WORKER_REGISTRATION_SOURCE_SELF_REGISTERED_V1
                | E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_BIND_V1
                | E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_PRIVILEGED_V1
        )
    }
}

pub const E2_WORKER_GOVERNED_PRIVILEGE_PAYLOAD_VERSION_V1: &str = "e2-worker-governed-privilege-v1";
pub const E2_WORKER_GOVERNED_PRIVILEGE_RECORD_VERSION_V1: &str =
    "e2-worker-governed-privilege-record-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum E2WorkerGovernedPrivilegeV1 {
    CloudUnit,
    GpuCapability,
    CriticalWorkload,
}

impl E2WorkerGovernedPrivilegeV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CloudUnit => "cloud_unit",
            Self::GpuCapability => "gpu_capability",
            Self::CriticalWorkload => "critical_workload",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerGovernedPrivilegePayloadV1 {
    pub format_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_snapshot_hash: Option<String>,
    /// Explicit review marker for critical workload grants. It must be a 64-hex
    /// governance-reviewed artifact hash distinct from the generic grant payload hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_review_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl E2WorkerGovernedPrivilegePayloadV1 {
    pub fn validate_contract_v1(&self) -> Result<(String, String), String> {
        if self.format_version.trim() != E2_WORKER_GOVERNED_PRIVILEGE_PAYLOAD_VERSION_V1 {
            return Err("e2_worker_governed_privilege_bad_format_version".to_string());
        }
        let worker_hex = keyfmt::pk_hex_from_any(&self.worker_node_pubkey)
            .map_err(|e| format!("e2_worker_governed_privilege_worker_invalid:{e}"))?;
        let operator_hex = keyfmt::pk_hex_from_any(&self.operator_wallet_pubkey)
            .map_err(|e| format!("e2_worker_governed_privilege_operator_invalid:{e}"))?;
        if worker_hex == operator_hex {
            return Err("e2_worker_governed_privilege_requires_distinct_identities".to_string());
        }
        if let Some(reason) = self.reason.as_ref() {
            if reason.len() > 512 {
                return Err("e2_worker_governed_privilege_reason_too_long".to_string());
            }
        }
        if let Some(hash) = self.capability_snapshot_hash.as_ref() {
            let h = hash.trim();
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "e2_worker_governed_privilege_capability_snapshot_hash_invalid".to_string(),
                );
            }
        }
        if let Some(hash) = self.critical_review_payload_hash.as_ref() {
            let h = hash.trim();
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "e2_worker_governed_privilege_critical_review_payload_hash_invalid".to_string(),
                );
            }
        }
        Ok((worker_hex, operator_hex))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerGovernedPrivilegeRecordV1 {
    pub format_version: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    pub updated_at_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_payload_hash: Option<String>,
    #[serde(default)]
    pub cloud_unit_allowed: bool,
    #[serde(default)]
    pub gpu_allowed: bool,
    #[serde(default)]
    pub critical_workload_allowed: bool,
}

impl E2WorkerGovernedPrivilegeRecordV1 {
    pub fn new(
        worker_node_pubkey: String,
        operator_wallet_pubkey: String,
        updated_at_height: u64,
        proposal_id: Option<String>,
    ) -> Self {
        Self {
            format_version: E2_WORKER_GOVERNED_PRIVILEGE_RECORD_VERSION_V1.to_string(),
            worker_node_pubkey,
            operator_wallet_pubkey,
            updated_at_height,
            proposal_id,
            cloud_unit_grant_proposal_id: None,
            cloud_unit_grant_payload_hash: None,
            gpu_grant_proposal_id: None,
            gpu_grant_payload_hash: None,
            critical_workload_grant_proposal_id: None,
            critical_workload_grant_payload_hash: None,
            critical_workload_review_proposal_id: None,
            critical_workload_review_payload_hash: None,
            cloud_unit_allowed: false,
            gpu_allowed: false,
            critical_workload_allowed: false,
        }
    }

    pub fn apply(
        &mut self,
        privilege: &E2WorkerGovernedPrivilegeV1,
        grant: bool,
        proposal_id: &str,
        payload_hash: &str,
        critical_review_payload_hash: Option<&str>,
    ) {
        match privilege {
            E2WorkerGovernedPrivilegeV1::CloudUnit => {
                self.cloud_unit_allowed = grant;
                if grant {
                    self.cloud_unit_grant_proposal_id = Some(proposal_id.to_string());
                    self.cloud_unit_grant_payload_hash = Some(payload_hash.to_string());
                } else {
                    self.cloud_unit_grant_proposal_id = None;
                    self.cloud_unit_grant_payload_hash = None;
                }
            }
            E2WorkerGovernedPrivilegeV1::GpuCapability => {
                self.gpu_allowed = grant;
                if grant {
                    self.gpu_grant_proposal_id = Some(proposal_id.to_string());
                    self.gpu_grant_payload_hash = Some(payload_hash.to_string());
                } else {
                    self.gpu_grant_proposal_id = None;
                    self.gpu_grant_payload_hash = None;
                }
            }
            E2WorkerGovernedPrivilegeV1::CriticalWorkload => {
                self.critical_workload_allowed = grant;
                if grant {
                    self.critical_workload_grant_proposal_id = Some(proposal_id.to_string());
                    self.critical_workload_grant_payload_hash = Some(payload_hash.to_string());
                    self.critical_workload_review_proposal_id = Some(proposal_id.to_string());
                    self.critical_workload_review_payload_hash = critical_review_payload_hash
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_string);
                } else {
                    self.critical_workload_grant_proposal_id = None;
                    self.critical_workload_grant_payload_hash = None;
                    self.critical_workload_review_proposal_id = None;
                    self.critical_workload_review_payload_hash = None;
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceApplyEffects {
    #[serde(default)]
    pub acknowledged_run_wallet_evidence_ids: Vec<String>,
    #[serde(default)]
    pub governed_e2_worker_reputation_evidence:
        Vec<GovernedE2WorkerReputationEvidenceApplyRequestV1>,
    #[serde(default)]
    pub governed_e2_worker_operator_bindings: Vec<GovernedE2WorkerOperatorBindingApplyRequestV1>,
    #[serde(default)]
    pub governed_compute_fiat_settlement_proofs:
        Vec<GovernedComputeFiatSettlementProofApplyRequestV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernedComputeFiatSettlementProofApplyRequestV1 {
    pub proposal_id: String,
    pub proof: crate::compute_contract::ComputeFiatSettlementProofV1,
}

pub const E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1: &str =
    "e2-worker-reputation-evidence-ingest-v1";
pub const E2_WORKER_REPUTATION_EVIDENCE_INGEST_MAX_ITEMS_V1: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerReputationEvidenceIngestPayloadV1 {
    pub format_version: String,
    pub evidences: Vec<crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1>,
}

impl E2WorkerReputationEvidenceIngestPayloadV1 {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.format_version.trim() != E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1 {
            return Err("e2_worker_reputation_evidence_payload_bad_format_version".to_string());
        }
        if self.evidences.is_empty() {
            return Err("e2_worker_reputation_evidence_payload_empty".to_string());
        }
        if self.evidences.len() > E2_WORKER_REPUTATION_EVIDENCE_INGEST_MAX_ITEMS_V1 {
            return Err("e2_worker_reputation_evidence_payload_too_many_items".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut seen_orders = BTreeSet::new();
        for ev in &self.evidences {
            let id = ev.evidence_hash().trim();
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("e2_worker_reputation_evidence_payload_bad_evidence_hash".to_string());
            }
            if !seen.insert(id.to_ascii_lowercase()) {
                return Err(
                    "e2_worker_reputation_evidence_payload_duplicate_evidence_hash".to_string(),
                );
            }
            let order_id = ev.order_id().trim();
            if order_id.len() != 64 || !order_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("e2_worker_reputation_evidence_payload_bad_order_id".to_string());
            }
            if !seen_orders.insert(order_id.to_ascii_lowercase()) {
                return Err("e2_worker_reputation_evidence_payload_duplicate_order_id".to_string());
            }
        }
        Ok(())
    }
}

pub const E2_WORKER_OPERATOR_BINDING_PAYLOAD_VERSION_V1: &str = "e2-worker-operator-binding-v1";
pub const E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_BIND_V1: &str = "GOVERNANCE_BIND";
pub const E2_WORKER_REGISTRATION_SOURCE_SELF_REGISTERED_V1: &str = "SELF_REGISTERED";
pub const E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_PRIVILEGED_V1: &str = "GOVERNANCE_PRIVILEGED";

fn default_e2_worker_registration_source_v1() -> String {
    E2_WORKER_REGISTRATION_SOURCE_GOVERNANCE_BIND_V1.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerOperatorBindingPayloadV1 {
    pub format_version: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl E2WorkerOperatorBindingPayloadV1 {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.format_version.trim() != E2_WORKER_OPERATOR_BINDING_PAYLOAD_VERSION_V1 {
            return Err("e2_worker_operator_binding_bad_format_version".to_string());
        }
        let worker_hex = keyfmt::pk_hex_from_any(&self.worker_node_pubkey)
            .map_err(|e| format!("e2_worker_operator_binding_worker_invalid:{e}"))?;
        let operator_hex = keyfmt::pk_hex_from_any(&self.operator_wallet_pubkey)
            .map_err(|e| format!("e2_worker_operator_binding_operator_invalid:{e}"))?;
        if worker_hex == operator_hex {
            return Err("e2_worker_operator_binding_requires_distinct_identities".to_string());
        }
        Ok(())
    }
}

const WALLET_REPUTATION_EVIDENCE_LOG_CAP: usize = 4096;

// ----------------------
// Validator ops payloads (rotation / revocation)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateValidatorKeyPayload {
    pub old_pub_key: String,
    pub new_pub_key: String,
    #[serde(default)]
    pub new_alias: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeValidatorPayload {
    pub pub_key: String,
    /// Revoca fino a questa height (esclusiva). Se None => permanente.
    #[serde(default)]
    pub until_height: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnrevokeValidatorPayload {
    pub pub_key: String,
    #[serde(default)]
    pub reason: Option<String>,
}

// ----------------------
// Operator Role Model V2: validator -> compute transition guard
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorComputeTransitionRequestPayload {
    pub validator_pub_key: String,
    pub operator_wallet_pubkey: String,
    #[serde(default)]
    pub requested_compute_only: bool,
    /// Optional operator-supplied request height for audit/backward compatibility.
    /// Consensus cooldown is anchored to the canonical block height that first creates
    /// `EXIT_PENDING`; payload-supplied heights must not be trusted to accelerate exit.
    #[serde(default)]
    pub requested_at_height: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorComputeTransitionStatusV1 {
    Requested,
    ExitPending,
    Finalized,
    Cancelled,
    Denied,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorComputeTransitionRecordV1 {
    pub validator_pubkey: String,
    pub operator_wallet_pubkey: String,
    pub status: ValidatorComputeTransitionStatusV1,
    pub requested_at_height: u64,
    pub decided_at_height: Option<u64>,
    pub finalized_at_height: Option<u64>,
    pub proposal_id: Option<String>,
    pub deny_reasons: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelValidatorComputeTransitionPayload {
    pub validator_pub_key: String,
    pub operator_wallet_pubkey: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorComputeTransitionQuorumPolicyV1 {
    pub min_active_validators: usize,
    pub min_finality_quorum: usize,
    #[serde(alias = "min_remaining_validator_quality_score")]
    pub validator_quality_floor: u32,
    #[serde(alias = "cooldown_blocks")]
    pub validator_exit_cooldown_blocks: u64,
    pub max_finality_lag_blocks: u64,
    pub max_recent_missed_slots: u64,
}

impl Default for ValidatorComputeTransitionQuorumPolicyV1 {
    fn default() -> Self {
        Self {
            min_active_validators: default_validator_compute_transition_min_active_validators(),
            min_finality_quorum: default_validator_compute_transition_min_finality_quorum(),
            validator_quality_floor: default_validator_compute_transition_validator_quality_floor(),
            validator_exit_cooldown_blocks:
                default_validator_compute_transition_exit_cooldown_blocks(),
            max_finality_lag_blocks: default_validator_compute_transition_max_finality_lag_blocks(),
            max_recent_missed_slots: default_validator_compute_transition_max_recent_missed_slots(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorComputeTransitionDecisionV1 {
    pub allowed: bool,
    pub deny_reasons: Vec<String>,
    pub active_validators_before: usize,
    /// Backwards-compatible field name for API/tests that already inspect the projected validator count.
    /// Semantics: active validators left after the requested validator exits.
    pub active_validators_after: usize,
    #[serde(default)]
    pub active_validators_after_exit: usize,
    pub min_active_validators: usize,
    /// Backwards-compatible field name. Semantics: healthy validators left after exit that can still
    /// participate in finality according to canonical projected reputation state.
    pub finality_quorum_after: usize,
    #[serde(default)]
    pub finality_quorum_after_exit: usize,
    pub min_finality_quorum: usize,
    pub remaining_validator_quality_floor: u32,
    pub max_recent_missed_slots: u64,
    #[serde(default)]
    pub unhealthy_remaining_validators: usize,
}

fn validator_reputation_for_transition_guard_v1(
    validator_reputation: &HashMap<String, ValidatorGovReputation>,
    validator_pubkey: &str,
) -> ValidatorGovReputation {
    let key = validator_pubkey.trim();
    validator_reputation
        .get(key)
        .or_else(|| validator_reputation.get(&key.to_ascii_lowercase()))
        .or_else(|| validator_reputation.get(&key.to_ascii_uppercase()))
        .cloned()
        .unwrap_or_default()
}

pub fn validator_quality_score_for_operator_role_model_v2(
    rep: &ValidatorGovReputation,
    current_height: u64,
) -> u32 {
    if rep.temporarily_revoked {
        return 0;
    }
    if rep
        .banned_until_height
        .map(|h| h > current_height)
        .unwrap_or(false)
    {
        return 0;
    }
    if rep
        .jailed_until_height
        .map(|h| h > current_height)
        .unwrap_or(false)
    {
        return 0;
    }
    let penalty = rep
        .misbehavior_points
        .saturating_mul(10)
        .saturating_add(rep.slashed_count.saturating_mul(100))
        .saturating_add((rep.recent_failure_count as u32).saturating_mul(25))
        .saturating_add((rep.recent_timeout_count as u32).saturating_mul(25))
        .saturating_add((rep.downtime_consecutive_missed_turns as u32).saturating_mul(10));
    1000u32.saturating_sub(penalty)
}

pub fn validator_is_healthy_for_compute_transition_quorum_guard_v1(
    rep: &ValidatorGovReputation,
    current_height: u64,
    max_recent_missed_slots: u64,
) -> bool {
    if rep.temporarily_revoked {
        return false;
    }
    if rep
        .banned_until_height
        .map(|h| h > current_height)
        .unwrap_or(false)
    {
        return false;
    }
    if rep
        .jailed_until_height
        .map(|h| h > current_height)
        .unwrap_or(false)
    {
        return false;
    }
    rep.downtime_consecutive_missed_turns <= max_recent_missed_slots
}

pub fn evaluate_validator_compute_transition_quorum_guard_v1(
    validator_set: &ValidatorSet,
    validator_reputation: &HashMap<String, ValidatorGovReputation>,
    exiting_validator_pubkey: &str,
    policy: &ValidatorComputeTransitionQuorumPolicyV1,
    current_height: u64,
    finalized_height: u64,
) -> ValidatorComputeTransitionDecisionV1 {
    let exiting = exiting_validator_pubkey.trim();
    let active: Vec<&ValidatorEntry> = validator_set
        .entries
        .iter()
        .filter(|v| !v.pub_key.trim().is_empty())
        .collect();
    let active_before = active.len();
    let remaining: Vec<&ValidatorEntry> = active
        .iter()
        .copied()
        .filter(|v| !v.pub_key.trim().eq_ignore_ascii_case(exiting))
        .collect();
    let active_after_exit = remaining.len();
    let mut deny_reasons = Vec::new();

    if exiting.is_empty() || active_after_exit == active_before {
        deny_reasons.push("validator_not_active".to_string());
    }
    if active_after_exit < policy.min_active_validators {
        deny_reasons.push("quorum_too_low".to_string());
    }

    let mut healthy_remaining = 0usize;
    let mut unhealthy_remaining = 0usize;
    let mut validator_quality_below_floor = false;

    // Projected state after exit: only remaining active validators are evaluated, using the canonical
    // reputation/health view as the source of truth. This prevents a validator from exiting if the
    // remaining set is numerically present but unable to sustain healthy finality.
    for validator in &remaining {
        let rep =
            validator_reputation_for_transition_guard_v1(validator_reputation, &validator.pub_key);
        if validator_is_healthy_for_compute_transition_quorum_guard_v1(
            &rep,
            current_height,
            policy.max_recent_missed_slots,
        ) {
            healthy_remaining = healthy_remaining.saturating_add(1);
        } else {
            unhealthy_remaining = unhealthy_remaining.saturating_add(1);
        }

        let score = validator_quality_score_for_operator_role_model_v2(&rep, current_height);
        if score < policy.validator_quality_floor {
            validator_quality_below_floor = true;
        }
    }

    let finality_quorum_after_exit = healthy_remaining;
    if finality_quorum_after_exit < policy.min_finality_quorum {
        deny_reasons.push("finality_quorum_broken".to_string());
    }
    if unhealthy_remaining > 0 {
        deny_reasons.push("remaining_validator_unhealthy".to_string());
    }
    if validator_quality_below_floor {
        deny_reasons.push("validator_quality_below_floor".to_string());
    }
    if current_height.saturating_sub(finalized_height) > policy.max_finality_lag_blocks {
        deny_reasons.push("finality_lag_too_high".to_string());
    }

    deny_reasons.sort();
    deny_reasons.dedup();

    ValidatorComputeTransitionDecisionV1 {
        allowed: deny_reasons.is_empty(),
        deny_reasons,
        active_validators_before: active_before,
        active_validators_after: active_after_exit,
        active_validators_after_exit: active_after_exit,
        min_active_validators: policy.min_active_validators,
        finality_quorum_after: finality_quorum_after_exit,
        finality_quorum_after_exit,
        min_finality_quorum: policy.min_finality_quorum,
        remaining_validator_quality_floor: policy.validator_quality_floor,
        max_recent_missed_slots: policy.max_recent_missed_slots,
        unhealthy_remaining_validators: unhealthy_remaining,
    }
}

// ----------------------
// Audit trail (validator ops)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorOpsOp {
    RotateKey,
    Revoke,
    Unrevoke,
    /// Full validator-set replacement through governance.
    ValidatorSetUpdate,
    DowntimeJail,
    DowntimeUnjail,
    /// Slash monetary event was reflected into canonical validator/wallet reputation.
    SlashReputationEffect,
    /// Generic wallet misconduct was attributed through a signed governance/evidence path.
    WalletMisconduct,
    /// Operator Role Model V2 validator exited active consensus duty to compute-only role.
    ValidatorExitForCompute,
    /// Operator Role Model V2 pending validator->compute transition was cancelled.
    ValidatorComputeTransitionCancel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorOpsLogEntry {
    pub height: u64,
    pub op: ValidatorOpsOp,
    /// Target validator pk (HEX, lowercase).
    pub target_pk_hex: String,
    /// For rotation: new pk (HEX).
    #[serde(default)]
    pub new_pk_hex: Option<String>,
    /// For revocation/jail: until height (exclusive).
    #[serde(default)]
    pub until_height: Option<u64>,
    /// Proposal id that produced the operation (if available).
    #[serde(default)]
    pub proposal_id: Option<String>,
    /// Optional freeform reason (short).
    #[serde(default)]
    pub reason: Option<String>,
}

pub(crate) const OPS_LOG_CAP: usize = 2048;

// ----------------------
// Delta: Economy / Security / Reputation / Mempool
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EconomyPolicyDelta {
    /// Nuovo valore per base_fee_per_tx (se Some)
    pub base_fee_per_tx: Option<u64>,
    /// Nuovo valore per treasury_pct_base (se Some)
    /// Percentuale fee → treasury in basis points (0..10_000).
    /// Compatibilità JSON: accetta il nome "treasury_pct_base" ma lo tratta come BPS intero.
    #[serde(rename = "treasury_pct_base")]
    pub treasury_pct_base_bps: Option<u32>,

    /// Nuovo valore per burn_bps (se Some)
    pub burn_bps: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecurityPolicyDelta {
    /// Nuova dimensione massima del blocco (byte)
    pub max_block_size: Option<u64>,
    /// Nuova fee minima per TX
    pub min_fee_per_tx: Option<u64>,
    /// Limite massimo connessioni per IP (esempio di parametro "hard")
    pub max_connections_per_ip: Option<u32>,
}

// ----------------------
// Delta: Reputation Policy (Step 48A)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReputationPolicyDelta {
    // --- Soglie (se usi stati Good / Probation / Banned) ---
    pub good_threshold: Option<i32>,
    pub probation_threshold: Option<i32>,
    pub banned_threshold: Option<i32>,

    // --- Ban tuning ---
    pub ban_duration_secs: Option<u64>,
    pub decay_per_tick: Option<i32>,
    pub tick_secs: Option<u64>,

    // --- Pesi eventi (coerenti con ReputationEvent / on_event) ---
    pub w_valid_tx: Option<i32>,
    pub w_invalid_tx: Option<i32>,
    pub w_valid_block: Option<i32>,
    pub w_invalid_block: Option<i32>,
    pub w_spam: Option<i32>,
    pub w_disconnect: Option<i32>,
    pub w_slashed: Option<i32>,
}

impl ReputationPolicyDelta {
    /// Default effective runtime thresholds produced by SecurityPolicy::default()
    /// through ReputationConfig::from_security_policy_v1(): initial=600,
    /// probation=500, banned=200 => good midpoint=550.
    ///
    /// These defaults are used only for validating partial governance deltas before
    /// they are materialized into runtime config. Runtime still performs a second
    /// fail-closed validation against the actual active ReputationConfig.
    pub const DEFAULT_EFFECTIVE_GOOD_THRESHOLD_V1: i32 = 550;
    pub const DEFAULT_EFFECTIVE_PROBATION_THRESHOLD_V1: i32 = 500;
    pub const DEFAULT_EFFECTIVE_BANNED_THRESHOLD_V1: i32 = 200;

    pub fn validate_contract_v1(&self) -> Result<(), String> {
        const SCORE_MIN: i32 = 0;
        const SCORE_MAX: i32 = 1000;
        const MAX_BAN_SECS: u64 = 60 * 60 * 24 * 30;
        const MAX_TICK_SECS: u64 = 60 * 60 * 24 * 365;
        const MAX_EVENT_ABS_WEIGHT: i32 = 10_000;

        for (name, value) in [
            ("good_threshold", self.good_threshold),
            ("probation_threshold", self.probation_threshold),
            ("banned_threshold", self.banned_threshold),
        ] {
            if let Some(v) = value {
                if !(SCORE_MIN..=SCORE_MAX).contains(&v) {
                    return Err(format!(
                        "{} fuori range {}..{}: {}",
                        name, SCORE_MIN, SCORE_MAX, v
                    ));
                }
            }
        }

        if let (Some(g), Some(p), Some(b)) = (
            self.good_threshold,
            self.probation_threshold,
            self.banned_threshold,
        ) {
            if !(g > p && p > b) {
                return Err(format!(
                    "soglie reputazione non coerenti: require good_threshold > probation_threshold > banned_threshold, got good={} probation={} banned={}",
                    g, p, b
                ));
            }
        }

        if let Some(secs) = self.ban_duration_secs {
            if secs == 0 || secs > MAX_BAN_SECS {
                return Err(format!(
                    "ban_duration_secs fuori range 1..{}: {}",
                    MAX_BAN_SECS, secs
                ));
            }
        }
        if let Some(tick) = self.tick_secs {
            if tick == 0 || tick > MAX_TICK_SECS {
                return Err(format!(
                    "tick_secs fuori range 1..{}: {}",
                    MAX_TICK_SECS, tick
                ));
            }
        }
        if let Some(decay) = self.decay_per_tick {
            if decay <= 0 || decay > SCORE_MAX {
                return Err(format!(
                    "decay_per_tick fuori range 1..{}: {}",
                    SCORE_MAX, decay
                ));
            }
        }

        for (name, value) in [
            ("w_valid_tx", self.w_valid_tx),
            ("w_invalid_tx", self.w_invalid_tx),
            ("w_valid_block", self.w_valid_block),
            ("w_invalid_block", self.w_invalid_block),
            ("w_spam", self.w_spam),
            ("w_disconnect", self.w_disconnect),
            ("w_slashed", self.w_slashed),
        ] {
            if let Some(v) = value {
                if v.abs() > MAX_EVENT_ABS_WEIGHT {
                    return Err(format!(
                        "{} fuori range assoluto <= {}: {}",
                        name, MAX_EVENT_ABS_WEIGHT, v
                    ));
                }
            }
        }
        if self.w_valid_tx.map(|v| v < 0).unwrap_or(false)
            || self.w_valid_block.map(|v| v < 0).unwrap_or(false)
        {
            return Err("w_valid_tx/w_valid_block devono essere non negativi".to_string());
        }
        if self.w_invalid_tx.map(|v| v > 0).unwrap_or(false)
            || self.w_invalid_block.map(|v| v > 0).unwrap_or(false)
            || self.w_spam.map(|v| v > 0).unwrap_or(false)
            || self.w_disconnect.map(|v| v > 0).unwrap_or(false)
            || self.w_slashed.map(|v| v > 0).unwrap_or(false)
        {
            return Err("pesi negativi di sicurezza devono essere non positivi".to_string());
        }

        // Runtime P2P spam is a generic rate-limit/backpressure signal. It must
        // remain soft even under governance overrides; hard faults must use typed
        // events such as invalid block, slash, or protocol-fault evidence.
        if self.w_spam.map(|v| v < -10).unwrap_or(false) {
            return Err("w_spam deve restare soft: range consentito -10..0".to_string());
        }

        Ok(())
    }

    pub fn validate_merged_contract_v1(
        &self,
        current: &ReputationPolicyDelta,
    ) -> Result<(), String> {
        self.validate_contract_v1()?;
        let good = self
            .good_threshold
            .or(current.good_threshold)
            .unwrap_or(Self::DEFAULT_EFFECTIVE_GOOD_THRESHOLD_V1);
        let probation = self
            .probation_threshold
            .or(current.probation_threshold)
            .unwrap_or(Self::DEFAULT_EFFECTIVE_PROBATION_THRESHOLD_V1);
        let banned = self
            .banned_threshold
            .or(current.banned_threshold)
            .unwrap_or(Self::DEFAULT_EFFECTIVE_BANNED_THRESHOLD_V1);
        if !(good > probation && probation > banned) {
            return Err(format!(
                "merged reputation thresholds are not coherent: require good > probation > banned, got good={} probation={} banned={}",
                good, probation, banned
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MempoolPolicyDelta {
    pub max_mempool_size: Option<u64>,  // es. 10_000
    pub max_tx_per_sender: Option<u64>, // es. 128
    pub max_mempool_bytes: Option<u64>, // es. 5_000_000
    pub tx_ttl_secs: Option<u64>,       // es. 3600 (1h)
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GovernanceParamsDelta {
    pub min_timelock_blocks: Option<u64>,
    pub min_timelock_blocks_emergency: Option<u64>,
    #[serde(default)]
    pub max_proposal_lifetime_blocks: Option<u64>,
    pub max_emergency_duration_blocks: Option<u64>,
    pub wallet_reputation_promotion_quorum: Option<u32>,
    #[serde(default)]
    pub e2_worker_admission_activation_height: Option<u64>,
    #[serde(default, alias = "min_active_validators")]
    pub validator_compute_transition_min_active_validators: Option<usize>,
    #[serde(default, alias = "min_finality_quorum")]
    pub validator_compute_transition_min_finality_quorum: Option<usize>,
    #[serde(default, alias = "validator_quality_floor")]
    pub validator_compute_transition_validator_quality_floor: Option<u32>,
    #[serde(default, alias = "validator_exit_cooldown_blocks")]
    pub validator_compute_transition_exit_cooldown_blocks: Option<u64>,
    #[serde(default, alias = "max_finality_lag_blocks")]
    pub validator_compute_transition_max_finality_lag_blocks: Option<u64>,
    #[serde(default, alias = "max_recent_missed_slots")]
    pub validator_compute_transition_max_recent_missed_slots: Option<u64>,
    pub protocol_threshold: Option<u8>,
    pub economy_threshold: Option<u8>,
    pub emergency_threshold: Option<u8>,

    // Downtime policy tuning
    pub downtime_enabled: Option<bool>,
    pub downtime_consecutive_missed_turns_threshold: Option<u64>,
    pub downtime_jail_duration_blocks: Option<u64>,
    #[serde(default)]
    pub ft_activation_height: Option<u64>,
    #[serde(default)]
    pub ft_max_tokens_per_owner: Option<u32>,
    #[serde(default)]
    pub ft_create_cooldown_blocks: Option<u64>,

    #[serde(default)]
    pub ft_create_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_activation_height: Option<u64>,
    #[serde(default)]
    pub nft_max_collections_per_owner: Option<u32>,
    #[serde(default)]
    pub nft_create_cooldown_blocks: Option<u64>,
    #[serde(default)]
    pub nft_create_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_create_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_mint_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_transfer_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_approval_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_burn_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_revoke_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_metadata_update_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_freeze_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_policy_update_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_issuer_update_enabled: Option<bool>,
    #[serde(default)]
    pub nft_public_pause_enabled: Option<bool>,
    #[serde(default)]
    pub nft_metadata_hash_required: Option<bool>,
    #[serde(default)]
    pub nft_max_memo_bytes: Option<u32>,
    #[serde(default)]
    pub nft_max_uri_bytes: Option<u32>,
    #[serde(default)]
    pub nft_max_name_bytes: Option<u32>,
    #[serde(default)]
    pub nft_max_symbol_bytes: Option<u32>,
    #[serde(default)]
    pub nft_max_tokens_per_collection: Option<u64>,
    #[serde(default)]
    pub nft_max_tokens_per_owner: Option<u64>,
    #[serde(default)]
    pub nft_mint_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_transfer_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_approval_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_burn_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_revoke_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_metadata_update_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_freeze_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_policy_update_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_issuer_update_fee_native: Option<u64>,
    #[serde(default)]
    pub nft_pause_fee_native: Option<u64>,
}

#[derive(Clone, Debug)]
struct GovernanceParamsUpdateStagedV1 {
    params: GovernanceParams,
    min_timelock_blocks_emergency: u64,
    downtime_policy: DowntimePolicy,
    protocol_council: Council,
    economy_council: Council,
    emergency_council: Council,
}

/// Canonical preview for governance parameter deltas.
///
/// API proposal surfaces and the on-chain application path must use this exact
/// helper so preview/hash validation cannot drift from canonical application.
pub fn preview_governance_params_delta_v1(
    current: &GovernanceParams,
    delta: &GovernanceParamsDelta,
) -> Result<GovernanceParams, String> {
    let mut params = current.clone();

    if let Some(v) = delta.min_timelock_blocks {
        params.min_timelock_blocks = v;
    }
    if let Some(v) = delta.max_proposal_lifetime_blocks {
        if v == 0 {
            return Err("max_proposal_lifetime_blocks_zero".to_string());
        }
        params.max_proposal_lifetime_blocks = v;
    }
    if let Some(v) = delta.max_emergency_duration_blocks {
        if v == 0 {
            return Err("max_emergency_duration_blocks_zero".to_string());
        }
        params.max_emergency_duration_blocks = v;
    }
    if let Some(v) = delta.wallet_reputation_promotion_quorum {
        if v == 0 {
            return Err("wallet_reputation_promotion_quorum_zero".to_string());
        }
        params.wallet_reputation_promotion_quorum = v;
    }
    if let Some(v) = delta.e2_worker_admission_activation_height {
        if v != params.e2_worker_admission_activation_height {
            return Err(format!(
                "e2_worker_admission_activation_height_immutable: current={} requested={}",
                params.e2_worker_admission_activation_height, v
            ));
        }
    }

    if let Some(v) = delta.validator_compute_transition_min_active_validators {
        if v == 0 {
            return Err("validator_compute_transition_min_active_validators_zero".to_string());
        }
        params.validator_compute_transition_min_active_validators = v;
    }
    if let Some(v) = delta.validator_compute_transition_min_finality_quorum {
        if v == 0 {
            return Err("validator_compute_transition_min_finality_quorum_zero".to_string());
        }
        params.validator_compute_transition_min_finality_quorum = v;
    }
    if let Some(v) = delta.validator_compute_transition_validator_quality_floor {
        if v > 1000 {
            return Err("validator_compute_transition_validator_quality_floor_gt_1000".to_string());
        }
        params.validator_compute_transition_validator_quality_floor = v;
    }
    if let Some(v) = delta.validator_compute_transition_exit_cooldown_blocks {
        if v == 0 {
            return Err("validator_compute_transition_exit_cooldown_blocks_zero".to_string());
        }
        params.validator_compute_transition_exit_cooldown_blocks = v;
    }
    if let Some(v) = delta.validator_compute_transition_max_finality_lag_blocks {
        params.validator_compute_transition_max_finality_lag_blocks = v;
    }
    if let Some(v) = delta.validator_compute_transition_max_recent_missed_slots {
        params.validator_compute_transition_max_recent_missed_slots = v;
    }

    if let Some(v) = delta.ft_activation_height {
        params.ft_activation_height = v;
    }
    if let Some(v) = delta.ft_max_tokens_per_owner {
        params.ft_max_tokens_per_owner = v.max(1);
    }
    if let Some(v) = delta.ft_create_cooldown_blocks {
        params.ft_create_cooldown_blocks = v;
    }
    if let Some(v) = delta.ft_create_fee_native {
        params.ft_create_fee_native = v;
    }

    if let Some(v) = delta.nft_activation_height {
        params.nft_activation_height = v;
    }
    if let Some(v) = delta.nft_max_collections_per_owner {
        params.nft_max_collections_per_owner = v;
    }
    if let Some(v) = delta.nft_create_cooldown_blocks {
        params.nft_create_cooldown_blocks = v;
    }
    if let Some(v) = delta.nft_create_fee_native {
        params.nft_create_fee_native = v;
    }
    if let Some(v) = delta.nft_enabled {
        params.nft_enabled = v;
    }
    if let Some(v) = delta.nft_public_create_enabled {
        params.nft_public_create_enabled = v;
    }
    if let Some(v) = delta.nft_public_mint_enabled {
        params.nft_public_mint_enabled = v;
    }
    if let Some(v) = delta.nft_public_transfer_enabled {
        params.nft_public_transfer_enabled = v;
    }
    if let Some(v) = delta.nft_public_approval_enabled {
        params.nft_public_approval_enabled = v;
    }
    if let Some(v) = delta.nft_public_burn_enabled {
        params.nft_public_burn_enabled = v;
    }
    if let Some(v) = delta.nft_public_revoke_enabled {
        params.nft_public_revoke_enabled = v;
    }
    if let Some(v) = delta.nft_public_metadata_update_enabled {
        params.nft_public_metadata_update_enabled = v;
    }
    if let Some(v) = delta.nft_public_freeze_enabled {
        params.nft_public_freeze_enabled = v;
    }
    if let Some(v) = delta.nft_public_policy_update_enabled {
        params.nft_public_policy_update_enabled = v;
    }
    if let Some(v) = delta.nft_public_issuer_update_enabled {
        params.nft_public_issuer_update_enabled = v;
    }
    if let Some(v) = delta.nft_public_pause_enabled {
        params.nft_public_pause_enabled = v;
    }
    if let Some(v) = delta.nft_metadata_hash_required {
        params.nft_metadata_hash_required = v;
    }
    if let Some(v) = delta.nft_max_memo_bytes {
        params.nft_max_memo_bytes = v;
    }
    if let Some(v) = delta.nft_max_uri_bytes {
        params.nft_max_uri_bytes = v;
    }
    if let Some(v) = delta.nft_max_name_bytes {
        params.nft_max_name_bytes = v;
    }
    if let Some(v) = delta.nft_max_symbol_bytes {
        params.nft_max_symbol_bytes = v;
    }
    if let Some(v) = delta.nft_max_tokens_per_collection {
        params.nft_max_tokens_per_collection = v;
    }
    if let Some(v) = delta.nft_max_tokens_per_owner {
        params.nft_max_tokens_per_owner = v;
    }
    if let Some(v) = delta.nft_mint_fee_native {
        params.nft_mint_fee_native = v;
    }
    if let Some(v) = delta.nft_transfer_fee_native {
        params.nft_transfer_fee_native = v;
    }
    if let Some(v) = delta.nft_approval_fee_native {
        params.nft_approval_fee_native = v;
    }
    if let Some(v) = delta.nft_burn_fee_native {
        params.nft_burn_fee_native = v;
    }
    if let Some(v) = delta.nft_revoke_fee_native {
        params.nft_revoke_fee_native = v;
    }
    if let Some(v) = delta.nft_metadata_update_fee_native {
        params.nft_metadata_update_fee_native = v;
    }
    if let Some(v) = delta.nft_freeze_fee_native {
        params.nft_freeze_fee_native = v;
    }
    if let Some(v) = delta.nft_policy_update_fee_native {
        params.nft_policy_update_fee_native = v;
    }
    if let Some(v) = delta.nft_issuer_update_fee_native {
        params.nft_issuer_update_fee_native = v;
    }
    if let Some(v) = delta.nft_pause_fee_native {
        params.nft_pause_fee_native = v;
    }

    validate_nft_governance_policy_v1(&params)?;
    Ok(params)
}

pub fn validate_nft_governance_policy_v1(params: &GovernanceParams) -> Result<(), String> {
    let public_any_enabled = params.nft_public_create_enabled
        || params.nft_public_mint_enabled
        || params.nft_public_transfer_enabled
        || params.nft_public_approval_enabled
        || params.nft_public_burn_enabled
        || params.nft_public_revoke_enabled
        || params.nft_public_metadata_update_enabled
        || params.nft_public_freeze_enabled
        || params.nft_public_policy_update_enabled
        || params.nft_public_issuer_update_enabled
        || params.nft_public_pause_enabled;

    if public_any_enabled && !params.nft_enabled {
        return Err("nft_public_gate_enabled_without_nft_master_gate".to_string());
    }

    if !params.nft_metadata_hash_required {
        return Err("nft_metadata_hash_required_must_remain_true".to_string());
    }

    if params.nft_max_memo_bytes == 0
        || params.nft_max_memo_bytes as usize > crate::nft::NFTV1_MEMO_MAX_BYTES
    {
        return Err(format!(
            "nft_max_memo_bytes_out_of_range: value={} max={}",
            params.nft_max_memo_bytes,
            crate::nft::NFTV1_MEMO_MAX_BYTES
        ));
    }
    if params.nft_max_uri_bytes == 0
        || params.nft_max_uri_bytes as usize > crate::nft::NFTV1_URI_MAX_BYTES
    {
        return Err(format!(
            "nft_max_uri_bytes_out_of_range: value={} max={}",
            params.nft_max_uri_bytes,
            crate::nft::NFTV1_URI_MAX_BYTES
        ));
    }
    if params.nft_max_name_bytes == 0
        || params.nft_max_name_bytes as usize > crate::nft::NFTV1_NAME_MAX_BYTES
    {
        return Err(format!(
            "nft_max_name_bytes_out_of_range: value={} max={}",
            params.nft_max_name_bytes,
            crate::nft::NFTV1_NAME_MAX_BYTES
        ));
    }
    if params.nft_max_symbol_bytes == 0
        || params.nft_max_symbol_bytes as usize > crate::nft::NFTV1_SYMBOL_MAX_BYTES
    {
        return Err(format!(
            "nft_max_symbol_bytes_out_of_range: value={} max={}",
            params.nft_max_symbol_bytes,
            crate::nft::NFTV1_SYMBOL_MAX_BYTES
        ));
    }

    if params.nft_enabled {
        if params.nft_activation_height == u64::MAX {
            return Err("nft_enabled_requires_finite_activation_height".to_string());
        }
        if params.nft_max_collections_per_owner == 0 {
            return Err("nft_enabled_requires_max_collections_per_owner_gt_zero".to_string());
        }
        if params.nft_max_tokens_per_collection == 0 {
            return Err("nft_enabled_requires_max_tokens_per_collection_gt_zero".to_string());
        }
        if params.nft_max_tokens_per_owner == 0 {
            return Err("nft_enabled_requires_max_tokens_per_owner_gt_zero".to_string());
        }
        if params.nft_public_create_enabled && params.nft_max_collections_per_owner == 0 {
            return Err(
                "nft_public_create_enabled_requires_max_collections_per_owner_gt_zero".to_string(),
            );
        }
        if params.nft_public_mint_enabled && params.nft_max_tokens_per_collection == 0 {
            return Err(
                "nft_public_mint_enabled_requires_max_tokens_per_collection_gt_zero".to_string(),
            );
        }
        if params.nft_public_mint_enabled && params.nft_max_tokens_per_owner == 0 {
            return Err(
                "nft_public_mint_enabled_requires_max_tokens_per_owner_gt_zero".to_string(),
            );
        }
        if params.nft_public_transfer_enabled && params.nft_max_tokens_per_collection == 0 {
            return Err(
                "nft_public_transfer_enabled_requires_max_tokens_per_collection_gt_zero"
                    .to_string(),
            );
        }
        if params.nft_public_transfer_enabled && params.nft_max_tokens_per_owner == 0 {
            return Err(
                "nft_public_transfer_enabled_requires_max_tokens_per_owner_gt_zero".to_string(),
            );
        }
    }

    let mut fee_sum = 0u64;
    for (name, fee) in [
        ("nft_create_fee_native", params.nft_create_fee_native),
        ("nft_mint_fee_native", params.nft_mint_fee_native),
        ("nft_transfer_fee_native", params.nft_transfer_fee_native),
        ("nft_approval_fee_native", params.nft_approval_fee_native),
        ("nft_burn_fee_native", params.nft_burn_fee_native),
        ("nft_revoke_fee_native", params.nft_revoke_fee_native),
        (
            "nft_metadata_update_fee_native",
            params.nft_metadata_update_fee_native,
        ),
        ("nft_freeze_fee_native", params.nft_freeze_fee_native),
        (
            "nft_policy_update_fee_native",
            params.nft_policy_update_fee_native,
        ),
        (
            "nft_issuer_update_fee_native",
            params.nft_issuer_update_fee_native,
        ),
        ("nft_pause_fee_native", params.nft_pause_fee_native),
    ] {
        fee_sum = fee_sum
            .checked_add(fee)
            .ok_or_else(|| format!("nft_fee_sum_overflow_at:{}", name))?;
    }

    Ok(())
}

// ----------------------
// Safe Mode (stato di emergenza)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SafeModeState {
    /// Se true, la rete è in modalità "safe"
    pub active: bool,
    /// Altezza del blocco in cui è stata attivata la modalità safe
    pub activated_at: Option<u64>,
}

// ----------------------
// Stato interno delle proposte
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Applied,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GovVoteRecordV1 {
    #[serde(default)]
    pub proposal_hash_hex: String,
    #[serde(default)]
    pub signature_domain: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub genesis_hash: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposalRecord {
    /// ID univoco della proposta (es. "2025-001" o un UUID)
    pub id: String,
    pub kind: GovProposalKind,
    /// Council responsabile (Protocol / Economy / Emergency)
    pub council: GovernanceCouncilKind,
    /// Payload raw: viene interpretato in base al kind (schema noto lato nodo/tool)
    pub payload: Vec<u8>,
    /// Height in cui è stata creata la proposta
    pub created_at_height: u64,
    /// Height a partire dalla quale può essere applicata (timelock)
    pub effective_height: u64,
    /// Chi ha proposto (pubkey any form)
    pub proposer: String,
    /// Firma del proposer (base64 signature over proposal_signing_bytes_v1)
    pub signature: String,
    /// Governance signature domain accepted for this proposal.
    #[serde(default)]
    pub signature_domain: String,
    /// Chain/network id bound into the accepted proposal signature.
    #[serde(default)]
    pub chain_id: String,
    /// Genesis hash bound into the accepted proposal signature.
    #[serde(default)]
    pub genesis_hash: String,
    /// Proposal hash (sha256 over canonical proposal fields) used to bind votes.
    #[serde(default)]
    pub proposal_hash_hex: String,
    /// Stato corrente della proposta
    pub status: ProposalStatus,
    /// Voti raccolti: mappa voter_pubkey_hex -> firma base64 (legacy compact view).
    pub votes: HashMap<String, String>,
    /// Audit-grade vote records preserving the exact hash/domain signed by each voter.
    #[serde(default)]
    pub vote_records_v1: HashMap<String, GovVoteRecordV1>,
    /// Height at which this proposal reached a terminal state (Applied/Rejected/Expired).
    /// WAL governance ingress compaction uses this value instead of `effective_height`: a
    /// proposal may become eligible at `effective_height` but only actually apply later.
    /// Entries are recoverable until the terminal transition itself is finalized.
    #[serde(default)]
    pub terminal_height: Option<u64>,
}

// ----------------------
// TX di governance (on-chain)
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxGovernanceProposal {
    pub id: String,
    pub kind: GovProposalKind,
    pub payload: Vec<u8>,
    pub created_at_height: u64,
    pub effective_height: u64,
    pub proposer: String,
    /// Governance signature domain version. Required in release/mainnet paths.
    #[serde(default)]
    pub signature_domain: String,
    /// Chain/network identifier bound into the proposal signature.
    #[serde(default)]
    pub chain_id: String,
    /// Genesis hash bound into the proposal signature.
    #[serde(default)]
    pub genesis_hash: String,
    /// base64(64) ed25519 signature
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxGovernanceVote {
    pub proposal_id: String,
    /// Exact proposal hash confirmed by the voter. This makes WAL/reorg/audit behavior explicit:
    /// a vote for H1 cannot silently become a vote for a reincluded proposal H2.
    #[serde(default)]
    pub proposal_hash_hex: String,
    pub voter: String,
    /// Governance signature domain version. Required in release/mainnet paths.
    #[serde(default)]
    pub signature_domain: String,
    /// Chain/network identifier bound into the vote signature.
    #[serde(default)]
    pub chain_id: String,
    /// Genesis hash bound into the vote signature.
    #[serde(default)]
    pub genesis_hash: String,
    /// base64(64) ed25519 signature
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxFinalityVote {
    /// Deterministic checkpoint for finality (see checkpoint.rs).
    pub checkpoint: Checkpoint,
    /// Ed25519 signature over checkpoint.signing_bytes().
    pub sig: CheckpointSig,
}

/// TX di governance che può stare dentro un blocco
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GovernanceTx {
    Proposal(TxGovernanceProposal),
    Vote(TxGovernanceVote),
    /// Finality vote for deterministic checkpoints (consensus-critical).
    FinalityVote(TxFinalityVote),
}

// ----------------------
// Stato globale di governance
// ----------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceState {
    /// Council che governa validator set, protocol version e security "hard"
    pub protocol_council: Council,

    /// Council che governa la parte economica (fee, reward, treasury, ecc.)
    pub economy_council: Council,

    /// Council di emergenza (safe mode, revoche)
    pub emergency_council: Council,

    /// Parametri globali (timelock, durata massima emergenza)
    pub params: GovernanceParams,

    /// Timelock minimo per proposte Emergency (default 0).
    #[serde(default)]
    pub min_timelock_blocks_emergency: u64,

    /// Downtime policy governabile (deterministica, con audit trail).
    #[serde(default)]
    pub downtime_policy: DowntimePolicy,

    /// Validator set canonico on-chain (canonico: HEX)
    pub validator_set: ValidatorSet,

    /// Override on-chain (delta) per la economy policy
    #[serde(default)]
    pub economy_overrides: EconomyPolicyDelta,

    /// Override on-chain (delta) per la security policy "hard"
    #[serde(default)]
    pub security_overrides: SecurityPolicyDelta,

    /// Reputazione canonica wallet-plane, governata e deterministica.
    ///
    /// Oggi viene derivata dal validator-plane per i wallet/validator conosciuti,
    /// ma il piano è esplicito e pronto a estendersi a identità non-validator.
    #[serde(default)]
    pub wallet_reputation: HashMap<String, WalletGovReputation>,

    /// Canonical E2 worker-node -> operator-wallet bindings.
    ///
    /// This is the only source consumed by worker eligibility/admission. It is
    /// deliberately separate from wallet_reputation to avoid fusing machine keys
    /// with provider economic identity.
    #[serde(default)]
    pub e2_worker_operator_bindings: BTreeMap<String, E2WorkerOperatorBindingRecordV1>,

    /// Privilegi E2 governati dal concilium per capacità ad alto rischio.
    ///
    /// Questo NON è il path ordinario di onboarding worker. Un worker self-registered
    /// deve partire PROBATION/probe-only; Cloud Unit, GPU e critical workload restano
    /// privilegi espliciti governati/finality-bound.
    #[serde(default)]
    pub e2_worker_governed_privileges: BTreeMap<String, E2WorkerGovernedPrivilegeRecordV1>,

    /// Reputazione on-chain dei validator (misbehavior, ban, jail, ecc.)
    pub validator_reputation: HashMap<String, ValidatorGovReputation>,

    /// Snapshot degli entry rimossi (revocati/ruotati) per restore deterministico.
    #[serde(default)]
    pub revoked_validators: HashMap<String, ValidatorEntry>,

    /// Operator Role Model V2 validator -> compute transition audit state keyed by validator pubkey hex.
    #[serde(default)]
    pub validator_compute_transitions: BTreeMap<String, ValidatorComputeTransitionRecordV1>,

    /// Proposte indicizzate per ID
    pub proposals: HashMap<String, GovProposalRecord>,

    /// Height-bounded invalid governance proposal counters by proposer wallet.
    /// A single malformed/invalid proposal remains reject-only; repeated invalid proposals
    /// in the same window become wallet misconduct spam evidence.
    #[serde(default)]
    pub wallet_governance_invalid_proposal_windows:
        HashMap<String, WalletGovernanceInvalidProposalWindowV1>,

    /// Stato della modalità emergenza
    pub safe_mode: SafeModeState,

    /// Override reputazione governabili (Step 48A). Applicati dal runtime in Step 48B.
    #[serde(default)]
    pub reputation_overrides: ReputationPolicyDelta,

    /// Override mempool governabili (Step 48C).
    #[serde(default)]
    pub mempool_overrides: MempoolPolicyDelta,

    /// Audit trail deterministico per operazioni validator (rotazione/revoca/jail)
    #[serde(default)]
    pub validator_ops_log: Vec<ValidatorOpsLogEntry>,

    /// Evidenze canoniche ingerite dal run-plane e approvate via governance.
    #[serde(default)]
    pub wallet_reputation_evidence_log: Vec<WalletReputationCanonicalEvidence>,
    /// Index finestra corrente per dedupe degli evidence_id ingeriti.
    #[serde(default)]
    pub wallet_reputation_evidence_ids: BTreeSet<String>,

    /// Aggregati canonici per claim reputazionale multi-source.
    #[serde(default)]
    pub wallet_reputation_claims: HashMap<String, WalletReputationCanonicalClaimAggregate>,
}

pub const GOVERNANCE_SIGNATURE_DOMAIN_V2: &str = "nggov-signature-domain-v2";

static GOVERNANCE_SIGNATURE_GENESIS_HASH_V1: OnceLock<RwLock<String>> = OnceLock::new();

pub fn set_governance_signature_genesis_hash_v1(genesis_hash: &str) {
    let lock = GOVERNANCE_SIGNATURE_GENESIS_HASH_V1.get_or_init(|| RwLock::new(String::new()));
    if let Ok(mut guard) = lock.write() {
        *guard = genesis_hash.trim().to_ascii_lowercase();
    }
}

fn governance_signature_genesis_hash_v1() -> String {
    GOVERNANCE_SIGNATURE_GENESIS_HASH_V1
        .get()
        .and_then(|lock| lock.read().ok().map(|g| g.clone()))
        .filter(|g| !g.trim().is_empty())
        .unwrap_or_else(|| {
            std::env::var("NEWGEN_GOVERNANCE_SIGNATURE_GENESIS_HASH").unwrap_or_default()
        })
        .trim()
        .to_ascii_lowercase()
}

fn governance_domain_chain_id_v1() -> String {
    crate::chain_identity::chain_id().to_string()
}

pub fn governance_signature_genesis_hash_for_runtime_v1() -> String {
    governance_domain_genesis_for_signing_v1()
}

fn governance_domain_genesis_for_signing_v1() -> String {
    let g = governance_signature_genesis_hash_v1();
    if !g.trim().is_empty() {
        return g;
    }
    if allow_legacy_gov() {
        // Unit tests and old dev-only fixtures may not bootstrap a full Blockchain genesis context.
        // Release/mainnet paths must initialize the real genesis hash before signing/verifying.
        return "legacy-debug-genesis-context".to_string();
    }
    String::new()
}

fn contains_separator_v1(v: &str) -> bool {
    v.contains('|')
}

fn is_lowercase_hex64_v1(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_canonical_governance_proposal_id_v1(raw: &str) -> bool {
    let id = raw.trim();
    if id.is_empty() || id.len() > 160 {
        return false;
    }
    if raw != id {
        return false;
    }
    if id.starts_with('-') || id.ends_with('-') {
        return false;
    }
    if !id
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return false;
    }
    let Some((prefix, suffix)) = id.rsplit_once("-govp-") else {
        return false;
    };
    if prefix.is_empty() || prefix.starts_with('-') || prefix.ends_with('-') {
        return false;
    }
    is_lowercase_hex32_v1(suffix)
}

fn is_lowercase_hex32_v1(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical_domain_field_v1(
    tx_kind: &str,
    name: &str,
    value: &str,
    legacy_fallback: String,
) -> Result<String, String> {
    if value.is_empty() {
        if allow_legacy_gov() {
            return Ok(legacy_fallback);
        }
        return Err(format!("governance {tx_kind} domain missing field: {name}"));
    }
    if value != value.trim() {
        return Err(format!(
            "governance {tx_kind} domain field must be raw-canonical without whitespace: {name}"
        ));
    }
    if contains_separator_v1(value) {
        return Err(format!(
            "governance {tx_kind} domain contains invalid '|': {name}"
        ));
    }
    Ok(value.to_string())
}

fn validate_domain_fields_v1(
    tx_kind: &str,
    domain: String,
    chain_id: String,
    genesis_hash: String,
) -> Result<(String, String, String), String> {
    if domain != GOVERNANCE_SIGNATURE_DOMAIN_V2 {
        return Err(format!("governance {tx_kind} domain version mismatch"));
    }
    if chain_id != governance_domain_chain_id_v1() {
        return Err(format!("governance {tx_kind} chain_id mismatch"));
    }
    if genesis_hash == "legacy-debug-genesis-context" {
        if allow_legacy_gov() {
            return Ok((domain, chain_id, genesis_hash));
        }
        return Err(format!(
            "governance {tx_kind} legacy genesis context not allowed"
        ));
    }
    if !is_lowercase_hex64_v1(&genesis_hash) {
        return Err(format!(
            "governance {tx_kind} genesis_hash must be 64 lowercase hex chars"
        ));
    }
    let expected_genesis = governance_signature_genesis_hash_v1();
    if !expected_genesis.is_empty() && genesis_hash != expected_genesis {
        return Err(format!("governance {tx_kind} genesis_hash mismatch"));
    }
    Ok((domain, chain_id, genesis_hash))
}

fn proposal_domain_fields_v1(p: &TxGovernanceProposal) -> Result<(String, String, String), String> {
    let domain = canonical_domain_field_v1(
        "proposal",
        "signature_domain",
        &p.signature_domain,
        GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
    )?;
    let chain_id = canonical_domain_field_v1(
        "proposal",
        "chain_id",
        &p.chain_id,
        governance_domain_chain_id_v1(),
    )?;
    let genesis_hash = canonical_domain_field_v1(
        "proposal",
        "genesis_hash",
        &p.genesis_hash,
        governance_domain_genesis_for_signing_v1(),
    )?;
    validate_domain_fields_v1("proposal", domain, chain_id, genesis_hash)
}

fn vote_domain_fields_v1(v: &TxGovernanceVote) -> Result<(String, String, String), String> {
    let domain = canonical_domain_field_v1(
        "vote",
        "signature_domain",
        &v.signature_domain,
        GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
    )?;
    let chain_id = canonical_domain_field_v1(
        "vote",
        "chain_id",
        &v.chain_id,
        governance_domain_chain_id_v1(),
    )?;
    let genesis_hash = canonical_domain_field_v1(
        "vote",
        "genesis_hash",
        &v.genesis_hash,
        governance_domain_genesis_for_signing_v1(),
    )?;
    validate_domain_fields_v1("vote", domain, chain_id, genesis_hash)
}

fn allow_legacy_gov() -> bool {
    // Legacy/debug signatures are test-only by default. A debug build must not silently
    // accept unauthenticated governance on a lab/server used by other people.
    #[cfg(test)]
    {
        true
    }

    #[cfg(not(test))]
    {
        let explicit = std::env::var("NEWGEN_ALLOW_LEGACY_GOV")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        explicit && !crate::runtime_mode::public_mode_enabled()
    }
}

/// Public view helper for API/read-model code that needs to decide whether legacy compact
/// governance vote fields may be interpreted. Runtime release/public paths remain fail-closed.
pub fn legacy_governance_compact_votes_allowed_for_view_v1() -> bool {
    allow_legacy_gov()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn verify_ed25519_sig_b64(pk_any: &str, sig_b64: &str, msg: &[u8]) -> Result<(), String> {
    let pk = keyfmt::decode_pk_any(pk_any).map_err(|e| format!("pubkey decode failed: {e}"))?;
    let sig_arr =
        keyfmt::decode_sig64_b64(sig_b64).map_err(|e| format!("signature decode failed: {e}"))?;

    let vk =
        VerifyingKey::from_bytes(&pk).map_err(|e| format!("VerifyingKey parse failed: {e}"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig)
        .map_err(|e| format!("signature verify failed: {e}"))?;
    Ok(())
}

fn proposal_payload_hash_hex(payload: &[u8]) -> String {
    sha256_hex(payload)
}

pub fn proposal_signing_bytes_v1(
    p: &TxGovernanceProposal,
    council: &GovernanceCouncilKind,
) -> Result<Vec<u8>, String> {
    if !is_canonical_governance_proposal_id_v1(&p.id) {
        return Err("proposal id must be canonical '<prefix>-govp-<32 lowercase hex>'".to_string());
    }
    // Prevent separator injection.
    for (name, v) in [("id", &p.id), ("proposer", &p.proposer)] {
        if v.contains('|') {
            return Err(format!("proposal field contains invalid '|': {name}"));
        }
    }
    let (domain, chain_id, genesis_hash) = proposal_domain_fields_v1(p)?;
    let proposer_hex = keyfmt::pk_hex_from_any(&p.proposer)
        .map_err(|e| format!("proposer pubkey invalid: {e}"))?;
    let payload_hash = proposal_payload_hash_hex(&p.payload);

    let s = format!(
        "nggov|proposal|v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        domain,
        chain_id,
        genesis_hash,
        p.id,
        kind_tag(&p.kind),
        council_tag(council),
        p.created_at_height,
        p.effective_height,
        proposer_hex,
        payload_hash,
    );
    Ok(s.into_bytes())
}

fn proposal_hash_hex_v1(
    p: &TxGovernanceProposal,
    council: &GovernanceCouncilKind,
) -> Result<String, String> {
    let msg = proposal_signing_bytes_v1(p, council)?;
    Ok(sha256_hex(&msg))
}

pub fn vote_signing_bytes_for_tx_v1(v: &TxGovernanceVote) -> Result<Vec<u8>, String> {
    if !is_canonical_governance_proposal_id_v1(&v.proposal_id) {
        return Err(
            "vote proposal_id must be canonical '<prefix>-govp-<32 lowercase hex>'".to_string(),
        );
    }
    let proposal_hash_hex = v.proposal_hash_hex.as_str();
    if !is_lowercase_hex64_v1(proposal_hash_hex) {
        return Err("vote proposal_hash_hex must be canonical lowercase 64 hex chars".to_string());
    }
    for (name, value) in [
        ("proposal_id", v.proposal_id.as_str()),
        ("proposal_hash_hex", proposal_hash_hex),
        ("voter", v.voter.as_str()),
    ] {
        if value.contains('|') {
            return Err(format!("vote field contains invalid '|': {name}"));
        }
    }
    let (domain, chain_id, genesis_hash) = vote_domain_fields_v1(v)?;
    let voter_hex =
        keyfmt::pk_hex_from_any(&v.voter).map_err(|e| format!("voter pubkey invalid: {e}"))?;
    let s = format!(
        "nggov|vote|v2|{}|{}|{}|{}|{}|{}",
        domain, chain_id, genesis_hash, v.proposal_id, proposal_hash_hex, voter_hex
    );
    Ok(s.into_bytes())
}

pub fn vote_signing_bytes_v1(
    proposal_id: &str,
    proposal_hash_hex: &str,
    voter_any: &str,
) -> Result<Vec<u8>, String> {
    let v = TxGovernanceVote {
        proposal_id: proposal_id.to_string(),
        proposal_hash_hex: proposal_hash_hex.to_string(),
        voter: voter_any.to_string(),
        signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
        chain_id: governance_domain_chain_id_v1(),
        genesis_hash: governance_domain_genesis_for_signing_v1(),
        signature: String::new(),
    };
    vote_signing_bytes_for_tx_v1(&v)
}

/// Verifies a governance vote against the exact v2 signing domain and signature bytes.
///
/// This is intentionally reusable by ingress/WAL code: a vote that the core would later
/// reject must not be accepted into the node-local durable queue. Legacy/debug vote
/// signatures remain confined to `allow_legacy_gov()` paths and never leak into public
/// mode.
pub fn verify_governance_vote_signature_v1(v: &TxGovernanceVote) -> Result<(), String> {
    let msg = vote_signing_bytes_for_tx_v1(v)?;
    if allow_legacy_gov() && (v.signature.trim().is_empty() || v.signature.trim() == "debug") {
        return Ok(());
    }
    verify_ed25519_sig_b64(&v.voter, &v.signature, &msg)
}

impl GovernanceState {
    fn stage_governance_params_delta_v1(
        &self,
        delta: &GovernanceParamsDelta,
    ) -> Result<GovernanceParamsUpdateStagedV1, String> {
        let params = preview_governance_params_delta_v1(&self.params, delta)?;
        let mut min_timelock_blocks_emergency = self.min_timelock_blocks_emergency;
        let mut downtime_policy = self.downtime_policy.clone();
        let mut protocol_council = self.protocol_council.clone();
        let mut economy_council = self.economy_council.clone();
        let mut emergency_council = self.emergency_council.clone();

        if let Some(v) = delta.min_timelock_blocks_emergency {
            min_timelock_blocks_emergency = v;
        }

        if let Some(t) = delta.protocol_threshold {
            protocol_council.threshold = t;
            protocol_council.normalize("protocol");
        }
        if let Some(t) = delta.economy_threshold {
            economy_council.threshold = t;
            economy_council.normalize("economy");
        }
        if let Some(t) = delta.emergency_threshold {
            emergency_council.threshold = t;
            emergency_council.normalize("emergency");
        }

        if let Some(v) = delta.downtime_enabled {
            downtime_policy.enabled = v;
        }
        if let Some(v) = delta.downtime_consecutive_missed_turns_threshold {
            downtime_policy.consecutive_missed_turns_threshold = v.max(1);
        }
        if let Some(v) = delta.downtime_jail_duration_blocks {
            downtime_policy.jail_duration_blocks = v.max(1);
        }

        Ok(GovernanceParamsUpdateStagedV1 {
            params,
            min_timelock_blocks_emergency,
            downtime_policy,
            protocol_council,
            economy_council,
            emergency_council,
        })
    }

    pub fn new(
        protocol_council: Council,
        economy_council: Council,
        emergency_council: Council,
        params: GovernanceParams,
        initial_validator_set: ValidatorSet,
    ) -> Self {
        let mut protocol_council = protocol_council;
        let mut economy_council = economy_council;
        let mut emergency_council = emergency_council;

        protocol_council.normalize("protocol");
        economy_council.normalize("economy");
        emergency_council.normalize("emergency");

        let mut params = params;
        if params.wallet_reputation_promotion_quorum == 0 {
            eprintln!(
                "[GOV] wallet_reputation_promotion_quorum=0 invalid; falling back to default"
            );
            params.wallet_reputation_promotion_quorum =
                default_wallet_reputation_promotion_quorum();
        }
        if params.max_proposal_lifetime_blocks == 0 {
            eprintln!("[GOV] max_proposal_lifetime_blocks=0 invalid; falling back to default");
            params.max_proposal_lifetime_blocks =
                default_governance_proposal_max_lifetime_blocks_v1();
        }
        if let Err(e) = validate_nft_governance_policy_v1(&params) {
            if crate::runtime_mode::public_mode_enabled() {
                panic!(
                    "[GOV][FAIL-CLOSED] invalid NFT governance policy in public mode: {}",
                    e
                );
            }
            eprintln!(
                "[GOV] invalid NFT governance policy in non-public mode: {}",
                e
            );
        }

        let mut gov = Self {
            protocol_council,
            economy_council,
            emergency_council,
            params,
            min_timelock_blocks_emergency: 0,
            downtime_policy: DowntimePolicy::default(),
            validator_set: initial_validator_set,

            economy_overrides: EconomyPolicyDelta::default(),
            security_overrides: SecurityPolicyDelta::default(),
            reputation_overrides: ReputationPolicyDelta::default(),
            mempool_overrides: MempoolPolicyDelta::default(),

            wallet_reputation: HashMap::new(),
            e2_worker_operator_bindings: BTreeMap::new(),
            e2_worker_governed_privileges: BTreeMap::new(),
            validator_reputation: HashMap::new(),
            revoked_validators: HashMap::new(),
            validator_compute_transitions: BTreeMap::new(),
            proposals: HashMap::new(),
            wallet_governance_invalid_proposal_windows: HashMap::new(),
            safe_mode: SafeModeState::default(),
            validator_ops_log: Vec::new(),
            wallet_reputation_evidence_log: Vec::new(),
            wallet_reputation_evidence_ids: BTreeSet::new(),
            wallet_reputation_claims: HashMap::new(),
        };

        // Canonicalize initial validator set (HEX, sorted, dedup).
        if let Err(e) = gov.normalize_validator_set_in_place() {
            eprintln!("[GOV] initial validator set normalization failed: {e}");
        }

        gov
    }

    /// Ricostruisce lo stato di governance applicando in sequenza
    /// le proposal contenute nei blocchi.
    ///
    /// Nota: qui ci interessa principalmente ricostruire gli override.
    pub fn rebuild_from_chain(blocks: &[Block]) -> Self {
        let mut gov = GovernanceState {
            protocol_council: Council {
                members: Vec::new(),
                threshold: 0,
            },
            economy_council: Council {
                members: Vec::new(),
                threshold: 0,
            },
            emergency_council: Council {
                members: Vec::new(),
                threshold: 0,
            },
            params: GovernanceParams {
                min_timelock_blocks: 0,
                max_proposal_lifetime_blocks: default_governance_proposal_max_lifetime_blocks_v1(),
                max_emergency_duration_blocks: 0,
                wallet_reputation_promotion_quorum: default_wallet_reputation_promotion_quorum(),
                e2_worker_admission_activation_height:
                    default_e2_worker_admission_activation_height(),
                validator_compute_transition_min_active_validators:
                    default_validator_compute_transition_min_active_validators(),
                validator_compute_transition_min_finality_quorum:
                    default_validator_compute_transition_min_finality_quorum(),
                validator_compute_transition_validator_quality_floor:
                    default_validator_compute_transition_validator_quality_floor(),
                validator_compute_transition_exit_cooldown_blocks:
                    default_validator_compute_transition_exit_cooldown_blocks(),
                validator_compute_transition_max_finality_lag_blocks:
                    default_validator_compute_transition_max_finality_lag_blocks(),
                validator_compute_transition_max_recent_missed_slots:
                    default_validator_compute_transition_max_recent_missed_slots(),
                ft_activation_height: u64::MAX,
                ft_max_tokens_per_owner: default_ft_max_tokens_per_owner(),
                ft_create_cooldown_blocks: default_ft_create_cooldown_blocks(),
                ft_create_fee_native: default_ft_create_fee_native(),
                nft_activation_height: u64::MAX,
                nft_max_collections_per_owner: default_nft_max_collections_per_owner(),
                nft_create_cooldown_blocks: default_nft_create_cooldown_blocks(),
                nft_create_fee_native: default_nft_create_fee_native(),
                nft_enabled: default_nft_enabled(),
                nft_public_create_enabled: default_nft_public_create_enabled(),
                nft_public_mint_enabled: default_nft_public_mint_enabled(),
                nft_public_transfer_enabled: default_nft_public_transfer_enabled(),
                nft_public_approval_enabled: default_nft_public_approval_enabled(),
                nft_public_burn_enabled: default_nft_public_burn_enabled(),
                nft_public_revoke_enabled: default_nft_public_revoke_enabled(),
                nft_public_metadata_update_enabled: default_nft_public_metadata_update_enabled(),
                nft_public_freeze_enabled: default_nft_public_freeze_enabled(),
                nft_public_policy_update_enabled: default_nft_public_policy_update_enabled(),
                nft_public_issuer_update_enabled: default_nft_public_issuer_update_enabled(),
                nft_public_pause_enabled: default_nft_public_pause_enabled(),
                nft_metadata_hash_required: default_nft_metadata_hash_required(),
                nft_max_memo_bytes: default_nft_max_memo_bytes(),
                nft_max_uri_bytes: default_nft_max_uri_bytes(),
                nft_max_name_bytes: default_nft_max_name_bytes(),
                nft_max_symbol_bytes: default_nft_max_symbol_bytes(),
                nft_max_tokens_per_collection: default_nft_max_tokens_per_collection(),
                nft_max_tokens_per_owner: default_nft_max_tokens_per_owner(),
                nft_mint_fee_native: default_nft_mint_fee_native(),
                nft_transfer_fee_native: default_nft_transfer_fee_native(),
                nft_approval_fee_native: default_nft_approval_fee_native(),
                nft_burn_fee_native: default_nft_burn_fee_native(),
                nft_revoke_fee_native: default_nft_revoke_fee_native(),
                nft_metadata_update_fee_native: default_nft_metadata_update_fee_native(),
                nft_freeze_fee_native: default_nft_freeze_fee_native(),
                nft_policy_update_fee_native: default_nft_policy_update_fee_native(),
                nft_issuer_update_fee_native: default_nft_issuer_update_fee_native(),
                nft_pause_fee_native: default_nft_pause_fee_native(),
            },
            min_timelock_blocks_emergency: 0,
            downtime_policy: DowntimePolicy::default(),
            validator_set: ValidatorSet::default(),

            economy_overrides: EconomyPolicyDelta::default(),
            security_overrides: SecurityPolicyDelta::default(),
            reputation_overrides: ReputationPolicyDelta::default(),
            mempool_overrides: MempoolPolicyDelta::default(),

            wallet_reputation: HashMap::new(),
            e2_worker_operator_bindings: BTreeMap::new(),
            e2_worker_governed_privileges: BTreeMap::new(),
            validator_reputation: HashMap::new(),
            revoked_validators: HashMap::new(),
            validator_compute_transitions: BTreeMap::new(),
            proposals: HashMap::new(),
            wallet_governance_invalid_proposal_windows: HashMap::new(),
            safe_mode: SafeModeState::default(),
            validator_ops_log: Vec::new(),
            wallet_reputation_evidence_log: Vec::new(),
            wallet_reputation_evidence_ids: BTreeSet::new(),
            wallet_reputation_claims: HashMap::new(),
        };

        for block in blocks {
            for tx in &block.governance_txs {
                if let GovernanceTx::Proposal(p) = tx {
                    match p.kind.clone() {
                        GovProposalKind::UpdateEconomyPolicy => {
                            if let Ok(delta) =
                                serde_json::from_slice::<EconomyPolicyDelta>(&p.payload)
                            {
                                if delta.base_fee_per_tx.is_some() {
                                    gov.economy_overrides.base_fee_per_tx = delta.base_fee_per_tx;
                                }
                                if let Some(v) = delta.treasury_pct_base_bps {
                                    gov.economy_overrides.treasury_pct_base_bps =
                                        Some(v.min(10_000));
                                }
                                if delta.burn_bps.is_some() {
                                    gov.economy_overrides.burn_bps = delta.burn_bps;
                                }
                            }
                        }

                        GovProposalKind::UpdateSecurityPolicy => {
                            if let Ok(delta) =
                                serde_json::from_slice::<SecurityPolicyDelta>(&p.payload)
                            {
                                if delta.min_fee_per_tx.is_some() {
                                    gov.security_overrides.min_fee_per_tx = delta.min_fee_per_tx;
                                }
                                if delta.max_block_size.is_some() {
                                    gov.security_overrides.max_block_size = delta.max_block_size;
                                }
                            }
                        }

                        GovProposalKind::UpdateReputationPolicy => {
                            if let Ok(delta) =
                                serde_json::from_slice::<ReputationPolicyDelta>(&p.payload)
                            {
                                if let Err(e) =
                                    delta.validate_merged_contract_v1(&gov.reputation_overrides)
                                {
                                    eprintln!(
                                        "⚠️ [GOV] Skip persisted invalid ReputationPolicyDelta: {}",
                                        e
                                    );
                                    continue;
                                }
                                if delta.good_threshold.is_some() {
                                    gov.reputation_overrides.good_threshold = delta.good_threshold;
                                }
                                if delta.probation_threshold.is_some() {
                                    gov.reputation_overrides.probation_threshold =
                                        delta.probation_threshold;
                                }
                                if delta.banned_threshold.is_some() {
                                    gov.reputation_overrides.banned_threshold =
                                        delta.banned_threshold;
                                }

                                if delta.ban_duration_secs.is_some() {
                                    gov.reputation_overrides.ban_duration_secs =
                                        delta.ban_duration_secs;
                                }
                                if delta.decay_per_tick.is_some() {
                                    gov.reputation_overrides.decay_per_tick = delta.decay_per_tick;
                                }
                                if delta.tick_secs.is_some() {
                                    gov.reputation_overrides.tick_secs = delta.tick_secs;
                                }

                                if delta.w_valid_tx.is_some() {
                                    gov.reputation_overrides.w_valid_tx = delta.w_valid_tx;
                                }
                                if delta.w_invalid_tx.is_some() {
                                    gov.reputation_overrides.w_invalid_tx = delta.w_invalid_tx;
                                }
                                if delta.w_valid_block.is_some() {
                                    gov.reputation_overrides.w_valid_block = delta.w_valid_block;
                                }
                                if delta.w_invalid_block.is_some() {
                                    gov.reputation_overrides.w_invalid_block =
                                        delta.w_invalid_block;
                                }
                                if delta.w_spam.is_some() {
                                    gov.reputation_overrides.w_spam = delta.w_spam;
                                }
                                if delta.w_disconnect.is_some() {
                                    gov.reputation_overrides.w_disconnect = delta.w_disconnect;
                                }
                                if delta.w_slashed.is_some() {
                                    gov.reputation_overrides.w_slashed = delta.w_slashed;
                                }
                            }
                        }

                        GovProposalKind::UpdateMempoolPolicy => {
                            if let Ok(delta) =
                                serde_json::from_slice::<MempoolPolicyDelta>(&p.payload)
                            {
                                if delta.max_mempool_size.is_some() {
                                    gov.mempool_overrides.max_mempool_size = delta.max_mempool_size;
                                }
                                if delta.max_tx_per_sender.is_some() {
                                    gov.mempool_overrides.max_tx_per_sender =
                                        delta.max_tx_per_sender;
                                }
                                if delta.max_mempool_bytes.is_some() {
                                    gov.mempool_overrides.max_mempool_bytes =
                                        delta.max_mempool_bytes;
                                }
                                if delta.tx_ttl_secs.is_some() {
                                    gov.mempool_overrides.tx_ttl_secs = delta.tx_ttl_secs;
                                }
                            }
                        }

                        _ => { /* ignore */ }
                    }
                }
            }
        }

        gov
    }

    /// Helper per sapere se la modalità safe è attiva a una certa height,
    /// tenendo conto anche della durata massima.
    pub fn is_safe_mode_active(&self, current_height: u64) -> bool {
        if !self.safe_mode.active {
            return false;
        }

        if let Some(activated_at) = self.safe_mode.activated_at {
            let max = self.params.max_emergency_duration_blocks;
            if current_height >= activated_at + max {
                return false;
            }
        }

        true
    }

    /// Determina quale council è responsabile di un certo tipo di proposta.
    pub fn council_for_kind(&self, kind: &GovProposalKind) -> GovernanceCouncilKind {
        match kind {
            GovProposalKind::UpdateValidators
            | GovProposalKind::UpdateSecurityPolicy
            | GovProposalKind::UpdateReputationPolicy
            | GovProposalKind::IngestWalletReputationEvidence
            | GovProposalKind::IngestE2WorkerReputationEvidence
            | GovProposalKind::BindE2WorkerOperatorWallet
            | GovProposalKind::GrantE2WorkerCloudUnit
            | GovProposalKind::RevokeE2WorkerCloudUnit
            | GovProposalKind::GrantE2WorkerGpuCapability
            | GovProposalKind::RevokeE2WorkerGpuCapability
            | GovProposalKind::GrantE2WorkerCriticalWorkload
            | GovProposalKind::RevokeE2WorkerCriticalWorkload
            | GovProposalKind::UpdateMempoolPolicy
            | GovProposalKind::BumpProtocolVersion
            | GovProposalKind::UpdateGovernanceParams
            | GovProposalKind::RotateValidatorKey => GovernanceCouncilKind::Protocol,

            GovProposalKind::UpdateEconomyPolicy
            | GovProposalKind::IngestComputeFiatSettlementProof => GovernanceCouncilKind::Economy,

            GovProposalKind::EmergencySafeModeOn
            | GovProposalKind::EmergencySafeModeOff
            | GovProposalKind::RevokeValidator
            | GovProposalKind::UnrevokeValidator
            | GovProposalKind::RequestValidatorComputeTransition
            | GovProposalKind::CancelValidatorComputeTransition => GovernanceCouncilKind::Emergency,
        }
    }

    /// Punto d’ingresso: applica le TX di governance di un blocco a questo stato.
    pub fn apply_block_governance(&mut self, block_height: u64, governance_txs: &[GovernanceTx]) {
        let _ = self.apply_block_governance_with_effects(block_height, governance_txs);
    }

    pub fn apply_block_governance_with_effects(
        &mut self,
        block_height: u64,
        governance_txs: &[GovernanceTx],
    ) -> GovernanceApplyEffects {
        self.apply_block_governance_with_effects_at_finality(
            block_height,
            governance_txs,
            block_height,
        )
    }

    /// Same deterministic governance application path, with an explicit finalized-height view.
    ///
    /// Runtime chain application passes the canonical finalized height here so validator -> compute
    /// finalization can fail closed when finality lags. Pure replay/test callers that only have
    /// block batches keep using `apply_block_governance_with_effects`, which treats the applied
    /// block as finalized for backwards-compatible deterministic reconstruction.
    pub fn apply_block_governance_with_effects_at_finality(
        &mut self,
        block_height: u64,
        governance_txs: &[GovernanceTx],
        finalized_height: u64,
    ) -> GovernanceApplyEffects {
        // 1) Expire stale Pending proposals before accepting votes from this block.
        // A proposal outside its bounded lifetime must become terminal before any
        // late approval can be recorded.
        self.expire_stale_pending_proposals_v1(block_height);

        // 2) registra proposte / voti
        for tx in governance_txs {
            match tx {
                GovernanceTx::Proposal(p) => self.handle_proposal(block_height, p),
                GovernanceTx::Vote(v) => self.handle_vote(v),
                GovernanceTx::FinalityVote(_) => { /* consensus-level finality; no governance state mutation */
                }
            }
        }

        // 3) prova ad applicare le proposte pronte (timelock + quorum)
        self.apply_ready_proposals(block_height, finalized_height)
    }

    /// Replay completo della governance a partire dai blocchi (on-chain truth).
    pub fn replay_from_chain(mut bootstrap: GovernanceState, blocks: &[Block]) -> GovernanceState {
        for b in blocks {
            bootstrap.apply_block_governance(b.index, &b.governance_txs);
        }
        bootstrap
    }

    /// Replay governance da batches (height, governance_txs) già estratti dalla chain.
    pub fn replay_from_batches(
        mut bootstrap: GovernanceState,
        batches: &[(u64, Vec<GovernanceTx>)],
    ) -> GovernanceState {
        for (h, txs) in batches {
            bootstrap.apply_block_governance(*h, txs);
        }
        bootstrap
    }

    fn council_members_for(&self, council: &GovernanceCouncilKind) -> &Vec<String> {
        match council {
            GovernanceCouncilKind::Protocol => &self.protocol_council.members,
            GovernanceCouncilKind::Economy => &self.economy_council.members,
            GovernanceCouncilKind::Emergency => &self.emergency_council.members,
        }
    }

    fn council_threshold_for(&self, council: &GovernanceCouncilKind) -> u8 {
        match council {
            GovernanceCouncilKind::Protocol => self.protocol_council.threshold,
            GovernanceCouncilKind::Economy => self.economy_council.threshold,
            GovernanceCouncilKind::Emergency => self.emergency_council.threshold,
        }
    }

    fn council_is_member(&self, council: &GovernanceCouncilKind, pk_any: &str) -> bool {
        match council {
            GovernanceCouncilKind::Protocol => self.protocol_council.is_member(pk_any),
            GovernanceCouncilKind::Economy => self.economy_council.is_member(pk_any),
            GovernanceCouncilKind::Emergency => self.emergency_council.is_member(pk_any),
        }
    }

    fn push_ops_log(&mut self, entry: ValidatorOpsLogEntry) {
        self.validator_ops_log.push(entry);
        if self.validator_ops_log.len() > OPS_LOG_CAP {
            let excess = self.validator_ops_log.len() - OPS_LOG_CAP;
            self.validator_ops_log.drain(0..excess);
        }
    }

    fn validator_compute_transition_quorum_policy_v1(
        &self,
    ) -> ValidatorComputeTransitionQuorumPolicyV1 {
        ValidatorComputeTransitionQuorumPolicyV1 {
            min_active_validators: self
                .params
                .validator_compute_transition_min_active_validators,
            min_finality_quorum: self.params.validator_compute_transition_min_finality_quorum,
            validator_quality_floor: self
                .params
                .validator_compute_transition_validator_quality_floor,
            validator_exit_cooldown_blocks: self
                .params
                .validator_compute_transition_exit_cooldown_blocks,
            max_finality_lag_blocks: self
                .params
                .validator_compute_transition_max_finality_lag_blocks,
            max_recent_missed_slots: self
                .params
                .validator_compute_transition_max_recent_missed_slots,
        }
    }

    fn default_wallet_gov_reputation(wallet_hex: &str) -> WalletGovReputation {
        WalletGovReputation::from_validator_reputation(
            wallet_hex,
            None,
            false,
            &ValidatorGovReputation::default(),
        )
    }

    fn normalize_validator_set_in_place(&mut self) -> Result<(), String> {
        if self.validator_set.entries.is_empty() {
            return Ok(());
        }
        let mut by_key: BTreeMap<String, ValidatorEntry> = BTreeMap::new();
        for entry in self.validator_set.entries.drain(..) {
            let pk_hex = keyfmt::pk_hex_from_any(&entry.pub_key)
                .map_err(|e| format!("invalid validator pub_key in validator set: {e}"))?;
            let mut normalized = entry;
            normalized.pub_key = pk_hex.clone();
            by_key.entry(pk_hex).or_insert(normalized);
        }
        self.validator_set.entries = by_key.into_values().collect();

        for entry in &self.validator_set.entries {
            self.validator_reputation
                .entry(entry.pub_key.clone())
                .or_default()
                .record_seen_at_height(0);
            self.wallet_reputation
                .entry(entry.pub_key.clone())
                .or_insert_with(|| {
                    WalletGovReputation::from_validator_reputation(
                        &entry.pub_key,
                        Some(entry.pub_key.clone()),
                        true,
                        &ValidatorGovReputation::default(),
                    )
                });
        }
        Ok(())
    }

    fn is_active_validator_member_v1(&self, pk_hex: &str, height: u64) -> bool {
        let in_set = self.validator_set.entries.iter().any(|e| {
            keyfmt::pk_hex_from_any(&e.pub_key)
                .map(|h| h == pk_hex)
                .unwrap_or(false)
        });
        if !in_set {
            return false;
        }
        match self.validator_reputation.get(pk_hex) {
            Some(rep) => {
                !rep.is_revoked_at(height)
                    && !rep.is_jailed_at(height)
                    && rep.misbehavior_points <= 50
            }
            None => true,
        }
    }

    fn can_join_validator_set(&self, pk_hex: &str, height: u64) -> bool {
        match self.validator_reputation.get(pk_hex) {
            Some(rep) => {
                !rep.is_revoked_at(height)
                    && !rep.is_jailed_at(height)
                    && rep.misbehavior_points <= 50
            }
            None => true,
        }
    }

    fn apply_ingest_wallet_reputation_evidence(
        &mut self,
        block_height: u64,
        prop: &mut GovProposalRecord,
        effects: &mut GovernanceApplyEffects,
    ) {
        let payload =
            match serde_json::from_slice::<WalletReputationEvidenceIngestPayload>(&prop.payload) {
                Ok(payload) => payload,
                Err(e) => {
                    self.reject_applied_proposal_with_wallet_misconduct_v1(
                        block_height,
                        prop,
                        WalletMisconductKindV1::MaliciousEvidenceSubmission,
                        &format!("wallet reputation evidence payload invalid: {e}"),
                    );
                    return;
                }
            };
        if payload.evidences.is_empty() || payload.evidences.len() > 64 {
            self.reject_applied_proposal_with_wallet_misconduct_v1(
                block_height,
                prop,
                WalletMisconductKindV1::MaliciousEvidenceSubmission,
                "wallet reputation evidence payload cardinality invalid",
            );
            return;
        }

        let batch_source_node_id = match normalize_wallet_reputation_batch_source_node_id(
            payload.source_node_id.clone(),
            &payload.evidences,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::MaliciousEvidenceSubmission,
                    &format!("wallet reputation evidence source_node_id invalid: {e}"),
                );
                return;
            }
        };

        #[derive(Clone)]
        struct PreparedWalletEvidence {
            canonical: WalletReputationCanonicalEvidence,
            item: WalletReputationEvidenceIngestItem,
            claim_id: String,
            evidence_id: String,
            wallet_hex: String,
            source_node_id: String,
            source_attester_hex: String,
        }

        let mut prepared = Vec::<PreparedWalletEvidence>::new();
        let mut batch_evidence_ids = BTreeSet::<String>::new();
        let mut batch_attesters_per_claim = BTreeSet::<(String, String)>::new();

        for original in payload.evidences {
            let mut item = original.clone();
            let item_source_node = item
                .source_node_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(batch_source_node_id.as_str())
                .to_string();
            item.source_node_id = Some(item_source_node.clone());

            let source_attester_raw = item
                .source_attester_pubkey
                .clone()
                .or_else(|| payload.source_attester_pubkey.clone())
                .unwrap_or_default();
            let source_attester_hex =
                match canonical_wallet_reputation_source_attester(&source_attester_raw) {
                    Some(v) => v,
                    None => {
                        self.reject_applied_proposal_with_wallet_misconduct_v1(
                            block_height,
                            prop,
                            WalletMisconductKindV1::MaliciousEvidenceSubmission,
                            "wallet reputation evidence missing/invalid source attester",
                        );
                        return;
                    }
                };
            item.source_attester_pubkey = Some(source_attester_hex.clone());

            if !self.is_active_validator_member_v1(&source_attester_hex, block_height) {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::MaliciousEvidenceSubmission,
                    "wallet reputation evidence source attester is not active validator",
                );
                return;
            }

            let sig = match item.source_attester_sig_b64.clone() {
                Some(sig) if !sig.trim().is_empty() => sig,
                _ => {
                    self.reject_applied_proposal_with_wallet_misconduct_v1(
                        block_height,
                        prop,
                        WalletMisconductKindV1::MaliciousEvidenceSubmission,
                        "wallet reputation evidence missing source attester signature",
                    );
                    return;
                }
            };
            if verify_wallet_reputation_evidence_signature(
                &source_attester_hex,
                &sig,
                &item,
                allow_legacy_gov(),
            )
            .is_err()
            {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::MaliciousEvidenceSubmission,
                    "wallet reputation evidence source attester signature invalid",
                );
                return;
            }

            let wallet_hex = match keyfmt::pk_hex_from_any(&item.wallet_pubkey) {
                Ok(v) => v,
                Err(_) => {
                    self.reject_applied_proposal_with_wallet_misconduct_v1(
                        block_height,
                        prop,
                        WalletMisconductKindV1::MaliciousEvidenceSubmission,
                        "wallet reputation evidence wallet_pubkey invalid",
                    );
                    return;
                }
            };
            item.wallet_pubkey = wallet_hex.clone();

            let expected_claim_id = wallet_reputation_claim_id_v1(&item);
            let claim_id = if item.claim_id.trim().is_empty() {
                expected_claim_id.clone()
            } else {
                item.claim_id.trim().to_string()
            };
            if claim_id != expected_claim_id {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::MaliciousEvidenceSubmission,
                    "wallet reputation evidence claim_id mismatch",
                );
                return;
            }
            item.claim_id = claim_id.clone();

            let expected_evidence_id = wallet_reputation_evidence_id_v1(&item);
            let evidence_id = if item.evidence_id.trim().is_empty() {
                expected_evidence_id.clone()
            } else {
                item.evidence_id.trim().to_string()
            };
            if evidence_id != expected_evidence_id {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::MaliciousEvidenceSubmission,
                    "wallet reputation evidence evidence_id mismatch",
                );
                return;
            }
            item.evidence_id = evidence_id.clone();

            if self.wallet_reputation_evidence_ids.contains(&evidence_id)
                || !batch_evidence_ids.insert(evidence_id.clone())
                || self
                    .wallet_reputation_claims
                    .get(&claim_id)
                    .map(|claim| claim.evidence_ids.contains(&evidence_id))
                    .unwrap_or(false)
            {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::ReplayProven,
                    "wallet reputation evidence duplicate evidence_id",
                );
                return;
            }
            if !batch_attesters_per_claim.insert((claim_id.clone(), source_attester_hex.clone())) {
                self.reject_applied_proposal_with_wallet_misconduct_v1(
                    block_height,
                    prop,
                    WalletMisconductKindV1::ReplayProven,
                    "wallet reputation evidence duplicate attester for claim in batch",
                );
                return;
            }

            let canonical = WalletReputationCanonicalEvidence {
                claim_id: claim_id.clone(),
                evidence_id: evidence_id.clone(),
                wallet_pubkey: wallet_hex.clone(),
                peer_id: item.peer_id.trim().to_string(),
                event: item.event.trim().to_string(),
                score_before: item.score_before,
                score_after: item.score_after,
                applied_delta: item.applied_delta,
                trust_tier: item.trust_tier.trim().to_string(),
                observed_at_secs: item.observed_at_secs,
                binding_source: item.binding_source.trim().to_string(),
                source_node_id: Some(item_source_node.clone()),
                source_attester_pubkey: Some(source_attester_hex.clone()),
                source_attester_sig_b64: item.source_attester_sig_b64.clone(),
                source_tip_height: payload.source_tip_height,
                source_tip_height_advisory: payload.source_tip_height.is_some(),
                proposal_id: prop.id.clone(),
                ingested_at_height: block_height,
                council: self.council_for_kind(&prop.kind),
            };

            prepared.push(PreparedWalletEvidence {
                canonical,
                item,
                claim_id,
                evidence_id,
                wallet_hex,
                source_node_id: item_source_node,
                source_attester_hex,
            });
        }

        // Validate conflicts against existing aggregates before mutating any state.
        // A malformed batch must be all-or-nothing.
        for p in &prepared {
            if let Some(existing) = self.wallet_reputation_claims.get(&p.claim_id) {
                let claim_matches = existing.wallet_pubkey == p.wallet_hex
                    && existing.peer_id == p.item.peer_id.trim()
                    && existing.event == p.item.event.trim()
                    && existing.score_before == p.item.score_before
                    && existing.score_after == p.item.score_after
                    && existing.applied_delta == p.item.applied_delta
                    && existing.trust_tier == p.item.trust_tier.trim()
                    && existing.observed_at_secs == p.item.observed_at_secs
                    && existing.binding_source == p.item.binding_source.trim();
                if !claim_matches
                    || existing
                        .source_attester_pubkeys
                        .contains(&p.source_attester_hex)
                {
                    self.reject_applied_proposal_with_wallet_misconduct_v1(
                        block_height,
                        prop,
                        WalletMisconductKindV1::ReplayProven,
                        "wallet reputation evidence claim conflict or duplicate attester",
                    );
                    return;
                }
            }
        }

        for p in prepared {
            let (promote_now, already_promoted, support_count_after) = {
                let claim = self
                    .wallet_reputation_claims
                    .entry(p.claim_id.clone())
                    .or_insert_with(|| WalletReputationCanonicalClaimAggregate {
                        claim_id: p.claim_id.clone(),
                        wallet_pubkey: p.wallet_hex.clone(),
                        peer_id: p.item.peer_id.trim().to_string(),
                        event: p.item.event.trim().to_string(),
                        score_before: p.item.score_before,
                        score_after: p.item.score_after,
                        applied_delta: p.item.applied_delta,
                        trust_tier: p.item.trust_tier.trim().to_string(),
                        observed_at_secs: p.item.observed_at_secs,
                        binding_source: p.item.binding_source.trim().to_string(),
                        source_node_ids: BTreeSet::new(),
                        source_attester_pubkeys: BTreeSet::new(),
                        evidence_ids: BTreeSet::new(),
                        support_count: 0,
                        promoted: false,
                        promoted_at_height: None,
                        last_source_tip_height: None,
                        last_source_tip_height_advisory: false,
                        last_ingested_height: 0,
                    });

                claim.source_node_ids.insert(p.source_node_id.clone());
                claim
                    .source_attester_pubkeys
                    .insert(p.source_attester_hex.clone());
                claim.evidence_ids.insert(p.evidence_id.clone());
                claim.support_count = claim.source_attester_pubkeys.len() as u32;
                claim.last_source_tip_height = p.canonical.source_tip_height;
                claim.last_source_tip_height_advisory = p.canonical.source_tip_height_advisory;
                claim.last_ingested_height = block_height;

                let threshold = self.params.wallet_reputation_promotion_quorum.max(1);
                let promote_now = !claim.promoted && claim.support_count >= threshold;
                let already_promoted = claim.promoted;
                if promote_now {
                    claim.promoted = true;
                    claim.promoted_at_height = Some(block_height);
                }
                (promote_now, already_promoted, claim.support_count)
            };

            self.wallet_reputation_evidence_log
                .push(p.canonical.clone());
            if self.wallet_reputation_evidence_log.len() > WALLET_REPUTATION_EVIDENCE_LOG_CAP {
                let excess =
                    self.wallet_reputation_evidence_log.len() - WALLET_REPUTATION_EVIDENCE_LOG_CAP;
                self.wallet_reputation_evidence_log.drain(0..excess);
            }
            self.wallet_reputation_evidence_ids = self
                .wallet_reputation_evidence_log
                .iter()
                .map(|ev| ev.evidence_id.clone())
                .collect();
            effects
                .acknowledged_run_wallet_evidence_ids
                .push(p.evidence_id.clone());

            let evidence_units_to_apply = if promote_now {
                support_count_after as u64
            } else if already_promoted {
                1
            } else {
                0
            };
            if evidence_units_to_apply > 0 {
                let rep = self
                    .wallet_reputation
                    .entry(p.wallet_hex.clone())
                    .or_insert_with(|| Self::default_wallet_gov_reputation(&p.wallet_hex));
                rep.reset_recent_reputation_window_if_stale(block_height);
                rep.accepted_run_evidence_count = rep
                    .accepted_run_evidence_count
                    .saturating_add(evidence_units_to_apply);
                if p.item.applied_delta >= 0 {
                    rep.accepted_positive_run_evidence_count = rep
                        .accepted_positive_run_evidence_count
                        .saturating_add(evidence_units_to_apply);
                } else {
                    rep.accepted_negative_run_evidence_count = rep
                        .accepted_negative_run_evidence_count
                        .saturating_add(evidence_units_to_apply);
                }
                rep.accepted_run_evidence_delta_total =
                    rep.accepted_run_evidence_delta_total.saturating_add(
                        (p.item.applied_delta as i64)
                            .saturating_mul(evidence_units_to_apply as i64),
                    );
                rep.last_run_evidence_height = Some(block_height);
                rep.last_run_evidence_id = Some(p.evidence_id.clone());
                if promote_now {
                    rep.promoted_run_claim_count = rep.promoted_run_claim_count.saturating_add(1);
                    if p.item.applied_delta >= 0 {
                        rep.promoted_positive_run_claim_count =
                            rep.promoted_positive_run_claim_count.saturating_add(1);
                    } else {
                        rep.promoted_negative_run_claim_count =
                            rep.promoted_negative_run_claim_count.saturating_add(1);
                    }
                    rep.promoted_run_claim_delta_total = rep
                        .promoted_run_claim_delta_total
                        .saturating_add(p.item.applied_delta as i64);
                    rep.last_promoted_run_claim_height = Some(block_height);
                    rep.last_promoted_run_claim_id = Some(p.claim_id.clone());
                }
            }
        }

        prop.status = ProposalStatus::Applied;
    }

    pub fn apply_wallet_generic_misconduct_effect_v1(
        &mut self,
        wallet_pubkey: &str,
        kind: WalletMisconductKindV1,
        height: u64,
        reason: &str,
    ) {
        let wallet_hex = match keyfmt::pk_hex_from_any(wallet_pubkey) {
            Ok(h) => h,
            Err(_) => return,
        };
        let until_height = {
            let entry = self
                .wallet_reputation
                .entry(wallet_hex.clone())
                .or_insert_with(|| Self::default_wallet_gov_reputation(&wallet_hex));
            entry.reset_recent_reputation_window_if_stale(height);
            entry.misbehavior_points = entry
                .misbehavior_points
                .saturating_add(kind.misbehavior_points_v1());
            entry.failure_count = entry.failure_count.saturating_add(1);
            entry.recent_failure_count = entry.recent_failure_count.saturating_add(1);
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.consecutive_timeouts = 0;
            entry.last_run_evidence_height = Some(height);
            entry.last_run_evidence_id = Some(format!(
                "wallet-misconduct:{:?}:{}:{}",
                kind, height, wallet_hex
            ));

            if matches!(
                kind.severity_v1(),
                WalletMisconductSeverityV1::HardGovernanceCandidate
            ) {
                // Hard wallet misconduct is a governance candidate. Do not auto-jail/revoke here;
                // dedicated governance/slash actions must perform the canonical discipline step.
                entry.last_hard_fault_height = Some(height);
            }
            entry.jailed_until_height
        };

        self.validator_ops_log.push(ValidatorOpsLogEntry {
            height,
            op: ValidatorOpsOp::WalletMisconduct,
            target_pk_hex: wallet_hex,
            new_pk_hex: None,
            until_height,
            proposal_id: None,
            reason: Some(format!("{:?}:{}", kind, reason)),
        });
        if self.validator_ops_log.len() > OPS_LOG_CAP {
            let excess = self.validator_ops_log.len() - OPS_LOG_CAP;
            self.validator_ops_log.drain(0..excess);
        }
    }

    fn record_invalid_governance_proposal_v1(
        &mut self,
        wallet_pubkey: &str,
        block_height: u64,
        reason: &str,
    ) -> bool {
        let wallet_hex = match keyfmt::pk_hex_from_any(wallet_pubkey) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut trigger_spam = false;
        {
            let window = self
                .wallet_governance_invalid_proposal_windows
                .entry(wallet_hex.clone())
                .or_default();
            window.reset_if_stale(block_height);
            window.invalid_governance_proposal_count =
                window.invalid_governance_proposal_count.saturating_add(1);
            window.recent_invalid_governance_proposal_count = window
                .recent_invalid_governance_proposal_count
                .saturating_add(1);
            window.last_invalid_governance_proposal_height = block_height;
            if window.recent_invalid_governance_proposal_count
                >= WALLET_GOVERNANCE_INVALID_PROPOSAL_SPAM_THRESHOLD_V1
                && !window.spam_misconduct_applied_in_window
            {
                window.spam_misconduct_applied_in_window = true;
                trigger_spam = true;
            }
        }
        if trigger_spam {
            self.apply_wallet_generic_misconduct_effect_v1(
                &wallet_hex,
                WalletMisconductKindV1::InvalidGovernanceProposalSpam,
                block_height,
                reason,
            );
        }
        trigger_spam
    }

    fn reject_pending_attributed_invalid_governance_v1(
        &mut self,
        block_height: u64,
        prop: &mut GovProposalRecord,
        reason: &str,
    ) {
        // This helper is only for proposals that already reached `Pending`, which means
        // proposer membership and the proposal signature were verified for this payload.
        // Pre-Pending rejects must remain reject-only to avoid spoofable wallet penalties.
        if prop.status == ProposalStatus::Pending {
            let attributed_reason = format!("{}; kind={:?}", reason, prop.kind);
            self.record_invalid_governance_proposal_v1(
                &prop.proposer,
                block_height,
                &attributed_reason,
            );
        }
        eprintln!("[GOV] {}. Rifiuto.", reason);
        prop.status = ProposalStatus::Rejected;
        prop.terminal_height = Some(block_height);
    }

    fn reject_applied_proposal_with_invalid_governance_window_v1(
        &mut self,
        block_height: u64,
        prop: &mut GovProposalRecord,
        reason: &str,
    ) {
        self.reject_pending_attributed_invalid_governance_v1(block_height, prop, reason);
    }

    fn reject_applied_proposal_with_wallet_misconduct_v1(
        &mut self,
        block_height: u64,
        prop: &mut GovProposalRecord,
        kind: WalletMisconductKindV1,
        reason: &str,
    ) {
        self.apply_wallet_generic_misconduct_effect_v1(&prop.proposer, kind, block_height, reason);
        eprintln!("[GOV] {}. Rifiuto.", reason);
        prop.status = ProposalStatus::Rejected;
        prop.terminal_height = Some(block_height);
    }

    fn handle_proposal(&mut self, block_height: u64, p: &TxGovernanceProposal) {
        // ID uniqueness and syntactic validity are checked before every reject path.
        // First-seen-wins must hold even when a later duplicate is malformed.
        if self.proposals.contains_key(&p.id) {
            return;
        }
        if !is_canonical_governance_proposal_id_v1(&p.id) {
            eprintln!(
                "[GOV] Proposal rejected before record: invalid canonical proposal_id id={}",
                p.id
            );
            return;
        }

        // created_at must match inclusion height (anti-replay within a chain).
        if p.created_at_height != block_height {
            let record = self.mk_rejected_record_unattributed_v1(
                block_height,
                p,
                "created_at_height mismatch",
            );
            self.proposals.insert(p.id.clone(), record);
            return;
        }

        // Determine responsible council.
        let council = self.council_for_kind(&p.kind);

        // Timelock: emergency council has its own minimal timelock (default 0).
        let min_tl = if council == GovernanceCouncilKind::Emergency {
            self.min_timelock_blocks_emergency
        } else {
            self.params.min_timelock_blocks
        };

        if p.effective_height < block_height.saturating_add(min_tl) {
            let record =
                self.mk_rejected_record_unattributed_v1(block_height, p, "timelock too small");
            self.proposals.insert(p.id.clone(), record);
            return;
        }

        // Council membership.
        let proposer_ok = self.council_is_member(&council, &p.proposer);

        // Signature/domain verification (strict in release). Domain separation is never bypassed:
        // even debug signatures must match the current chain/genesis domain or use empty legacy
        // fields that resolve to the local debug domain.
        let proposal_domain_fields = proposal_domain_fields_v1(p).ok();
        let mut sig_ok = false;
        if proposer_ok && proposal_domain_fields.is_some() {
            let legacy_allowed = allow_legacy_gov();
            if legacy_allowed && (p.signature.trim().is_empty() || p.signature.trim() == "debug") {
                sig_ok = true;
            } else {
                match proposal_signing_bytes_v1(p, &council) {
                    Ok(msg) => {
                        sig_ok = verify_ed25519_sig_b64(&p.proposer, &p.signature, &msg).is_ok();
                    }
                    Err(_) => sig_ok = false,
                }
            }
        }

        let status = if proposer_ok && sig_ok {
            ProposalStatus::Pending
        } else {
            ProposalStatus::Rejected
        };

        // Bind votes to proposal hash.
        let proposal_hash_hex = if status == ProposalStatus::Pending {
            proposal_hash_hex_v1(p, &council).unwrap_or_else(|_| String::new())
        } else {
            String::new()
        };

        // Mainnet-grade governance requires explicit approval votes. Proposal
        // submission only creates a Pending proposal; it does not implicitly count
        // as a YES vote. This keeps propose/approve actions separately signed,
        // auditable and replayable.
        let votes = HashMap::new();

        let (record_signature_domain, record_chain_id, record_genesis_hash) =
            if status == ProposalStatus::Pending {
                proposal_domain_fields.unwrap_or_else(|| {
                    (
                        p.signature_domain.clone(),
                        p.chain_id.clone(),
                        p.genesis_hash.clone(),
                    )
                })
            } else {
                (
                    p.signature_domain.clone(),
                    p.chain_id.clone(),
                    p.genesis_hash.clone(),
                )
            };

        let record = GovProposalRecord {
            id: p.id.clone(),
            kind: p.kind.clone(),
            council,
            payload: p.payload.clone(),
            created_at_height: p.created_at_height,
            effective_height: p.effective_height,
            proposer: p.proposer.clone(),
            signature: p.signature.clone(),
            signature_domain: record_signature_domain,
            chain_id: record_chain_id,
            genesis_hash: record_genesis_hash,
            proposal_hash_hex,
            status: status.clone(),
            votes,
            vote_records_v1: HashMap::new(),
            terminal_height: if matches!(status, ProposalStatus::Pending) {
                None
            } else {
                Some(block_height)
            },
        };

        self.proposals.insert(p.id.clone(), record);
    }

    fn rejected_record_base_v1(
        &self,
        block_height: u64,
        p: &TxGovernanceProposal,
    ) -> GovProposalRecord {
        GovProposalRecord {
            id: p.id.clone(),
            kind: p.kind.clone(),
            council: self.council_for_kind(&p.kind),
            payload: p.payload.clone(),
            created_at_height: p.created_at_height,
            effective_height: p.effective_height,
            proposer: p.proposer.clone(),
            signature: p.signature.clone(),
            signature_domain: p.signature_domain.clone(),
            chain_id: p.chain_id.clone(),
            genesis_hash: p.genesis_hash.clone(),
            proposal_hash_hex: String::new(),
            status: ProposalStatus::Rejected,
            votes: HashMap::new(),
            vote_records_v1: HashMap::new(),
            terminal_height: Some(block_height),
        }
    }

    fn mk_rejected_record_unattributed_v1(
        &self,
        block_height: u64,
        p: &TxGovernanceProposal,
        reason: &str,
    ) -> GovProposalRecord {
        // Reject-only: this path runs before cryptographic attribution is complete.
        // Do not feed wallet governance spam windows from unauthenticated proposal bytes;
        // otherwise a malicious peer could spoof `proposer` and penalize a victim wallet.
        eprintln!(
            "[GOV] Proposal rejected without wallet attribution: id={} reason={}",
            p.id, reason
        );
        self.rejected_record_base_v1(block_height, p)
    }

    #[allow(dead_code)]
    fn mk_rejected_record_attributed_invalid_governance_v1(
        &mut self,
        block_height: u64,
        p: &TxGovernanceProposal,
        reason: &str,
    ) -> GovProposalRecord {
        // Only call this after proposer identity, council membership and signature
        // have been verified for this exact proposal payload/signing context.
        self.record_invalid_governance_proposal_v1(&p.proposer, block_height, reason);
        eprintln!(
            "[GOV] Proposal rejected with attributed wallet misconduct window: id={} reason={}",
            p.id, reason
        );
        self.rejected_record_base_v1(block_height, p)
    }

    fn handle_vote(&mut self, v: &TxGovernanceVote) {
        // 1) lettura immutabile: proposta deve esistere ed essere Pending
        let (council_kind, status, proposal_hash_hex) = match self.proposals.get(&v.proposal_id) {
            Some(prop) => (
                prop.council.clone(),
                prop.status.clone(),
                prop.proposal_hash_hex.clone(),
            ),
            None => return,
        };

        if status != ProposalStatus::Pending {
            return;
        }
        if proposal_hash_hex.is_empty() {
            return;
        }
        let vote_proposal_hash_hex = v.proposal_hash_hex.as_str();
        if !is_lowercase_hex64_v1(vote_proposal_hash_hex) {
            return;
        }
        if !is_lowercase_hex64_v1(proposal_hash_hex.as_str()) {
            return;
        }
        if vote_proposal_hash_hex != proposal_hash_hex.as_str() {
            return;
        }

        // 2) membership voter
        if !self.council_is_member(&council_kind, &v.voter) {
            return;
        }

        // 3) signature verify
        if verify_governance_vote_signature_v1(v).is_err() {
            return;
        }

        // 4) registriamo voto (key = canonical voter hex)
        let voter_hex = match keyfmt::pk_hex_from_any(&v.voter) {
            Ok(h) => h,
            Err(_) => return,
        };

        if let Some(prop_mut) = self.proposals.get_mut(&v.proposal_id) {
            if prop_mut.status == ProposalStatus::Pending {
                let voter_hex_key = voter_hex.clone();
                prop_mut
                    .votes
                    .entry(voter_hex_key.clone())
                    .or_insert_with(|| v.signature.clone());
                prop_mut
                    .vote_records_v1
                    .entry(voter_hex_key)
                    .or_insert_with(|| GovVoteRecordV1 {
                        proposal_hash_hex: vote_proposal_hash_hex.to_string(),
                        signature_domain: v.signature_domain.clone(),
                        chain_id: v.chain_id.clone(),
                        genesis_hash: v.genesis_hash.clone(),
                        signature: v.signature.clone(),
                    });
            }
        }
    }

    fn valid_vote_count_for_apply_v1(
        &self,
        prop: &GovProposalRecord,
        members_hex: &BTreeSet<String>,
    ) -> usize {
        let prop_hash = prop.proposal_hash_hex.as_str();
        let prop_domain = prop.signature_domain.as_str();
        let prop_chain_id = prop.chain_id.as_str();
        let prop_genesis_hash = prop.genesis_hash.as_str();
        if !is_lowercase_hex64_v1(prop_hash)
            || prop_domain != GOVERNANCE_SIGNATURE_DOMAIN_V2
            || prop_chain_id != governance_domain_chain_id_v1()
            || (prop_genesis_hash == "legacy-debug-genesis-context" && !allow_legacy_gov())
            || (prop_genesis_hash != "legacy-debug-genesis-context"
                && !is_lowercase_hex64_v1(prop_genesis_hash))
        {
            return 0;
        }

        if !prop.vote_records_v1.is_empty() {
            return prop
                .vote_records_v1
                .iter()
                .filter(|(voter_hex, record)| {
                    let voter_hex = voter_hex.trim().to_ascii_lowercase();
                    if !members_hex.contains(&voter_hex) {
                        return false;
                    }
                    if !is_lowercase_hex64_v1(record.proposal_hash_hex.as_str())
                        || record.proposal_hash_hex.as_str() != prop_hash
                    {
                        return false;
                    }
                    if record.signature_domain.as_str() != prop_domain {
                        return false;
                    }
                    if record.chain_id.as_str() != prop_chain_id {
                        return false;
                    }
                    if record.genesis_hash.as_str() != prop_genesis_hash {
                        return false;
                    }
                    if record.signature.trim().is_empty() {
                        return false;
                    }

                    let vote = TxGovernanceVote {
                        proposal_id: prop.id.clone(),
                        proposal_hash_hex: record.proposal_hash_hex.clone(),
                        voter: voter_hex.clone(),
                        signature_domain: record.signature_domain.clone(),
                        chain_id: record.chain_id.clone(),
                        genesis_hash: record.genesis_hash.clone(),
                        signature: record.signature.clone(),
                    };

                    verify_governance_vote_signature_v1(&vote).is_ok()
                })
                .count();
        }

        // Legacy compact vote map is accepted only when explicitly enabled. New governance
        // must count audit-grade vote_records_v1 so each approval is bound to the exact
        // proposal hash, chain id, genesis hash and signature domain.
        if allow_legacy_gov() {
            prop.votes
                .keys()
                .filter(|voter_hex| members_hex.contains(&voter_hex.trim().to_ascii_lowercase()))
                .count()
        } else {
            0
        }
    }

    fn expire_stale_pending_proposals_v1(&mut self, block_height: u64) {
        let max_lifetime = self.params.max_proposal_lifetime_blocks.max(1);
        let mut ids_to_expire: Vec<String> = self
            .proposals
            .iter()
            .filter_map(|(id, prop)| {
                if prop.status != ProposalStatus::Pending {
                    return None;
                }
                let expires_at = prop.created_at_height.saturating_add(max_lifetime);
                if block_height > expires_at {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        ids_to_expire.sort_unstable();
        for id in ids_to_expire {
            if let Some(prop) = self.proposals.get_mut(&id) {
                if prop.status == ProposalStatus::Pending {
                    prop.status = ProposalStatus::Expired;
                    prop.terminal_height = Some(block_height);
                }
            }
        }
    }

    fn e2_worker_privilege_kind_from_proposal_v1(
        kind: &GovProposalKind,
    ) -> Option<(E2WorkerGovernedPrivilegeV1, bool)> {
        match kind {
            GovProposalKind::GrantE2WorkerCloudUnit => {
                Some((E2WorkerGovernedPrivilegeV1::CloudUnit, true))
            }
            GovProposalKind::RevokeE2WorkerCloudUnit => {
                Some((E2WorkerGovernedPrivilegeV1::CloudUnit, false))
            }
            GovProposalKind::GrantE2WorkerGpuCapability => {
                Some((E2WorkerGovernedPrivilegeV1::GpuCapability, true))
            }
            GovProposalKind::RevokeE2WorkerGpuCapability => {
                Some((E2WorkerGovernedPrivilegeV1::GpuCapability, false))
            }
            GovProposalKind::GrantE2WorkerCriticalWorkload => {
                Some((E2WorkerGovernedPrivilegeV1::CriticalWorkload, true))
            }
            GovProposalKind::RevokeE2WorkerCriticalWorkload => {
                Some((E2WorkerGovernedPrivilegeV1::CriticalWorkload, false))
            }
            _ => None,
        }
    }

    pub(crate) fn e2_worker_governed_privilege_bridge_payload_hash_v1(
        payload: &E2WorkerGovernedPrivilegePayloadV1,
    ) -> Option<String> {
        let request_id = payload.request_id.as_deref()?.trim();
        let proposal_kind = payload.proposal_kind.as_deref()?.trim();
        let proposal_action = payload.proposal_action.as_deref()?.trim();
        let requested_tier = payload.requested_tier.as_deref()?.trim();
        let worker_id = payload.worker_id.as_deref()?.trim();
        let capability_snapshot_hash = payload.capability_snapshot_hash.as_deref()?.trim();
        let reason = payload.reason.as_deref()?.trim();
        if request_id.is_empty()
            || proposal_kind.is_empty()
            || proposal_action.is_empty()
            || requested_tier.is_empty()
            || worker_id.is_empty()
            || capability_snapshot_hash.is_empty()
            || reason.is_empty()
        {
            return None;
        }

        // E2 stores the hash of its governance bridge canonical payload, not
        // necessarily the raw TxGovernanceProposal payload bytes. Derive the
        // same canonical object here so the finalized L1 eligibility surface can
        // expose the exact hash E2 recorded on the access request. Without this
        // bridge hash, the Coordinator stays fail-closed even after a proposal is
        // Applied because ar.l1_proposal_payload_hash would not match the chain
        // projection grant hash.
        let canonical_payload = serde_json::json!({
            "format_version": payload.format_version.trim(),
            "request_id": request_id,
            "proposal_kind": proposal_kind,
            "proposal_action": proposal_action,
            "requested_tier": requested_tier,
            "worker_id": worker_id,
            "worker_node_pubkey": payload.worker_node_pubkey.trim(),
            "operator_wallet_pubkey": payload.operator_wallet_pubkey.trim(),
            "capability_snapshot_hash": capability_snapshot_hash.to_ascii_lowercase(),
            "reason": reason,
        });
        serde_json::to_vec(&canonical_payload)
            .ok()
            .map(|bytes| hex::encode(Sha256::digest(&bytes)))
    }

    fn apply_e2_worker_governed_privilege_v1(
        &mut self,
        block_height: u64,
        proposal_id: &str,
        payload_hash: &str,
        payload: E2WorkerGovernedPrivilegePayloadV1,
        privilege: E2WorkerGovernedPrivilegeV1,
        grant: bool,
    ) -> Result<(), String> {
        let (worker_hex, operator_hex) = payload.validate_contract_v1()?;
        if grant {
            for (field, value) in [
                ("request_id", payload.request_id.as_deref()),
                ("proposal_kind", payload.proposal_kind.as_deref()),
                ("proposal_action", payload.proposal_action.as_deref()),
                ("requested_tier", payload.requested_tier.as_deref()),
                ("worker_id", payload.worker_id.as_deref()),
                (
                    "capability_snapshot_hash",
                    payload.capability_snapshot_hash.as_deref(),
                ),
            ] {
                if value.map(str::trim).filter(|s| !s.is_empty()).is_none() {
                    return Err(format!(
                        "e2_worker_governed_privilege_grant_missing_{field}"
                    ));
                }
            }
        }
        if grant && matches!(privilege, E2WorkerGovernedPrivilegeV1::CriticalWorkload) {
            if payload
                .critical_review_payload_hash
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                return Err(
                    "e2_worker_governed_privilege_grant_missing_critical_review_payload_hash"
                        .to_string(),
                );
            }
        }

        if let Some(action) = payload
            .proposal_action
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let expected = if grant { "grant" } else { "revoke" };
            if !action.eq_ignore_ascii_case(expected) {
                return Err("e2_worker_governed_privilege_payload_action_mismatch".to_string());
            }
        }
        if let Some(kind) = payload
            .proposal_kind
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let expected_kind = match (&privilege, grant) {
                (E2WorkerGovernedPrivilegeV1::CloudUnit, true) => "GrantE2WorkerCloudUnit",
                (E2WorkerGovernedPrivilegeV1::CloudUnit, false) => "RevokeE2WorkerCloudUnit",
                (E2WorkerGovernedPrivilegeV1::GpuCapability, true) => "GrantE2WorkerGpuCapability",
                (E2WorkerGovernedPrivilegeV1::GpuCapability, false) => {
                    "RevokeE2WorkerGpuCapability"
                }
                (E2WorkerGovernedPrivilegeV1::CriticalWorkload, true) => {
                    "GrantE2WorkerCriticalWorkload"
                }
                (E2WorkerGovernedPrivilegeV1::CriticalWorkload, false) => {
                    "RevokeE2WorkerCriticalWorkload"
                }
            };
            if !kind.eq_ignore_ascii_case(expected_kind) {
                return Err("e2_worker_governed_privilege_payload_kind_mismatch".to_string());
            }
        }
        if let Some(tier) = payload
            .requested_tier
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let expected_tier = match &privilege {
                E2WorkerGovernedPrivilegeV1::CloudUnit => "CLOUD_UNIT",
                E2WorkerGovernedPrivilegeV1::GpuCapability => "GPU",
                E2WorkerGovernedPrivilegeV1::CriticalWorkload => "CRITICAL",
            };
            if !tier.eq_ignore_ascii_case(expected_tier) {
                return Err("e2_worker_governed_privilege_payload_tier_mismatch".to_string());
            }
        }
        let Some(binding) = self.e2_worker_operator_bindings.get(&worker_hex) else {
            return Err("e2_worker_governed_privilege_binding_missing".to_string());
        };
        if !binding.is_active() {
            return Err("e2_worker_governed_privilege_binding_not_active".to_string());
        }
        let binding_operator_hex = keyfmt::pk_hex_from_any(&binding.operator_wallet_pubkey)
            .map_err(|e| format!("e2_worker_governed_privilege_binding_operator_invalid:{e}"))?;
        if binding_operator_hex != operator_hex {
            return Err("e2_worker_governed_privilege_operator_mismatch".to_string());
        }
        let record = self
            .e2_worker_governed_privileges
            .entry(worker_hex.clone())
            .or_insert_with(|| {
                E2WorkerGovernedPrivilegeRecordV1::new(
                    worker_hex.clone(),
                    operator_hex.clone(),
                    block_height,
                    Some(proposal_id.to_string()),
                )
            });
        if record.operator_wallet_pubkey != operator_hex {
            return Err("e2_worker_governed_privilege_record_operator_mismatch".to_string());
        }
        record.updated_at_height = block_height;
        record.proposal_id = Some(proposal_id.to_string());
        let grant_payload_hash = if grant {
            Self::e2_worker_governed_privilege_bridge_payload_hash_v1(&payload)
                .unwrap_or_else(|| payload_hash.to_string())
        } else {
            payload_hash.to_string()
        };
        record.apply(
            &privilege,
            grant,
            proposal_id,
            &grant_payload_hash,
            payload.critical_review_payload_hash.as_deref(),
        );
        Ok(())
    }

    fn apply_ready_proposals(
        &mut self,
        block_height: u64,
        finalized_height: u64,
    ) -> GovernanceApplyEffects {
        let mut ids_to_apply: Vec<String> = self
            .proposals
            .iter()
            .filter_map(|(id, prop)| {
                if prop.status != ProposalStatus::Pending {
                    return None;
                }
                if block_height < prop.effective_height {
                    return None;
                }

                let threshold: usize = self.council_threshold_for(&prop.council) as usize;
                if threshold == 0 {
                    return None; // fail-closed
                }

                let members = self.council_members_for(&prop.council);
                let mut members_hex: BTreeSet<String> = BTreeSet::new();
                for m in members {
                    if let Ok(h) = keyfmt::pk_hex_from_any(m) {
                        members_hex.insert(h);
                    }
                }
                if members_hex.is_empty() {
                    return None;
                }

                let valid_votes = self.valid_vote_count_for_apply_v1(prop, &members_hex);

                if valid_votes >= threshold {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        // ordine deterministico
        ids_to_apply.sort_unstable();

        let mut effects = GovernanceApplyEffects::default();
        for id in ids_to_apply {
            if let Some(mut prop) = self.proposals.remove(&id) {
                self.apply_single_proposal(block_height, finalized_height, &mut prop, &mut effects);
                if !matches!(prop.status, ProposalStatus::Pending) && prop.terminal_height.is_none()
                {
                    prop.terminal_height = Some(block_height);
                }
                self.proposals.insert(id, prop);
            }
        }
        effects
    }

    fn apply_single_proposal(
        &mut self,
        block_height: u64,
        finalized_height: u64,
        prop: &mut GovProposalRecord,
        effects: &mut GovernanceApplyEffects,
    ) {
        match prop.kind.clone() {
            // ---------------- SAFE MODE ----------------
            GovProposalKind::EmergencySafeModeOn => {
                self.safe_mode.active = true;
                self.safe_mode.activated_at = Some(block_height);
                prop.status = ProposalStatus::Applied;
            }
            GovProposalKind::EmergencySafeModeOff => {
                self.safe_mode.active = false;
                self.safe_mode.activated_at = None;
                prop.status = ProposalStatus::Applied;
            }

            // ---------------- VALIDATOR OPS ----------------
            GovProposalKind::RotateValidatorKey => {
                let payload =
                    match serde_json::from_slice::<RotateValidatorKeyPayload>(&prop.payload) {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("[GOV] Payload RotateValidatorKey invalido");
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                            return;
                        }
                    };

                let old_hex = match keyfmt::pk_hex_from_any(&payload.old_pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] old_pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };
                let new_hex = match keyfmt::pk_hex_from_any(&payload.new_pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] new_pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                if old_hex == new_hex {
                    eprintln!("[GOV] RotateValidatorKey: old == new");
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                    return;
                }

                // Ensure old exists and new does not exist. Keep immutable lookups
                // completed before calling the mutable reject helper.
                if self
                    .validator_set
                    .entries
                    .iter()
                    .any(|e| e.pub_key == new_hex)
                {
                    eprintln!("[GOV] RotateValidatorKey: new key already in validator set");
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                    return;
                }
                let found_idx = self
                    .validator_set
                    .entries
                    .iter()
                    .position(|e| e.pub_key == old_hex);
                let idx = match found_idx {
                    Some(i) => i,
                    None => {
                        eprintln!("[GOV] RotateValidatorKey: old key not in validator set");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                // Snapshot old entry for deterministic restore/audit.
                let old_entry = self.validator_set.entries[idx].clone();
                self.revoked_validators
                    .insert(old_hex.clone(), old_entry.clone());

                // Replace entry with new key.
                let mut new_entry = old_entry.clone();
                new_entry.pub_key = new_hex.clone();
                if payload.new_alias.is_some() {
                    new_entry.alias = payload.new_alias.clone();
                }
                self.validator_set.entries[idx] = new_entry;

                // Sort deterministically.
                self.validator_set
                    .entries
                    .sort_by(|a, b| a.pub_key.cmp(&b.pub_key));
                self.validator_set.version = self.validator_set.version.saturating_add(1);

                // Mark old key permanently revoked.
                let rep = self
                    .validator_reputation
                    .entry(old_hex.clone())
                    .or_default();
                rep.temporarily_revoked = true;
                rep.banned_until_height = None;

                // Ensure new key is not revoked.
                let rep_new = self
                    .validator_reputation
                    .entry(new_hex.clone())
                    .or_default();
                rep_new.temporarily_revoked = false;
                rep_new.banned_until_height = None;

                self.push_ops_log(ValidatorOpsLogEntry {
                    height: block_height,
                    op: ValidatorOpsOp::RotateKey,
                    target_pk_hex: old_hex,
                    new_pk_hex: Some(new_hex),
                    until_height: None,
                    proposal_id: Some(prop.id.clone()),
                    reason: None,
                });

                prop.status = ProposalStatus::Applied;
            }

            GovProposalKind::RevokeValidator => {
                let payload = match serde_json::from_slice::<RevokeValidatorPayload>(&prop.payload)
                {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("[GOV] Payload RevokeValidator invalido");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                let target_hex = match keyfmt::pk_hex_from_any(&payload.pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                // Cannot revoke to empty validator set.
                let is_in_set = self
                    .validator_set
                    .entries
                    .iter()
                    .any(|e| e.pub_key == target_hex);
                if is_in_set && self.validator_set.entries.len() == 1 {
                    eprintln!("[GOV] RevokeValidator would leave empty validator set");
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                    return;
                }

                // Remove from active set and snapshot.
                if is_in_set {
                    if let Some(pos) = self
                        .validator_set
                        .entries
                        .iter()
                        .position(|e| e.pub_key == target_hex)
                    {
                        let entry = self.validator_set.entries.remove(pos);
                        self.revoked_validators.insert(target_hex.clone(), entry);
                        self.validator_set.version = self.validator_set.version.saturating_add(1);
                        self.validator_set
                            .entries
                            .sort_by(|a, b| a.pub_key.cmp(&b.pub_key));
                    }
                }

                let until =
                    payload
                        .until_height
                        .and_then(|u| if u <= block_height { None } else { Some(u) });

                // Set reputation flags (revoked).
                let rep = self
                    .validator_reputation
                    .entry(target_hex.clone())
                    .or_default();
                rep.temporarily_revoked = true;
                rep.banned_until_height = until;

                self.push_ops_log(ValidatorOpsLogEntry {
                    height: block_height,
                    op: ValidatorOpsOp::Revoke,
                    target_pk_hex: target_hex,
                    new_pk_hex: None,
                    until_height: until,
                    proposal_id: Some(prop.id.clone()),
                    reason: payload.reason.clone(),
                });

                prop.status = ProposalStatus::Applied;
            }

            GovProposalKind::UnrevokeValidator => {
                let payload =
                    match serde_json::from_slice::<UnrevokeValidatorPayload>(&prop.payload) {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("[GOV] Payload UnrevokeValidator invalido");
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                            return;
                        }
                    };

                let target_hex = match keyfmt::pk_hex_from_any(&payload.pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                // Clear revoke flags.
                let rep = self
                    .validator_reputation
                    .entry(target_hex.clone())
                    .or_default();
                rep.temporarily_revoked = false;
                rep.banned_until_height = None;

                // Restore to active set if missing.
                if !self
                    .validator_set
                    .entries
                    .iter()
                    .any(|e| e.pub_key == target_hex)
                {
                    let entry = self.revoked_validators.get(&target_hex).cloned().unwrap_or(
                        ValidatorEntry {
                            pub_key: target_hex.clone(),
                            alias: None,
                            weight: 1,
                        },
                    );
                    self.validator_set.entries.push(entry);
                    self.validator_set
                        .entries
                        .sort_by(|a, b| a.pub_key.cmp(&b.pub_key));
                    self.validator_set.version = self.validator_set.version.saturating_add(1);
                }

                self.push_ops_log(ValidatorOpsLogEntry {
                    height: block_height,
                    op: ValidatorOpsOp::Unrevoke,
                    target_pk_hex: target_hex,
                    new_pk_hex: None,
                    until_height: None,
                    proposal_id: Some(prop.id.clone()),
                    reason: payload.reason.clone(),
                });

                prop.status = ProposalStatus::Applied;
            }

            // ---------------- OPERATOR ROLE MODEL V2: VALIDATOR -> COMPUTE TRANSITION ----------------
            GovProposalKind::RequestValidatorComputeTransition => {
                let payload = match serde_json::from_slice::<ValidatorComputeTransitionRequestPayload>(
                    &prop.payload,
                ) {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("[GOV] Payload RequestValidatorComputeTransition invalido");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                let target_hex = match keyfmt::pk_hex_from_any(&payload.validator_pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] validator_pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };
                let operator_hex = match keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] operator_wallet_pubkey invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                let policy = self.validator_compute_transition_quorum_policy_v1();
                let existing_pending = self
                    .validator_compute_transitions
                    .get(&target_hex)
                    .filter(|r| r.status == ValidatorComputeTransitionStatusV1::ExitPending)
                    .cloned();
                let requested_at = existing_pending
                    .as_ref()
                    .map(|r| r.requested_at_height)
                    .unwrap_or(block_height);

                if let Some(existing) = existing_pending.as_ref() {
                    if existing.operator_wallet_pubkey != operator_hex {
                        // Preserve the canonical pending record. A mismatched operator request must
                        // reject only the new proposal; it must not overwrite or cancel the legitimate
                        // pending transition for this validator.
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "validator compute transition operator mismatch",
                        );
                        return;
                    }
                }

                let mut decision = evaluate_validator_compute_transition_quorum_guard_v1(
                    &self.validator_set,
                    &self.validator_reputation,
                    &target_hex,
                    &policy,
                    block_height,
                    finalized_height,
                );

                // Canonical two-step lifecycle:
                //   Request -> EXIT_PENDING -> re-check quorum/finality after cooldown -> FINALIZED/CANCELLED/DENIED.
                // The first approved proposal never removes the validator. A later request proposal finalizes
                // only after the cooldown and a fresh guard pass, so exits cannot race a weakening L1 set.
                if existing_pending.is_none() {
                    if !decision.allowed {
                        self.validator_compute_transitions.insert(
                            target_hex.clone(),
                            ValidatorComputeTransitionRecordV1 {
                                validator_pubkey: target_hex.clone(),
                                operator_wallet_pubkey: operator_hex,
                                status: ValidatorComputeTransitionStatusV1::Denied,
                                requested_at_height: requested_at,
                                decided_at_height: Some(block_height),
                                finalized_at_height: None,
                                proposal_id: Some(prop.id.clone()),
                                deny_reasons: decision.deny_reasons.clone(),
                                reason: payload.reason.clone(),
                            },
                        );
                        eprintln!(
                            "[GOV] Validator compute transition denied at request: {:?}",
                            decision.deny_reasons
                        );
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "validator compute transition quorum guard denied",
                        );
                        return;
                    }
                    self.validator_compute_transitions.insert(
                        target_hex.clone(),
                        ValidatorComputeTransitionRecordV1 {
                            validator_pubkey: target_hex,
                            operator_wallet_pubkey: operator_hex,
                            status: ValidatorComputeTransitionStatusV1::ExitPending,
                            requested_at_height: requested_at,
                            decided_at_height: Some(block_height),
                            finalized_at_height: None,
                            proposal_id: Some(prop.id.clone()),
                            deny_reasons: Vec::new(),
                            reason: payload.reason.clone(),
                        },
                    );
                    prop.status = ProposalStatus::Applied;
                } else {
                    let cooldown_not_elapsed = block_height
                        < requested_at.saturating_add(policy.validator_exit_cooldown_blocks);
                    if cooldown_not_elapsed {
                        decision
                            .deny_reasons
                            .push("cooldown_not_elapsed".to_string());
                        decision.deny_reasons.sort();
                        decision.deny_reasons.dedup();
                        decision.allowed = false;
                    }

                    if !decision.allowed {
                        if cooldown_not_elapsed {
                            // An early finalization attempt must not destroy the canonical pending exit.
                            // Keep the transition pending and attach the precise deny reason to the record
                            // so operators/API clients can see why this proposal was rejected.
                            if let Some(mut pending) = existing_pending.clone() {
                                pending.decided_at_height = Some(block_height);
                                pending.deny_reasons = decision.deny_reasons.clone();
                                self.validator_compute_transitions
                                    .insert(target_hex.clone(), pending);
                            }
                            eprintln!("[GOV] Validator compute transition finalization rejected before cooldown elapsed: {:?}", decision.deny_reasons);
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "validator compute transition cooldown not elapsed",
                            );
                            return;
                        }
                        self.validator_compute_transitions.insert(
                            target_hex.clone(),
                            ValidatorComputeTransitionRecordV1 {
                                validator_pubkey: target_hex.clone(),
                                operator_wallet_pubkey: operator_hex,
                                status: ValidatorComputeTransitionStatusV1::Denied,
                                requested_at_height: requested_at,
                                decided_at_height: Some(block_height),
                                finalized_at_height: None,
                                proposal_id: Some(prop.id.clone()),
                                deny_reasons: decision.deny_reasons.clone(),
                                reason: payload.reason.clone(),
                            },
                        );
                        eprintln!(
                            "[GOV] Validator compute transition denied at final re-check: {:?}",
                            decision.deny_reasons
                        );
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "validator compute transition quorum guard denied",
                        );
                        return;
                    }

                    if let Some(pos) = self
                        .validator_set
                        .entries
                        .iter()
                        .position(|e| e.pub_key == target_hex)
                    {
                        let entry = self.validator_set.entries.remove(pos);
                        self.revoked_validators.insert(target_hex.clone(), entry);
                        self.validator_set
                            .entries
                            .sort_by(|a, b| a.pub_key.cmp(&b.pub_key));
                        self.validator_set.version = self.validator_set.version.saturating_add(1);
                    }

                    let rep = self
                        .validator_reputation
                        .entry(target_hex.clone())
                        .or_default();
                    rep.temporarily_revoked = false;
                    rep.banned_until_height = None;

                    let wallet_rep = self
                        .wallet_reputation
                        .entry(operator_hex.clone())
                        .or_default();
                    wallet_rep.wallet_pubkey = operator_hex.clone();
                    wallet_rep.validator_pubkey = Some(target_hex.clone());
                    wallet_rep.validator_set_member = false;
                    wallet_rep.operator_binding_status =
                        Some("VALIDATOR_EXITED_FOR_COMPUTE".to_string());
                    wallet_rep.record_seen_at_height(block_height);

                    self.validator_compute_transitions.insert(
                        target_hex.clone(),
                        ValidatorComputeTransitionRecordV1 {
                            validator_pubkey: target_hex.clone(),
                            operator_wallet_pubkey: operator_hex,
                            status: ValidatorComputeTransitionStatusV1::Finalized,
                            requested_at_height: requested_at,
                            decided_at_height: Some(block_height),
                            finalized_at_height: Some(block_height),
                            proposal_id: Some(prop.id.clone()),
                            deny_reasons: Vec::new(),
                            reason: payload.reason.clone(),
                        },
                    );

                    self.push_ops_log(ValidatorOpsLogEntry {
                        height: block_height,
                        op: ValidatorOpsOp::ValidatorExitForCompute,
                        target_pk_hex: target_hex,
                        new_pk_hex: None,
                        until_height: None,
                        proposal_id: Some(prop.id.clone()),
                        reason: payload.reason.clone(),
                    });

                    prop.status = ProposalStatus::Applied;
                }
            }

            GovProposalKind::CancelValidatorComputeTransition => {
                let payload = match serde_json::from_slice::<CancelValidatorComputeTransitionPayload>(
                    &prop.payload,
                ) {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("[GOV] Payload CancelValidatorComputeTransition invalido");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };
                let target_hex = match keyfmt::pk_hex_from_any(&payload.validator_pub_key) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] validator_pub_key invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };
                let operator_hex = match keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[GOV] operator_wallet_pubkey invalida: {e}");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };
                let Some(existing) = self.validator_compute_transitions.get(&target_hex).cloned()
                else {
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "validator compute transition cancel missing pending transition",
                    );
                    return;
                };
                if existing.status != ValidatorComputeTransitionStatusV1::ExitPending
                    || existing.operator_wallet_pubkey != operator_hex
                {
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "validator compute transition cancel requires matching pending transition",
                    );
                    return;
                }
                self.validator_compute_transitions.insert(
                    target_hex.clone(),
                    ValidatorComputeTransitionRecordV1 {
                        validator_pubkey: target_hex.clone(),
                        operator_wallet_pubkey: operator_hex,
                        status: ValidatorComputeTransitionStatusV1::Cancelled,
                        requested_at_height: existing.requested_at_height,
                        decided_at_height: Some(block_height),
                        finalized_at_height: None,
                        proposal_id: Some(prop.id.clone()),
                        deny_reasons: Vec::new(),
                        reason: payload.reason.clone(),
                    },
                );
                self.push_ops_log(ValidatorOpsLogEntry {
                    height: block_height,
                    op: ValidatorOpsOp::ValidatorComputeTransitionCancel,
                    target_pk_hex: target_hex,
                    new_pk_hex: None,
                    until_height: None,
                    proposal_id: Some(prop.id.clone()),
                    reason: payload.reason.clone(),
                });
                prop.status = ProposalStatus::Applied;
            }

            // ---------------- UPDATE VALIDATORS ----------------
            GovProposalKind::UpdateValidators => {
                let payload = match serde_json::from_slice::<ValidatorSetPayload>(&prop.payload) {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("[GOV] Payload UpdateValidators invalido");
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }
                };

                if payload.version <= self.validator_set.version {
                    eprintln!(
                        "[GOV] ValidatorSet version {} <= current {}, rifiuto.",
                        payload.version, self.validator_set.version
                    );
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                    return;
                }

                // Canonicalize + dedupe entries by pk_hex.
                let mut map: BTreeMap<String, ValidatorEntry> = BTreeMap::new();
                for e in payload.entries {
                    let pk_hex = match keyfmt::pk_hex_from_any(&e.pub_key) {
                        Ok(h) => h,
                        Err(_) => {
                            eprintln!("[GOV] UpdateValidators: invalid pub_key");
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                            return;
                        }
                    };

                    if !self.can_join_validator_set(&pk_hex, block_height) {
                        eprintln!(
                            "[GOV] UpdateValidators rejected: validator {} fails reputation checks",
                            pk_hex
                        );
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                        return;
                    }

                    let mut ee = e;
                    ee.pub_key = pk_hex.clone();
                    map.insert(pk_hex, ee);
                }

                let entries: Vec<ValidatorEntry> = map.into_values().collect();
                if entries.is_empty() {
                    eprintln!("[GOV] UpdateValidators rejected: empty validator set");
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                    return;
                }

                self.validator_set.entries = entries;
                self.validator_set.version = payload.version;

                self.push_ops_log(ValidatorOpsLogEntry {
                    height: block_height,
                    op: ValidatorOpsOp::ValidatorSetUpdate,
                    target_pk_hex: "__validator_set__".to_string(),
                    new_pk_hex: None,
                    until_height: None,
                    proposal_id: Some(prop.id.clone()),
                    reason: Some(format!(
                        "validator_set_version={}",
                        self.validator_set.version
                    )),
                });

                prop.status = ProposalStatus::Applied;
            }

            // ---------------- UPDATE ECONOMY POLICY ----------------
            GovProposalKind::UpdateEconomyPolicy => {
                match serde_json::from_slice::<EconomyPolicyDelta>(&prop.payload) {
                    Ok(delta) => {
                        if delta.base_fee_per_tx.is_some() {
                            self.economy_overrides.base_fee_per_tx = delta.base_fee_per_tx;
                        }
                        if let Some(v) = delta.treasury_pct_base_bps {
                            self.economy_overrides.treasury_pct_base_bps = Some(v.min(10_000));
                        }
                        if delta.burn_bps.is_some() {
                            self.economy_overrides.burn_bps = delta.burn_bps;
                        }
                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        eprintln!("⚠️ [GOV] Payload UpdateEconomyPolicy invalido: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- UPDATE MEMPOOL POLICY ----------------
            GovProposalKind::UpdateMempoolPolicy => {
                match serde_json::from_slice::<MempoolPolicyDelta>(&prop.payload) {
                    Ok(delta) => {
                        if let Some(v) = delta.max_mempool_size {
                            if v == 0 || v > 5_000_000 {
                                eprintln!("[GOV] max_mempool_size fuori range. Rifiuto.");
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                                return;
                            }
                        }
                        if let Some(v) = delta.max_tx_per_sender {
                            if v == 0 || v > 1_000_000 {
                                eprintln!("[GOV] max_tx_per_sender fuori range. Rifiuto.");
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                                return;
                            }
                        }
                        if let (Some(sender_cap), Some(pool_cap)) =
                            (delta.max_tx_per_sender, delta.max_mempool_size)
                        {
                            if sender_cap > pool_cap {
                                eprintln!("[GOV] max_tx_per_sender > max_mempool_size. Rifiuto.");
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                                return;
                            }
                        }
                        if let Some(v) = delta.max_mempool_bytes {
                            if !(1024..=10_u64 * 1024 * 1024 * 1024).contains(&v) {
                                eprintln!("[GOV] max_mempool_bytes fuori range. Rifiuto.");
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                                return;
                            }
                        }
                        if let Some(v) = delta.tx_ttl_secs {
                            if !(10..=60 * 60 * 24 * 30).contains(&v) {
                                eprintln!(
                                    "[GOV] tx_ttl_secs fuori range (10..30 giorni). Rifiuto."
                                );
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                                return;
                            }
                        }

                        if delta.max_mempool_size.is_some() {
                            self.mempool_overrides.max_mempool_size = delta.max_mempool_size;
                        }
                        if delta.max_tx_per_sender.is_some() {
                            self.mempool_overrides.max_tx_per_sender = delta.max_tx_per_sender;
                        }
                        if delta.max_mempool_bytes.is_some() {
                            self.mempool_overrides.max_mempool_bytes = delta.max_mempool_bytes;
                        }
                        if delta.tx_ttl_secs.is_some() {
                            self.mempool_overrides.tx_ttl_secs = delta.tx_ttl_secs;
                        }

                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        eprintln!("⚠️ [GOV] Payload UpdateMempoolPolicy invalido: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- UPDATE SECURITY POLICY ----------------
            GovProposalKind::UpdateSecurityPolicy => {
                match serde_json::from_slice::<SecurityPolicyDelta>(&prop.payload) {
                    Ok(delta) => {
                        if delta.max_block_size.is_some() {
                            self.security_overrides.max_block_size = delta.max_block_size;
                        }
                        if delta.min_fee_per_tx.is_some() {
                            self.security_overrides.min_fee_per_tx = delta.min_fee_per_tx;
                        }
                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        eprintln!("⚠️ [GOV] Payload UpdateSecurityPolicy invalido: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- UPDATE REPUTATION POLICY ----------------
            GovProposalKind::UpdateReputationPolicy => {
                match serde_json::from_slice::<ReputationPolicyDelta>(&prop.payload) {
                    Ok(delta) => {
                        if let Err(e) =
                            delta.validate_merged_contract_v1(&self.reputation_overrides)
                        {
                            eprintln!("[GOV] ReputationPolicyDelta invalido: {}. Rifiuto.", e);
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                            return;
                        }

                        if delta.good_threshold.is_some() {
                            self.reputation_overrides.good_threshold = delta.good_threshold;
                        }
                        if delta.probation_threshold.is_some() {
                            self.reputation_overrides.probation_threshold =
                                delta.probation_threshold;
                        }
                        if delta.banned_threshold.is_some() {
                            self.reputation_overrides.banned_threshold = delta.banned_threshold;
                        }
                        if delta.ban_duration_secs.is_some() {
                            self.reputation_overrides.ban_duration_secs = delta.ban_duration_secs;
                        }
                        if delta.decay_per_tick.is_some() {
                            self.reputation_overrides.decay_per_tick = delta.decay_per_tick;
                        }
                        if delta.tick_secs.is_some() {
                            self.reputation_overrides.tick_secs = delta.tick_secs;
                        }

                        if delta.w_valid_tx.is_some() {
                            self.reputation_overrides.w_valid_tx = delta.w_valid_tx;
                        }
                        if delta.w_invalid_tx.is_some() {
                            self.reputation_overrides.w_invalid_tx = delta.w_invalid_tx;
                        }
                        if delta.w_valid_block.is_some() {
                            self.reputation_overrides.w_valid_block = delta.w_valid_block;
                        }
                        if delta.w_invalid_block.is_some() {
                            self.reputation_overrides.w_invalid_block = delta.w_invalid_block;
                        }
                        if delta.w_spam.is_some() {
                            self.reputation_overrides.w_spam = delta.w_spam;
                        }
                        if delta.w_disconnect.is_some() {
                            self.reputation_overrides.w_disconnect = delta.w_disconnect;
                        }
                        if delta.w_slashed.is_some() {
                            self.reputation_overrides.w_slashed = delta.w_slashed;
                        }

                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        eprintln!("⚠️ [GOV] Payload UpdateReputationPolicy invalido: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- INGEST WALLET REPUTATION EVIDENCE ----------------
            GovProposalKind::IngestWalletReputationEvidence => {
                self.apply_ingest_wallet_reputation_evidence(block_height, prop, effects);
            }

            // ---------------- INGEST E2 WORKER REPUTATION EVIDENCE ----------------
            GovProposalKind::IngestE2WorkerReputationEvidence => {
                match serde_json::from_slice::<E2WorkerReputationEvidenceIngestPayloadV1>(
                    &prop.payload,
                ) {
                    Ok(payload) => {
                        if let Err(e) = payload.validate_contract_v1() {
                            self.reject_applied_proposal_with_wallet_misconduct_v1(
                                block_height,
                                prop,
                                WalletMisconductKindV1::MaliciousEvidenceSubmission,
                                &format!("E2 worker reputation evidence payload invalid: {}", e),
                            );
                            return;
                        }
                        for evidence in payload.evidences {
                            effects.governed_e2_worker_reputation_evidence.push(
                                GovernedE2WorkerReputationEvidenceApplyRequestV1 {
                                    proposal_id: prop.id.clone(),
                                    evidence,
                                },
                            );
                        }
                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        self.reject_applied_proposal_with_invalid_governance_window_v1(
                            block_height,
                            prop,
                            &format!("Payload IngestE2WorkerReputationEvidence invalid: {:?}", e),
                        );
                    }
                }
            }

            // ---------------- INGEST COMPUTE FIAT SETTLEMENT PROOF ----------------
            GovProposalKind::IngestComputeFiatSettlementProof => {
                match serde_json::from_slice::<
                    crate::compute_contract::ComputeFiatSettlementProofIngestPayloadV1,
                >(&prop.payload)
                {
                    Ok(payload) => {
                        if let Err(e) = payload.validate_contract_v1() {
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                &format!("compute fiat settlement proof payload invalid: {}", e),
                            );
                            return;
                        }
                        for proof in payload.proofs {
                            effects.governed_compute_fiat_settlement_proofs.push(
                                GovernedComputeFiatSettlementProofApplyRequestV1 {
                                    proposal_id: prop.id.clone(),
                                    proof,
                                },
                            );
                        }
                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            &format!("Payload IngestComputeFiatSettlementProof invalid: {:?}", e),
                        );
                    }
                }
            }

            // ---------------- GOVERNED E2 WORKER PRIVILEGES ----------------
            GovProposalKind::GrantE2WorkerCloudUnit
            | GovProposalKind::RevokeE2WorkerCloudUnit
            | GovProposalKind::GrantE2WorkerGpuCapability
            | GovProposalKind::RevokeE2WorkerGpuCapability
            | GovProposalKind::GrantE2WorkerCriticalWorkload
            | GovProposalKind::RevokeE2WorkerCriticalWorkload => {
                let Some((privilege, grant)) =
                    Self::e2_worker_privilege_kind_from_proposal_v1(&prop.kind)
                else {
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "unknown e2 worker privilege proposal kind",
                    );
                    return;
                };
                match serde_json::from_slice::<E2WorkerGovernedPrivilegePayloadV1>(&prop.payload) {
                    Ok(payload) => {
                        let proposal_id = prop.id.clone();
                        let payload_value =
                            serde_json::from_slice::<serde_json::Value>(&prop.payload)
                                .unwrap_or(serde_json::Value::Null);
                        let canonical_payload_bytes = serde_json::to_vec(&payload_value)
                            .unwrap_or_else(|_| prop.payload.clone());
                        let payload_hash =
                            hex::encode(sha2::Sha256::digest(&canonical_payload_bytes));
                        match self.apply_e2_worker_governed_privilege_v1(
                            block_height,
                            &proposal_id,
                            &payload_hash,
                            payload,
                            privilege,
                            grant,
                        ) {
                            Ok(()) => prop.status = ProposalStatus::Applied,
                            Err(e) => {
                                eprintln!("[GOV] E2 worker governed privilege apply failed: {}", e);
                                self.reject_pending_attributed_invalid_governance_v1(
                                    block_height,
                                    prop,
                                    "attributed invalid governance proposal",
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[GOV] Payload E2WorkerGovernedPrivilege invalid: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- BIND E2 WORKER OPERATOR WALLET ----------------
            GovProposalKind::BindE2WorkerOperatorWallet => {
                match serde_json::from_slice::<E2WorkerOperatorBindingPayloadV1>(&prop.payload) {
                    Ok(payload) => {
                        if let Err(e) = payload.validate_contract_v1() {
                            eprintln!("[GOV] E2 worker operator binding payload invalid: {}", e);
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                            return;
                        }
                        effects.governed_e2_worker_operator_bindings.push(
                            GovernedE2WorkerOperatorBindingApplyRequestV1 {
                                proposal_id: prop.id.clone(),
                                worker_node_pubkey: payload.worker_node_pubkey,
                                operator_wallet_pubkey: payload.operator_wallet_pubkey,
                            },
                        );
                        prop.status = ProposalStatus::Applied;
                    }
                    Err(e) => {
                        eprintln!("[GOV] Payload BindE2WorkerOperatorWallet invalid: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "attributed invalid governance proposal",
                        );
                    }
                }
            }

            // ---------------- BUMP PROTOCOL VERSION ----------------
            GovProposalKind::BumpProtocolVersion => {
                #[derive(Deserialize)]
                #[allow(dead_code)]
                // Forward-compatible payload decoding (fields may be unused in current binary).
                struct ProtoPayload {
                    new_version: u32,
                }

                if serde_json::from_slice::<ProtoPayload>(&prop.payload).is_ok() {
                    prop.status = ProposalStatus::Applied;
                } else {
                    eprintln!("⚠️ [GOV] Payload BumpProtocolVersion invalido");
                    self.reject_pending_attributed_invalid_governance_v1(
                        block_height,
                        prop,
                        "attributed invalid governance proposal",
                    );
                }
            }

            // ---------------- UPDATE GOVERNANCE PARAMS ----------------
            GovProposalKind::UpdateGovernanceParams => {
                match serde_json::from_slice::<GovernanceParamsDelta>(&prop.payload) {
                    Ok(delta) => match self.stage_governance_params_delta_v1(&delta) {
                        Ok(staged) => {
                            // Atomic commit boundary: no governance field is mutated until the
                            // full staged policy has passed validation.
                            self.params = staged.params;
                            self.min_timelock_blocks_emergency =
                                staged.min_timelock_blocks_emergency;
                            self.downtime_policy = staged.downtime_policy;
                            self.protocol_council = staged.protocol_council;
                            self.economy_council = staged.economy_council;
                            self.emergency_council = staged.emergency_council;
                            prop.status = ProposalStatus::Applied;
                        }
                        Err(e) => {
                            eprintln!(
                                "[GOV] UpdateGovernanceParams staged validation failed: {}",
                                e
                            );
                            self.reject_pending_attributed_invalid_governance_v1(
                                block_height,
                                prop,
                                "attributed invalid governance proposal",
                            );
                        }
                    },
                    Err(e) => {
                        eprintln!("[GOV] Payload UpdateGovernanceParams invalid: {:?}", e);
                        self.reject_pending_attributed_invalid_governance_v1(
                            block_height,
                            prop,
                            "Payload UpdateGovernanceParams invalid",
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    pub(super) fn sk_from_byte(b: u8) -> SigningKey {
        let seed = [b; 32];
        SigningKey::from_bytes(&seed)
    }

    pub(super) fn pk_b64(sk: &SigningKey) -> String {
        B64.encode(sk.verifying_key().to_bytes())
    }

    pub(super) fn sign_b64(sk: &SigningKey, msg: &[u8]) -> String {
        let sig = sk.sign(msg);
        B64.encode(sig.to_bytes())
    }

    pub(super) fn mk_bootstrap(min_timelock: u64) -> (GovernanceState, SigningKey) {
        let sk_a = sk_from_byte(7);
        let a_pk = pk_b64(&sk_a);

        let protocol = Council {
            members: vec![a_pk.clone()],
            threshold: 1,
        };
        let economy = Council {
            members: vec![a_pk.clone()],
            threshold: 1,
        };
        let emergency = Council {
            members: vec![a_pk.clone()],
            threshold: 1,
        };

        let params = GovernanceParams {
            min_timelock_blocks: min_timelock,
            max_proposal_lifetime_blocks: default_governance_proposal_max_lifetime_blocks_v1(),
            max_emergency_duration_blocks: 50,
            wallet_reputation_promotion_quorum: default_wallet_reputation_promotion_quorum(),
            e2_worker_admission_activation_height: default_e2_worker_admission_activation_height(),
            validator_compute_transition_min_active_validators:
                default_validator_compute_transition_min_active_validators(),
            validator_compute_transition_min_finality_quorum:
                default_validator_compute_transition_min_finality_quorum(),
            validator_compute_transition_validator_quality_floor:
                default_validator_compute_transition_validator_quality_floor(),
            validator_compute_transition_exit_cooldown_blocks:
                default_validator_compute_transition_exit_cooldown_blocks(),
            validator_compute_transition_max_finality_lag_blocks:
                default_validator_compute_transition_max_finality_lag_blocks(),
            validator_compute_transition_max_recent_missed_slots:
                default_validator_compute_transition_max_recent_missed_slots(),
            ft_activation_height: u64::MAX,
            ft_max_tokens_per_owner: default_ft_max_tokens_per_owner(),
            ft_create_cooldown_blocks: default_ft_create_cooldown_blocks(),
            ft_create_fee_native: default_ft_create_fee_native(),
            nft_activation_height: u64::MAX,
            nft_max_collections_per_owner: default_nft_max_collections_per_owner(),
            nft_create_cooldown_blocks: default_nft_create_cooldown_blocks(),
            nft_create_fee_native: default_nft_create_fee_native(),
            nft_enabled: default_nft_enabled(),
            nft_public_create_enabled: default_nft_public_create_enabled(),
            nft_public_mint_enabled: default_nft_public_mint_enabled(),
            nft_public_transfer_enabled: default_nft_public_transfer_enabled(),
            nft_public_approval_enabled: default_nft_public_approval_enabled(),
            nft_public_burn_enabled: default_nft_public_burn_enabled(),
            nft_public_revoke_enabled: default_nft_public_revoke_enabled(),
            nft_public_metadata_update_enabled: default_nft_public_metadata_update_enabled(),
            nft_public_freeze_enabled: default_nft_public_freeze_enabled(),
            nft_public_policy_update_enabled: default_nft_public_policy_update_enabled(),
            nft_public_issuer_update_enabled: default_nft_public_issuer_update_enabled(),
            nft_public_pause_enabled: default_nft_public_pause_enabled(),
            nft_metadata_hash_required: default_nft_metadata_hash_required(),
            nft_max_memo_bytes: default_nft_max_memo_bytes(),
            nft_max_uri_bytes: default_nft_max_uri_bytes(),
            nft_max_name_bytes: default_nft_max_name_bytes(),
            nft_max_symbol_bytes: default_nft_max_symbol_bytes(),
            nft_max_tokens_per_collection: default_nft_max_tokens_per_collection(),
            nft_max_tokens_per_owner: default_nft_max_tokens_per_owner(),
            nft_mint_fee_native: default_nft_mint_fee_native(),
            nft_transfer_fee_native: default_nft_transfer_fee_native(),
            nft_approval_fee_native: default_nft_approval_fee_native(),
            nft_burn_fee_native: default_nft_burn_fee_native(),
            nft_revoke_fee_native: default_nft_revoke_fee_native(),
            nft_metadata_update_fee_native: default_nft_metadata_update_fee_native(),
            nft_freeze_fee_native: default_nft_freeze_fee_native(),
            nft_policy_update_fee_native: default_nft_policy_update_fee_native(),
            nft_issuer_update_fee_native: default_nft_issuer_update_fee_native(),
            nft_pause_fee_native: default_nft_pause_fee_native(),
        };

        // validator_set stored as HEX (but we can provide base64 and canonicalize).
        let initial_validator_set = ValidatorSet {
            entries: vec![ValidatorEntry {
                pub_key: a_pk.clone(),
                alias: Some("Validator_A".to_string()),
                weight: 1,
            }],
            version: 1,
        };

        (
            GovernanceState::new(protocol, economy, emergency, params, initial_validator_set),
            sk_a,
        )
    }

    fn mk_block(index: u64, gov_txs: Vec<GovernanceTx>) -> Block {
        let mut b = Block::build_local(
            index,
            0,
            format!("{:064x}", index.saturating_sub(1)),
            Vec::new(),
        )
        .expect("test block build");
        b.governance_txs = gov_txs;
        b
    }

    pub(super) fn signed_vote_for_test(
        prop: &TxGovernanceProposal,
        council: &GovernanceCouncilKind,
        voter_sk: &SigningKey,
    ) -> TxGovernanceVote {
        let voter = pk_b64(voter_sk);
        let proposal_hash = proposal_hash_hex_v1(prop, council).expect("proposal hash");
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &voter).expect("vote bytes");
        TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter,
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(voter_sk, &vote_msg),
        }
    }

    fn signed_update_validators_proposal_for_test(
        id: &str,
        created_at_height: u64,
        effective_height: u64,
        proposer_sk: &SigningKey,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let payload = ValidatorSetPayload {
            entries: vec![ValidatorEntry {
                pub_key: proposer.clone(),
                alias: Some("Validator_A".to_string()),
                weight: 1,
            }],
            version: 2,
        };
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height,
            effective_height,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    fn signed_update_governance_params_proposal_for_test(
        id: &str,
        delta: GovernanceParamsDelta,
        created_at_height: u64,
        effective_height: u64,
        proposer_sk: &SigningKey,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::UpdateGovernanceParams,
            payload: serde_json::to_vec(&delta).unwrap(),
            created_at_height,
            effective_height,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    #[test]
    fn vote_tx_stores_confirmed_proposal_hash_and_rejects_stale_hash() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let payload = ValidatorSetPayload {
            version: 2,
            entries: vec![],
        };
        let mut prop = TxGovernanceProposal {
            id: "vote-hash-bound-govp-00000000000000000000000000000001".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop.clone())]);

        let actual_hash = gov
            .proposals
            .get(&prop.id)
            .unwrap()
            .proposal_hash_hex
            .clone();
        let stale_hash = "ab".repeat(32);
        assert_ne!(actual_hash, stale_hash);
        let mut stale_vote = TxGovernanceVote {
            proposal_id: prop.id.clone(),
            proposal_hash_hex: stale_hash.clone(),
            voter: proposer.clone(),
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        let stale_msg = vote_signing_bytes_for_tx_v1(&stale_vote).unwrap();
        stale_vote.signature = sign_b64(&sk_a, &stale_msg);
        gov.apply_block_governance_with_effects(2, &[GovernanceTx::Vote(stale_vote)]);
        assert!(gov.proposals.get(&prop.id).unwrap().votes.is_empty());

        let vote = signed_vote_for_test(&prop, &council, &sk_a);
        assert_eq!(vote.proposal_hash_hex, actual_hash);
        gov.apply_block_governance_with_effects(3, &[GovernanceTx::Vote(vote)]);
        assert_eq!(gov.proposals.get(&prop.id).unwrap().votes.len(), 1);
    }

    #[test]
    fn vote_signing_rejects_uppercase_proposal_hash_core() {
        let voter_sk = sk_from_byte(7);
        let voter = pk_b64(&voter_sk);
        let uppercase_hash = "AA".repeat(32);
        let vote = TxGovernanceVote {
            proposal_id: "uppercase-core-govp-00000000000000000000000000000002".to_string(),
            proposal_hash_hex: uppercase_hash,
            voter,
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        assert!(vote_signing_bytes_for_tx_v1(&vote).is_err());
    }

    #[test]
    fn vote_signing_rejects_whitespace_wrapped_proposal_hash_core() {
        let voter_sk = sk_from_byte(7);
        let voter = pk_b64(&voter_sk);
        let wrapped_hash = format!(" {} ", "aa".repeat(32));
        let vote = TxGovernanceVote {
            proposal_id: "wrapped-core-govp-00000000000000000000000000000002".to_string(),
            proposal_hash_hex: wrapped_hash,
            voter,
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        assert!(vote_signing_bytes_for_tx_v1(&vote).is_err());
    }

    #[test]
    fn nft_governance_params_update_applies_policy_surface() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let delta = GovernanceParamsDelta {
            nft_activation_height: Some(0),
            nft_enabled: Some(true),
            nft_public_create_enabled: Some(true),
            nft_public_mint_enabled: Some(true),
            nft_public_transfer_enabled: Some(true),
            nft_public_approval_enabled: Some(true),
            nft_public_burn_enabled: Some(true),
            nft_public_revoke_enabled: Some(true),
            nft_public_metadata_update_enabled: Some(true),
            nft_public_freeze_enabled: Some(true),
            nft_public_policy_update_enabled: Some(true),
            nft_public_issuer_update_enabled: Some(true),
            nft_public_pause_enabled: Some(false),
            nft_metadata_hash_required: Some(true),
            nft_max_memo_bytes: Some(crate::nft::NFTV1_MEMO_MAX_BYTES as u32),
            nft_max_uri_bytes: Some(256),
            nft_max_name_bytes: Some(64),
            nft_max_symbol_bytes: Some(12),
            nft_max_tokens_per_collection: Some(1000),
            nft_max_tokens_per_owner: Some(250),
            nft_mint_fee_native: Some(3),
            nft_transfer_fee_native: Some(5),
            nft_approval_fee_native: Some(7),
            nft_burn_fee_native: Some(11),
            nft_revoke_fee_native: Some(17),
            nft_metadata_update_fee_native: Some(19),
            nft_freeze_fee_native: Some(23),
            nft_policy_update_fee_native: Some(29),
            nft_issuer_update_fee_native: Some(31),
            nft_pause_fee_native: Some(13),
            ..Default::default()
        };
        let prop = signed_update_governance_params_proposal_for_test(
            "nft-policy-apply-govp-00000000000000000000000000000001",
            delta,
            1,
            1,
            &sk_a,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            1,
            &[
                GovernanceTx::Proposal(prop.clone()),
                GovernanceTx::Vote(vote),
            ],
        );

        let rec = gov.proposals.get(&prop.id).expect("proposal applied");
        assert_eq!(rec.status, ProposalStatus::Applied);
        assert_eq!(gov.params.nft_activation_height, 0);
        assert!(gov.params.nft_enabled);
        assert!(gov.params.nft_public_create_enabled);
        assert!(gov.params.nft_public_mint_enabled);
        assert!(gov.params.nft_public_transfer_enabled);
        assert!(gov.params.nft_public_approval_enabled);
        assert!(gov.params.nft_public_burn_enabled);
        assert!(gov.params.nft_public_revoke_enabled);
        assert!(gov.params.nft_public_metadata_update_enabled);
        assert!(gov.params.nft_public_freeze_enabled);
        assert!(gov.params.nft_public_policy_update_enabled);
        assert!(gov.params.nft_public_issuer_update_enabled);
        assert!(!gov.params.nft_public_pause_enabled);
        assert!(gov.params.nft_metadata_hash_required);
        assert_eq!(gov.params.nft_max_uri_bytes, 256);
        assert_eq!(gov.params.nft_max_name_bytes, 64);
        assert_eq!(gov.params.nft_max_symbol_bytes, 12);
        assert_eq!(gov.params.nft_max_tokens_per_collection, 1000);
        assert_eq!(gov.params.nft_max_tokens_per_owner, 250);
        assert_eq!(gov.params.nft_mint_fee_native, 3);
        assert_eq!(gov.params.nft_transfer_fee_native, 5);
        assert_eq!(gov.params.nft_approval_fee_native, 7);
        assert_eq!(gov.params.nft_burn_fee_native, 11);
        assert_eq!(gov.params.nft_revoke_fee_native, 17);
        assert_eq!(gov.params.nft_metadata_update_fee_native, 19);
        assert_eq!(gov.params.nft_freeze_fee_native, 23);
        assert_eq!(gov.params.nft_policy_update_fee_native, 29);
        assert_eq!(gov.params.nft_issuer_update_fee_native, 31);
        assert_eq!(gov.params.nft_pause_fee_native, 13);
    }

    #[test]
    fn nft_governance_params_reject_invalid_policy_surface() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let delta = GovernanceParamsDelta {
            nft_metadata_hash_required: Some(false),
            nft_enabled: Some(true),
            ..Default::default()
        };
        let prop = signed_update_governance_params_proposal_for_test(
            "nft-policy-invalid-govp-00000000000000000000000000000002",
            delta,
            1,
            1,
            &sk_a,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            1,
            &[
                GovernanceTx::Proposal(prop.clone()),
                GovernanceTx::Vote(vote),
            ],
        );

        let rec = gov.proposals.get(&prop.id).expect("proposal rejected");
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(!gov.params.nft_enabled);
        assert!(gov.params.nft_metadata_hash_required);
    }

    #[test]
    fn nft_governance_params_reject_enabled_with_zero_global_caps() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let delta = GovernanceParamsDelta {
            nft_activation_height: Some(0),
            nft_enabled: Some(true),
            nft_metadata_hash_required: Some(true),
            nft_max_collections_per_owner: Some(10),
            nft_max_tokens_per_collection: Some(0),
            nft_max_tokens_per_owner: Some(10),
            ..Default::default()
        };
        let prop = signed_update_governance_params_proposal_for_test(
            "nft-policy-zero-global-cap-govp-00000000000000000000000000000004",
            delta,
            1,
            1,
            &sk_a,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            1,
            &[
                GovernanceTx::Proposal(prop.clone()),
                GovernanceTx::Vote(vote),
            ],
        );

        let rec = gov.proposals.get(&prop.id).expect("proposal rejected");
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(!gov.params.nft_enabled);
        assert_eq!(gov.params.nft_max_tokens_per_collection, 0);
    }

    #[test]
    fn update_governance_params_reject_is_atomic_for_nft_policy_validation() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let original_min_timelock = gov.params.min_timelock_blocks;
        let original_max_lifetime = gov.params.max_proposal_lifetime_blocks;
        let original_nft_enabled = gov.params.nft_enabled;
        let original_metadata_required = gov.params.nft_metadata_hash_required;

        let delta = GovernanceParamsDelta {
            min_timelock_blocks: Some(77),
            max_proposal_lifetime_blocks: Some(88),
            nft_enabled: Some(true),
            nft_metadata_hash_required: Some(false),
            ..Default::default()
        };
        let prop = signed_update_governance_params_proposal_for_test(
            "nft-policy-atomic-reject-govp-00000000000000000000000000000003",
            delta,
            1,
            1,
            &sk_a,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            1,
            &[
                GovernanceTx::Proposal(prop.clone()),
                GovernanceTx::Vote(vote),
            ],
        );

        let rec = gov.proposals.get(&prop.id).expect("proposal rejected");
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert_eq!(gov.params.min_timelock_blocks, original_min_timelock);
        assert_eq!(
            gov.params.max_proposal_lifetime_blocks,
            original_max_lifetime
        );
        assert_eq!(gov.params.nft_enabled, original_nft_enabled);
        assert_eq!(
            gov.params.nft_metadata_hash_required,
            original_metadata_required
        );
    }

    #[test]
    fn pending_proposal_expires_after_bounded_lifetime() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        gov.params.max_proposal_lifetime_blocks = 2;
        let proposer = pk_b64(&sk_a);
        let payload = ValidatorSetPayload {
            version: 2,
            entries: vec![],
        };
        let mut prop = TxGovernanceProposal {
            id: "expires-govp-00000000000000000000000000000003".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);

        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop)]);
        assert_eq!(
            gov.proposals
                .get("expires-govp-00000000000000000000000000000003")
                .unwrap()
                .status,
            ProposalStatus::Pending
        );
        gov.apply_block_governance_with_effects(3, &[]);
        assert_eq!(
            gov.proposals
                .get("expires-govp-00000000000000000000000000000003")
                .unwrap()
                .status,
            ProposalStatus::Pending
        );
        gov.apply_block_governance_with_effects(4, &[]);
        let rec = gov
            .proposals
            .get("expires-govp-00000000000000000000000000000003")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Expired);
        assert_eq!(rec.terminal_height, Some(4));
    }

    #[test]
    fn duplicate_invalid_proposal_does_not_overwrite_pending() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let id = "dup-pending-govp-00000000000000000000000000000001";
        let prop = signed_update_validators_proposal_for_test(id, 1, 10, &sk_a);
        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop.clone())]);
        let before = gov.proposals.get(id).expect("pending proposal").clone();
        assert_eq!(before.status, ProposalStatus::Pending);
        assert!(!before.proposal_hash_hex.is_empty());

        let mut duplicate_invalid = prop;
        duplicate_invalid.created_at_height = 999;
        duplicate_invalid.effective_height = 999;
        duplicate_invalid.signature = "not-a-valid-signature".to_string();
        gov.apply_block_governance_with_effects(2, &[GovernanceTx::Proposal(duplicate_invalid)]);

        let after = gov.proposals.get(id).expect("proposal must remain present");
        assert_eq!(after.status, ProposalStatus::Pending);
        assert_eq!(after.created_at_height, before.created_at_height);
        assert_eq!(after.effective_height, before.effective_height);
        assert_eq!(after.proposal_hash_hex, before.proposal_hash_hex);
        assert_eq!(after.terminal_height, None);
    }

    #[test]
    fn duplicate_invalid_proposal_does_not_overwrite_applied() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let id = "dup-applied-govp-00000000000000000000000000000002";
        let prop = signed_update_validators_proposal_for_test(id, 1, 1, &sk_a);
        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop.clone())]);
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(2, &[GovernanceTx::Vote(vote)]);
        let before = gov.proposals.get(id).expect("applied proposal").clone();
        assert_eq!(before.status, ProposalStatus::Applied);

        let mut duplicate_invalid = prop;
        duplicate_invalid.created_at_height = 777;
        duplicate_invalid.effective_height = 777;
        duplicate_invalid.signature = "not-a-valid-signature".to_string();
        gov.apply_block_governance_with_effects(3, &[GovernanceTx::Proposal(duplicate_invalid)]);

        let after = gov.proposals.get(id).expect("proposal must remain present");
        assert_eq!(after.status, ProposalStatus::Applied);
        assert_eq!(after.created_at_height, before.created_at_height);
        assert_eq!(after.effective_height, before.effective_height);
        assert_eq!(after.proposal_hash_hex, before.proposal_hash_hex);
        assert_eq!(after.terminal_height, before.terminal_height);
    }

    #[test]
    fn core_rejects_empty_or_noncanonical_proposal_id() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let payload = ValidatorSetPayload {
            version: 2,
            entries: vec![],
        };
        let bad_ids = [
            "",
            " ",
            "P-UPPERCASE-govp-00000000000000000000000000000003",
            "bad/id-govp-00000000000000000000000000000003",
            "missing-govp-suffix",
            "bad-govp-ABCDEF00000000000000000000000003",
            "bad-govp-000000000000000000000000000003",
        ];

        for (idx, bad_id) in bad_ids.iter().enumerate() {
            let prop = TxGovernanceProposal {
                id: bad_id.to_string(),
                kind: GovProposalKind::UpdateValidators,
                payload: serde_json::to_vec(&payload).unwrap(),
                created_at_height: 10 + idx as u64,
                effective_height: 10 + idx as u64,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            assert!(proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).is_err());
            gov.apply_block_governance_with_effects(
                10 + idx as u64,
                &[GovernanceTx::Proposal(prop)],
            );
            assert!(
                !gov.proposals.contains_key(*bad_id),
                "noncanonical proposal id must not enter governance state"
            );
        }
    }

    #[test]
    fn vote_signing_rejects_empty_or_noncanonical_proposal_id() {
        let voter_sk = sk_from_byte(7);
        let voter = pk_b64(&voter_sk);
        let hash = "ab".repeat(32);
        for proposal_id in [
            "",
            "P-UPPERCASE-govp-00000000000000000000000000000004",
            "bad/id-govp-00000000000000000000000000000004",
            "missing-govp-suffix",
        ] {
            let vote = TxGovernanceVote {
                proposal_id: proposal_id.to_string(),
                proposal_hash_hex: hash.clone(),
                voter: voter.clone(),
                signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                chain_id: crate::chain_identity::chain_id().to_string(),
                genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
                signature: String::new(),
            };
            assert!(vote_signing_bytes_for_tx_v1(&vote).is_err());
        }
    }

    #[test]
    fn late_vote_after_expiry_is_not_recorded() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        gov.params.max_proposal_lifetime_blocks = 1;
        let id = "late-vote-expiry-govp-00000000000000000000000000000005";
        let prop = signed_update_validators_proposal_for_test(id, 1, 100, &sk_a);
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop)]);
        assert_eq!(
            gov.proposals.get(id).unwrap().status,
            ProposalStatus::Pending
        );

        gov.apply_block_governance_with_effects(3, &[GovernanceTx::Vote(vote)]);
        let rec = gov.proposals.get(id).unwrap();
        assert_eq!(rec.status, ProposalStatus::Expired);
        assert_eq!(rec.terminal_height, Some(3));
        assert!(rec.votes.is_empty());
        assert!(rec.vote_records_v1.is_empty());
    }

    #[test]
    fn proposal_signature_rejects_wrong_chain_domain() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let payload = ValidatorSetPayload {
            version: 2,
            entries: vec![],
        };
        let mut prop = TxGovernanceProposal {
            id: "wrong-chain-domain-govp-00000000000000000000000000000004".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: "wrong-chain-id".to_string(),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        // Signing may fail because the signing domain rejects the wrong chain; if a caller somehow
        // submits such a proposal, handle_proposal must still reject it fail-closed.
        prop.signature = "debug".to_string();
        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop)]);
        let rec = gov
            .proposals
            .get("wrong-chain-domain-govp-00000000000000000000000000000004")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }

    #[test]
    fn proposal_submission_does_not_auto_approve_without_explicit_vote() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let payload = ValidatorSetPayload {
            entries: vec![ValidatorEntry {
                pub_key: proposer.clone(),
                alias: Some("Validator_A".to_string()),
                weight: 1,
            }],
            version: 2,
        };
        let mut prop = TxGovernanceProposal {
            id: "no-auto-vote-govp-00000000000000000000000000000005".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);

        gov.apply_block_governance_with_effects(1, &[GovernanceTx::Proposal(prop)]);

        let rec = gov
            .proposals
            .get("no-auto-vote-govp-00000000000000000000000000000005")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Pending);
        assert!(
            rec.votes.is_empty(),
            "proposal must not imply approval vote"
        );
        assert_ne!(gov.validator_set.version, 2);
    }

    #[test]
    fn update_validators_applies_after_timelock_and_quorum() {
        let (bootstrap, sk_a) = mk_bootstrap(2);
        let proposer = pk_b64(&sk_a);

        let sk_b = sk_from_byte(9);
        let b_pk = pk_b64(&sk_b);

        let payload = ValidatorSetPayload {
            entries: vec![ValidatorEntry {
                pub_key: b_pk.clone(),
                alias: Some("Validator_B".to_string()),
                weight: 1,
            }],
            version: 2,
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");

        // Proposal in block #1, effective at height 3
        let mut prop = TxGovernanceProposal {
            id: "update-validators-govp-00000000000000000000000000000006".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: payload_bytes,
            created_at_height: 1,
            effective_height: 3,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);

        // Vote in block #2
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };

        let blocks = vec![
            mk_block(1, vec![GovernanceTx::Proposal(prop)]),
            mk_block(2, vec![GovernanceTx::Vote(vote)]),
            mk_block(3, vec![]),
        ];

        let final_gov = GovernanceState::replay_from_chain(bootstrap, &blocks);
        assert_eq!(final_gov.validator_set.version, 2);
        assert_eq!(final_gov.validator_set.entries.len(), 1);
        // Canonical HEX
        assert_eq!(
            final_gov.validator_set.entries[0].pub_key,
            keyfmt::pk_hex_from_any(&b_pk).unwrap()
        );
    }

    #[test]
    fn revoke_and_unrevoke_validator_changes_set_deterministically() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);

        // add validator B via UpdateValidators
        let sk_b = sk_from_byte(9);
        let b_pk = pk_b64(&sk_b);

        let payload = ValidatorSetPayload {
            entries: vec![
                ValidatorEntry {
                    pub_key: proposer.clone(),
                    alias: Some("A".into()),
                    weight: 1,
                },
                ValidatorEntry {
                    pub_key: b_pk.clone(),
                    alias: Some("B".into()),
                    weight: 1,
                },
            ],
            version: 2,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut prop = TxGovernanceProposal {
            id: "upd-govp-00000000000000000000000000000007".into(),
            kind: GovProposalKind::UpdateValidators,
            payload: payload_bytes,
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };

        gov.apply_block_governance(1, &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)]);
        assert_eq!(gov.validator_set.entries.len(), 2);

        // revoke B via emergency
        let revoke_payload = RevokeValidatorPayload {
            pub_key: b_pk.clone(),
            until_height: None,
            reason: Some("compromised".into()),
        };
        let revoke_bytes = serde_json::to_vec(&revoke_payload).unwrap();
        let mut prop2 = TxGovernanceProposal {
            id: "rev-govp-00000000000000000000000000000008".into(),
            kind: GovProposalKind::RevokeValidator,
            payload: revoke_bytes,
            created_at_height: 2,
            effective_height: 2,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council2 = GovernanceCouncilKind::Emergency;
        let msg2 = proposal_signing_bytes_v1(&prop2, &council2).unwrap();
        prop2.signature = sign_b64(&sk_a, &msg2);
        let proposal_hash2 = proposal_hash_hex_v1(&prop2, &council2).unwrap();
        let vote_msg2 = vote_signing_bytes_v1(&prop2.id, &proposal_hash2, &proposer).unwrap();
        let vote2 = TxGovernanceVote {
            proposal_hash_hex: proposal_hash2.clone(),
            proposal_id: prop2.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg2),
        };

        gov.apply_block_governance(
            2,
            &[GovernanceTx::Proposal(prop2), GovernanceTx::Vote(vote2)],
        );
        assert_eq!(gov.validator_set.entries.len(), 1);

        // unrevoke B
        let unrev_payload = UnrevokeValidatorPayload {
            pub_key: b_pk.clone(),
            reason: Some("recovered".into()),
        };
        let unrev_bytes = serde_json::to_vec(&unrev_payload).unwrap();
        let mut prop3 = TxGovernanceProposal {
            id: "unrev-govp-00000000000000000000000000000009".into(),
            kind: GovProposalKind::UnrevokeValidator,
            payload: unrev_bytes,
            created_at_height: 3,
            effective_height: 3,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg3 = proposal_signing_bytes_v1(&prop3, &council2).unwrap();
        prop3.signature = sign_b64(&sk_a, &msg3);
        let proposal_hash3 = proposal_hash_hex_v1(&prop3, &council2).unwrap();
        let vote_msg3 = vote_signing_bytes_v1(&prop3.id, &proposal_hash3, &proposer).unwrap();
        let vote3 = TxGovernanceVote {
            proposal_hash_hex: proposal_hash3.clone(),
            proposal_id: prop3.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg3),
        };

        gov.apply_block_governance(
            3,
            &[GovernanceTx::Proposal(prop3), GovernanceTx::Vote(vote3)],
        );
        assert_eq!(gov.validator_set.entries.len(), 2);
    }
    #[test]
    fn validator_reputation_deserializes_legacy_last_seen_only_into_both_fields() {
        let rep: ValidatorGovReputation = serde_json::from_value(serde_json::json!({
            "last_seen_height": 17,
            "downtime_consecutive_missed_turns": 3
        }))
        .unwrap();

        assert_eq!(rep.last_seen_height, 17);
        assert_eq!(rep.last_produced_height, 17);
        assert_eq!(rep.downtime_consecutive_missed_turns, 3);
    }

    #[test]
    fn validator_reputation_deserializes_phase1_last_produced_only_into_seen_too() {
        let rep: ValidatorGovReputation = serde_json::from_value(serde_json::json!({
            "last_produced_height": 23,
            "downtime_missed_turns_total": 9
        }))
        .unwrap();

        assert_eq!(rep.last_produced_height, 23);
        assert_eq!(rep.last_seen_height, 23);
        assert_eq!(rep.downtime_missed_turns_total, 9);
    }

    #[test]
    fn validator_reputation_preserves_distinct_seen_and_produced_heights_when_both_present() {
        let rep: ValidatorGovReputation = serde_json::from_value(serde_json::json!({
            "last_produced_height": 21,
            "last_seen_height": 34
        }))
        .unwrap();

        assert_eq!(rep.last_produced_height, 21);
        assert_eq!(rep.last_seen_height, 34);
    }

    #[test]
    fn validator_reputation_deserializer_preserves_run_evidence_counters() {
        let rep: ValidatorGovReputation = serde_json::from_value(serde_json::json!({
            "accepted_run_evidence_count": 7,
            "accepted_positive_run_evidence_count": 5,
            "accepted_negative_run_evidence_count": 2,
            "accepted_run_evidence_delta_total": -80,
            "last_run_evidence_height": 123,
            "last_run_evidence_id": "ev-1",
            "promoted_run_claim_count": 3,
            "promoted_positive_run_claim_count": 2,
            "promoted_negative_run_claim_count": 1,
            "promoted_run_claim_delta_total": -40,
            "last_promoted_run_claim_height": 124,
            "last_promoted_run_claim_id": "claim-1"
        }))
        .unwrap();

        assert_eq!(rep.accepted_run_evidence_count, 7);
        assert_eq!(rep.accepted_positive_run_evidence_count, 5);
        assert_eq!(rep.accepted_negative_run_evidence_count, 2);
        assert_eq!(rep.accepted_run_evidence_delta_total, -80);
        assert_eq!(rep.last_run_evidence_height, Some(123));
        assert_eq!(rep.last_run_evidence_id.as_deref(), Some("ev-1"));
        assert_eq!(rep.promoted_run_claim_count, 3);
        assert_eq!(rep.promoted_positive_run_claim_count, 2);
        assert_eq!(rep.promoted_negative_run_claim_count, 1);
        assert_eq!(rep.promoted_run_claim_delta_total, -40);
        assert_eq!(rep.last_promoted_run_claim_height, Some(124));
        assert_eq!(rep.last_promoted_run_claim_id.as_deref(), Some("claim-1"));
    }
    #[test]
    fn ingest_wallet_reputation_evidence_applies_canonically_and_updates_wallet_plane() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
            source_attester_sig_b64: None,
        };
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![item],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut prop = TxGovernanceProposal {
            id: "rep-ingest-govp-00000000000000000000000000000019".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: payload_bytes,
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        let effects = gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        assert_eq!(effects.acknowledged_run_wallet_evidence_ids.len(), 1);
        assert_eq!(gov.wallet_reputation_evidence_log.len(), 1);
        let wallet_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.accepted_run_evidence_count, 0);
        assert_eq!(rep.promoted_run_claim_count, 0);
        assert_eq!(gov.wallet_reputation_claims.len(), 1);
        let claim = gov.wallet_reputation_claims.values().next().unwrap();
        assert_eq!(claim.support_count, 1);
        assert!(!claim.promoted);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_duplicate_ids() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item1 = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "Spam".to_string(),
            score_before: 500,
            score_after: 498,
            applied_delta: -2,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 124,
            binding_source: "hello_runtime_telemetry".to_string(),
            source_attester_sig_b64: None,
        };
        item1.claim_id = wallet_reputation_claim_id_v1(&item1);
        item1.evidence_id = wallet_reputation_evidence_id_v1(&item1);
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item1).unwrap();
        item1.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
        let mut item2 = item1.clone();
        item2.peer_id = "12D3KooWAnotherPeer".to_string();
        item2.claim_id = item1.claim_id.clone();
        item2.evidence_id = item1.evidence_id.clone();
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: None,
            evidences: vec![item1, item2],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut prop = TxGovernanceProposal {
            id: "rep-dup-govp-00000000000000000000000000000018".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: payload_bytes,
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-dup-govp-00000000000000000000000000000018")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(gov.wallet_reputation_evidence_log.is_empty());
    }

    #[test]
    fn wallet_reputation_claim_id_is_source_agnostic_across_scores_tiers_and_small_time_drift() {
        let base = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            wallet_pubkey: "abcd".to_string(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
            source_attester_sig_b64: None,
        };
        let mut variant = base.clone();
        variant.source_node_id = Some("node-B".to_string());
        variant.source_attester_pubkey =
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
        variant.score_before = 700;
        variant.score_after = 660;
        variant.trust_tier = "Tier2".to_string();
        variant.observed_at_secs = 129; // same 30s bucket
        variant.binding_source = "hello_runtime_telemetry".to_string();
        assert_eq!(
            wallet_reputation_claim_id_v1(&base),
            wallet_reputation_claim_id_v1(&variant)
        );
        assert_ne!(
            wallet_reputation_evidence_id_v1(&base),
            wallet_reputation_evidence_id_v1(&variant)
        );
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_unauthorized_source_attester() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-X".to_string()),
            source_attester_pubkey: Some(pk_b64(&sk_from_byte(42))),
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
            source_attester_sig_b64: None,
        };
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_from_byte(42), &msg_ev));
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-X".to_string()),
            source_attester_pubkey: item.source_attester_pubkey.clone(),
            source_tip_height: Some(10),
            evidences: vec![item],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-bad-attester-govp-00000000000000000000000000000012".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-bad-attester-govp-00000000000000000000000000000012")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }

    #[test]
    fn wallet_reputation_signature_contract_versions_are_distinct() {
        let item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            source_attester_sig_b64: None,
            wallet_pubkey: "abcd".to_string(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let legacy = wallet_reputation_evidence_signing_bytes_legacy_v2(&item).unwrap();
        let current = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        assert_ne!(legacy, current);
        assert!(String::from_utf8(current).unwrap().contains("|v3|"));
    }

    #[test]
    fn wallet_reputation_signature_verifier_allows_legacy_only_without_source_node_binding() {
        let signer = sk_from_byte(77);
        let attester = pk_b64(&signer);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: None,
            source_attester_pubkey: Some(attester.clone()),
            source_attester_sig_b64: None,
            wallet_pubkey: attester,
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let legacy_sig = sign_b64(
            &signer,
            &wallet_reputation_evidence_signing_bytes_legacy_v2(&item).unwrap(),
        );
        assert_eq!(
            verify_wallet_reputation_evidence_signature(
                item.source_attester_pubkey.as_deref().unwrap(),
                &legacy_sig,
                &item,
                true,
            )
            .unwrap(),
            WalletReputationEvidenceSignatureVersion::LegacyV2
        );
        item.source_node_id = Some("node-A".to_string());
        assert!(verify_wallet_reputation_evidence_signature(
            item.source_attester_pubkey.as_deref().unwrap(),
            &legacy_sig,
            &item,
            true,
        )
        .is_err());
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_mixed_item_source_node_ids_without_payload_source_node_id(
    ) {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let observed_at_secs = 123;
        let make_item = |source_node: &str| {
            let mut item = WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some(source_node.to_string()),
                source_attester_pubkey: Some(proposer.clone()),
                source_attester_sig_b64: None,
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
            };
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
            item
        };
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: None,
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![make_item("node-A"), make_item("node-B")],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-mixed-node-no-payload-govp-00000000000000000000000000000022".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-mixed-node-no-payload-govp-00000000000000000000000000000022")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(gov.wallet_reputation_evidence_log.is_empty());
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_deprecated_batch_signature_field() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_attester_sig_b64: None,
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
        let payload = serde_json::json!({
            "source_node_id": "node-A",
            "source_attester_pubkey": proposer,
            "source_attester_sig_b64": "deprecated-batch-sig",
            "source_tip_height": 10,
            "evidences": [item],
        });
        let mut prop = TxGovernanceProposal {
            id: "rep-deprecated-batch-sig-govp-00000000000000000000000000000016".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: pk_b64(&sk_a),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &pk_b64(&sk_a)).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: pk_b64(&sk_a),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-deprecated-batch-sig-govp-00000000000000000000000000000016")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(gov.wallet_reputation_evidence_log.is_empty());
    }

    #[test]
    fn ingest_wallet_reputation_evidence_derives_batch_source_node_id_from_items_when_payload_omits_it(
    ) {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let make_item = |observed_at_secs: u64| {
            let mut item = WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some("node-A".to_string()),
                source_attester_pubkey: Some(proposer.clone()),
                source_attester_sig_b64: None,
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
            };
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
            item
        };
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: None,
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![make_item(123), make_item(154)],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-derive-node-from-items-govp-00000000000000000000000000000017".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-derive-node-from-items-govp-00000000000000000000000000000017")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Applied);
        assert_eq!(gov.wallet_reputation_evidence_log.len(), 2);
        assert!(gov
            .wallet_reputation_evidence_log
            .iter()
            .all(|evidence| evidence.source_node_id.as_deref() == Some("node-A")));
    }

    #[test]
    fn wallet_reputation_signature_binds_source_node_id() {
        let base = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            source_attester_sig_b64: None,
            wallet_pubkey: "abcd".to_string(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let mut variant = base.clone();
        variant.source_node_id = Some("node-B".to_string());
        assert_ne!(
            wallet_reputation_evidence_signing_bytes_v1(&base).unwrap(),
            wallet_reputation_evidence_signing_bytes_v1(&variant).unwrap()
        );
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_legacy_v2_signature_after_source_node_binding() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_attester_sig_b64: None,
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let legacy_msg = wallet_reputation_evidence_signing_bytes_legacy_v2(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &legacy_msg));
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![item],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-legacy-v2-govp-00000000000000000000000000000021".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-legacy-v2-govp-00000000000000000000000000000021")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_jailed_source_attester() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let proposer_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();
        gov.validator_reputation.insert(
            proposer_hex,
            ValidatorGovReputation {
                jailed_from_height: Some(0),
                jailed_until_height: Some(10),
                ..ValidatorGovReputation::default()
            },
        );
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_attester_sig_b64: None,
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
        };
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![item],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-jailed-attester-govp-00000000000000000000000000000020".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-jailed-attester-govp-00000000000000000000000000000020")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_uses_governed_promotion_quorum() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        gov.params.wallet_reputation_promotion_quorum = 3;
        let proposer = pk_b64(&sk_a);
        let sk_b = sk_from_byte(9);
        let attester_b = pk_b64(&sk_b);
        let sk_c = sk_from_byte(13);
        let attester_c = pk_b64(&sk_c);
        let observed_at_secs = 123;
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_b.clone(),
            alias: Some("Validator_B".to_string()),
            weight: 1,
        });
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_c.clone(),
            alias: Some("Validator_C".to_string()),
            weight: 1,
        });
        let make_item =
            |source_node: &str, source_attester: &str| WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some(source_node.to_string()),
                source_attester_pubkey: Some(source_attester.to_string()),
                source_attester_sig_b64: None,
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
            };
        for (idx, (source_node, source_attester, sk)) in [
            ("node-A", proposer.as_str(), &sk_a),
            ("node-B", attester_b.as_str(), &sk_b),
            ("node-C", attester_c.as_str(), &sk_c),
        ]
        .into_iter()
        .enumerate()
        {
            let mut item = make_item(source_node, source_attester);
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(sk, &msg_ev));
            let payload = WalletReputationEvidenceIngestPayload {
                source_node_id: item.source_node_id.clone(),
                source_attester_pubkey: item.source_attester_pubkey.clone(),
                source_tip_height: Some(10),
                evidences: vec![item],
            };
            let id = format!("rep-q-govp-{:032x}", idx + 1);
            let mut prop = TxGovernanceProposal {
                id: id.clone(),
                kind: GovProposalKind::IngestWalletReputationEvidence,
                payload: serde_json::to_vec(&payload).unwrap(),
                created_at_height: (idx + 1) as u64,
                effective_height: (idx + 1) as u64,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            let council = GovernanceCouncilKind::Protocol;
            let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
            prop.signature = sign_b64(&sk_a, &msg);
            let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
            let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
            let vote = TxGovernanceVote {
                proposal_hash_hex: proposal_hash.clone(),
                proposal_id: prop.id.clone(),
                voter: proposer.clone(),
                signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                chain_id: crate::chain_identity::chain_id().to_string(),
                genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
                signature: sign_b64(&sk_a, &vote_msg),
            };
            gov.apply_block_governance_with_effects(
                (idx + 1) as u64,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
            let rep = gov
                .wallet_reputation
                .get(&keyfmt::pk_hex_from_any(&proposer).unwrap())
                .unwrap();
            let claim = gov.wallet_reputation_claims.values().next().unwrap();
            if idx < 2 {
                assert!(!claim.promoted);
                assert_eq!(rep.promoted_run_claim_count, 0);
            }
        }
        let rep = gov
            .wallet_reputation
            .get(&keyfmt::pk_hex_from_any(&proposer).unwrap())
            .unwrap();
        let claim = gov.wallet_reputation_claims.values().next().unwrap();
        assert!(claim.promoted);
        assert_eq!(claim.support_count, 3);
        assert_eq!(rep.promoted_run_claim_count, 1);
        assert_eq!(rep.accepted_run_evidence_count, 3);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_promotes_claim_only_at_quorum() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let sk_b = sk_from_byte(9);
        let attester_b = pk_b64(&sk_b);
        let observed_at_secs = 123;
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_b.clone(),
            alias: Some("Validator_B".to_string()),
            weight: 1,
        });
        let make_item =
            |source_node: &str, source_attester: &str| WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some(source_node.to_string()),
                source_attester_pubkey: Some(source_attester.to_string()),
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
                source_attester_sig_b64: None,
            };
        let submit = |gov: &mut GovernanceState,
                      mut item: WalletReputationEvidenceIngestItem,
                      pid: &str,
                      height: u64| {
            let signer = if item.source_attester_pubkey.as_deref() == Some(proposer.as_str()) {
                sk_a.clone()
            } else {
                sk_b.clone()
            };
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(&signer, &msg_ev));
            let payload = WalletReputationEvidenceIngestPayload {
                source_node_id: item.source_node_id.clone(),
                source_attester_pubkey: item.source_attester_pubkey.clone(),
                source_tip_height: Some(10),
                evidences: vec![item],
            };
            let mut prop = TxGovernanceProposal {
                id: pid.into(),
                kind: GovProposalKind::IngestWalletReputationEvidence,
                payload: serde_json::to_vec(&payload).unwrap(),
                created_at_height: height,
                effective_height: height,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            let council = GovernanceCouncilKind::Protocol;
            let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
            prop.signature = sign_b64(&sk_a, &msg);
            let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
            let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
            let vote = TxGovernanceVote {
                proposal_hash_hex: proposal_hash.clone(),
                proposal_id: prop.id.clone(),
                voter: proposer.clone(),
                signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                chain_id: crate::chain_identity::chain_id().to_string(),
                genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
                signature: sign_b64(&sk_a, &vote_msg),
            };
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
        };
        submit(
            &mut gov,
            make_item("node-A", &proposer),
            "rep-q1-govp-00000000000000000000000000000023",
            1,
        );
        let wallet_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 0);
        let claim = gov.wallet_reputation_claims.values().next().unwrap();
        assert_eq!(claim.support_count, 1);
        assert!(!claim.promoted);
        submit(
            &mut gov,
            make_item("node-B", &attester_b),
            "rep-q2-govp-00000000000000000000000000000024",
            2,
        );
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 1);
        let claim = gov.wallet_reputation_claims.values().next().unwrap();
        assert_eq!(claim.support_count, 2);
        assert!(claim.promoted);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_keeps_counting_new_support_after_promotion() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let sk_b = sk_from_byte(9);
        let attester_b = pk_b64(&sk_b);
        let sk_c = sk_from_byte(10);
        let attester_c = pk_b64(&sk_c);
        let observed_at_secs = 123;
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_b.clone(),
            alias: Some("Validator_B".to_string()),
            weight: 1,
        });
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_c.clone(),
            alias: Some("Validator_C".to_string()),
            weight: 1,
        });
        let make_item =
            |source_node: &str, source_attester: &str| WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some(source_node.to_string()),
                source_attester_pubkey: Some(source_attester.to_string()),
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
                source_attester_sig_b64: None,
            };
        let submit = |gov: &mut GovernanceState,
                      mut item: WalletReputationEvidenceIngestItem,
                      pid: &str,
                      height: u64| {
            let signer = if item.source_attester_pubkey.as_deref() == Some(proposer.as_str()) {
                sk_a.clone()
            } else if item.source_attester_pubkey.as_deref() == Some(attester_b.as_str()) {
                sk_b.clone()
            } else {
                sk_c.clone()
            };
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(&signer, &msg_ev));
            let payload = WalletReputationEvidenceIngestPayload {
                source_node_id: item.source_node_id.clone(),
                source_attester_pubkey: item.source_attester_pubkey.clone(),
                source_tip_height: Some(10),
                evidences: vec![item],
            };
            let mut prop = TxGovernanceProposal {
                id: pid.into(),
                kind: GovProposalKind::IngestWalletReputationEvidence,
                payload: serde_json::to_vec(&payload).unwrap(),
                created_at_height: height,
                effective_height: height,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            let council = GovernanceCouncilKind::Protocol;
            let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
            prop.signature = sign_b64(&sk_a, &msg);
            let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
            let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
            let vote = TxGovernanceVote {
                proposal_hash_hex: proposal_hash.clone(),
                proposal_id: prop.id.clone(),
                voter: proposer.clone(),
                signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                chain_id: crate::chain_identity::chain_id().to_string(),
                genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
                signature: sign_b64(&sk_a, &vote_msg),
            };
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
        };

        submit(
            &mut gov,
            make_item("node-A", &proposer),
            "rep-c1-govp-00000000000000000000000000000013",
            1,
        );
        submit(
            &mut gov,
            make_item("node-B", &attester_b),
            "rep-c2-govp-00000000000000000000000000000014",
            2,
        );
        let wallet_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 1);
        assert_eq!(rep.accepted_run_evidence_count, 2);
        assert_eq!(rep.accepted_negative_run_evidence_count, 2);
        assert_eq!(rep.accepted_run_evidence_delta_total, -80);

        submit(
            &mut gov,
            make_item("node-C", &attester_c),
            "rep-c3-govp-00000000000000000000000000000015",
            3,
        );
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 1);
        assert_eq!(rep.accepted_run_evidence_count, 3);
        assert_eq!(rep.accepted_negative_run_evidence_count, 3);
        assert_eq!(rep.accepted_run_evidence_delta_total, -120);
        assert_eq!(rep.last_run_evidence_height, Some(3));
        let claim = gov.wallet_reputation_claims.values().next().unwrap();
        assert_eq!(claim.support_count, 3);
        assert_eq!(claim.evidence_ids.len(), 3);
        assert!(claim.promoted);
    }

    #[test]
    fn promoted_wallet_plane_counts_supporting_evidences_consistently() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let sk_b = sk_from_byte(9);
        let attester_b = pk_b64(&sk_b);
        let sk_c = sk_from_byte(10);
        let attester_c = pk_b64(&sk_c);
        let observed_at_secs = 123;
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_b.clone(),
            alias: Some("Validator_B".to_string()),
            weight: 1,
        });
        gov.validator_set.entries.push(ValidatorEntry {
            pub_key: attester_c.clone(),
            alias: Some("Validator_C".to_string()),
            weight: 1,
        });
        let make_item =
            |source_node: &str, source_attester: &str| WalletReputationEvidenceIngestItem {
                claim_id: String::new(),
                evidence_id: String::new(),
                source_node_id: Some(source_node.to_string()),
                source_attester_pubkey: Some(source_attester.to_string()),
                wallet_pubkey: proposer.clone(),
                peer_id: "12D3KooWExamplePeer".to_string(),
                event: "InvalidBlock".to_string(),
                score_before: 500,
                score_after: 460,
                applied_delta: -40,
                trust_tier: "Tier0".to_string(),
                observed_at_secs,
                binding_source: "pulse_runtime_telemetry".to_string(),
                source_attester_sig_b64: None,
            };
        let submit = |gov: &mut GovernanceState,
                      mut item: WalletReputationEvidenceIngestItem,
                      pid: &str,
                      height: u64| {
            let signer = if item.source_attester_pubkey.as_deref() == Some(proposer.as_str()) {
                sk_a.clone()
            } else if item.source_attester_pubkey.as_deref() == Some(attester_b.as_str()) {
                sk_b.clone()
            } else {
                sk_c.clone()
            };
            let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
            item.source_attester_sig_b64 = Some(sign_b64(&signer, &msg_ev));
            let payload = WalletReputationEvidenceIngestPayload {
                source_node_id: item.source_node_id.clone(),
                source_attester_pubkey: item.source_attester_pubkey.clone(),
                source_tip_height: Some(10),
                evidences: vec![item],
            };
            let mut prop = TxGovernanceProposal {
                id: pid.into(),
                kind: GovProposalKind::IngestWalletReputationEvidence,
                payload: serde_json::to_vec(&payload).unwrap(),
                created_at_height: height,
                effective_height: height,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            let council = GovernanceCouncilKind::Protocol;
            let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
            prop.signature = sign_b64(&sk_a, &msg);
            let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
            let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
            let vote = TxGovernanceVote {
                proposal_hash_hex: proposal_hash.clone(),
                proposal_id: prop.id.clone(),
                voter: proposer.clone(),
                signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                chain_id: crate::chain_identity::chain_id().to_string(),
                genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
                signature: sign_b64(&sk_a, &vote_msg),
            };
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
        };
        submit(
            &mut gov,
            make_item("node-A", &proposer),
            "rep-c1-govp-00000000000000000000000000000013",
            1,
        );
        submit(
            &mut gov,
            make_item("node-B", &attester_b),
            "rep-c2-govp-00000000000000000000000000000014",
            2,
        );
        let wallet_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 1);
        assert_eq!(rep.accepted_run_evidence_count, 2);
        assert_eq!(rep.accepted_negative_run_evidence_count, 2);
        assert_eq!(rep.accepted_run_evidence_delta_total, -80);
        submit(
            &mut gov,
            make_item("node-C", &attester_c),
            "rep-c3-govp-00000000000000000000000000000015",
            3,
        );
        let rep = gov.wallet_reputation.get(&wallet_hex).unwrap();
        assert_eq!(rep.promoted_run_claim_count, 1);
        assert_eq!(rep.accepted_run_evidence_count, 3);
        assert_eq!(rep.accepted_negative_run_evidence_count, 3);
        assert_eq!(rep.accepted_run_evidence_delta_total, -120);
    }

    #[test]
    fn ingest_wallet_reputation_evidence_rejects_duplicate_after_log_window_eviction() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let mut item = WalletReputationEvidenceIngestItem {
            claim_id: String::new(),
            evidence_id: String::new(),
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            wallet_pubkey: proposer.clone(),
            peer_id: "12D3KooWExamplePeer".to_string(),
            event: "InvalidBlock".to_string(),
            score_before: 500,
            score_after: 460,
            applied_delta: -40,
            trust_tier: "Tier0".to_string(),
            observed_at_secs: 123,
            binding_source: "pulse_runtime_telemetry".to_string(),
            source_attester_sig_b64: None,
        };
        let msg_ev = wallet_reputation_evidence_signing_bytes_v1(&item).unwrap();
        item.source_attester_sig_b64 = Some(sign_b64(&sk_a, &msg_ev));
        item.claim_id = wallet_reputation_claim_id_v1(&item);
        item.evidence_id = wallet_reputation_evidence_id_v1(&item);
        let claim_id = item.claim_id.clone();
        gov.wallet_reputation_claims.insert(
            claim_id.clone(),
            WalletReputationCanonicalClaimAggregate {
                claim_id: claim_id.clone(),
                wallet_pubkey: keyfmt::pk_hex_from_any(&proposer).unwrap(),
                peer_id: item.peer_id.clone(),
                event: item.event.clone(),
                score_before: item.score_before,
                score_after: item.score_after,
                applied_delta: item.applied_delta,
                trust_tier: item.trust_tier.clone(),
                observed_at_secs: item.observed_at_secs,
                binding_source: item.binding_source.clone(),
                source_node_ids: BTreeSet::new(),
                source_attester_pubkeys: BTreeSet::new(),
                evidence_ids: {
                    let mut s = BTreeSet::new();
                    s.insert(item.evidence_id.clone());
                    s
                },
                support_count: 1,
                promoted: false,
                promoted_at_height: None,
                last_source_tip_height: None,
                last_source_tip_height_advisory: false,
                last_ingested_height: 1,
            },
        );
        gov.wallet_reputation_evidence_ids.clear();
        let payload = WalletReputationEvidenceIngestPayload {
            source_node_id: Some("node-A".to_string()),
            source_attester_pubkey: Some(proposer.clone()),
            source_tip_height: Some(10),
            evidences: vec![item],
        };
        let mut prop = TxGovernanceProposal {
            id: "rep-window-dup-govp-00000000000000000000000000000025".into(),
            kind: GovProposalKind::IngestWalletReputationEvidence,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 2,
            effective_height: 2,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let proposal_hash = proposal_hash_hex_v1(&prop, &council).unwrap();
        let vote_msg = vote_signing_bytes_v1(&prop.id, &proposal_hash, &proposer).unwrap();
        let vote = TxGovernanceVote {
            proposal_hash_hex: proposal_hash.clone(),
            proposal_id: prop.id.clone(),
            voter: proposer.clone(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
            signature: sign_b64(&sk_a, &vote_msg),
        };
        gov.apply_block_governance_with_effects(
            2,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("rep-window-dup-govp-00000000000000000000000000000025")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }
    #[test]
    fn reputation_policy_delta_rejects_unknown_fields() {
        let raw = serde_json::json!({
            "good_threshold": 550,
            "probation_threshold": 500,
            "banned_threshold": 200,
            "unexpected": true
        });
        let res = serde_json::from_value::<ReputationPolicyDelta>(raw);
        assert!(res.is_err(), "unknown governance fields must be rejected");
    }

    #[test]
    fn reputation_policy_delta_validates_threshold_order_and_weight_direction() {
        let bad_thresholds = ReputationPolicyDelta {
            good_threshold: Some(600),
            probation_threshold: Some(700),
            banned_threshold: Some(300),
            ..Default::default()
        };
        assert!(bad_thresholds.validate_contract_v1().is_err());

        let bad_weight = ReputationPolicyDelta {
            w_invalid_tx: Some(1),
            ..Default::default()
        };
        assert!(bad_weight.validate_contract_v1().is_err());

        let hard_spam = ReputationPolicyDelta {
            w_spam: Some(-99),
            ..Default::default()
        };
        assert!(hard_spam.validate_contract_v1().is_err());

        let soft_spam = ReputationPolicyDelta {
            w_spam: Some(-10),
            ..Default::default()
        };
        assert!(soft_spam.validate_contract_v1().is_ok());

        let good = ReputationPolicyDelta {
            good_threshold: Some(550),
            probation_threshold: Some(500),
            banned_threshold: Some(200),
            w_valid_tx: Some(1),
            w_invalid_tx: Some(-50),
            ban_duration_secs: Some(3600),
            tick_secs: Some(300),
            decay_per_tick: Some(5),
            ..Default::default()
        };
        assert!(good.validate_contract_v1().is_ok());
    }

    #[test]
    fn reputation_policy_delta_uses_mainnet_default_baseline_for_partial_updates() {
        let current = ReputationPolicyDelta::default();

        let below_default_ban = ReputationPolicyDelta {
            probation_threshold: Some(150),
            ..Default::default()
        };
        assert!(
            below_default_ban
                .validate_merged_contract_v1(&current)
                .is_err(),
            "partial probation override below default banned threshold must be rejected"
        );

        let above_default_probation = ReputationPolicyDelta {
            banned_threshold: Some(525),
            ..Default::default()
        };
        assert!(
            above_default_probation
                .validate_merged_contract_v1(&current)
                .is_err(),
            "partial banned override above default probation threshold must be rejected"
        );

        let valid_partial = ReputationPolicyDelta {
            probation_threshold: Some(520),
            ..Default::default()
        };
        assert!(valid_partial.validate_merged_contract_v1(&current).is_ok());
    }

    #[test]
    fn reputation_policy_delta_rejects_partial_update_that_breaks_merged_thresholds() {
        let current = ReputationPolicyDelta {
            good_threshold: Some(550),
            probation_threshold: Some(500),
            banned_threshold: Some(200),
            ..Default::default()
        };
        let delta = ReputationPolicyDelta {
            probation_threshold: Some(575),
            ..Default::default()
        };
        assert!(delta.validate_merged_contract_v1(&current).is_err());
    }

    fn dummy_e2_worker_evidence_for_governance_test(
        id_byte: u8,
    ) -> crate::e2_worker_evidence::E2WorkerExecutionEvidenceV1 {
        crate::e2_worker_evidence::E2WorkerExecutionEvidenceV1 {
            format_version: crate::e2_worker_evidence::E2_WORKER_EVIDENCE_FORMAT_VERSION_V1
                .to_string(),
            chain_id: "newgen-devnet-slot".to_string(),
            genesis_hash: "aa".repeat(32),
            e2_contract_version: "1.0.0".to_string(),
            order_id: "11".repeat(32),
            job_id: "job-1".to_string(),
            job_kind: "wasm".to_string(),
            worker_node_pubkey: "worker".to_string(),
            operator_wallet_pubkey: "operator".to_string(),
            payer_wallet: "payer".to_string(),
            order_created_height: 10,
            order_claimed_height: 11,
            order_terminal_height: 12,
            result_hash: Some("22".repeat(32)),
            artifact_root_hash: None,
            receipt_hash: Some("33".repeat(32)),
            execution_status: "COMPLETED".to_string(),
            failure_class: "SUCCESS".to_string(),
            sla_ms: 100,
            max_time_ms: 1000,
            coordinator_id: "coord-a".to_string(),
            attester_pubkey: "attester".to_string(),
            evidence_timestamp_ms: 123,
            evidence_hash: format!("{:02x}", id_byte).repeat(32),
            signature: "sig".to_string(),
        }
    }

    #[test]
    fn ingest_e2_worker_reputation_evidence_emits_governed_effect_only() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let payload = E2WorkerReputationEvidenceIngestPayloadV1 {
            format_version: E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1.to_string(),
            evidences: vec![
                crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1::V1(
                    dummy_e2_worker_evidence_for_governance_test(0x44),
                ),
            ],
        };
        assert!(payload.validate_contract_v1().is_ok());
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut prop = TxGovernanceProposal {
            id: "e2-ingest-1-govp-00000000000000000000000000000027".to_string(),
            kind: GovProposalKind::IngestE2WorkerReputationEvidence,
            payload: payload_bytes,
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let council = GovernanceCouncilKind::Protocol;
        let msg = proposal_signing_bytes_v1(&prop, &council).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let vote = signed_vote_for_test(&prop, &council, &sk_a);
        let effects = gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        assert_eq!(effects.governed_e2_worker_reputation_evidence.len(), 1);
        let rec = gov
            .proposals
            .get("e2-ingest-1-govp-00000000000000000000000000000027")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Applied);
    }

    #[test]
    fn ingest_e2_worker_reputation_evidence_rejects_duplicate_payload_ids() {
        let ev = dummy_e2_worker_evidence_for_governance_test(0x55);
        let payload = E2WorkerReputationEvidenceIngestPayloadV1 {
            format_version: E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1.to_string(),
            evidences: vec![
                crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1::V1(ev.clone()),
                crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1::V1(ev),
            ],
        };
        assert!(payload.validate_contract_v1().is_err());
    }

    fn signed_e2_worker_privilege_proposal_for_test(
        id: &str,
        kind: GovProposalKind,
        worker: &str,
        operator: &str,
        proposer_sk: &SigningKey,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let (proposal_action, requested_tier) = match kind {
            GovProposalKind::GrantE2WorkerCloudUnit => ("grant", "CLOUD_UNIT"),
            GovProposalKind::RevokeE2WorkerCloudUnit => ("revoke", "CLOUD_UNIT"),
            GovProposalKind::GrantE2WorkerGpuCapability => ("grant", "GPU"),
            GovProposalKind::RevokeE2WorkerGpuCapability => ("revoke", "GPU"),
            GovProposalKind::GrantE2WorkerCriticalWorkload => ("grant", "CRITICAL"),
            GovProposalKind::RevokeE2WorkerCriticalWorkload => ("revoke", "CRITICAL"),
            _ => ("grant", "GPU"),
        };
        let payload = E2WorkerGovernedPrivilegePayloadV1 {
            format_version: E2_WORKER_GOVERNED_PRIVILEGE_PAYLOAD_VERSION_V1.to_string(),
            request_id: Some("test-request".to_string()),
            proposal_kind: Some(format!("{:?}", kind)),
            proposal_action: Some(proposal_action.to_string()),
            requested_tier: Some(requested_tier.to_string()),
            worker_id: Some("worker-test".to_string()),
            worker_node_pubkey: worker.to_string(),
            operator_wallet_pubkey: operator.to_string(),
            capability_snapshot_hash: Some("11".repeat(32)),
            critical_review_payload_hash: Some("22".repeat(32)),
            reason: Some("test governed e2 privilege".to_string()),
        };
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    #[test]
    fn governed_e2_worker_cloud_unit_grant_requires_existing_binding() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let worker = pk_b64(&sk_from_byte(31));
        let operator = pk_b64(&sk_from_byte(32));
        let prop = signed_e2_worker_privilege_proposal_for_test(
            "e2-cloud-missing-bind-govp-00000000000000000000000000000001",
            GovProposalKind::GrantE2WorkerCloudUnit,
            &worker,
            &operator,
            &sk_a,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);

        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );

        let rec = gov
            .proposals
            .get("e2-cloud-missing-bind-govp-00000000000000000000000000000001")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
        assert!(gov.e2_worker_governed_privileges.is_empty());
    }

    #[test]
    fn governed_e2_worker_grant_requires_bridge_correlation_fields() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let worker = pk_b64(&sk_from_byte(39));
        let operator = pk_b64(&sk_from_byte(40));
        let worker_hex = keyfmt::pk_hex_from_any(&worker).unwrap();
        let operator_hex = keyfmt::pk_hex_from_any(&operator).unwrap();
        gov.e2_worker_operator_bindings.insert(
            worker_hex,
            E2WorkerOperatorBindingRecordV1::active(
                keyfmt::pk_hex_from_any(&worker).unwrap(),
                operator_hex,
                1,
                None,
            ),
        );
        let mut prop = signed_e2_worker_privilege_proposal_for_test(
            "e2-gpu-missing-request-govp-00000000000000000000000000000009",
            GovProposalKind::GrantE2WorkerGpuCapability,
            &worker,
            &operator,
            &sk_a,
        );
        let mut payload: E2WorkerGovernedPrivilegePayloadV1 =
            serde_json::from_slice(&prop.payload).unwrap();
        payload.request_id = None;
        prop.payload = serde_json::to_vec(&payload).unwrap();
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(&sk_a, &msg);
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
        let rec = gov
            .proposals
            .get("e2-gpu-missing-request-govp-00000000000000000000000000000009")
            .unwrap();
        assert_eq!(rec.status, ProposalStatus::Rejected);
    }

    #[test]
    fn governed_e2_worker_cloud_gpu_critical_grants_are_protocol_concilium_effects() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let worker = pk_b64(&sk_from_byte(33));
        let operator = pk_b64(&sk_from_byte(34));
        let worker_hex = keyfmt::pk_hex_from_any(&worker).unwrap();
        let operator_hex = keyfmt::pk_hex_from_any(&operator).unwrap();
        gov.e2_worker_operator_bindings.insert(
            worker_hex.clone(),
            E2WorkerOperatorBindingRecordV1::active(
                worker_hex.clone(),
                operator_hex.clone(),
                1,
                None,
            ),
        );

        for (id, kind) in [
            (
                "e2-cloud-grant-govp-00000000000000000000000000000002",
                GovProposalKind::GrantE2WorkerCloudUnit,
            ),
            (
                "e2-gpu-grant-govp-00000000000000000000000000000003",
                GovProposalKind::GrantE2WorkerGpuCapability,
            ),
            (
                "e2-critical-grant-govp-00000000000000000000000000000004",
                GovProposalKind::GrantE2WorkerCriticalWorkload,
            ),
        ] {
            let prop =
                signed_e2_worker_privilege_proposal_for_test(id, kind, &worker, &operator, &sk_a);
            let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
            gov.apply_block_governance_with_effects(
                1,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
            assert_eq!(
                gov.proposals.get(id).unwrap().status,
                ProposalStatus::Applied
            );
        }

        let privileges = gov.e2_worker_governed_privileges.get(&worker_hex).unwrap();
        assert!(privileges.cloud_unit_allowed);
        assert!(privileges.gpu_allowed);
        assert!(privileges.critical_workload_allowed);

        let cloud_prop = gov
            .proposals
            .get("e2-cloud-grant-govp-00000000000000000000000000000002")
            .unwrap();
        let cloud_payload: E2WorkerGovernedPrivilegePayloadV1 =
            serde_json::from_slice(&cloud_prop.payload).unwrap();
        let expected_bridge_hash =
            GovernanceState::e2_worker_governed_privilege_bridge_payload_hash_v1(&cloud_payload)
                .expect("test bridge grant payload must be hashable");
        assert_eq!(
            privileges.cloud_unit_grant_payload_hash.as_deref(),
            Some(expected_bridge_hash.as_str()),
            "canonical worker eligibility must expose the E2 governance bridge payload hash, not an unrelated raw proposal serialization hash"
        );
    }

    #[test]
    fn governed_e2_worker_grants_and_revokes_are_tier_scoped() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let worker = pk_b64(&sk_from_byte(35));
        let operator = pk_b64(&sk_from_byte(36));
        let worker_hex = keyfmt::pk_hex_from_any(&worker).unwrap();
        let operator_hex = keyfmt::pk_hex_from_any(&operator).unwrap();
        gov.e2_worker_operator_bindings.insert(
            worker_hex.clone(),
            E2WorkerOperatorBindingRecordV1::active(worker_hex.clone(), operator_hex, 1, None),
        );

        for (id, kind) in [
            (
                "e2-cloud-grant-scoped-govp-00000000000000000000000000000005",
                GovProposalKind::GrantE2WorkerCloudUnit,
            ),
            (
                "e2-gpu-grant-scoped-govp-00000000000000000000000000000006",
                GovProposalKind::GrantE2WorkerGpuCapability,
            ),
            (
                "e2-critical-grant-scoped-govp-00000000000000000000000000000007",
                GovProposalKind::GrantE2WorkerCriticalWorkload,
            ),
            (
                "e2-cloud-revoke-scoped-govp-00000000000000000000000000000008",
                GovProposalKind::RevokeE2WorkerCloudUnit,
            ),
        ] {
            let prop =
                signed_e2_worker_privilege_proposal_for_test(id, kind, &worker, &operator, &sk_a);
            let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
            gov.apply_block_governance_with_effects(
                1,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
            assert_eq!(
                gov.proposals.get(id).unwrap().status,
                ProposalStatus::Applied
            );
        }

        let privileges = gov.e2_worker_governed_privileges.get(&worker_hex).unwrap();
        assert!(!privileges.cloud_unit_allowed);
        assert!(privileges.gpu_allowed);
        assert!(privileges.critical_workload_allowed);
        assert!(privileges.cloud_unit_grant_proposal_id.is_none());
        assert!(privileges.gpu_grant_proposal_id.is_some());
        assert!(privileges.critical_workload_grant_proposal_id.is_some());
    }

    #[test]
    fn wallet_generic_misconduct_applies_points_without_auto_revoke() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let wallet = pk_b64(&sk_a);
        let wallet_hex = keyfmt::pk_hex_from_any(&wallet).unwrap();

        gov.apply_wallet_generic_misconduct_effect_v1(
            &wallet,
            WalletMisconductKindV1::InvalidGovernanceProposalSpam,
            42,
            "test invalid proposal",
        );

        let rep = gov.wallet_reputation.get(&wallet_hex).expect("wallet rep");
        assert_eq!(
            rep.misbehavior_points,
            WalletMisconductKindV1::InvalidGovernanceProposalSpam.misbehavior_points_v1()
        );
        assert_eq!(rep.failure_count, 1);
        assert_eq!(rep.recent_failure_count, 1);
        assert_eq!(rep.last_hard_fault_height, None);
        assert!(!rep.temporarily_revoked);
        assert_eq!(rep.jailed_until_height, None);
    }

    #[test]
    fn wallet_double_claim_is_hard_candidate_without_auto_jail_or_slash() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let wallet = pk_b64(&sk_a);
        let wallet_hex = keyfmt::pk_hex_from_any(&wallet).unwrap();

        gov.apply_wallet_generic_misconduct_effect_v1(
            &wallet,
            WalletMisconductKindV1::DoubleClaim,
            77,
            "test double claim",
        );

        let rep = gov.wallet_reputation.get(&wallet_hex).expect("wallet rep");
        assert_eq!(
            rep.misbehavior_points,
            WalletMisconductKindV1::DoubleClaim.misbehavior_points_v1()
        );
        assert_eq!(rep.last_hard_fault_height, Some(77));
        assert_eq!(rep.slashed_count, 0);
        assert_eq!(rep.last_slash_height, 0);
        assert!(!rep.temporarily_revoked);
        assert_eq!(rep.jailed_until_height, None);
    }

    fn invalid_created_at_proposal_for_spam_test(
        id: &str,
        proposer: &str,
        block_height: u64,
    ) -> TxGovernanceProposal {
        TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::UpdateEconomyPolicy,
            payload: Vec::new(),
            created_at_height: block_height.saturating_sub(1),
            effective_height: block_height,
            proposer: proposer.to_string(),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        }
    }

    fn signed_invalid_e2_ingest_proposal_for_spam_test(
        id: &str,
        proposer_sk: &ed25519_dalek::SigningKey,
        block_height: u64,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::IngestE2WorkerReputationEvidence,
            payload: b"not-json".to_vec(),
            created_at_height: block_height,
            effective_height: block_height,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    #[test]
    fn unauthenticated_invalid_proposal_does_not_increment_wallet_spam_window() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer = pk_b64(&sk_a);
        let proposer_hex = keyfmt::pk_hex_from_any(&proposer).unwrap();

        for i in 0..3 {
            let height = 100 + i;
            let prop = invalid_created_at_proposal_for_spam_test(
                &format!("unattr-spam-govp-{:032x}", i),
                &proposer,
                height,
            );
            gov.apply_block_governance_with_effects(height, &[GovernanceTx::Proposal(prop)]);
        }

        assert!(
            !gov.wallet_governance_invalid_proposal_windows
                .contains_key(&proposer_hex),
            "pre-signature proposal rejects must not feed wallet spam windows"
        );
        let points = gov
            .wallet_reputation
            .get(&proposer_hex)
            .map(|rep| rep.misbehavior_points)
            .unwrap_or(0);
        assert_eq!(points, 0, "unauthenticated rejects must be reject-only");
    }

    #[test]
    fn spoofed_proposer_invalid_proposals_do_not_penalize_victim_wallet() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let victim = pk_b64(&sk_a);
        let victim_hex = keyfmt::pk_hex_from_any(&victim).unwrap();

        for i in 0..3 {
            let height = 200 + i;
            let prop = invalid_created_at_proposal_for_spam_test(
                &format!("spoofed-spam-govp-{:032x}", i),
                &victim,
                height,
            );
            gov.apply_block_governance_with_effects(height, &[GovernanceTx::Proposal(prop)]);
        }

        assert!(
            !gov.wallet_governance_invalid_proposal_windows
                .contains_key(&victim_hex),
            "spoofed pre-attribution proposals must not create victim spam windows"
        );
        let points = gov
            .wallet_reputation
            .get(&victim_hex)
            .map(|rep| rep.misbehavior_points)
            .unwrap_or(0);
        assert_eq!(
            points, 0,
            "spoofed pre-attribution proposals must not penalize the victim wallet"
        );
    }

    #[test]
    fn signed_invalid_proposal_is_reject_only_until_spam_threshold() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer_hex = keyfmt::pk_hex_from_any(&pk_b64(&sk_a)).unwrap();

        for i in 0..2 {
            let height = 300 + i;
            let prop = signed_invalid_e2_ingest_proposal_for_spam_test(
                &format!("signed-invalid-govp-{:032x}", i),
                &sk_a,
                height,
            );
            let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
            let points = gov
                .wallet_reputation
                .get(&proposer_hex)
                .map(|rep| rep.misbehavior_points)
                .unwrap_or(0);
            assert_eq!(
                points, 0,
                "single/second signed invalid proposal must remain reject-only"
            );
        }

        let window = gov
            .wallet_governance_invalid_proposal_windows
            .get(&proposer_hex)
            .expect("invalid proposal window");
        assert_eq!(window.recent_invalid_governance_proposal_count, 2);
        assert!(!window.spam_misconduct_applied_in_window);
    }

    #[test]
    fn third_signed_invalid_proposal_triggers_wallet_spam_misconduct_once_per_window() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer_hex = keyfmt::pk_hex_from_any(&pk_b64(&sk_a)).unwrap();

        for i in 0..3 {
            let height = 400 + i;
            let prop = signed_invalid_e2_ingest_proposal_for_spam_test(
                &format!("signed-spam-trigger-govp-{:032x}", i),
                &sk_a,
                height,
            );
            let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
        }

        let rep = gov
            .wallet_reputation
            .get(&proposer_hex)
            .expect("wallet misconduct rep");
        assert_eq!(
            rep.misbehavior_points,
            WalletMisconductKindV1::InvalidGovernanceProposalSpam.misbehavior_points_v1()
        );
        let window = gov
            .wallet_governance_invalid_proposal_windows
            .get(&proposer_hex)
            .expect("invalid proposal window");
        assert_eq!(window.recent_invalid_governance_proposal_count, 3);
        assert!(window.spam_misconduct_applied_in_window);

        let extra = signed_invalid_e2_ingest_proposal_for_spam_test(
            "signed-spam-extra-govp-00000000000000000000000000000026",
            &sk_a,
            404,
        );
        let extra_vote = signed_vote_for_test(&extra, &GovernanceCouncilKind::Protocol, &sk_a);
        gov.apply_block_governance_with_effects(
            404,
            &[
                GovernanceTx::Proposal(extra),
                GovernanceTx::Vote(extra_vote),
            ],
        );
        let rep_after = gov
            .wallet_reputation
            .get(&proposer_hex)
            .expect("wallet misconduct rep");
        assert_eq!(
            rep_after.misbehavior_points,
            WalletMisconductKindV1::InvalidGovernanceProposalSpam.misbehavior_points_v1(),
            "spam misconduct must not be re-applied repeatedly in the same window"
        );
    }

    fn signed_invalid_protocol_proposal_for_spam_test(
        id: &str,
        proposer_sk: &ed25519_dalek::SigningKey,
        block_height: u64,
        kind: GovProposalKind,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind,
            payload: b"not-json".to_vec(),
            created_at_height: block_height,
            effective_height: block_height,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    #[test]
    fn third_signed_invalid_mixed_kind_proposal_triggers_spam_once() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let proposer_hex = keyfmt::pk_hex_from_any(&pk_b64(&sk_a)).unwrap();
        let cases = [
            GovProposalKind::UpdateSecurityPolicy,
            GovProposalKind::BindE2WorkerOperatorWallet,
            GovProposalKind::BumpProtocolVersion,
        ];

        for (i, kind) in cases.iter().cloned().enumerate() {
            let height = 500 + i as u64;
            let prop = signed_invalid_protocol_proposal_for_spam_test(
                &format!("signed-mixed-spam-govp-{:032x}", i),
                &sk_a,
                height,
                kind,
            );
            let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Protocol, &sk_a);
            gov.apply_block_governance_with_effects(
                height,
                &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            );
        }

        let window = gov
            .wallet_governance_invalid_proposal_windows
            .get(&proposer_hex)
            .expect("mixed invalid proposal window");
        assert_eq!(window.recent_invalid_governance_proposal_count, 3);
        assert!(window.spam_misconduct_applied_in_window);

        let rep = gov
            .wallet_reputation
            .get(&proposer_hex)
            .expect("wallet spam rep");
        assert_eq!(
            rep.misbehavior_points,
            WalletMisconductKindV1::InvalidGovernanceProposalSpam.misbehavior_points_v1()
        );
    }

    fn signed_emergency_safe_mode_proposal_for_test(
        id: &str,
        proposer_sk: &SigningKey,
        created_at_height: u64,
        effective_height: u64,
    ) -> TxGovernanceProposal {
        let proposer = pk_b64(proposer_sk);
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::EmergencySafeModeOn,
            payload: Vec::new(),
            created_at_height,
            effective_height,
            proposer,
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Emergency)
            .expect("proposal signing bytes");
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    #[test]
    fn apply_ready_counts_vote_records_v1_matching_hash_and_domain() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let prop = signed_emergency_safe_mode_proposal_for_test(
            "audit-vote-apply-govp-00000000000000000000000000000010",
            &sk_a,
            1,
            1,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Emergency, &sk_a);

        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );

        let record = gov
            .proposals
            .get("audit-vote-apply-govp-00000000000000000000000000000010")
            .expect("proposal record");
        assert_eq!(record.status, ProposalStatus::Applied);
        assert!(
            !record.vote_records_v1.is_empty(),
            "applied proposal must retain audit-grade vote records"
        );
        assert!(gov.safe_mode.active, "proposal effect must apply");
    }

    #[test]
    fn apply_ready_rejects_vote_record_with_mismatched_hash_even_if_compact_vote_exists() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let prop = signed_emergency_safe_mode_proposal_for_test(
            "audit-vote-mismatch-govp-00000000000000000000000000000011",
            &sk_a,
            1,
            2,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Emergency, &sk_a);

        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );

        let proposal = gov
            .proposals
            .get_mut("audit-vote-mismatch-govp-00000000000000000000000000000011")
            .expect("pending proposal");
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert!(
            !proposal.votes.is_empty(),
            "compact legacy vote view should exist for compatibility"
        );
        let first_record = proposal
            .vote_records_v1
            .values_mut()
            .next()
            .expect("audit vote record");
        first_record.proposal_hash_hex = "00".repeat(32);

        gov.apply_block_governance_with_effects(2, &[]);

        let proposal = gov
            .proposals
            .get("audit-vote-mismatch-govp-00000000000000000000000000000011")
            .expect("proposal after apply attempt");
        assert_eq!(
            proposal.status,
            ProposalStatus::Pending,
            "invalid audit vote record must not be rescued by compact legacy votes"
        );
        assert!(!gov.safe_mode.active, "proposal effect must not apply");
    }

    #[test]
    fn proposal_signing_rejects_whitespace_domain_fields() {
        let proposer_sk = sk_from_byte(21);
        let proposer = pk_b64(&proposer_sk);
        let prop = TxGovernanceProposal {
            id: "domain-whitespace-prop-govp-00000000000000000000000000000001".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&ValidatorSetPayload {
                version: 2,
                entries: vec![],
            })
            .unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer,
            signature_domain: format!(" {} ", GOVERNANCE_SIGNATURE_DOMAIN_V2),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        assert!(proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).is_err());
    }

    #[test]
    fn vote_signing_rejects_whitespace_domain_fields() {
        let voter_sk = sk_from_byte(22);
        let vote = TxGovernanceVote {
            proposal_id: "domain-whitespace-vote-govp-00000000000000000000000000000002".to_string(),
            proposal_hash_hex: "aa".repeat(32),
            voter: pk_b64(&voter_sk),
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: format!(" {} ", crate::chain_identity::chain_id()),
            genesis_hash: governance_signature_genesis_hash_for_runtime_v1(),
            signature: String::new(),
        };
        assert!(vote_signing_bytes_for_tx_v1(&vote).is_err());
    }

    #[test]
    fn proposal_and_vote_signing_reject_uppercase_genesis_hash() {
        let proposer_sk = sk_from_byte(23);
        let proposer = pk_b64(&proposer_sk);
        let uppercase_genesis = "AA".repeat(32);
        let prop = TxGovernanceProposal {
            id: "uppercase-genesis-prop-govp-00000000000000000000000000000003".to_string(),
            kind: GovProposalKind::UpdateValidators,
            payload: serde_json::to_vec(&ValidatorSetPayload {
                version: 2,
                entries: vec![],
            })
            .unwrap(),
            created_at_height: 1,
            effective_height: 1,
            proposer: proposer.clone(),
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: uppercase_genesis.clone(),
            signature: String::new(),
        };
        assert!(proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Protocol).is_err());

        let vote = TxGovernanceVote {
            proposal_id: "uppercase-genesis-vote-govp-00000000000000000000000000000004".to_string(),
            proposal_hash_hex: "aa".repeat(32),
            voter: proposer,
            signature_domain: GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: uppercase_genesis,
            signature: String::new(),
        };
        assert!(vote_signing_bytes_for_tx_v1(&vote).is_err());
    }

    #[test]
    fn valid_vote_count_requires_exact_domain_fields() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let prop = signed_emergency_safe_mode_proposal_for_test(
            "audit-vote-domain-exact-govp-00000000000000000000000000000012",
            &sk_a,
            1,
            2,
        );
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Emergency, &sk_a);

        gov.apply_block_governance_with_effects(
            1,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );

        let proposal = gov
            .proposals
            .get_mut("audit-vote-domain-exact-govp-00000000000000000000000000000012")
            .expect("pending proposal");
        assert_eq!(proposal.status, ProposalStatus::Pending);
        let first_record = proposal
            .vote_records_v1
            .values_mut()
            .next()
            .expect("audit vote record");
        first_record.signature_domain = format!(" {} ", GOVERNANCE_SIGNATURE_DOMAIN_V2);

        gov.apply_block_governance_with_effects(2, &[]);

        let proposal = gov
            .proposals
            .get("audit-vote-domain-exact-govp-00000000000000000000000000000012")
            .expect("proposal after apply attempt");
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert!(
            !gov.safe_mode.active,
            "domain-normalized vote record must not apply"
        );
    }
}

#[cfg(test)]
mod governance_params_preview_public_helper_tests_v1 {
    use super::*;

    #[test]
    fn preview_governance_params_delta_matches_nft_policy_validation_v1() {
        let mut current = GovernanceParams::default();
        current.nft_enabled = false;
        current.nft_activation_height = u64::MAX;

        let bad = GovernanceParamsDelta {
            nft_enabled: Some(true),
            nft_activation_height: Some(10),
            nft_metadata_hash_required: Some(false),
            nft_max_collections_per_owner: Some(1),
            nft_max_tokens_per_collection: Some(1),
            nft_max_tokens_per_owner: Some(1),
            ..GovernanceParamsDelta::default()
        };
        let err = preview_governance_params_delta_v1(&current, &bad).unwrap_err();
        assert!(err.contains("nft_metadata_hash_required"));

        let good = GovernanceParamsDelta {
            nft_enabled: Some(true),
            nft_activation_height: Some(10),
            nft_metadata_hash_required: Some(true),
            nft_max_collections_per_owner: Some(1),
            nft_max_tokens_per_collection: Some(1),
            nft_max_tokens_per_owner: Some(1),
            ..GovernanceParamsDelta::default()
        };
        let staged = preview_governance_params_delta_v1(&current, &good).unwrap();
        assert!(staged.nft_enabled);
        assert_eq!(staged.nft_activation_height, 10);
    }
}

#[cfg(test)]
mod operator_role_model_v2_transition_tests {
    use super::tests::{mk_bootstrap, pk_b64, sign_b64, signed_vote_for_test, sk_from_byte};
    use super::*;
    use ed25519_dalek::SigningKey;

    fn validator(pk: &str) -> ValidatorEntry {
        ValidatorEntry {
            pub_key: pk.to_string(),
            alias: None,
            weight: 1,
        }
    }

    fn install_three_validator_set(
        gov: &mut GovernanceState,
        sk_a: &SigningKey,
        sk_b: &SigningKey,
        sk_c: &SigningKey,
    ) -> (String, String, String, String, String) {
        let a_hex = keyfmt::pk_hex_from_any(&pk_b64(sk_a)).unwrap();
        let b_b64 = pk_b64(sk_b);
        let c_b64 = pk_b64(sk_c);
        let b_hex = keyfmt::pk_hex_from_any(&b_b64).unwrap();
        let c_hex = keyfmt::pk_hex_from_any(&c_b64).unwrap();
        gov.validator_set.entries = vec![
            ValidatorEntry {
                pub_key: a_hex.clone(),
                alias: Some("A".to_string()),
                weight: 1,
            },
            ValidatorEntry {
                pub_key: b_hex.clone(),
                alias: Some("B".to_string()),
                weight: 1,
            },
            ValidatorEntry {
                pub_key: c_hex.clone(),
                alias: Some("C".to_string()),
                weight: 1,
            },
        ];
        gov.validator_set.version = 7;
        (a_hex, b_b64, b_hex, c_b64, c_hex)
    }

    fn signed_transition_request_proposal(
        id: &str,
        proposer_sk: &SigningKey,
        validator_pub_key: &str,
        operator_wallet_pubkey: &str,
        created_at_height: u64,
        effective_height: u64,
        requested_at_height: Option<u64>,
    ) -> TxGovernanceProposal {
        let payload = ValidatorComputeTransitionRequestPayload {
            validator_pub_key: validator_pub_key.to_string(),
            operator_wallet_pubkey: operator_wallet_pubkey.to_string(),
            requested_compute_only: true,
            requested_at_height,
            reason: Some("operator-role-v2-test".to_string()),
        };
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::RequestValidatorComputeTransition,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height,
            effective_height,
            proposer: pk_b64(proposer_sk),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Emergency).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    fn signed_transition_cancel_proposal(
        id: &str,
        proposer_sk: &SigningKey,
        validator_pub_key: &str,
        operator_wallet_pubkey: &str,
        created_at_height: u64,
        effective_height: u64,
    ) -> TxGovernanceProposal {
        let payload = CancelValidatorComputeTransitionPayload {
            validator_pub_key: validator_pub_key.to_string(),
            operator_wallet_pubkey: operator_wallet_pubkey.to_string(),
            reason: Some("operator-role-v2-cancel-test".to_string()),
        };
        let mut prop = TxGovernanceProposal {
            id: id.to_string(),
            kind: GovProposalKind::CancelValidatorComputeTransition,
            payload: serde_json::to_vec(&payload).unwrap(),
            created_at_height,
            effective_height,
            proposer: pk_b64(proposer_sk),
            signature_domain: String::new(),
            chain_id: String::new(),
            genesis_hash: String::new(),
            signature: String::new(),
        };
        let msg = proposal_signing_bytes_v1(&prop, &GovernanceCouncilKind::Emergency).unwrap();
        prop.signature = sign_b64(proposer_sk, &msg);
        prop
    }

    fn apply_signed_proposal(
        gov: &mut GovernanceState,
        height: u64,
        prop: TxGovernanceProposal,
        sk_a: &SigningKey,
    ) {
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Emergency, sk_a);
        gov.apply_block_governance_with_effects(
            height,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
        );
    }

    fn apply_signed_proposal_at_finality(
        gov: &mut GovernanceState,
        height: u64,
        finalized_height: u64,
        prop: TxGovernanceProposal,
        sk_a: &SigningKey,
    ) {
        let vote = signed_vote_for_test(&prop, &GovernanceCouncilKind::Emergency, sk_a);
        gov.apply_block_governance_with_effects_at_finality(
            height,
            &[GovernanceTx::Proposal(prop), GovernanceTx::Vote(vote)],
            finalized_height,
        );
    }

    #[test]
    fn validator_compute_transition_denies_when_quorum_would_break() {
        let set = ValidatorSet {
            entries: vec![validator("a"), validator("b")],
            version: 1,
        };
        let policy = ValidatorComputeTransitionQuorumPolicyV1 {
            min_active_validators: 2,
            min_finality_quorum: 2,
            ..Default::default()
        };
        let decision = evaluate_validator_compute_transition_quorum_guard_v1(
            &set,
            &HashMap::new(),
            "a",
            &policy,
            10,
            10,
        );
        assert!(!decision.allowed);
        assert!(decision
            .deny_reasons
            .contains(&"quorum_too_low".to_string()));
        assert!(decision
            .deny_reasons
            .contains(&"finality_quorum_broken".to_string()));
    }

    #[test]
    fn validator_compute_transition_allows_when_remaining_set_is_safe() {
        let set = ValidatorSet {
            entries: vec![validator("a"), validator("b"), validator("c")],
            version: 1,
        };
        let policy = ValidatorComputeTransitionQuorumPolicyV1 {
            min_active_validators: 2,
            min_finality_quorum: 2,
            ..Default::default()
        };
        let decision = evaluate_validator_compute_transition_quorum_guard_v1(
            &set,
            &HashMap::new(),
            "a",
            &policy,
            10,
            10,
        );
        assert!(decision.allowed, "reasons={:?}", decision.deny_reasons);
        assert_eq!(decision.active_validators_after, 2);
    }

    #[test]
    fn validator_compute_transition_denies_when_remaining_quality_is_low() {
        let set = ValidatorSet {
            entries: vec![validator("a"), validator("b"), validator("c")],
            version: 1,
        };
        let mut reps = HashMap::new();
        reps.insert(
            "b".to_string(),
            ValidatorGovReputation {
                misbehavior_points: 100,
                ..Default::default()
            },
        );
        let policy = ValidatorComputeTransitionQuorumPolicyV1 {
            min_active_validators: 2,
            min_finality_quorum: 2,
            validator_quality_floor: 600,
            ..Default::default()
        };
        let decision = evaluate_validator_compute_transition_quorum_guard_v1(
            &set, &reps, "a", &policy, 10, 10,
        );
        assert!(!decision.allowed);
        assert!(decision
            .deny_reasons
            .contains(&"validator_quality_below_floor".to_string()));
    }

    #[test]
    fn validator_compute_transition_denies_when_remaining_recent_missed_slots_exceed_limit() {
        let set = ValidatorSet {
            entries: vec![validator("a"), validator("b"), validator("c")],
            version: 1,
        };
        let mut reps = HashMap::new();
        reps.insert(
            "b".to_string(),
            ValidatorGovReputation {
                downtime_consecutive_missed_turns: 4,
                ..Default::default()
            },
        );
        let policy = ValidatorComputeTransitionQuorumPolicyV1 {
            min_active_validators: 2,
            min_finality_quorum: 2,
            max_recent_missed_slots: 3,
            ..Default::default()
        };
        let decision = evaluate_validator_compute_transition_quorum_guard_v1(
            &set, &reps, "a", &policy, 10, 10,
        );
        assert!(!decision.allowed);
        assert!(decision
            .deny_reasons
            .contains(&"remaining_validator_unhealthy".to_string()));
    }

    #[test]
    fn validator_compute_transition_governance_params_delta_is_governable() {
        let current = GovernanceParams::default();
        let staged = preview_governance_params_delta_v1(
            &current,
            &GovernanceParamsDelta {
                validator_compute_transition_min_active_validators: Some(3),
                validator_compute_transition_min_finality_quorum: Some(3),
                validator_compute_transition_validator_quality_floor: Some(700),
                validator_compute_transition_exit_cooldown_blocks: Some(20),
                validator_compute_transition_max_finality_lag_blocks: Some(4),
                validator_compute_transition_max_recent_missed_slots: Some(2),
                ..GovernanceParamsDelta::default()
            },
        )
        .unwrap();
        assert_eq!(staged.validator_compute_transition_min_active_validators, 3);
        assert_eq!(staged.validator_compute_transition_min_finality_quorum, 3);
        assert_eq!(
            staged.validator_compute_transition_validator_quality_floor,
            700
        );
        assert_eq!(staged.validator_compute_transition_exit_cooldown_blocks, 20);
        assert_eq!(
            staged.validator_compute_transition_max_finality_lag_blocks,
            4
        );
        assert_eq!(
            staged.validator_compute_transition_max_recent_missed_slots,
            2
        );

        let err = preview_governance_params_delta_v1(
            &current,
            &GovernanceParamsDelta {
                validator_compute_transition_validator_quality_floor: Some(1001),
                ..GovernanceParamsDelta::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("validator_compute_transition_validator_quality_floor_gt_1000"));
    }

    #[test]
    fn validator_compute_transition_governance_lifecycle_pending_then_finalized() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(8);
        let sk_c = sk_from_byte(9);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);

        let prop1 = signed_transition_request_proposal(
            "validator-compute-transition-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 20, prop1, &sk_a);

        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
        let pending = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("pending transition record");
        assert_eq!(
            pending.status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );

        let prop2 = signed_transition_request_proposal(
            "validator-compute-transition-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &b_b64,
            31,
            31,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 31, prop2, &sk_a);

        assert!(!gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
        let transition = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("transition record");
        assert_eq!(
            transition.status,
            ValidatorComputeTransitionStatusV1::Finalized
        );
        assert_eq!(transition.requested_at_height, 20);
        assert!(gov
            .validator_ops_log
            .iter()
            .any(|entry| entry.op == ValidatorOpsOp::ValidatorExitForCompute
                && entry.target_pk_hex == b_hex));
    }

    #[test]
    fn validator_compute_transition_cancel_is_allowed_only_while_pending() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(10);
        let sk_c = sk_from_byte(11);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);

        let missing_cancel = signed_transition_cancel_proposal(
            "validator-compute-transition-cancel-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            10,
            10,
        );
        apply_signed_proposal(&mut gov, 10, missing_cancel, &sk_a);
        let rejected = gov
            .proposals
            .get("validator-compute-transition-cancel-govp-00000000000000000000000000000001")
            .expect("missing cancel proposal record");
        assert_eq!(rejected.status, ProposalStatus::Rejected);
        assert!(!gov.validator_compute_transitions.contains_key(&b_hex));

        let request = signed_transition_request_proposal(
            "validator-compute-transition-cancel-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 20, request, &sk_a);
        assert_eq!(
            gov.validator_compute_transitions
                .get(&b_hex)
                .unwrap()
                .status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );

        let cancel = signed_transition_cancel_proposal(
            "validator-compute-transition-cancel-govp-00000000000000000000000000000003",
            &sk_a,
            &b_b64,
            &b_b64,
            21,
            21,
        );
        apply_signed_proposal(&mut gov, 21, cancel, &sk_a);
        let cancelled = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("cancelled transition");
        assert_eq!(
            cancelled.status,
            ValidatorComputeTransitionStatusV1::Cancelled
        );
        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
    }

    #[test]
    fn validator_compute_transition_mismatched_operator_request_preserves_pending_record() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(16);
        let sk_c = sk_from_byte(17);
        let (_a_hex, b_b64, b_hex, c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);

        let request = signed_transition_request_proposal(
            "validator-compute-transition-mismatch-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 20, request, &sk_a);
        let pending_before = gov
            .validator_compute_transitions
            .get(&b_hex)
            .cloned()
            .expect("pending transition");
        assert_eq!(
            pending_before.status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );

        let mismatched_operator_request = signed_transition_request_proposal(
            "validator-compute-transition-mismatch-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &c_b64,
            21,
            21,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 21, mismatched_operator_request, &sk_a);

        let pending_after = gov
            .validator_compute_transitions
            .get(&b_hex)
            .cloned()
            .expect("pending transition preserved");
        assert_eq!(
            pending_after.status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );
        assert_eq!(
            pending_after.operator_wallet_pubkey,
            pending_before.operator_wallet_pubkey
        );
        assert_eq!(
            pending_after.requested_at_height,
            pending_before.requested_at_height
        );
        let rejected = gov
            .proposals
            .get("validator-compute-transition-mismatch-govp-00000000000000000000000000000002")
            .expect("mismatched proposal record");
        assert_eq!(rejected.status, ProposalStatus::Rejected);
    }

    #[test]
    fn validator_compute_transition_early_finalization_denied_with_cooldown_reason_and_keeps_pending(
    ) {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(18);
        let sk_c = sk_from_byte(19);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);
        gov.params.validator_compute_transition_exit_cooldown_blocks = 10;

        let request = signed_transition_request_proposal(
            "validator-compute-transition-cooldown-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal_at_finality(&mut gov, 20, 20, request, &sk_a);
        assert_eq!(
            gov.validator_compute_transitions
                .get(&b_hex)
                .unwrap()
                .status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );

        let early_finalize = signed_transition_request_proposal(
            "validator-compute-transition-cooldown-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &b_b64,
            25,
            25,
            Some(20),
        );
        apply_signed_proposal_at_finality(&mut gov, 25, 25, early_finalize, &sk_a);

        let transition = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("pending transition");
        assert_eq!(
            transition.status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );
        assert!(transition
            .deny_reasons
            .contains(&"cooldown_not_elapsed".to_string()));
        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
        let rejected = gov
            .proposals
            .get("validator-compute-transition-cooldown-govp-00000000000000000000000000000002")
            .expect("early finalization proposal record");
        assert_eq!(rejected.status, ProposalStatus::Rejected);
    }

    #[test]
    fn validator_compute_transition_backdated_payload_cannot_bypass_cooldown_same_block() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(20);
        let sk_c = sk_from_byte(21);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);
        gov.params.validator_compute_transition_exit_cooldown_blocks = 10;

        let request = signed_transition_request_proposal(
            "validator-compute-transition-backdate-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(0),
        );
        let finalize_same_block = signed_transition_request_proposal(
            "validator-compute-transition-backdate-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(0),
        );
        let vote_1 = signed_vote_for_test(&request, &GovernanceCouncilKind::Emergency, &sk_a);
        let vote_2 = signed_vote_for_test(
            &finalize_same_block,
            &GovernanceCouncilKind::Emergency,
            &sk_a,
        );
        gov.apply_block_governance_with_effects_at_finality(
            20,
            &[
                GovernanceTx::Proposal(request),
                GovernanceTx::Vote(vote_1),
                GovernanceTx::Proposal(finalize_same_block),
                GovernanceTx::Vote(vote_2),
            ],
            20,
        );

        let transition = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("pending transition");
        assert_eq!(
            transition.status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );
        assert_eq!(
            transition.requested_at_height, 20,
            "cooldown must start at canonical block height, not payload backdate"
        );
        assert!(transition
            .deny_reasons
            .contains(&"cooldown_not_elapsed".to_string()));
        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
        let rejected = gov
            .proposals
            .get("validator-compute-transition-backdate-govp-00000000000000000000000000000002")
            .expect("same-block backdated finalization proposal record");
        assert_eq!(rejected.status, ProposalStatus::Rejected);
    }

    #[test]
    fn validator_compute_transition_finalization_denied_if_finality_lag_worsens_during_cooldown() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(12);
        let sk_c = sk_from_byte(13);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);
        gov.params.validator_compute_transition_exit_cooldown_blocks = 10;
        gov.params
            .validator_compute_transition_max_finality_lag_blocks = 2;

        let request = signed_transition_request_proposal(
            "validator-compute-transition-finality-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal_at_finality(&mut gov, 20, 20, request, &sk_a);
        assert_eq!(
            gov.validator_compute_transitions
                .get(&b_hex)
                .unwrap()
                .status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );

        let finalize = signed_transition_request_proposal(
            "validator-compute-transition-finality-govp-00000000000000000000000000000002",
            &sk_a,
            &b_b64,
            &b_b64,
            31,
            31,
            Some(20),
        );
        apply_signed_proposal_at_finality(&mut gov, 31, 20, finalize, &sk_a);

        let transition = gov
            .validator_compute_transitions
            .get(&b_hex)
            .expect("denied transition");
        assert_eq!(
            transition.status,
            ValidatorComputeTransitionStatusV1::Denied
        );
        assert!(transition
            .deny_reasons
            .contains(&"finality_lag_too_high".to_string()));
        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));
    }

    #[test]
    fn validator_compute_transition_exit_pending_does_not_bypass_penalty_accounting() {
        let (mut gov, sk_a) = mk_bootstrap(0);
        let sk_b = sk_from_byte(14);
        let sk_c = sk_from_byte(15);
        let (_a_hex, b_b64, b_hex, _c_b64, _c_hex) =
            install_three_validator_set(&mut gov, &sk_a, &sk_b, &sk_c);

        let request = signed_transition_request_proposal(
            "validator-compute-transition-penalty-govp-00000000000000000000000000000001",
            &sk_a,
            &b_b64,
            &b_b64,
            20,
            20,
            Some(20),
        );
        apply_signed_proposal(&mut gov, 20, request, &sk_a);
        assert_eq!(
            gov.validator_compute_transitions
                .get(&b_hex)
                .unwrap()
                .status,
            ValidatorComputeTransitionStatusV1::ExitPending
        );
        assert!(gov.validator_set.entries.iter().any(|v| v.pub_key == b_hex));

        let rep = gov.validator_reputation.entry(b_hex.clone()).or_default();
        rep.downtime_missed_turns_total = rep.downtime_missed_turns_total.saturating_add(1);
        rep.downtime_consecutive_missed_turns =
            rep.downtime_consecutive_missed_turns.saturating_add(1);
        rep.misbehavior_points = rep.misbehavior_points.saturating_add(1);

        let rep_after = gov.validator_reputation.get(&b_hex).unwrap();
        assert_eq!(rep_after.downtime_missed_turns_total, 1);
        assert_eq!(rep_after.downtime_consecutive_missed_turns, 1);
        assert_eq!(rep_after.misbehavior_points, 1);
        assert!(
            validator_quality_score_for_operator_role_model_v2(rep_after, 21) < 1000,
            "pending exit validator must remain penalty/accounting-visible until finalized"
        );
    }
}
