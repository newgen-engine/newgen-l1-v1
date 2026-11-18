// src/reputation_score.rs
// Canonical chain-side reputation scoring surfaces for E2 consumers.
//
// NewGen L1 remains the canonical source of truth. E2 consumes these surfaces;
// it must not recompute canonical reputation locally.

use serde::{Deserialize, Serialize};

pub const REPUTATION_SCORE_SCALE_V1: &str = "0_1000";
pub const REPUTATION_SCORE_MIN_V1: i32 = 0;
pub const REPUTATION_SCORE_MAX_V1: i32 = 1000;

pub const REPUTATION_SURFACE_VERSION_V1: &str = "node-reputation-surface-v1";
pub const NODE_REPUTATION_SCORE_FORMULA_VERSION_V1: &str = "node-reputation-score-formula-v2";
pub const NODE_REPUTATION_POLICY_VERSION_V1: &str = "node-reputation-policy-v2";

pub const WALLET_REPUTATION_SURFACE_VERSION_V1: &str = "wallet-reputation-surface-v1";
pub const WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1: &str = "wallet-reputation-score-formula-v2";
pub const WALLET_REPUTATION_POLICY_VERSION_V1: &str = "wallet-reputation-policy-v2";

pub const WORKER_ELIGIBILITY_SURFACE_VERSION_V1: &str = "canonical-worker-eligibility-v1";
pub const WORKER_ELIGIBILITY_POLICY_VERSION_V1: &str = "worker-eligibility-policy-v2";
pub const OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2: &str = "operator-role-score-projection-v2";

/// Canonical worker eligibility thresholds for policy v2.
///
/// The base non-probe lane is intentionally distinct from elevated compute
/// privileges. A worker that has finalized evidence and reaches ACTIVE_BASE can
/// execute short deterministic base jobs. Cloud Unit base admission is also a
/// governed elevated lane, but it must not require prior real Cloud Unit jobs:
/// that would create an impossible bootstrap loop. Real-job history is reserved
/// for higher-risk lanes such as long-running, GPU and critical workloads.
/// This prevents threshold flapping around 700 from blocking base work without
/// weakening elevated lanes.
pub const WORKER_PROBE_MIN_SCORE_V1: i32 = 600;
pub const WORKER_ACTIVE_BASE_MIN_SCORE_V1: i32 = 650;
pub const WORKER_LOW_RISK_MIN_SCORE_V1: i32 = 700;
pub const WORKER_CLOUD_UNIT_MIN_SCORE_V1: i32 = 850;
pub const WORKER_LONG_RUNNING_MIN_SCORE_V1: i32 = 900;
pub const WORKER_GPU_MIN_SCORE_V1: i32 = 920;
pub const WORKER_CRITICAL_MIN_SCORE_V1: i32 = 950;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReputationScoreFormulaV1 {
    pub format_version: String,
    pub base_score: i32,
    pub success_weight: i32,
    pub timeout_penalty: i32,
    pub failure_penalty: i32,
    pub slash_penalty: i32,
    pub jail_penalty: i32,
    pub missed_turn_penalty: i32,
    pub misbehavior_penalty: i32,
    pub decay_window: u64,
    pub min_score: i32,
    pub max_score: i32,
}

impl NodeReputationScoreFormulaV1 {
    pub fn canonical_v1() -> Self {
        Self {
            format_version: NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            base_score: 600,
            success_weight: 5,
            timeout_penalty: 10,
            failure_penalty: 30,
            slash_penalty: 650,
            jail_penalty: 950,
            missed_turn_penalty: 33,
            misbehavior_penalty: 20,
            decay_window: 10_000,
            min_score: REPUTATION_SCORE_MIN_V1,
            max_score: REPUTATION_SCORE_MAX_V1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletReputationScoreFormulaV1 {
    pub format_version: String,
    pub base_score: i32,
    pub success_weight: i32,
    pub timeout_penalty: i32,
    pub failure_penalty: i32,
    pub slash_penalty: i32,
    pub jail_penalty: i32,
    pub missed_turn_penalty: i32,
    pub misbehavior_penalty: i32,
    pub negative_evidence_penalty: i32,
    pub positive_evidence_cap: i32,
    pub evidence_delta_weight: i32,
    pub decay_window: u64,
    pub min_score: i32,
    pub max_score: i32,
}

impl WalletReputationScoreFormulaV1 {
    pub fn canonical_v1() -> Self {
        Self {
            format_version: WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            base_score: 600,
            success_weight: 4,
            timeout_penalty: 10,
            failure_penalty: 30,
            slash_penalty: 650,
            jail_penalty: 950,
            missed_turn_penalty: 33,
            misbehavior_penalty: 20,
            negative_evidence_penalty: 30,
            positive_evidence_cap: 400,
            evidence_delta_weight: 1,
            decay_window: 10_000,
            min_score: REPUTATION_SCORE_MIN_V1,
            max_score: REPUTATION_SCORE_MAX_V1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReputationScoreInputV1 {
    pub active: bool,
    pub revoked: bool,
    pub jailed: bool,
    pub misbehavior_points: u32,
    pub slashed_count: u32,
    pub consecutive_missed_turns: u64,
    pub last_slash_height: u64,
    pub source_height: u64,
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
    pub last_evidence_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletReputationScoreInputV1 {
    pub revoked: bool,
    pub jailed: bool,
    pub misbehavior_points: u32,
    pub slashed_count: u32,
    pub consecutive_missed_turns: u64,
    pub source_height: u64,
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
    pub last_evidence_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationJobWeightV1 {
    Probe,
    Normal,
    LongRunning,
}

pub fn success_delta_for_score_v1(score: i32, job_weight: ReputationJobWeightV1) -> i32 {
    match score.clamp(REPUTATION_SCORE_MIN_V1, REPUTATION_SCORE_MAX_V1) {
        0..=649 => match job_weight {
            ReputationJobWeightV1::Probe => 2,
            ReputationJobWeightV1::Normal => 5,
            ReputationJobWeightV1::LongRunning => 8,
        },
        650..=799 => match job_weight {
            ReputationJobWeightV1::Probe => 1,
            ReputationJobWeightV1::Normal => 4,
            ReputationJobWeightV1::LongRunning => 6,
        },
        800..=899 => match job_weight {
            ReputationJobWeightV1::Probe => 1,
            ReputationJobWeightV1::Normal => 3,
            ReputationJobWeightV1::LongRunning => 5,
        },
        900..=959 => match job_weight {
            ReputationJobWeightV1::Probe => 0,
            ReputationJobWeightV1::Normal => 2,
            ReputationJobWeightV1::LongRunning => 3,
        },
        960..=1000 => match job_weight {
            ReputationJobWeightV1::Probe => 0,
            ReputationJobWeightV1::Normal => 1,
            ReputationJobWeightV1::LongRunning => 2,
        },
        _ => 0,
    }
}

/// Applies success rewards with diminishing returns near the canonical cap.
/// This is intentionally score-aware: a worker at 970 cannot farm reputation at
/// the same rate as a worker below the active threshold.
pub fn dampened_success_bonus_for_score_v1(
    start_score: i32,
    positive_count: u64,
    job_weight: ReputationJobWeightV1,
) -> i32 {
    let mut score = start_score.clamp(REPUTATION_SCORE_MIN_V1, REPUTATION_SCORE_MAX_V1);
    let mut total: i32 = 0;
    for _ in 0..positive_count.min(10_000) {
        let delta = success_delta_for_score_v1(score, job_weight);
        if delta <= 0 {
            break;
        }
        let next = score
            .saturating_add(delta)
            .clamp(REPUTATION_SCORE_MIN_V1, REPUTATION_SCORE_MAX_V1);
        total = total.saturating_add(next.saturating_sub(score));
        score = next;
        if score >= REPUTATION_SCORE_MAX_V1 {
            break;
        }
    }
    total
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNodeReputationScoreV1 {
    pub reputation_surface_version: String,
    pub score_formula_version: String,
    pub policy_version: String,
    pub effective_score: i32,
    pub eligibility_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub max_risk_class: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWalletReputationScoreV1 {
    pub reputation_surface_version: String,
    pub score_formula_version: String,
    pub policy_version: String,
    pub effective_score: i32,
    pub eligibility_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub max_risk_class: String,
}

fn evidence_score_adjustment(
    current_score: i32,
    _success_weight: i32,
    timeout_penalty: i32,
    failure_penalty: i32,
    positive_cap: i32,
    delta_weight: i32,
    decay_window: u64,
    source_height: u64,
    last_evidence_height: Option<u64>,
    positive_count: u64,
    negative_count: u64,
    delta_total: i64,
    timeout_count: u64,
    failure_count: u64,
) -> i32 {
    let positive_bonus = dampened_success_bonus_for_score_v1(
        current_score,
        positive_count,
        ReputationJobWeightV1::Normal,
    )
    .min(positive_cap.max(0));
    let negative_penalty = (negative_count as i32)
        .saturating_mul(timeout_penalty.max(1) / 2)
        .min(300);
    let timeout_penalty_total = (timeout_count as i32)
        .saturating_mul(timeout_penalty)
        .min(250);
    let failure_penalty_total = (failure_count as i32)
        .saturating_mul(failure_penalty)
        .min(500);
    // Positive SUCCESS deltas are intentionally not counted here: success growth is
    // governed only by dampened_success_bonus_for_score_v1. Delta totals contribute
    // punitive/corrective evidence only, which prevents SUCCESS from being counted twice.
    let punitive_delta_total = delta_total.min(0);
    let delta_component = (punitive_delta_total as i32)
        .saturating_mul(delta_weight)
        .clamp(-150, 0);

    let raw = positive_bonus
        .saturating_add(delta_component)
        .saturating_sub(negative_penalty)
        .saturating_sub(timeout_penalty_total)
        .saturating_sub(failure_penalty_total);

    if raw == 0 || decay_window == 0 {
        return raw;
    }

    let Some(last_evidence_height) = last_evidence_height else {
        return raw;
    };
    let age = source_height.saturating_sub(last_evidence_height);
    if age >= decay_window {
        return 0;
    }
    let remaining = decay_window.saturating_sub(age) as i64;
    ((raw as i64).saturating_mul(remaining) / (decay_window as i64)) as i32
}

pub fn compute_canonical_node_reputation_score_v1(
    input: &NodeReputationScoreInputV1,
) -> CanonicalNodeReputationScoreV1 {
    let formula = NodeReputationScoreFormulaV1::canonical_v1();

    let mut hard_deny: Option<&'static str> = None;
    if input.revoked {
        hard_deny = Some("REVOKED");
    } else if input.jailed {
        hard_deny = Some("JAILED");
    } else if !input.active {
        hard_deny = Some("NOT_ACTIVE");
    }

    let mut score = formula.base_score;
    score += evidence_score_adjustment(
        score,
        formula.success_weight,
        formula.timeout_penalty,
        formula.failure_penalty,
        400,
        1,
        formula.decay_window,
        input.source_height,
        input.last_evidence_height,
        input.accepted_positive_run_evidence_count,
        input.accepted_negative_run_evidence_count,
        input.accepted_run_evidence_delta_total,
        input.timeout_count,
        input.failure_count,
    );
    score -= (input.misbehavior_points as i32)
        .saturating_mul(formula.misbehavior_penalty)
        .min(400);
    score -= (input.slashed_count as i32)
        .saturating_mul(formula.slash_penalty)
        .min(950);
    score -= (input.consecutive_missed_turns as i32)
        .saturating_mul(formula.missed_turn_penalty)
        .min(500);
    if hard_deny == Some("JAILED") {
        score -= formula.jail_penalty;
    }
    if hard_deny == Some("REVOKED") {
        score = 0;
    }
    score = score.clamp(formula.min_score, formula.max_score);

    let (eligibility_state, deny_reason, max_risk_class) = classify_score_v1(
        hard_deny,
        score,
        input.slashed_count,
        input.timeout_count,
        input.failure_count,
    );

    CanonicalNodeReputationScoreV1 {
        reputation_surface_version: REPUTATION_SURFACE_VERSION_V1.to_string(),
        score_formula_version: NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
        policy_version: NODE_REPUTATION_POLICY_VERSION_V1.to_string(),
        effective_score: score,
        eligibility_state: eligibility_state.to_string(),
        deny_reason,
        max_risk_class: max_risk_class.to_string(),
    }
}

pub fn compute_canonical_wallet_reputation_score_v1(
    input: &WalletReputationScoreInputV1,
) -> CanonicalWalletReputationScoreV1 {
    let formula = WalletReputationScoreFormulaV1::canonical_v1();

    let mut hard_deny: Option<&'static str> = None;
    if input.revoked {
        hard_deny = Some("REVOKED");
    } else if input.jailed {
        hard_deny = Some("JAILED");
    }

    let mut score = formula.base_score;
    score += evidence_score_adjustment(
        score,
        formula.success_weight,
        formula.timeout_penalty,
        formula.failure_penalty,
        formula.positive_evidence_cap,
        formula.evidence_delta_weight,
        formula.decay_window,
        input.source_height,
        input.last_evidence_height,
        input.accepted_positive_run_evidence_count,
        input.accepted_negative_run_evidence_count,
        input.accepted_run_evidence_delta_total,
        input.timeout_count,
        input.failure_count,
    );
    score -= (input.accepted_negative_run_evidence_count as i32)
        .saturating_mul(formula.negative_evidence_penalty)
        .min(300);
    score -= (input.misbehavior_points as i32)
        .saturating_mul(formula.misbehavior_penalty)
        .min(400);
    score -= (input.slashed_count as i32)
        .saturating_mul(formula.slash_penalty)
        .min(950);
    score -= (input.consecutive_missed_turns as i32)
        .saturating_mul(formula.missed_turn_penalty)
        .min(500);
    if hard_deny == Some("JAILED") {
        score -= formula.jail_penalty;
    }
    if hard_deny == Some("REVOKED") {
        score = 0;
    }
    score = score.clamp(formula.min_score, formula.max_score);

    let (eligibility_state, deny_reason, max_risk_class) = classify_score_v1(
        hard_deny,
        score,
        input.slashed_count,
        input.timeout_count,
        input.failure_count,
    );

    CanonicalWalletReputationScoreV1 {
        reputation_surface_version: WALLET_REPUTATION_SURFACE_VERSION_V1.to_string(),
        score_formula_version: WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
        policy_version: WALLET_REPUTATION_POLICY_VERSION_V1.to_string(),
        effective_score: score,
        eligibility_state: eligibility_state.to_string(),
        deny_reason,
        max_risk_class: max_risk_class.to_string(),
    }
}

pub fn canonical_risk_class_for_score_v1(score: i32) -> &'static str {
    if score >= 950 {
        "CRITICAL"
    } else if score >= 920 {
        "HIGH"
    } else if score >= 850 {
        "STANDARD"
    } else if score >= 700 {
        "LOW"
    } else {
        "NONE"
    }
}

fn classify_score_v1(
    hard_deny: Option<&'static str>,
    score: i32,
    slashed_count: u32,
    timeout_count: u64,
    failure_count: u64,
) -> (&'static str, Option<String>, &'static str) {
    if let Some(reason) = hard_deny {
        ("INELIGIBLE", Some(reason.to_string()), "NONE")
    } else if slashed_count > 0 || score < 400 {
        (
            "PROBATION",
            Some("RECENT_OR_ACCUMULATED_SLASH".to_string()),
            "NONE",
        )
    } else if failure_count >= 3 {
        (
            "INELIGIBLE",
            Some("RECENT_WORKER_FAILURE_PATTERN".to_string()),
            "NONE",
        )
    } else if failure_count >= 2 {
        (
            "PROBATION",
            Some("RECENT_WORKER_FAILURE_PATTERN".to_string()),
            "NONE",
        )
    } else if timeout_count >= 3 {
        (
            "PROBATION",
            Some("CONSECUTIVE_TIMEOUT_PATTERN".to_string()),
            "NONE",
        )
    } else if score < 650 {
        (
            "PROBATION",
            Some("SCORE_BELOW_ACTIVE_THRESHOLD".to_string()),
            "NONE",
        )
    } else {
        ("ELIGIBLE", None, canonical_risk_class_for_score_v1(score))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNodeReputationSurfaceV1 {
    pub reputation_surface_version: String,
    pub score_formula_version: String,
    pub policy_version: String,
    pub node_pubkey: String,
    pub source_height: u64,
    pub validator_set_member: bool,
    pub active: bool,
    pub revoked: bool,
    pub jailed: bool,
    pub misbehavior_points: u32,
    pub slashed_count: u32,
    pub last_slash_height: u64,
    pub consecutive_missed_turns: u64,
    pub last_seen_height: u64,
    pub last_produced_height: u64,
    pub accepted_positive_run_evidence_count: u64,
    pub accepted_negative_run_evidence_count: u64,
    pub accepted_run_evidence_delta_total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_evidence_height: Option<u64>,
    pub effective_score: i32,
    pub eligibility_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub max_risk_class: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWalletReputationSurfaceV1 {
    pub reputation_surface_version: String,
    pub score_formula_version: String,
    pub policy_version: String,
    pub wallet_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    pub source_height: u64,
    pub validator_set_member: bool,
    pub revoked: bool,
    pub jailed: bool,
    pub misbehavior_points: u32,
    pub slashed_count: u32,
    pub consecutive_missed_turns: u64,
    pub last_seen_height: u64,
    pub last_produced_height: u64,
    pub accepted_positive_run_evidence_count: u64,
    pub accepted_negative_run_evidence_count: u64,
    pub accepted_run_evidence_delta_total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_evidence_height: Option<u64>,
    pub effective_score: i32,
    pub eligibility_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub max_risk_class: String,
}

pub fn canonical_node_reputation_surface_v1(
    node_pubkey: String,
    validator_set_member: bool,
    last_seen_height: u64,
    last_produced_height: u64,
    input: NodeReputationScoreInputV1,
) -> CanonicalNodeReputationSurfaceV1 {
    let score = compute_canonical_node_reputation_score_v1(&input);
    CanonicalNodeReputationSurfaceV1 {
        reputation_surface_version: score.reputation_surface_version,
        score_formula_version: score.score_formula_version,
        policy_version: score.policy_version,
        node_pubkey,
        source_height: input.source_height,
        validator_set_member,
        active: input.active,
        revoked: input.revoked,
        jailed: input.jailed,
        misbehavior_points: input.misbehavior_points,
        slashed_count: input.slashed_count,
        last_slash_height: input.last_slash_height,
        consecutive_missed_turns: input.consecutive_missed_turns,
        last_seen_height,
        last_produced_height,
        accepted_positive_run_evidence_count: input.accepted_positive_run_evidence_count,
        accepted_negative_run_evidence_count: input.accepted_negative_run_evidence_count,
        accepted_run_evidence_delta_total: input.accepted_run_evidence_delta_total,
        last_evidence_height: input.last_evidence_height,
        effective_score: score.effective_score,
        eligibility_state: score.eligibility_state,
        deny_reason: score.deny_reason,
        max_risk_class: score.max_risk_class,
    }
}

pub fn canonical_wallet_reputation_surface_v1(
    wallet_pubkey: String,
    validator_pubkey: Option<String>,
    validator_set_member: bool,
    last_seen_height: u64,
    last_produced_height: u64,
    input: WalletReputationScoreInputV1,
) -> CanonicalWalletReputationSurfaceV1 {
    let score = compute_canonical_wallet_reputation_score_v1(&input);
    CanonicalWalletReputationSurfaceV1 {
        reputation_surface_version: score.reputation_surface_version,
        score_formula_version: score.score_formula_version,
        policy_version: score.policy_version,
        wallet_pubkey,
        validator_pubkey,
        source_height: input.source_height,
        validator_set_member,
        revoked: input.revoked,
        jailed: input.jailed,
        misbehavior_points: input.misbehavior_points,
        slashed_count: input.slashed_count,
        consecutive_missed_turns: input.consecutive_missed_turns,
        last_seen_height,
        last_produced_height,
        accepted_positive_run_evidence_count: input.accepted_positive_run_evidence_count,
        accepted_negative_run_evidence_count: input.accepted_negative_run_evidence_count,
        accepted_run_evidence_delta_total: input.accepted_run_evidence_delta_total,
        last_evidence_height: input.last_evidence_height,
        effective_score: score.effective_score,
        eligibility_state: score.eligibility_state,
        deny_reason: score.deny_reason,
        max_risk_class: score.max_risk_class,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationBridgeContractMetadataV1 {
    pub canonical_worker_eligibility_v1: bool,
    pub reputation_score_scale: String,
    pub reputation_score_max: i32,
    pub worker_penalty_taxonomy: String,
    pub node_reputation_score_formula_version: String,
    pub wallet_reputation_score_formula_version: String,
    pub worker_eligibility_policy_version: String,
}

pub fn reputation_bridge_contract_metadata_v1() -> ReputationBridgeContractMetadataV1 {
    ReputationBridgeContractMetadataV1 {
        canonical_worker_eligibility_v1: true,
        reputation_score_scale: REPUTATION_SCORE_SCALE_V1.to_string(),
        reputation_score_max: REPUTATION_SCORE_MAX_V1,
        worker_penalty_taxonomy: crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1
            .to_string(),
        node_reputation_score_formula_version: NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
        wallet_reputation_score_formula_version: WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1
            .to_string(),
        worker_eligibility_policy_version: WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEligibilityPolicyV1 {
    pub policy_version: String,
    pub minimum_successful_probe_jobs: u64,
    /// Minimum successful base real jobs required before any elevated lane can be considered.
    /// Kept for backwards-compatible policy readers; exact lane gates below are authoritative.
    pub minimum_successful_real_jobs: u64,
    /// Retained as a policy/public contract field for Cloud Unit *upgrade* or
    /// operational-limit logic. It must not gate the first governed Cloud Unit
    /// unlock, because a worker cannot build Cloud Unit real-job history before
    /// the governed Cloud Unit lane is opened.
    pub cloud_unit_min_successful_real_jobs: u64,
    pub long_running_min_successful_real_jobs: u64,
    pub gpu_min_successful_real_jobs: u64,
    /// Minimum GPU-specific benchmark/execution evidence for GPU lane.
    pub gpu_min_successful_gpu_evidence_jobs: u64,
    pub critical_workload_min_successful_real_jobs: u64,
    /// Critical lane requires an explicit governance review marker, represented by
    /// the critical grant proposal/payload hash link in the canonical surface.
    pub critical_workload_requires_explicit_review_marker: bool,
    pub minimum_observation_window: u64,
    pub minimum_uptime_window: u64,
    pub minimum_evidence_count: u64,
    /// Minimum score for the base real-work lane.
    ///
    /// This is intentionally lower than Cloud Unit/GPU/Critical thresholds:
    /// base non-probe work is a canonical L1 eligibility state, while elevated
    /// capabilities remain explicit governed privileges.
    pub base_non_probe_min_score: i32,
    pub cloud_unit_min_score: i32,
    pub long_running_min_score: i32,
    pub gpu_min_score: i32,
    pub critical_workload_min_score: i32,
}

impl WorkerEligibilityPolicyV1 {
    pub fn canonical_v1() -> Self {
        Self {
            policy_version: WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
            minimum_successful_probe_jobs: 1,
            minimum_successful_real_jobs: 1,
            cloud_unit_min_successful_real_jobs: 3,
            long_running_min_successful_real_jobs: 5,
            gpu_min_successful_real_jobs: 5,
            gpu_min_successful_gpu_evidence_jobs: 1,
            critical_workload_min_successful_real_jobs: 10,
            critical_workload_requires_explicit_review_marker: true,
            minimum_observation_window: 10,
            minimum_uptime_window: 10,
            minimum_evidence_count: 2,
            base_non_probe_min_score: WORKER_ACTIVE_BASE_MIN_SCORE_V1,
            cloud_unit_min_score: WORKER_CLOUD_UNIT_MIN_SCORE_V1,
            long_running_min_score: WORKER_LONG_RUNNING_MIN_SCORE_V1,
            gpu_min_score: WORKER_GPU_MIN_SCORE_V1,
            critical_workload_min_score: WORKER_CRITICAL_MIN_SCORE_V1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerGovernedGrantLinksV1 {
    #[serde(default)]
    pub cloud_unit_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_payload_hash: Option<String>,
    #[serde(default)]
    pub gpu_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_payload_hash: Option<String>,
    #[serde(default)]
    pub critical_workload_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_payload_hash: Option<String>,
}

impl WorkerGovernedGrantLinksV1 {
    pub fn from_legacy_booleans_v1(
        _cloud_unit_allowed: bool,
        _gpu_allowed: bool,
        _critical_workload_allowed: bool,
    ) -> Self {
        // Legacy boolean-only callers cannot provide governance proposal/payload links.
        // Keep the wrapper fail-closed for elevated lanes; production callsites must use
        // compute_canonical_worker_eligibility_with_grant_links_v1.
        Self::default()
    }
}

fn default_worker_registration_source_unknown_v1() -> String {
    "UNKNOWN".to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWorkerEligibilityV1 {
    pub format_version: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    pub source_height: u64,
    pub finalized_height: u64,
    pub source_commitment: String,
    #[serde(default = "default_worker_registration_source_unknown_v1")]
    pub registration_source: String,
    #[serde(default)]
    pub chain_known: bool,
    #[serde(default)]
    pub eligible_for_probe: bool,
    #[serde(default)]
    pub eligible_for_non_probe: bool,
    pub wallet_reputation_score: i32,
    pub node_reliability_score: i32,
    pub effective_score: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_score_projection_version: Option<String>,
    #[serde(default)]
    pub operator_reputation: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_score: Option<i32>,
    #[serde(default)]
    pub compute_score: i32,
    #[serde(default)]
    pub cloud_unit_score: i32,
    #[serde(default)]
    pub gpu_score: i32,
    #[serde(default)]
    pub critical_score: i32,
    pub eligibility_state: String,
    pub tier: String,
    pub max_risk_class: String,
    pub cloud_unit_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_unit_grant_payload_hash: Option<String>,
    pub long_running_allowed: bool,
    pub gpu_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_grant_payload_hash: Option<String>,
    pub critical_workload_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_grant_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_workload_review_payload_hash: Option<String>,
    pub max_parallel_jobs: u32,
    pub max_job_duration_sec: u64,
    pub successful_probe_jobs: u64,
    pub successful_real_jobs: u64,
    #[serde(default)]
    pub successful_cloud_unit_jobs: u64,
    #[serde(default)]
    pub successful_gpu_evidence_jobs: u64,
    #[serde(default)]
    pub successful_critical_workload_jobs: u64,
    pub total_evidence_count: u64,
    pub observation_window: u64,
    pub uptime_window: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_recovery_action: Option<String>,
    pub policy_version: String,
}

fn worker_eligibility_hex64_present_v1(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .is_some()
}

fn worker_eligibility_non_empty_ref_present_v1(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .is_some()
}

fn worker_eligibility_validate_governed_grant_link_v1(
    lane: &str,
    allowed: bool,
    proposal_id: &Option<String>,
    payload_hash: &Option<String>,
) -> Result<(), String> {
    if allowed {
        if !worker_eligibility_non_empty_ref_present_v1(proposal_id) {
            return Err(format!(
                "worker_eligibility_{}_grant_proposal_id_missing",
                lane
            ));
        }
        if !worker_eligibility_hex64_present_v1(payload_hash) {
            return Err(format!(
                "worker_eligibility_{}_grant_payload_hash_invalid",
                lane
            ));
        }
    } else if proposal_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_some()
        || payload_hash
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some()
    {
        return Err(format!(
            "worker_eligibility_{}_grant_link_present_without_lane",
            lane
        ));
    }
    Ok(())
}

impl CanonicalWorkerEligibilityV1 {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.format_version.trim() != WORKER_ELIGIBILITY_SURFACE_VERSION_V1 {
            return Err("worker_eligibility_bad_format_version".to_string());
        }
        if self.policy_version.trim() != WORKER_ELIGIBILITY_POLICY_VERSION_V1 {
            return Err("worker_eligibility_bad_policy_version".to_string());
        }
        if !self
            .source_commitment
            .trim()
            .eq_ignore_ascii_case("finalized")
        {
            return Err("worker_eligibility_source_commitment_not_finalized".to_string());
        }
        if self.source_height > self.finalized_height {
            return Err("worker_eligibility_source_height_gt_finalized_height".to_string());
        }
        match self.registration_source.trim() {
            "SELF_REGISTERED" | "GOVERNANCE_BIND" | "GOVERNANCE_PRIVILEGED" | "UNKNOWN" => {}
            _ => return Err("worker_eligibility_bad_registration_source".to_string()),
        }
        if !self.chain_known && (self.eligible_for_probe || self.eligible_for_non_probe) {
            return Err("worker_eligibility_unknown_chain_with_allowed_lane".to_string());
        }
        if self.worker_node_pubkey.trim().is_empty()
            || self.operator_wallet_pubkey.trim().is_empty()
        {
            return Err("worker_eligibility_principal_missing".to_string());
        }
        if self
            .worker_node_pubkey
            .trim()
            .eq_ignore_ascii_case(self.operator_wallet_pubkey.trim())
        {
            return Err("worker_eligibility_worker_operator_not_distinct".to_string());
        }
        if !(REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1)
            .contains(&self.wallet_reputation_score)
            || !(REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1)
                .contains(&self.node_reliability_score)
            || !(REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&self.effective_score)
        {
            return Err("worker_eligibility_score_out_of_range".to_string());
        }
        if self.effective_score
            != self
                .wallet_reputation_score
                .min(self.node_reliability_score)
        {
            return Err("worker_eligibility_effective_score_mismatch".to_string());
        }

        if self.role_score_projection_version.as_deref()
            != Some(OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2)
        {
            return Err("worker_eligibility_missing_role_score_projection_version".to_string());
        }
        let role_scores_in_range = (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1)
            .contains(&self.operator_reputation)
            && (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&self.compute_score)
            && (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&self.cloud_unit_score)
            && (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&self.gpu_score)
            && (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&self.critical_score)
            && self
                .validator_score
                .map(|score| (REPUTATION_SCORE_MIN_V1..=REPUTATION_SCORE_MAX_V1).contains(&score))
                .unwrap_or(true);
        if !role_scores_in_range {
            return Err("worker_eligibility_role_score_out_of_range".to_string());
        }
        if self.operator_reputation != self.wallet_reputation_score {
            return Err("worker_eligibility_operator_reputation_mismatch".to_string());
        }
        if self.compute_score != self.node_reliability_score {
            return Err("worker_eligibility_compute_score_mismatch".to_string());
        }
        let expected_cloud_unit_score = if self.cloud_unit_allowed {
            self.effective_score
        } else {
            0
        };
        let expected_gpu_score = if self.gpu_allowed {
            self.effective_score
        } else {
            0
        };
        let expected_critical_score = if self.critical_workload_allowed {
            self.effective_score
        } else {
            0
        };
        if self.cloud_unit_score != expected_cloud_unit_score {
            return Err("worker_eligibility_cloud_unit_score_mismatch".to_string());
        }
        if self.gpu_score != expected_gpu_score {
            return Err("worker_eligibility_gpu_score_mismatch".to_string());
        }
        if self.critical_score != expected_critical_score {
            return Err("worker_eligibility_critical_score_mismatch".to_string());
        }

        let eligibility_state = self.eligibility_state.trim();
        let max_risk_class = self.max_risk_class.trim();
        match eligibility_state {
            "ACTIVE" | "PROBATION" | "INELIGIBLE" => {}
            _ => return Err("worker_eligibility_bad_state".to_string()),
        }
        match max_risk_class {
            "NONE" | "LOW" | "STANDARD" | "HIGH" | "CRITICAL" => {}
            _ => return Err("worker_eligibility_bad_risk_class".to_string()),
        }
        if self.tier.trim() != eligibility_state {
            return Err("worker_eligibility_tier_state_mismatch".to_string());
        }
        if self.eligible_for_probe && !matches!(eligibility_state, "ACTIVE" | "PROBATION") {
            return Err("worker_eligibility_probe_lane_bad_state".to_string());
        }
        if matches!(eligibility_state, "ACTIVE" | "PROBATION") && !self.eligible_for_probe {
            return Err("worker_eligibility_probe_lane_missing".to_string());
        }
        if self.eligible_for_non_probe && eligibility_state != "ACTIVE" {
            return Err("worker_eligibility_non_probe_bad_state".to_string());
        }
        if eligibility_state == "ACTIVE" && !self.eligible_for_non_probe {
            return Err("worker_eligibility_active_without_non_probe_lane".to_string());
        }
        if self.cloud_unit_allowed && eligibility_state != "ACTIVE" {
            return Err("worker_eligibility_cloud_allowed_but_not_active".to_string());
        }
        if self.long_running_allowed && eligibility_state != "ACTIVE" {
            return Err("worker_eligibility_long_running_allowed_but_not_active".to_string());
        }
        if self.gpu_allowed && eligibility_state != "ACTIVE" {
            return Err("worker_eligibility_gpu_allowed_but_not_active".to_string());
        }
        if self.critical_workload_allowed && eligibility_state != "ACTIVE" {
            return Err("worker_eligibility_critical_allowed_but_not_active".to_string());
        }
        if self.eligible_for_non_probe && self.effective_score < WORKER_ACTIVE_BASE_MIN_SCORE_V1 {
            return Err("worker_eligibility_non_probe_score_below_threshold".to_string());
        }
        if self.cloud_unit_allowed && self.effective_score < WORKER_CLOUD_UNIT_MIN_SCORE_V1 {
            return Err("worker_eligibility_cloud_score_below_threshold".to_string());
        }
        if self.long_running_allowed && !self.cloud_unit_allowed {
            return Err("worker_eligibility_long_running_without_cloud_unit".to_string());
        }
        if self.long_running_allowed && self.effective_score < WORKER_LONG_RUNNING_MIN_SCORE_V1 {
            return Err("worker_eligibility_long_running_score_below_threshold".to_string());
        }
        if self.gpu_allowed && self.effective_score < WORKER_GPU_MIN_SCORE_V1 {
            return Err("worker_eligibility_gpu_score_below_threshold".to_string());
        }
        if self.critical_workload_allowed && self.effective_score < WORKER_CRITICAL_MIN_SCORE_V1 {
            return Err("worker_eligibility_critical_score_below_threshold".to_string());
        }
        let policy = WorkerEligibilityPolicyV1::canonical_v1();
        // Cloud Unit base admission is intentionally governed by explicit L1
        // grant + ACTIVE/non-probe eligibility + Cloud Unit score, not by prior
        // Cloud Unit real-job history. Requiring successful_real_jobs here would
        // create a catch-22 for the first Cloud Unit unlock. Higher-risk lanes
        // below still require real-job history.
        if self.long_running_allowed
            && self.successful_real_jobs < policy.long_running_min_successful_real_jobs
        {
            return Err("worker_eligibility_long_running_real_history_below_threshold".to_string());
        }
        if self.gpu_allowed && self.successful_real_jobs < policy.gpu_min_successful_real_jobs {
            return Err("worker_eligibility_gpu_real_history_below_threshold".to_string());
        }
        if self.gpu_allowed
            && self.successful_gpu_evidence_jobs < policy.gpu_min_successful_gpu_evidence_jobs
        {
            return Err("worker_eligibility_gpu_specific_evidence_below_threshold".to_string());
        }
        if self.critical_workload_allowed
            && self.successful_real_jobs < policy.critical_workload_min_successful_real_jobs
        {
            return Err("worker_eligibility_critical_real_history_below_threshold".to_string());
        }
        worker_eligibility_validate_governed_grant_link_v1(
            "cloud_unit",
            self.cloud_unit_allowed,
            &self.cloud_unit_grant_proposal_id,
            &self.cloud_unit_grant_payload_hash,
        )?;
        worker_eligibility_validate_governed_grant_link_v1(
            "gpu",
            self.gpu_allowed,
            &self.gpu_grant_proposal_id,
            &self.gpu_grant_payload_hash,
        )?;
        worker_eligibility_validate_governed_grant_link_v1(
            "critical",
            self.critical_workload_allowed,
            &self.critical_workload_grant_proposal_id,
            &self.critical_workload_grant_payload_hash,
        )?;
        if policy.critical_workload_requires_explicit_review_marker {
            worker_eligibility_validate_governed_grant_link_v1(
                "critical_review",
                self.critical_workload_allowed,
                &self.critical_workload_review_proposal_id,
                &self.critical_workload_review_payload_hash,
            )?;
        }
        if eligibility_state == "ACTIVE" {
            if self.deny_reason.is_some() || self.next_recovery_action.is_some() {
                return Err("worker_eligibility_allowed_with_deny_reason".to_string());
            }
            if self.max_parallel_jobs == 0 || self.max_job_duration_sec == 0 {
                return Err("worker_eligibility_allowed_with_zero_limits".to_string());
            }
            if max_risk_class == "NONE" {
                return Err("worker_eligibility_allowed_with_none_risk".to_string());
            }
        } else {
            if self.max_parallel_jobs != 0 || self.max_job_duration_sec != 0 {
                return Err("worker_eligibility_denied_with_nonzero_limits".to_string());
            }
            if max_risk_class != "NONE" {
                return Err("worker_eligibility_denied_with_non_none_risk".to_string());
            }
            if self.deny_reason.as_deref().unwrap_or("").trim().is_empty() {
                return Err("worker_eligibility_denied_without_reason".to_string());
            }
        }
        Ok(())
    }
}

fn canonical_worker_observation_window_v1(
    source_height: u64,
    first_evidence_height: Option<u64>,
    last_evidence_height: Option<u64>,
) -> u64 {
    let Some(first) = first_evidence_height else {
        return 0;
    };

    // The observation window is a finalized-chain age check, not a spacing check
    // between evidence transactions. Batched evidence can legitimately finalize in
    // the same block; requiring `last - first` would deadlock probation workers
    // until another probe happens to be created. Use the canonical source view as
    // the clock, while still failing closed on malformed evidence ranges that are
    // outside that source view.
    if let Some(last) = last_evidence_height {
        if last < first || last > source_height {
            return 0;
        }
    }

    source_height.saturating_sub(first)
}

fn canonical_worker_uptime_window_v1(
    source_height: u64,
    first_evidence_height: Option<u64>,
    last_evidence_height: Option<u64>,
) -> u64 {
    let Some(first) = first_evidence_height else {
        return 0;
    };

    // E2 worker liveness at lease time is enforced by the E2 runtime heartbeat
    // and local scheduler. L1 canonical eligibility cannot observe continuous
    // off-chain uptime between evidence submissions. Therefore the canonical
    // uptime window for E2 eligibility is the finalized age of accepted evidence,
    // with the same malformed-range fail-closed checks used by the observation
    // window. This prevents same-block evidence batches from creating a permanent
    // minimum_uptime_window_not_met deadlock while preserving L1 fail-closed
    // behavior for future or inverted evidence heights.
    if let Some(last) = last_evidence_height {
        if last < first || last > source_height {
            return 0;
        }
    }

    source_height.saturating_sub(first)
}

fn worker_next_recovery_action_v1(reason: &str) -> &'static str {
    match reason {
        "reputation_view_not_finalized" => "wait_for_l1_finality",
        "worker_operator_binding_missing" => "submit_worker_operator_binding_governance_record",
        "minimum_successful_probe_jobs_not_met" => "run_probe_jobs",
        "minimum_observation_window_not_met" => "wait_for_observation_window",
        "minimum_uptime_window_not_met" => "maintain_runtime_uptime",
        "minimum_evidence_count_not_met" => "collect_more_evidence",
        "worker_node_reputation_missing" => "register_worker_node_reputation",
        "operator_wallet_reputation_missing" => "register_operator_wallet_reputation",
        "SCORE_BELOW_ACTIVE_THRESHOLD" => "collect_more_evidence",
        "base_non_probe_score_below_threshold" => "collect_more_evidence",
        _ => "manual_governance_review",
    }
}

fn component_score_onboarding_probation_v1(
    eligibility_state: &str,
    deny_reason: Option<&str>,
    max_risk_class: &str,
) -> bool {
    eligibility_state.trim() == "PROBATION"
        && deny_reason.map(str::trim) == Some("SCORE_BELOW_ACTIVE_THRESHOLD")
        && max_risk_class.trim() == "NONE"
}

pub fn compute_canonical_worker_eligibility_with_grant_links_v1(
    worker_node_pubkey: String,
    operator_wallet_pubkey: String,
    finalized_height: u64,
    binding_finalized: bool,
    node: Option<&CanonicalNodeReputationSurfaceV1>,
    wallet: Option<&CanonicalWalletReputationSurfaceV1>,
    successful_probe_jobs: u64,
    successful_real_jobs: u64,
    successful_cloud_unit_jobs: u64,
    successful_gpu_evidence_jobs: u64,
    successful_critical_workload_jobs: u64,
    total_evidence_count: u64,
    failed_recovery_probe_count: u64,
    first_evidence_height: Option<u64>,
    last_evidence_height: Option<u64>,
    governed_grants: WorkerGovernedGrantLinksV1,
) -> CanonicalWorkerEligibilityV1 {
    let policy = WorkerEligibilityPolicyV1::canonical_v1();
    let source_height = node
        .map(|n| n.source_height)
        .into_iter()
        .chain(wallet.map(|w| w.source_height))
        .max()
        .unwrap_or(finalized_height);
    let node_score = node.map(|n| n.effective_score).unwrap_or(0);
    let wallet_score = wallet.map(|w| w.effective_score).unwrap_or(0);
    let effective_score = node_score.min(wallet_score);
    let observation_window = canonical_worker_observation_window_v1(
        source_height,
        first_evidence_height,
        last_evidence_height,
    );
    let uptime_window = if node.is_some() {
        canonical_worker_uptime_window_v1(
            source_height,
            first_evidence_height,
            last_evidence_height,
        )
    } else {
        0
    };

    let mut deny_reason: Option<String> = None;
    if source_height > finalized_height {
        deny_reason = Some("reputation_view_not_finalized".to_string());
    } else if !binding_finalized {
        deny_reason = Some("worker_operator_binding_missing".to_string());
    } else if node.is_none() {
        deny_reason = Some("worker_node_reputation_missing".to_string());
    } else if wallet.is_none() {
        deny_reason = Some("operator_wallet_reputation_missing".to_string());
    } else if let Some(n) = node {
        if n.node_pubkey != worker_node_pubkey {
            deny_reason = Some("worker_node_surface_mismatch".to_string());
        } else if n.eligibility_state != "ELIGIBLE"
            && !component_score_onboarding_probation_v1(
                &n.eligibility_state,
                n.deny_reason.as_deref(),
                &n.max_risk_class,
            )
        {
            deny_reason = n
                .deny_reason
                .clone()
                .or_else(|| Some(format!("worker_node_not_eligible:{}", n.eligibility_state)));
        }
    }
    if deny_reason.is_none() {
        if let Some(w) = wallet {
            if w.wallet_pubkey != operator_wallet_pubkey {
                deny_reason = Some("operator_wallet_surface_mismatch".to_string());
            } else if w.eligibility_state != "ELIGIBLE"
                && !component_score_onboarding_probation_v1(
                    &w.eligibility_state,
                    w.deny_reason.as_deref(),
                    &w.max_risk_class,
                )
            {
                deny_reason = w.deny_reason.clone().or_else(|| {
                    Some(format!(
                        "operator_wallet_not_eligible:{}",
                        w.eligibility_state
                    ))
                });
            }
        }
    }
    if deny_reason.is_none() && failed_recovery_probe_count > 0 {
        deny_reason = Some("failed_recovery_probe".to_string());
    }
    if deny_reason.is_none() && total_evidence_count < policy.minimum_evidence_count {
        deny_reason = Some("minimum_evidence_count_not_met".to_string());
    }
    if deny_reason.is_none() && successful_probe_jobs < policy.minimum_successful_probe_jobs {
        deny_reason = Some("minimum_successful_probe_jobs_not_met".to_string());
    }
    if deny_reason.is_none() && observation_window < policy.minimum_observation_window {
        deny_reason = Some("minimum_observation_window_not_met".to_string());
    }
    if deny_reason.is_none() && uptime_window < policy.minimum_uptime_window {
        deny_reason = Some("minimum_uptime_window_not_met".to_string());
    }
    if deny_reason.is_none() && effective_score < policy.base_non_probe_min_score {
        deny_reason = Some("base_non_probe_score_below_threshold".to_string());
    }

    let eligible_for_non_probe_base = deny_reason.is_none();
    // Do not gate the first governed Cloud Unit unlock on prior real-job
    // history. The worker must already be ACTIVE/non-probe, have enough score,
    // and carry an explicit governed grant link. Real-job history remains a
    // requirement for long-running/GPU/critical lanes.
    let long_running_history_satisfied =
        successful_real_jobs >= policy.long_running_min_successful_real_jobs;
    let gpu_history_satisfied = successful_real_jobs >= policy.gpu_min_successful_real_jobs
        && successful_gpu_evidence_jobs >= policy.gpu_min_successful_gpu_evidence_jobs;
    let critical_review_marker_satisfied = !policy
        .critical_workload_requires_explicit_review_marker
        || (worker_eligibility_non_empty_ref_present_v1(
            &governed_grants.critical_workload_review_proposal_id,
        ) && worker_eligibility_hex64_present_v1(
            &governed_grants.critical_workload_review_payload_hash,
        ));
    let critical_history_satisfied = successful_real_jobs
        >= policy.critical_workload_min_successful_real_jobs
        && critical_review_marker_satisfied;
    let cloud_unit_allowed = eligible_for_non_probe_base
        && effective_score >= policy.cloud_unit_min_score
        && governed_grants.cloud_unit_allowed;
    let long_running_allowed = cloud_unit_allowed
        && long_running_history_satisfied
        && effective_score >= policy.long_running_min_score;
    let gpu_allowed = eligible_for_non_probe_base
        && gpu_history_satisfied
        && effective_score >= policy.gpu_min_score
        && governed_grants.gpu_allowed;
    let critical_workload_allowed = eligible_for_non_probe_base
        && critical_history_satisfied
        && effective_score >= policy.critical_workload_min_score
        && governed_grants.critical_workload_allowed;
    let hard_ineligible = matches!(
        deny_reason.as_deref(),
        Some(
            "worker_node_reputation_missing"
                | "operator_wallet_reputation_missing"
                | "worker_operator_binding_missing"
                | "failed_recovery_probe"
        )
    );
    let probe_allowed = binding_finalized
        && source_height <= finalized_height
        && effective_score >= WORKER_PROBE_MIN_SCORE_V1
        && !matches!(
            deny_reason.as_deref(),
            Some(
                "worker_operator_binding_missing"
                    | "worker_node_reputation_missing"
                    | "operator_wallet_reputation_missing"
                    | "failed_recovery_probe"
            )
        );
    let max_parallel_jobs = if critical_workload_allowed {
        16
    } else if gpu_allowed {
        8
    } else if cloud_unit_allowed {
        4
    } else if eligible_for_non_probe_base {
        1
    } else {
        0
    };
    let max_job_duration_sec = if critical_workload_allowed {
        86_400
    } else if long_running_allowed {
        21_600
    } else if gpu_allowed {
        7_200
    } else if cloud_unit_allowed {
        3_600
    } else if eligible_for_non_probe_base {
        900
    } else {
        0
    };
    let eligibility_state = if eligible_for_non_probe_base {
        "ACTIVE"
    } else if hard_ineligible {
        "INELIGIBLE"
    } else {
        "PROBATION"
    };
    let tier = eligibility_state;
    let next_recovery_action = deny_reason
        .as_deref()
        .map(worker_next_recovery_action_v1)
        .map(str::to_string);

    CanonicalWorkerEligibilityV1 {
        format_version: WORKER_ELIGIBILITY_SURFACE_VERSION_V1.to_string(),
        worker_node_pubkey,
        operator_wallet_pubkey,
        source_height,
        finalized_height,
        source_commitment: "finalized".to_string(),
        registration_source: default_worker_registration_source_unknown_v1(),
        chain_known: binding_finalized,
        eligible_for_probe: probe_allowed,
        eligible_for_non_probe: eligible_for_non_probe_base,
        wallet_reputation_score: wallet_score,
        node_reliability_score: node_score,
        effective_score,
        role_score_projection_version: Some(OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string()),
        operator_reputation: wallet_score,
        validator_score: None,
        compute_score: node_score,
        cloud_unit_score: if cloud_unit_allowed {
            effective_score
        } else {
            0
        },
        gpu_score: if gpu_allowed { effective_score } else { 0 },
        critical_score: if critical_workload_allowed {
            effective_score
        } else {
            0
        },
        eligibility_state: eligibility_state.to_string(),
        tier: tier.to_string(),
        max_risk_class: if critical_workload_allowed {
            "CRITICAL".to_string()
        } else if gpu_allowed {
            "HIGH".to_string()
        } else if cloud_unit_allowed {
            "STANDARD".to_string()
        } else if eligible_for_non_probe_base {
            "LOW".to_string()
        } else {
            "NONE".to_string()
        },
        cloud_unit_allowed,
        cloud_unit_grant_proposal_id: cloud_unit_allowed
            .then(|| governed_grants.cloud_unit_grant_proposal_id.clone())
            .flatten(),
        cloud_unit_grant_payload_hash: cloud_unit_allowed
            .then(|| governed_grants.cloud_unit_grant_payload_hash.clone())
            .flatten(),
        long_running_allowed,
        gpu_allowed,
        gpu_grant_proposal_id: gpu_allowed
            .then(|| governed_grants.gpu_grant_proposal_id.clone())
            .flatten(),
        gpu_grant_payload_hash: gpu_allowed
            .then(|| governed_grants.gpu_grant_payload_hash.clone())
            .flatten(),
        critical_workload_allowed,
        critical_workload_grant_proposal_id: critical_workload_allowed
            .then(|| governed_grants.critical_workload_grant_proposal_id.clone())
            .flatten(),
        critical_workload_grant_payload_hash: critical_workload_allowed
            .then(|| governed_grants.critical_workload_grant_payload_hash.clone())
            .flatten(),
        critical_workload_review_proposal_id: critical_workload_allowed
            .then(|| governed_grants.critical_workload_review_proposal_id.clone())
            .flatten(),
        critical_workload_review_payload_hash: critical_workload_allowed
            .then(|| {
                governed_grants
                    .critical_workload_review_payload_hash
                    .clone()
            })
            .flatten(),
        max_parallel_jobs,
        max_job_duration_sec,
        successful_probe_jobs,
        successful_real_jobs,
        successful_cloud_unit_jobs,
        successful_gpu_evidence_jobs,
        successful_critical_workload_jobs,
        total_evidence_count,
        observation_window,
        uptime_window,
        deny_reason,
        next_recovery_action,
        policy_version: policy.policy_version,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReputationGoldenVectorV1 {
    pub case_id: String,
    pub input: NodeReputationScoreInputV1,
    pub expected_score: i32,
    pub expected_eligibility_state: String,
    pub expected_max_risk_class: String,
}

fn node_input(
    active: bool,
    revoked: bool,
    jailed: bool,
    misbehavior_points: u32,
    slashed_count: u32,
    consecutive_missed_turns: u64,
    last_slash_height: u64,
    source_height: u64,
) -> NodeReputationScoreInputV1 {
    NodeReputationScoreInputV1 {
        active,
        revoked,
        jailed,
        misbehavior_points,
        slashed_count,
        consecutive_missed_turns,
        last_slash_height,
        source_height,
        accepted_positive_run_evidence_count: 0,
        accepted_negative_run_evidence_count: 0,
        accepted_run_evidence_delta_total: 0,
        timeout_count: 0,
        failure_count: 0,
        last_evidence_height: None,
    }
}

pub fn node_reputation_golden_vectors_v1() -> Vec<NodeReputationGoldenVectorV1> {
    vec![
        NodeReputationGoldenVectorV1 {
            case_id: "case_001_new_worker_baseline".to_string(),
            input: node_input(true, false, false, 0, 0, 0, 0, 100),
            expected_score: 600,
            expected_eligibility_state: "PROBATION".to_string(),
            expected_max_risk_class: "NONE".to_string(),
        },
        NodeReputationGoldenVectorV1 {
            case_id: "case_002_jailed_worker".to_string(),
            input: node_input(false, false, true, 0, 0, 0, 0, 100),
            expected_score: 0,
            expected_eligibility_state: "INELIGIBLE".to_string(),
            expected_max_risk_class: "NONE".to_string(),
        },
        NodeReputationGoldenVectorV1 {
            case_id: "case_003_revoked_worker".to_string(),
            input: node_input(false, true, false, 0, 0, 0, 0, 100),
            expected_score: 0,
            expected_eligibility_state: "INELIGIBLE".to_string(),
            expected_max_risk_class: "NONE".to_string(),
        },
        NodeReputationGoldenVectorV1 {
            case_id: "case_004_many_missed_turns".to_string(),
            input: node_input(true, false, false, 0, 0, 10, 0, 100),
            expected_score: 270,
            expected_eligibility_state: "PROBATION".to_string(),
            expected_max_risk_class: "NONE".to_string(),
        },
        NodeReputationGoldenVectorV1 {
            case_id: "case_005_recent_slash".to_string(),
            input: node_input(true, false, false, 0, 1, 0, 95, 100),
            expected_score: 0,
            expected_eligibility_state: "PROBATION".to_string(),
            expected_max_risk_class: "NONE".to_string(),
        },
    ]
}

pub fn compute_canonical_worker_eligibility_v1(
    worker_node_pubkey: String,
    operator_wallet_pubkey: String,
    finalized_height: u64,
    binding_finalized: bool,
    node: Option<&CanonicalNodeReputationSurfaceV1>,
    wallet: Option<&CanonicalWalletReputationSurfaceV1>,
    successful_probe_jobs: u64,
    successful_real_jobs: u64,
    total_evidence_count: u64,
    failed_recovery_probe_count: u64,
    first_evidence_height: Option<u64>,
    last_evidence_height: Option<u64>,
    governed_cloud_unit_granted: bool,
    governed_gpu_granted: bool,
    governed_critical_workload_granted: bool,
) -> CanonicalWorkerEligibilityV1 {
    compute_canonical_worker_eligibility_with_grant_links_v1(
        worker_node_pubkey,
        operator_wallet_pubkey,
        finalized_height,
        binding_finalized,
        node,
        wallet,
        successful_probe_jobs,
        successful_real_jobs,
        0,
        0,
        0,
        total_evidence_count,
        failed_recovery_probe_count,
        first_evidence_height,
        last_evidence_height,
        WorkerGovernedGrantLinksV1::from_legacy_booleans_v1(
            governed_cloud_unit_granted,
            governed_gpu_granted,
            governed_critical_workload_granted,
        ),
    )
}

#[cfg(test)]
fn high_reputation_worker_components_for_privilege_tests() -> (
    CanonicalNodeReputationSurfaceV1,
    CanonicalWalletReputationSurfaceV1,
) {
    let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
    node_input.accepted_positive_run_evidence_count = 130;
    node_input.last_evidence_height = Some(100);
    let node =
        canonical_node_reputation_surface_v1("worker-hex".to_string(), true, 100, 100, node_input);
    let wallet = canonical_wallet_reputation_surface_v1(
        "operator-hex".to_string(),
        Some("worker-hex".to_string()),
        true,
        100,
        100,
        WalletReputationScoreInputV1 {
            revoked: false,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            consecutive_missed_turns: 0,
            source_height: 100,
            accepted_positive_run_evidence_count: 130,
            accepted_negative_run_evidence_count: 0,
            accepted_run_evidence_delta_total: 0,
            timeout_count: 0,
            failure_count: 0,
            last_evidence_height: Some(100),
        },
    );
    (node, wallet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_reputation_golden_vectors_match_formula_v1() {
        for vector in node_reputation_golden_vectors_v1() {
            let decision = compute_canonical_node_reputation_score_v1(&vector.input);
            assert_eq!(
                decision.effective_score, vector.expected_score,
                "{} score",
                vector.case_id
            );
            assert_eq!(
                decision.eligibility_state, vector.expected_eligibility_state,
                "{} eligibility",
                vector.case_id
            );
            assert_eq!(
                decision.max_risk_class, vector.expected_max_risk_class,
                "{} max risk",
                vector.case_id
            );
            assert_eq!(
                decision.reputation_surface_version,
                REPUTATION_SURFACE_VERSION_V1
            );
            assert_eq!(
                decision.score_formula_version,
                NODE_REPUTATION_SCORE_FORMULA_VERSION_V1
            );
            assert_eq!(decision.policy_version, NODE_REPUTATION_POLICY_VERSION_V1);
        }
    }

    #[test]
    fn evidence_terms_are_effective_not_decorative() {
        let mut input = node_input(true, false, false, 0, 0, 0, 0, 100);
        input.accepted_positive_run_evidence_count = 3;
        let positive = compute_canonical_node_reputation_score_v1(&input).effective_score;
        input.accepted_positive_run_evidence_count = 0;
        input.timeout_count = 1;
        let timeout = compute_canonical_node_reputation_score_v1(&input).effective_score;
        assert!(positive > timeout);
    }

    #[test]
    fn wallet_canonical_score_is_chain_side_and_risk_bounded() {
        let input = WalletReputationScoreInputV1 {
            revoked: false,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            consecutive_missed_turns: 0,
            source_height: 100,
            accepted_positive_run_evidence_count: 0,
            accepted_negative_run_evidence_count: 4,
            accepted_run_evidence_delta_total: -4,
            timeout_count: 0,
            failure_count: 0,
            last_evidence_height: Some(100),
        };
        let score = compute_canonical_wallet_reputation_score_v1(&input);
        assert_eq!(
            score.reputation_surface_version,
            WALLET_REPUTATION_SURFACE_VERSION_V1
        );
        assert!(score.effective_score < 950);
    }

    #[test]
    fn node_surface_is_flat_versioned_and_contains_decision_fields() {
        let input = node_input(true, false, false, 0, 0, 0, 0, 42);
        let surface =
            canonical_node_reputation_surface_v1("node-hex".to_string(), true, 41, 40, input);
        assert_eq!(
            surface.reputation_surface_version,
            REPUTATION_SURFACE_VERSION_V1
        );
        assert_eq!(
            surface.score_formula_version,
            NODE_REPUTATION_SCORE_FORMULA_VERSION_V1
        );
        assert_eq!(surface.policy_version, NODE_REPUTATION_POLICY_VERSION_V1);
        assert_eq!(surface.node_pubkey, "node-hex");
        assert_eq!(surface.source_height, 42);
        assert_eq!(surface.effective_score, 600);
        assert_eq!(surface.eligibility_state, "PROBATION");
        assert_eq!(surface.max_risk_class, "NONE");
    }

    #[test]
    fn wallet_surface_is_flat_versioned_and_fail_closed_on_revoked() {
        let input = WalletReputationScoreInputV1 {
            revoked: true,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            consecutive_missed_turns: 0,
            source_height: 43,
            accepted_positive_run_evidence_count: 0,
            accepted_negative_run_evidence_count: 0,
            accepted_run_evidence_delta_total: 0,
            timeout_count: 0,
            failure_count: 0,
            last_evidence_height: None,
        };
        let surface = canonical_wallet_reputation_surface_v1(
            "wallet-hex".to_string(),
            Some("validator-hex".to_string()),
            true,
            41,
            40,
            input,
        );
        assert_eq!(
            surface.reputation_surface_version,
            WALLET_REPUTATION_SURFACE_VERSION_V1
        );
        assert_eq!(
            surface.score_formula_version,
            WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1
        );
        assert_eq!(surface.policy_version, WALLET_REPUTATION_POLICY_VERSION_V1);
        assert_eq!(surface.effective_score, 0);
        assert_eq!(surface.eligibility_state, "INELIGIBLE");
        assert_eq!(surface.deny_reason.as_deref(), Some("REVOKED"));
    }

    #[test]
    fn worker_eligibility_requires_history_before_cloud_unit() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 70;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            0,
            0,
            0,
            0,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(!eligibility.cloud_unit_allowed);
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("minimum_evidence_count_not_met")
        );
        assert_eq!(eligibility.tier, "PROBATION");
    }

    #[test]
    fn worker_eligibility_probation_is_probe_only_without_real_work_limits() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 1;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 1,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            1,
            0,
            Some(100),
            Some(100),
            false,
            false,
            false,
        );
        assert_eq!(eligibility.eligibility_state, "PROBATION");
        assert!(eligibility.eligible_for_probe);
        assert!(!eligibility.eligible_for_non_probe);
        assert_eq!(eligibility.max_risk_class, "NONE");
        assert_eq!(eligibility.max_parallel_jobs, 0);
        assert_eq!(eligibility.max_job_duration_sec, 0);
        assert!(!eligibility.cloud_unit_allowed);
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("minimum_evidence_count_not_met")
        );
        eligibility
            .validate_contract_v1()
            .expect("probation worker eligibility must remain probe-only and contract-valid");
    }

    #[test]
    fn worker_eligibility_contract_rejects_probation_without_probe_lane() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 1;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 1,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let mut eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            1,
            0,
            Some(100),
            Some(100),
            false,
            false,
            false,
        );
        eligibility.eligible_for_probe = false;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(err, "worker_eligibility_probe_lane_missing");
    }

    #[test]
    fn worker_eligibility_contract_rejects_active_without_probe_lane() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let mut eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            71,
            0,
            Some(80),
            Some(100),
            false,
            false,
            false,
        );
        eligibility.eligible_for_probe = false;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(err, "worker_eligibility_probe_lane_missing");
    }

    #[test]
    fn worker_eligibility_keeps_hard_component_probation_probe_only() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 70;
        node_input.timeout_count = 3;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            1,
            0,
            Some(100),
            Some(100),
            false,
            false,
            false,
        );
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("CONSECUTIVE_TIMEOUT_PATTERN")
        );
        assert_eq!(eligibility.max_risk_class, "NONE");
        assert_eq!(eligibility.max_parallel_jobs, 0);
        assert_eq!(eligibility.max_job_duration_sec, 0);
        eligibility
            .validate_contract_v1()
            .expect("component timeout probation must remain contract-valid probe-only");
    }

    #[test]
    fn worker_eligibility_does_not_open_probation_lane_for_unfinalized_view() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 101);
        node_input.accepted_positive_run_evidence_count = 1;
        node_input.last_evidence_height = Some(101);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            101,
            101,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            101,
            101,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 101,
                accepted_positive_run_evidence_count: 1,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(101),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            1,
            0,
            Some(101),
            Some(101),
            false,
            false,
            false,
        );
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("reputation_view_not_finalized")
        );
        assert_eq!(eligibility.max_risk_class, "NONE");
        assert_eq!(eligibility.max_parallel_jobs, 0);
        assert_eq!(eligibility.max_job_duration_sec, 0);
    }

    #[test]
    fn worker_eligibility_rejects_any_component_newer_than_finality() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 101);
        node_input.accepted_positive_run_evidence_count = 2;
        node_input.last_evidence_height = Some(101);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            101,
            101,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            1,
            71,
            0,
            Some(80),
            Some(100),
            false,
            false,
            false,
        );
        assert!(!eligibility.cloud_unit_allowed);
        assert_eq!(eligibility.source_height, 101);
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("reputation_view_not_finalized")
        );
        assert_eq!(
            eligibility.next_recovery_action.as_deref(),
            Some("wait_for_l1_finality")
        );
    }

    #[test]
    fn worker_eligibility_does_not_require_validator_set_membership_for_e2_worker() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 70;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            false,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            false,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let mut eligibility = compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            70,
            3,
            1,
            1,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
                cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
                ..WorkerGovernedGrantLinksV1::default()
            },
        );
        attach_governed_grant_metadata_for_test(&mut eligibility);
        assert_ne!(
            eligibility.deny_reason.as_deref(),
            Some("worker_not_in_finalized_validator_set")
        );
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.cloud_unit_allowed);
        eligibility
            .validate_contract_v1()
            .expect("non-validator E2 worker eligibility surface must be contract-valid");
    }

    #[test]
    fn worker_eligibility_active_after_finalized_history_and_binding() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 70;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let mut eligibility = compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            70,
            3,
            1,
            1,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
                cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
                ..WorkerGovernedGrantLinksV1::default()
            },
        );
        attach_governed_grant_metadata_for_test(&mut eligibility);
        assert!(eligibility.cloud_unit_allowed);
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert_eq!(eligibility.max_risk_class, "STANDARD");
    }

    #[test]
    fn worker_eligibility_observation_window_uses_finalized_source_age_for_batched_evidence_v1() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 8515);
        node_input.accepted_positive_run_evidence_count = 87;
        node_input.last_evidence_height = Some(8429);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            8429,
            0,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            8429,
            0,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 8515,
                accepted_positive_run_evidence_count: 87,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(8429),
            },
        );

        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            8515,
            true,
            Some(&node),
            Some(&wallet),
            87,
            0,
            87,
            0,
            Some(8429),
            Some(8429),
            false,
            false,
            false,
        );

        assert_eq!(eligibility.observation_window, 86);
        assert_eq!(eligibility.uptime_window, 86);
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.eligible_for_non_probe);
        assert_eq!(eligibility.deny_reason.as_deref(), None);
        assert_ne!(
            eligibility.deny_reason.as_deref(),
            Some("minimum_observation_window_not_met")
        );
        eligibility
            .validate_contract_v1()
            .expect("batched finalized evidence must not permanently deadlock worker promotion");
    }

    #[test]
    fn worker_eligibility_observation_window_fails_closed_for_future_evidence_height_v1() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 8430);
        node_input.accepted_positive_run_evidence_count = 87;
        node_input.last_evidence_height = Some(8515);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            8430,
            8430,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            8430,
            8430,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 8430,
                accepted_positive_run_evidence_count: 87,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(8515),
            },
        );

        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            8430,
            true,
            Some(&node),
            Some(&wallet),
            87,
            0,
            87,
            0,
            Some(8429),
            Some(8515),
            false,
            false,
            false,
        );

        assert_eq!(eligibility.observation_window, 0);
        assert!(!eligibility.eligible_for_non_probe);
        assert_eq!(eligibility.eligibility_state, "PROBATION");
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("minimum_observation_window_not_met")
        );
        eligibility
            .validate_contract_v1()
            .expect("future evidence height must remain fail-closed and contract-valid");
    }

    fn high_reputation_worker_components_for_privilege_tests() -> (
        CanonicalNodeReputationSurfaceV1,
        CanonicalWalletReputationSurfaceV1,
    ) {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 130;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 130,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        (node, wallet)
    }

    fn compute_high_reputation_worker_with_governed_privileges(
        cloud_granted: bool,
        gpu_granted: bool,
        critical_granted: bool,
    ) -> CanonicalWorkerEligibilityV1 {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            70,
            3,
            1,
            1,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: cloud_granted,
                cloud_unit_grant_proposal_id: cloud_granted
                    .then(|| "cloud-proposal-test".to_string()),
                cloud_unit_grant_payload_hash: cloud_granted.then(|| "aa".repeat(32)),
                gpu_allowed: gpu_granted,
                gpu_grant_proposal_id: gpu_granted.then(|| "gpu-proposal-test".to_string()),
                gpu_grant_payload_hash: gpu_granted.then(|| "bb".repeat(32)),
                critical_workload_allowed: critical_granted,
                critical_workload_grant_proposal_id: critical_granted
                    .then(|| "critical-proposal-test".to_string()),
                critical_workload_grant_payload_hash: critical_granted.then(|| "cc".repeat(32)),
                critical_workload_review_proposal_id: critical_granted
                    .then(|| "critical-review-proposal-test".to_string()),
                critical_workload_review_payload_hash: critical_granted.then(|| "dd".repeat(32)),
            },
        )
    }

    fn attach_governed_grant_metadata_for_test(eligibility: &mut CanonicalWorkerEligibilityV1) {
        if eligibility.cloud_unit_allowed {
            eligibility.cloud_unit_grant_proposal_id = Some("cloud-proposal-test".to_string());
            eligibility.cloud_unit_grant_payload_hash = Some("aa".repeat(32));
        }
        if eligibility.gpu_allowed {
            eligibility.gpu_grant_proposal_id = Some("gpu-proposal-test".to_string());
            eligibility.gpu_grant_payload_hash = Some("bb".repeat(32));
        }
        if eligibility.critical_workload_allowed {
            eligibility.critical_workload_grant_proposal_id =
                Some("critical-proposal-test".to_string());
            eligibility.critical_workload_grant_payload_hash = Some("cc".repeat(32));
            eligibility.critical_workload_review_proposal_id =
                Some("critical-review-proposal-test".to_string());
            eligibility.critical_workload_review_payload_hash = Some("dd".repeat(32));
        }
    }

    #[test]
    fn worker_eligibility_base_real_work_does_not_require_cloud_grant_or_real_job_history() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            71,
            0,
            Some(80),
            Some(100),
            false,
            false,
            false,
        );
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.eligible_for_non_probe);
        assert!(!eligibility.cloud_unit_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        assert_eq!(eligibility.max_risk_class, "LOW");
        assert_eq!(eligibility.max_parallel_jobs, 1);
        assert_eq!(eligibility.max_job_duration_sec, 900);
        assert!(eligibility.deny_reason.is_none());
        assert!(eligibility.next_recovery_action.is_none());
        eligibility
            .validate_contract_v1()
            .expect("base real-work eligibility without concilium grant or prior real job must be contract-valid");
    }

    #[test]
    fn worker_eligibility_cloud_unit_grant_bootstraps_without_prior_real_jobs_v1() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let eligibility = compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            0,
            0,
            0,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
                cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
                ..WorkerGovernedGrantLinksV1::default()
            },
        );

        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.eligible_for_non_probe);
        assert!(eligibility.cloud_unit_allowed);
        assert!(!eligibility.long_running_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        assert_eq!(eligibility.max_risk_class, "STANDARD");
        assert_eq!(eligibility.max_parallel_jobs, 4);
        assert_eq!(eligibility.max_job_duration_sec, 3_600);
        assert_eq!(eligibility.successful_real_jobs, 0);
        assert_eq!(
            eligibility.cloud_unit_grant_proposal_id.as_deref(),
            Some("cloud-proposal-test")
        );
        assert_eq!(
            eligibility.cloud_unit_grant_payload_hash.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        eligibility.validate_contract_v1().expect(
            "governed Cloud Unit base grant must bootstrap without prior Cloud Unit real jobs",
        );
    }

    #[test]
    fn worker_eligibility_active_base_accepts_650_score_without_elevated_grants_v1() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 10;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 10,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );

        assert_eq!(node.effective_score, WORKER_ACTIVE_BASE_MIN_SCORE_V1);
        assert_eq!(wallet.effective_score, WORKER_ACTIVE_BASE_MIN_SCORE_V1);

        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            10,
            0,
            Some(80),
            Some(100),
            false,
            false,
            false,
        );

        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.eligible_for_non_probe);
        assert_eq!(eligibility.max_risk_class, "LOW");
        assert_eq!(eligibility.max_parallel_jobs, 1);
        assert_eq!(eligibility.max_job_duration_sec, 900);
        assert!(!eligibility.cloud_unit_allowed);
        assert!(!eligibility.long_running_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        assert!(eligibility.deny_reason.is_none());
        eligibility
            .validate_contract_v1()
            .expect("active-base worker at 650 must be contract-valid for base non-probe lane");
    }

    #[test]
    fn worker_eligibility_rejects_non_probe_below_active_base_650_v1() {
        let mut eligibility = CanonicalWorkerEligibilityV1 {
            format_version: WORKER_ELIGIBILITY_SURFACE_VERSION_V1.to_string(),
            worker_node_pubkey: "worker-hex".to_string(),
            operator_wallet_pubkey: "operator-hex".to_string(),
            source_height: 100,
            finalized_height: 100,
            source_commitment: "finalized".to_string(),
            registration_source: "GOVERNANCE_BIND".to_string(),
            chain_known: true,
            eligible_for_probe: true,
            eligible_for_non_probe: true,
            wallet_reputation_score: WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1,
            node_reliability_score: WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1,
            effective_score: WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1,
            role_score_projection_version: Some(
                OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string(),
            ),
            operator_reputation: WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1,
            validator_score: None,
            compute_score: WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1,
            cloud_unit_score: 0,
            gpu_score: 0,
            critical_score: 0,
            eligibility_state: "ACTIVE".to_string(),
            tier: "ACTIVE".to_string(),
            max_risk_class: "LOW".to_string(),
            cloud_unit_allowed: false,
            cloud_unit_grant_proposal_id: None,
            cloud_unit_grant_payload_hash: None,
            long_running_allowed: false,
            gpu_allowed: false,
            gpu_grant_proposal_id: None,
            gpu_grant_payload_hash: None,
            critical_workload_allowed: false,
            critical_workload_grant_proposal_id: None,
            critical_workload_grant_payload_hash: None,
            critical_workload_review_proposal_id: None,
            critical_workload_review_payload_hash: None,
            max_parallel_jobs: 1,
            max_job_duration_sec: 900,
            successful_probe_jobs: 1,
            successful_real_jobs: 0,
            successful_cloud_unit_jobs: 0,
            successful_gpu_evidence_jobs: 0,
            successful_critical_workload_jobs: 0,
            total_evidence_count: 2,
            observation_window: 10,
            uptime_window: 10,
            deny_reason: None,
            next_recovery_action: None,
            policy_version: WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
        };

        assert_eq!(
            eligibility.validate_contract_v1().unwrap_err(),
            "worker_eligibility_non_probe_score_below_threshold"
        );
        eligibility.eligible_for_non_probe = false;
        eligibility.eligibility_state = "PROBATION".to_string();
        eligibility.tier = "PROBATION".to_string();
        eligibility.max_risk_class = "NONE".to_string();
        eligibility.max_parallel_jobs = 0;
        eligibility.max_job_duration_sec = 0;
        eligibility.deny_reason = Some("base_non_probe_score_below_threshold".to_string());
        eligibility.next_recovery_action = Some("collect_more_evidence".to_string());
        eligibility
            .validate_contract_v1()
            .expect("below active-base must remain valid only as probe/probation");
    }

    #[test]
    fn worker_eligibility_elevated_privileges_require_real_job_history() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            71,
            0,
            Some(80),
            Some(100),
            true,
            true,
            true,
        );
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.eligible_for_non_probe);
        assert!(!eligibility.cloud_unit_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        assert_eq!(eligibility.max_risk_class, "LOW");
        eligibility
            .validate_contract_v1()
            .expect("active base lane without elevated history must remain contract-valid");
    }

    #[test]
    fn worker_eligibility_cloud_grant_does_not_imply_gpu_or_critical() {
        let eligibility =
            compute_high_reputation_worker_with_governed_privileges(true, false, false);
        assert_eq!(eligibility.eligibility_state, "ACTIVE");
        assert!(eligibility.cloud_unit_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        assert_eq!(eligibility.max_risk_class, "STANDARD");
        assert_eq!(eligibility.max_parallel_jobs, 4);
        eligibility
            .validate_contract_v1()
            .expect("cloud-only concilium grant must be contract-valid");
    }

    #[test]
    fn worker_eligibility_gpu_and_critical_require_matching_governed_grants() {
        let gpu = compute_high_reputation_worker_with_governed_privileges(false, true, false);
        assert!(!gpu.cloud_unit_allowed);
        assert!(gpu.gpu_allowed);
        assert!(!gpu.critical_workload_allowed);
        assert_eq!(gpu.max_risk_class, "HIGH");
        assert_eq!(gpu.max_parallel_jobs, 8);
        gpu.validate_contract_v1()
            .expect("gpu concilium grant must be contract-valid without implicit cloud grant");

        let critical = compute_high_reputation_worker_with_governed_privileges(false, false, true);
        assert!(!critical.cloud_unit_allowed);
        assert!(!critical.gpu_allowed);
        assert!(critical.critical_workload_allowed);
        assert_eq!(critical.max_risk_class, "CRITICAL");
        assert_eq!(critical.max_parallel_jobs, 16);
        critical.validate_contract_v1().expect(
            "critical concilium grant must be contract-valid without implicit gpu/cloud grants",
        );
    }

    #[test]
    fn score_scale_contract_is_0_1000_v1() {
        assert_eq!(REPUTATION_SCORE_SCALE_V1, "0_1000");
        assert_eq!(REPUTATION_SCORE_MAX_V1, 1000);
        assert_eq!(NodeReputationScoreFormulaV1::canonical_v1().max_score, 1000);
        assert_eq!(NodeReputationScoreFormulaV1::canonical_v1().base_score, 600);
        assert_eq!(
            WalletReputationScoreFormulaV1::canonical_v1().base_score,
            600
        );
        assert_eq!(
            WorkerEligibilityPolicyV1::canonical_v1().base_non_probe_min_score,
            WORKER_ACTIVE_BASE_MIN_SCORE_V1
        );
        assert_eq!(
            WorkerEligibilityPolicyV1::canonical_v1().cloud_unit_min_score,
            850
        );
    }

    #[test]
    fn success_growth_is_dampened_near_cap_v1() {
        assert!(
            success_delta_for_score_v1(500, ReputationJobWeightV1::Normal)
                > success_delta_for_score_v1(970, ReputationJobWeightV1::Normal)
        );
        assert_eq!(
            success_delta_for_score_v1(970, ReputationJobWeightV1::Probe),
            0
        );
    }

    #[test]
    fn timeout_penalizes_more_than_success_rewards_v1() {
        let formula = NodeReputationScoreFormulaV1::canonical_v1();
        assert!(
            formula.timeout_penalty.abs()
                > success_delta_for_score_v1(700, ReputationJobWeightV1::Normal)
        );
        assert!(formula.failure_penalty.abs() > formula.timeout_penalty.abs());
    }

    #[test]
    fn worker_eligibility_rejects_scores_above_1000_v1() {
        let mut eligibility = CanonicalWorkerEligibilityV1 {
            format_version: WORKER_ELIGIBILITY_SURFACE_VERSION_V1.to_string(),
            worker_node_pubkey: "worker".to_string(),
            operator_wallet_pubkey: "operator".to_string(),
            source_height: 1,
            finalized_height: 1,
            source_commitment: "finalized".to_string(),
            registration_source: "GOVERNANCE_BIND".to_string(),
            chain_known: true,
            eligible_for_probe: true,
            eligible_for_non_probe: true,
            wallet_reputation_score: 1001,
            node_reliability_score: 1000,
            effective_score: 1000,
            role_score_projection_version: Some(
                OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string(),
            ),
            operator_reputation: 1001,
            validator_score: None,
            compute_score: 1000,
            cloud_unit_score: 1000,
            gpu_score: 1000,
            critical_score: 1000,
            eligibility_state: "ACTIVE".to_string(),
            tier: "ACTIVE".to_string(),
            max_risk_class: "CRITICAL".to_string(),
            cloud_unit_allowed: true,
            cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
            cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
            long_running_allowed: true,
            gpu_allowed: true,
            gpu_grant_proposal_id: Some("gpu-proposal-test".to_string()),
            gpu_grant_payload_hash: Some("bb".repeat(32)),
            critical_workload_allowed: true,
            critical_workload_grant_proposal_id: Some("critical-proposal-test".to_string()),
            critical_workload_grant_payload_hash: Some("cc".repeat(32)),
            critical_workload_review_proposal_id: Some("critical-review-proposal-test".to_string()),
            critical_workload_review_payload_hash: Some("dd".repeat(32)),
            max_parallel_jobs: 16,
            max_job_duration_sec: 86_400,
            successful_probe_jobs: 1,
            successful_real_jobs: 10,
            successful_cloud_unit_jobs: 3,
            successful_gpu_evidence_jobs: 1,
            successful_critical_workload_jobs: 1,
            total_evidence_count: 12,
            observation_window: 10,
            uptime_window: 10,
            deny_reason: None,
            next_recovery_action: None,
            policy_version: WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
        };
        assert_eq!(
            eligibility.validate_contract_v1().unwrap_err(),
            "worker_eligibility_score_out_of_range"
        );
        eligibility.wallet_reputation_score = 1000;
        eligibility.operator_reputation = 1000;
        assert!(eligibility.validate_contract_v1().is_ok());
    }

    #[test]
    fn success_growth_is_used_by_canonical_score_v1() {
        let mut input = node_input(true, false, false, 0, 0, 0, 0, 100);
        input.accepted_positive_run_evidence_count = 5;
        input.accepted_run_evidence_delta_total = 25;
        input.last_evidence_height = Some(100);
        let score = compute_canonical_node_reputation_score_v1(&input);
        let expected_bonus =
            dampened_success_bonus_for_score_v1(600, 5, ReputationJobWeightV1::Normal);
        assert_eq!(score.effective_score, 600 + expected_bonus);
        assert!(score.effective_score < 600 + 25 + expected_bonus);
    }

    #[test]
    fn consecutive_timeouts_downgrade_active_to_probation_v1() {
        let mut input = node_input(true, false, false, 0, 0, 0, 0, 100);
        input.timeout_count = 3;
        input.last_evidence_height = Some(100);
        let score = compute_canonical_node_reputation_score_v1(&input);
        assert_eq!(score.eligibility_state, "PROBATION");
        assert_eq!(
            score.deny_reason.as_deref(),
            Some("CONSECUTIVE_TIMEOUT_PATTERN")
        );
    }

    #[test]
    fn repeated_worker_failures_downgrade_to_ineligible_v1() {
        let mut input = node_input(true, false, false, 0, 0, 0, 0, 100);
        input.failure_count = 3;
        input.last_evidence_height = Some(100);
        let score = compute_canonical_node_reputation_score_v1(&input);
        assert_eq!(score.eligibility_state, "INELIGIBLE");
        assert_eq!(
            score.deny_reason.as_deref(),
            Some("RECENT_WORKER_FAILURE_PATTERN")
        );
    }

    #[test]
    fn probation_failed_probe_to_ineligible_worker_eligibility_v1() {
        let mut node_input = node_input(true, false, false, 0, 0, 0, 0, 100);
        node_input.accepted_positive_run_evidence_count = 70;
        node_input.last_evidence_height = Some(100);
        let node = canonical_node_reputation_surface_v1(
            "worker-hex".to_string(),
            true,
            100,
            100,
            node_input,
        );
        let wallet = canonical_wallet_reputation_surface_v1(
            "operator-hex".to_string(),
            Some("worker-hex".to_string()),
            true,
            100,
            100,
            WalletReputationScoreInputV1 {
                revoked: false,
                jailed: false,
                misbehavior_points: 0,
                slashed_count: 0,
                consecutive_missed_turns: 0,
                source_height: 100,
                accepted_positive_run_evidence_count: 70,
                accepted_negative_run_evidence_count: 0,
                accepted_run_evidence_delta_total: 0,
                timeout_count: 0,
                failure_count: 0,
                last_evidence_height: Some(100),
            },
        );
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            70,
            70,
            140,
            1,
            Some(80),
            Some(100),
            false,
            false,
            false,
        );
        assert_eq!(eligibility.eligibility_state, "INELIGIBLE");
        assert_eq!(
            eligibility.deny_reason.as_deref(),
            Some("failed_recovery_probe")
        );
    }

    #[test]
    fn new_worker_base_score_is_not_trusted_v1() {
        let input = node_input(true, false, false, 0, 0, 0, 0, 100);
        let score = compute_canonical_node_reputation_score_v1(&input);
        assert_eq!(score.effective_score, 600);
        assert_eq!(score.eligibility_state, "PROBATION");
        assert_eq!(score.max_risk_class, "NONE");
    }

    #[test]
    fn two_successes_do_not_make_worker_critical_v1() {
        let mut input = node_input(true, false, false, 0, 0, 0, 0, 100);
        input.accepted_positive_run_evidence_count = 2;
        input.accepted_run_evidence_delta_total = 10;
        input.last_evidence_height = Some(100);
        let score = compute_canonical_node_reputation_score_v1(&input);
        assert_eq!(score.effective_score, 610);
        assert_ne!(score.max_risk_class, "CRITICAL");
        assert_eq!(score.eligibility_state, "PROBATION");
    }

    #[test]
    fn trusted_requires_sustained_success_history_v1() {
        let mut five = node_input(true, false, false, 0, 0, 0, 0, 100);
        five.accepted_positive_run_evidence_count = 5;
        five.last_evidence_height = Some(100);
        let five_score = compute_canonical_node_reputation_score_v1(&five);
        assert!(five_score.effective_score < 850);

        let mut sustained = node_input(true, false, false, 0, 0, 0, 0, 100);
        sustained.accepted_positive_run_evidence_count = 150;
        sustained.last_evidence_height = Some(100);
        let sustained_score = compute_canonical_node_reputation_score_v1(&sustained);
        assert!(sustained_score.effective_score >= 950);
        assert_eq!(sustained_score.max_risk_class, "CRITICAL");
    }

    #[test]
    fn worker_eligibility_rejects_allowed_cloud_lane_without_grant_metadata_v1() {
        let mut eligibility =
            compute_high_reputation_worker_with_governed_privileges(true, false, false);
        eligibility.cloud_unit_grant_proposal_id = None;
        eligibility.cloud_unit_grant_payload_hash = None;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(
            err,
            "worker_eligibility_cloud_unit_grant_proposal_id_missing"
        );
    }

    #[test]
    fn worker_eligibility_rejects_grant_metadata_when_lane_is_not_allowed_v1() {
        let mut eligibility =
            compute_high_reputation_worker_with_governed_privileges(false, false, false);
        eligibility.cloud_unit_grant_proposal_id = Some("cloud-proposal-test".to_string());
        eligibility.cloud_unit_grant_payload_hash = Some("aa".repeat(32));
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(
            err,
            "worker_eligibility_cloud_unit_grant_link_present_without_lane"
        );
    }

    #[test]
    fn legacy_boolean_grant_wrapper_is_fail_closed_for_elevated_lanes_v1() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let eligibility = compute_canonical_worker_eligibility_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            70,
            71,
            0,
            Some(80),
            Some(100),
            true,
            true,
            true,
        );
        assert!(eligibility.eligible_for_non_probe);
        assert!(!eligibility.cloud_unit_allowed);
        assert!(!eligibility.gpu_allowed);
        assert!(!eligibility.critical_workload_allowed);
        eligibility
            .validate_contract_v1()
            .expect("legacy boolean wrapper must remain contract-valid by denying elevated lanes");
    }

    #[test]
    fn worker_eligibility_with_governed_grant_links_is_self_validating_v1() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let eligibility = compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            70,
            3,
            1,
            1,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
                cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
                gpu_allowed: true,
                gpu_grant_proposal_id: Some("gpu-proposal-test".to_string()),
                gpu_grant_payload_hash: Some("bb".repeat(32)),
                critical_workload_allowed: true,
                critical_workload_grant_proposal_id: Some("critical-proposal-test".to_string()),
                critical_workload_grant_payload_hash: Some("cc".repeat(32)),
                critical_workload_review_proposal_id: Some(
                    "critical-review-proposal-test".to_string(),
                ),
                critical_workload_review_payload_hash: Some("dd".repeat(32)),
            },
        );
        assert!(eligibility.cloud_unit_allowed);
        assert!(eligibility.gpu_allowed);
        assert!(eligibility.critical_workload_allowed);
        eligibility
            .validate_contract_v1()
            .expect("eligibility generated with governed grant links must be self-validating");
    }
}

#[cfg(test)]
mod v34_worker_elevated_history_tests {
    use super::*;

    fn high_score_with_grants_and_history(gpu_specific: u64) -> CanonicalWorkerEligibilityV1 {
        let node = CanonicalNodeReputationSurfaceV1 {
            reputation_surface_version: REPUTATION_SURFACE_VERSION_V1.to_string(),
            score_formula_version: NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            policy_version: NODE_REPUTATION_POLICY_VERSION_V1.to_string(),
            node_pubkey: "worker".to_string(),
            source_height: 100,
            validator_set_member: false,
            active: true,
            revoked: false,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            last_slash_height: 0,
            consecutive_missed_turns: 0,
            last_seen_height: 100,
            last_produced_height: 100,
            accepted_positive_run_evidence_count: 130,
            accepted_negative_run_evidence_count: 0,
            accepted_run_evidence_delta_total: 0,
            last_evidence_height: Some(100),
            effective_score: WORKER_GPU_MIN_SCORE_V1,
            eligibility_state: "ELIGIBLE".to_string(),
            deny_reason: None,
            max_risk_class: "HIGH".to_string(),
        };
        let wallet = CanonicalWalletReputationSurfaceV1 {
            reputation_surface_version: REPUTATION_SURFACE_VERSION_V1.to_string(),
            score_formula_version: WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            policy_version: WALLET_REPUTATION_POLICY_VERSION_V1.to_string(),
            wallet_pubkey: "operator".to_string(),
            validator_pubkey: Some("worker".to_string()),
            source_height: 100,
            validator_set_member: false,
            revoked: false,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            consecutive_missed_turns: 0,
            last_seen_height: 100,
            last_produced_height: 100,
            accepted_positive_run_evidence_count: 130,
            accepted_negative_run_evidence_count: 0,
            accepted_run_evidence_delta_total: 0,
            last_evidence_height: Some(100),
            effective_score: WORKER_GPU_MIN_SCORE_V1,
            eligibility_state: "ELIGIBLE".to_string(),
            deny_reason: None,
            max_risk_class: "HIGH".to_string(),
        };
        compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker".to_string(),
            "operator".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            3,
            10,
            3,
            gpu_specific,
            0,
            12,
            0,
            Some(1),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some("cloud-proposal".to_string()),
                cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
                gpu_allowed: true,
                gpu_grant_proposal_id: Some("gpu-proposal".to_string()),
                gpu_grant_payload_hash: Some("bb".repeat(32)),
                critical_workload_allowed: false,
                critical_workload_grant_proposal_id: None,
                critical_workload_grant_payload_hash: None,
                critical_workload_review_proposal_id: None,
                critical_workload_review_payload_hash: None,
            },
        )
    }

    #[test]
    fn gpu_grant_and_generic_real_history_without_gpu_specific_evidence_is_not_enough_v34() {
        let eligibility = high_score_with_grants_and_history(0);
        assert!(eligibility.cloud_unit_allowed);
        assert!(!eligibility.gpu_allowed);
    }

    #[test]
    fn gpu_grant_plus_gpu_specific_evidence_unlocks_gpu_lane_v34() {
        let eligibility = high_score_with_grants_and_history(1);
        assert!(eligibility.gpu_allowed);
        eligibility.validate_contract_v1().unwrap();
    }

    #[test]
    fn cloud_unit_applied_grant_projects_exact_metadata_without_prior_real_jobs_v68() {
        let (node, wallet) = high_reputation_worker_components_for_privilege_tests();
        let proposal_id = "e2-worker-privilege-govp-test".to_string();
        let payload_hash = "12".repeat(32);
        let eligibility = compute_canonical_worker_eligibility_with_grant_links_v1(
            "worker-hex".to_string(),
            "operator-hex".to_string(),
            100,
            true,
            Some(&node),
            Some(&wallet),
            1,
            0,
            0,
            0,
            0,
            71,
            0,
            Some(80),
            Some(100),
            WorkerGovernedGrantLinksV1 {
                cloud_unit_allowed: true,
                cloud_unit_grant_proposal_id: Some(proposal_id.clone()),
                cloud_unit_grant_payload_hash: Some(payload_hash.clone()),
                ..WorkerGovernedGrantLinksV1::default()
            },
        );

        assert!(eligibility.eligible_for_non_probe);
        assert!(eligibility.cloud_unit_allowed);
        assert_eq!(eligibility.successful_real_jobs, 0);
        assert_eq!(eligibility.cloud_unit_grant_proposal_id, Some(proposal_id));
        assert_eq!(
            eligibility.cloud_unit_grant_payload_hash,
            Some(payload_hash)
        );
        assert!(!eligibility.long_running_allowed);
        eligibility.validate_contract_v1().unwrap();
    }
}

#[cfg(test)]
mod operator_role_score_projection_v2_tests {
    use super::*;

    fn base_role_projection_worker() -> CanonicalWorkerEligibilityV1 {
        CanonicalWorkerEligibilityV1 {
            format_version: WORKER_ELIGIBILITY_SURFACE_VERSION_V1.to_string(),
            worker_node_pubkey: "worker-role-score".to_string(),
            operator_wallet_pubkey: "operator-role-score".to_string(),
            source_height: 10,
            finalized_height: 10,
            source_commitment: "finalized".to_string(),
            registration_source: "GOVERNANCE_BIND".to_string(),
            chain_known: true,
            eligible_for_probe: true,
            eligible_for_non_probe: true,
            wallet_reputation_score: 900,
            node_reliability_score: 880,
            effective_score: 880,
            role_score_projection_version: Some(
                OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string(),
            ),
            operator_reputation: 900,
            validator_score: Some(910),
            compute_score: 880,
            cloud_unit_score: 880,
            gpu_score: 0,
            critical_score: 0,
            eligibility_state: "ACTIVE".to_string(),
            tier: "ACTIVE".to_string(),
            max_risk_class: "STANDARD".to_string(),
            cloud_unit_allowed: true,
            cloud_unit_grant_proposal_id: Some("cloud-proposal-test".to_string()),
            cloud_unit_grant_payload_hash: Some("aa".repeat(32)),
            long_running_allowed: false,
            gpu_allowed: false,
            gpu_grant_proposal_id: None,
            gpu_grant_payload_hash: None,
            critical_workload_allowed: false,
            critical_workload_grant_proposal_id: None,
            critical_workload_grant_payload_hash: None,
            critical_workload_review_proposal_id: None,
            critical_workload_review_payload_hash: None,
            max_parallel_jobs: 4,
            max_job_duration_sec: 3_600,
            successful_probe_jobs: 3,
            successful_real_jobs: 2,
            successful_cloud_unit_jobs: 1,
            successful_gpu_evidence_jobs: 0,
            successful_critical_workload_jobs: 0,
            total_evidence_count: 5,
            observation_window: 60,
            uptime_window: 60,
            deny_reason: None,
            next_recovery_action: None,
            policy_version: WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
        }
    }

    #[test]
    fn worker_eligibility_role_score_projection_v2_is_mandatory() {
        let mut eligibility = base_role_projection_worker();
        eligibility.role_score_projection_version = None;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(
            err,
            "worker_eligibility_missing_role_score_projection_version"
        );
    }

    #[test]
    fn worker_eligibility_role_score_projection_v2_is_contract_validated() {
        let mut eligibility = base_role_projection_worker();
        eligibility
            .validate_contract_v1()
            .expect("valid explicit role score projection");

        eligibility.compute_score = 879;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(err, "worker_eligibility_compute_score_mismatch");

        let mut eligibility = base_role_projection_worker();
        eligibility.cloud_unit_score = 0;
        let err = eligibility.validate_contract_v1().unwrap_err();
        assert_eq!(err, "worker_eligibility_cloud_unit_score_mismatch");
    }
}
