// src/e2_worker_evidence.rs
//
// Canonical E2 -> Chain worker reputation evidence surface.
// The chain is the source of truth: E2 only submits signed, finality-bound evidence.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const E2_WORKER_EVIDENCE_FORMAT_VERSION_V1: &str = "e2-worker-execution-evidence-v1";
pub const E2_WORKER_EVIDENCE_DOMAIN_V1: &str = "newgen-e2-worker-evidence|v1";
pub const E2_WORKER_EVIDENCE_FORMAT_VERSION_V2: &str = "e2-worker-execution-evidence-v2";
pub const E2_WORKER_EVIDENCE_DOMAIN_V2: &str = "newgen-e2-worker-evidence|v2";
pub const E2_WORKER_PROBE_BOOTSTRAP_ORDER_DOMAIN_V1: &str = "newgen-e2-probe-bootstrap-order|v1";
pub const WORKER_PENALTY_TAXONOMY_VERSION_V1: &str = "worker-penalty-taxonomy-v1";
/// Height-bounded window used for recent fault counters. Consecutive counters are
/// intentionally separate and do not decay across the window.
pub const E2_WORKER_REPUTATION_RECENT_WINDOW_BLOCKS_V1: u64 = 10_000;

pub const FAILURE_SUCCESS: &str = "SUCCESS";
pub const FAILURE_TIMEOUT: &str = "TIMEOUT";
pub const FAILURE_NON_RESPONSIVE: &str = "NON_RESPONSIVE";
pub const FAILURE_WORKER_CRASH: &str = "WORKER_CRASH";
pub const FAILURE_MISSING_ARTIFACT: &str = "MISSING_ARTIFACT";
pub const FAILURE_BAD_RESULT_HASH: &str = "BAD_RESULT_HASH";
pub const FAILURE_INVALID_RECEIPT: &str = "INVALID_RECEIPT";
pub const FAILURE_IDENTITY_MISMATCH: &str = "IDENTITY_MISMATCH";
pub const FAILURE_SIGNATURE_INVALID: &str = "SIGNATURE_INVALID";
pub const FAILURE_REPLAY_ATTEMPT: &str = "REPLAY_ATTEMPT";
pub const FAILURE_DOUBLE_CLAIM: &str = "DOUBLE_CLAIM";
pub const FAILURE_PROTOCOL_VIOLATION: &str = "PROTOCOL_VIOLATION";
pub const FAILURE_MALICIOUS_BEHAVIOR: &str = "MALICIOUS_BEHAVIOR";
pub const FAILURE_INPUT_INVALID: &str = "INPUT_INVALID";
pub const FAILURE_COORDINATOR_ERROR: &str = "COORDINATOR_ERROR";
pub const FAILURE_CHAIN_FINALITY_ERROR: &str = "CHAIN_FINALITY_ERROR";
pub const FAILURE_INFRA_ERROR: &str = "INFRA_ERROR";
pub const FAILURE_UNKNOWN: &str = "UNKNOWN_FAILURE";

pub const FAULT_WORKER: &str = "WORKER";
pub const FAULT_INPUT: &str = "INPUT";
pub const FAULT_COORDINATOR: &str = "COORDINATOR";
pub const FAULT_CHAIN: &str = "CHAIN";
pub const FAULT_INFRA: &str = "INFRA";
pub const FAULT_UNKNOWN: &str = "UNKNOWN";

pub const EFFECT_POSITIVE: &str = "POSITIVE";
pub const EFFECT_SOFT_PENALTY: &str = "SOFT_PENALTY";
pub const EFFECT_MEDIUM_PENALTY: &str = "MEDIUM_PENALTY";
pub const EFFECT_HARD_PENALTY: &str = "HARD_PENALTY";
pub const EFFECT_GOVERNANCE_REQUIRED: &str = "GOVERNANCE_REQUIRED";
pub const EFFECT_REJECT_ONLY: &str = "REJECT_ONLY";
pub const EFFECT_NO_WORKER_PENALTY: &str = "NO_WORKER_PENALTY";

pub const VERDICT_ACCEPT_POSITIVE: &str = "ACCEPT_POSITIVE";
pub const VERDICT_WORKER_PENALTY_CANDIDATE: &str = "WORKER_PENALTY_CANDIDATE";
pub const VERDICT_GOVERNANCE_REQUIRED: &str = "GOVERNANCE_REQUIRED";
pub const VERDICT_REJECT_ONLY: &str = "REJECT_ONLY";
pub const VERDICT_NO_WORKER_PENALTY: &str = "NO_WORKER_PENALTY";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerExecutionEvidenceV1 {
    pub format_version: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub e2_contract_version: String,

    pub order_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub worker_node_pubkey: String,
    /// Provider/operator wallet that owns the worker for economic reputation.
    /// This is distinct from payer_wallet, which is the customer paying the job.
    #[serde(default)]
    pub operator_wallet_pubkey: String,
    pub payer_wallet: String,

    pub order_created_height: u64,
    pub order_claimed_height: u64,
    pub order_terminal_height: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,

    pub execution_status: String,
    pub failure_class: String,
    pub sla_ms: u64,
    pub max_time_ms: u64,

    pub coordinator_id: String,
    pub attester_pubkey: String,
    pub evidence_timestamp_ms: u64,

    pub evidence_hash: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerExecutionEvidenceV2 {
    pub format_version: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub e2_contract_version: String,

    pub order_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub worker_node_pubkey: String,
    #[serde(default)]
    pub operator_wallet_pubkey: String,
    pub payer_wallet: String,

    pub order_created_height: u64,
    pub order_claimed_height: u64,
    pub order_terminal_height: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,

    pub execution_status: String,
    pub failure_class: String,
    pub fault_domain: String,
    pub penalty_effect: String,
    pub worker_fault: bool,
    pub verifier_verdict: String,
    pub taxonomy_version: String,
    pub sla_ms: u64,
    pub max_time_ms: u64,

    pub coordinator_id: String,
    pub attester_pubkey: String,
    pub evidence_timestamp_ms: u64,

    pub evidence_hash: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum E2WorkerExecutionEvidenceAnyV1 {
    V2(E2WorkerExecutionEvidenceV2),
    V1(E2WorkerExecutionEvidenceV1),
}

impl E2WorkerExecutionEvidenceV2 {
    pub fn legacy_projection_v1(&self) -> E2WorkerExecutionEvidenceV1 {
        E2WorkerExecutionEvidenceV1 {
            format_version: E2_WORKER_EVIDENCE_FORMAT_VERSION_V1.to_string(),
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            e2_contract_version: self.e2_contract_version.clone(),
            order_id: self.order_id.clone(),
            job_id: self.job_id.clone(),
            job_kind: self.job_kind.clone(),
            worker_node_pubkey: self.worker_node_pubkey.clone(),
            operator_wallet_pubkey: self.operator_wallet_pubkey.clone(),
            payer_wallet: self.payer_wallet.clone(),
            order_created_height: self.order_created_height,
            order_claimed_height: self.order_claimed_height,
            order_terminal_height: self.order_terminal_height,
            result_hash: self.result_hash.clone(),
            artifact_root_hash: self.artifact_root_hash.clone(),
            receipt_hash: self.receipt_hash.clone(),
            execution_status: self.execution_status.clone(),
            failure_class: self.failure_class.clone(),
            sla_ms: self.sla_ms,
            max_time_ms: self.max_time_ms,
            coordinator_id: self.coordinator_id.clone(),
            attester_pubkey: self.attester_pubkey.clone(),
            evidence_timestamp_ms: self.evidence_timestamp_ms,
            evidence_hash: self.evidence_hash.clone(),
            signature: self.signature.clone(),
        }
    }
}

impl E2WorkerExecutionEvidenceAnyV1 {
    pub fn evidence_hash(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.evidence_hash,
            Self::V2(ev) => &ev.evidence_hash,
        }
    }
    pub fn order_id(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.order_id,
            Self::V2(ev) => &ev.order_id,
        }
    }
    pub fn worker_node_pubkey(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.worker_node_pubkey,
            Self::V2(ev) => &ev.worker_node_pubkey,
        }
    }
    pub fn failure_class(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.failure_class,
            Self::V2(ev) => &ev.failure_class,
        }
    }
    pub fn fault_domain(&self) -> &str {
        match self {
            Self::V1(ev) => legacy_fault_domain_for_failure_class_v1(&ev.failure_class),
            Self::V2(ev) => &ev.fault_domain,
        }
    }
    pub fn penalty_effect(&self) -> Option<&str> {
        match self {
            Self::V1(_) => None,
            Self::V2(ev) => Some(ev.penalty_effect.as_str()),
        }
    }
    pub fn worker_fault(&self) -> bool {
        match self {
            Self::V1(ev) => legacy_worker_fault_for_failure_class_v1(&ev.failure_class),
            Self::V2(ev) => ev.worker_fault && ev.fault_domain.trim() == FAULT_WORKER,
        }
    }
    pub fn updates_worker_fault_counters_v1(&self) -> bool {
        match self {
            Self::V1(ev) => legacy_worker_fault_for_failure_class_v1(&ev.failure_class),
            Self::V2(ev) => {
                ev.worker_fault
                    && ev.fault_domain.trim() == FAULT_WORKER
                    && matches!(
                        ev.penalty_effect.trim(),
                        EFFECT_SOFT_PENALTY
                            | EFFECT_MEDIUM_PENALTY
                            | EFFECT_HARD_PENALTY
                            | EFFECT_GOVERNANCE_REQUIRED
                    )
            }
        }
    }
    pub fn requires_secondary_governance_v1(&self) -> bool {
        match self {
            Self::V1(ev) => e2_worker_evidence_is_hard_v1(&ev.failure_class),
            Self::V2(ev) => {
                ev.worker_fault
                    && ev.fault_domain.trim() == FAULT_WORKER
                    && matches!(
                        ev.penalty_effect.trim(),
                        EFFECT_HARD_PENALTY | EFFECT_GOVERNANCE_REQUIRED
                    )
            }
        }
    }
    pub fn execution_status(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.execution_status,
            Self::V2(ev) => &ev.execution_status,
        }
    }
    pub fn job_kind(&self) -> &str {
        match self {
            Self::V1(ev) => &ev.job_kind,
            Self::V2(ev) => &ev.job_kind,
        }
    }
    pub fn legacy_projection_v1(&self) -> E2WorkerExecutionEvidenceV1 {
        match self {
            Self::V1(ev) => ev.clone(),
            Self::V2(ev) => ev.legacy_projection_v1(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2WorkerEvidenceApplyOutcomeV1 {
    pub status: String,
    pub evidence_id: String,
    pub applied_delta: i32,
    #[serde(default)]
    pub candidate_delta: i32,
    pub requires_governance: bool,
    pub hard_evidence: bool,
    pub worker_node_pubkey: String,
    pub order_id: String,
}

fn default_e2_worker_evidence_source_commitment_v1() -> String {
    "finalized".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2WorkerCanonicalEvidenceRecordV1 {
    pub evidence_id: String,
    pub evidence: E2WorkerExecutionEvidenceAnyV1,
    pub accepted_at_height: u64,
    pub applied_delta: i32,
    #[serde(default)]
    pub candidate_delta: i32,
    pub hard_evidence: bool,
    pub requires_governance: bool,
    /// Finalized L1 height used to validate the compute order, attester authorization,
    /// worker membership and evidence/order binding.
    #[serde(default)]
    pub validated_against_finalized_height: u64,
    /// Finalized L1 block hash for replay/audit anchoring.
    #[serde(default)]
    pub validated_against_finalized_hash: String,
    /// Commitment class consumed by downstream E2 admission/audit code.
    #[serde(default = "default_e2_worker_evidence_source_commitment_v1")]
    pub source_commitment: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerCanonicalHistoryStatsV1 {
    #[serde(default)]
    pub successful_probe_jobs: u64,
    #[serde(default)]
    pub successful_real_jobs: u64,
    #[serde(default)]
    pub successful_cloud_unit_jobs: u64,
    #[serde(default)]
    pub successful_gpu_evidence_jobs: u64,
    #[serde(default)]
    pub successful_critical_workload_jobs: u64,
    #[serde(default)]
    pub total_evidence_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_evidence_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_evidence_height: Option<u64>,
    #[serde(default)]
    pub latest_accepted_at_height: u64,
    #[serde(default)]
    pub latest_validated_against_finalized_height: u64,
    #[serde(default = "default_e2_worker_evidence_source_commitment_v1")]
    pub source_commitment: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hard_fault_height: Option<u64>,
    #[serde(default)]
    pub failed_recovery_probe_count: u64,
}

impl E2WorkerCanonicalHistoryStatsV1 {
    pub fn reset_recent_window_if_stale_v1(&mut self, height: u64) {
        if self.recent_window_start_height == 0 {
            self.recent_window_start_height = height;
            return;
        }
        if height.saturating_sub(self.recent_window_start_height)
            > E2_WORKER_REPUTATION_RECENT_WINDOW_BLOCKS_V1
        {
            self.recent_window_start_height = height;
            self.recent_timeout_count = 0;
            self.recent_failure_count = 0;
            self.recent_invalid_output_count = 0;
        }
    }

    pub fn observe_evidence_v1(
        &mut self,
        ev: &E2WorkerExecutionEvidenceAnyV1,
        accepted_at_height: u64,
        validated_against_finalized_height: u64,
        source_commitment: &str,
    ) {
        // Governance-required/hard evidence records are audit candidates until a
        // secondary governance action explicitly applies consequences. Do not let
        // pending candidates influence eligibility counters, probe recovery state,
        // last hard-fault height, or total evidence thresholds.
        if ev.requires_secondary_governance_v1() {
            return;
        }

        self.reset_recent_window_if_stale_v1(accepted_at_height);
        self.total_evidence_count = self.total_evidence_count.saturating_add(1);
        self.first_evidence_height = Some(
            self.first_evidence_height
                .map(|h| h.min(accepted_at_height))
                .unwrap_or(accepted_at_height),
        );
        self.last_evidence_height = Some(
            self.last_evidence_height
                .map(|h| h.max(accepted_at_height))
                .unwrap_or(accepted_at_height),
        );
        self.latest_accepted_at_height = self.latest_accepted_at_height.max(accepted_at_height);
        self.latest_validated_against_finalized_height = self
            .latest_validated_against_finalized_height
            .max(validated_against_finalized_height);
        let source_commitment = source_commitment.trim().to_ascii_lowercase();
        if self.source_commitment.trim().is_empty() {
            self.source_commitment = source_commitment;
        } else if !self
            .source_commitment
            .eq_ignore_ascii_case(&source_commitment)
        {
            self.source_commitment = "mixed".to_string();
        }

        let failure_class = ev.failure_class().trim();
        let job_is_probe = e2_worker_job_kind_is_probe_bootstrap_v1(ev.job_kind());
        let update_worker_fault_counters = ev.updates_worker_fault_counters_v1();
        let requires_secondary_governance = ev.requires_secondary_governance_v1();
        if ev.execution_status().trim() == "COMPLETED" && failure_class == FAILURE_SUCCESS {
            self.consecutive_failures = 0;
            self.consecutive_timeouts = 0;
            if job_is_probe {
                self.successful_probe_jobs = self.successful_probe_jobs.saturating_add(1);
            } else {
                self.successful_real_jobs = self.successful_real_jobs.saturating_add(1);
                match e2_worker_evidence_workload_class_v1(ev.job_kind()) {
                    E2WorkerEvidenceWorkloadClassV1::CloudUnit
                    | E2WorkerEvidenceWorkloadClassV1::LongRunning => {
                        self.successful_cloud_unit_jobs =
                            self.successful_cloud_unit_jobs.saturating_add(1);
                    }
                    E2WorkerEvidenceWorkloadClassV1::Gpu => {
                        self.successful_gpu_evidence_jobs =
                            self.successful_gpu_evidence_jobs.saturating_add(1);
                    }
                    E2WorkerEvidenceWorkloadClassV1::Critical => {
                        self.successful_critical_workload_jobs =
                            self.successful_critical_workload_jobs.saturating_add(1);
                    }
                    E2WorkerEvidenceWorkloadClassV1::Base => {}
                }
            }
        } else if update_worker_fault_counters {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if failure_class == FAILURE_TIMEOUT {
                self.recent_timeout_count = self.recent_timeout_count.saturating_add(1);
                self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            } else {
                self.recent_failure_count = self.recent_failure_count.saturating_add(1);
                self.consecutive_timeouts = 0;
            }
            if matches!(
                failure_class,
                FAILURE_BAD_RESULT_HASH | FAILURE_INVALID_RECEIPT | FAILURE_SIGNATURE_INVALID
            ) {
                self.recent_invalid_output_count =
                    self.recent_invalid_output_count.saturating_add(1);
            }
            if requires_secondary_governance {
                self.last_hard_fault_height = Some(accepted_at_height);
            }
            if job_is_probe {
                self.failed_recovery_probe_count =
                    self.failed_recovery_probe_count.saturating_add(1);
            }
        } else {
            self.consecutive_timeouts = 0;
        }
    }

    pub fn is_finalized_for_height_v1(&self, finalized_height: u64) -> bool {
        self.source_commitment
            .trim()
            .eq_ignore_ascii_case("finalized")
            && self.latest_accepted_at_height <= finalized_height
            && self.latest_validated_against_finalized_height <= finalized_height
    }

    pub fn as_tuple_v1(&self) -> (u64, u64, u64, u64, Option<u64>, Option<u64>) {
        (
            self.successful_probe_jobs,
            self.successful_real_jobs,
            self.total_evidence_count,
            self.failed_recovery_probe_count,
            self.first_evidence_height,
            self.last_evidence_height,
        )
    }

    pub fn as_tuple_with_classes_v1(
        &self,
    ) -> (u64, u64, u64, u64, u64, u64, u64, Option<u64>, Option<u64>) {
        (
            self.successful_probe_jobs,
            self.successful_real_jobs,
            self.successful_cloud_unit_jobs,
            self.successful_gpu_evidence_jobs,
            self.successful_critical_workload_jobs,
            self.total_evidence_count,
            self.failed_recovery_probe_count,
            self.first_evidence_height,
            self.last_evidence_height,
        )
    }
}

pub fn e2_worker_history_key_v1(
    worker_node_pubkey_hex: &str,
    operator_wallet_pubkey_hex: &str,
) -> String {
    format!(
        "{}:{}",
        worker_node_pubkey_hex.trim().to_ascii_lowercase(),
        operator_wallet_pubkey_hex.trim().to_ascii_lowercase()
    )
}

#[derive(Clone, Debug)]
struct E2WorkerEvidenceValidationContextV1 {
    finalized_height: u64,
    finalized_hash: String,
    source_commitment: String,
    hard_evidence: bool,
    applied_delta: i32,
    candidate_delta: i32,
    worker_hex: String,
    operator_wallet_hex: String,
}

fn trim_opt(v: &Option<String>) -> &str {
    v.as_deref().map(str::trim).unwrap_or("")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Strict bootstrap-probe job-kind allow-list.
///
/// Do not use substring matching here. Values such as `nonprobe`, `probe-real`,
/// or `myprobe` must not be classified as bootstrap probes, otherwise an
/// ordinary workload can accidentally enter the probe-only evidence lane.
pub fn e2_worker_job_kind_is_probe_bootstrap_v1(job_kind: &str) -> bool {
    matches!(
        job_kind.trim().to_ascii_lowercase().as_str(),
        "probe" | "probe:v1" | "bootstrap_probe_v1"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum E2WorkerEvidenceWorkloadClassV1 {
    Base,
    CloudUnit,
    LongRunning,
    Gpu,
    Critical,
}

pub fn e2_worker_evidence_workload_class_v1(job_kind: &str) -> E2WorkerEvidenceWorkloadClassV1 {
    let kind = job_kind
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(':', "_");
    match kind.as_str() {
        "cloud_unit_long_running_v1"
        | "long_running_v1"
        | "long_running_service_v1"
        | "http_service_v1"
        | "jupyter_session_v1"
        | "persistent_session_v1" => E2WorkerEvidenceWorkloadClassV1::LongRunning,
        "cloud_unit"
        | "cloud_unit_v1"
        | "cloud_unit_lease_v1"
        | "cloud_unit_session_v1"
        | "cloud_unit_native_v1"
        | "compute_instance_v1"
        | "compute_instance_lease_v1" => E2WorkerEvidenceWorkloadClassV1::CloudUnit,
        "gpu"
        | "gpu_v1"
        | "gpu_job_v1"
        | "gpu_inference_v1"
        | "gpu_training_v1"
        | "gpu_lease_v1"
        | "gpu_runtime_benchmark_v1" => E2WorkerEvidenceWorkloadClassV1::Gpu,
        "critical"
        | "critical_v1"
        | "critical_workload_v1"
        | "critical_job_v1"
        | "critical_inference_v1" => E2WorkerEvidenceWorkloadClassV1::Critical,
        _ => E2WorkerEvidenceWorkloadClassV1::Base,
    }
}

pub fn expected_e2_worker_probe_bootstrap_order_id_v1(
    chain_id: &str,
    genesis_hash: &str,
    worker_node_pubkey: &str,
    operator_wallet_pubkey: &str,
    job_id: &str,
    result_hash: &str,
) -> String {
    sha256_hex(
        format!(
            "{domain}\x1f{chain}\x1f{genesis}\x1f{worker}\x1f{operator}\x1f{job}\x1f{result}",
            domain = E2_WORKER_PROBE_BOOTSTRAP_ORDER_DOMAIN_V1,
            chain = chain_id.trim(),
            genesis = genesis_hash.trim(),
            worker = worker_node_pubkey.trim(),
            operator = operator_wallet_pubkey.trim(),
            job = job_id.trim(),
            result = result_hash.trim(),
        )
        .as_bytes(),
    )
}

pub fn expected_e2_worker_probe_bootstrap_order_id_for_evidence_v1(
    ev: &E2WorkerExecutionEvidenceV1,
) -> Option<String> {
    let result_hash = ev.result_hash.as_deref()?.trim();
    if result_hash.is_empty() {
        return None;
    }
    Some(expected_e2_worker_probe_bootstrap_order_id_v1(
        &ev.chain_id,
        &ev.genesis_hash,
        &ev.worker_node_pubkey,
        &ev.operator_wallet_pubkey,
        &ev.job_id,
        result_hash,
    ))
}

pub fn e2_worker_evidence_signing_bytes_v1(ev: &E2WorkerExecutionEvidenceV1) -> Vec<u8> {
    // Use an ASCII unit separator. Do not include evidence_hash/signature:
    // evidence_hash = sha256(signing_bytes), signature = sign(signing_bytes).
    format!(
        "{d}\x1f{fv}\x1f{chain}\x1f{genesis}\x1f{e2v}\x1f{oid}\x1f{jid}\x1f{kind}\x1f{worker}\x1f{operator}\x1f{payer}\x1f{created}\x1f{claimed}\x1f{terminal}\x1f{result}\x1f{artifact}\x1f{receipt}\x1f{status}\x1f{failure}\x1f{sla}\x1f{max}\x1f{coord}\x1f{attester}\x1f{ts}",
        d = E2_WORKER_EVIDENCE_DOMAIN_V1,
        fv = ev.format_version.trim(),
        chain = ev.chain_id.trim(),
        genesis = ev.genesis_hash.trim(),
        e2v = ev.e2_contract_version.trim(),
        oid = ev.order_id.trim(),
        jid = ev.job_id.trim(),
        kind = ev.job_kind.trim(),
        worker = ev.worker_node_pubkey.trim(),
        operator = ev.operator_wallet_pubkey.trim(),
        payer = ev.payer_wallet.trim(),
        created = ev.order_created_height,
        claimed = ev.order_claimed_height,
        terminal = ev.order_terminal_height,
        result = trim_opt(&ev.result_hash),
        artifact = trim_opt(&ev.artifact_root_hash),
        receipt = trim_opt(&ev.receipt_hash),
        status = ev.execution_status.trim(),
        failure = ev.failure_class.trim(),
        sla = ev.sla_ms,
        max = ev.max_time_ms,
        coord = ev.coordinator_id.trim(),
        attester = ev.attester_pubkey.trim(),
        ts = ev.evidence_timestamp_ms,
    )
    .into_bytes()
}

pub fn expected_e2_worker_evidence_id_v1(ev: &E2WorkerExecutionEvidenceV1) -> String {
    sha256_hex(&e2_worker_evidence_signing_bytes_v1(ev))
}
pub fn e2_worker_evidence_signing_bytes_v2(ev: &E2WorkerExecutionEvidenceV2) -> Vec<u8> {
    format!(
        "{d}\x1f{fv}\x1f{chain}\x1f{genesis}\x1f{e2v}\x1f{oid}\x1f{jid}\x1f{kind}\x1f{worker}\x1f{operator}\x1f{payer}\x1f{created}\x1f{claimed}\x1f{terminal}\x1f{result}\x1f{artifact}\x1f{receipt}\x1f{status}\x1f{failure}\x1f{fault_domain}\x1f{penalty_effect}\x1f{worker_fault}\x1f{verifier_verdict}\x1f{taxonomy}\x1f{sla}\x1f{max}\x1f{coord}\x1f{attester}\x1f{ts}",
        d = E2_WORKER_EVIDENCE_DOMAIN_V2,
        fv = ev.format_version.trim(),
        chain = ev.chain_id.trim(),
        genesis = ev.genesis_hash.trim(),
        e2v = ev.e2_contract_version.trim(),
        oid = ev.order_id.trim(),
        jid = ev.job_id.trim(),
        kind = ev.job_kind.trim(),
        worker = ev.worker_node_pubkey.trim(),
        operator = ev.operator_wallet_pubkey.trim(),
        payer = ev.payer_wallet.trim(),
        created = ev.order_created_height,
        claimed = ev.order_claimed_height,
        terminal = ev.order_terminal_height,
        result = trim_opt(&ev.result_hash),
        artifact = trim_opt(&ev.artifact_root_hash),
        receipt = trim_opt(&ev.receipt_hash),
        status = ev.execution_status.trim(),
        failure = ev.failure_class.trim(),
        fault_domain = ev.fault_domain.trim(),
        penalty_effect = ev.penalty_effect.trim(),
        worker_fault = ev.worker_fault,
        verifier_verdict = ev.verifier_verdict.trim(),
        taxonomy = ev.taxonomy_version.trim(),
        sla = ev.sla_ms,
        max = ev.max_time_ms,
        coord = ev.coordinator_id.trim(),
        attester = ev.attester_pubkey.trim(),
        ts = ev.evidence_timestamp_ms,
    )
    .into_bytes()
}

pub fn expected_e2_worker_evidence_id_v2(ev: &E2WorkerExecutionEvidenceV2) -> String {
    sha256_hex(&e2_worker_evidence_signing_bytes_v2(ev))
}

pub fn legacy_fault_domain_for_failure_class_v1(failure_class: &str) -> &'static str {
    match failure_class.trim() {
        FAILURE_SUCCESS => FAULT_WORKER,
        FAILURE_TIMEOUT
        | FAILURE_NON_RESPONSIVE
        | FAILURE_WORKER_CRASH
        | FAILURE_MISSING_ARTIFACT
        | FAILURE_BAD_RESULT_HASH
        | FAILURE_INVALID_RECEIPT
        | FAILURE_SIGNATURE_INVALID
        | FAILURE_IDENTITY_MISMATCH
        | FAILURE_DOUBLE_CLAIM
        | FAILURE_PROTOCOL_VIOLATION
        | FAILURE_MALICIOUS_BEHAVIOR => FAULT_WORKER,
        FAILURE_INPUT_INVALID => FAULT_INPUT,
        FAILURE_COORDINATOR_ERROR => FAULT_COORDINATOR,
        FAILURE_CHAIN_FINALITY_ERROR => FAULT_CHAIN,
        FAILURE_INFRA_ERROR => FAULT_INFRA,
        FAILURE_REPLAY_ATTEMPT | FAILURE_UNKNOWN => FAULT_UNKNOWN,
        _ => FAULT_UNKNOWN,
    }
}

pub fn legacy_worker_fault_for_failure_class_v1(failure_class: &str) -> bool {
    legacy_fault_domain_for_failure_class_v1(failure_class) == FAULT_WORKER
        && !matches!(failure_class.trim(), FAILURE_SUCCESS)
}

pub fn allowed_failure_class_v1(v: &str) -> bool {
    matches!(
        v.trim(),
        FAILURE_SUCCESS
            | FAILURE_TIMEOUT
            | FAILURE_NON_RESPONSIVE
            | FAILURE_WORKER_CRASH
            | FAILURE_MISSING_ARTIFACT
            | FAILURE_BAD_RESULT_HASH
            | FAILURE_INVALID_RECEIPT
            | FAILURE_IDENTITY_MISMATCH
            | FAILURE_SIGNATURE_INVALID
            | FAILURE_REPLAY_ATTEMPT
            | FAILURE_DOUBLE_CLAIM
            | FAILURE_PROTOCOL_VIOLATION
            | FAILURE_MALICIOUS_BEHAVIOR
            | FAILURE_INPUT_INVALID
            | FAILURE_COORDINATOR_ERROR
            | FAILURE_CHAIN_FINALITY_ERROR
            | FAILURE_INFRA_ERROR
            | FAILURE_UNKNOWN
    )
}

pub fn allowed_fault_domain_v1(v: &str) -> bool {
    matches!(
        v.trim(),
        FAULT_WORKER | FAULT_INPUT | FAULT_COORDINATOR | FAULT_CHAIN | FAULT_INFRA | FAULT_UNKNOWN
    )
}

pub fn allowed_penalty_effect_v1(v: &str) -> bool {
    matches!(
        v.trim(),
        EFFECT_POSITIVE
            | EFFECT_SOFT_PENALTY
            | EFFECT_MEDIUM_PENALTY
            | EFFECT_HARD_PENALTY
            | EFFECT_GOVERNANCE_REQUIRED
            | EFFECT_REJECT_ONLY
            | EFFECT_NO_WORKER_PENALTY
    )
}

pub fn allowed_verifier_verdict_v1(v: &str) -> bool {
    matches!(
        v.trim(),
        VERDICT_ACCEPT_POSITIVE
            | VERDICT_WORKER_PENALTY_CANDIDATE
            | VERDICT_GOVERNANCE_REQUIRED
            | VERDICT_REJECT_ONLY
            | VERDICT_NO_WORKER_PENALTY
    )
}

pub fn expected_verifier_verdict_from_effect_v1(effect: &str) -> &'static str {
    match effect.trim() {
        EFFECT_POSITIVE => VERDICT_ACCEPT_POSITIVE,
        EFFECT_SOFT_PENALTY | EFFECT_MEDIUM_PENALTY | EFFECT_HARD_PENALTY => {
            VERDICT_WORKER_PENALTY_CANDIDATE
        }
        EFFECT_GOVERNANCE_REQUIRED => VERDICT_GOVERNANCE_REQUIRED,
        EFFECT_REJECT_ONLY => VERDICT_REJECT_ONLY,
        EFFECT_NO_WORKER_PENALTY => VERDICT_NO_WORKER_PENALTY,
        _ => VERDICT_NO_WORKER_PENALTY,
    }
}

pub fn expected_penalty_effect_for_failure_class_and_domain_v1(
    failure_class: &str,
    fault_domain: &str,
) -> Result<&'static str, String> {
    match (failure_class.trim(), fault_domain.trim()) {
        (FAILURE_SUCCESS, FAULT_WORKER) => Ok(EFFECT_POSITIVE),
        (FAILURE_TIMEOUT | FAILURE_NON_RESPONSIVE, FAULT_WORKER) => Ok(EFFECT_SOFT_PENALTY),
        (FAILURE_WORKER_CRASH | FAILURE_MISSING_ARTIFACT, FAULT_WORKER) => {
            Ok(EFFECT_MEDIUM_PENALTY)
        }
        (
            FAILURE_BAD_RESULT_HASH
            | FAILURE_INVALID_RECEIPT
            | FAILURE_IDENTITY_MISMATCH
            | FAILURE_SIGNATURE_INVALID,
            FAULT_WORKER,
        ) => Ok(EFFECT_HARD_PENALTY),
        (FAILURE_REPLAY_ATTEMPT, FAULT_WORKER) => Ok(EFFECT_REJECT_ONLY),
        (
            FAILURE_DOUBLE_CLAIM | FAILURE_PROTOCOL_VIOLATION | FAILURE_MALICIOUS_BEHAVIOR,
            FAULT_WORKER,
        ) => Ok(EFFECT_GOVERNANCE_REQUIRED),
        (FAILURE_INPUT_INVALID, FAULT_INPUT) => Ok(EFFECT_NO_WORKER_PENALTY),
        (FAILURE_COORDINATOR_ERROR, FAULT_COORDINATOR) => Ok(EFFECT_NO_WORKER_PENALTY),
        (FAILURE_CHAIN_FINALITY_ERROR, FAULT_CHAIN) => Ok(EFFECT_NO_WORKER_PENALTY),
        (FAILURE_INFRA_ERROR, FAULT_INFRA) => Ok(EFFECT_NO_WORKER_PENALTY),
        (FAILURE_UNKNOWN, FAULT_UNKNOWN) => Ok(EFFECT_NO_WORKER_PENALTY),
        // Explicit non-worker identity mismatch is reserved for coordinator-side
        // worker-id/header/body attribution rejects. It must not become a canonical
        // worker penalty, but it also must not be admitted by a generic fallback.
        (FAILURE_IDENTITY_MISMATCH, FAULT_COORDINATOR) => Ok(EFFECT_NO_WORKER_PENALTY),
        _ => Err("e2_worker_evidence_v2_invalid_failure_domain_combination".to_string()),
    }
}

pub fn expected_worker_fault_from_domain_effect_v1(
    fault_domain: &str,
    penalty_effect: &str,
) -> bool {
    fault_domain.trim() == FAULT_WORKER
        && matches!(
            penalty_effect.trim(),
            EFFECT_SOFT_PENALTY
                | EFFECT_MEDIUM_PENALTY
                | EFFECT_HARD_PENALTY
                | EFFECT_GOVERNANCE_REQUIRED
                | EFFECT_REJECT_ONLY
        )
}

fn validate_e2_worker_evidence_v2_taxonomy(ev: &E2WorkerExecutionEvidenceV2) -> Result<(), String> {
    if ev.format_version.trim() != E2_WORKER_EVIDENCE_FORMAT_VERSION_V2 {
        return Err("e2_worker_evidence_v2_bad_format_version".to_string());
    }
    if ev.taxonomy_version.trim() != WORKER_PENALTY_TAXONOMY_VERSION_V1 {
        return Err("e2_worker_evidence_v2_bad_taxonomy_version".to_string());
    }
    if !allowed_failure_class_v1(&ev.failure_class) {
        return Err("e2_worker_evidence_v2_bad_failure_class".to_string());
    }
    if !allowed_fault_domain_v1(&ev.fault_domain) {
        return Err("e2_worker_evidence_v2_bad_fault_domain".to_string());
    }
    if !allowed_penalty_effect_v1(&ev.penalty_effect) {
        return Err("e2_worker_evidence_v2_bad_penalty_effect".to_string());
    }
    if !allowed_verifier_verdict_v1(&ev.verifier_verdict) {
        return Err("e2_worker_evidence_v2_bad_verifier_verdict".to_string());
    }
    let expected_effect = expected_penalty_effect_for_failure_class_and_domain_v1(
        &ev.failure_class,
        &ev.fault_domain,
    )?;
    if ev.penalty_effect.trim() != expected_effect {
        return Err("e2_worker_evidence_v2_penalty_effect_mismatch".to_string());
    }
    let expected_verdict = expected_verifier_verdict_from_effect_v1(&ev.penalty_effect);
    if ev.verifier_verdict.trim() != expected_verdict {
        return Err("e2_worker_evidence_v2_verifier_verdict_mismatch".to_string());
    }
    let expected_worker_fault =
        expected_worker_fault_from_domain_effect_v1(&ev.fault_domain, &ev.penalty_effect);
    if ev.worker_fault != expected_worker_fault {
        return Err("e2_worker_evidence_v2_worker_fault_mismatch".to_string());
    }
    Ok(())
}

fn parse_pk32_any(raw: &str) -> Result<[u8; 32], String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("missing_pubkey".to_string());
    }
    if let Ok(bytes) = STANDARD.decode(s) {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(s).map_err(|e| format!("pubkey_hex_invalid:{e}"))?;
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    Err("pubkey_format_invalid".to_string())
}

fn parse_sig64_b64(raw: &str) -> Result<[u8; 64], String> {
    let bytes = STANDARD
        .decode(raw.trim())
        .map_err(|e| format!("signature_b64_invalid:{e}"))?;
    if bytes.len() != 64 {
        return Err("signature_len_invalid".to_string());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn verify_e2_worker_evidence_signature_v1(
    ev: &E2WorkerExecutionEvidenceV1,
) -> Result<(), String> {
    if ev.format_version.trim() != E2_WORKER_EVIDENCE_FORMAT_VERSION_V1 {
        return Err("e2_worker_evidence_bad_format_version".to_string());
    }
    let expected_hash = expected_e2_worker_evidence_id_v1(ev);
    if ev.evidence_hash.trim() != expected_hash {
        return Err("e2_worker_evidence_hash_mismatch".to_string());
    }
    let pk = parse_pk32_any(&ev.attester_pubkey)?;
    let sig = parse_sig64_b64(&ev.signature)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("attester_pubkey_invalid:{e}"))?;
    let sig = Signature::from_bytes(&sig);
    vk.verify_strict(&e2_worker_evidence_signing_bytes_v1(ev), &sig)
        .map_err(|e| format!("e2_worker_evidence_signature_invalid:{e}"))
}

pub fn verify_e2_worker_evidence_signature_v2(
    ev: &E2WorkerExecutionEvidenceV2,
) -> Result<(), String> {
    validate_e2_worker_evidence_v2_taxonomy(ev)?;
    let expected_hash = expected_e2_worker_evidence_id_v2(ev);
    if ev.evidence_hash.trim() != expected_hash {
        return Err("e2_worker_evidence_v2_hash_mismatch".to_string());
    }
    let pk = parse_pk32_any(&ev.attester_pubkey)?;
    let sig = parse_sig64_b64(&ev.signature)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("attester_pubkey_invalid:{e}"))?;
    let sig = Signature::from_bytes(&sig);
    vk.verify_strict(&e2_worker_evidence_signing_bytes_v2(ev), &sig)
        .map_err(|e| format!("e2_worker_evidence_v2_signature_invalid:{e}"))
}

pub fn verify_e2_worker_evidence_signature_any_v1(
    ev: &E2WorkerExecutionEvidenceAnyV1,
) -> Result<(), String> {
    match ev {
        E2WorkerExecutionEvidenceAnyV1::V1(ev) => verify_e2_worker_evidence_signature_v1(ev),
        E2WorkerExecutionEvidenceAnyV1::V2(ev) => verify_e2_worker_evidence_signature_v2(ev),
    }
}

pub fn e2_worker_evidence_is_hard_v1(failure_class: &str) -> bool {
    matches!(
        failure_class.trim(),
        FAILURE_BAD_RESULT_HASH
            | FAILURE_INVALID_RECEIPT
            | FAILURE_SIGNATURE_INVALID
            | FAILURE_IDENTITY_MISMATCH
            | FAILURE_DOUBLE_CLAIM
            | FAILURE_PROTOCOL_VIOLATION
            | FAILURE_MALICIOUS_BEHAVIOR
    )
}

pub fn e2_worker_failure_class_delta_v1(failure_class: &str) -> i32 {
    match failure_class.trim() {
        FAILURE_SUCCESS => 5,
        FAILURE_TIMEOUT => -10,
        FAILURE_NON_RESPONSIVE => -12,
        FAILURE_WORKER_CRASH => -30,
        FAILURE_MISSING_ARTIFACT => -40,
        FAILURE_BAD_RESULT_HASH => -75,
        FAILURE_INVALID_RECEIPT => -80,
        FAILURE_SIGNATURE_INVALID => -100,
        FAILURE_INPUT_INVALID
        | FAILURE_COORDINATOR_ERROR
        | FAILURE_CHAIN_FINALITY_ERROR
        | FAILURE_INFRA_ERROR
        | FAILURE_UNKNOWN
        | FAILURE_REPLAY_ATTEMPT => 0,
        // Governance-grade events are recorded as hard candidates; jail/slash/revoke is decided by governance.
        FAILURE_IDENTITY_MISMATCH
        | FAILURE_DOUBLE_CLAIM
        | FAILURE_PROTOCOL_VIOLATION
        | FAILURE_MALICIOUS_BEHAVIOR => 0,
        _ => 0,
    }
}

pub fn e2_worker_evidence_delta_v1(ev: &E2WorkerExecutionEvidenceV1) -> i32 {
    e2_worker_failure_class_delta_v1(&ev.failure_class)
}

pub fn e2_worker_evidence_delta_any_v1(ev: &E2WorkerExecutionEvidenceAnyV1) -> i32 {
    match ev {
        E2WorkerExecutionEvidenceAnyV1::V1(ev) => e2_worker_evidence_delta_v1(ev),
        E2WorkerExecutionEvidenceAnyV1::V2(ev) => {
            let failure_class = ev.failure_class.trim();
            let fault_domain = ev.fault_domain.trim();
            if failure_class == FAILURE_SUCCESS {
                if fault_domain == FAULT_WORKER {
                    e2_worker_failure_class_delta_v1(failure_class)
                } else {
                    0
                }
            } else if !ev.worker_fault
                || matches!(
                    fault_domain,
                    FAULT_INPUT | FAULT_COORDINATOR | FAULT_CHAIN | FAULT_UNKNOWN
                )
            {
                0
            } else {
                e2_worker_failure_class_delta_v1(failure_class)
            }
        }
    }
}

fn nonempty_hex64_opt(value: Option<&String>, field: &str) -> Result<(), String> {
    if let Some(v) = value {
        let s = v.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("{field}_invalid"));
        }
    }
    Ok(())
}

fn e2_worker_evidence_token_v1(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    let s = value.trim();
    if s.is_empty() || s.len() > max_len {
        return Err(format!("{field}_invalid"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
    {
        return Err(format!("{field}_invalid"));
    }
    Ok(())
}

fn validate_e2_worker_evidence_status_binding_v1(
    order_status_debug: &str,
    execution_status: &str,
    failure_class: &str,
) -> Result<(), String> {
    let order_status = order_status_debug.trim().to_ascii_lowercase();
    let execution_status = execution_status.trim();
    let failure_class = failure_class.trim();

    match (execution_status, failure_class) {
        ("COMPLETED", "SUCCESS") => {
            if !order_status.contains("completed") {
                return Err("e2_worker_evidence_status_mismatch_completed".to_string());
            }
        }
        (
            "FAILED",
            "TIMEOUT"
            | "WORKER_CRASH"
            | "BAD_RESULT_HASH"
            | "MISSING_ARTIFACT"
            | "INVALID_RECEIPT"
            | "IDENTITY_MISMATCH"
            | "SIGNATURE_INVALID"
            | "REPLAY_ATTEMPT"
            | "DOUBLE_CLAIM"
            | "NON_RESPONSIVE"
            | "PROTOCOL_VIOLATION"
            | "MALICIOUS_BEHAVIOR"
            | "INPUT_INVALID"
            | "COORDINATOR_ERROR"
            | "CHAIN_FINALITY_ERROR"
            | "INFRA_ERROR"
            | "UNKNOWN_FAILURE",
        ) => {
            if !order_status.contains("failed") {
                return Err("e2_worker_evidence_status_mismatch_failed".to_string());
            }
        }
        _ => return Err("e2_worker_evidence_status_class_invalid".to_string()),
    }

    Ok(())
}

impl crate::Blockchain {
    fn e2_attester_is_authorized(&self, attester_pubkey: &str, height: u64) -> bool {
        self.validator_set_member_effectively_authorized_finalized_at_v1(attester_pubkey, height)
            .map(|(authorized, _reason)| authorized)
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn e2_worker_validator_set_member_at_height_v1(&self, worker_hex: &str, height: u64) -> bool {
        self.validator_set_member_effectively_authorized_finalized_at_v1(worker_hex, height)
            .map(|(authorized, _reason)| authorized)
            .unwrap_or(false)
    }

    fn e2_worker_operator_binding_is_authorized_finalized_v1(
        &self,
        worker_hex: &str,
        operator_wallet_hex: &str,
        height: u64,
    ) -> bool {
        self.resolve_e2_worker_operator_binding_finalized_hex_v1(worker_hex, height)
            .map(|binding| {
                binding.worker_node_pubkey == worker_hex
                    && binding.operator_wallet_pubkey == operator_wallet_hex
                    && binding.bound_at_height <= height
                    && binding.is_active()
            })
            .unwrap_or(false)
    }

    fn e2_worker_reputation_order_already_recorded_v1(&self, order_id: &str) -> bool {
        let normalized = order_id.trim().to_ascii_lowercase();
        self.e2_worker_reputation_order_ids.contains(&normalized)
            || self.e2_worker_reputation_evidence_log.iter().any(|record| {
                record
                    .evidence
                    .order_id()
                    .trim()
                    .eq_ignore_ascii_case(&normalized)
            })
    }
    fn e2_worker_evidence_is_bootstrap_probe_success_v1(
        ev_any: &E2WorkerExecutionEvidenceAnyV1,
        ev: &E2WorkerExecutionEvidenceV1,
    ) -> bool {
        matches!(ev_any, E2WorkerExecutionEvidenceAnyV1::V2(_))
            && e2_worker_job_kind_is_probe_bootstrap_v1(&ev.job_kind)
            && ev.order_created_height == 0
            && ev.order_claimed_height == 0
            && ev.order_terminal_height == 0
    }

    fn validate_e2_worker_reputation_evidence_context_v1(
        &self,
        ev_any: &E2WorkerExecutionEvidenceAnyV1,
    ) -> Result<E2WorkerEvidenceValidationContextV1, String> {
        verify_e2_worker_evidence_signature_any_v1(ev_any)?;
        let ev = ev_any.legacy_projection_v1();

        if ev.chain_id.trim() != crate::chain_identity::network_id() {
            return Err("e2_worker_evidence_chain_id_mismatch".to_string());
        }
        if !self.genesis_hash.trim().is_empty()
            && ev.genesis_hash.trim() != self.genesis_hash.trim()
        {
            return Err("e2_worker_evidence_genesis_hash_mismatch".to_string());
        }
        if ev.e2_contract_version.trim() != crate::version::E2_CONTRACT_VERSION {
            return Err("e2_worker_evidence_contract_version_mismatch".to_string());
        }

        if ev.order_id.trim().len() != 64 || !ev.order_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("e2_worker_evidence_order_id_invalid".to_string());
        }
        if ev.job_id.trim().is_empty()
            || ev.job_kind.trim().is_empty()
            || ev.worker_node_pubkey.trim().is_empty()
            || ev.operator_wallet_pubkey.trim().is_empty()
            || ev.payer_wallet.trim().is_empty()
        {
            return Err("e2_worker_evidence_required_field_missing".to_string());
        }
        e2_worker_evidence_token_v1(&ev.job_id, "job_id", 128)?;
        e2_worker_evidence_token_v1(&ev.job_kind, "job_kind", 64)?;
        if ev.worker_node_pubkey.trim().len() > 256
            || ev.operator_wallet_pubkey.trim().len() > 256
            || ev.payer_wallet.trim().len() > 256
        {
            return Err("e2_worker_evidence_principal_too_long".to_string());
        }
        // The authoritative security principal is attester_pubkey. coordinator_id is signed
        // metadata only until governance introduces a canonical coordinator registry/binding.
        // Keep it bounded and deterministic, but never treat it as an authorization source.
        let coordinator_id = ev.coordinator_id.trim();
        if coordinator_id.is_empty()
            || coordinator_id.len() > 128
            || !coordinator_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err("e2_worker_evidence_coordinator_id_metadata_invalid".to_string());
        }
        nonempty_hex64_opt(ev.result_hash.as_ref(), "result_hash")?;
        nonempty_hex64_opt(ev.artifact_root_hash.as_ref(), "artifact_root_hash")?;
        nonempty_hex64_opt(ev.receipt_hash.as_ref(), "receipt_hash")?;

        if self
            .e2_worker_reputation_evidence_ids
            .contains(ev.evidence_hash.trim())
        {
            return Err("e2_worker_evidence_duplicate".to_string());
        }
        if self.e2_worker_reputation_order_already_recorded_v1(ev.order_id.trim()) {
            return Err("e2_worker_evidence_order_already_recorded".to_string());
        }

        let hard = ev_any.requires_secondary_governance_v1();
        let candidate_delta_raw = e2_worker_evidence_delta_any_v1(ev_any);
        let applied_delta = if hard { 0 } else { candidate_delta_raw };
        let candidate_delta = if hard { candidate_delta_raw } else { 0 };
        let worker_hex = crate::keyfmt::pk_hex_from_any(&ev.worker_node_pubkey)
            .map_err(|e| format!("e2_worker_evidence_worker_pubkey_invalid:{e}"))?;
        let operator_wallet_hex = crate::keyfmt::pk_hex_from_any(&ev.operator_wallet_pubkey)
            .map_err(|e| format!("e2_worker_evidence_operator_wallet_pubkey_invalid:{e}"))?;
        if operator_wallet_hex == worker_hex {
            return Err(
                "e2_worker_evidence_operator_wallet_must_be_distinct_from_worker_node".to_string(),
            );
        }

        if matches!(ev_any, E2WorkerExecutionEvidenceAnyV1::V2(_))
            && ev.order_created_height == 0
            && ev.order_claimed_height == 0
            && ev.order_terminal_height == 0
            && !e2_worker_job_kind_is_probe_bootstrap_v1(&ev.job_kind)
        {
            return Err("e2_worker_probe_bootstrap_job_kind_not_allowlisted".to_string());
        }

        if Self::e2_worker_evidence_is_bootstrap_probe_success_v1(ev_any, &ev) {
            if ev.execution_status.trim() != "COMPLETED"
                || ev.failure_class.trim() != FAILURE_SUCCESS
            {
                return Err("e2_worker_probe_bootstrap_must_be_completed_success".to_string());
            }
            let result_hash = ev.result_hash.as_deref().map(str::trim).unwrap_or("");
            if result_hash.is_empty() {
                return Err("e2_worker_probe_bootstrap_result_hash_required".to_string());
            }
            let expected_order_id = expected_e2_worker_probe_bootstrap_order_id_v1(
                &ev.chain_id,
                &ev.genesis_hash,
                &ev.worker_node_pubkey,
                &ev.operator_wallet_pubkey,
                &ev.job_id,
                result_hash,
            );
            if !ev.order_id.trim().eq_ignore_ascii_case(&expected_order_id) {
                return Err("e2_worker_probe_bootstrap_order_id_mismatch".to_string());
            }
            let payer_hex = crate::keyfmt::pk_hex_from_any(&ev.payer_wallet)
                .map_err(|e| format!("e2_worker_evidence_payer_wallet_invalid:{e}"))?;
            if payer_hex != operator_wallet_hex {
                return Err("e2_worker_probe_bootstrap_payer_must_be_operator_wallet".to_string());
            }
            let (finalized_height, finalized_hash) = self.finalized_view();
            let finalized_hash = finalized_hash.trim().to_string();
            if finalized_hash.is_empty() {
                return Err("e2_worker_evidence_finalized_hash_missing".to_string());
            }
            if !self.e2_attester_is_authorized(&ev.attester_pubkey, finalized_height) {
                return Err("e2_worker_evidence_attester_not_authorized".to_string());
            }
            if !self.e2_worker_operator_binding_is_authorized_finalized_v1(
                &worker_hex,
                &operator_wallet_hex,
                finalized_height,
            ) {
                return Err("e2_worker_evidence_unbound_worker_operator_pair_finalized".to_string());
            }
            return Ok(E2WorkerEvidenceValidationContextV1 {
                finalized_height,
                finalized_hash,
                source_commitment: "finalized".to_string(),
                hard_evidence: hard,
                applied_delta,
                candidate_delta,
                worker_hex,
                operator_wallet_hex,
            });
        }

        let lookup = crate::compute_contract::compute_order_lookup_for_finalized_chain(
            self,
            ev.order_id.trim(),
        )?;
        let finalized_height = lookup.finalized_height;
        let finalized_hash = lookup.finalized_hash.trim().to_string();
        if finalized_hash.is_empty() {
            return Err("e2_worker_evidence_finalized_hash_missing".to_string());
        }
        let Some(order) = lookup.order else {
            return Err("e2_worker_evidence_order_not_found_finalized".to_string());
        };
        if order.order_id != ev.order_id {
            return Err("e2_worker_evidence_order_lookup_mismatch".to_string());
        }
        let status_norm = format!("{:?}", order.status).to_ascii_lowercase();
        let terminal_ok = status_norm.contains("completed") || status_norm.contains("failed");
        if !terminal_ok {
            return Err("e2_worker_evidence_order_not_terminal_finalized".to_string());
        }
        if order.claimed_worker.as_deref() != Some(ev.worker_node_pubkey.trim()) {
            return Err("e2_worker_evidence_worker_not_claimed_worker".to_string());
        }
        if order.payer.trim() != ev.payer_wallet.trim() {
            return Err("e2_worker_evidence_payer_mismatch".to_string());
        }
        if order.created_height != ev.order_created_height {
            return Err("e2_worker_evidence_created_height_mismatch".to_string());
        }
        if order.claim_height.unwrap_or(0) != ev.order_claimed_height {
            return Err("e2_worker_evidence_claim_height_mismatch".to_string());
        }
        if order.completed_height.unwrap_or(0) != ev.order_terminal_height {
            return Err("e2_worker_evidence_terminal_height_mismatch".to_string());
        }
        if ev.order_terminal_height > finalized_height {
            return Err("e2_worker_evidence_terminal_not_finalized".to_string());
        }
        if order.max_time_ms != ev.max_time_ms {
            return Err("e2_worker_evidence_max_time_ms_mismatch".to_string());
        }
        let execution_status = ev.execution_status.trim();
        let failure_class = ev.failure_class.trim();
        validate_e2_worker_evidence_status_binding_v1(
            &status_norm,
            execution_status,
            failure_class,
        )?;
        if order.result_hash.as_deref() != ev.result_hash.as_deref() {
            return Err("e2_worker_evidence_result_hash_mismatch".to_string());
        }
        if order.artifact_root_hash.as_deref() != ev.artifact_root_hash.as_deref() {
            return Err("e2_worker_evidence_artifact_root_hash_mismatch".to_string());
        }
        if order.receipt_hash.as_deref() != ev.receipt_hash.as_deref() {
            return Err("e2_worker_evidence_receipt_hash_mismatch".to_string());
        }
        if !self.e2_attester_is_authorized(&ev.attester_pubkey, finalized_height) {
            return Err("e2_worker_evidence_attester_not_authorized".to_string());
        }

        // E2 worker identity is not L1 validator identity. The canonical authorization
        // edge for execution evidence is the finalized worker/operator binding plus
        // an authorized attester; requiring worker_node_pubkey to be in the L1
        // validator set would incorrectly restrict Compute Hub workers to consensus
        // validators and would deadlock non-validator worker onboarding.
        if !self.e2_worker_operator_binding_is_authorized_finalized_v1(
            &worker_hex,
            &operator_wallet_hex,
            finalized_height,
        ) {
            return Err("e2_worker_evidence_unbound_worker_operator_pair_finalized".to_string());
        }
        Ok(E2WorkerEvidenceValidationContextV1 {
            finalized_height,
            finalized_hash,
            source_commitment: "finalized".to_string(),
            hard_evidence: hard,
            applied_delta,
            candidate_delta,
            worker_hex,
            operator_wallet_hex,
        })
    }

    /// Local validation only. This does not mutate canonical L1 reputation state.
    /// Canonical ingestion must go through a governance proposal/block path.
    pub fn preview_e2_worker_reputation_evidence_v1(
        &self,
        ev: &E2WorkerExecutionEvidenceAnyV1,
    ) -> Result<E2WorkerEvidenceApplyOutcomeV1, String> {
        if self
            .e2_worker_reputation_evidence_ids
            .contains(ev.evidence_hash().trim())
        {
            let hard = ev.requires_secondary_governance_v1();
            return Ok(E2WorkerEvidenceApplyOutcomeV1 {
                status: "duplicate".to_string(),
                evidence_id: ev.evidence_hash().to_string(),
                applied_delta: 0,
                candidate_delta: 0,
                requires_governance: hard,
                hard_evidence: hard,
                worker_node_pubkey: ev.worker_node_pubkey().to_string(),
                order_id: ev.order_id().to_string(),
            });
        }
        let validation = self.validate_e2_worker_reputation_evidence_context_v1(ev)?;
        Ok(E2WorkerEvidenceApplyOutcomeV1 {
            status: "validated_governance_required".to_string(),
            evidence_id: ev.evidence_hash().to_string(),
            applied_delta: validation.applied_delta,
            candidate_delta: validation.candidate_delta,
            requires_governance: true,
            hard_evidence: validation.hard_evidence,
            worker_node_pubkey: ev.worker_node_pubkey().to_string(),
            order_id: ev.order_id().to_string(),
        })
    }

    /// Canonical standard L1 transaction apply path for ordinary E2 execution evidence.
    /// This is the non-governance path used by compute `worker_evidence_submit_v1` txs.
    /// Hard/governance-required evidence is recorded with `applied_delta=0` and
    /// `candidate_delta` set for downstream council review; it never mutates worker/operator
    /// fault counters, eligibility counters, or reputation totals automatically. Ordinary
    /// evidence updates worker/operator reputation once included on L1 and finalized by block finality.
    pub fn apply_e2_worker_reputation_evidence_from_standard_tx_v1(
        &mut self,
        ev: E2WorkerExecutionEvidenceAnyV1,
        accepted_at_height: u64,
    ) -> Result<E2WorkerEvidenceApplyOutcomeV1, String> {
        if self
            .e2_worker_reputation_evidence_ids
            .contains(ev.evidence_hash().trim())
        {
            return Err("e2_worker_evidence_duplicate".to_string());
        }
        if self.e2_worker_reputation_order_already_recorded_v1(ev.order_id().trim()) {
            return Err("e2_worker_evidence_order_already_recorded".to_string());
        }
        self.apply_e2_worker_reputation_evidence_core_v1(ev, accepted_at_height)
    }

    /// Canonical governed/manual apply path. Kept explicit so callsites do not
    /// confuse governance-proposed evidence with the ordinary signed standard-tx path.
    pub fn apply_e2_worker_reputation_evidence_from_governance_v1(
        &mut self,
        ev: E2WorkerExecutionEvidenceAnyV1,
        governance_applied_height: u64,
    ) -> Result<E2WorkerEvidenceApplyOutcomeV1, String> {
        self.apply_e2_worker_reputation_evidence_core_v1(ev, governance_applied_height)
    }

    fn apply_e2_worker_reputation_evidence_core_v1(
        &mut self,
        ev: E2WorkerExecutionEvidenceAnyV1,
        governance_applied_height: u64,
    ) -> Result<E2WorkerEvidenceApplyOutcomeV1, String> {
        if self
            .e2_worker_reputation_evidence_ids
            .contains(ev.evidence_hash().trim())
        {
            let hard = ev.requires_secondary_governance_v1();
            return Ok(E2WorkerEvidenceApplyOutcomeV1 {
                status: "duplicate".to_string(),
                evidence_id: ev.evidence_hash().to_string(),
                applied_delta: 0,
                candidate_delta: 0,
                requires_governance: hard,
                hard_evidence: hard,
                worker_node_pubkey: ev.worker_node_pubkey().to_string(),
                order_id: ev.order_id().to_string(),
            });
        }

        let validation = self.validate_e2_worker_reputation_evidence_context_v1(&ev)?;
        let ev_legacy = ev.legacy_projection_v1();
        let hard = validation.hard_evidence;
        let delta = validation.applied_delta;
        let candidate_delta = validation.candidate_delta;
        let worker_hex = validation.worker_hex.clone();
        let operator_wallet_hex = validation.operator_wallet_hex.clone();
        let requires_secondary_governance = hard;
        let automatic_reputation_effects = !requires_secondary_governance;
        let failure_class = ev.failure_class().trim().to_string();
        let update_worker_fault_counters = ev.updates_worker_fault_counters_v1();
        let job_is_probe = e2_worker_job_kind_is_probe_bootstrap_v1(ev.job_kind());

        if automatic_reputation_effects {
            if let Some(gov) = self.governance.as_mut() {
                let rep_snapshot = {
                    let rep = gov
                        .validator_reputation
                        .entry(worker_hex.clone())
                        .or_insert_with(Default::default);
                    rep.reset_recent_reputation_window_if_stale(governance_applied_height);
                    // Accepted E2 evidence is a canonical L1 observation of this worker.
                    // Keep last_seen_height aligned with finalized evidence progress so
                    // worker uptime windows cannot remain stale after batched evidence is
                    // applied. This does not imply block production.
                    rep.record_seen_at_height(governance_applied_height);
                    rep.accepted_run_evidence_count =
                        rep.accepted_run_evidence_count.saturating_add(1);
                    if failure_class == FAILURE_SUCCESS {
                        rep.consecutive_failures = 0;
                        rep.consecutive_timeouts = 0;
                    } else if update_worker_fault_counters {
                        rep.consecutive_failures = rep.consecutive_failures.saturating_add(1);
                        if failure_class == FAILURE_TIMEOUT {
                            rep.timeout_count = rep.timeout_count.saturating_add(1);
                            rep.recent_timeout_count = rep.recent_timeout_count.saturating_add(1);
                            rep.consecutive_timeouts = rep.consecutive_timeouts.saturating_add(1);
                        } else {
                            rep.failure_count = rep.failure_count.saturating_add(1);
                            rep.recent_failure_count = rep.recent_failure_count.saturating_add(1);
                            rep.consecutive_timeouts = 0;
                        }
                        if matches!(
                            failure_class.as_str(),
                            FAILURE_BAD_RESULT_HASH
                                | FAILURE_INVALID_RECEIPT
                                | FAILURE_SIGNATURE_INVALID
                        ) {
                            rep.recent_invalid_output_count =
                                rep.recent_invalid_output_count.saturating_add(1);
                        }
                        if hard {
                            rep.last_hard_fault_height = Some(governance_applied_height);
                        }
                        if job_is_probe {
                            rep.failed_recovery_probe_count =
                                rep.failed_recovery_probe_count.saturating_add(1);
                        }
                    }
                    if !hard {
                        if delta > 0 {
                            rep.accepted_positive_run_evidence_count =
                                rep.accepted_positive_run_evidence_count.saturating_add(1);
                        } else if delta < 0 {
                            rep.accepted_negative_run_evidence_count =
                                rep.accepted_negative_run_evidence_count.saturating_add(1);
                            rep.misbehavior_points = rep
                                .misbehavior_points
                                .saturating_add(delta.unsigned_abs().min(10));
                        }
                        rep.accepted_run_evidence_delta_total = rep
                            .accepted_run_evidence_delta_total
                            .saturating_add(delta as i64);
                    }
                    rep.last_run_evidence_height = Some(governance_applied_height);
                    rep.last_run_evidence_id = Some(ev_legacy.evidence_hash.clone());
                    rep.clone()
                };

                let wallet = gov
                    .wallet_reputation
                    .entry(operator_wallet_hex.clone())
                    .or_insert_with(|| {
                        crate::governance::WalletGovReputation::from_validator_reputation(
                            &operator_wallet_hex,
                            None,
                            false,
                            &rep_snapshot,
                        )
                    });
                wallet.wallet_pubkey = operator_wallet_hex.clone();
                wallet
                    .note_operator_worker_binding_v2(worker_hex.clone(), governance_applied_height);
                wallet.reset_recent_reputation_window_if_stale(governance_applied_height);
                // Mirror the canonical evidence observation on the operator wallet surface.
                wallet.last_seen_height = wallet.last_seen_height.max(governance_applied_height);
                wallet.accepted_run_evidence_count =
                    wallet.accepted_run_evidence_count.saturating_add(1);
                if failure_class == FAILURE_SUCCESS {
                    wallet.consecutive_failures = 0;
                    wallet.consecutive_timeouts = 0;
                } else if update_worker_fault_counters {
                    wallet.consecutive_failures = wallet.consecutive_failures.saturating_add(1);
                    if failure_class == FAILURE_TIMEOUT {
                        wallet.timeout_count = wallet.timeout_count.saturating_add(1);
                        wallet.recent_timeout_count = wallet.recent_timeout_count.saturating_add(1);
                        wallet.consecutive_timeouts = wallet.consecutive_timeouts.saturating_add(1);
                    } else {
                        wallet.failure_count = wallet.failure_count.saturating_add(1);
                        wallet.recent_failure_count = wallet.recent_failure_count.saturating_add(1);
                        wallet.consecutive_timeouts = 0;
                    }
                    if matches!(
                        failure_class.as_str(),
                        FAILURE_BAD_RESULT_HASH
                            | FAILURE_INVALID_RECEIPT
                            | FAILURE_SIGNATURE_INVALID
                    ) {
                        wallet.recent_invalid_output_count =
                            wallet.recent_invalid_output_count.saturating_add(1);
                    }
                    if hard {
                        wallet.last_hard_fault_height = Some(governance_applied_height);
                    }
                    if job_is_probe {
                        wallet.failed_recovery_probe_count =
                            wallet.failed_recovery_probe_count.saturating_add(1);
                    }
                }
                if !hard {
                    if delta > 0 {
                        wallet.accepted_positive_run_evidence_count = wallet
                            .accepted_positive_run_evidence_count
                            .saturating_add(1);
                    } else if delta < 0 {
                        wallet.accepted_negative_run_evidence_count = wallet
                            .accepted_negative_run_evidence_count
                            .saturating_add(1);
                        wallet.misbehavior_points = wallet
                            .misbehavior_points
                            .saturating_add(delta.unsigned_abs().min(10));
                    }
                    wallet.accepted_run_evidence_delta_total = wallet
                        .accepted_run_evidence_delta_total
                        .saturating_add(delta as i64);
                }
                wallet.last_run_evidence_height = Some(governance_applied_height);
                wallet.last_run_evidence_id = Some(ev_legacy.evidence_hash.clone());
            }
        }

        self.e2_worker_reputation_evidence_ids
            .insert(ev_legacy.evidence_hash.clone());
        self.e2_worker_reputation_order_ids
            .insert(ev_legacy.order_id.trim().to_ascii_lowercase());

        let history_key = e2_worker_history_key_v1(&worker_hex, &operator_wallet_hex);
        if automatic_reputation_effects {
            self.e2_worker_reputation_history_index
                .entry(history_key)
                .or_default()
                .observe_evidence_v1(
                    &ev,
                    governance_applied_height,
                    validation.finalized_height,
                    &validation.source_commitment,
                );
        }

        self.e2_worker_reputation_evidence_log
            .push(E2WorkerCanonicalEvidenceRecordV1 {
                evidence_id: ev_legacy.evidence_hash.clone(),
                evidence: ev.clone(),
                accepted_at_height: governance_applied_height,
                applied_delta: delta,
                candidate_delta,
                hard_evidence: hard,
                requires_governance: requires_secondary_governance,
                validated_against_finalized_height: validation.finalized_height,
                validated_against_finalized_hash: validation.finalized_hash.clone(),
                source_commitment: validation.source_commitment.clone(),
            });
        self.trim_e2_worker_reputation_evidence_log_v1();

        Ok(E2WorkerEvidenceApplyOutcomeV1 {
            status: if requires_secondary_governance {
                "recorded_pending_secondary_governance"
            } else {
                "applied"
            }
            .to_string(),
            evidence_id: ev_legacy.evidence_hash,
            applied_delta: delta,
            candidate_delta,
            requires_governance: requires_secondary_governance,
            hard_evidence: hard,
            worker_node_pubkey: ev_legacy.worker_node_pubkey,
            order_id: ev_legacy.order_id,
        })
    }

    /// Backward-compatible name retained as a local preview only.
    /// It must not be used to mutate canonical L1 reputation state.
    pub fn submit_e2_worker_reputation_evidence_v1(
        &mut self,
        ev: E2WorkerExecutionEvidenceV1,
    ) -> Result<E2WorkerEvidenceApplyOutcomeV1, String> {
        self.preview_e2_worker_reputation_evidence_v1(&E2WorkerExecutionEvidenceAnyV1::V1(ev))
    }

    fn trim_e2_worker_reputation_evidence_log_v1(&mut self) {
        if self.e2_worker_reputation_evidence_log.len() > 1024 {
            let excess = self.e2_worker_reputation_evidence_log.len() - 1024;
            // Keep the audit log bounded, but never remove IDs from the canonical
            // replay-protection set. Otherwise an old evidence could be replayed
            // after it falls out of the visible audit window.
            self.e2_worker_reputation_evidence_log.drain(0..excess);
        }
    }

    pub fn e2_worker_reputation_evidence_snapshot(
        &self,
        limit: usize,
    ) -> Vec<E2WorkerCanonicalEvidenceRecordV1> {
        let n = limit.min(1024);
        self.e2_worker_reputation_evidence_log
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> E2WorkerExecutionEvidenceV1 {
        E2WorkerExecutionEvidenceV1 {
            format_version: E2_WORKER_EVIDENCE_FORMAT_VERSION_V1.to_string(),
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
            evidence_hash: String::new(),
            signature: String::new(),
        }
    }

    fn sample_evidence_v2() -> E2WorkerExecutionEvidenceV2 {
        let v1 = sample_evidence();
        E2WorkerExecutionEvidenceV2 {
            format_version: E2_WORKER_EVIDENCE_FORMAT_VERSION_V2.to_string(),
            chain_id: v1.chain_id,
            genesis_hash: v1.genesis_hash,
            e2_contract_version: v1.e2_contract_version,
            order_id: v1.order_id,
            job_id: v1.job_id,
            job_kind: v1.job_kind,
            worker_node_pubkey: v1.worker_node_pubkey,
            operator_wallet_pubkey: v1.operator_wallet_pubkey,
            payer_wallet: v1.payer_wallet,
            order_created_height: v1.order_created_height,
            order_claimed_height: v1.order_claimed_height,
            order_terminal_height: v1.order_terminal_height,
            result_hash: v1.result_hash,
            artifact_root_hash: v1.artifact_root_hash,
            receipt_hash: v1.receipt_hash,
            execution_status: v1.execution_status,
            failure_class: v1.failure_class,
            fault_domain: FAULT_WORKER.to_string(),
            penalty_effect: EFFECT_POSITIVE.to_string(),
            worker_fault: false,
            verifier_verdict: VERDICT_ACCEPT_POSITIVE.to_string(),
            taxonomy_version: WORKER_PENALTY_TAXONOMY_VERSION_V1.to_string(),
            sla_ms: v1.sla_ms,
            max_time_ms: v1.max_time_ms,
            coordinator_id: v1.coordinator_id,
            attester_pubkey: v1.attester_pubkey,
            evidence_timestamp_ms: v1.evidence_timestamp_ms,
            evidence_hash: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn bootstrap_probe_job_kind_is_strict_allowlist() {
        for accepted in ["probe", "PROBE", " probe:v1 ", "bootstrap_probe_v1"] {
            assert!(
                e2_worker_job_kind_is_probe_bootstrap_v1(accepted),
                "accepted={accepted}"
            );
        }
        for rejected in [
            "nonprobe",
            "probe-real",
            "health_probe",
            "myprobe",
            "bootstrap-probe-v1",
            "",
        ] {
            assert!(
                !e2_worker_job_kind_is_probe_bootstrap_v1(rejected),
                "rejected={rejected}"
            );
        }
    }

    #[test]
    fn bootstrap_probe_order_id_is_domain_separated_and_deterministic() {
        let mut ev = sample_evidence();
        ev.job_kind = "probe".to_string();
        ev.order_created_height = 0;
        ev.order_claimed_height = 0;
        ev.order_terminal_height = 0;
        let expected = expected_e2_worker_probe_bootstrap_order_id_for_evidence_v1(&ev)
            .expect("sample evidence has result_hash");
        assert_eq!(expected.len(), 64);
        assert!(expected.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(expected, ev.order_id);

        let mut changed = ev.clone();
        changed.result_hash = Some("44".repeat(32));
        assert_ne!(
            expected,
            expected_e2_worker_probe_bootstrap_order_id_for_evidence_v1(&changed).unwrap()
        );
    }

    #[test]
    fn history_stats_do_not_classify_nonprobe_substrings_as_probe() {
        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        let mut ev = sample_evidence();
        ev.job_kind = "nonprobe".to_string();
        ev.execution_status = "COMPLETED".to_string();
        ev.failure_class = FAILURE_SUCCESS.to_string();
        stats.observe_evidence_v1(&E2WorkerExecutionEvidenceAnyV1::V1(ev), 10, 9, "finalized");
        assert_eq!(stats.successful_probe_jobs, 0);
        assert_eq!(stats.successful_real_jobs, 1);
    }

    #[test]
    fn evidence_v2_hash_binds_taxonomy_fields() {
        let mut ev = sample_evidence_v2();
        let h1 = expected_e2_worker_evidence_id_v2(&ev);
        ev.fault_domain = FAULT_INPUT.to_string();
        let h2 = expected_e2_worker_evidence_id_v2(&ev);
        assert_ne!(h1, h2);
    }

    #[test]
    fn evidence_v2_rejects_unknown_taxonomy_version() {
        let mut ev = sample_evidence_v2();
        ev.taxonomy_version = "worker-penalty-taxonomy-v999".to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_bad_taxonomy_version"
        );
    }

    #[test]
    fn unknown_failure_is_no_worker_penalty() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_UNKNOWN.to_string();
        ev.fault_domain = FAULT_UNKNOWN.to_string();
        ev.penalty_effect = EFFECT_NO_WORKER_PENALTY.to_string();
        ev.worker_fault = false;
        ev.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
            0
        );
    }

    #[test]
    fn chain_finality_and_input_errors_do_not_penalize_worker() {
        for (class, domain) in [
            (FAILURE_CHAIN_FINALITY_ERROR, FAULT_CHAIN),
            (FAILURE_INPUT_INVALID, FAULT_INPUT),
        ] {
            let mut ev = sample_evidence_v2();
            ev.execution_status = "FAILED".to_string();
            ev.failure_class = class.to_string();
            ev.fault_domain = domain.to_string();
            ev.penalty_effect = EFFECT_NO_WORKER_PENALTY.to_string();
            ev.worker_fault = false;
            ev.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
            assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
            assert_eq!(
                e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
                0
            );
        }
    }

    #[test]
    fn signature_invalid_is_hard_penalty_candidate() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_SIGNATURE_INVALID.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        assert!(e2_worker_evidence_is_hard_v1(&ev.failure_class));
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
            -100
        );
    }

    #[test]
    fn e2_v2_accepts_e2_positive_verdict_accept_positive() {
        let mut ev = sample_evidence_v2();
        ev.penalty_effect = EFFECT_POSITIVE.to_string();
        ev.worker_fault = false;
        ev.verifier_verdict = VERDICT_ACCEPT_POSITIVE.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
    }

    #[test]
    fn e2_v2_accepts_worker_penalty_candidate_for_soft_medium_hard() {
        for (class, effect, expected_delta) in [
            (FAILURE_TIMEOUT, EFFECT_SOFT_PENALTY, -10),
            (FAILURE_WORKER_CRASH, EFFECT_MEDIUM_PENALTY, -30),
            (FAILURE_SIGNATURE_INVALID, EFFECT_HARD_PENALTY, -100),
        ] {
            let mut ev = sample_evidence_v2();
            ev.execution_status = "FAILED".to_string();
            ev.failure_class = class.to_string();
            ev.fault_domain = FAULT_WORKER.to_string();
            ev.penalty_effect = effect.to_string();
            ev.worker_fault = true;
            ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
            assert!(
                validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok(),
                "class={class} effect={effect}"
            );
            assert_eq!(
                e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
                expected_delta
            );
        }
    }

    #[test]
    fn e2_v2_rejects_legacy_accepted_verdict() {
        let mut ev = sample_evidence_v2();
        ev.verifier_verdict = "ACCEPTED".to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_bad_verifier_verdict"
        );
    }

    #[test]
    fn e2_v2_rejects_legacy_soft_medium_hard_specific_candidate_verdict() {
        for legacy in [
            "SOFT_PENALTY_CANDIDATE",
            "MEDIUM_PENALTY_CANDIDATE",
            "HARD_PENALTY_CANDIDATE",
        ] {
            let mut ev = sample_evidence_v2();
            ev.execution_status = "FAILED".to_string();
            ev.failure_class = FAILURE_TIMEOUT.to_string();
            ev.fault_domain = FAULT_WORKER.to_string();
            ev.penalty_effect = EFFECT_SOFT_PENALTY.to_string();
            ev.worker_fault = true;
            ev.verifier_verdict = legacy.to_string();
            assert_eq!(
                validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
                "e2_worker_evidence_v2_bad_verifier_verdict",
                "legacy={legacy}"
            );
        }
    }

    #[test]
    fn e2_v2_rejects_penalty_effect_verifier_verdict_mismatch() {
        let mut positive = sample_evidence_v2();
        positive.penalty_effect = EFFECT_POSITIVE.to_string();
        positive.worker_fault = false;
        positive.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&positive).unwrap_err(),
            "e2_worker_evidence_v2_verifier_verdict_mismatch"
        );

        let mut hard = sample_evidence_v2();
        hard.execution_status = "FAILED".to_string();
        hard.failure_class = FAILURE_SIGNATURE_INVALID.to_string();
        hard.fault_domain = FAULT_WORKER.to_string();
        hard.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        hard.worker_fault = true;
        hard.verifier_verdict = VERDICT_ACCEPT_POSITIVE.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&hard).unwrap_err(),
            "e2_worker_evidence_v2_verifier_verdict_mismatch"
        );
    }

    #[test]
    fn e2_v2_rejects_success_with_hard_penalty() {
        let mut ev = sample_evidence_v2();
        ev.failure_class = FAILURE_SUCCESS.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_penalty_effect_mismatch"
        );
    }

    #[test]
    fn e2_v2_rejects_chain_finality_as_worker_penalty() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_CHAIN_FINALITY_ERROR.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_SOFT_PENALTY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_invalid_failure_domain_combination"
        );
    }

    #[test]
    fn e2_v2_rejects_worker_fault_true_for_positive_success() {
        let mut ev = sample_evidence_v2();
        ev.failure_class = FAILURE_SUCCESS.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_POSITIVE.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_ACCEPT_POSITIVE.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_worker_fault_mismatch"
        );
    }

    #[test]
    fn e2_v2_accepts_replay_attempt_as_reject_only_worker_fault() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_REPLAY_ATTEMPT.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_REJECT_ONLY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_REJECT_ONLY.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
            0
        );
    }

    #[test]
    fn e2_v2_accepts_double_claim_as_governance_required_worker_fault() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_DOUBLE_CLAIM.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_GOVERNANCE_REQUIRED.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_GOVERNANCE_REQUIRED.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        assert!(e2_worker_evidence_is_hard_v1(&ev.failure_class));
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
            0
        );
    }

    #[test]
    fn e2_v2_reject_only_does_not_increment_worker_fault_counters() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_REPLAY_ATTEMPT.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_REJECT_ONLY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_REJECT_ONLY.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());

        let ev_any = E2WorkerExecutionEvidenceAnyV1::V2(ev);
        assert!(ev_any.worker_fault());
        assert!(!ev_any.updates_worker_fault_counters_v1());
        assert!(!ev_any.requires_secondary_governance_v1());
        assert_eq!(e2_worker_evidence_delta_any_v1(&ev_any), 0);

        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        stats.observe_evidence_v1(&ev_any, 123, 123, "finalized");
        assert_eq!(stats.consecutive_failures, 0);
        assert_eq!(stats.recent_failure_count, 0);
        assert_eq!(stats.failed_recovery_probe_count, 0);
        assert_eq!(stats.last_hard_fault_height, None);
    }

    #[test]
    fn e2_v2_identity_mismatch_coordinator_does_not_require_secondary_governance() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_IDENTITY_MISMATCH.to_string();
        ev.fault_domain = FAULT_COORDINATOR.to_string();
        ev.penalty_effect = EFFECT_NO_WORKER_PENALTY.to_string();
        ev.worker_fault = false;
        ev.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());

        let ev_any = E2WorkerExecutionEvidenceAnyV1::V2(ev);
        assert!(!ev_any.worker_fault());
        assert!(!ev_any.updates_worker_fault_counters_v1());
        assert!(!ev_any.requires_secondary_governance_v1());
        assert_eq!(e2_worker_evidence_delta_any_v1(&ev_any), 0);
    }

    #[test]
    fn e2_v2_hard_penalty_still_requires_secondary_governance() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_SIGNATURE_INVALID.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());

        let ev_any = E2WorkerExecutionEvidenceAnyV1::V2(ev);
        assert!(ev_any.updates_worker_fault_counters_v1());
        assert!(ev_any.requires_secondary_governance_v1());
        assert_eq!(e2_worker_evidence_delta_any_v1(&ev_any), -100);
    }

    #[test]
    fn e2_v2_governance_required_requires_secondary_governance() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_MALICIOUS_BEHAVIOR.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_GOVERNANCE_REQUIRED.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_GOVERNANCE_REQUIRED.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());

        let ev_any = E2WorkerExecutionEvidenceAnyV1::V2(ev);
        assert!(ev_any.updates_worker_fault_counters_v1());
        assert!(ev_any.requires_secondary_governance_v1());
        assert_eq!(e2_worker_evidence_delta_any_v1(&ev_any), 0);
    }

    fn assert_invalid_failure_domain_combo(
        failure_class: &str,
        fault_domain: &str,
        penalty_effect: &str,
        worker_fault: bool,
        verifier_verdict: &str,
    ) {
        let mut ev = sample_evidence_v2();
        ev.execution_status = if failure_class == FAILURE_SUCCESS {
            "COMPLETED".to_string()
        } else {
            "FAILED".to_string()
        };
        ev.failure_class = failure_class.to_string();
        ev.fault_domain = fault_domain.to_string();
        ev.penalty_effect = penalty_effect.to_string();
        ev.worker_fault = worker_fault;
        ev.verifier_verdict = verifier_verdict.to_string();
        assert_eq!(
            validate_e2_worker_evidence_v2_taxonomy(&ev).unwrap_err(),
            "e2_worker_evidence_v2_invalid_failure_domain_combination",
            "class={failure_class} domain={fault_domain}"
        );
    }

    #[test]
    fn e2_v2_rejects_success_with_non_worker_domain() {
        for domain in [FAULT_INPUT, FAULT_CHAIN, FAULT_INFRA, FAULT_UNKNOWN] {
            assert_invalid_failure_domain_combo(
                FAILURE_SUCCESS,
                domain,
                EFFECT_NO_WORKER_PENALTY,
                false,
                VERDICT_NO_WORKER_PENALTY,
            );
        }
    }

    #[test]
    fn e2_v2_rejects_timeout_with_chain_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_TIMEOUT,
            FAULT_CHAIN,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_rejects_worker_crash_with_input_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_WORKER_CRASH,
            FAULT_INPUT,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_rejects_bad_result_hash_with_infra_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_BAD_RESULT_HASH,
            FAULT_INFRA,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_rejects_double_claim_with_unknown_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_DOUBLE_CLAIM,
            FAULT_UNKNOWN,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_rejects_input_invalid_with_worker_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_INPUT_INVALID,
            FAULT_WORKER,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_rejects_chain_finality_with_worker_domain() {
        assert_invalid_failure_domain_combo(
            FAILURE_CHAIN_FINALITY_ERROR,
            FAULT_WORKER,
            EFFECT_NO_WORKER_PENALTY,
            false,
            VERDICT_NO_WORKER_PENALTY,
        );
    }

    #[test]
    fn e2_v2_accepts_identity_mismatch_coordinator_as_no_worker_penalty() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_IDENTITY_MISMATCH.to_string();
        ev.fault_domain = FAULT_COORDINATOR.to_string();
        ev.penalty_effect = EFFECT_NO_WORKER_PENALTY.to_string();
        ev.worker_fault = false;
        ev.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
    }

    #[test]
    fn v2_non_worker_fault_records_no_worker_penalty_or_fault_counters() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_CHAIN_FINALITY_ERROR.to_string();
        ev.fault_domain = FAULT_CHAIN.to_string();
        ev.penalty_effect = EFFECT_NO_WORKER_PENALTY.to_string();
        ev.worker_fault = false;
        ev.verifier_verdict = VERDICT_NO_WORKER_PENALTY.to_string();
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev.clone())),
            0
        );
        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        stats.observe_evidence_v1(
            &E2WorkerExecutionEvidenceAnyV1::V2(ev),
            100,
            100,
            "finalized",
        );
        assert_eq!(stats.consecutive_failures, 0);
        assert_eq!(stats.consecutive_timeouts, 0);
        assert_eq!(stats.recent_failure_count, 0);
        assert_eq!(stats.recent_timeout_count, 0);
    }

    #[test]
    fn double_claim_records_governance_candidate_without_auto_delta() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_DOUBLE_CLAIM.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_GOVERNANCE_REQUIRED.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_GOVERNANCE_REQUIRED.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        assert!(e2_worker_evidence_is_hard_v1(&ev.failure_class));
        assert_eq!(
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev)),
            0
        );
    }

    #[test]
    fn evidence_hash_is_deterministic_and_excludes_signature() {
        let mut ev = sample_evidence();
        let h1 = expected_e2_worker_evidence_id_v1(&ev);
        ev.signature = "changed".to_string();
        let h2 = expected_e2_worker_evidence_id_v1(&ev);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hard_classes_require_governance() {
        assert!(e2_worker_evidence_is_hard_v1("DOUBLE_CLAIM"));
        assert!(e2_worker_evidence_is_hard_v1("PROTOCOL_VIOLATION"));
        assert!(!e2_worker_evidence_is_hard_v1("TIMEOUT"));
    }

    #[test]
    fn hard_evidence_delta_is_zero_and_pending_governance() {
        let mut ev = sample_evidence();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = "DOUBLE_CLAIM".to_string();
        assert!(e2_worker_evidence_is_hard_v1(&ev.failure_class));
        assert_eq!(e2_worker_evidence_delta_v1(&ev), 0);
    }

    #[test]
    fn non_hard_evidence_delta_direction_is_explicit() {
        let mut ev = sample_evidence();
        ev.execution_status = "COMPLETED".to_string();
        ev.failure_class = "SUCCESS".to_string();
        assert_eq!(e2_worker_evidence_delta_v1(&ev), 5);

        ev.execution_status = "FAILED".to_string();
        ev.failure_class = "WORKER_CRASH".to_string();
        assert_eq!(e2_worker_evidence_delta_v1(&ev), -30);
    }

    #[test]
    fn status_binding_rejects_success_for_failed_order() {
        assert_eq!(
            validate_e2_worker_evidence_status_binding_v1("Failed", "COMPLETED", "SUCCESS")
                .unwrap_err(),
            "e2_worker_evidence_status_mismatch_completed"
        );
    }

    #[test]
    fn status_binding_rejects_failure_for_completed_order() {
        assert_eq!(
            validate_e2_worker_evidence_status_binding_v1("Completed", "FAILED", "TIMEOUT")
                .unwrap_err(),
            "e2_worker_evidence_status_mismatch_failed"
        );
    }

    #[test]
    fn e2_worker_evidence_metadata_tokens_are_bounded() {
        assert!(e2_worker_evidence_token_v1("job-1/wasm:v1", "job_id", 128).is_ok());
        assert!(e2_worker_evidence_token_v1("", "job_id", 128).is_err());
        assert!(e2_worker_evidence_token_v1(&"x".repeat(129), "job_id", 128).is_err());
        assert!(e2_worker_evidence_token_v1("bad space", "job_id", 128).is_err());
    }

    #[test]
    fn evidence_log_trim_preserves_replay_protection_ids_and_order_ids() {
        let mut chain = crate::Blockchain::new();
        for i in 0..1030usize {
            let mut ev = sample_evidence();
            ev.order_id = format!("{:064x}", i);
            ev.evidence_hash = format!("{:064x}", i);
            chain
                .e2_worker_reputation_evidence_ids
                .insert(ev.evidence_hash.clone());
            chain
                .e2_worker_reputation_order_ids
                .insert(ev.order_id.clone());
            chain
                .e2_worker_reputation_evidence_log
                .push(E2WorkerCanonicalEvidenceRecordV1 {
                    evidence_id: ev.evidence_hash.clone(),
                    evidence: E2WorkerExecutionEvidenceAnyV1::V1(ev),
                    accepted_at_height: i as u64,
                    applied_delta: 0,
                    candidate_delta: 0,
                    hard_evidence: false,
                    requires_governance: false,
                    validated_against_finalized_height: i as u64,
                    validated_against_finalized_hash: format!("{:064x}", i),
                    source_commitment: "finalized".to_string(),
                });
        }

        chain.trim_e2_worker_reputation_evidence_log_v1();

        assert_eq!(chain.e2_worker_reputation_evidence_log.len(), 1024);
        assert_eq!(chain.e2_worker_reputation_evidence_ids.len(), 1030);
        assert_eq!(chain.e2_worker_reputation_order_ids.len(), 1030);
        assert!(chain
            .e2_worker_reputation_evidence_ids
            .contains(&format!("{:064x}", 0)));
        assert!(chain
            .e2_worker_reputation_order_ids
            .contains(&format!("{:064x}", 0)));
        assert!(chain.e2_worker_reputation_order_already_recorded_v1(&format!("{:064x}", 0)));
        assert!(!chain
            .e2_worker_reputation_evidence_log
            .iter()
            .any(|record| record.evidence_id == format!("{:064x}", 0)));
    }

    #[test]
    fn e2_worker_standard_evidence_apply_rejects_duplicate_evidence_id_before_mutation() {
        let mut chain = crate::Blockchain::new();
        let ev = sample_evidence();
        chain
            .e2_worker_reputation_evidence_ids
            .insert(ev.evidence_hash.clone());
        let err = chain
            .apply_e2_worker_reputation_evidence_from_standard_tx_v1(
                E2WorkerExecutionEvidenceAnyV1::V1(ev),
                7,
            )
            .unwrap_err();
        assert_eq!(err, "e2_worker_evidence_duplicate");
    }

    #[test]
    fn e2_worker_standard_evidence_apply_rejects_duplicate_order_before_mutation() {
        let mut chain = crate::Blockchain::new();
        let ev = sample_evidence();
        chain
            .e2_worker_reputation_order_ids
            .insert(ev.order_id.clone());
        let err = chain
            .apply_e2_worker_reputation_evidence_from_standard_tx_v1(
                E2WorkerExecutionEvidenceAnyV1::V1(ev),
                7,
            )
            .unwrap_err();
        assert_eq!(err, "e2_worker_evidence_order_already_recorded");
    }

    #[test]
    fn e2_worker_standard_evidence_sender_attester_mismatch_rejected_before_signature_validation() {
        let chain = crate::Blockchain::new();
        let sender = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let attester = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let mut ev = sample_evidence();
        ev.chain_id = crate::chain_identity::network_id().to_string();
        ev.genesis_hash = chain.genesis_hash.clone();
        ev.worker_node_pubkey = crate::keyfmt::pk_b64_from_bytes(&[3u8; 32]);
        ev.operator_wallet_pubkey = crate::keyfmt::pk_b64_from_bytes(&[4u8; 32]);
        ev.payer_wallet = crate::keyfmt::pk_b64_from_bytes(&[5u8; 32]);
        ev.attester_pubkey = attester;
        // Deliberately leave the evidence signature empty. The sender/attester mismatch
        // must be rejected before expensive signature/context validation.
        let memo = serde_json::json!({
            "v": 1,
            "op": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_OP_V1,
            "format_version": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_PAYLOAD_VERSION_V1,
            "evidence": E2WorkerExecutionEvidenceAnyV1::V1(ev),
        })
        .to_string();
        let tx = crate::transaction::Transaction::new(
            sender,
            crate::compute_contract::COMPUTE_RECEIVER.to_string(),
            0,
            0,
            0,
            String::new(),
            false,
            Some(memo),
        );
        let err = chain
            .validate_e2_worker_standard_evidence_tx_v1(&tx)
            .unwrap_err();
        assert_eq!(err, "e2_worker_evidence_submit_sender_attester_mismatch");
    }

    #[test]
    fn e2_worker_reputation_ingest_rejects_duplicate_order_id_even_with_distinct_evidence_hashes() {
        let mut ev1 = sample_evidence();
        ev1.order_id = "ab".repeat(32);
        ev1.evidence_hash = "01".repeat(32);
        let mut ev2 = ev1.clone();
        ev2.job_id = "job-2".to_string();
        ev2.evidence_hash = "02".repeat(32);

        let payload = crate::governance::E2WorkerReputationEvidenceIngestPayloadV1 {
            format_version:
                crate::governance::E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1
                    .to_string(),
            evidences: vec![
                E2WorkerExecutionEvidenceAnyV1::V1(ev1),
                E2WorkerExecutionEvidenceAnyV1::V1(ev2),
            ],
        };

        assert_eq!(
            payload.validate_contract_v1().unwrap_err(),
            "e2_worker_reputation_evidence_payload_duplicate_order_id"
        );
    }

    #[test]
    fn e2_worker_validator_membership_is_derived_fail_closed() {
        let worker_hex = "11".repeat(32);
        let other_hex = "22".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }

        assert!(chain.e2_worker_validator_set_member_at_height_v1(&worker_hex, 0));
        assert!(!chain.e2_worker_validator_set_member_at_height_v1(&other_hex, 0));

        {
            let gov = chain.governance.as_mut().expect("governance expected");
            let rep = gov
                .validator_reputation
                .entry(worker_hex.clone())
                .or_default();
            rep.temporarily_revoked = true;
            rep.banned_until_height = None;
        }
        assert!(!chain.e2_worker_validator_set_member_at_height_v1(&worker_hex, 0));
    }

    #[test]
    fn e2_worker_validator_membership_fail_closes_on_post_finalized_validator_set_mutation() {
        let worker_hex = "44".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
            gov.validator_ops_log
                .push(crate::governance::ValidatorOpsLogEntry {
                    height: 1,
                    op: crate::governance::ValidatorOpsOp::ValidatorSetUpdate,
                    target_pk_hex: "__validator_set__".to_string(),
                    new_pk_hex: None,
                    until_height: None,
                    proposal_id: Some("p1".to_string()),
                    reason: Some("test post-finalized mutation".to_string()),
                });
        }

        assert!(!chain.e2_worker_validator_set_member_at_height_v1(&worker_hex, 0));
        assert!(chain
            .canonical_node_reputation_surface_finalized_snapshot_v1()
            .is_empty());
    }

    #[test]
    fn finalized_reputation_surface_omits_post_finalized_evidence() {
        let worker_hex = "33".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
            let rep = gov
                .validator_reputation
                .entry(worker_hex.clone())
                .or_default();
            rep.last_run_evidence_height = Some(1);
            rep.accepted_negative_run_evidence_count = 1;
            rep.accepted_run_evidence_delta_total = -1;
        }

        let rows = chain.canonical_node_reputation_surface_finalized_snapshot_v1();
        assert!(rows.iter().all(|row| row.node_pubkey != worker_hex));
    }

    #[test]
    fn finalized_wallet_reputation_surface_omits_post_finalized_evidence() {
        let wallet_hex = "34".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            let wallet = gov.wallet_reputation.entry(wallet_hex.clone()).or_default();
            wallet.wallet_pubkey = wallet_hex.clone();
            wallet.last_run_evidence_height = Some(1);
            wallet.accepted_negative_run_evidence_count = 1;
            wallet.accepted_run_evidence_delta_total = -1;
        }

        let rows = chain.canonical_wallet_reputation_surface_finalized_snapshot_v1();
        assert!(rows.iter().all(|row| row.wallet_pubkey != wallet_hex));
    }

    #[test]
    fn e2_worker_operator_binding_is_required_and_distinct() {
        let worker_hex = "55".repeat(32);
        let operator_hex = "66".repeat(32);
        let payer_hex = "77".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }

        assert!(
            !chain.e2_worker_operator_binding_is_authorized_finalized_v1(
                &worker_hex,
                &operator_hex,
                0,
            )
        );

        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();
        assert!(chain.e2_worker_operator_binding_is_authorized_finalized_v1(
            &worker_hex,
            &operator_hex,
            0,
        ));
        assert!(
            !chain.e2_worker_operator_binding_is_authorized_finalized_v1(
                &worker_hex,
                &payer_hex,
                0,
            )
        );
    }

    #[test]
    fn e2_worker_operator_binding_accepts_non_validator_worker_identity() {
        let worker_hex = "81".repeat(32);
        let operator_hex = "82".repeat(32);
        let mut chain = crate::Blockchain::new();

        // Deliberately do not add worker_hex to the L1 validator set. E2 worker
        // identity is not consensus-validator authority; governance-finalized
        // worker/operator binding is the canonical relation consumed by E2.
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .expect("non-validator E2 worker binding must be accepted");

        let binding = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_hex, 0)
            .expect("binding should resolve without validator-set membership");
        assert_eq!(binding.worker_node_pubkey, worker_hex);
        assert_eq!(binding.operator_wallet_pubkey, operator_hex);

        let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].worker_node_pubkey, worker_hex);
        assert_eq!(rows[0].operator_wallet_pubkey, operator_hex);
        assert!(!rows[0].cloud_unit_allowed);
        assert_eq!(rows[0].node_reliability_score, 600);
        assert_eq!(
            rows[0].deny_reason.as_deref(),
            Some("minimum_evidence_count_not_met")
        );
    }

    #[test]
    fn e2_worker_operator_binding_rejects_post_finalized_binding() {
        let worker_hex = "88".repeat(32);
        let operator_hex = "99".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }

        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 1)
            .unwrap();
        assert!(
            !chain.e2_worker_operator_binding_is_authorized_finalized_v1(
                &worker_hex,
                &operator_hex,
                0,
            )
        );
        assert!(chain.e2_worker_operator_binding_is_authorized_finalized_v1(
            &worker_hex,
            &operator_hex,
            1,
        ));
    }

    #[test]
    fn e2_worker_operator_binding_duplicate_same_pair_preserves_original_finalized_height() {
        let worker_hex = "8a".repeat(32);
        let operator_hex = "9a".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }

        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 1)
            .unwrap();

        let binding = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_hex, 0)
            .expect("original finalized binding must remain visible");
        assert_eq!(binding.bound_at_height, 0);
        assert_eq!(binding.operator_wallet_pubkey, operator_hex);
        assert_eq!(
            chain
                .canonical_worker_eligibility_finalized_snapshot_v1()
                .len(),
            1
        );
    }

    #[test]
    fn e2_worker_operator_binding_allows_one_operator_multiple_workers_v2() {
        let worker_a = "aa".repeat(32);
        let worker_b = "ab".repeat(32);
        let operator_a = "ba".repeat(32);
        let operator_b = "bb".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![
                crate::governance::ValidatorEntry {
                    pub_key: worker_a.clone(),
                    alias: None,
                    weight: 1,
                },
                crate::governance::ValidatorEntry {
                    pub_key: worker_b.clone(),
                    alias: None,
                    weight: 1,
                },
            ];
        }

        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_a, &operator_a, 0)
            .unwrap();
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_b, &operator_a, 0)
            .unwrap();
        assert!(chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_a, &operator_b, 0)
            .unwrap_err()
            .contains("worker_already_bound"));

        let gov = chain.governance.as_ref().expect("governance expected");
        let wallet = gov
            .wallet_reputation
            .get(&operator_a)
            .expect("operator wallet reputation mirror expected");
        assert_eq!(
            wallet.operator_bound_worker_pubkey.as_deref(),
            Some(worker_a.as_str())
        );
        assert_eq!(
            wallet.operator_bound_worker_pubkeys,
            vec![worker_a.clone(), worker_b.clone()]
        );
    }

    #[test]
    fn worker_eligibility_uses_only_explicit_operator_registry() {
        let worker_hex = "cc".repeat(32);
        let operator_hex = "dd".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
            gov.wallet_reputation.insert(
                operator_hex.clone(),
                crate::governance::WalletGovReputation::from_validator_reputation(
                    &operator_hex,
                    Some(worker_hex.clone()),
                    true,
                    &crate::governance::ValidatorGovReputation::default(),
                ),
            );
        }

        assert!(chain
            .canonical_worker_eligibility_finalized_snapshot_v1()
            .is_empty());
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();
        let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].worker_node_pubkey, worker_hex);
        assert_eq!(rows[0].operator_wallet_pubkey, operator_hex);
    }

    #[test]
    fn worker_operator_registry_read_allows_same_operator_for_multiple_workers_v2() {
        let worker_a = "da".repeat(32);
        let worker_b = "db".repeat(32);
        let operator = "dc".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![
                crate::governance::ValidatorEntry {
                    pub_key: worker_a.clone(),
                    alias: None,
                    weight: 1,
                },
                crate::governance::ValidatorEntry {
                    pub_key: worker_b.clone(),
                    alias: None,
                    weight: 1,
                },
            ];
            gov.e2_worker_operator_bindings.insert(
                worker_a.clone(),
                crate::governance::E2WorkerOperatorBindingRecordV1::active(
                    worker_a.clone(),
                    operator.clone(),
                    0,
                    None,
                ),
            );
            gov.e2_worker_operator_bindings.insert(
                worker_b.clone(),
                crate::governance::E2WorkerOperatorBindingRecordV1::active(
                    worker_b.clone(),
                    operator.clone(),
                    0,
                    None,
                ),
            );
        }

        let binding_a = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_a, 0)
            .expect("operator role model v2 resolves worker-specific binding");
        let binding_b = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_b, 0)
            .expect("operator role model v2 resolves second worker-specific binding");
        assert_eq!(binding_a.operator_wallet_pubkey, operator);
        assert_eq!(binding_b.operator_wallet_pubkey, operator);
        let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn worker_operator_registry_read_rejects_key_record_mismatch() {
        let registry_key = "ea".repeat(32);
        let record_worker = "eb".repeat(32);
        let operator = "ec".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: record_worker.clone(),
                alias: None,
                weight: 1,
            }];
            gov.e2_worker_operator_bindings.insert(
                registry_key.clone(),
                crate::governance::E2WorkerOperatorBindingRecordV1::active(
                    record_worker.clone(),
                    operator.clone(),
                    0,
                    None,
                ),
            );
        }

        let err = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&record_worker, 0)
            .unwrap_err();
        assert!(err.contains("registry_key_mismatch"));
        assert!(chain
            .canonical_worker_eligibility_finalized_snapshot_v1()
            .is_empty());
    }

    #[test]
    fn worker_history_counts_only_finalized_evidence() {
        let worker_hex = "fa".repeat(32);
        let operator_hex = "fb".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();

        let mut ev = sample_evidence();
        ev.worker_node_pubkey = worker_hex.clone();
        ev.operator_wallet_pubkey = operator_hex.clone();
        ev.job_kind = "probe".to_string();
        ev.execution_status = "COMPLETED".to_string();
        ev.failure_class = "SUCCESS".to_string();
        chain
            .e2_worker_reputation_evidence_log
            .push(E2WorkerCanonicalEvidenceRecordV1 {
                evidence_id: "01".repeat(32),
                evidence: E2WorkerExecutionEvidenceAnyV1::V1(ev.clone()),
                accepted_at_height: 0,
                applied_delta: 1,
                candidate_delta: 0,
                hard_evidence: false,
                requires_governance: false,
                validated_against_finalized_height: 0,
                validated_against_finalized_hash: "00".repeat(32),
                source_commitment: "finalized".to_string(),
            });

        let mut unfinalized_accept = ev.clone();
        unfinalized_accept.job_kind = "real".to_string();
        chain
            .e2_worker_reputation_evidence_log
            .push(E2WorkerCanonicalEvidenceRecordV1 {
                evidence_id: "02".repeat(32),
                evidence: E2WorkerExecutionEvidenceAnyV1::V1(unfinalized_accept),
                accepted_at_height: 1,
                applied_delta: 1,
                candidate_delta: 0,
                hard_evidence: false,
                requires_governance: false,
                validated_against_finalized_height: 0,
                validated_against_finalized_hash: "00".repeat(32),
                source_commitment: "finalized".to_string(),
            });

        let mut unfinalized_anchor = ev.clone();
        unfinalized_anchor.job_kind = "real".to_string();
        chain
            .e2_worker_reputation_evidence_log
            .push(E2WorkerCanonicalEvidenceRecordV1 {
                evidence_id: "03".repeat(32),
                evidence: E2WorkerExecutionEvidenceAnyV1::V1(unfinalized_anchor),
                accepted_at_height: 0,
                applied_delta: 1,
                candidate_delta: 0,
                hard_evidence: false,
                requires_governance: false,
                validated_against_finalized_height: 1,
                validated_against_finalized_hash: "00".repeat(32),
                source_commitment: "finalized".to_string(),
            });

        let mut non_finalized_commitment = ev.clone();
        non_finalized_commitment.job_kind = "real".to_string();
        chain
            .e2_worker_reputation_evidence_log
            .push(E2WorkerCanonicalEvidenceRecordV1 {
                evidence_id: "04".repeat(32),
                evidence: E2WorkerExecutionEvidenceAnyV1::V1(non_finalized_commitment),
                accepted_at_height: 0,
                applied_delta: 1,
                candidate_delta: 0,
                hard_evidence: false,
                requires_governance: false,
                validated_against_finalized_height: 0,
                validated_against_finalized_hash: "00".repeat(32),
                source_commitment: "tip".to_string(),
            });

        let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].total_evidence_count, 1);
        assert_eq!(rows[0].successful_probe_jobs, 1);
        assert_eq!(rows[0].successful_real_jobs, 0);
    }

    #[test]
    fn worker_history_index_preserves_counts_when_audit_window_is_trimmed() {
        let worker_hex = "fc".repeat(32);
        let operator_hex = "fd".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();

        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        let mut probe = sample_evidence();
        probe.worker_node_pubkey = worker_hex.clone();
        probe.operator_wallet_pubkey = operator_hex.clone();
        probe.job_kind = "probe".to_string();
        probe.execution_status = "COMPLETED".to_string();
        probe.failure_class = "SUCCESS".to_string();
        stats.observe_evidence_v1(
            &E2WorkerExecutionEvidenceAnyV1::V1(probe),
            0,
            0,
            "finalized",
        );

        let mut real = sample_evidence();
        real.worker_node_pubkey = worker_hex.clone();
        real.operator_wallet_pubkey = operator_hex.clone();
        real.job_kind = "wasm".to_string();
        stats.observe_evidence_v1(&E2WorkerExecutionEvidenceAnyV1::V1(real), 0, 0, "finalized");

        chain
            .e2_worker_reputation_history_index
            .insert(e2_worker_history_key_v1(&worker_hex, &operator_hex), stats);
        chain.e2_worker_reputation_evidence_log.clear();

        let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].total_evidence_count, 2);
        assert_eq!(rows[0].successful_probe_jobs, 1);
        assert_eq!(rows[0].successful_real_jobs, 1);
    }

    #[test]
    fn worker_operator_binding_persists_governance_proposal_id() {
        let worker_hex = "ab".repeat(32);
        let operator_hex = "ac".repeat(32);
        let proposal_id = "bind-worker-operator-001".to_string();
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }

        chain
            .apply_e2_worker_operator_binding_from_governance_with_proposal_id_v1(
                &worker_hex,
                &operator_hex,
                0,
                Some(proposal_id.clone()),
            )
            .unwrap();

        let binding = chain
            .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_hex, 0)
            .expect("binding should resolve at finalized height");
        assert_eq!(binding.proposal_id.as_deref(), Some(proposal_id.as_str()));
    }

    #[test]
    fn worker_operator_binding_does_not_mark_operator_wallet_as_validator() {
        let worker_hex = "ad".repeat(32);
        let operator_hex = "ae".repeat(32);
        let mut chain = crate::Blockchain::new();
        {
            let gov = chain.governance.as_mut().expect("governance expected");
            gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
                pub_key: worker_hex.clone(),
                alias: None,
                weight: 1,
            }];
        }
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .unwrap();
        let gov = chain.governance.as_ref().expect("governance expected");
        let wallet = gov
            .wallet_reputation
            .get(&operator_hex)
            .expect("operator wallet reputation mirror expected");
        assert_eq!(wallet.validator_pubkey, None);
        assert!(!wallet.validator_set_member);
        assert_eq!(
            wallet.operator_bound_worker_pubkey.as_deref(),
            Some(worker_hex.as_str())
        );
        assert_eq!(
            wallet.operator_bound_worker_pubkeys,
            vec![worker_hex.clone()]
        );
        assert_eq!(wallet.operator_binding_height, Some(0));
        assert_eq!(wallet.operator_binding_status.as_deref(), Some("ACTIVE"));
    }

    #[test]
    fn hard_evidence_reports_candidate_delta_without_applied_delta_until_secondary_governance() {
        let mut ev = sample_evidence_v2();
        ev.execution_status = "FAILED".to_string();
        ev.failure_class = FAILURE_SIGNATURE_INVALID.to_string();
        ev.fault_domain = FAULT_WORKER.to_string();
        ev.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        ev.worker_fault = true;
        ev.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert!(validate_e2_worker_evidence_v2_taxonomy(&ev).is_ok());
        let candidate_delta =
            e2_worker_evidence_delta_any_v1(&E2WorkerExecutionEvidenceAnyV1::V2(ev.clone()));
        let hard = e2_worker_evidence_is_hard_v1(&ev.failure_class);
        let applied_delta = if hard { 0 } else { candidate_delta };
        assert!(hard);
        assert_eq!(candidate_delta, -100);
        assert_eq!(applied_delta, 0);
    }

    #[test]
    fn history_stats_track_timeout_failure_and_probe_streaks() {
        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        let mut timeout = sample_evidence_v2();
        timeout.execution_status = "FAILED".to_string();
        timeout.failure_class = FAILURE_TIMEOUT.to_string();
        timeout.fault_domain = FAULT_WORKER.to_string();
        timeout.penalty_effect = EFFECT_SOFT_PENALTY.to_string();
        timeout.worker_fault = true;
        timeout.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        timeout.job_kind = "probe".to_string();
        stats.observe_evidence_v1(
            &E2WorkerExecutionEvidenceAnyV1::V2(timeout),
            10,
            10,
            "finalized",
        );

        let mut crash = sample_evidence_v2();
        crash.execution_status = "FAILED".to_string();
        crash.failure_class = FAILURE_WORKER_CRASH.to_string();
        crash.fault_domain = FAULT_WORKER.to_string();
        crash.penalty_effect = EFFECT_MEDIUM_PENALTY.to_string();
        crash.worker_fault = true;
        crash.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        stats.observe_evidence_v1(
            &E2WorkerExecutionEvidenceAnyV1::V2(crash),
            11,
            11,
            "finalized",
        );

        assert_eq!(stats.recent_timeout_count, 1);
        assert_eq!(stats.recent_failure_count, 1);
        assert_eq!(stats.recent_invalid_output_count, 0);
        assert_eq!(stats.consecutive_failures, 2);
        assert_eq!(stats.consecutive_timeouts, 0);
        assert_eq!(stats.failed_recovery_probe_count, 1);
        assert_eq!(stats.last_hard_fault_height, None);
    }

    #[test]
    fn hard_candidate_history_observe_has_no_automatic_counter_effect() {
        let mut stats = E2WorkerCanonicalHistoryStatsV1::default();
        let mut hard = sample_evidence_v2();
        hard.execution_status = "FAILED".to_string();
        hard.failure_class = FAILURE_BAD_RESULT_HASH.to_string();
        hard.fault_domain = FAULT_WORKER.to_string();
        hard.penalty_effect = EFFECT_HARD_PENALTY.to_string();
        hard.worker_fault = true;
        hard.verifier_verdict = VERDICT_WORKER_PENALTY_CANDIDATE.to_string();
        assert!(E2WorkerExecutionEvidenceAnyV1::V2(hard.clone()).requires_secondary_governance_v1());

        stats.observe_evidence_v1(
            &E2WorkerExecutionEvidenceAnyV1::V2(hard),
            11,
            11,
            "finalized",
        );

        assert_eq!(stats.total_evidence_count, 0);
        assert_eq!(stats.recent_timeout_count, 0);
        assert_eq!(stats.recent_failure_count, 0);
        assert_eq!(stats.recent_invalid_output_count, 0);
        assert_eq!(stats.consecutive_failures, 0);
        assert_eq!(stats.failed_recovery_probe_count, 0);
        assert_eq!(stats.last_hard_fault_height, None);
    }
}
