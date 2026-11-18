use crate::chain_identity;
use crate::cognitive_chain::{
    validate_sha256_hex_field, CognitiveRegistryClaimViewV1, CognitiveRegistryObjectViewV1,
    CognitiveRegistryReconciliationContextV1, CognitiveRegistryStatusViewV1,
    COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
};
use crate::storage::ChainStorage;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use warp::http::Method;
use warp::path::FullPath;
use warp::Filter;
use warp::Reply;

macro_rules! lock_any {
    ($m:expr) => {{
        let __t0 = std::time::Instant::now();
        match $m.lock() {
            Ok(__g) => crate::perf_metrics::TimedMutexGuard::new_api(__g, __t0.elapsed()),
            Err(__poison) => {
                eprintln!("⚠️ mutex poisoned; recovering with into_inner()");
                crate::perf_metrics::TimedMutexGuard::new_api(__poison.into_inner(), __t0.elapsed())
            }
        }
    }};
}

use hex;
use sha2::{Digest, Sha256};

// ====== Crate imports ======
use crate::blockchain::{
    Blockchain, CognitiveConsensusFinalityViewV1, CognitiveContractSnapshotV1,
};
use crate::compute_contract::{
    compute_order_events_snapshot_for_finalized_chain, compute_order_lookup_v2_for_finalized_chain,
    compute_orders_snapshot_v2_for_finalized_chain,
    evaluate_compute_worker_admission_for_finalized_order_v1, validate_compute_tx_syntax,
    validate_compute_tx_worker_admission_v1,
};
use crate::ft;
use crate::mempool::{Mempool, MempoolAddResult};
use crate::netmsg::NetMsg;
use crate::nft;
use crate::pos;
use crate::staking;
use crate::transaction::Transaction;
use crate::wallet::{canonical_signing_string, TransactionPayload};
use crate::{SharedChain, SharedMempool};
// Versioning base esposto da /status (delegato a src/version.rs)
use crate::state_smt::{addr_key, bytes32_from_hex, StateSmt};
use crate::storage::DbStore;

use crate::utils::build_fingerprint;
use crate::version::{E2ContractSnapshotV1, VersionInfo, API_CONTRACT, API_CONTRACT_VERSION};

fn json_value_for_api_v1<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn json_object_for_api_v1(
    pairs: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (key, value) in pairs {
        object.insert(key.to_string(), value);
    }
    serde_json::Value::Object(object)
}
fn api_unix_ms_v1() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Clone, Debug, Default, Serialize)]
struct RuntimeStatusCache {
    height: Option<u64>,
    finalized_height: Option<u64>,
    last_block_hash: Option<String>,
    finalized_hash: Option<String>,
    boot_phase: Option<String>,
    sync_state: Option<String>,
    last_snapshot_error: Option<String>,
    last_state_sync_error: Option<String>,
    updated_at_ms: Option<u64>,
}

static RUNTIME_STATUS_CACHE_V1: OnceLock<Mutex<RuntimeStatusCache>> = OnceLock::new();

fn runtime_status_cache_store_v1() -> &'static Mutex<RuntimeStatusCache> {
    RUNTIME_STATUS_CACHE_V1.get_or_init(|| Mutex::new(RuntimeStatusCache::default()))
}

fn runtime_status_cache_read_v1() -> RuntimeStatusCache {
    match runtime_status_cache_store_v1().try_lock() {
        Ok(cache) => cache.clone(),
        Err(TryLockError::Poisoned(poison)) => (*poison.into_inner()).clone(),
        Err(TryLockError::WouldBlock) => RuntimeStatusCache::default(),
    }
}

fn runtime_status_cache_update_v1(next: RuntimeStatusCache) {
    match runtime_status_cache_store_v1().try_lock() {
        Ok(mut cache) => {
            let last_snapshot_error = cache.last_snapshot_error.clone();
            let last_state_sync_error = cache.last_state_sync_error.clone();
            *cache = next;
            if cache.last_snapshot_error.is_none() {
                cache.last_snapshot_error = last_snapshot_error;
            }
            if cache.last_state_sync_error.is_none() {
                cache.last_state_sync_error = last_state_sync_error;
            }
        }
        Err(TryLockError::Poisoned(poison)) => {
            let mut cache = poison.into_inner();
            let last_snapshot_error = cache.last_snapshot_error.clone();
            let last_state_sync_error = cache.last_state_sync_error.clone();
            *cache = next;
            if cache.last_snapshot_error.is_none() {
                cache.last_snapshot_error = last_snapshot_error;
            }
            if cache.last_state_sync_error.is_none() {
                cache.last_state_sync_error = last_state_sync_error;
            }
        }
        Err(TryLockError::WouldBlock) => {}
    }
}

pub(crate) fn runtime_status_cache_height_v1() -> Option<u64> {
    runtime_status_cache_read_v1().height
}

/// Blocking height read for safety-critical snapshot serving decisions.
///
/// The public `runtime_status_cache_height_v1()` intentionally uses a best-effort
/// try-lock for API/status paths.  RRv3 `GetSnapshotV2Latest` is different: serving
/// a stale latest snapshot can make a RestartCatchup node import a non-progressive
/// bundle and lose quorum.  Use a real lock here so the provider either compares
/// against the actual cached tip or, if the cache has not been populated yet, can
/// fail closed explicitly.
pub(crate) fn runtime_status_cache_height_blocking_v200() -> Option<u64> {
    match runtime_status_cache_store_v1().lock() {
        Ok(cache) => cache.height,
        Err(poison) => poison.into_inner().height,
    }
}

pub(crate) fn record_runtime_snapshot_error_v1(message: impl Into<String>) {
    let message = message.into();
    match runtime_status_cache_store_v1().try_lock() {
        Ok(mut cache) => {
            cache.last_snapshot_error = Some(message);
            cache.updated_at_ms = Some(api_unix_ms_v1());
        }
        Err(TryLockError::Poisoned(poison)) => {
            let mut cache = poison.into_inner();
            cache.last_snapshot_error = Some(message);
            cache.updated_at_ms = Some(api_unix_ms_v1());
        }
        Err(TryLockError::WouldBlock) => {}
    }
}

pub(crate) fn record_runtime_state_sync_error_v1(message: impl Into<String>) {
    let message = message.into();
    match runtime_status_cache_store_v1().try_lock() {
        Ok(mut cache) => {
            cache.last_state_sync_error = Some(message);
            cache.updated_at_ms = Some(api_unix_ms_v1());
        }
        Err(TryLockError::Poisoned(poison)) => {
            let mut cache = poison.into_inner();
            cache.last_state_sync_error = Some(message);
            cache.updated_at_ms = Some(api_unix_ms_v1());
        }
        Err(TryLockError::WouldBlock) => {}
    }
}

fn runtime_status_cache_from_status_body_v1(status_body: &serde_json::Value) -> RuntimeStatusCache {
    let local_runtime = status_body.get("local_runtime");
    let sync_caught_up = local_runtime
        .and_then(|v| v.get("runtime_sync_caught_up"))
        .and_then(|v| v.as_bool());
    let p2p_ready = local_runtime
        .and_then(|v| v.get("p2p_ready_for_mining"))
        .and_then(|v| v.as_bool());
    let proposal_gate_open = local_runtime
        .and_then(|v| v.get("proposal_gate_open"))
        .and_then(|v| v.as_bool());
    let consensus_ready = local_runtime
        .and_then(|v| v.get("consensus_ready"))
        .and_then(|v| v.as_bool());

    let sync_state = match (
        sync_caught_up,
        p2p_ready,
        proposal_gate_open,
        consensus_ready,
    ) {
        (Some(true), Some(true), Some(true), Some(true)) => Some("steady".to_string()),
        (Some(true), _, _, _) => Some("caught_up_not_operational".to_string()),
        (Some(false), _, _, _) => Some("catching_up".to_string()),
        _ => None,
    };

    let boot_phase = match (sync_caught_up, p2p_ready, proposal_gate_open) {
        (Some(true), Some(true), Some(true)) => Some("steady_state".to_string()),
        (Some(false), _, _) => Some("sync_or_bootstrap".to_string()),
        _ => None,
    };

    RuntimeStatusCache {
        height: status_body.get("height").and_then(|v| v.as_u64()),
        finalized_height: status_body.get("finalized_height").and_then(|v| v.as_u64()),
        last_block_hash: status_body
            .get("last_block_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        finalized_hash: status_body
            .get("finalized_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        boot_phase,
        sync_state,
        last_snapshot_error: None,
        last_state_sync_error: None,
        updated_at_ms: Some(api_unix_ms_v1()),
    }
}

fn runtime_status_cache_from_chain_v1(bc: &Blockchain) -> RuntimeStatusCache {
    // V202: use the chain abstraction for height. In pruned/snapshot states the
    // in-memory block Vec can be empty or windowed while the logical tip remains
    // non-zero; snapshot serving decisions consume this cache and must not see a
    // synthetic height=0/stale value.
    let height = Some(bc.tip_height_u64());
    let last_block_hash = bc.chain.last().map(|last| last.hash.clone());
    let (finalized_height, finalized_hash) = bc.finalized_view();
    let local_runtime = json_value_for_api_v1(bc.local_consensus_runtime_view_for_next_block());
    let body = json_object_for_api_v1([
        ("height", json_value_for_api_v1(height)),
        ("finalized_height", json_value_for_api_v1(finalized_height)),
        ("last_block_hash", json_value_for_api_v1(last_block_hash)),
        ("finalized_hash", json_value_for_api_v1(finalized_hash)),
        ("local_runtime", local_runtime),
    ]);
    // Keep extraction logic single-sourced through the same status-body parser used by /status.
    runtime_status_cache_from_status_body_v1(&body)
}

pub fn publish_runtime_status_cache_from_chain_v1(bc: &Blockchain) {
    runtime_status_cache_update_v1(runtime_status_cache_from_chain_v1(bc));
}

fn build_degraded_status_from_cache_v1(
    cache: &RuntimeStatusCache,
    reason: &'static str,
    mempool_snapshot: Option<(u64, u64)>,
) -> serde_json::Value {
    let (mempool_size, mempool_bytes) = mempool_snapshot
        .map(|(size, bytes)| (json_value_for_api_v1(size), json_value_for_api_v1(bytes)))
        .unwrap_or((serde_json::Value::Null, serde_json::Value::Null));

    json_object_for_api_v1([
        ("status", json_value_for_api_v1("degraded")),
        ("reason", json_value_for_api_v1(reason)),
        ("api_alive", json_value_for_api_v1(true)),
        (
            "software_version",
            json_value_for_api_v1(VersionInfo::current().software_version),
        ),
        (
            "protocol_version",
            json_value_for_api_v1(VersionInfo::current().protocol_version),
        ),
        (
            "min_supported_protocol_version",
            json_value_for_api_v1(VersionInfo::current().min_supported_protocol_version),
        ),
        ("api_contract", json_value_for_api_v1(API_CONTRACT)),
        (
            "api_contract_version",
            json_value_for_api_v1(API_CONTRACT_VERSION),
        ),
        (
            "network_id",
            json_value_for_api_v1(chain_identity::network_id()),
        ),
        ("last_cached_height", json_value_for_api_v1(cache.height)),
        (
            "last_cached_finalized_height",
            json_value_for_api_v1(cache.finalized_height),
        ),
        (
            "last_cached_block_hash",
            json_value_for_api_v1(cache.last_block_hash.clone()),
        ),
        (
            "last_cached_finalized_hash",
            json_value_for_api_v1(cache.finalized_hash.clone()),
        ),
        (
            "boot_phase",
            json_value_for_api_v1(cache.boot_phase.clone()),
        ),
        (
            "sync_state",
            json_value_for_api_v1(cache.sync_state.clone()),
        ),
        (
            "last_snapshot_error",
            json_value_for_api_v1(cache.last_snapshot_error.clone()),
        ),
        (
            "last_state_sync_error",
            json_value_for_api_v1(cache.last_state_sync_error.clone()),
        ),
        ("updated_at_ms", json_value_for_api_v1(cache.updated_at_ms)),
        ("mempool_size", mempool_size),
        ("mempool_bytes", mempool_bytes),
        ("cache", json_value_for_api_v1(cache)),
        (
            "build_fingerprint",
            json_value_for_api_v1(build_fingerprint()),
        ),
        ("runtime_surface", runtime_surface_json()),
    ])
}

fn canonical_worker_eligibility_compat_aliases_v1(
    worker: &crate::reputation_score::CanonicalWorkerEligibilityV1,
) -> serde_json::Value {
    serde_json::json!({
        "workerNodePubkey": worker.worker_node_pubkey.clone(),
        "operatorWalletPubkey": worker.operator_wallet_pubkey.clone(),
        "sourceHeight": worker.source_height,
        "finalizedHeight": worker.finalized_height,
        "sourceCommitment": worker.source_commitment.clone(),
        "registrationSource": worker.registration_source.clone(),
        "chainKnown": worker.chain_known,
        "eligibleForProbe": worker.eligible_for_probe,
        "eligibleForNonProbe": worker.eligible_for_non_probe,
        "walletReputationScore": worker.wallet_reputation_score,
        "nodeReliabilityScore": worker.node_reliability_score,
        "effectiveScore": worker.effective_score,
        "eligibilityState": worker.eligibility_state.clone(),
        "tier": worker.tier.clone(),
        "maxRiskClass": worker.max_risk_class.clone(),
        "cloudUnitAllowed": worker.cloud_unit_allowed,
        "cloudUnitGrantProposalId": worker.cloud_unit_grant_proposal_id.clone(),
        "cloudUnitGrantPayloadHash": worker.cloud_unit_grant_payload_hash.clone(),
        "longRunningAllowed": worker.long_running_allowed,
        "gpuAllowed": worker.gpu_allowed,
        "gpuGrantProposalId": worker.gpu_grant_proposal_id.clone(),
        "gpuGrantPayloadHash": worker.gpu_grant_payload_hash.clone(),
        "criticalWorkloadAllowed": worker.critical_workload_allowed,
        "criticalWorkloadGrantProposalId": worker.critical_workload_grant_proposal_id.clone(),
        "criticalWorkloadGrantPayloadHash": worker.critical_workload_grant_payload_hash.clone(),
        "maxParallelJobs": worker.max_parallel_jobs,
        "maxJobDurationSec": worker.max_job_duration_sec,
        "successfulProbeJobs": worker.successful_probe_jobs,
        "successfulRealJobs": worker.successful_real_jobs,
        "totalEvidenceCount": worker.total_evidence_count,
        "observationWindow": worker.observation_window,
        "uptimeWindow": worker.uptime_window,
        "denyReason": worker.deny_reason.clone(),
        "nextRecoveryAction": worker.next_recovery_action.clone(),
        "policyVersion": worker.policy_version.clone(),
    })
}

fn canonical_worker_eligibility_missing_requirements_v1(
    worker: &crate::reputation_score::CanonicalWorkerEligibilityV1,
) -> Vec<serde_json::Value> {
    let policy = crate::reputation_score::WorkerEligibilityPolicyV1::canonical_v1();
    let mut out = Vec::new();
    if worker.successful_probe_jobs < policy.minimum_successful_probe_jobs {
        out.push(serde_json::json!({
            "code": "minimum_successful_probe_jobs_not_met",
            "current": worker.successful_probe_jobs,
            "required": policy.minimum_successful_probe_jobs,
            "next_action": "run_probe_and_submit_evidence"
        }));
    }
    if worker.total_evidence_count < policy.minimum_evidence_count {
        out.push(serde_json::json!({
            "code": "minimum_evidence_count_not_met",
            "current": worker.total_evidence_count,
            "required": policy.minimum_evidence_count,
            "next_action": "collect_more_finalized_evidence"
        }));
    }
    if worker.observation_window < policy.minimum_observation_window {
        out.push(serde_json::json!({
            "code": "minimum_observation_window_not_met",
            "current": worker.observation_window,
            "required": policy.minimum_observation_window,
            "next_action": "wait_for_observation_window"
        }));
    }
    if worker.uptime_window < policy.minimum_uptime_window {
        out.push(serde_json::json!({
            "code": "minimum_uptime_window_not_met",
            "current": worker.uptime_window,
            "required": policy.minimum_uptime_window,
            "next_action": "maintain_runtime_uptime"
        }));
    }
    if worker.effective_score < policy.base_non_probe_min_score {
        out.push(serde_json::json!({
            "code": "base_non_probe_score_below_threshold",
            "current": worker.effective_score,
            "required": policy.base_non_probe_min_score,
            "next_action": "collect_successful_finalized_evidence"
        }));
    }
    out
}

fn canonical_worker_eligibility_onboarding_guidance_v1(
    worker: &crate::reputation_score::CanonicalWorkerEligibilityV1,
) -> serde_json::Value {
    let policy = crate::reputation_score::WorkerEligibilityPolicyV1::canonical_v1();
    let missing = canonical_worker_eligibility_missing_requirements_v1(worker);
    let stage = if worker.eligible_for_non_probe {
        "ACTIVE_BASE"
    } else if worker.eligible_for_probe && worker.successful_probe_jobs == 0 {
        "PROBE_READY"
    } else if worker.eligible_for_probe {
        "PROMOTION_PENDING"
    } else if worker.chain_known {
        "DENIED_CHAIN_KNOWN"
    } else {
        "UNKNOWN_TO_CHAIN"
    };
    let reason = if worker.eligible_for_non_probe {
        "base_non_probe_threshold_satisfied".to_string()
    } else if let Some(reason) = worker.deny_reason.clone() {
        reason
    } else if stage == "PROMOTION_PENDING" {
        "threshold_or_finality_pending".to_string()
    } else {
        "worker_not_currently_admitted".to_string()
    };
    let next_action = worker
        .next_recovery_action
        .clone()
        .unwrap_or_else(|| match stage {
            "ACTIVE_BASE" => "accept_base_workloads".to_string(),
            "PROBE_READY" => "run_probe_and_submit_evidence".to_string(),
            "PROMOTION_PENDING" => "wait_finality_or_collect_more_evidence".to_string(),
            "DENIED_CHAIN_KNOWN" => "inspect_deny_reason".to_string(),
            _ => "submit_worker_registration_or_wait_projection".to_string(),
        });

    let mut progress = serde_json::Map::new();
    progress.insert(
        "successful_probe_jobs".to_string(),
        json_value_for_api_v1(worker.successful_probe_jobs),
    );
    progress.insert(
        "successfulProbeJobs".to_string(),
        json_value_for_api_v1(worker.successful_probe_jobs),
    );
    progress.insert(
        "minimum_successful_probe_jobs".to_string(),
        json_value_for_api_v1(policy.minimum_successful_probe_jobs),
    );
    progress.insert(
        "minimumSuccessfulProbeJobs".to_string(),
        json_value_for_api_v1(policy.minimum_successful_probe_jobs),
    );
    progress.insert(
        "total_evidence_count".to_string(),
        json_value_for_api_v1(worker.total_evidence_count),
    );
    progress.insert(
        "totalEvidenceCount".to_string(),
        json_value_for_api_v1(worker.total_evidence_count),
    );
    progress.insert(
        "minimum_evidence_count".to_string(),
        json_value_for_api_v1(policy.minimum_evidence_count),
    );
    progress.insert(
        "minimumEvidenceCount".to_string(),
        json_value_for_api_v1(policy.minimum_evidence_count),
    );
    progress.insert(
        "observation_window".to_string(),
        json_value_for_api_v1(worker.observation_window),
    );
    progress.insert(
        "observationWindow".to_string(),
        json_value_for_api_v1(worker.observation_window),
    );
    progress.insert(
        "minimum_observation_window".to_string(),
        json_value_for_api_v1(policy.minimum_observation_window),
    );
    progress.insert(
        "minimumObservationWindow".to_string(),
        json_value_for_api_v1(policy.minimum_observation_window),
    );
    progress.insert(
        "uptime_window".to_string(),
        json_value_for_api_v1(worker.uptime_window),
    );
    progress.insert(
        "uptimeWindow".to_string(),
        json_value_for_api_v1(worker.uptime_window),
    );
    progress.insert(
        "minimum_uptime_window".to_string(),
        json_value_for_api_v1(policy.minimum_uptime_window),
    );
    progress.insert(
        "minimumUptimeWindow".to_string(),
        json_value_for_api_v1(policy.minimum_uptime_window),
    );
    progress.insert(
        "effective_score".to_string(),
        json_value_for_api_v1(worker.effective_score),
    );
    progress.insert(
        "effectiveScore".to_string(),
        json_value_for_api_v1(worker.effective_score),
    );
    progress.insert(
        "base_non_probe_min_score".to_string(),
        json_value_for_api_v1(policy.base_non_probe_min_score),
    );
    progress.insert(
        "baseNonProbeMinScore".to_string(),
        json_value_for_api_v1(policy.base_non_probe_min_score),
    );
    progress.insert(
        "active_base_min_score".to_string(),
        json_value_for_api_v1(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1),
    );
    progress.insert(
        "activeBaseMinScore".to_string(),
        json_value_for_api_v1(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1),
    );
    progress.insert(
        "low_risk_min_score".to_string(),
        json_value_for_api_v1(crate::reputation_score::WORKER_LOW_RISK_MIN_SCORE_V1),
    );
    progress.insert(
        "lowRiskMinScore".to_string(),
        json_value_for_api_v1(crate::reputation_score::WORKER_LOW_RISK_MIN_SCORE_V1),
    );
    progress.insert(
        "cloud_unit_min_score".to_string(),
        json_value_for_api_v1(policy.cloud_unit_min_score),
    );
    progress.insert(
        "cloudUnitMinScore".to_string(),
        json_value_for_api_v1(policy.cloud_unit_min_score),
    );
    progress.insert(
        "cloud_unit_min_successful_real_jobs".to_string(),
        json_value_for_api_v1(policy.cloud_unit_min_successful_real_jobs),
    );
    progress.insert(
        "cloudUnitMinSuccessfulRealJobs".to_string(),
        json_value_for_api_v1(policy.cloud_unit_min_successful_real_jobs),
    );
    progress.insert(
        "long_running_min_score".to_string(),
        json_value_for_api_v1(policy.long_running_min_score),
    );
    progress.insert(
        "longRunningMinScore".to_string(),
        json_value_for_api_v1(policy.long_running_min_score),
    );
    progress.insert(
        "long_running_min_successful_real_jobs".to_string(),
        json_value_for_api_v1(policy.long_running_min_successful_real_jobs),
    );
    progress.insert(
        "longRunningMinSuccessfulRealJobs".to_string(),
        json_value_for_api_v1(policy.long_running_min_successful_real_jobs),
    );
    progress.insert(
        "gpu_min_score".to_string(),
        json_value_for_api_v1(policy.gpu_min_score),
    );
    progress.insert(
        "gpuMinScore".to_string(),
        json_value_for_api_v1(policy.gpu_min_score),
    );
    progress.insert(
        "gpu_min_successful_real_jobs".to_string(),
        json_value_for_api_v1(policy.gpu_min_successful_real_jobs),
    );
    progress.insert(
        "gpuMinSuccessfulRealJobs".to_string(),
        json_value_for_api_v1(policy.gpu_min_successful_real_jobs),
    );
    progress.insert(
        "gpu_min_successful_gpu_evidence_jobs".to_string(),
        json_value_for_api_v1(policy.gpu_min_successful_gpu_evidence_jobs),
    );
    progress.insert(
        "gpuMinSuccessfulGpuEvidenceJobs".to_string(),
        json_value_for_api_v1(policy.gpu_min_successful_gpu_evidence_jobs),
    );
    progress.insert(
        "critical_workload_min_score".to_string(),
        json_value_for_api_v1(policy.critical_workload_min_score),
    );
    progress.insert(
        "criticalWorkloadMinScore".to_string(),
        json_value_for_api_v1(policy.critical_workload_min_score),
    );
    progress.insert(
        "critical_workload_min_successful_real_jobs".to_string(),
        json_value_for_api_v1(policy.critical_workload_min_successful_real_jobs),
    );
    progress.insert(
        "criticalWorkloadMinSuccessfulRealJobs".to_string(),
        json_value_for_api_v1(policy.critical_workload_min_successful_real_jobs),
    );
    progress.insert(
        "critical_workload_requires_explicit_review_marker".to_string(),
        json_value_for_api_v1(policy.critical_workload_requires_explicit_review_marker),
    );
    progress.insert(
        "criticalWorkloadRequiresExplicitReviewMarker".to_string(),
        json_value_for_api_v1(policy.critical_workload_requires_explicit_review_marker),
    );

    let mut response = serde_json::Map::new();
    response.insert("stage".to_string(), json_value_for_api_v1(stage));
    response.insert("reason".to_string(), json_value_for_api_v1(reason));
    response.insert(
        "next_action".to_string(),
        json_value_for_api_v1(next_action.clone()),
    );
    response.insert("nextAction".to_string(), json_value_for_api_v1(next_action));
    response.insert(
        "policy_version".to_string(),
        json_value_for_api_v1(policy.policy_version.clone()),
    );
    response.insert(
        "policyVersion".to_string(),
        json_value_for_api_v1(policy.policy_version),
    );
    response.insert("progress".to_string(), serde_json::Value::Object(progress));
    response.insert(
        "missing_requirements".to_string(),
        json_value_for_api_v1(missing.clone()),
    );
    response.insert(
        "missingRequirements".to_string(),
        json_value_for_api_v1(missing),
    );
    response.insert(
        "note".to_string(),
        json_value_for_api_v1("A successful probe is necessary but may not immediately promote the worker; promotion is finalized only after the canonical policy thresholds are satisfied."),
    );
    serde_json::Value::Object(response)
}

fn e2_worker_bootstrap_probe_contract_v1() -> serde_json::Value {
    serde_json::json!({
        "surface": "e2_worker_bootstrap_probe_contract_v1",
        "canonical_job_kind": "probe:v1",
        "canonicalJobKind": "probe:v1",
        "allowed_job_kinds": ["probe", "probe:v1", "bootstrap_probe_v1"],
        "allowedJobKinds": ["probe", "probe:v1", "bootstrap_probe_v1"],
        "order_id_domain": crate::e2_worker_evidence::E2_WORKER_PROBE_BOOTSTRAP_ORDER_DOMAIN_V1,
        "orderIdDomain": crate::e2_worker_evidence::E2_WORKER_PROBE_BOOTSTRAP_ORDER_DOMAIN_V1,
        "order_id_formula": "sha256(domain || US || chain_id || US || genesis_hash || US || worker_node_pubkey || US || operator_wallet_pubkey || US || job_id || US || result_hash)",
        "orderIdFormula": "sha256(domain || US || chain_id || US || genesis_hash || US || worker_node_pubkey || US || operator_wallet_pubkey || US || job_id || US || result_hash)",
        "requires_compute_order": false,
        "requiresComputeOrder": false,
        "required_zero_heights": ["order_created_height", "order_claimed_height", "order_terminal_height"],
        "requiredZeroHeights": ["order_created_height", "order_claimed_height", "order_terminal_height"],
        "required_execution_status": "COMPLETED",
        "requiredExecutionStatus": "COMPLETED",
        "required_failure_class": crate::e2_worker_evidence::FAILURE_SUCCESS,
        "requiredFailureClass": crate::e2_worker_evidence::FAILURE_SUCCESS,
        "payer_must_equal_operator_wallet": true,
        "payerMustEqualOperatorWallet": true,
        "real_workload_rule": "Any non-bootstrap-probe workload evidence still requires a finalized terminal L1 compute order.",
        "realWorkloadRule": "Any non-bootstrap-probe workload evidence still requires a finalized terminal L1 compute order."
    })
}

fn e2_worker_evidence_bootstrap_probe_preflight_v1(
    ev: &crate::e2_worker_evidence::E2WorkerExecutionEvidenceV1,
) -> serde_json::Value {
    let is_zero_height_bootstrap_shape = ev.order_created_height == 0
        && ev.order_claimed_height == 0
        && ev.order_terminal_height == 0;
    let result_hash = ev.result_hash.as_deref().map(str::trim).unwrap_or("");
    let expected_order_id = if is_zero_height_bootstrap_shape && !result_hash.is_empty() {
        Some(
            crate::e2_worker_evidence::expected_e2_worker_probe_bootstrap_order_id_v1(
                &ev.chain_id,
                &ev.genesis_hash,
                &ev.worker_node_pubkey,
                &ev.operator_wallet_pubkey,
                &ev.job_id,
                result_hash,
            ),
        )
    } else {
        None
    };
    let job_kind_allowed =
        crate::e2_worker_evidence::e2_worker_job_kind_is_probe_bootstrap_v1(&ev.job_kind);
    let order_id_matches = expected_order_id
        .as_ref()
        .map(|expected| ev.order_id.trim().eq_ignore_ascii_case(expected))
        .unwrap_or(false);
    let mut errors = Vec::<&'static str>::new();
    if is_zero_height_bootstrap_shape && !job_kind_allowed {
        errors.push("e2_worker_probe_bootstrap_job_kind_not_allowlisted");
    }
    if is_zero_height_bootstrap_shape && expected_order_id.is_some() && !order_id_matches {
        errors.push("e2_worker_probe_bootstrap_order_id_mismatch");
    }
    if is_zero_height_bootstrap_shape && result_hash.is_empty() {
        errors.push("e2_worker_probe_bootstrap_result_hash_required");
    }
    serde_json::json!({
        "is_bootstrap_probe_shape": is_zero_height_bootstrap_shape,
        "isBootstrapProbeShape": is_zero_height_bootstrap_shape,
        "job_kind_allowed": job_kind_allowed,
        "jobKindAllowed": job_kind_allowed,
        "order_id_matches": order_id_matches,
        "orderIdMatches": order_id_matches,
        "expected_order_id": expected_order_id.clone(),
        "expectedOrderId": expected_order_id,
        "canonical_job_kind": "probe:v1",
        "canonicalJobKind": "probe:v1",
        "errors": errors,
        "contract": e2_worker_bootstrap_probe_contract_v1()
    })
}

fn compute_fiat_settlement_proof_canonical_response_v1(
    order_id_trimmed: &str,
    proof: Option<crate::compute_contract::ComputeFiatSettlementProofV1>,
    canonical_order_id_seen: bool,
) -> serde_json::Value {
    let found = proof.is_some() || canonical_order_id_seen;
    let pruned = proof.is_none() && canonical_order_id_seen;
    serde_json::json!({
        "status": "ok",
        "surface": "compute_fiat_settlement_proof_v1",
        "order_id": order_id_trimmed,
        "found": found,
        "canonical": found,
        "pruned": pruned,
        "proof": proof,
    })
}

#[derive(Debug, Deserialize)]
struct E2OrderEventsQuery {
    from_height: Option<u64>,
    to_height: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct E2WorkerAdmissionQuery {
    order_id: String,
}

#[derive(Debug, Deserialize)]
struct ReputationEvidenceLimitQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SecurityReputationQuery {
    #[serde(default)]
    limit: Option<usize>,
}

const SECURITY_REPUTATION_DEFAULT_LIMIT: usize = 128;
const SECURITY_REPUTATION_MAX_LIMIT: usize = 500;

#[derive(Debug, Deserialize, Default)]
struct GovernanceProposalListQuery {
    limit: Option<usize>,
    status: Option<String>,
    kind: Option<String>,
}

fn governance_council_threshold_for_view_v1(
    gov: &crate::governance::GovernanceState,
    council: &crate::governance::GovernanceCouncilKind,
) -> u8 {
    match council {
        crate::governance::GovernanceCouncilKind::Protocol => gov.protocol_council.threshold,
        crate::governance::GovernanceCouncilKind::Economy => gov.economy_council.threshold,
        crate::governance::GovernanceCouncilKind::Emergency => gov.emergency_council.threshold,
    }
}

fn governance_flow_response_v1(proposal_id: &str) -> serde_json::Value {
    serde_json::json!({
        "requires_vote": true,
        "show_proposal_path": format!("/api/v2/gov/proposals/{}", proposal_id),
        "vote_path": format!("/api/v2/gov/proposals/{}/vote", proposal_id),
        "vote_requires_proposal_hash_hex": true,
        "proposal_hash_available_after_inclusion": true,
        "proposal_hash_source": "GET /api/v2/gov/proposals/{proposal_id}",
        "flow": [
            "proposal_queued",
            "wait_proposal_visible",
            "show_decoded_proposal_and_hash",
            "vote_with_explicit_proposal_hash_hex",
            "wait_vote_inclusion_and_quorum",
            "wait_effective_height_and_apply",
            "wait_finality"
        ]
    })
}

#[allow(clippy::too_many_arguments)]
fn governance_proposal_id_from_entropy_v1(
    prefix: &str,
    kind: &crate::governance::GovProposalKind,
    proposer: &str,
    payload: &[u8],
    _created_at_height: u64,
    _effective_height: u64,
    _queue_len: usize,
    chain_id: &str,
    genesis_hash: &str,
    unix_nanos: u128,
    nonce: u64,
) -> String {
    let payload_hash_hex = format!("{:x}", Sha256::digest(payload));
    let kind_debug = format!("{:?}", kind);
    let id_material = [
        "nggov-proposal-id-v1".to_string(),
        chain_id.trim().to_string(),
        genesis_hash.trim().to_string(),
        prefix.trim().to_string(),
        kind_debug,
        proposer.trim().to_string(),
        payload_hash_hex,
        // Do not bind the operational proposal_id to provisional queue heights.
        // The canonical final content digest is proposal_hash_hex after inclusion;
        // this ID is a stable request/proposal handle plus entropy.
        unix_nanos.to_string(),
        nonce.to_string(),
    ];

    let mut h = Sha256::new();
    for part in id_material.iter() {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    let digest_hex = hex::encode(h.finalize());
    let canonical_prefix: String = prefix
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let canonical_prefix = canonical_prefix.trim_matches('-');
    let canonical_prefix = if canonical_prefix.is_empty() {
        "gov-proposal"
    } else {
        canonical_prefix
    };
    format!("{}-govp-{}", canonical_prefix, &digest_hex[..32])
}

fn governance_proposal_id_v1(
    prefix: &str,
    kind: &crate::governance::GovProposalKind,
    proposer: &str,
    payload: &[u8],
    created_at_height: u64,
    effective_height: u64,
    queue_len: usize,
    genesis_hash: &str,
) -> String {
    static GOVERNANCE_PROPOSAL_ID_NONCE_V1: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);

    let nonce = GOVERNANCE_PROPOSAL_ID_NONCE_V1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();

    governance_proposal_id_from_entropy_v1(
        prefix,
        kind,
        proposer,
        payload,
        created_at_height,
        effective_height,
        queue_len,
        crate::chain_identity::chain_id(),
        genesis_hash,
        unix_nanos,
        nonce,
    )
}

fn is_canonical_lowercase_sha256_hex_v1(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_canonical_governance_proposal_id_for_api_v1(value: &str) -> bool {
    crate::governance::is_canonical_governance_proposal_id_v1(value)
}

fn governance_proposal_payload_view_v1(
    prop: &crate::governance::GovProposalRecord,
) -> serde_json::Value {
    let payload_sha256 = format!("{:x}", Sha256::digest(&prop.payload));
    let payload_utf8 = std::str::from_utf8(&prop.payload).ok().map(str::to_string);

    match prop.kind {
        crate::governance::GovProposalKind::BindE2WorkerOperatorWallet => {
            match serde_json::from_slice::<crate::governance::E2WorkerOperatorBindingPayloadV1>(
                &prop.payload,
            ) {
                Ok(payload) => {
                    let worker_hex =
                        crate::keyfmt::pk_hex_from_any(&payload.worker_node_pubkey).ok();
                    let operator_hex =
                        crate::keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey).ok();
                    serde_json::json!({
                        "decoded": true,
                        "format": "e2-worker-operator-binding-v1",
                        "payload_sha256": payload_sha256,
                        "decoded_payload": {
                            "format_version": payload.format_version,
                            "worker_node_pubkey": payload.worker_node_pubkey,
                            "worker_node_pubkey_hex": worker_hex,
                            "operator_wallet_pubkey": payload.operator_wallet_pubkey,
                            "operator_wallet_pubkey_hex": operator_hex,
                            "reason": payload.reason,
                        },
                        "human_summary": "Bind an E2 worker node identity to an operator wallet identity on NewGen L1.",
                        "effects_if_approved": [
                            "Creates a canonical worker/operator binding on NewGen L1 after quorum, timelock, block inclusion and finality.",
                            "Allows E2 to project canonical worker eligibility for this worker after the finalized state includes the binding.",
                            "Does not grant validator, consensus, mining, council or protocol authority to the E2 worker.",
                            "Does not bypass E2 worker evidence validation, reputation policy, or admission checks."
                        ],
                    })
                }
                Err(e) => serde_json::json!({
                    "decoded": false,
                    "format": "e2-worker-operator-binding-v1",
                    "payload_sha256": payload_sha256,
                    "decode_error": e.to_string(),
                    "payload_utf8": payload_utf8,
                }),
            }
        }
        crate::governance::GovProposalKind::GrantE2WorkerCloudUnit
        | crate::governance::GovProposalKind::RevokeE2WorkerCloudUnit
        | crate::governance::GovProposalKind::GrantE2WorkerGpuCapability
        | crate::governance::GovProposalKind::RevokeE2WorkerGpuCapability
        | crate::governance::GovProposalKind::GrantE2WorkerCriticalWorkload
        | crate::governance::GovProposalKind::RevokeE2WorkerCriticalWorkload => {
            match serde_json::from_slice::<crate::governance::E2WorkerGovernedPrivilegePayloadV1>(
                &prop.payload,
            ) {
                Ok(payload) => {
                    let worker_hex =
                        crate::keyfmt::pk_hex_from_any(&payload.worker_node_pubkey).ok();
                    let operator_hex =
                        crate::keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey).ok();
                    serde_json::json!({
                        "decoded": true,
                        "format": "e2-worker-governed-privilege-v1",
                        "payload_sha256": payload_sha256,
                        "decoded_payload": {
                            "format_version": payload.format_version,
                            "worker_node_pubkey": payload.worker_node_pubkey,
                            "worker_node_pubkey_hex": worker_hex,
                            "operator_wallet_pubkey": payload.operator_wallet_pubkey,
                            "operator_wallet_pubkey_hex": operator_hex,
                            "reason": payload.reason,
                        },
                        "human_summary": "Govern a privileged E2 worker capability through concilium/finality.",
                        "effects_if_approved": [
                            "Updates only governed E2 privilege flags for an already canonical worker/operator relation.",
                            "Does not create standard worker onboarding; normal public workers must use the L1 self-registration path.",
                            "Does not bypass reputation/evidence validation for ordinary work.",
                            "Cloud Unit, GPU and critical workload capabilities remain explicit governed privileges."
                        ],
                    })
                }
                Err(e) => serde_json::json!({
                    "decoded": false,
                    "format": "e2-worker-governed-privilege-v1",
                    "payload_sha256": payload_sha256,
                    "decode_error": e.to_string(),
                    "payload_utf8": payload_utf8,
                }),
            }
        }
        crate::governance::GovProposalKind::IngestE2WorkerReputationEvidence => {
            match serde_json::from_slice::<
                crate::governance::E2WorkerReputationEvidenceIngestPayloadV1,
            >(&prop.payload)
            {
                Ok(payload) => serde_json::json!({
                    "decoded": true,
                    "format": "e2-worker-reputation-evidence-ingest-v1",
                    "payload_sha256": payload_sha256,
                    "decoded_payload": {
                        "format_version": payload.format_version,
                        "evidence_count": payload.evidences.len(),
                    },
                    "human_summary": "Ingest governed E2 worker execution evidence into the canonical L1 reputation plane.",
                    "effects_if_approved": [
                        "Evaluates E2 worker evidence through the canonical L1 evidence/reputation policy.",
                        "May update canonical worker/operator reputation according to the active taxonomy and policy.",
                        "Does not make E2 local state canonical before L1 governance application and finality."
                    ],
                }),
                Err(e) => serde_json::json!({
                    "decoded": false,
                    "format": "e2-worker-reputation-evidence-ingest-v1",
                    "payload_sha256": payload_sha256,
                    "decode_error": e.to_string(),
                    "payload_utf8": payload_utf8,
                }),
            }
        }
        crate::governance::GovProposalKind::IngestComputeFiatSettlementProof => {
            match serde_json::from_slice::<
                crate::compute_contract::ComputeFiatSettlementProofIngestPayloadV1,
            >(&prop.payload)
            {
                Ok(payload) => serde_json::json!({
                    "decoded": true,
                    "format": "compute-fiat-settlement-proof-ingest-v1",
                    "payload_sha256": payload_sha256,
                    "decoded_payload": {
                        "format_version": payload.format_version,
                        "proof_count": payload.proofs.len(),
                    },
                    "human_summary": "Ingest governed compute fiat/simulated settlement proof metadata.",
                    "effects_if_approved": [
                        "Records settlement proof metadata for canonical compute orders after governance application.",
                        "Does not move off-chain fiat value on-chain.",
                    ],
                }),
                Err(e) => serde_json::json!({
                    "decoded": false,
                    "format": "compute-fiat-settlement-proof-ingest-v1",
                    "payload_sha256": payload_sha256,
                    "decode_error": e.to_string(),
                    "payload_utf8": payload_utf8,
                }),
            }
        }
        _ => {
            let payload_json = serde_json::from_slice::<serde_json::Value>(&prop.payload).ok();
            serde_json::json!({
                "decoded": payload_json.is_some(),
                "format": "generic-json-or-opaque-governance-payload-v1",
                "payload_sha256": payload_sha256,
                "payload_len_bytes": prop.payload.len(),
                "decoded_payload": payload_json,
                "payload_utf8": payload_utf8,
                "human_summary": format!("Governance proposal of kind {:?}.", prop.kind),
                "effects_if_approved": [
                    "Effects are determined by the governance proposal kind and the deterministic L1 apply path.",
                ],
            })
        }
    }
}

fn governance_proposal_view_v1(
    gov: &crate::governance::GovernanceState,
    prop: &crate::governance::GovProposalRecord,
) -> serde_json::Value {
    let threshold = governance_council_threshold_for_view_v1(gov, &prop.council);
    let audit_votes_for = prop.vote_records_v1.len();
    let legacy_votes_allowed =
        crate::governance::legacy_governance_compact_votes_allowed_for_view_v1();
    let votes_for = if audit_votes_for > 0 {
        audit_votes_for
    } else if legacy_votes_allowed {
        prop.votes.len()
    } else {
        0
    };
    let voters = if audit_votes_for > 0 {
        prop.vote_records_v1.keys().cloned().collect::<Vec<_>>()
    } else if legacy_votes_allowed {
        prop.votes.keys().cloned().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let votes_remaining = (threshold as usize).saturating_sub(votes_for);
    let payload_view = governance_proposal_payload_view_v1(prop);
    serde_json::json!({
        "proposal_id": prop.id,
        "proposal_type": format!("{:?}", prop.kind),
        "proposal_status": format!("{:?}", prop.status),
        "required_council": format!("{:?}", prop.council),
        "proposal_hash_hex": prop.proposal_hash_hex,
        "proposal_id_semantics": "operational-handle-v1; not a canonical content digest",
        "canonical_content_digest": "proposal_hash_hex",
        "proposal_hash_required_for_vote": true,
        "signature_domain": prop.signature_domain,
        "chain_id": prop.chain_id,
        "genesis_hash": prop.genesis_hash,
        "expected_signature_domain": crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2,
        "vote_domain_bound_fields": ["signature_domain", "chain_id", "genesis_hash", "proposal_hash_hex"],
        "created_at_height": prop.created_at_height,
        "effective_height": prop.effective_height,
        "terminal_height": prop.terminal_height,
        "expires_at_height": prop.created_at_height.saturating_add(gov.params.max_proposal_lifetime_blocks.max(1)),
        "max_proposal_lifetime_blocks": gov.params.max_proposal_lifetime_blocks.max(1),
        "proposer": prop.proposer,
        "threshold": threshold,
        "votes_for": votes_for,
        "votes_remaining": votes_remaining,
        "voters": voters,
        "vote_records_v1": &prop.vote_records_v1,
        "vote_path": format!("/api/v2/gov/proposals/{}/vote", prop.id),
        "vote_body_template": {
            "approve": true,
            "proposal_hash_hex": prop.proposal_hash_hex,
            "reason": "<optional local/operator reason; not canonical on-chain in v1>"
        },
        "vote_reason_on_chain": false,
        "rejection_vote_supported": false,
        "decoded": payload_view,
    })
}

fn governance_proposals_list_response_v1(
    gov: &crate::governance::GovernanceState,
    query: &GovernanceProposalListQuery,
) -> serde_json::Value {
    let requested_limit = query.limit.unwrap_or(100);
    let limit = requested_limit.clamp(1, 500);
    let status_filter = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let kind_filter = query
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    let mut proposals: Vec<serde_json::Value> = gov
        .proposals
        .values()
        .filter(|p| {
            let status_ok = status_filter
                .as_ref()
                .map(|wanted| format!("{:?}", p.status).to_ascii_lowercase() == wanted.as_str())
                .unwrap_or(true);
            let kind_ok = kind_filter
                .as_ref()
                .map(|wanted| format!("{:?}", p.kind).to_ascii_lowercase() == wanted.as_str())
                .unwrap_or(true);
            status_ok && kind_ok
        })
        .map(|p| {
            let threshold = governance_council_threshold_for_view_v1(gov, &p.council);
            let audit_votes_for = p.vote_records_v1.len();
            let legacy_votes_allowed =
                crate::governance::legacy_governance_compact_votes_allowed_for_view_v1();
            let votes_for = if audit_votes_for > 0 {
                audit_votes_for
            } else if legacy_votes_allowed {
                p.votes.len()
            } else {
                0
            };
            serde_json::json!({
                "proposal_id": p.id,
                "proposal_type": format!("{:?}", p.kind),
                "proposal_status": format!("{:?}", p.status),
                "required_council": format!("{:?}", p.council),
                "proposal_hash_hex": p.proposal_hash_hex,
                "proposal_id_semantics": "operational-handle-v1; not a canonical content digest",
                "canonical_content_digest": "proposal_hash_hex",
                "proposal_hash_required_for_vote": true,
                "signature_domain": p.signature_domain,
                "chain_id": p.chain_id,
                "genesis_hash": p.genesis_hash,
                "created_at_height": p.created_at_height,
                "effective_height": p.effective_height,
                "terminal_height": p.terminal_height,
                "expires_at_height": p.created_at_height.saturating_add(gov.params.max_proposal_lifetime_blocks.max(1)),
                "max_proposal_lifetime_blocks": gov.params.max_proposal_lifetime_blocks.max(1),
                "threshold": threshold,
                "votes_for": votes_for,
                "votes_remaining": (threshold as usize).saturating_sub(votes_for),
                "vote_path": format!("/api/v2/gov/proposals/{}/vote", p.id),
                "governance_flow": governance_flow_response_v1(&p.id),
            })
        })
        .collect();
    proposals.sort_by(|a, b| {
        let a_height = a
            .get("created_at_height")
            .and_then(|h| h.as_u64())
            .unwrap_or(0);
        let b_height = b
            .get("created_at_height")
            .and_then(|h| h.as_u64())
            .unwrap_or(0);
        let a_id = a
            .get("proposal_id")
            .and_then(|id| id.as_str())
            .unwrap_or("");
        let b_id = b
            .get("proposal_id")
            .and_then(|id| id.as_str())
            .unwrap_or("");
        b_height.cmp(&a_height).then_with(|| a_id.cmp(b_id))
    });
    let total_matching = proposals.len();
    proposals.truncate(limit);
    let returned = proposals.len();

    serde_json::json!({
        "status": "ok",
        "surface": "governance-proposals-v1",
        "limit": limit,
        "returned": returned,
        "total_matching": total_matching,
        "filters": {
            "status": status_filter,
            "kind": kind_filter,
        },
        "count": returned,
        "proposals": proposals,
    })
}

// ==========================================================
// Step 37 — Superficie API "ufficiale" di NewGen Engine™
// ==========================================================
// Questi endpoint sono quelli che consideriamo stabili per:
//  - Explorer ufficiale
//  - eventuali client / servizi esterni
//
// HEALTH & INFO
//   GET  /health                      → {"status":"ok"}
//   GET  /status                      → {"status":"ok"}
//   GET  /api/blockchain/info         → height, hash, supply, ecc.
//   GET  /api/blockchain/last         → ultimo blocco
//
// WALLET & TX (v2)
//   GET  /api/v2/wallet/balance/{pk}  → saldo per public_key b64
//
// LOCAL/LAB ONLY (not mounted in public_mode):
//   GET  /api/v2/wallet/info          → wallet locale del nodo (pk, balance)
//   GET  /api/v2/wallet/local_pubkey  → pubkey locale del nodo
//   POST /api/v2/wallet/send_from_node
//        body: { "receiver": pk_b64, "amount": u64 | "0.00057" }
//        → { status, tx_hash, nonce_used }
//
//   POST /api/v2/tx/submit_signed
//        body: SignedTransaction (schema canonico v2)
//        → { status, ... } (invalid_signature / replay_or_old_nonce / ok)
//
//   GET  /api/v2/wallet/next_nonce/{pk}  → { address, next_nonce }
//   GET  /api/v2/tx/get_next_nonce/{pk}  → alias legacy/compat dello stesso endpoint
//
// MEMPOOL
//   GET  /api/mempool                 → lista TX in attesa (debug / explorer)
//
// ECONOMIA & TREASURY
//   GET  /api/v2/dashboard/economy    → committed + controller_local (+ legacy canonical_chain_economy/local_node_observation)
//   GET  /api/v2/treasury/state       → treasury_balance, total_supply, parametri
//   GET  /api/v2/epn/history          → lista (stub) delle Economic Policy Notes
//
// Nota: altri endpoint presenti in questo file possono essere
//       LEGACY / DEV-ONLY e non fanno parte della superficie pubblica stabile.
// ==========================================================

// ====== Costanti API ======
const MAX_NONCE_GAP: u64 = 10; // tolleranza nonce futuro
#[allow(dead_code)]
const REPLACE_FEE_FACTOR_BPS: u64 = 11000;
const MAX_TX_BODY_BYTES: u64 = 64 * 1024;
const MAX_SMALL_BODY_BYTES: u64 = 4 * 1024; // 1.10x in basis points (10000=1.00x)

// NGT amount encoding: UI may send decimal strings (e.g. "0.000575").
// We parse deterministically into atomic units without floats.
const NGT_DECIMALS: usize = 6;
const NGT_SCALE: u64 = 1_000_000;

fn record_gateway_fee_low_rejection(mp: &Arc<Mutex<Mempool>>) {
    let mut mp = lock_any!(mp);
    mp.record_fee_low_rejection_from_gateway();
}

#[derive(Clone, Debug, Deserialize)]
struct MempoolListQueryV1 {
    limit: Option<usize>,
}

const MEMPOOL_LIST_DEFAULT_LIMIT_V1: usize = 128;
const MEMPOOL_LIST_MAX_LIMIT_V1: usize = 500;

fn mempool_list_limit_v1(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(MEMPOOL_LIST_DEFAULT_LIMIT_V1)
        .clamp(1, MEMPOOL_LIST_MAX_LIMIT_V1)
}

fn constant_time_eq_bytes_v1(a: &[u8], b: &[u8]) -> bool {
    // Compare without early-returning on length mismatch. This avoids making
    // admin-token verification branch on the supplied token length before the
    // byte scan. The length still participates in the final diff.
    let max_len = a.len().max(b.len());
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= av ^ bv;
    }
    diff == 0
}

fn enforce_security_fee_with_mempool_snapshot(
    mp: &Arc<Mutex<Mempool>>,
    tx: &Transaction,
) -> Result<(), crate::mempool::FeeError> {
    let (min_fee_per_tx, min_fee_per_byte, base_fee_per_tx) = {
        let mp = lock_any!(mp);
        mp.fee_policy_snapshot()
    };
    let result = Mempool::enforce_min_fee_for_tx_with_fee_floors(
        tx,
        min_fee_per_tx,
        min_fee_per_byte,
        base_fee_per_tx,
    );
    if result.is_err() {
        // Gateway/API pre-admission rejects are local ingress telemetry.
        // They must be visible to the adaptive fee controller, but they do
        // not mutate consensus state and do not insert anything in mempool.
        record_gateway_fee_low_rejection(mp);
    }
    result
}

#[derive(Debug, Clone)]
struct SenderAdmissionState {
    chain_balance: u64,
    base_fee_per_tx: u64,
    last_chain_nonce: u64,
    last_mempool_nonce: u64,
    pending_reserved_total: u64,
    pending_count: usize,
}

impl SenderAdmissionState {
    fn expected_next_nonce(&self) -> u64 {
        std::cmp::max(self.last_chain_nonce, self.last_mempool_nonce).saturating_add(1)
    }

    fn available_balance_after_pending(&self) -> u64 {
        self.chain_balance
            .saturating_sub(self.pending_reserved_total)
    }
}

fn snapshot_sender_admission_state(
    chain: &SharedChain,
    mempool: &Arc<Mutex<Mempool>>,
    sender: &str,
) -> SenderAdmissionState {
    let (chain_balance, base_fee_per_tx, last_chain_nonce) = {
        let bc = lock_any!(chain);
        let balance_i128 = bc.get_balance(sender);
        let chain_balance = if balance_i128 <= 0 {
            0
        } else {
            balance_i128 as u64
        };
        (
            chain_balance,
            bc.base_fee_per_tx(),
            bc.get_last_nonce(sender),
        )
    };

    let (pending_reserved_total, pending_count, last_mempool_nonce) = {
        let mp = lock_any!(mempool);
        (
            mp.sender_pending_reserved_total(sender),
            mp.sender_pending_count(sender),
            mp.get_last_nonce(sender),
        )
    };

    SenderAdmissionState {
        chain_balance,
        base_fee_per_tx,
        last_chain_nonce,
        last_mempool_nonce,
        pending_reserved_total,
        pending_count,
    }
}

fn insufficient_funds_after_pending_reply(
    state: &SenderAdmissionState,
    required_additional: u64,
    requested_amount: u64,
    requested_max_fee_per_tx: u64,
    extra_native_required: u64,
) -> warp::reply::WithStatus<warp::reply::Json> {
    let available_after_pending = state.available_balance_after_pending();
    let max_send_after_pending = available_after_pending
        .saturating_sub(requested_max_fee_per_tx.saturating_add(extra_native_required));

    warp::reply::with_status(
        warp::reply::json(&serde_json::json!({
            "status": "insufficient_funds_after_pending",
            "message": "insufficient_funds_after_pending",
            "chain_balance": state.chain_balance,
            "pending_reserved_total": state.pending_reserved_total,
            "pending_tx_count": state.pending_count as u64,
            "available_balance_after_pending": available_after_pending,
            "requested_amount": requested_amount,
            "requested_max_fee_per_tx": requested_max_fee_per_tx,
            "base_fee_per_tx": state.base_fee_per_tx,
            "extra_native_required": extra_native_required,
            "required_additional": required_additional,
            "required_total_with_pending": state.pending_reserved_total.saturating_add(required_additional),
            "max_send_after_pending": max_send_after_pending
        })),
        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
    )
}

fn reject_if_sender_cannot_cover_pending(
    state: &SenderAdmissionState,
    required_additional: u64,
    requested_amount: u64,
    requested_max_fee_per_tx: u64,
    extra_native_required: u64,
) -> Option<warp::reply::WithStatus<warp::reply::Json>> {
    if state.available_balance_after_pending() < required_additional {
        Some(insufficient_funds_after_pending_reply(
            state,
            required_additional,
            requested_amount,
            requested_max_fee_per_tx,
            extra_native_required,
        ))
    } else {
        None
    }
}

// Allow legacy/compat network_id handling for devnet/public tests.
// Default is STRICT (false). Enable only when you intentionally support older clients:
//   set NEWGEN_DEVNET_COMPAT_NETWORK_ID=1
fn allow_legacy_network_id() -> bool {
    // Professional default: OFF unless you explicitly build with:
    //   --features devnet-compat-network-id
    #[cfg(feature = "devnet-compat-network-id")]
    {
        match env::var("NEWGEN_DEVNET_COMPAT_NETWORK_ID") {
            Ok(v) => {
                let v = v.trim().to_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "on"
            }
            Err(_) => false,
        }
    }

    #[cfg(not(feature = "devnet-compat-network-id"))]
    {
        false
    }
}

// API hard caps (do not let clients force unbounded JSON / lock time)
const BLOCKS_V2_DEFAULT_LIMIT: usize = 50;
const BLOCKS_V2_MAX_LIMIT: usize = 100;

#[cfg_attr(not(debug_assertions), allow(dead_code))]
#[derive(Debug, Clone, serde::Deserialize)]
struct MineEmptyReq {
    /// Quanti blocchi vuoti minare (default: 1)
    pub count: Option<u32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RandaoFromNodeReq {
    pub epoch: u64,
    /// 32 bytes, base64 o hex (accetta entrambi)
    pub secret_b64: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GovUpdateValidatorsReq {
    /// Lista completa del nuovo validator set (pub_key b64/hex, alias opzionale, weight opzionale)
    pub entries: Vec<crate::governance::ValidatorEntry>,
    /// Versione esplicita (se assente: current_version + 1)
    pub version: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BlocksQuery {
    from_height: Option<u64>,
    limit: Option<usize>,
    order: Option<String>, // "asc" | "desc" (default: desc)
}

#[derive(Debug, Deserialize)]
struct CognitiveRegistryEventsQuery {
    from_height: Option<u64>,
    limit: Option<usize>,
}

const COGNITIVE_REGISTRY_EVENTS_DEFAULT_LIMIT: usize = 100;
const COGNITIVE_REGISTRY_EVENTS_MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
struct TxHistoryQuery {
    /// height di partenza (inclusa). Se assente: tip corrente.
    from_height: Option<u64>,
    /// numero massimo di blocchi da scandire (bounded). Se assente: default.
    blocks: Option<usize>,
    /// numero massimo di transazioni da restituire (bounded). Se assente: default.
    max_txs: Option<usize>,
    /// Default true. Set false per escludere le coinbase dalla wallet history.
    include_coinbase: Option<bool>,
    /// Alias UX: true == include_coinbase=false.
    only_user_txs: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WalletSecureNewBody {
    password: String,
}

#[derive(Debug, Deserialize)]
struct ChainExportQuery {
    /// height di partenza (inclusa). Se assente: tip.
    from_height: Option<u64>,
    /// numero massimo di blocchi da esportare (bounded).
    limit: Option<usize>,
    /// includi anche le transazioni per blocco (bounded). Default: false.
    include_txs: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TxHistoryItem {
    height: u64,
    sender: String,
    receiver: String,
    amount: u64,
    max_fee_per_tx: u64,
    nonce: u64,
    hash: String,
    is_coinbase: bool,
    memo: Option<String>,
}

#[derive(Debug, Serialize)]
struct TxHistoryResponse {
    status: String,
    address: String,
    tip_height: u64,
    from_height: u64,
    scanned_blocks: usize,
    returned: usize,
    returned_user_txs: usize,
    returned_coinbase_txs: usize,
    include_coinbase: bool,
    next_from_height: Option<u64>,
    txs: Vec<TxHistoryItem>,
}

#[derive(Debug, Serialize)]
struct ExportTx {
    sender: String,
    receiver: String,
    amount: u64,
    max_fee_per_tx: u64,
    nonce: u64,
    is_coinbase: bool,
    hash: String,
    memo: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExportBlock {
    index: u64,
    timestamp: u64,
    hash: String,
    previous_hash: String,
    miner_pub_key: String,
    tx_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nft_events: Vec<crate::nft::NftEventV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transactions: Option<Vec<ExportTx>>,
}

#[derive(Debug, Serialize)]
struct ExportBlocksResponse {
    status: String,
    tip_height: u64,
    from_height: u64,
    returned: usize,
    next_from_height: Option<u64>,
    include_txs: bool,
    blocks: Vec<ExportBlock>,
}

const TX_HISTORY_DEFAULT_BLOCKS: usize = 200;
const TX_HISTORY_MAX_BLOCKS: usize = 300;
const TX_HISTORY_DEFAULT_MAX_TXS: usize = 2000;
const TX_HISTORY_MAX_TXS: usize = 5000;

const EXPORT_DEFAULT_LIMIT: usize = 100;
const EXPORT_MAX_LIMIT: usize = 300;
const EXPORT_MAX_LIMIT_WITH_TXS: usize = 80;

fn clamp_usize(v: Option<usize>, default_v: usize, min_v: usize, max_v: usize) -> usize {
    v.unwrap_or(default_v).clamp(min_v, max_v)
}

fn export_blocks_from_chain(
    bc: &Blockchain,
    from_height: u64,
    limit: usize,
    include_txs: bool,
) -> (Vec<ExportBlock>, Option<u64>) {
    if bc.chain.is_empty() {
        return (vec![], None);
    }

    let base = bc.chain.first().map(|b| b.index).unwrap_or(0);
    let tip = bc.chain.last().map(|b| b.index).unwrap_or(0);

    let from = from_height.clamp(base, tip);

    // Fast-path: chain contigua (index == position)
    let contiguous = ((tip - base) as usize + 1) == bc.chain.len();

    let mut selected: Vec<&_> = Vec::with_capacity(limit);
    let mut earliest: Option<u64> = None;

    if contiguous {
        let pos = (from - base) as usize;
        for b in bc.chain[..=pos].iter().rev().take(limit) {
            earliest = Some(b.index);
            selected.push(b);
        }
    } else {
        for b in bc.chain.iter().rev() {
            if b.index > from {
                continue;
            }
            earliest = Some(b.index);
            selected.push(b);
            if selected.len() >= limit {
                break;
            }
        }
    }

    let mut out: Vec<ExportBlock> = Vec::with_capacity(selected.len());
    for b in selected {
        let txs = if include_txs {
            Some(
                b.transactions
                    .iter()
                    .map(|tx| ExportTx {
                        sender: tx.sender.clone(),
                        receiver: tx.receiver.clone(),
                        amount: tx.amount,
                        max_fee_per_tx: tx.max_fee_per_tx,
                        nonce: tx.nonce,
                        is_coinbase: tx.is_coinbase,
                        hash: tx.hash.clone(),
                        memo: tx.memo.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        out.push(ExportBlock {
            index: b.index,
            timestamp: b.timestamp,
            hash: b.hash.clone(),
            previous_hash: b.previous_hash.clone(),
            miner_pub_key: b.miner_pub_key.clone(),
            tx_count: b.transactions.len(),
            nft_events: b.nft_events.clone(),
            transactions: txs,
        });
    }

    let next_from_height = earliest.and_then(|h| if h > base { Some(h - 1) } else { None });

    (out, next_from_height)
}
#[derive(Debug, Serialize, Clone)]
struct BlockSummaryV2 {
    index: u64,
    timestamp: u64,
    hash: String,
    previous_hash: String,
    miner_pub_key: String,
    tx_count: usize,
}

#[derive(Debug, Serialize)]
struct BlocksPageV2 {
    status: String,
    tip_height: u64,
    from_height: u64,
    returned: usize,
    next_from_height: Option<u64>,
    order: String,
    blocks: Vec<BlockSummaryV2>,
}

#[derive(Debug, Serialize)]
struct CognitiveViewEnvelopeV1<T: Serialize + std::fmt::Debug> {
    status: &'static str,
    format_version: u16,
    view: T,
}

#[derive(Debug, Serialize)]
struct CognitiveNotFoundEnvelopeV1 {
    status: &'static str,
    format_version: u16,
    object_hash: String,
}

#[derive(Debug, Serialize)]
struct CognitiveErrorEnvelopeV1 {
    status: &'static str,
    format_version: u16,
    message: String,
}

#[derive(Debug, Serialize)]
struct CognitiveConsensusFinalityEnvelopeV2 {
    status: &'static str,
    format_version: u16,
    view: CognitiveConsensusFinalityViewV1,
    e2_ready: bool,
    unavailable_reason: Option<String>,
}

fn validate_api_cognitive_reconciliation_context_v1(
    view: &CognitiveRegistryReconciliationContextV1,
) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err(format!(
            "unsupported cognitive reconciliation context format_version={} expected={}",
            view.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
        ));
    }
    if view.chain_id.trim().is_empty() {
        return Err("cognitive reconciliation context missing chain_id".to_string());
    }
    if view.genesis_hash.trim().is_empty() {
        return Err("cognitive reconciliation context missing genesis_hash".to_string());
    }
    if view.tip_height > 0 && view.tip_hash.trim().is_empty() {
        return Err(
            "cognitive reconciliation context missing tip_hash for non-zero tip_height".to_string(),
        );
    }
    if view.finalized_height > 0 && view.finalized_hash.trim().is_empty() {
        return Err(
            "cognitive reconciliation context missing finalized_hash for non-zero finalized_height"
                .to_string(),
        );
    }
    if view.finalized_height > view.tip_height {
        return Err(
            "cognitive reconciliation context finalized_height exceeds tip_height".to_string(),
        );
    }
    Ok(())
}

fn validate_api_cognitive_status_view_v1(
    view: &CognitiveRegistryStatusViewV1,
) -> Result<(), String> {
    validate_api_cognitive_reconciliation_context_v1(&view.reconciliation_context)?;
    if view.object_hash_hex.trim().is_empty() {
        return Err("cognitive status view missing object_hash_hex".to_string());
    }
    if view.claim_hash_hex.trim().is_empty() {
        return Err("cognitive status view missing claim_hash_hex".to_string());
    }
    if view.lifecycle_state.trim().is_empty() {
        return Err("cognitive status view missing lifecycle_state".to_string());
    }
    if view.policy_id.trim().is_empty() {
        return Err("cognitive status view missing policy_id".to_string());
    }
    if view.anchor_height > 0 && view.anchor_block_hash.trim().is_empty() {
        return Err(
            "cognitive status view missing anchor_block_hash for non-zero anchor_height"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_api_cognitive_object_view_v1(
    view: &CognitiveRegistryObjectViewV1,
) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err(format!(
            "unsupported cognitive object view format_version={} expected={}",
            view.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
        ));
    }
    if view.entry.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("cognitive object entry format_version mismatch".to_string());
    }
    if view.entry.object_hash_hex != view.status_view.object_hash_hex {
        return Err(
            "cognitive object view object_hash_hex mismatch between entry and status_view"
                .to_string(),
        );
    }
    if view.entry.claim_hash_hex != view.status_view.claim_hash_hex {
        return Err(
            "cognitive object view claim_hash_hex mismatch between entry and status_view"
                .to_string(),
        );
    }
    validate_api_cognitive_status_view_v1(&view.status_view)
}

fn validate_api_cognitive_claim_view_v1(view: &CognitiveRegistryClaimViewV1) -> Result<(), String> {
    validate_api_cognitive_reconciliation_context_v1(&view.reconciliation_context)?;
    if view.claim_hash_hex.trim().is_empty() {
        return Err("cognitive claim view missing claim_hash_hex".to_string());
    }
    for row in &view.rows {
        validate_api_cognitive_status_view_v1(&row.status_view)?;
        if row.entry.claim_hash_hex != view.claim_hash_hex {
            return Err("cognitive claim view row claim_hash_hex mismatch".to_string());
        }
        if row.entry.object_hash_hex != row.status_view.object_hash_hex {
            return Err(
                "cognitive claim view row object_hash_hex mismatch between entry and status_view"
                    .to_string(),
            );
        }
        if row.entry.claim_hash_hex != row.status_view.claim_hash_hex {
            return Err(
                "cognitive claim view row claim_hash_hex mismatch between entry and status_view"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn validate_api_cognitive_consensus_finality_view_v1(
    view: &CognitiveConsensusFinalityViewV1,
) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err(format!(
            "unsupported cognitive consensus finality format_version={} expected={}",
            view.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
        ));
    }
    if view.tip_height > 0 && view.tip_hash.trim().is_empty() {
        return Err(
            "cognitive consensus finality missing tip_hash for non-zero tip_height".to_string(),
        );
    }
    if view.finalized_height > 0 && view.finalized_hash.trim().is_empty() {
        return Err(
            "cognitive consensus finality missing finalized_hash for non-zero finalized_height"
                .to_string(),
        );
    }
    if view.highest_qc_height > 0 && view.highest_qc_block_hash.trim().is_empty() {
        return Err("cognitive consensus finality missing highest_qc_block_hash for non-zero highest_qc_height".to_string());
    }
    if view.finalized_height > view.tip_height {
        return Err("cognitive consensus finality finalized_height exceeds tip_height".to_string());
    }
    Ok(())
}

fn validate_api_cognitive_contract_snapshot_v1(
    view: &CognitiveContractSnapshotV1,
) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err(format!(
            "unsupported cognitive contract snapshot format_version={} expected={}",
            view.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
        ));
    }
    if view.cognitive_contract_version.trim().is_empty() {
        return Err("cognitive contract snapshot missing cognitive_contract_version".to_string());
    }
    if view.min_supported_version.trim().is_empty() {
        return Err("cognitive contract snapshot missing min_supported_version".to_string());
    }
    if view.registry_features.is_empty() {
        return Err("cognitive contract snapshot missing registry_features".to_string());
    }
    if view.object_kind_allowlist.is_empty() {
        return Err("cognitive contract snapshot missing object_kind_allowlist".to_string());
    }
    if view.finality_binding_rules.is_empty() {
        return Err("cognitive contract snapshot missing finality_binding_rules".to_string());
    }
    if view.hash_algo.trim().is_empty() {
        return Err("cognitive contract snapshot missing hash_algo".to_string());
    }
    Ok(())
}

fn cognitive_api_error_reply_v1(
    message: String,
    status: warp::http::StatusCode,
) -> warp::reply::Response {
    warp::reply::with_header(
        warp::reply::with_status(
            warp::reply::json(&CognitiveErrorEnvelopeV1 {
                status: "error",
                format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
                message,
            }),
            status,
        ),
        "Cache-Control",
        "no-store",
    )
    .into_response()
}

// ====== Admin guard (release hardening) ======
#[derive(Debug, Clone)]
struct AdminConfig {
    admin_token: Option<String>,
}

fn admin_token_is_strong_enough_for_public_mode_v1(token: &str) -> bool {
    let token = token.trim();
    token.len() >= 32
        && !matches!(
            token.to_ascii_lowercase().as_str(),
            "admin" | "password" | "local-admin" | "newgen-local-admin" | "changeme"
        )
        && token.bytes().any(|b| b.is_ascii_uppercase())
        && token.bytes().any(|b| b.is_ascii_lowercase())
        && token.bytes().any(|b| b.is_ascii_digit())
        && token.bytes().any(|b| !b.is_ascii_alphanumeric())
}

fn env_flag_true_v1(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn admin_routes_enabled_v1(admin: &AdminConfig) -> bool {
    admin.admin_token.is_some()
}

fn load_admin_config(public_mode: bool) -> AdminConfig {
    // In release: set NEWGEN_API_ADMIN_TOKEN to enable admin endpoints.
    // If unset, admin endpoints are not mounted at all.
    let tok = env::var("NEWGEN_API_ADMIN_TOKEN").ok().and_then(|v| {
        let v = v.trim().to_string();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    });

    if public_mode {
        if let Some(token) = tok.as_deref() {
            if !admin_token_is_strong_enough_for_public_mode_v1(token) {
                panic!(
                    "NEWGEN_API_ADMIN_TOKEN is too weak for public mode: require >=32 chars with upper/lower/digit/symbol, or unset it to disable admin routes"
                );
            }
        }
    }

    AdminConfig { admin_token: tok }
}

#[cfg(debug_assertions)]
fn debug_faucet_mempool_disabled_response_v1(receiver: String, amount: u64) -> serde_json::Value {
    serde_json::json!({
        "status":"error",
        "message":"debug_faucet_mempool_path_disabled",
        "reason":"coinbase_transactions_are_block_rewards_only",
        "to": receiver,
        "amount": amount
    })
}

fn enforce_admin_public_bind_policy_v1(
    public_mode: bool,
    admin_enabled: bool,
    api_bind_ip: std::net::IpAddr,
) {
    if !admin_enabled {
        return;
    }

    eprintln!(
        "⚠️ [API ADMIN] admin routes enabled; bind_ip={} public_mode={} allow_public_bind={}",
        api_bind_ip,
        public_mode,
        env_flag_true_v1("NEWGEN_API_ADMIN_ALLOW_PUBLIC_BIND")
    );

    if public_mode
        && !api_bind_ip.is_loopback()
        && !env_flag_true_v1("NEWGEN_API_ADMIN_ALLOW_PUBLIC_BIND")
    {
        panic!(
            "admin routes cannot bind to non-loopback address in public mode unless NEWGEN_API_ADMIN_ALLOW_PUBLIC_BIND=1"
        );
    }
}

fn with_admin(
    admin: Arc<AdminConfig>,
) -> impl Filter<Extract = (Arc<AdminConfig>,), Error = Infallible> + Clone {
    warp::any().map(move || admin.clone())
}

fn admin_guard(
    admin: Arc<AdminConfig>,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("x-admin-token")
        .and(with_admin(admin))
        .and_then(|hdr: Option<String>, admin: Arc<AdminConfig>| async move {
            match (hdr.as_deref(), admin.admin_token.as_deref()) {
                (Some(provided), Some(expected))
                    if constant_time_eq_bytes_v1(provided.as_bytes(), expected.as_bytes()) =>
                {
                    Ok(())
                }
                _ => Err(warp::reject::custom(ApiError::Forbidden)),
            }
        })
}

#[cfg(test)]
mod admin_surface_policy_tests {
    use super::*;

    #[test]
    fn public_mode_admin_token_requires_strong_secret_v1() {
        assert!(!admin_token_is_strong_enough_for_public_mode_v1(
            "local-admin"
        ));
        assert!(!admin_token_is_strong_enough_for_public_mode_v1(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(admin_token_is_strong_enough_for_public_mode_v1(
            "NewGen-Admin-Token-2026-Strong-Secret!"
        ));
    }

    #[test]
    fn admin_token_compare_requires_exact_constant_time_match_v1() {
        assert!(constant_time_eq_bytes_v1(
            b"NewGen-Admin-Token-2026",
            b"NewGen-Admin-Token-2026"
        ));
        assert!(!constant_time_eq_bytes_v1(
            b"NewGen-Admin-Token-2026",
            b"NewGen-Admin-Token-2027"
        ));
        assert!(!constant_time_eq_bytes_v1(
            b"NewGen-Admin-Token-2026",
            b"NewGen-Admin-Token"
        ));
        assert!(!constant_time_eq_bytes_v1(
            b"NewGen-Admin-Token",
            b"NewGen-Admin-Token-2026"
        ));
    }

    #[test]
    fn public_mode_admin_bind_requires_loopback_or_explicit_override_v1() {
        std::env::remove_var("NEWGEN_API_ADMIN_ALLOW_PUBLIC_BIND");
        assert!(std::panic::catch_unwind(|| {
            enforce_admin_public_bind_policy_v1(
                true,
                true,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            )
        })
        .is_err());

        enforce_admin_public_bind_policy_v1(
            true,
            true,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
    }

    #[test]
    fn gov_nft_policy_propose_public_admin_surface_requires_token_and_loopback_v1() {
        assert!(!admin_token_is_strong_enough_for_public_mode_v1(
            "local-admin"
        ));
        assert!(admin_token_is_strong_enough_for_public_mode_v1(
            "NewGen-Admin-Token-2026-Strong-Secret!"
        ));
        let disabled = AdminConfig { admin_token: None };
        assert!(
            !admin_routes_enabled_v1(&disabled),
            "admin routes, including gov/nft/policy/propose, must not mount without NEWGEN_API_ADMIN_TOKEN"
        );
        enforce_admin_public_bind_policy_v1(
            true,
            false,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        );
        assert!(std::panic::catch_unwind(|| {
            enforce_admin_public_bind_policy_v1(
                true,
                true,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            )
        })
        .is_err());
    }

    #[test]
    fn gov_nft_policy_propose_admin_guard_rejects_missing_and_wrong_token_v1() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let admin = Arc::new(AdminConfig {
                admin_token: Some("NewGen-Admin-Token-2026-Strong-Secret!".to_string()),
            });
            let route = warp::path!("api" / "v2" / "gov" / "nft" / "policy" / "propose")
                .and(warp::post())
                .and(admin_guard(admin))
                .map(|_g: ()| warp::reply::json(&serde_json::json!({"status":"ok"})))
                .recover(error_handler);

            let missing = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/nft/policy/propose")
                .reply(&route)
                .await;
            assert_eq!(missing.status(), warp::http::StatusCode::FORBIDDEN);

            let wrong = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/nft/policy/propose")
                .header("x-admin-token", "wrong-token")
                .reply(&route)
                .await;
            assert_eq!(wrong.status(), warp::http::StatusCode::FORBIDDEN);

            let ok = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/nft/policy/propose")
                .header("x-admin-token", "NewGen-Admin-Token-2026-Strong-Secret!")
                .reply(&route)
                .await;
            assert_eq!(ok.status(), warp::http::StatusCode::OK);
        });
    }
}

/* ==========================================================
Step 60A — API abuse-resistance middleware
- Per-IP rate limiting (token bucket)
- Global in-flight concurrency cap
- Common security + cache headers
========================================================== */

#[derive(Debug)]
struct RateLimited {
    retry_after_secs: u32,
    scope: &'static str,
    profile: &'static str,
    policy_rps: f64,
    policy_burst: f64,
}
impl warp::reject::Reject for RateLimited {}

#[derive(Debug)]
struct ServerBusy;
impl warp::reject::Reject for ServerBusy {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateScope {
    General,
    HeavyRead,
    TxSubmit,
}
impl RateScope {
    fn as_str(&self) -> &'static str {
        match self {
            RateScope::General => "general",
            RateScope::HeavyRead => "heavy_read",
            RateScope::TxSubmit => "tx_submit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiGuardProfile {
    Production,
    LegacyNonPublic,
    TrustedBenchmarkLocal,
}
impl ApiGuardProfile {
    fn as_str(&self) -> &'static str {
        match self {
            ApiGuardProfile::Production => "production",
            ApiGuardProfile::LegacyNonPublic => "legacy_non_public",
            ApiGuardProfile::TrustedBenchmarkLocal => "trusted_benchmark_local",
        }
    }

    fn from_env(public_mode: bool) -> Self {
        let raw = std::env::var("NEWGEN_API_GUARD_PROFILE").ok();
        if public_mode {
            if let Some(v) = raw.as_deref() {
                let norm = v.trim().to_ascii_lowercase();
                if norm != "production" && norm != "prod" {
                    eprintln!(
                        "⚠️ [API BOOT] ignoring NEWGEN_API_GUARD_PROFILE='{}' in public_mode; forcing production profile.",
                        v
                    );
                }
            }
            return ApiGuardProfile::Production;
        }

        match raw.as_deref().map(|v| v.trim().to_ascii_lowercase()) {
            None => ApiGuardProfile::LegacyNonPublic,
            Some(v) if v == "production" || v == "prod" => ApiGuardProfile::Production,
            Some(v)
                if v == "legacy_non_public"
                    || v == "legacy-non-public"
                    || v == "legacy"
                    || v == "default" =>
            {
                ApiGuardProfile::LegacyNonPublic
            }
            Some(v)
                if v == "trusted_benchmark_local"
                    || v == "trusted-benchmark-local"
                    || v == "benchmark"
                    || v == "benchmark_local"
                    || v == "trusted_dev"
                    || v == "trusted-dev" =>
            {
                ApiGuardProfile::TrustedBenchmarkLocal
            }
            Some(other) => {
                eprintln!(
                    "⚠️ [API BOOT] invalid NEWGEN_API_GUARD_PROFILE='{}'; falling back to legacy_non_public.",
                    other
                );
                ApiGuardProfile::LegacyNonPublic
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RatePolicy {
    rps: f64,
    burst: f64,
}
impl RatePolicy {
    fn from_env(prefix: &str, default_rps: f64, default_burst: f64) -> Self {
        let rps = std::env::var(format!("{prefix}_RPS"))
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v > 0.0)
            .unwrap_or(default_rps);

        let burst = std::env::var(format!("{prefix}_BURST"))
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v > 0.0)
            .unwrap_or(default_burst);

        Self { rps, burst }
    }
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug, Clone)]
struct ApiGuardConfig {
    profile: ApiGuardProfile,
    general: RatePolicy,
    heavy_read: RatePolicy,
    tx_submit: RatePolicy,
    max_in_flight: usize,
}

impl ApiGuardConfig {
    fn resolve(public_mode: bool) -> Self {
        let profile = ApiGuardProfile::from_env(public_mode);
        let ((g_rps, g_burst), (h_rps, h_burst), (t_rps, t_burst), max_in_flight_default) =
            match profile {
                ApiGuardProfile::Production => ((15.0, 30.0), (3.0, 6.0), (2.0, 4.0), 128),
                ApiGuardProfile::LegacyNonPublic => ((50.0, 100.0), (10.0, 20.0), (8.0, 16.0), 512),
                ApiGuardProfile::TrustedBenchmarkLocal => {
                    ((200.0, 400.0), (50.0, 100.0), (1000.0, 2000.0), 4096)
                }
            };

        let general = RatePolicy::from_env("NEWGEN_API_RL_GENERAL", g_rps, g_burst);
        let heavy_read = RatePolicy::from_env("NEWGEN_API_RL_HEAVY", h_rps, h_burst);
        let tx_submit = RatePolicy::from_env("NEWGEN_API_RL_TX", t_rps, t_burst);
        let max_in_flight = std::env::var("NEWGEN_API_MAX_IN_FLIGHT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(max_in_flight_default);

        Self {
            profile,
            general,
            heavy_read,
            tx_submit,
            max_in_flight,
        }
    }
}

#[derive(Clone)]
struct RateLimiter {
    // key: (ip, scope)
    buckets: Arc<Mutex<HashMap<(String, RateScope), TokenBucket>>>,
    profile: ApiGuardProfile,
    general: RatePolicy,
    heavy_read: RatePolicy,
    tx_submit: RatePolicy,
}

impl RateLimiter {
    fn new(cfg: &ApiGuardConfig) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            profile: cfg.profile,
            general: cfg.general.clone(),
            heavy_read: cfg.heavy_read.clone(),
            tx_submit: cfg.tx_submit.clone(),
        }
    }

    fn classify(path: &str, method: &Method) -> RateScope {
        // Writes: stricter
        if *method == Method::POST
            && (path.starts_with("/api/v2/tx/submit_signed")
                || path.starts_with("/api/v2/tx/submit")
                || path.starts_with("/api/v2/wallet/send_from_node")
                || path.starts_with("/api/v2/ft/send_from_node")
                || path.starts_with("/api/v2/nft/send_from_node"))
        {
            return RateScope::TxSubmit;
        }

        // Heavy reads
        if *method == Method::GET
            && (path.starts_with("/api/tx/history/")
                || path.starts_with("/api/v2/light/headers")
                || path.starts_with("/api/v2/blocks")
                || path.starts_with("/api/v2/block/"))
        {
            return RateScope::HeavyRead;
        }

        RateScope::General
    }

    fn policy(&self, scope: RateScope) -> RatePolicy {
        match scope {
            RateScope::General => self.general.clone(),
            RateScope::HeavyRead => self.heavy_read.clone(),
            RateScope::TxSubmit => self.tx_submit.clone(),
        }
    }

    fn check(&self, ip: &str, scope: RateScope) -> Result<(), RateLimited> {
        let pol = self.policy(scope);

        // Safety: avoid division by zero
        if pol.rps <= 0.0 || pol.burst <= 0.0 {
            return Ok(());
        }

        let now = Instant::now();
        let mut map = lock_any!(self.buckets);

        // crude memory cap: if under attack with many spoofed IPs, bound state
        if map.len() > 50_000 {
            map.clear();
        }

        let key = (ip.to_string(), scope);
        let b = map.entry(key).or_insert(TokenBucket {
            tokens: pol.burst,
            last: now,
        });

        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * pol.rps).min(pol.burst);

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            // retry-after in seconds (ceil)
            let need = 1.0 - b.tokens;
            let ra = (need / pol.rps).ceil().max(1.0) as u32;
            Err(RateLimited {
                retry_after_secs: ra,
                scope: scope.as_str(),
                profile: self.profile.as_str(),
                policy_rps: pol.rps,
                policy_burst: pol.burst,
            })
        }
    }
}

fn with_rate_limiter(
    lim: Arc<RateLimiter>,
) -> impl Filter<Extract = (Arc<RateLimiter>,), Error = Infallible> + Clone {
    warp::any().map(move || lim.clone())
}

fn with_semaphore(
    sem: Arc<Semaphore>,
) -> impl Filter<Extract = (Arc<Semaphore>,), Error = Infallible> + Clone {
    warp::any().map(move || sem.clone())
}

async fn abuse_guard(
    remote: Option<SocketAddr>,
    path: FullPath,
    method: Method,
    lim: Arc<RateLimiter>,
    sem: Arc<Semaphore>,
) -> Result<(FullPath, Method, OwnedSemaphorePermit), warp::Rejection> {
    let ip = remote
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let scope = RateLimiter::classify(path.as_str(), &method);
    lim.check(&ip, scope).map_err(warp::reject::custom)?;

    let permit = sem
        .try_acquire_owned()
        .map_err(|_| warp::reject::custom(ServerBusy))?;

    Ok((path, method, permit))
}

fn apply_common_headers(path: &str, method: &Method, resp: &mut warp::reply::Response) {
    use warp::http::header::HeaderValue;

    // Security headers (API-friendly)
    resp.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    resp.headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    // Contract versioning: stable signal for clients/proxies
    resp.headers_mut()
        .insert("x-newgen-api-contract", HeaderValue::from_static("v2.0.0"));

    // Cache policy: conservative defaults (avoid serving stale mempool/tip).
    // You can tighten per-endpoint later with ETag support.
    let cache_control = if *method != Method::GET {
        "no-store"
    } else if path.starts_with("/api/v2/tx/by-hash/")
        || path.starts_with("/api/v2/tx/by_hash/")
        || path.starts_with("/api/v2/light/tx-proof/")
        || path.starts_with("/api/v2/light/state-proof/")
        || path.starts_with("/api/v2/light/state/proof")
    {
        "public, max-age=60"
    } else {
        "no-store"
    };

    if let Ok(v) = HeaderValue::from_str(cache_control) {
        resp.headers_mut().insert("cache-control", v);
    }
}

// ====== Filtri helper warp ======

fn spawn_blocking_join_rejection(ctx: &'static str, e: tokio::task::JoinError) -> warp::Rejection {
    eprintln!("[API] {}: spawn_blocking join failed: {:?}", ctx, e);
    warp::reject::custom(ApiError::Internal("spawn_blocking_join_failed"))
}

fn with_chain(
    chain: Arc<Mutex<Blockchain>>,
) -> impl Filter<Extract = (Arc<Mutex<Blockchain>>,), Error = Infallible> + Clone {
    warp::any().map(move || chain.clone())
}

fn with_mempool(
    mempool: Arc<Mutex<Mempool>>,
) -> impl Filter<Extract = (Arc<Mutex<Mempool>>,), Error = Infallible> + Clone {
    warp::any().map(move || mempool.clone())
}

fn with_validator_key(
    sk: Arc<SigningKey>,
    pk_b64: String,
) -> impl Filter<Extract = (Arc<SigningKey>, String), Error = Infallible> + Clone {
    let sk_f = {
        let sk = sk.clone();
        warp::any().map(move || sk.clone())
    };
    let pk_f = {
        let pk_b64 = pk_b64.clone();
        warp::any().map(move || pk_b64.clone())
    };
    sk_f.and(pk_f)
}

fn with_p2p(
    tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
) -> impl Filter<Extract = (tokio::sync::mpsc::UnboundedSender<NetMsg>,), Error = Infallible> + Clone
{
    warp::any().map(move || tx_p2p.clone())
}

type ApiResponseFilter = warp::filters::BoxedFilter<(warp::reply::Response,)>;

fn build_reputation_bridge_route(chain: SharedChain) -> ApiResponseFilter {
    warp::path!("api" / "v2" / "reputation" / "bridge")
        .and(warp::get())
        .and(with_chain(chain))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_rep_bridge".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/reputation/bridge"
            );
            let bc = lock_any!(ch);
            let source_height = bc.tip_height_u64();
            let finalized_height = bc.finalized_height();
            let canonical_wallets = bc.governance_wallet_reputation_snapshot();
            let canonical_node_surfaces = bc.canonical_node_reputation_surface_snapshot_v1();
            let canonical_wallet_surfaces = bc.canonical_wallet_reputation_surface_snapshot_v1();
            let canonical_evidence = bc.governance_wallet_reputation_evidence_snapshot(512);
            let canonical_e2_worker_evidence = bc.e2_worker_reputation_evidence_snapshot(512);
            let canonical_e2_worker_governed_privileges = bc.e2_worker_governed_privileges_finalized_snapshot_v1();
            let (run_summary, run_wallets, pending_evidence) = bc.run_wallet_reputation_snapshot();
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "source_height": source_height,
                "finalized_height": finalized_height,
                "run": {
                    "summary": run_summary,
                    "wallets": run_wallets,
                    "pending_evidence": pending_evidence,
                },
                "wallet_plane": canonical_wallets,
                "contract": crate::reputation_score::reputation_bridge_contract_metadata_v1(),
                "reputation_score_scale": crate::reputation_score::REPUTATION_SCORE_SCALE_V1,
                "reputation_score_max": crate::reputation_score::REPUTATION_SCORE_MAX_V1,
                "worker_penalty_taxonomy": crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1,
                "node_reputation_score_formula_version": crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1,
                "wallet_reputation_score_formula_version": crate::reputation_score::WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1,
                "worker_eligibility_policy_version": crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1,
                "canonical_node_reputation_surface_v1": canonical_node_surfaces,
                "canonical_wallet_reputation_surface_v1": canonical_wallet_surfaces,
                "canonical_evidence": canonical_evidence,
                "canonical_e2_worker_evidence": canonical_e2_worker_evidence,
                "canonical_e2_worker_governed_privileges": canonical_e2_worker_governed_privileges,
                "canonical_claims": bc.governance_wallet_reputation_claim_snapshot(512),
            }))
            .into_response()
        })
        .boxed()
}

fn build_gov_wallet_reputation_ingest_run_route(
    admin: Arc<AdminConfig>,
    validator_sk: Arc<SigningKey>,
    validator_pk_b64: String,
    chain: SharedChain,
    mempool: SharedMempool,
    tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
) -> ApiResponseFilter {
    warp::path!("api" / "v2" / "gov" / "reputation" / "wallet" / "ingest_run")
        .and(warp::post())
        .and(admin_guard(admin))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(validator_sk, validator_pk_b64))
        .and(with_chain(chain))
        .and(with_mempool(mempool))
        .and(with_p2p(tx_p2p))
        .map(|_g: (), body: serde_json::Value, sk: Arc<SigningKey>, local_pk_b64: String, chain: Arc<Mutex<Blockchain>>, _mp: Arc<Mutex<Mempool>>, _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
            let evidence_ids: Option<Vec<String>> = body.get("evidence_ids").and_then(|v| v.as_array()).map(|arr| {
                arr.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())).collect::<Vec<_>>()
            });
            let max_items = body.get("max_items").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(64).clamp(1, 512);
            let requested_timelock = body.get("timelock_blocks").and_then(|v| v.as_u64());
            let source_node_id = body.get("source_node_id").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            let source_attester_pubkey = body
                .get("source_attester_pubkey")
                .and_then(|v| v.as_str())
                .and_then(|s| crate::governance::canonical_wallet_reputation_source_attester(s));

            ng_trace_throttle!(
                key: "api_gov_wallet_rep_ingest".to_string(),
                every_ms: 30000,
                target: "api.req",
                "POST /api/v2/gov/reputation/wallet/ingest_run"
            );

            let mut ch = lock_any!(chain);
            let (timelock, proposer, source_tip_height) = match ch.governance.as_ref() {
                Some(g) => {
                    if !g.protocol_council.is_member(&local_pk_b64) {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "not_protocol_council_member",
                                "local_pk_b64": local_pk_b64
                            })),
                            warp::http::StatusCode::FORBIDDEN,
                        ).into_response();
                    }
                    let min_tl = g.params.min_timelock_blocks;
                    let chosen = requested_timelock.unwrap_or(min_tl).max(min_tl);
                    (chosen, local_pk_b64.clone(), ch.chain.last().map(|b| b.index).unwrap_or(0))
                }
                None => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":"governance_disabled"})),
                        warp::http::StatusCode::PRECONDITION_FAILED,
                    ).into_response();
                }
            };

            let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
            let next_height = prev_index + 1;
            let effective_height = next_height + timelock;

            let (_summary, _wallets, pending_all) = ch.run_wallet_reputation_snapshot();
            let mut selected = pending_all;
            if let Some(ids) = evidence_ids {
                let wanted: std::collections::BTreeSet<String> = ids.into_iter().collect();
                selected.retain(|ev| wanted.contains(&ev.evidence_id));
                if selected.len() != wanted.len() {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":"missing_requested_wallet_evidence_ids"})),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ).into_response();
                }
            }
            if selected.is_empty() {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status":"error","message":"no_pending_wallet_evidence"})),
                    warp::http::StatusCode::NOT_FOUND,
                ).into_response();
            }
            if selected.len() > max_items {
                selected.truncate(max_items);
            }
            let chosen_source_node_id = source_node_id.or_else(|| selected.first().map(|ev| ev.source_node_id.clone()).filter(|s| !s.is_empty()));
            if let Some(ref chosen_node_id) = chosen_source_node_id {
                if selected.iter().any(|ev| ev.source_node_id != *chosen_node_id) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":"mixed_source_node_ids_not_allowed"})),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ).into_response();
                }
            }
            let chosen_source_attester_pubkey = source_attester_pubkey.or_else(|| {
                selected.first().and_then(|ev| crate::governance::canonical_wallet_reputation_source_attester(&ev.source_attester_pubkey))
            });
            let Some(chosen_source_attester_pubkey) = chosen_source_attester_pubkey else {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status":"error","message":"missing_canonical_source_attester_pubkey"})),
                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                ).into_response();
            };
            if selected.iter().any(|ev| crate::governance::canonical_wallet_reputation_source_attester(&ev.source_attester_pubkey).as_deref() != Some(chosen_source_attester_pubkey.as_str())) {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status":"error","message":"mixed_source_attester_pubkeys_not_allowed"})),
                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                ).into_response();
            }
            let payload = crate::governance::WalletReputationEvidenceIngestPayload {
                source_node_id: chosen_source_node_id,
                source_attester_pubkey: Some(chosen_source_attester_pubkey.clone()),
                source_tip_height: Some(source_tip_height),
                evidences: selected.iter().map(|ev| crate::governance::WalletReputationEvidenceIngestItem {
                    claim_id: ev.claim_id.clone(),
                    evidence_id: ev.evidence_id.clone(),
                    source_node_id: Some(ev.source_node_id.clone()),
                    source_attester_pubkey: Some(ev.source_attester_pubkey.clone()),
                    source_attester_sig_b64: Some(ev.source_attester_sig_b64.clone()),
                    wallet_pubkey: ev.wallet_pubkey.clone(),
                    peer_id: ev.peer_id.clone(),
                    event: ev.event.clone(),
                    score_before: ev.score_before,
                    score_after: ev.score_after,
                    applied_delta: ev.applied_delta,
                    trust_tier: format!("{:?}", ev.trust_tier),
                    observed_at_secs: ev.observed_at_secs,
                    binding_source: ev.binding_source.clone(),
                }).collect(),
            };
            let payload_bytes = match serde_json::to_vec(&payload) {
                Ok(v) => v,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":"payload_serialize_failed","error":e.to_string()})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ).into_response();
                }
            };

            let proposal_kind = crate::governance::GovProposalKind::IngestWalletReputationEvidence;
            let proposal_id = governance_proposal_id_v1(
                "wallet-rep-ingest",
                &proposal_kind,
                &proposer,
                &payload_bytes,
                next_height,
                effective_height,
                ch.pending_governance_queue_len_v1(),
                &ch.genesis_hash,
            );
            let mut proposal = crate::governance::TxGovernanceProposal {
                id: proposal_id.clone(),
                kind: proposal_kind,
                payload: payload_bytes,
                created_at_height: next_height,
                effective_height,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            proposal.signature_domain = crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
            proposal.chain_id = crate::chain_identity::chain_id().to_string();
            proposal.genesis_hash = ch.genesis_hash.clone();
            let council = crate::governance::GovernanceCouncilKind::Protocol;
            let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                Ok(m) => m,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":"proposal_signing_bytes_failed","error":e})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ).into_response();
                }
            };
            proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());
            let selected_evidence_ids: Vec<String> = selected
                .iter()
                .map(|ev| ev.evidence_id.clone())
                .collect();
            let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                Ok(v) => v,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e.reason_code(),
                            "error": e.to_string(),
                            "proposal_id": proposal_id,
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ).into_response();
                }
            };

            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status":"accepted",
                    "mode": "governance_proposal_queued",
                    "canonical_inclusion": "pending_block_production",
                    "proposal_id": proposal_id,
                    "governance_flow": governance_flow_response_v1(&proposal_id),
                    "provisional_created_at_height": next_height,
                    "provisional_effective_height": effective_height,
                    "effective_height_assigned_at_inclusion": true,
                    "timelock_blocks": timelock,
                    "queue_depth": ingress.queue_depth,
                    "selected_evidence_ids": selected_evidence_ids,
                    "source_attester_pubkey": chosen_source_attester_pubkey,
                    "source_node_id": payload.source_node_id,
                })),
                warp::http::StatusCode::ACCEPTED,
            ).into_response()
        })
        .boxed()
}

// ====== Errori API ======
#[derive(Debug, Copy, Clone)]
enum ApiError {
    MasterKeyError,
    Forbidden,
    InvalidData,
    BadRequest(&'static str),
    Internal(&'static str),
}
impl warp::reject::Reject for ApiError {}

async fn error_handler(err: warp::Rejection) -> Result<warp::reply::Response, Infallible> {
    use warp::http::StatusCode;

    let (code, mut body, retry_after): (StatusCode, serde_json::Value, Option<u32>) =
        if err.is_not_found() {
            (
                StatusCode::NOT_FOUND,
                serde_json::json!({"status":"error","message":"not_found"}),
                None,
            )
        } else if err.find::<warp::reject::PayloadTooLarge>().is_some() {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"status":"error","message":"payload_too_large"}),
                None,
            )
        } else if err
            .find::<warp::filters::body::BodyDeserializeError>()
            .is_some()
        {
            (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"status":"error","message":"invalid_body"}),
                None,
            )
        } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                serde_json::json!({"status":"error","message":"method_not_allowed"}),
                None,
            )
        } else if let Some(rl) = err.find::<RateLimited>() {
            (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({
                    "status": "rate_limited",
                    "message": "too_many_requests",
                    "scope": rl.scope,
                    "profile": rl.profile,
                    "policy_rps": rl.policy_rps,
                    "policy_burst": rl.policy_burst,
                    "retry_after_secs": rl.retry_after_secs
                }),
                Some(rl.retry_after_secs),
            )
        } else if err.find::<ServerBusy>().is_some() {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "status": "server_busy",
                    "message": "too_many_in_flight_requests"
                }),
                Some(1),
            )
        } else if let Some(ApiError::BadRequest(msg)) = err.find() {
            (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"status":"error","message":msg}),
                None,
            )
        } else if let Some(ApiError::Forbidden) = err.find() {
            (
                StatusCode::FORBIDDEN,
                serde_json::json!({"status":"error","message":"forbidden"}),
                None,
            )
        } else if let Some(ApiError::MasterKeyError) = err.find() {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"status":"error","message":"internal_server_error_master_key"}),
                None,
            )
        } else if let Some(e) = err.find::<ApiError>() {
            let (code, msg) = match *e {
                ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
                ApiError::MasterKeyError => (StatusCode::INTERNAL_SERVER_ERROR, "master_key_error"),
                ApiError::InvalidData => (StatusCode::BAD_REQUEST, "invalid_data"),
                ApiError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
                ApiError::Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s),
            };
            (
                code,
                serde_json::json!({"status":"error","message":msg}),
                None,
            )
        } else {
            eprintln!("Errore non gestito: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"status":"error","message":"internal_server_error"}),
                None,
            )
        };

    // Backward-compatible envelope: ensure we always have `status`
    if body.get("status").is_none() {
        body["status"] = serde_json::json!("error");
    }

    let mut resp = warp::reply::json(&body).into_response();
    *resp.status_mut() = code;

    // Apply common headers even on errors
    apply_common_headers("", &Method::GET, &mut resp);

    if let Some(secs) = retry_after {
        resp.headers_mut().insert(
            "retry-after",
            warp::http::header::HeaderValue::from_str(&secs.to_string()).unwrap(),
        );
    }

    Ok(resp)
}

fn mempool_reject_status(result: &MempoolAddResult) -> warp::http::StatusCode {
    use warp::http::StatusCode;

    match result {
        MempoolAddResult::Accepted => StatusCode::OK,
        MempoolAddResult::SenderRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        MempoolAddResult::LowPriority { .. } => StatusCode::TOO_MANY_REQUESTS,
        MempoolAddResult::SenderCap { .. } => StatusCode::TOO_MANY_REQUESTS,
        MempoolAddResult::DuplicateHash { .. } => StatusCode::CONFLICT,
        MempoolAddResult::HashMismatch { .. }
        | MempoolAddResult::CoinbaseNotAllowed
        | MempoolAddResult::StakeSyntaxInvalid { .. }
        | MempoolAddResult::NftSyntaxInvalid { .. }
        | MempoolAddResult::FeeTooLow { .. }
        | MempoolAddResult::Oversize { .. } => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

fn mempool_reject_json(result: &MempoolAddResult, mp: &Mempool) -> serde_json::Value {
    let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) = mp.limits_snapshot();
    let drop_counters = mp.drop_counters_snapshot();

    serde_json::json!({
        "status": "rejected",
        "mempool_reject": result,
        "mempool": {
            "size": mp.len() as u64,
            "total_bytes": mp.total_bytes() as u64,
            "drop_counters": drop_counters,
        },
        "limits": {
            "max_mempool_size": max_size as u64,
            "max_tx_per_sender": max_tx_per_sender as u64,
            "max_mempool_bytes": max_bytes as u64,
            "tx_ttl_secs": tx_ttl_secs,
        }
    })
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    balance: i128,
}

fn with_storage(
    storage: std::sync::Arc<DbStore>,
) -> impl warp::Filter<Extract = (std::sync::Arc<DbStore>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || storage.clone())
}

// Decodifica molto semplice di stringhe URL-encodate (es. da encodeURIComponent)
fn url_decode_simple(input: &str) -> Result<String, warp::Rejection> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            let hex = [h1, h2];

            if let Ok(hex_str) = std::str::from_utf8(&hex) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }

            // fallback: se non è hex valido, tieni il carattere così com'è
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).map_err(|_| warp::reject::custom(ApiError::BadRequest("invalid_utf8")))
}

// ==========================================================
// Step 58 — Light client API (headers + Merkle TX inclusion proofs)
// ==========================================================

#[derive(Debug, Deserialize)]
struct LightHeadersQuery {
    #[serde(alias = "from", alias = "fromHeight")]
    from_height: Option<u64>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct LightStateHeightQuery {
    #[serde(alias = "height", alias = "h")]
    height: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LightStateProofQuery {
    #[serde(alias = "pk_b64", alias = "pk", alias = "address")]
    pk_b64: Option<String>,
    #[serde(alias = "height", alias = "h")]
    height: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum MerkleSide {
    Left,
    Right,
}

// leaf = SHA256(0x00 || txid)
// node = SHA256(0x01 || left || right)
// odd handling: promote last (RFC6962-style)
fn sha256_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn merkle_leaf(txid: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[&[0x00], txid])
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[&[0x01], left, right])
}

fn empty_tx_root_v1() -> [u8; 32] {
    sha256_concat(&[b"NG_TX_ROOT_EMPTY_V1"])
}

fn txid_bytes_from_tx(tx: &Transaction) -> Result<[u8; 32], String> {
    // Preferisci tx.hash se presente; se manca, calcolalo.
    let hex_id = if !tx.hash.is_empty() {
        tx.hash.clone()
    } else {
        tx.calculate_hash()
    };

    let raw = hex::decode(hex_id.trim()).map_err(|e| format!("txid_hex_decode_failed: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("txid_len_invalid: expected=32 got={}", raw.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    Ok(a)
}

fn txids_from_block_txs(txs: &[Transaction]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(txs.len());
    for tx in txs {
        out.push(txid_bytes_from_tx(tx)?);
    }
    Ok(out)
}

fn merkle_root_from_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return empty_tx_root_v1();
    }

    let mut level: Vec<[u8; 32]> = txids.iter().map(merkle_leaf).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
            } else {
                // odd: promote last
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
    }

    level[0]
}

fn merkle_proof_from_txids(txids: &[[u8; 32]], mut index: usize) -> Vec<(MerkleSide, [u8; 32])> {
    if txids.is_empty() {
        return vec![];
    }

    let mut proof: Vec<(MerkleSide, [u8; 32])> = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.iter().map(merkle_leaf).collect();

    while level.len() > 1 {
        if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                proof.push((MerkleSide::Right, level[index + 1]));
            }
        } else {
            proof.push((MerkleSide::Left, level[index - 1]));
        }

        // next level
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }

        level = next;
        index /= 2;
    }

    proof
}

fn normalize_txid(mut s: String) -> String {
    s = s.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("0x") {
        rest.to_string()
    } else {
        s
    }
}

fn normalize_pk_b64(s: &str) -> String {
    // 1) alcuni client/URL encoding trasformano '+' in ' ' (space) in querystring
    // 2) alcuni client usano base64url ('-' e '_') invece di base64 standard
    // 3) alcuni client omettono il padding '=': lo ripristiniamo per evitare rifiuti ingiusti
    let mut out = s
        .trim()
        .replace([' ', '-'], "+")
        .replace('_', "/")
        .replace(['\n', '\r'], "");

    let rem = out.len() % 4;
    if rem != 0 {
        out.push_str(&"=".repeat(4 - rem));
    }
    out
}
/// Parse an amount into atomic units (u64) without using floats.
///
/// Accepted encodings:
/// - JSON integer: treated as atomic units (backward compatible)
/// - JSON number with fraction (e.g. 0.00057): parsed as decimal NGT and converted to atomic units
/// - String:
///   - "575" (no dot/comma) => atomic units
///   - "0.000575" or "0,000575" => decimal NGT => atomic units
fn ft_receipt_json_or_error(tx: &Transaction) -> Option<serde_json::Value> {
    match ft::ft_receipt_json_v1(tx) {
        Ok(v) => v,
        Err(e) => Some(serde_json::json!({
            "kind": "ft_decode_error",
            "message": e,
        })),
    }
}

fn nft_event_values_for_tx_from_block_v1(
    block: &crate::block::Block,
    tx_hash: &str,
    tx_index: usize,
) -> Vec<serde_json::Value> {
    nft::nft_events_for_tx_v1(&block.nft_events, tx_hash, tx_index as u32)
        .into_iter()
        .filter_map(|event| nft::nft_event_json_v1(event).ok())
        .collect()
}

fn nft_first_event_for_tx_from_block_v1(
    block: &crate::block::Block,
    tx_hash: &str,
    tx_index: usize,
) -> Option<serde_json::Value> {
    nft_event_values_for_tx_from_block_v1(block, tx_hash, tx_index)
        .into_iter()
        .next()
}

fn ft_recent_activity_from_blocks(
    blocks: &[crate::block::Block],
    window: usize,
) -> (usize, BTreeMap<String, u64>) {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut total_ft_txs: usize = 0;

    for block in blocks.iter().rev().take(window) {
        for tx in &block.transactions {
            if let Some(v) = ft_receipt_json_or_error(tx) {
                let kind = v
                    .get("kind")
                    .and_then(|x| x.as_str())
                    .unwrap_or("ft_unknown")
                    .to_string();
                *counts.entry(kind).or_insert(0) += 1;
                total_ft_txs = total_ft_txs.saturating_add(1);
            }
        }
    }

    (total_ft_txs, counts)
}

fn nft_recent_activity_from_blocks(
    blocks: &[crate::block::Block],
    window: usize,
) -> (usize, BTreeMap<String, u64>) {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut total_nft_events: usize = 0;

    for block in blocks.iter().rev().take(window) {
        for event in &block.nft_events {
            *counts.entry(event.kind.clone()).or_insert(0) += 1;
            total_nft_events = total_nft_events.saturating_add(1);
        }
    }

    (total_nft_events, counts)
}

fn ft_total_tokens_created_from_state_root(
    storage: &DbStore,
    state_root_hex: &str,
) -> Result<u64, String> {
    if state_root_hex.trim().is_empty() {
        return Ok(0);
    }
    let root = bytes32_from_hex(state_root_hex)?;
    let smt = StateSmt::new(storage.state_node_store());
    match smt.get_account(root, ft::k_ft_next_token_id()) {
        Ok(Some(st)) => {
            let next_id = st.balance;
            Ok(if next_id == 0 {
                0
            } else {
                next_id.saturating_sub(1)
            })
        }
        Ok(None) => Ok(0),
        Err(e) => Err(format!("smt_read_failed: {}", e)),
    }
}

fn nft_total_collections_created_from_state_root(
    storage: &DbStore,
    state_root_hex: &str,
) -> Result<u64, String> {
    if state_root_hex.trim().is_empty() {
        return Ok(0);
    }
    let root = bytes32_from_hex(state_root_hex.trim())?;
    let smt = StateSmt::new(storage.state_node_store());
    match smt.get_account(root, nft::k_nft_next_collection_id()) {
        Ok(Some(st)) => {
            let next_id = if st.balance == 0 { 1 } else { st.balance };
            Ok(next_id.saturating_sub(1))
        }
        Ok(None) => Ok(0),
        Err(e) => Err(format!("smt_read_failed: {}", e)),
    }
}

fn nft_api_url_component_v1(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        let keep =
            matches!(*b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~');
        if keep {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn nft_api_link_set_v1(
    collection_id: u64,
    serial: Option<u64>,
    owner_b64: Option<&str>,
) -> serde_json::Value {
    let collection_path = format!("/nft/collection/{}", collection_id);
    let collection_api = format!("/api/v2/nft/collection?id={}", collection_id);
    let collection_tokens_api = format!(
        "/api/v2/nft/collection_tokens?collection_id={}&cursor=0&limit=50",
        collection_id
    );
    let mut links = serde_json::json!({
        "collection": collection_path,
        "collection_api": collection_api,
        "collection_tokens_api": collection_tokens_api,
    });
    if let Some(serial) = serial {
        links["token"] = serde_json::Value::from(format!(
            "/nft/collection/{}/token/{}",
            collection_id, serial
        ));
        links["token_api"] = serde_json::Value::from(format!(
            "/api/v2/nft/token?collection_id={}&serial={}",
            collection_id, serial
        ));
        links["owner_of_api"] = serde_json::Value::from(format!(
            "/api/v2/nft/owner_of?collection_id={}&serial={}",
            collection_id, serial
        ));
        links["approval_api"] = serde_json::Value::from(format!(
            "/api/v2/nft/approval?collection_id={}&serial={}",
            collection_id, serial
        ));
    }
    if let Some(owner) = owner_b64 {
        let owner_q = nft_api_url_component_v1(owner);
        links["wallet_assets"] =
            serde_json::Value::from(format!("/wallet/assets?owner={}", owner_q));
        links["wallet_assets_api"] = serde_json::Value::from(format!(
            "/api/v2/nft/wallet?owner={}&cursor=0&limit=50",
            owner_q
        ));
        links["owner_collections_api"] = serde_json::Value::from(format!(
            "/api/v2/nft/owner_collections?owner={}&cursor=0&limit=50",
            owner_q
        ));
    }
    links
}

#[derive(Clone)]
struct NftPublicReadContextV1 {
    source_commitment: &'static str,
    finalized_height: u64,
    finalized_hash: String,
    finalized_state_root: String,
    tip_height: u64,
    tip_hash: String,
    finalized_root: [u8; 32],
    finalized_blocks: Vec<crate::block::Block>,
}

fn nft_public_read_source_json_v1(ctx: &NftPublicReadContextV1) -> serde_json::Value {
    serde_json::json!({
        "source_commitment": ctx.source_commitment,
        "finalized_height": ctx.finalized_height,
        "finalized_hash": ctx.finalized_hash,
        "finalized_state_root": ctx.finalized_state_root,
        "tip_height": ctx.tip_height,
        "tip_hash": ctx.tip_hash,
        "read_model_version": "nft_public_read_model_v1",
    })
}

fn nft_governance_public_read_source_json_v1(
    ctx: &NftPublicReadContextV1,
    governance_height: u64,
) -> serde_json::Value {
    serde_json::json!({
        "source_commitment": "finalized",
        "finalized_height": ctx.finalized_height,
        "governance_height": governance_height,
        "finalized_hash": ctx.finalized_hash,
        "tip_height": ctx.tip_height,
        "tip_hash": ctx.tip_hash,
        "read_model_version": "nft_governance_policy_read_model_v1",
    })
}

fn nft_governance_policy_delta_allowed_keys_v1() -> &'static [&'static str] {
    &[
        "nft_activation_height",
        "nft_max_collections_per_owner",
        "nft_create_cooldown_blocks",
        "nft_create_fee_native",
        "nft_enabled",
        "nft_public_create_enabled",
        "nft_public_mint_enabled",
        "nft_public_transfer_enabled",
        "nft_public_approval_enabled",
        "nft_public_burn_enabled",
        "nft_public_revoke_enabled",
        "nft_public_metadata_update_enabled",
        "nft_public_freeze_enabled",
        "nft_public_policy_update_enabled",
        "nft_public_issuer_update_enabled",
        "nft_public_pause_enabled",
        "nft_metadata_hash_required",
        "nft_max_memo_bytes",
        "nft_max_uri_bytes",
        "nft_max_name_bytes",
        "nft_max_symbol_bytes",
        "nft_max_tokens_per_collection",
        "nft_max_tokens_per_owner",
        "nft_mint_fee_native",
        "nft_transfer_fee_native",
        "nft_approval_fee_native",
        "nft_burn_fee_native",
        "nft_revoke_fee_native",
        "nft_metadata_update_fee_native",
        "nft_freeze_fee_native",
        "nft_policy_update_fee_native",
        "nft_issuer_update_fee_native",
        "nft_pause_fee_native",
    ]
}

fn nft_governance_policy_request_allowed_keys_v1() -> &'static [&'static str] {
    &["delta", "timelock_blocks", "reason"]
}

fn reject_unknown_json_object_keys_v1(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), String> {
    for key in object.keys() {
        if !allowed
            .iter()
            .any(|allowed_key| *allowed_key == key.as_str())
        {
            return Err(format!("unknown_{}_field:{}", scope, key));
        }
    }
    Ok(())
}

fn nft_governance_delta_is_empty_v1(delta: &crate::governance::GovernanceParamsDelta) -> bool {
    delta.nft_activation_height.is_none()
        && delta.nft_max_collections_per_owner.is_none()
        && delta.nft_create_cooldown_blocks.is_none()
        && delta.nft_create_fee_native.is_none()
        && delta.nft_enabled.is_none()
        && delta.nft_public_create_enabled.is_none()
        && delta.nft_public_mint_enabled.is_none()
        && delta.nft_public_transfer_enabled.is_none()
        && delta.nft_public_approval_enabled.is_none()
        && delta.nft_public_burn_enabled.is_none()
        && delta.nft_public_revoke_enabled.is_none()
        && delta.nft_public_metadata_update_enabled.is_none()
        && delta.nft_public_freeze_enabled.is_none()
        && delta.nft_public_policy_update_enabled.is_none()
        && delta.nft_public_issuer_update_enabled.is_none()
        && delta.nft_public_pause_enabled.is_none()
        && delta.nft_metadata_hash_required.is_none()
        && delta.nft_max_memo_bytes.is_none()
        && delta.nft_max_uri_bytes.is_none()
        && delta.nft_max_name_bytes.is_none()
        && delta.nft_max_symbol_bytes.is_none()
        && delta.nft_max_tokens_per_collection.is_none()
        && delta.nft_max_tokens_per_owner.is_none()
        && delta.nft_mint_fee_native.is_none()
        && delta.nft_transfer_fee_native.is_none()
        && delta.nft_approval_fee_native.is_none()
        && delta.nft_burn_fee_native.is_none()
        && delta.nft_revoke_fee_native.is_none()
        && delta.nft_metadata_update_fee_native.is_none()
        && delta.nft_freeze_fee_native.is_none()
        && delta.nft_policy_update_fee_native.is_none()
        && delta.nft_issuer_update_fee_native.is_none()
        && delta.nft_pause_fee_native.is_none()
}

fn preview_nft_governance_delta_for_api_v1(
    current: &crate::governance::GovernanceParams,
    delta: &crate::governance::GovernanceParamsDelta,
) -> Result<crate::governance::GovernanceParams, String> {
    crate::governance::preview_governance_params_delta_v1(current, delta)
}

fn nft_policy_json_from_snapshot_v1(snap: &NftPolicySnapshotV1) -> serde_json::Value {
    let p = &snap.params;
    let active = p.nft_enabled && snap.finalized_height >= p.nft_activation_height;
    serde_json::json!({
        "status": "ok",
        "module": "nft_v1",
        "enabled": p.nft_enabled,
        "active": active,
        "activation_height": p.nft_activation_height,
        "public_create_enabled": p.nft_public_create_enabled,
        "public_mint_enabled": p.nft_public_mint_enabled,
        "public_transfer_enabled": p.nft_public_transfer_enabled,
        "public_approval_enabled": p.nft_public_approval_enabled,
        "public_burn_enabled": p.nft_public_burn_enabled,
        "public_revoke_enabled": p.nft_public_revoke_enabled,
        "public_metadata_update_enabled": p.nft_public_metadata_update_enabled,
        "public_freeze_enabled": p.nft_public_freeze_enabled,
        "public_policy_update_enabled": p.nft_public_policy_update_enabled,
        "public_issuer_update_enabled": p.nft_public_issuer_update_enabled,
        "public_pause_enabled": p.nft_public_pause_enabled,
        "metadata_hash_required": p.nft_metadata_hash_required,
        "caps": {
            "max_collections_per_owner": p.nft_max_collections_per_owner,
            "create_cooldown_blocks": p.nft_create_cooldown_blocks,
            "max_tokens_per_collection": p.nft_max_tokens_per_collection,
            "max_tokens_per_owner": p.nft_max_tokens_per_owner,
        },
        "limits": {
            "max_memo_bytes": p.nft_max_memo_bytes,
            "max_uri_bytes": p.nft_max_uri_bytes,
            "max_name_bytes": p.nft_max_name_bytes,
            "max_symbol_bytes": p.nft_max_symbol_bytes,
        },
        "fees": {
            "base_fee_per_tx": snap.base_fee_per_tx,
            "create_fee_native": p.nft_create_fee_native,
            "mint_fee_native": p.nft_mint_fee_native,
            "transfer_fee_native": p.nft_transfer_fee_native,
            "approval_fee_native": p.nft_approval_fee_native,
            "burn_fee_native": p.nft_burn_fee_native,
            "revoke_fee_native": p.nft_revoke_fee_native,
            "metadata_update_fee_native": p.nft_metadata_update_fee_native,
            "freeze_fee_native": p.nft_freeze_fee_native,
            "policy_update_fee_native": p.nft_policy_update_fee_native,
            "issuer_update_fee_native": p.nft_issuer_update_fee_native,
            "pause_fee_native": p.nft_pause_fee_native,
        },
        "policy_hash": snap.policy_hash.clone(),
        "source_commitment": snap.source_commitment,
        "governance_height": snap.governance_height,
        "finalized_height": snap.finalized_height,
        "finalized_hash": snap.finalized_hash.clone(),
        "tip_height": snap.tip_height,
        "policy_source": nft_policy_source_json_from_snapshot_v1(snap),
        "read_model_version": "nft_governance_policy_read_model_v1",
    })
}

#[derive(Clone)]
struct NftPolicySnapshotV1 {
    source_commitment: &'static str,
    tip_height: u64,
    finalized_height: u64,
    finalized_hash: String,
    governance_height: u64,
    base_fee_per_tx: u64,
    policy_hash: String,
    params: crate::governance::GovernanceParams,
}

fn nft_governance_policy_hash_v1(
    params: &crate::governance::GovernanceParams,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(params)
        .map_err(|e| format!("nft_governance_policy_serialize_failed:{e}"))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn nft_policy_source_json_from_snapshot_v1(snap: &NftPolicySnapshotV1) -> serde_json::Value {
    serde_json::json!({
        "source_commitment": snap.source_commitment,
        "tip_height": snap.tip_height,
        "finalized_height": snap.finalized_height,
        "finalized_hash": snap.finalized_hash.clone(),
        "governance_height": snap.governance_height,
        "policy_hash": snap.policy_hash.clone(),
        "read_model_version": "nft_governance_policy_read_model_v1",
    })
}

fn nft_policy_unavailable_response_v1(detail: impl ToString) -> warp::reply::Response {
    let body = serde_json::json!({
        "status": "error",
        "message": "nft_policy_unavailable",
        "detail": detail.to_string(),
        "source_commitment": "finalized",
    });
    let mut resp = warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        .into_response();
    *resp.status_mut() = warp::http::StatusCode::SERVICE_UNAVAILABLE;
    resp
}

fn nft_finalized_policy_snapshot_for_api_v1(
    ch: &SharedChain,
) -> Result<NftPolicySnapshotV1, String> {
    let bc = lock_any!(ch);
    let tip_height = bc.chain.last().map(|b| b.index).unwrap_or(0);
    let base_fee_per_tx = bc.base_fee_per_tx();
    let (finalized_height, finalized_hash) = bc.finalized_view();
    let (governance_height, params) = bc.finalized_governance_params_for_api_v1()?;
    if governance_height != finalized_height {
        return Err(format!(
            "nft_governance_finalized_height_mismatch: governance_height={} finalized_height={}",
            governance_height, finalized_height
        ));
    }
    crate::governance::validate_nft_governance_policy_v1(&params)
        .map_err(|e| format!("nft_governance_policy_invalid:{}", e))?;
    let policy_hash = nft_governance_policy_hash_v1(&params)?;
    Ok(NftPolicySnapshotV1 {
        source_commitment: "finalized",
        tip_height,
        finalized_height,
        finalized_hash,
        governance_height,
        base_fee_per_tx,
        policy_hash,
        params,
    })
}

fn nft_public_read_context_error_reply_v1(
    detail: impl ToString,
) -> warp::reply::WithHeader<warp::reply::Json> {
    warp::reply::with_header(
        warp::reply::json(&serde_json::json!({
            "status": "error",
            "message": "nft_finalized_read_context_unavailable",
            "detail": detail.to_string(),
            "source_commitment": "finalized",
        })),
        "Cache-Control",
        "no-store",
    )
}

fn nft_finalized_public_read_context_v1(
    ch: &SharedChain,
) -> Result<NftPublicReadContextV1, String> {
    let bc = lock_any!(ch);
    let (tip_height, tip_hash) = bc
        .chain
        .last()
        .map(|b| (b.index, b.hash.clone()))
        .unwrap_or((0, String::new()));
    let finalized_block = bc
        .finalized_block_for_api()
        .map_err(|e| format!("finalized_block_lookup_failed:{}", e))?
        .ok_or_else(|| "finalized_block_unavailable".to_string())?;
    if finalized_block.state_root.trim().is_empty() {
        return Err(format!(
            "finalized_state_root_missing:{}",
            finalized_block.index
        ));
    }
    let finalized_root = bytes32_from_hex(finalized_block.state_root.trim())
        .map_err(|e| format!("bad_finalized_state_root_hex:{}", e))?;
    let finalized_height = finalized_block.index;
    let finalized_blocks = bc
        .chain
        .iter()
        .filter(|b| b.index <= finalized_height)
        .cloned()
        .collect::<Vec<_>>();
    Ok(NftPublicReadContextV1 {
        source_commitment: "finalized",
        finalized_height,
        finalized_hash: finalized_block.hash.clone(),
        finalized_state_root: finalized_block.state_root.clone(),
        tip_height,
        tip_hash,
        finalized_root,
        finalized_blocks,
    })
}

fn nft_collection_read_model_from_smt_v1(
    smt: &StateSmt,
    root: [u8; 32],
    collection_id: u64,
) -> Result<serde_json::Value, String> {
    let st_meta = smt
        .get_account(root, nft::k_nft_collection_meta(collection_id))
        .map_err(|e| format!("smt_read_failed: {}", e))?
        .ok_or_else(|| format!("nft_collection_not_found: {}", collection_id))?;
    let meta = nft::decode_collection_meta_state_v1(&st_meta)
        .map_err(|e| format!("nft_collection_meta_decode_failed: {}", e))?;
    let cfg = match smt
        .get_account(root, nft::k_nft_collection_cfg(collection_id))
        .map_err(|e| format!("smt_read_failed: {}", e))?
    {
        Some(st) => nft::decode_collection_cfg_state_v1(&st)
            .map_err(|e| format!("nft_collection_cfg_decode_failed: {}", e))?,
        None => nft::NftCollectionCfgV1::default(),
    };
    let next_serial = smt
        .get_account(root, nft::k_nft_collection_next_serial(collection_id))
        .map_err(|e| format!("smt_read_failed: {}", e))?
        .map(|st| if st.balance == 0 { 1 } else { st.balance })
        .unwrap_or(1);
    let token_count = smt
        .get_account(root, nft::k_nft_collection_token_count(collection_id))
        .map_err(|e| format!("smt_read_failed: {}", e))?
        .map(|st| st.balance)
        .unwrap_or(0);
    let owner_b64 = meta.owner_b64.clone();
    let links = nft_api_link_set_v1(collection_id, None, Some(&owner_b64));
    Ok(serde_json::json!({
        "id": meta.id,
        "owner_b64": owner_b64,
        "issuer_b64": meta.issuer_b64,
        "asset_type": meta.asset_type.as_str(),
        "transfer_policy": meta.transfer_policy.as_str(),
        "revocable": meta.revocable,
        "symbol": meta.symbol,
        "name": meta.name,
        "max_supply": meta.max_supply,
        "total_minted": meta.total_minted,
        "live_supply": meta.live_supply,
        "created_height": meta.created_height,
        "metadata_hash_hex": hex::encode(meta.metadata_hash),
        "base_uri": meta.base_uri,
        "cfg": {
            "mintable": cfg.mintable,
            "burnable": cfg.burnable,
            "paused": cfg.paused,
        },
        "token_count_indexed": token_count,
        "next_serial_hint": next_serial,
        "links": links,
    }))
}

fn nft_token_read_model_from_smt_v1(
    smt: &StateSmt,
    root: [u8; 32],
    collection_id: u64,
    serial: u64,
    at_height: u64,
) -> Result<serde_json::Value, String> {
    let st_meta = smt
        .get_account(root, nft::k_nft_token_meta(collection_id, serial))
        .map_err(|e| format!("smt_read_failed: {}", e))?
        .ok_or_else(|| format!("nft_token_not_found: {}:{}", collection_id, serial))?;
    let token = nft::decode_token_meta_state_v1(&st_meta)
        .map_err(|e| format!("nft_token_meta_decode_failed: {}", e))?;
    let effective_status = nft::nft_token_effective_status_v1(&token, at_height);
    let owner = match smt
        .get_account(root, nft::k_nft_token_owner(collection_id, serial))
        .map_err(|e| format!("smt_read_failed: {}", e))?
    {
        Some(st) => Some(
            nft::decode_token_owner_b64_v1(&st)
                .map_err(|e| format!("nft_token_owner_decode_failed: {}", e))?,
        ),
        None if matches!(
            token.status,
            nft::NftTokenStatusV1::Burned | nft::NftTokenStatusV1::Revoked
        ) =>
        {
            None
        }
        None => {
            return Err(format!(
                "nft_token_owner_missing: {}:{}",
                collection_id, serial
            ))
        }
    };
    let approved = if owner.is_some() {
        match smt
            .get_account(root, nft::k_nft_token_approval(collection_id, serial))
            .map_err(|e| format!("smt_read_failed: {}", e))?
        {
            Some(st) => Some(
                nft::decode_token_approval_b64_v1(&st)
                    .map_err(|e| format!("nft_token_approval_decode_failed: {}", e))?,
            ),
            None => None,
        }
    } else {
        None
    };
    let collection = nft_collection_read_model_from_smt_v1(smt, root, collection_id)?;
    let owner_for_links = owner.clone();
    let links = nft_api_link_set_v1(collection_id, Some(serial), owner_for_links.as_deref());
    Ok(serde_json::json!({
        "collection_id": token.collection_id,
        "serial": token.serial,
        "asset_id": nft::nft_asset_id_v1(collection_id, serial),
        "minted_height": token.minted_height,
        "metadata_hash_hex": hex::encode(token.metadata_hash),
        "token_uri": token.token_uri,
        "status": effective_status.as_str(),
        "stored_status": token.status.as_str(),
        "effective_status": effective_status.as_str(),
        "expires_at_height": token.expires_at_height,
        "owner_b64": owner,
        "owner_present": owner_for_links.is_some(),
        "owner_state": if owner_for_links.is_some() { "present" } else { "terminal_tombstone" },
        "approved_b64": approved,
        "collection": collection,
        "links": links,
    }))
}

fn nft_recent_activity_items_from_blocks_v1(
    blocks: &[crate::block::Block],
    window: usize,
    cursor: u64,
    limit: u64,
    collection_id: Option<u64>,
    owner: Option<&str>,
) -> (u64, Vec<serde_json::Value>) {
    let mut skipped = 0u64;
    let mut total_matched = 0u64;
    let mut items = Vec::new();
    let limit = limit.clamp(1, 200);
    for block in blocks.iter().rev().take(window) {
        for event in block.nft_events.iter().rev() {
            if let Some(cid) = collection_id {
                if event.collection_id != Some(cid) {
                    continue;
                }
            }
            if let Some(owner_filter) = owner {
                let owner_match = event.owner_b64.as_deref() == Some(owner_filter)
                    || event.previous_owner_b64.as_deref() == Some(owner_filter)
                    || event.from_b64.as_deref() == Some(owner_filter)
                    || event.to_b64.as_deref() == Some(owner_filter)
                    || event.approved_b64.as_deref() == Some(owner_filter)
                    || event.operator_b64.as_deref() == Some(owner_filter)
                    || event.issuer_b64.as_deref() == Some(owner_filter)
                    || event.old_issuer_b64.as_deref() == Some(owner_filter)
                    || event.new_issuer_b64.as_deref() == Some(owner_filter);
                if !owner_match {
                    continue;
                }
            }
            total_matched = total_matched.saturating_add(1);
            if skipped < cursor {
                skipped = skipped.saturating_add(1);
                continue;
            }
            if (items.len() as u64) >= limit {
                continue;
            }
            let mut v = nft::nft_event_json_v1(event).unwrap_or_else(|_| {
                serde_json::json!({
                    "kind": event.kind.clone(),
                    "op": event.op.clone(),
                    "block_height": event.block_height,
                    "tx_hash": event.tx_hash.clone(),
                    "tx_index": event.tx_index,
                })
            });
            if let Some(cid) = event.collection_id {
                v["links"] = nft_api_link_set_v1(
                    cid,
                    event.serial,
                    event
                        .owner_b64
                        .as_deref()
                        .or(event.to_b64.as_deref())
                        .or(event.from_b64.as_deref()),
                );
            }
            items.push(v);
        }
    }
    (total_matched, items)
}

fn nft_api_bad_request_v1(
    message: &str,
    detail: impl ToString,
) -> warp::reply::WithStatus<warp::reply::Json> {
    warp::reply::with_status(
        warp::reply::json(&serde_json::json!({
            "status": "invalid_data",
            "message": message,
            "detail": detail.to_string()
        })),
        warp::http::StatusCode::BAD_REQUEST,
    )
}

fn nft_api_exact_keys_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), String> {
    for key in map.keys() {
        if !allowed.iter().any(|k| *k == key) {
            return Err(format!("nft_unknown_request_field: {}", key));
        }
    }
    Ok(())
}

fn nft_api_required_str_raw_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    let s = map
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("nft_missing_or_invalid_field: {}", key))?;
    if s != s.trim() {
        return Err(format!("nft_field_not_raw_canonical: {}", key));
    }
    Ok(s.to_string())
}

fn nft_api_required_nonempty_str_raw_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    let s = nft_api_required_str_raw_v1(map, key)?;
    if s.is_empty() {
        return Err(format!("nft_missing_or_invalid_field: {}", key));
    }
    Ok(s)
}

fn nft_api_required_u64_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    map.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("nft_missing_or_invalid_field: {}", key))
}

fn nft_api_required_nonzero_u64_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    let n = nft_api_required_u64_v1(map, key)?;
    if n == 0 {
        return Err(format!("nft_missing_or_invalid_field: {}", key));
    }
    Ok(n)
}

fn nft_api_required_bool_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    map.get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("nft_missing_or_invalid_field: {}", key))
}

fn nft_api_optional_nullable_u64_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<u64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) if v.is_u64() => Ok(Some(v.as_u64().unwrap())),
        _ => Err(format!("nft_missing_or_invalid_field: {}", key)),
    }
}

fn nft_api_required_nullable_str_raw_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match map.get(key) {
        Some(v) if v.is_null() => Ok(None),
        Some(v) if v.is_string() => {
            let s = v.as_str().unwrap();
            if s.is_empty() || s != s.trim() {
                return Err(format!("nft_missing_or_invalid_field: {}", key));
            }
            Ok(Some(s.to_string()))
        }
        _ => Err(format!("nft_missing_or_invalid_field: {}", key)),
    }
}

fn nft_api_optional_u64_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<u64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(v) if v.is_u64() => Ok(Some(v.as_u64().unwrap())),
        _ => Err(format!("nft_missing_or_invalid_field: {}", key)),
    }
}

fn nft_api_parse_metadata_hash_v1(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<[u8; 32], String> {
    let metadata_hash_hex = nft_api_required_nonempty_str_raw_v1(map, "metadata_hash_hex")?;
    crate::nft::parse_nft_hash32_hex_v1("metadata_hash_hex", &metadata_hash_hex)
}

fn nft_api_allowed_keys_for_op_v1(
    op: &str,
    common_keys: &[&'static str],
) -> Result<Vec<&'static str>, String> {
    let mut out: Vec<&'static str> = match op {
        "create_collection" => vec![
            "asset_type",
            "base_uri",
            "burnable",
            "max_supply",
            "metadata_hash_hex",
            "mintable",
            "name",
            "op",
            "revocable",
            "symbol",
            "transfer_policy",
        ],
        "mint" => vec![
            "collection_id",
            "metadata_hash_hex",
            "expires_at_height",
            "op",
            "to",
            "token_uri",
        ],
        "transfer" => vec!["collection_id", "op", "serial", "to"],
        "approve" => vec!["approved", "collection_id", "op", "serial"],
        "set_approval_for_all" => vec!["approved", "collection_id", "op", "operator"],
        "burn" | "revoke" => vec!["collection_id", "op", "serial"],
        "set_token_uri" => vec![
            "collection_id",
            "metadata_hash_hex",
            "op",
            "serial",
            "token_uri",
        ],
        "set_collection_uri" => vec!["base_uri", "collection_id", "metadata_hash_hex", "op"],
        "freeze_token" => vec!["collection_id", "frozen", "op", "serial"],
        "set_collection_policy" => vec![
            "burnable",
            "collection_id",
            "mintable",
            "op",
            "revocable",
            "transfer_policy",
        ],
        "set_issuer" => vec!["collection_id", "issuer", "op"],
        "pause" => vec!["collection_id", "op", "paused"],
        _ => return Err(format!("unknown_op: {}", op)),
    };
    for key in common_keys {
        if !out.iter().any(|existing| existing == key) {
            out.push(*key);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn nft_api_parse_op_from_body_v1(
    body_obj: &serde_json::Map<String, serde_json::Value>,
    common_keys: &[&'static str],
) -> Result<crate::nft::NftOpV1, String> {
    let op = nft_api_required_nonempty_str_raw_v1(body_obj, "op")?;
    let allowed = nft_api_allowed_keys_for_op_v1(&op, common_keys)?;
    nft_api_exact_keys_v1(body_obj, &allowed)?;
    match op.as_str() {
        "create_collection" => Ok(crate::nft::NftOpV1::CreateCollection {
            symbol: nft_api_required_nonempty_str_raw_v1(body_obj, "symbol")?,
            name: nft_api_required_nonempty_str_raw_v1(body_obj, "name")?,
            max_supply: nft_api_optional_nullable_u64_v1(body_obj, "max_supply")?,
            base_uri: nft_api_required_str_raw_v1(body_obj, "base_uri")?,
            metadata_hash: nft_api_parse_metadata_hash_v1(body_obj)?,
            mintable: nft_api_required_bool_v1(body_obj, "mintable")?,
            burnable: nft_api_required_bool_v1(body_obj, "burnable")?,
            asset_type: nft_api_required_nonempty_str_raw_v1(body_obj, "asset_type")
                .and_then(|v| crate::nft::NftAssetTypeV1::parse_raw(&v))?,
            transfer_policy: nft_api_required_nonempty_str_raw_v1(body_obj, "transfer_policy")
                .and_then(|v| crate::nft::NftTransferPolicyV1::parse_raw(&v))?,
            revocable: nft_api_required_bool_v1(body_obj, "revocable")?,
        }),
        "mint" => Ok(crate::nft::NftOpV1::Mint {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            to_b64: nft_api_required_nonempty_str_raw_v1(body_obj, "to")?,
            token_uri: nft_api_required_str_raw_v1(body_obj, "token_uri")?,
            metadata_hash: nft_api_parse_metadata_hash_v1(body_obj)?,
            expires_at_height: nft_api_optional_nullable_u64_v1(body_obj, "expires_at_height")?,
        }),
        "transfer" => Ok(crate::nft::NftOpV1::Transfer {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
            to_b64: nft_api_required_nonempty_str_raw_v1(body_obj, "to")?,
        }),
        "approve" => Ok(crate::nft::NftOpV1::Approve {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
            approved_b64: nft_api_required_nullable_str_raw_v1(body_obj, "approved")?,
        }),
        "set_approval_for_all" => Ok(crate::nft::NftOpV1::SetApprovalForAll {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            operator_b64: nft_api_required_nonempty_str_raw_v1(body_obj, "operator")?,
            approved: nft_api_required_bool_v1(body_obj, "approved")?,
        }),
        "burn" => Ok(crate::nft::NftOpV1::Burn {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
        }),
        "revoke" => Ok(crate::nft::NftOpV1::Revoke {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
        }),
        "set_token_uri" => Ok(crate::nft::NftOpV1::SetTokenUri {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
            token_uri: nft_api_required_str_raw_v1(body_obj, "token_uri")?,
            metadata_hash: nft_api_parse_metadata_hash_v1(body_obj)?,
        }),
        "set_collection_uri" => Ok(crate::nft::NftOpV1::SetCollectionUri {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            base_uri: nft_api_required_str_raw_v1(body_obj, "base_uri")?,
            metadata_hash: nft_api_parse_metadata_hash_v1(body_obj)?,
        }),
        "freeze_token" => Ok(crate::nft::NftOpV1::FreezeToken {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            serial: nft_api_required_nonzero_u64_v1(body_obj, "serial")?,
            frozen: nft_api_required_bool_v1(body_obj, "frozen")?,
        }),
        "set_collection_policy" => Ok(crate::nft::NftOpV1::SetCollectionPolicy {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            mintable: nft_api_required_bool_v1(body_obj, "mintable")?,
            burnable: nft_api_required_bool_v1(body_obj, "burnable")?,
            transfer_policy: nft_api_required_nonempty_str_raw_v1(body_obj, "transfer_policy")
                .and_then(|v| crate::nft::NftTransferPolicyV1::parse_raw(&v))?,
            revocable: nft_api_required_bool_v1(body_obj, "revocable")?,
        }),
        "set_issuer" => Ok(crate::nft::NftOpV1::SetIssuer {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            issuer_b64: nft_api_required_nonempty_str_raw_v1(body_obj, "issuer")?,
        }),
        "pause" => Ok(crate::nft::NftOpV1::SetPaused {
            collection_id: nft_api_required_nonzero_u64_v1(body_obj, "collection_id")?,
            paused: nft_api_required_bool_v1(body_obj, "paused")?,
        }),
        _ => Err(format!("unknown_op: {}", op)),
    }
}

fn nft_api_optional_bool_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    match map.get(key).and_then(|v| v.as_bool()) {
        None if !map.contains_key(key) => Ok(false),
        Some(v) => Ok(v),
        None => Err(format!("nft_missing_or_invalid_field: {}", key)),
    }
}

fn nft_api_reject_unsupported_public_field_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<(), String> {
    if map.contains_key(key) {
        Err(format!("unsupported_public_field: {}", key))
    } else {
        Ok(())
    }
}

fn nft_api_effective_unsigned_max_fee_v1(
    requested_max_fee_per_tx: Option<u64>,
    priority_fee: u64,
    base_fee_per_tx: u64,
) -> Result<u64, String> {
    match requested_max_fee_per_tx {
        Some(v) if v < base_fee_per_tx => Err(format!(
            "max_fee_per_tx_below_base_fee: provided={} required_at_least={}",
            v, base_fee_per_tx
        )),
        Some(v) => Ok(v),
        None => base_fee_per_tx.checked_add(priority_fee).ok_or_else(|| {
            format!(
                "max_fee_per_tx_overflow: base_fee_per_tx={} priority_fee={}",
                base_fee_per_tx, priority_fee
            )
        }),
    }
}

fn nft_policy_enabled_v1(params: Option<&crate::governance::GovernanceParams>) -> bool {
    params.map(|p| p.nft_enabled).unwrap_or(false)
}

fn nft_policy_op_enabled_v1(
    op: &crate::nft::NftOpV1,
    params: Option<&crate::governance::GovernanceParams>,
) -> bool {
    match op {
        crate::nft::NftOpV1::CreateCollection { .. } => {
            params.map(|p| p.nft_public_create_enabled).unwrap_or(false)
        }
        crate::nft::NftOpV1::Mint { .. } => {
            params.map(|p| p.nft_public_mint_enabled).unwrap_or(false)
        }
        crate::nft::NftOpV1::Transfer { .. } => params
            .map(|p| p.nft_public_transfer_enabled)
            .unwrap_or(false),
        crate::nft::NftOpV1::Approve { .. } | crate::nft::NftOpV1::SetApprovalForAll { .. } => {
            params
                .map(|p| p.nft_public_approval_enabled)
                .unwrap_or(false)
        }
        crate::nft::NftOpV1::Burn { .. } => {
            params.map(|p| p.nft_public_burn_enabled).unwrap_or(false)
        }
        crate::nft::NftOpV1::Revoke { .. } => {
            params.map(|p| p.nft_public_revoke_enabled).unwrap_or(false)
        }
        crate::nft::NftOpV1::SetTokenUri { .. } | crate::nft::NftOpV1::SetCollectionUri { .. } => {
            params
                .map(|p| p.nft_public_metadata_update_enabled)
                .unwrap_or(false)
        }
        crate::nft::NftOpV1::FreezeToken { .. } => {
            params.map(|p| p.nft_public_freeze_enabled).unwrap_or(false)
        }
        crate::nft::NftOpV1::SetCollectionPolicy { .. } => params
            .map(|p| p.nft_public_policy_update_enabled)
            .unwrap_or(false),
        crate::nft::NftOpV1::SetIssuer { .. } => params
            .map(|p| p.nft_public_issuer_update_enabled)
            .unwrap_or(false),
        crate::nft::NftOpV1::SetPaused { .. } => {
            params.map(|p| p.nft_public_pause_enabled).unwrap_or(false)
        }
    }
}

fn nft_policy_fee_for_op_v1(
    op: &crate::nft::NftOpV1,
    params: Option<&crate::governance::GovernanceParams>,
) -> u64 {
    match op {
        crate::nft::NftOpV1::CreateCollection { .. } => {
            params.map(|p| p.nft_create_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::Mint { .. } => params.map(|p| p.nft_mint_fee_native).unwrap_or(0),
        crate::nft::NftOpV1::Transfer { .. } => {
            params.map(|p| p.nft_transfer_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::Approve { .. } | crate::nft::NftOpV1::SetApprovalForAll { .. } => {
            params.map(|p| p.nft_approval_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::Burn { .. } => params.map(|p| p.nft_burn_fee_native).unwrap_or(0),
        crate::nft::NftOpV1::Revoke { .. } => params.map(|p| p.nft_revoke_fee_native).unwrap_or(0),
        crate::nft::NftOpV1::SetTokenUri { .. } | crate::nft::NftOpV1::SetCollectionUri { .. } => {
            params
                .map(|p| p.nft_metadata_update_fee_native)
                .unwrap_or(0)
        }
        crate::nft::NftOpV1::FreezeToken { .. } => {
            params.map(|p| p.nft_freeze_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::SetCollectionPolicy { .. } => {
            params.map(|p| p.nft_policy_update_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::SetIssuer { .. } => {
            params.map(|p| p.nft_issuer_update_fee_native).unwrap_or(0)
        }
        crate::nft::NftOpV1::SetPaused { .. } => {
            params.map(|p| p.nft_pause_fee_native).unwrap_or(0)
        }
    }
}

fn nft_policy_validate_request_v1(
    op: &crate::nft::NftOpV1,
    memo: &str,
    params: Option<&crate::governance::GovernanceParams>,
) -> Result<(), String> {
    if !nft_policy_enabled_v1(params) {
        return Err("nft_disabled".to_string());
    }
    if !params.map(|p| p.nft_metadata_hash_required).unwrap_or(true) {
        return Err("nft_metadata_hash_required_must_remain_true".to_string());
    }
    if !nft_policy_op_enabled_v1(op, params) {
        return Err(format!(
            "nft_op_disabled: {}",
            crate::nft::nft_op_name_v1(op)
        ));
    }
    let max_memo = params
        .map(|p| p.nft_max_memo_bytes)
        .unwrap_or(crate::nft::NFTV1_MEMO_MAX_BYTES as u32)
        .clamp(1, crate::nft::NFTV1_MEMO_MAX_BYTES as u32) as usize;
    if memo.is_empty() || memo.len() > max_memo {
        return Err(format!(
            "nft_memo_policy_limit_exceeded: len={} max={}",
            memo.len(),
            max_memo
        ));
    }
    let max_uri = params
        .map(|p| p.nft_max_uri_bytes)
        .unwrap_or(crate::nft::NFTV1_URI_MAX_BYTES as u32)
        .clamp(1, crate::nft::NFTV1_URI_MAX_BYTES as u32) as usize;
    let max_name = params
        .map(|p| p.nft_max_name_bytes)
        .unwrap_or(crate::nft::NFTV1_NAME_MAX_BYTES as u32)
        .clamp(1, crate::nft::NFTV1_NAME_MAX_BYTES as u32) as usize;
    let max_symbol = params
        .map(|p| p.nft_max_symbol_bytes)
        .unwrap_or(crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32)
        .clamp(1, crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32) as usize;
    let max_tokens = params.map(|p| p.nft_max_tokens_per_collection).unwrap_or(0);
    match op {
        crate::nft::NftOpV1::CreateCollection {
            symbol,
            name,
            base_uri,
            max_supply,
            ..
        } => {
            if symbol.len() > max_symbol {
                return Err(format!(
                    "nft_symbol_policy_limit_exceeded: len={} max={}",
                    symbol.len(),
                    max_symbol
                ));
            }
            if name.len() > max_name {
                return Err(format!(
                    "nft_name_policy_limit_exceeded: len={} max={}",
                    name.len(),
                    max_name
                ));
            }
            if base_uri.len() > max_uri {
                return Err(format!(
                    "nft_uri_policy_limit_exceeded: len={} max={}",
                    base_uri.len(),
                    max_uri
                ));
            }
            if let Some(max_supply) = max_supply {
                if max_tokens > 0 && *max_supply > max_tokens {
                    return Err(format!(
                        "nft_collection_max_supply_exceeds_policy: max_supply={} cap={}",
                        max_supply, max_tokens
                    ));
                }
            }
        }
        crate::nft::NftOpV1::Mint { token_uri, .. }
        | crate::nft::NftOpV1::SetTokenUri { token_uri, .. } => {
            if token_uri.len() > max_uri {
                return Err(format!(
                    "nft_uri_policy_limit_exceeded: len={} max={}",
                    token_uri.len(),
                    max_uri
                ));
            }
        }
        crate::nft::NftOpV1::SetCollectionUri { base_uri, .. } => {
            if base_uri.len() > max_uri {
                return Err(format!(
                    "nft_uri_policy_limit_exceeded: len={} max={}",
                    base_uri.len(),
                    max_uri
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_amount_atomic(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    if let Some(i) = v.as_i64() {
        if i >= 0 {
            return Some(i as u64);
        } else {
            return None;
        }
    }
    if let Some(s) = v.as_str() {
        return parse_amount_str_to_atomic(s);
    }
    if v.is_number() {
        // serde_json::Number prints in a stable decimal form for finite values.
        return parse_amount_str_to_atomic(&v.to_string());
    }
    None
}

fn parse_amount_str_to_atomic(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // allow comma as decimal separator
    let s = s.replace(',', ".");
    // fast path: no decimal separator -> atomic units
    if !s.contains('.') {
        return s.parse::<u64>().ok();
    }
    // strict decimal parsing (no exponent, no sign)
    let mut it = s.splitn(2, '.');
    let whole_str = it.next().unwrap_or("");
    let frac_str = it.next().unwrap_or("");

    if !whole_str.is_empty() && !whole_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !frac_str.is_empty() && !frac_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if frac_str.len() > NGT_DECIMALS {
        return None;
    }

    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().ok()?
    };

    let mut frac_padded = frac_str.to_string();
    while frac_padded.len() < NGT_DECIMALS {
        frac_padded.push('0');
    }
    let frac: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().ok()?
    };

    let atomic = whole.checked_mul(NGT_SCALE)?.checked_add(frac)?;
    Some(atomic)
}

/// GET /api/v2/light/headers?from_height=H&limit=N
async fn light_headers_handler(
    storage: Arc<DbStore>,
    q: LightHeadersQuery,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    tokio::task::spawn_blocking(move || light_headers_handler_sync(storage, q))
        .await
        .map_err(|e| spawn_blocking_join_rejection("light_headers", e))?
}

fn light_headers_handler_sync(
    storage: Arc<DbStore>,
    q: LightHeadersQuery,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    let from = q.from_height.unwrap_or(0);
    let limit = q.limit.unwrap_or(128).clamp(1, 2000);

    let blocks = match storage.get_blocks_range(from, limit) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[API] light_headers: storage_read_failed: {:?}", e);
            let body = serde_json::json!({"status":"error","message":"storage_read_failed"});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let mut headers: Vec<serde_json::Value> = Vec::with_capacity(blocks.len());
    for b in blocks {
        let computed_root = match txids_from_block_txs(&b.transactions) {
            Ok(txids) => hex::encode(merkle_root_from_txids(&txids)),
            Err(err) => {
                let body = serde_json::json!({
                    "status":"error",
                    "message":"txid_decode_failed",
                    "detail": err,
                    "height": b.index
                });
                return Ok(warp::reply::with_status(
                    warp::reply::json(&body),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        };

        let tx_root = if !b.tx_root.is_empty() {
            // Safety: se il DB contiene tx_root, deve combaciare col ricalcolo
            if b.tx_root != computed_root {
                let body = serde_json::json!({
                    "status":"error",
                    "message":"tx_root_mismatch_db",
                    "height": b.index,
                    "db_tx_root": b.tx_root,
                    "computed_tx_root": computed_root
                });
                return Ok(warp::reply::with_status(
                    warp::reply::json(&body),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
            b.tx_root
        } else {
            computed_root
        };

        headers.push(serde_json::json!({
            "height": b.index,
            "hash": b.hash,
            "prev_hash": b.previous_hash,
            "timestamp": b.timestamp,
            "tx_root": tx_root,
            "state_root": b.state_root
        }));
    }

    let body = serde_json::json!({
        "status":"ok",
        "from_height": from,
        "count": headers.len(),
        "headers": headers
    });

    Ok(warp::reply::with_status(
        warp::reply::json(&body),
        warp::http::StatusCode::OK,
    ))
}

/// GET /api/v2/light/tx/{txid}/proof
async fn light_tx_proof_handler(
    txid_in: String,
    storage: Arc<DbStore>,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    tokio::task::spawn_blocking(move || light_tx_proof_handler_sync(txid_in, storage))
        .await
        .map_err(|e| spawn_blocking_join_rejection("light_tx_proof", e))?
}

fn light_tx_proof_handler_sync(
    txid_in: String,
    storage: Arc<DbStore>,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    let txid = normalize_txid(txid_in);

    let (height, _tx) = match storage.get_tx_by_hash(&txid) {
        Ok(Some(v)) => v,
        Ok(None) => {
            let body = serde_json::json!({"status":"not_found","txid":txid});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::NOT_FOUND,
            ));
        }
        Err(e) => {
            eprintln!("[API] light_tx_proof: tx_lookup_failed: {:?}", e);
            let body = serde_json::json!({"status":"error","message":"tx_lookup_failed"});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let block = match storage.get_block(height) {
        Ok(Some(b)) => b,
        Ok(None) => {
            let body = serde_json::json!({
                "status":"error",
                "message":"block_missing_for_tx_index",
                "height": height
            });
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
        Err(e) => {
            eprintln!("[API] light_tx_proof: block_load_failed: {:?}", e);
            let body = serde_json::json!({"status":"error","message":"block_load_failed"});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let tx_index = match block.transactions.iter().position(|t| t.hash == txid) {
        Some(i) => i,
        None => {
            let body = serde_json::json!({
                "status":"error",
                "message":"tx_not_in_block_transactions",
                "height": height,
                "block_hash": block.hash
            });
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let txids = match txids_from_block_txs(&block.transactions) {
        Ok(v) => v,
        Err(err) => {
            let body = serde_json::json!({
                "status":"error",
                "message":"txid_decode_failed",
                "detail": err,
                "height": height
            });
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let root = merkle_root_from_txids(&txids);
    let root_hex = hex::encode(root);

    // Safety: se il blocco ha già tx_root persistita, deve combaciare.
    if !block.tx_root.is_empty() && block.tx_root != root_hex {
        let body = serde_json::json!({
            "status":"error",
            "message":"tx_root_mismatch_db",
            "height": height,
            "db_tx_root": block.tx_root,
            "computed_tx_root": root_hex
        });
        return Ok(warp::reply::with_status(
            warp::reply::json(&body),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let proof = merkle_proof_from_txids(&txids, tx_index);
    let siblings: Vec<serde_json::Value> = proof
        .into_iter()
        .map(|(side, h)| {
            serde_json::json!({
                "side": match side { MerkleSide::Left => "left", MerkleSide::Right => "right" },
                "hash": hex::encode(h)
            })
        })
        .collect();

    let tip = storage.get_height().unwrap_or(height);
    let confirmations = if tip >= height { tip - height + 1 } else { 0 };

    let body = serde_json::json!({
        "status":"ok",
        "txid": txid,
        "height": height,
        "confirmations": confirmations,
        "block_hash": block.hash,
        "tx_index": tx_index,
        "tx_count": block.transactions.len(),
        "header": {
            "height": block.index,
            "hash": block.hash,
            "prev_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "tx_root": if !block.tx_root.is_empty() { block.tx_root } else { root_hex.clone() }
        },
        "merkle": {
            "rule": {
                "odd_handling": "promote_last",
                "leaf_hashing": "SHA256(00||txid)",
                "node_hashing": "SHA256(01||L||R)"
            },
            "root": root_hex,
            "siblings": siblings
        }
    });

    Ok(warp::reply::with_status(
        warp::reply::json(&body),
        warp::http::StatusCode::OK,
    ))
}

/// GET /api/v2/light/state/{pk_b64}/proof?height=H
async fn light_state_proof_handler(
    pk_b64_in: String,
    storage: Arc<DbStore>,
    q: LightStateHeightQuery,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    tokio::task::spawn_blocking(move || light_state_proof_handler_sync(pk_b64_in, storage, q))
        .await
        .map_err(|e| spawn_blocking_join_rejection("light_state_proof", e))?
}

fn light_state_proof_handler_sync(
    pk_b64_in: String,
    storage: Arc<DbStore>,
    q: LightStateHeightQuery,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    // Path segment: può arrivare url-encoded (%2F, %3D, ecc.)
    let pk_decoded = url_decode_simple(&pk_b64_in)?;
    let pk_b64 = normalize_pk_b64(&pk_decoded);

    let tip = storage.get_height().unwrap_or(0);
    let height = q.height.unwrap_or(tip);
    if height > tip {
        let body = serde_json::json!({"status":"error","message":"height_out_of_range","tip":tip,"height":height});
        return Ok(warp::reply::with_status(
            warp::reply::json(&body),
            warp::http::StatusCode::BAD_REQUEST,
        ));
    }

    let block = match storage.get_block(height) {
        Ok(Some(b)) => b,
        Ok(None) => {
            let body =
                serde_json::json!({"status":"error","message":"block_not_found","height":height});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::NOT_FOUND,
            ));
        }
        Err(e) => {
            eprintln!("[API] light_state_proof: block_load_failed: {:?}", e);
            let body = serde_json::json!({"status":"error","message":"block_load_failed"});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    if block.state_root.trim().is_empty() {
        let body =
            serde_json::json!({"status":"error","message":"missing_state_root","height":height});
        return Ok(warp::reply::with_status(
            warp::reply::json(&body),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let root = match bytes32_from_hex(block.state_root.trim()) {
        Ok(r) => r,
        Err(e) => {
            let body =
                serde_json::json!({"status":"error","message":"bad_state_root_hex","detail":e});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let smt = StateSmt::new(storage.state_node_store());
    let key = addr_key(&pk_b64);

    let proof = match smt.prove_account(root, key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[API] light_state_proof: prove_failed: {:?}", e);
            let body = serde_json::json!({"status":"error","message":"prove_failed","detail":e});
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let body = serde_json::json!({
        "status":"ok",
        "address": pk_b64,
        "height": height,
        "header": {
            "height": block.index,
            "hash": block.hash,
            "prev_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "tx_root": block.tx_root,
            "state_root": block.state_root
        },
        "proof": proof
    });

    Ok(warp::reply::with_status(
        warp::reply::json(&body),
        warp::http::StatusCode::OK,
    ))
}

/// GET /api/v2/light/state/proof?pk_b64=...&height=H
async fn light_state_proof_query_handler(
    storage: std::sync::Arc<DbStore>,
    q: LightStateProofQuery,
) -> Result<impl warp::Reply, warp::Rejection> {
    let pk_b64 = match q.pk_b64 {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            let body = serde_json::json!({
                "status": "error",
                "message": "missing_pk_b64",
            });
            return Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::BAD_REQUEST,
            ));
        }
    };

    // Riutilizziamo lo stesso handler (headers/proof) ma passando lo storage gia' aperto.
    light_state_proof_handler(pk_b64, storage, LightStateHeightQuery { height: q.height }).await
}

// ====== Handler bilancio v2 ======
async fn get_v2_wallet_balance_handler(
    address_enc: String,
    chain: SharedChain,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    // Decodifica "%3D" → "=" ecc.
    let address = url_decode_simple(&address_enc)?;

    let ch = chain
        .lock()
        .map_err(|_| warp::reject::custom(ApiError::Internal("chain_lock_poisoned")))?;
    let balance = ch.get_balance(&address);

    Ok(warp::reply::with_status(
        warp::reply::json(&BalanceResponse { address, balance }),
        warp::http::StatusCode::OK,
    ))
}

fn get_v2_wallet_balance_route(
    chain: SharedChain,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("api" / "v2" / "wallet" / "balance" / String)
        .and(warp::get())
        .and(with_chain(chain))
        .and_then(get_v2_wallet_balance_handler)
}

fn next_nonce_handler(
    address_enc: String,
    chain: Arc<Mutex<Blockchain>>,
    mp: Arc<Mutex<Mempool>>,
) -> warp::reply::WithStatus<warp::reply::Json> {
    // Wallet/client public keys are standard base64 and may contain '+', '/' and '='.
    // Keep this path consistent with /api/v2/wallet/balance/{pk}, otherwise clients can
    // compute nonce for the URL-encoded string instead of the canonical wallet key.
    let address = match url_decode_simple(&address_enc) {
        Ok(v) => v,
        Err(_) => {
            return warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "message": "invalid_address_encoding"
                })),
                warp::http::StatusCode::BAD_REQUEST,
            );
        }
    };

    let last_chain_nonce = lock_any!(chain).get_last_nonce(&address);
    let last_mempool_nonce = lock_any!(mp).get_last_nonce(&address);
    let next_nonce = std::cmp::max(last_chain_nonce, last_mempool_nonce).saturating_add(1);

    warp::reply::with_status(
        warp::reply::json(&serde_json::json!({
            "address": address,
            "next_nonce": next_nonce
        })),
        warp::http::StatusCode::OK,
    )
}

// ====== Handler TX by hash (indice storage) ======
/// GET /api/v2/tx/by-hash/{hash} (canonico)
/// GET /api/v2/tx/by_hash/{hash} (alias legacy/compat)
/// Legge la transazione dal backend storage usando l’indice tx_index
async fn tx_by_hash_handler(
    hash: String,
    storage: Arc<DbStore>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Una sola chiamata al DB (niente doppio get)
    let found = storage.get_tx_by_hash(&hash);

    // Qui supponiamo che get_tx_by_hash ritorni:
    //   Ok(Some((height, tx)))  dove tx: Transaction
    match found {
        Ok(Some((height, tx))) => {
            let (nft, nft_events) = match storage.get_block(height) {
                Ok(Some(block)) => {
                    let tx_index = block
                        .transactions
                        .iter()
                        .position(|candidate| candidate.hash == tx.hash)
                        .unwrap_or(usize::MAX);
                    if tx_index == usize::MAX {
                        (None, Vec::<serde_json::Value>::new())
                    } else {
                        let events =
                            nft_event_values_for_tx_from_block_v1(&block, &tx.hash, tx_index);
                        (events.first().cloned(), events)
                    }
                }
                _ => (None, Vec::<serde_json::Value>::new()),
            };
            let body = serde_json::json!({
                "status": "ok",
                "height": height,
                "tx": {
                    "hash": tx.hash,
                    "sender": tx.sender.clone(),
                            "receiver": tx.receiver.clone(),
                            "amount": tx.amount,
                    "max_fee_per_tx": tx.max_fee_per_tx,
                    "nonce": tx.nonce,
                    "is_coinbase": tx.is_coinbase,
                    "memo": tx.memo,
                    "ft": ft_receipt_json_or_error(&tx),
                    "nft": nft,
                    "nft_events": nft_events,
                }
            });

            Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::OK,
            ))
        }
        Ok(None) => {
            let body = serde_json::json!({
                "status": "not_found",
                "hash": hash,
            });
            Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::NOT_FOUND,
            ))
        }
        Err(e) => {
            eprintln!("[API] Errore get_tx_by_hash: {:?}", e);
            let body = serde_json::json!({
                "status": "error",
                "message": "storage_error"
            });
            Ok(warp::reply::with_status(
                warp::reply::json(&body),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

// ====== Handler mining (UI manual) ======
async fn mine_handler(
    chain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<Mempool>>,
    tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Altezza PRIMA del mining (safe)
    let index_before = {
        let ch = lock_any!(chain);
        match ch.get_latest_block_opt() {
            Some(b) => b.index,
            None => {
                eprintln!("⚠️ [mine_handler] chain vuota: impossibile minare (nessun genesis)");
                return Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "height": null,
                    "message": "Chain vuota: impossibile minare. In devnet deve esserci almeno il blocco di genesis."
                })));
            }
        }
    };

    // 2. Esegui il mining
    {
        let mut ch = lock_any!(chain);
        ch.mine_real_block(&mempool, &tx_p2p);
    } // lock rilasciato

    // Altezza DOPO il mining (safe)
    let index_after = {
        let ch = lock_any!(chain);
        match ch.get_latest_block_opt() {
            Some(b) => b.index,
            None => {
                eprintln!("⚠️ [mine_handler] chain vuota dopo il mining: stato incoerente");
                return Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "height": null,
                    "message": "Chain vuota dopo il mining: stato incoerente. Controlla il nodo."
                })));
            }
        }
    };

    // 4. Mining saltato?
    if index_after == index_before {
        // Nota: senza un ritorno deterministico dal core (mine_real_block),
        // non possiamo distinguere in modo atomico tra "mempool vuota", "non proposatore"
        // o "blocco arrivato via P2P". Per i test pubblici rispondiamo in modo corretto:
        // nessun nuovo blocco osservato.
        Ok(warp::reply::json(&serde_json::json!({
            "status": "ok",
            "height_before": index_before,
            "height_after": index_after,
            "message": "No new block produced"
        })))
    } else {
        Ok(warp::reply::json(&serde_json::json!({
            "status": "ok",
            "height_before": index_before,
            "height_after": index_after,
            "delta": index_after.saturating_sub(index_before),
            "message": "Chain advanced"
        })))
    }
}

// ===================================================================
// ======================= FUNZIONE PRINCIPALE ========================
// ===================================================================

async fn wallet_history_handler(
    address_enc: String,
    q: TxHistoryQuery,
    ch: SharedChain,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    tokio::task::spawn_blocking(move || wallet_history_handler_sync(address_enc, q, ch))
        .await
        .map_err(|e| spawn_blocking_join_rejection("wallet_history", e))?
}

fn wallet_history_handler_sync(
    address_enc: String,
    q: TxHistoryQuery,
    ch: SharedChain,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    let address = url_decode_simple(&address_enc)?;

    let blocks = clamp_usize(
        q.blocks,
        TX_HISTORY_DEFAULT_BLOCKS,
        1,
        TX_HISTORY_MAX_BLOCKS,
    );
    let max_txs = clamp_usize(q.max_txs, TX_HISTORY_DEFAULT_MAX_TXS, 1, TX_HISTORY_MAX_TXS);
    let include_coinbase = if q.only_user_txs.unwrap_or(false) {
        false
    } else {
        q.include_coinbase.unwrap_or(true)
    };

    let (tip_height, from_height, scanned_blocks, next_from_height, txs) = {
        let bc = lock_any!(ch);

        if bc.chain.is_empty() {
            (0u64, 0u64, 0usize, None, vec![])
        } else {
            let base = bc.chain.first().map(|b| b.index).unwrap_or(0);
            let tip = bc.chain.last().map(|b| b.index).unwrap_or(0);
            let from = q.from_height.unwrap_or(tip).clamp(base, tip);

            let contiguous = ((tip - base) as usize + 1) == bc.chain.len();

            let mut out: Vec<TxHistoryItem> = Vec::new();
            let mut scanned: usize = 0;
            let mut earliest: Option<u64> = None;

            macro_rules! push_tx {
                ($height:expr, $tx:expr) => {{
                    out.push(TxHistoryItem {
                        height: $height,
                        sender: $tx.sender.clone(),
                        receiver: $tx.receiver.clone(),
                        amount: $tx.amount,
                        max_fee_per_tx: $tx.max_fee_per_tx,
                        nonce: $tx.nonce,
                        hash: $tx.hash.clone(),
                        is_coinbase: $tx.is_coinbase,
                        memo: $tx.memo.clone(),
                    });
                }};
            }

            let addr = address.as_str();

            if contiguous {
                let pos = (from - base) as usize;
                'outer: for b in bc.chain[..=pos].iter().rev().take(blocks) {
                    scanned += 1;
                    earliest = Some(b.index);
                    for tx in &b.transactions {
                        if !include_coinbase && tx.is_coinbase {
                            continue;
                        }
                        if tx.sender == addr || tx.receiver == addr {
                            push_tx!(b.index, tx);
                            if out.len() >= max_txs {
                                break 'outer;
                            }
                        }
                    }
                }
            } else {
                'outer2: for b in bc.chain.iter().rev() {
                    if b.index > from {
                        continue;
                    }
                    scanned += 1;
                    earliest = Some(b.index);
                    for tx in &b.transactions {
                        if !include_coinbase && tx.is_coinbase {
                            continue;
                        }
                        if tx.sender == addr || tx.receiver == addr {
                            push_tx!(b.index, tx);
                            if out.len() >= max_txs {
                                break 'outer2;
                            }
                        }
                    }
                    if scanned >= blocks {
                        break;
                    }
                }
            }

            let next_from = earliest.and_then(|h| if h > base { Some(h - 1) } else { None });

            (tip, from, scanned, next_from, out)
        }
    };

    let returned_coinbase_txs = txs.iter().filter(|t| t.is_coinbase).count();
    let returned_user_txs = txs.len().saturating_sub(returned_coinbase_txs);

    let resp = TxHistoryResponse {
        status: "ok".to_string(),
        address,
        tip_height,
        from_height,
        scanned_blocks,
        returned: txs.len(),
        returned_user_txs,
        returned_coinbase_txs,
        include_coinbase,
        next_from_height,
        txs,
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&resp),
        warp::http::StatusCode::OK,
    ))
}

async fn blockchain_export_handler(
    include_txs_default: bool,
    _guard: (),
    q: ChainExportQuery,
    ch: SharedChain,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    tokio::task::spawn_blocking(move || blockchain_export_handler_sync(include_txs_default, q, ch))
        .await
        .map_err(|e| spawn_blocking_join_rejection("blockchain_export", e))?
}

fn blockchain_export_handler_sync(
    include_txs_default: bool,
    q: ChainExportQuery,
    ch: SharedChain,
) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    let include_txs = q.include_txs.unwrap_or(include_txs_default);

    let max_limit = if include_txs {
        EXPORT_MAX_LIMIT_WITH_TXS
    } else {
        EXPORT_MAX_LIMIT
    };
    let limit = clamp_usize(q.limit, EXPORT_DEFAULT_LIMIT, 1, max_limit);

    let (tip_height, from_height, blocks, next_from_height) = {
        let bc = lock_any!(ch);
        if bc.chain.is_empty() {
            (0u64, 0u64, vec![], None)
        } else {
            let base = bc.chain.first().map(|b| b.index).unwrap_or(0);
            let tip = bc.chain.last().map(|b| b.index).unwrap_or(0);
            let from = q.from_height.unwrap_or(tip).clamp(base, tip);
            let (blocks, next) = export_blocks_from_chain(&bc, from, limit, include_txs);
            (tip, from, blocks, next)
        }
    };

    let resp = ExportBlocksResponse {
        status: "ok".to_string(),
        tip_height,
        from_height,
        returned: blocks.len(),
        next_from_height,
        include_txs,
        blocks,
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&resp),
        warp::http::StatusCode::OK,
    ))
}

#[derive(Debug, Deserialize)]
struct EconomySeriesQuery {
    #[serde(default)]
    window_secs: Option<u64>,
    #[serde(default)]
    max_points: Option<usize>,
}

// Read-model contract for economy/treasury/blockchain info HTTP surfaces.
// Versioning policy (mainnet hygiene):
// - bump schema_version for any payload shape change
// - bump read_model_version for semantic changes without shape changes
const ECONOMY_HTTP_READ_MODEL_VERSION: u32 = 15;
const ECONOMY_HTTP_SCHEMA_VERSION: u32 = 15;
const ECONOMY_HTTP_BINDING_KIND_FINALIZED: &str = "finalized";

#[derive(Debug, Clone, Serialize)]
struct EconomyReadModelMeta {
    status: &'static str,
    read_model_version: u32,
    schema_version: u32,
    binding_kind: &'static str,
    binding_height: Option<u64>,
    binding_hash: Option<String>,
    binding_status: &'static str,
    binding_reason_codes: Vec<String>,
    snapshot_status: &'static str,
    snapshot_reason_codes: Vec<String>,
    contract_status: &'static str,
    contract_reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyReadModelContractMetadata {
    scope: &'static str,
    controller_contract_version: u32,
    policy_version: u32,
    policy_compat_version: u32,
    supported_policy_version: u32,
    supported_policy_compat_version: u32,
    policy_version_status: String,
    policy_version_reason_code: String,
    policy_version_error: Option<String>,
    canonical_supply_field: &'static str,
    legacy_total_supply_alias_field: &'static str,
    legacy_total_supply_alias_deprecated: bool,
    finalized_binding_field: &'static str,
    legacy_finalized_binding_alias_fields: Vec<&'static str>,
    observed_tip_field: &'static str,
    committed_field: &'static str,
    controller_local_field: &'static str,
    legacy_canonical_chain_economy_field: &'static str,
    legacy_local_node_observation_field: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyCanonicalReadModel {
    scope: &'static str,
    total_supply: Option<u64>,
    net_issued_supply: Option<u64>,
    treasury_balance: Option<u64>,
    base_fee_per_tx: Option<u64>,
    emission_controller_enabled: Option<bool>,
    emission_phase: Option<String>,
    reward_multiplier_bps: Option<u32>,
    current_applied_reward_base_schedule: Option<u64>,
    current_applied_reward_effective: Option<u64>,
    current_applied_validator_fee_budget: Option<u64>,
    unavailable_reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyCommittedReadModel {
    scope: &'static str,
    committed_height: Option<u64>,
    finalized_height: Option<u64>,
    finalized_hash: Option<String>,
    previous_finalized_height: Option<u64>,
    previous_finalized_hash: Option<String>,
    canonical_base_fee_per_tx: Option<u64>,
    previous_canonical_base_fee_per_tx: Option<u64>,
    committed_fee_action: String,
    committed_fee_reason_code: String,
    canonical_reward_multiplier_bps: Option<u32>,
    previous_canonical_reward_multiplier_bps: Option<u32>,
    canonical_reward_effective: Option<u64>,
    previous_canonical_reward_effective: Option<u64>,
    committed_emission_signal_field: &'static str,
    committed_emission_action: String,
    committed_emission_reason_code: String,
    unavailable_reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyDerivedRuntimeProjectionReadModel {
    scope: &'static str,
    observed_tip_height: u64,
    observed_tip_hash: String,
    reward_floor: u64,
    burn_bps: u32,
    next_projected_reward_base_schedule: u64,
    next_projected_reward_effective: u64,
    validator_fee_budget_ma30: u128,
    target_validator_budget_day: u128,
    current_budget_state: String,
    consecutive_sustainable_days: u32,
    hard_cap_day: u32,
    taper_days_remaining: u64,
    block_fill_ema_ppm: u32,
}

#[derive(Debug, Clone, Serialize)]
struct BlockchainInfoObservedTipReadModel {
    scope: &'static str,
    height: Option<u64>,
    hash: Option<String>,
    total_blocks: u64,
    total_transactions: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BlockchainInfoFinalizedHeadReadModel {
    scope: &'static str,
    height: Option<u64>,
    hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyLocalObservationReadModel {
    scope: &'static str,
    observed_tip_height: u64,
    observed_tip_hash: String,
    prospective_base_fee_per_tx: u64,
    tip_applied_base_fee_per_tx: Option<u64>,
    tip_applied_fee_height: Option<u64>,
    /// Backward-compatible alias for older explorer builds.
    /// Semantically identical to `tip_applied_base_fee_per_tx`.
    observed_tip_base_fee_per_tx: Option<u64>,
    /// Backward-compatible alias for older explorer builds.
    /// Semantically identical to `tip_applied_fee_height`.
    observed_tip_fee_height: Option<u64>,
    prospective_fee_delta_vs_observed_tip: Option<i64>,
    finalized_fee_lag_blocks: Option<u64>,
    prospective_emission_phase: String,
    prospective_reward_multiplier_bps: u32,
    regime: String,
    current_pressure_state: String,
    last_applied_fee_pressure_state: String,
    last_applied_budget_state: String,
    last_applied_emission_pressure_state: String,
    last_fee_controller_action: String,
    last_fee_controller_reason_code: String,
    controller_fee_action: String,
    controller_fee_reason_code: String,
    last_controller_fee_action: String,
    last_controller_fee_reason_code: String,
    last_controller_fee_decision_height: u64,
    controller_fee_action_semantics: &'static str,
    last_fee_controller_apply_height: u64,
    last_emission_controller_action: String,
    last_emission_controller_reason_code: String,
    last_emission_controller_apply_height: u64,
    emission_revenue_gap_ppm: i32,
    emission_under_target_streak: u32,
    emission_over_target_streak: u32,
    emission_near_target_streak: u32,
    emission_budget_deadband_ppm: u32,
    emission_budget_streak_required: u32,
    mempool_ema: u64,
    backlog_ratio: u32,
    stability_score_ppm: u32,
    fee_min_base_fee_per_tx: u64,
    fee_max_base_fee_per_tx: u64,
    fee_max_multiplier_bps: u32,
    fee_hot_raise_bps: u32,
    fee_critical_raise_bps: u32,
    fee_cold_lower_bps: u32,
    fee_recovery_lower_bps: u32,
    fee_neutral_revert_active: bool,
    fee_neutral_revert_armed: bool,
    fee_neutral_revert_target_base_fee: u64,
    fee_neutral_revert_lower_bps: u32,
    fee_neutral_revert_apply_interval_blocks: u64,
    fee_neutral_revert_min_streak_blocks: u32,
    fee_max_raise_per_apply_bps: u32,
    fee_max_lower_per_apply_bps: u32,
    fee_base_fee_delta_max_bps: u32,
    fee_base_fee_shadow: u64,
    fee_raise_delta_requested_ppm: u32,
    fee_raise_delta_capped_ppm: u32,
    fee_raise_delta_realized_ppm: u32,
    fee_raise_delta_applied_ppm: u32,
    fee_lower_delta_requested_ppm: u32,
    fee_lower_delta_capped_ppm: u32,
    fee_lower_delta_realized_ppm: u32,
    fee_lower_delta_applied_ppm: u32,
    fee_apply_interval_blocks: u64,
    fee_cadence_due: bool,
    fee_governance_base_fee_override_active: bool,
    fee_governance_base_fee_override_value: Option<u64>,
    fee_governance_base_fee_override_mode: String,
    fee_prospective_lag_cap_bps: u32,
    fee_prospective_lag_reference: Option<u64>,
    fee_prospective_lag_reference_height: Option<u64>,
    fee_prospective_lag_cap_active: bool,
    mempool_len_before_block: u64,
    mempool_len_after_block: u64,
    txs_selected_for_block: u64,
    recent_admitted_tx_count: u64,
    recent_rejected_fee_low_count: u64,
    recent_pruned_fee_low_count: u64,
    recent_ingress_tx_count: u64,
    mempool_eligible_len_before_block: u64,
    mempool_eligible_len_after_block: u64,
    stale_backlog_streak: u32,
    stale_backlog_hold_active: bool,
    incoming_pressure_ratio_ppm: u32,
    fee_empty_recovery_streak_blocks: u32,
    fee_recovery_hold_blocks: u32,
    fee_empty_recovery_streak: u32,
    fee_hot_streak: u32,
    fee_critical_streak: u32,
    fee_cold_streak: u32,
    fee_recovery_streak: u32,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyControllerLocalReadModel {
    scope: &'static str,
    tip_height: u64,
    tip_hash: String,
    controller_decision_height: u64,
    prospective_base_fee_per_tx: u64,
    tip_applied_base_fee_per_tx: Option<u64>,
    tip_applied_fee_height: Option<u64>,
    /// Backward-compatible alias for older explorer builds.
    /// Semantically identical to `tip_applied_base_fee_per_tx`.
    observed_tip_base_fee_per_tx: Option<u64>,
    /// Backward-compatible alias for older explorer builds.
    /// Semantically identical to `tip_applied_fee_height`.
    observed_tip_fee_height: Option<u64>,
    prospective_fee_delta_vs_observed_tip: Option<i64>,
    finalized_fee_lag_blocks: Option<u64>,
    prospective_fee_action: String,
    prospective_fee_reason_code: String,
    controller_fee_action: String,
    controller_fee_reason_code: String,
    last_controller_fee_action: String,
    last_controller_fee_reason_code: String,
    last_controller_fee_decision_height: u64,
    controller_fee_action_semantics: &'static str,
    prospective_fee_apply_height: u64,
    prospective_emission_phase: String,
    prospective_reward_multiplier_bps: u32,
    prospective_emission_action: String,
    prospective_emission_reason_code: String,
    prospective_emission_apply_height: u64,
    emission_revenue_gap_ppm: i32,
    emission_under_target_streak: u32,
    emission_over_target_streak: u32,
    emission_near_target_streak: u32,
    emission_budget_deadband_ppm: u32,
    emission_budget_streak_required: u32,
    regime: String,
    current_pressure_state: String,
    last_applied_fee_pressure_state: String,
    last_applied_budget_state: String,
    last_applied_emission_pressure_state: String,
    mempool_ema: u64,
    backlog_ratio: u32,
    stability_score_ppm: u32,
    fee_min_base_fee_per_tx: u64,
    fee_max_base_fee_per_tx: u64,
    fee_max_multiplier_bps: u32,
    fee_hot_raise_bps: u32,
    fee_critical_raise_bps: u32,
    fee_cold_lower_bps: u32,
    fee_recovery_lower_bps: u32,
    fee_neutral_revert_active: bool,
    fee_neutral_revert_armed: bool,
    fee_neutral_revert_target_base_fee: u64,
    fee_neutral_revert_lower_bps: u32,
    fee_neutral_revert_apply_interval_blocks: u64,
    fee_neutral_revert_min_streak_blocks: u32,
    fee_max_raise_per_apply_bps: u32,
    fee_max_lower_per_apply_bps: u32,
    fee_base_fee_delta_max_bps: u32,
    fee_base_fee_shadow: u64,
    fee_raise_delta_requested_ppm: u32,
    fee_raise_delta_capped_ppm: u32,
    fee_raise_delta_realized_ppm: u32,
    fee_raise_delta_applied_ppm: u32,
    fee_lower_delta_requested_ppm: u32,
    fee_lower_delta_capped_ppm: u32,
    fee_lower_delta_realized_ppm: u32,
    fee_lower_delta_applied_ppm: u32,
    fee_apply_interval_blocks: u64,
    fee_cadence_due: bool,
    fee_governance_base_fee_override_active: bool,
    fee_governance_base_fee_override_value: Option<u64>,
    fee_governance_base_fee_override_mode: String,
    fee_prospective_lag_cap_bps: u32,
    fee_prospective_lag_reference: Option<u64>,
    fee_prospective_lag_reference_height: Option<u64>,
    fee_prospective_lag_cap_active: bool,
    mempool_len_before_block: u64,
    mempool_len_after_block: u64,
    txs_selected_for_block: u64,
    recent_admitted_tx_count: u64,
    recent_rejected_fee_low_count: u64,
    recent_pruned_fee_low_count: u64,
    recent_ingress_tx_count: u64,
    mempool_eligible_len_before_block: u64,
    mempool_eligible_len_after_block: u64,
    stale_backlog_streak: u32,
    stale_backlog_hold_active: bool,
    incoming_pressure_ratio_ppm: u32,
    fee_empty_recovery_streak_blocks: u32,
    fee_recovery_hold_blocks: u32,
    fee_empty_recovery_streak: u32,
    fee_hot_streak: u32,
    fee_critical_streak: u32,
    fee_cold_streak: u32,
    fee_recovery_streak: u32,
}

#[derive(Debug, Clone, Serialize)]
struct TreasuryStateReadModel {
    #[serde(flatten)]
    meta: EconomyReadModelMeta,
    read_model_contract: EconomyReadModelContractMetadata,
    canonical_chain_economy: EconomyCanonicalReadModel,
    treasury_pct_base_bps: u32,
    treasury_pct_base: u32,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardEconomyReadModel {
    #[serde(flatten)]
    meta: EconomyReadModelMeta,
    read_model_contract: EconomyReadModelContractMetadata,
    committed: EconomyCommittedReadModel,
    controller_local: EconomyControllerLocalReadModel,
    canonical_chain_economy: EconomyCanonicalReadModel,
    derived_runtime_projection: EconomyDerivedRuntimeProjectionReadModel,
    local_node_observation: EconomyLocalObservationReadModel,
    rewards_last_20: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct EconomyControllerContractReadModel {
    status: &'static str,
    controller_contract_version: u32,
    fee_action_values: Vec<&'static str>,
    emission_action_values: Vec<&'static str>,
    reason_code_values: Vec<&'static str>,
}

fn finalized_binding_for_read_model(bc: &Blockchain) -> (Option<u64>, Option<String>, Vec<String>) {
    match bc.finalized_block_for_api() {
        Ok(Some(block)) => {
            let hash = block.hash.trim().to_string();
            if hash.is_empty() {
                (
                    Some(block.index),
                    None,
                    vec!["finalized_binding_hash_missing".to_string()],
                )
            } else {
                (Some(block.index), Some(hash), Vec::new())
            }
        }
        Ok(None) => (None, None, vec!["finalized_block_unavailable".to_string()]),
        Err(e) => (
            None,
            None,
            vec![format!("finalized_block_lookup_failed:{}", e)],
        ),
    }
}

fn finalized_snapshot_for_read_model(
    bc: &Blockchain,
) -> (
    Option<crate::blockchain::FinalizedEconomySnapshot>,
    Vec<String>,
) {
    match bc.finalized_economy_snapshot_for_api() {
        Ok(snap) => (Some(snap), Vec::new()),
        Err(e) => (None, vec![format!("finalized_snapshot_unavailable:{}", e)]),
    }
}

fn combine_reason_codes(mut lhs: Vec<String>, rhs: Vec<String>) -> Vec<String> {
    for code in rhs {
        if !lhs.iter().any(|existing| existing == &code) {
            lhs.push(code);
        }
    }
    lhs
}

fn runtime_surface_json() -> serde_json::Value {
    serde_json::json!({
        "binding_kind": ECONOMY_HTTP_BINDING_KIND_FINALIZED,
        "canonical_supply_field": "net_issued_supply",
        "legacy_total_supply_alias_field": "total_supply",
        "legacy_total_supply_alias_deprecated": true,
        "finalized_binding_field": "finalized_head",
        "legacy_finalized_binding_alias_fields": ["best_height", "best_hash", "tip_hash", "last_block_hash"],
        "observed_tip_field": "observed_tip",
        "cognitive_contract_route": "/api/v2/cognitive/contract",
        "cognitive_registry_meta_route": "/api/v2/cognitive/registry/meta",
        "cognitive_contract_route_enabled": true,
        "cognitive_registry_meta_route_enabled": true
    })
}

fn build_economy_read_model_meta(bc: &Blockchain) -> EconomyReadModelMeta {
    let policy_version_status = bc.policy_version_status_for_api();
    let policy_version_reason_code = bc.policy_version_reason_code_for_api();
    let (binding_height, binding_hash, binding_reason_codes) = finalized_binding_for_read_model(bc);
    let (_snap, snapshot_reason_codes) = finalized_snapshot_for_read_model(bc);

    let binding_status = if binding_reason_codes.is_empty() {
        "ok"
    } else {
        "degraded"
    };
    let snapshot_status = if snapshot_reason_codes.is_empty() {
        "ok"
    } else {
        "degraded"
    };
    let contract_reason_codes = if policy_version_status == "ok" {
        Vec::new()
    } else {
        vec![policy_version_reason_code.to_string()]
    };
    let contract_status = if contract_reason_codes.is_empty() {
        "ok"
    } else {
        "degraded"
    };
    let read_model_status = if binding_reason_codes.is_empty()
        && snapshot_reason_codes.is_empty()
        && contract_reason_codes.is_empty()
    {
        "ok"
    } else {
        "degraded"
    };
    EconomyReadModelMeta {
        status: read_model_status,
        read_model_version: ECONOMY_HTTP_READ_MODEL_VERSION,
        schema_version: ECONOMY_HTTP_SCHEMA_VERSION,
        binding_kind: ECONOMY_HTTP_BINDING_KIND_FINALIZED,
        binding_height,
        binding_hash,
        binding_status,
        binding_reason_codes,
        snapshot_status,
        snapshot_reason_codes,
        contract_status,
        contract_reason_codes,
    }
}

fn build_blockchain_info_read_model(bc: &Blockchain) -> serde_json::Value {
    let total_blocks = bc.chain.len() as u64;
    let total_txs: u64 = bc.total_txs_cached();
    let now_unix_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let chain_id: String = crate::chain_identity::network_id().to_string();
    let finalized_meta = build_economy_read_model_meta(bc);
    let read_model_contract = build_economy_read_model_contract_metadata(bc);
    let finalized = build_economy_canonical_read_model(bc);
    let (binding_tx_root, binding_state_root, root_reason_codes) =
        match bc.finalized_block_roots_for_api() {
            Ok(Some((tx_root, state_root))) => (Some(tx_root), Some(state_root), Vec::new()),
            Ok(None) => (
                None,
                None,
                vec!["finalized_block_roots_unavailable".to_string()],
            ),
            Err(e) => (None, None, vec![e]),
        };
    let (observed_tip_height, observed_tip_hash) = if let Some(last) = bc.chain.last() {
        (Some(last.index), Some(last.hash.clone()))
    } else {
        (None, None)
    };
    let observed_tip = BlockchainInfoObservedTipReadModel {
        scope: "node_local_observed_tip",
        height: observed_tip_height,
        hash: observed_tip_hash,
        total_blocks,
        total_transactions: total_txs,
    };
    let finalized_head = BlockchainInfoFinalizedHeadReadModel {
        scope: "finalized_chain_binding",
        height: finalized_meta.binding_height,
        hash: finalized_meta.binding_hash.clone(),
    };
    let economy_reason_codes = finalized.unavailable_reason_codes.clone();
    let snapshot_reason_codes = combine_reason_codes(
        finalized_meta.snapshot_reason_codes.clone(),
        root_reason_codes,
    );
    let snapshot_status = if snapshot_reason_codes.is_empty() {
        "ok"
    } else {
        "degraded"
    };
    let read_model_status = if finalized_meta.binding_status == "ok"
        && snapshot_status == "ok"
        && finalized_meta.contract_status == "ok"
    {
        "ok"
    } else {
        "degraded"
    };
    serde_json::json!({
        "status": read_model_status,
        "schema_version": finalized_meta.schema_version,
        "read_model_version": finalized_meta.read_model_version,
        "binding_kind": finalized_meta.binding_kind,
        "binding_height": finalized_meta.binding_height,
        "binding_hash": finalized_meta.binding_hash.clone(),
        "binding_status": finalized_meta.binding_status,
        "binding_reason_codes": finalized_meta.binding_reason_codes.clone(),
        "snapshot_status": snapshot_status,
        "snapshot_reason_codes": snapshot_reason_codes,
        "contract_status": finalized_meta.contract_status,
        "contract_reason_codes": finalized_meta.contract_reason_codes.clone(),
        "read_model_contract": read_model_contract,
        "chain_id": chain_id,
        "software_version": env!("CARGO_PKG_VERSION"),
        "now_unix_ms": now_unix_ms,
        "height": finalized_meta.binding_height,
        "best_height": finalized_meta.binding_height,
        "last_block_hash": finalized_meta.binding_hash.clone(),
        "tip_hash": finalized_meta.binding_hash.clone(),
        "best_hash": finalized_meta.binding_hash.clone(),
        "tx_root": binding_tx_root,
        "state_root": binding_state_root,
        "observed_tip": observed_tip,
        "finalized_head": finalized_head,
        "economy_unavailable_reason_codes": economy_reason_codes,
        "economy": {
            "total_supply": finalized.total_supply,
            "net_issued_supply": finalized.net_issued_supply,
            "treasury_balance": finalized.treasury_balance,
            "base_fee_per_tx": finalized.base_fee_per_tx,
            "unavailable_reason_codes": finalized.unavailable_reason_codes
        }
    })
}

fn build_economy_read_model_contract_metadata(bc: &Blockchain) -> EconomyReadModelContractMetadata {
    EconomyReadModelContractMetadata {
        scope: "runtime_contract_metadata",
        controller_contract_version: crate::blockchain::EconomicControllerAction::contract_version(
        ),
        policy_version: bc.policy_version_for_api(),
        policy_compat_version: bc.policy_compat_version_for_api(),
        supported_policy_version: bc.supported_policy_version_for_api(),
        supported_policy_compat_version: bc.supported_policy_compat_version_for_api(),
        policy_version_status: bc.policy_version_status_for_api().to_string(),
        policy_version_reason_code: bc.policy_version_reason_code_for_api().to_string(),
        policy_version_error: bc.policy_version_error_for_api(),
        canonical_supply_field: "net_issued_supply",
        legacy_total_supply_alias_field: "total_supply",
        legacy_total_supply_alias_deprecated: true,
        finalized_binding_field: "finalized_head",
        legacy_finalized_binding_alias_fields: vec![
            "best_height",
            "best_hash",
            "tip_hash",
            "last_block_hash",
        ],
        observed_tip_field: "observed_tip",
        committed_field: "committed",
        controller_local_field: "controller_local",
        legacy_canonical_chain_economy_field: "canonical_chain_economy",
        legacy_local_node_observation_field: "local_node_observation",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StatusEconomySupplyBindingV210 {
    base_fee_per_tx: u64,
    total_supply: u64,
    net_issued_supply: u64,
    treasury_balance: u64,
    supply_source: &'static str,
    reason_codes: Vec<String>,
    local_observed_base_fee_per_tx: u64,
    local_observed_total_supply: u64,
    local_observed_treasury_balance: u64,
}

fn status_economy_supply_binding_v210(bc: &Blockchain) -> StatusEconomySupplyBindingV210 {
    let local_observed_base_fee_per_tx = bc.base_fee_per_tx();
    let local_observed_total_supply = bc.total_supply;
    let local_observed_treasury_balance = bc.policy.treasury.reserve_balance;
    let canonical = build_economy_canonical_read_model(bc);

    let total_supply = canonical
        .net_issued_supply
        .or(canonical.total_supply)
        .unwrap_or(local_observed_total_supply);
    let net_issued_supply = canonical.net_issued_supply.unwrap_or(total_supply);
    let treasury_balance = canonical
        .treasury_balance
        .unwrap_or(local_observed_treasury_balance);
    let base_fee_per_tx = canonical
        .base_fee_per_tx
        .unwrap_or(local_observed_base_fee_per_tx);

    let mut reason_codes = canonical.unavailable_reason_codes.clone();
    let canonical_complete = canonical.net_issued_supply.is_some()
        && canonical.total_supply.is_some()
        && canonical.treasury_balance.is_some()
        && canonical.base_fee_per_tx.is_some();

    let supply_source = if canonical_complete {
        "finalized_economy_snapshot"
    } else {
        if !reason_codes
            .iter()
            .any(|code| code == "finalized_economy_snapshot_incomplete")
        {
            reason_codes.push("finalized_economy_snapshot_incomplete".to_string());
        }
        "local_runtime_fallback"
    };

    StatusEconomySupplyBindingV210 {
        base_fee_per_tx,
        total_supply,
        net_issued_supply,
        treasury_balance,
        supply_source,
        reason_codes,
        local_observed_base_fee_per_tx,
        local_observed_total_supply,
        local_observed_treasury_balance,
    }
}

fn build_economy_canonical_read_model(bc: &Blockchain) -> EconomyCanonicalReadModel {
    let (snap, snap_reason_codes) = finalized_snapshot_for_read_model(bc);
    let unavailable_reason_codes = combine_reason_codes(
        snap.as_ref()
            .map(|s| s.unavailable_reason_codes.clone())
            .unwrap_or_default(),
        snap_reason_codes,
    );
    EconomyCanonicalReadModel {
        scope: "finalized_chain_derived",
        total_supply: snap.as_ref().map(|s| s.total_supply),
        net_issued_supply: snap.as_ref().map(|s| s.total_supply),
        treasury_balance: snap.as_ref().map(|s| s.treasury_balance),
        base_fee_per_tx: snap.as_ref().and_then(|s| s.base_fee_per_tx),
        emission_controller_enabled: snap.as_ref().and_then(|s| s.emission_controller_enabled),
        emission_phase: snap.as_ref().and_then(|s| s.emission_phase.clone()),
        reward_multiplier_bps: snap.as_ref().and_then(|s| s.reward_multiplier_bps),
        current_applied_reward_base_schedule: snap
            .as_ref()
            .and_then(|s| s.current_applied_reward_base_schedule),
        current_applied_reward_effective: snap
            .as_ref()
            .and_then(|s| s.current_applied_reward_effective),
        current_applied_validator_fee_budget: snap
            .as_ref()
            .and_then(|s| s.current_applied_validator_fee_budget),
        unavailable_reason_codes,
    }
}

fn derive_committed_action_reason(
    previous_value: Option<u64>,
    current_value: Option<u64>,
    domain: &'static str,
) -> (String, String) {
    match (previous_value, current_value) {
        (Some(previous), Some(current)) if current > previous => (
            "raise".to_string(),
            format!("canonical_{}_increased", domain),
        ),
        (Some(previous), Some(current)) if current < previous => (
            "lower".to_string(),
            format!("canonical_{}_decreased", domain),
        ),
        (Some(_), Some(_)) => (
            "hold".to_string(),
            format!("canonical_{}_unchanged", domain),
        ),
        (None, Some(_)) => (
            "hold".to_string(),
            format!("canonical_{}_baseline_unavailable", domain),
        ),
        (_, None) => (
            "hold".to_string(),
            format!("canonical_{}_unavailable", domain),
        ),
    }
}

fn build_economy_committed_read_model(bc: &Blockchain) -> EconomyCommittedReadModel {
    match bc.finalized_economy_commitment_snapshot_for_api() {
        Ok(commit) => {
            let (committed_fee_action, committed_fee_reason_code) = derive_committed_action_reason(
                commit.previous_canonical_base_fee_per_tx,
                commit.canonical_base_fee_per_tx,
                "fee",
            );
            let (previous_emission_value, current_emission_value, committed_emission_signal_field) =
                if commit.canonical_reward_multiplier_bps.is_some()
                    || commit.previous_canonical_reward_multiplier_bps.is_some()
                {
                    (
                        commit
                            .previous_canonical_reward_multiplier_bps
                            .map(u64::from),
                        commit.canonical_reward_multiplier_bps.map(u64::from),
                        "reward_multiplier_bps",
                    )
                } else {
                    (
                        commit.previous_canonical_reward_effective,
                        commit.canonical_reward_effective,
                        "current_applied_reward_effective",
                    )
                };
            let (committed_emission_action, committed_emission_reason_code) =
                derive_committed_action_reason(
                    previous_emission_value,
                    current_emission_value,
                    "emission",
                );

            EconomyCommittedReadModel {
                scope: "finalized_committed_delta",
                committed_height: Some(commit.finalized_height),
                finalized_height: Some(commit.finalized_height),
                finalized_hash: commit.finalized_hash,
                previous_finalized_height: commit.previous_finalized_height,
                previous_finalized_hash: commit.previous_finalized_hash,
                canonical_base_fee_per_tx: commit.canonical_base_fee_per_tx,
                previous_canonical_base_fee_per_tx: commit.previous_canonical_base_fee_per_tx,
                committed_fee_action,
                committed_fee_reason_code,
                canonical_reward_multiplier_bps: commit.canonical_reward_multiplier_bps,
                previous_canonical_reward_multiplier_bps: commit
                    .previous_canonical_reward_multiplier_bps,
                canonical_reward_effective: commit.canonical_reward_effective,
                previous_canonical_reward_effective: commit.previous_canonical_reward_effective,
                committed_emission_signal_field,
                committed_emission_action,
                committed_emission_reason_code,
                unavailable_reason_codes: commit.unavailable_reason_codes,
            }
        }
        Err(e) => EconomyCommittedReadModel {
            scope: "finalized_committed_delta",
            committed_height: None,
            finalized_height: None,
            finalized_hash: None,
            previous_finalized_height: None,
            previous_finalized_hash: None,
            canonical_base_fee_per_tx: None,
            previous_canonical_base_fee_per_tx: None,
            committed_fee_action: "hold".to_string(),
            committed_fee_reason_code: "canonical_fee_unavailable".to_string(),
            canonical_reward_multiplier_bps: None,
            previous_canonical_reward_multiplier_bps: None,
            canonical_reward_effective: None,
            previous_canonical_reward_effective: None,
            committed_emission_signal_field: "unavailable",
            committed_emission_action: "hold".to_string(),
            committed_emission_reason_code: "canonical_emission_unavailable".to_string(),
            unavailable_reason_codes: vec![format!("finalized_commitment_unavailable:{}", e)],
        },
    }
}

fn build_economy_runtime_projection_read_model(
    bc: &Blockchain,
) -> EconomyDerivedRuntimeProjectionReadModel {
    let pol = &bc.policy;
    EconomyDerivedRuntimeProjectionReadModel {
        scope: "runtime_projection",
        observed_tip_height: bc.height() as u64,
        observed_tip_hash: bc.chain.last().map(|b| b.hash.clone()).unwrap_or_default(),
        reward_floor: pol.reward_floor_base,
        burn_bps: pol.burn_bps,
        next_projected_reward_base_schedule: bc.next_projected_reward_base_schedule_for_api(),
        next_projected_reward_effective: bc.next_projected_reward_effective_for_api(),
        validator_fee_budget_ma30: pol.emission_state.validator_fee_budget_ma30,
        target_validator_budget_day: bc.target_validator_budget_day_for_api(),
        current_budget_state: bc.current_budget_state_for_api().to_string(),
        consecutive_sustainable_days: pol.emission_window.consecutive_sustainable_days,
        hard_cap_day: pol.emission_controller.hard_cap_days,
        taper_days_remaining: bc.taper_days_remaining_for_api(),
        block_fill_ema_ppm: pol.ema.ema_block_fill_ppm,
    }
}

fn signed_fee_delta_vs_observed_tip_for_api(
    prospective_base_fee_per_tx: u64,
    observed_tip_base_fee_per_tx: Option<u64>,
) -> Option<i64> {
    let observed = observed_tip_base_fee_per_tx?;
    let delta = prospective_base_fee_per_tx as i128 - observed as i128;
    if delta > i64::MAX as i128 {
        Some(i64::MAX)
    } else if delta < i64::MIN as i128 {
        Some(i64::MIN)
    } else {
        Some(delta as i64)
    }
}

fn build_economy_local_observation_read_model(bc: &Blockchain) -> EconomyLocalObservationReadModel {
    let pol = &bc.policy;
    let tip_applied = bc.observed_tip_applied_base_fee_for_api();
    let tip_applied_fee = tip_applied.map(|(_, fee)| fee);
    let tip_applied_height = tip_applied.map(|(height, _)| height);
    let prospective_fee = pol.base_fee_per_tx;
    EconomyLocalObservationReadModel {
        scope: "node_local_transient",
        observed_tip_height: bc.height() as u64,
        observed_tip_hash: bc.chain.last().map(|b| b.hash.clone()).unwrap_or_default(),
        prospective_base_fee_per_tx: prospective_fee,
        tip_applied_base_fee_per_tx: tip_applied_fee,
        tip_applied_fee_height: tip_applied_height,
        observed_tip_base_fee_per_tx: tip_applied_fee,
        observed_tip_fee_height: tip_applied_height,
        prospective_fee_delta_vs_observed_tip: signed_fee_delta_vs_observed_tip_for_api(
            prospective_fee,
            tip_applied_fee,
        ),
        finalized_fee_lag_blocks: bc.finalized_fee_lag_blocks_for_api(),
        prospective_emission_phase: format!("{:?}", pol.emission_state.phase),
        prospective_reward_multiplier_bps: pol.emission_state.reward_multiplier_bps,
        regime: pol.current_regime.clone(),
        current_pressure_state: bc.current_pressure_state_for_api().to_string(),
        last_applied_fee_pressure_state: bc.last_applied_fee_pressure_state_for_api().to_string(),
        last_applied_budget_state: bc.last_applied_budget_state_for_api().to_string(),
        last_applied_emission_pressure_state: bc
            .last_applied_emission_pressure_state_for_api()
            .to_string(),
        last_fee_controller_action: bc.fee_action_for_api().to_string(),
        last_fee_controller_reason_code: bc.fee_reason_code_for_api().to_string(),
        controller_fee_action: bc.fee_action_for_api().to_string(),
        controller_fee_reason_code: bc.fee_reason_code_for_api().to_string(),
        last_controller_fee_action: bc.fee_action_for_api().to_string(),
        last_controller_fee_reason_code: bc.fee_reason_code_for_api().to_string(),
        last_controller_fee_decision_height: bc.fee_decision_height_for_api(),
        controller_fee_action_semantics: "last_controller_decision",
        last_fee_controller_apply_height: bc.fee_apply_height_for_api(),
        last_emission_controller_action: bc.emission_action_for_api().to_string(),
        last_emission_controller_reason_code: bc.emission_reason_code_for_api().to_string(),
        last_emission_controller_apply_height: bc.emission_apply_height_for_api(),
        emission_revenue_gap_ppm: pol.emission_state.revenue_gap_ppm,
        emission_under_target_streak: pol.emission_state.under_target_streak,
        emission_over_target_streak: pol.emission_state.over_target_streak,
        emission_near_target_streak: pol.emission_state.near_target_streak,
        emission_budget_deadband_ppm: pol.emission_controller.budget_deadband_ppm,
        emission_budget_streak_required: pol.emission_controller.budget_streak_required,
        mempool_ema: pol.ema.ema_mempool,
        backlog_ratio: pol.backlog_ratio_ppm,
        stability_score_ppm: pol.ema.stability_score_ppm,
        fee_min_base_fee_per_tx: pol.base_fee_min,
        fee_max_base_fee_per_tx: pol.base_fee_max,
        fee_max_multiplier_bps: pol.base_fee_max_multiplier_bps,
        fee_hot_raise_bps: pol.fee_hot_raise_bps,
        fee_critical_raise_bps: pol.fee_critical_raise_bps,
        fee_cold_lower_bps: pol.fee_cold_lower_bps,
        fee_recovery_lower_bps: pol.fee_recovery_lower_bps,
        fee_neutral_revert_active: pol.last_fee_neutral_revert_active,
        fee_neutral_revert_armed: pol.last_fee_neutral_revert_armed,
        fee_neutral_revert_target_base_fee: pol.last_fee_neutral_revert_target_base_fee,
        fee_neutral_revert_lower_bps: pol.fee_neutral_revert_lower_bps,
        fee_neutral_revert_apply_interval_blocks: pol.fee_neutral_revert_apply_interval_blocks,
        fee_neutral_revert_min_streak_blocks: pol.fee_neutral_revert_min_streak_blocks,
        fee_max_raise_per_apply_bps: pol.fee_max_raise_per_apply_bps,
        fee_max_lower_per_apply_bps: pol.fee_max_lower_per_apply_bps,
        fee_base_fee_delta_max_bps: pol.base_fee_delta_max_bps,
        fee_base_fee_shadow: pol.base_fee_shadow,
        fee_raise_delta_requested_ppm: pol.last_fee_raise_delta_requested_ppm,
        fee_raise_delta_capped_ppm: pol.last_fee_raise_delta_capped_ppm,
        fee_raise_delta_realized_ppm: pol.last_fee_raise_delta_realized_ppm,
        fee_raise_delta_applied_ppm: pol.last_fee_raise_delta_applied_ppm,
        fee_lower_delta_requested_ppm: pol.last_fee_lower_delta_requested_ppm,
        fee_lower_delta_capped_ppm: pol.last_fee_lower_delta_capped_ppm,
        fee_lower_delta_realized_ppm: pol.last_fee_lower_delta_realized_ppm,
        fee_lower_delta_applied_ppm: pol.last_fee_lower_delta_applied_ppm,
        fee_apply_interval_blocks: pol.last_fee_apply_interval_blocks,
        fee_cadence_due: pol.last_fee_cadence_due,
        fee_governance_base_fee_override_active: pol.last_fee_governance_base_fee_override_active,
        fee_governance_base_fee_override_value: pol.last_fee_governance_base_fee_override_value,
        fee_governance_base_fee_override_mode: pol
            .last_fee_governance_base_fee_override_mode
            .clone(),
        fee_prospective_lag_cap_bps: pol.last_fee_prospective_lag_cap_bps,
        fee_prospective_lag_reference: pol.last_fee_prospective_lag_reference,
        fee_prospective_lag_reference_height: pol.last_fee_prospective_lag_reference_height,
        fee_prospective_lag_cap_active: pol.last_fee_prospective_lag_cap_active,
        mempool_len_before_block: pol.last_observed_mempool_len_before_block,
        mempool_len_after_block: pol.last_observed_mempool_len_after_block,
        txs_selected_for_block: pol.last_observed_txs_selected_for_block,
        recent_admitted_tx_count: pol.last_observed_recent_admitted_tx_count,
        recent_rejected_fee_low_count: pol.last_observed_recent_rejected_fee_low_count,
        recent_pruned_fee_low_count: pol.last_observed_recent_pruned_fee_low_count,
        recent_ingress_tx_count: pol.last_observed_recent_ingress_tx_count,
        mempool_eligible_len_before_block: pol.last_observed_mempool_eligible_len_before_block,
        mempool_eligible_len_after_block: pol.last_observed_mempool_eligible_len_after_block,
        stale_backlog_streak: pol.last_observed_stale_backlog_streak,
        stale_backlog_hold_active: pol.last_observed_stale_backlog_hold_active,
        incoming_pressure_ratio_ppm: pol.last_observed_incoming_pressure_ratio_ppm,
        fee_empty_recovery_streak_blocks: pol.fee_empty_recovery_streak_blocks,
        fee_recovery_hold_blocks: pol.fee_recovery_hold_blocks,
        fee_empty_recovery_streak: pol.empty_backlog_recovery_streak,
        fee_hot_streak: pol.last_fee_hot_streak,
        fee_critical_streak: pol.last_fee_critical_streak,
        fee_cold_streak: pol.last_fee_cold_streak,
        fee_recovery_streak: pol.last_fee_recovery_streak,
    }
}

fn build_economy_controller_local_read_model(bc: &Blockchain) -> EconomyControllerLocalReadModel {
    let pol = &bc.policy;
    let tip_applied = bc.observed_tip_applied_base_fee_for_api();
    let tip_applied_fee = tip_applied.map(|(_, fee)| fee);
    let tip_applied_height = tip_applied.map(|(height, _)| height);
    let prospective_fee = pol.base_fee_per_tx;
    EconomyControllerLocalReadModel {
        scope: "controller_local_prospective",
        tip_height: bc.height() as u64,
        tip_hash: bc.chain.last().map(|b| b.hash.clone()).unwrap_or_default(),
        controller_decision_height: bc.fee_decision_height_for_api(),
        prospective_base_fee_per_tx: prospective_fee,
        tip_applied_base_fee_per_tx: tip_applied_fee,
        tip_applied_fee_height: tip_applied_height,
        observed_tip_base_fee_per_tx: tip_applied_fee,
        observed_tip_fee_height: tip_applied_height,
        prospective_fee_delta_vs_observed_tip: signed_fee_delta_vs_observed_tip_for_api(
            prospective_fee,
            tip_applied_fee,
        ),
        finalized_fee_lag_blocks: bc.finalized_fee_lag_blocks_for_api(),
        prospective_fee_action: bc.fee_action_for_api().to_string(),
        prospective_fee_reason_code: bc.fee_reason_code_for_api().to_string(),
        controller_fee_action: bc.fee_action_for_api().to_string(),
        controller_fee_reason_code: bc.fee_reason_code_for_api().to_string(),
        last_controller_fee_action: bc.fee_action_for_api().to_string(),
        last_controller_fee_reason_code: bc.fee_reason_code_for_api().to_string(),
        last_controller_fee_decision_height: bc.fee_decision_height_for_api(),
        controller_fee_action_semantics: "last_controller_decision",
        prospective_fee_apply_height: bc.fee_apply_height_for_api(),
        prospective_emission_phase: format!("{:?}", pol.emission_state.phase),
        prospective_reward_multiplier_bps: pol.emission_state.reward_multiplier_bps,
        prospective_emission_action: bc.emission_action_for_api().to_string(),
        prospective_emission_reason_code: bc.emission_reason_code_for_api().to_string(),
        prospective_emission_apply_height: bc.emission_apply_height_for_api(),
        emission_revenue_gap_ppm: pol.emission_state.revenue_gap_ppm,
        emission_under_target_streak: pol.emission_state.under_target_streak,
        emission_over_target_streak: pol.emission_state.over_target_streak,
        emission_near_target_streak: pol.emission_state.near_target_streak,
        emission_budget_deadband_ppm: pol.emission_controller.budget_deadband_ppm,
        emission_budget_streak_required: pol.emission_controller.budget_streak_required,
        regime: pol.current_regime.clone(),
        current_pressure_state: bc.current_pressure_state_for_api().to_string(),
        last_applied_fee_pressure_state: bc.last_applied_fee_pressure_state_for_api().to_string(),
        last_applied_budget_state: bc.last_applied_budget_state_for_api().to_string(),
        last_applied_emission_pressure_state: bc
            .last_applied_emission_pressure_state_for_api()
            .to_string(),
        mempool_ema: pol.ema.ema_mempool,
        backlog_ratio: pol.backlog_ratio_ppm,
        stability_score_ppm: pol.ema.stability_score_ppm,
        fee_min_base_fee_per_tx: pol.base_fee_min,
        fee_max_base_fee_per_tx: pol.base_fee_max,
        fee_max_multiplier_bps: pol.base_fee_max_multiplier_bps,
        fee_hot_raise_bps: pol.fee_hot_raise_bps,
        fee_critical_raise_bps: pol.fee_critical_raise_bps,
        fee_cold_lower_bps: pol.fee_cold_lower_bps,
        fee_recovery_lower_bps: pol.fee_recovery_lower_bps,
        fee_neutral_revert_active: pol.last_fee_neutral_revert_active,
        fee_neutral_revert_armed: pol.last_fee_neutral_revert_armed,
        fee_neutral_revert_target_base_fee: pol.last_fee_neutral_revert_target_base_fee,
        fee_neutral_revert_lower_bps: pol.fee_neutral_revert_lower_bps,
        fee_neutral_revert_apply_interval_blocks: pol.fee_neutral_revert_apply_interval_blocks,
        fee_neutral_revert_min_streak_blocks: pol.fee_neutral_revert_min_streak_blocks,
        fee_max_raise_per_apply_bps: pol.fee_max_raise_per_apply_bps,
        fee_max_lower_per_apply_bps: pol.fee_max_lower_per_apply_bps,
        fee_base_fee_delta_max_bps: pol.base_fee_delta_max_bps,
        fee_base_fee_shadow: pol.base_fee_shadow,
        fee_raise_delta_requested_ppm: pol.last_fee_raise_delta_requested_ppm,
        fee_raise_delta_capped_ppm: pol.last_fee_raise_delta_capped_ppm,
        fee_raise_delta_realized_ppm: pol.last_fee_raise_delta_realized_ppm,
        fee_raise_delta_applied_ppm: pol.last_fee_raise_delta_applied_ppm,
        fee_lower_delta_requested_ppm: pol.last_fee_lower_delta_requested_ppm,
        fee_lower_delta_capped_ppm: pol.last_fee_lower_delta_capped_ppm,
        fee_lower_delta_realized_ppm: pol.last_fee_lower_delta_realized_ppm,
        fee_lower_delta_applied_ppm: pol.last_fee_lower_delta_applied_ppm,
        fee_apply_interval_blocks: pol.last_fee_apply_interval_blocks,
        fee_cadence_due: pol.last_fee_cadence_due,
        fee_governance_base_fee_override_active: pol.last_fee_governance_base_fee_override_active,
        fee_governance_base_fee_override_value: pol.last_fee_governance_base_fee_override_value,
        fee_governance_base_fee_override_mode: pol
            .last_fee_governance_base_fee_override_mode
            .clone(),
        fee_prospective_lag_cap_bps: pol.last_fee_prospective_lag_cap_bps,
        fee_prospective_lag_reference: pol.last_fee_prospective_lag_reference,
        fee_prospective_lag_reference_height: pol.last_fee_prospective_lag_reference_height,
        fee_prospective_lag_cap_active: pol.last_fee_prospective_lag_cap_active,
        mempool_len_before_block: pol.last_observed_mempool_len_before_block,
        mempool_len_after_block: pol.last_observed_mempool_len_after_block,
        txs_selected_for_block: pol.last_observed_txs_selected_for_block,
        recent_admitted_tx_count: pol.last_observed_recent_admitted_tx_count,
        recent_rejected_fee_low_count: pol.last_observed_recent_rejected_fee_low_count,
        recent_pruned_fee_low_count: pol.last_observed_recent_pruned_fee_low_count,
        recent_ingress_tx_count: pol.last_observed_recent_ingress_tx_count,
        mempool_eligible_len_before_block: pol.last_observed_mempool_eligible_len_before_block,
        mempool_eligible_len_after_block: pol.last_observed_mempool_eligible_len_after_block,
        stale_backlog_streak: pol.last_observed_stale_backlog_streak,
        stale_backlog_hold_active: pol.last_observed_stale_backlog_hold_active,
        incoming_pressure_ratio_ppm: pol.last_observed_incoming_pressure_ratio_ppm,
        fee_empty_recovery_streak_blocks: pol.fee_empty_recovery_streak_blocks,
        fee_recovery_hold_blocks: pol.fee_recovery_hold_blocks,
        fee_empty_recovery_streak: pol.empty_backlog_recovery_streak,
        fee_hot_streak: pol.last_fee_hot_streak,
        fee_critical_streak: pol.last_fee_critical_streak,
        fee_cold_streak: pol.last_fee_cold_streak,
        fee_recovery_streak: pol.last_fee_recovery_streak,
    }
}

fn build_treasury_state_read_model(bc: &Blockchain) -> TreasuryStateReadModel {
    let pol = &bc.policy;
    TreasuryStateReadModel {
        meta: build_economy_read_model_meta(bc),
        read_model_contract: build_economy_read_model_contract_metadata(bc),
        canonical_chain_economy: build_economy_canonical_read_model(bc),
        treasury_pct_base_bps: pol.treasury_pct_base_bps,
        treasury_pct_base: pol.treasury_pct_base_bps,
    }
}

fn build_dashboard_economy_read_model(bc: &Blockchain) -> DashboardEconomyReadModel {
    DashboardEconomyReadModel {
        meta: build_economy_read_model_meta(bc),
        read_model_contract: build_economy_read_model_contract_metadata(bc),
        committed: build_economy_committed_read_model(bc),
        controller_local: build_economy_controller_local_read_model(bc),
        canonical_chain_economy: build_economy_canonical_read_model(bc),
        derived_runtime_projection: build_economy_runtime_projection_read_model(bc),
        local_node_observation: build_economy_local_observation_read_model(bc),
        rewards_last_20: serde_json::Value::Null,
    }
}

fn build_economy_controller_contract_read_model() -> EconomyControllerContractReadModel {
    EconomyControllerContractReadModel {
        status: "ok",
        controller_contract_version: crate::blockchain::EconomicControllerAction::contract_version(
        ),
        fee_action_values: crate::blockchain::EconomicControllerAction::all_values().to_vec(),
        emission_action_values: crate::blockchain::EconomicControllerAction::all_values().to_vec(),
        reason_code_values: crate::blockchain::EconomicControllerReasonCode::all_values().to_vec(),
    }
}

pub async fn serve_api(
    chain: SharedChain,
    mempool: SharedMempool,
    tx_p2p: UnboundedSender<NetMsg>,
    api_port: u16,
    storage: Arc<DbStore>,
    public_mode: bool,
    follower_mode: bool,
) {
    use crate::keystore::{self, KeyRole};

    let (validator_sk, validator_pk_b64) = if follower_mode {
        eprintln!("ℹ️ [API BOOT] follower_mode attivo: endpoint con firma locale disabilitati.");
        let sk_arr = [0u8; 32];
        let validator_sk = Arc::new(SigningKey::from_bytes(&sk_arr));
        let validator_pk_b64 = STANDARD.encode(validator_sk.verifying_key().to_bytes());
        (validator_sk, validator_pk_b64)
    } else {
        let ks_path = keystore::keystore_path();
        let sk_bytes = keystore::load_secret_bytes(KeyRole::ValidatorSigning, public_mode)
            .unwrap_or_else(|e| {
                eprintln!(
                    "❌ [API BOOT] validator_signing mancante (keystore: {}). Err={:?}",
                    ks_path.display(),
                    e
                );
                std::process::exit(2);
            });

        if sk_bytes.len() != 32 {
            eprintln!(
                "❌ [API BOOT] validator_signing deve essere 32 bytes, trovato={}",
                sk_bytes.len()
            );
            std::process::exit(2);
        }

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes[..32]);
        let validator_sk = Arc::new(SigningKey::from_bytes(&sk_arr));
        let validator_pk_b64 = STANDARD.encode(validator_sk.verifying_key().to_bytes());
        (validator_sk, validator_pk_b64)
    };

    let admin = Arc::new(load_admin_config(public_mode));
    let admin_enabled: bool = admin_routes_enabled_v1(admin.as_ref());
    if public_mode && env_flag_true_v1("NEWGEN_ENABLE_LOCAL_TX_SIGNER") {
        eprintln!(
            "⚠️ [API BOOT] NEWGEN_ENABLE_LOCAL_TX_SIGNER=1 ignored for public-mode HTTP surface; node-local signing routes are not mounted"
        );
    }

    // One-time startup warning if legacy network_id compatibility is enabled
    if allow_legacy_network_id() {
        eprintln!(
            "[WARN] Legacy network_id compatibility ENABLED (dev/test only). canonical_network_id='{}'",
            crate::chain_identity::network_id()
        );
    }

    // ------- DEV ONLY: Wallet generators (mai in release) -------
    #[cfg(debug_assertions)]
    let wallet_new = warp::path!("api" / "wallet" / "new")
        .and(warp::get())
        .map(|| {
            let (address, private_key) = crate::wallet::generate_wallet();
            warp::reply::json(&serde_json::json!({
                "address": address,
                "private_key": private_key
            }))
        });

    #[cfg(debug_assertions)]
    let wallet_new_b64 = warp::path!("api" / "v2" / "wallet" / "new_b64")
        .and(warp::post())
        .map(|| {
            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            let sk_b64 = STANDARD.encode(sk.to_bytes());
            let pk_b64 = STANDARD.encode(pk.to_bytes());
            warp::reply::json(&serde_json::json!({
                "public_key_b64": pk_b64,
                "private_key_b64": sk_b64
            }))
        });

    // ------- Wallet history (UI) -------
    // NOTE: endpoint potenzialmente costoso se abusato. Per test pubblici:
    // - bounded blocks scan
    // - bounded tx output
    // - support paginazione tramite query
    //   ?from_height=...&blocks=...&max_txs=...
    let wallet_history = warp::path!("api" / "tx" / "history" / String)
        .and(warp::get())
        .and(warp::query::<TxHistoryQuery>())
        .and(with_chain(chain.clone()))
        .and_then(wallet_history_handler);

    // ------- Wallet secure new (certificato firmato dal nodo) -------
    // (Questo blocco è corretto)
    let wallet_secure_new = {
        warp::path!("api" / "wallet_secure" / "new" / String)
            .and(warp::get())
            .and(admin_guard(admin.clone()))
            .and_then(move |password: String, _guard: ()| async move {
                use crate::wallet_secure::SecureWallet;

                // Mainnet/public: OFF anche con admin token
                if public_mode {
                    return Err(warp::reject::custom(ApiError::Forbidden));
                }

                // Crea wallet key e cifra
                let sk = SigningKey::generate(&mut OsRng);
                let sk_bytes = sk.to_bytes();
                let wallet = SecureWallet::encrypt(&sk_bytes, &password).map_err(|_| {
                    warp::reject::custom(ApiError::Internal("wallet_encrypt_failed"))
                })?;

                // Carica Wallet CA dal keystore (non master_keys.json)
                let ca_bytes = keystore::load_secret_bytes(KeyRole::WalletCA, false)
                    .map_err(|_| warp::reject::custom(ApiError::MasterKeyError))?;
                let ca_arr: &[u8; 32] = ca_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| warp::reject::custom(ApiError::MasterKeyError))?;
                let ca_key = SigningKey::from_bytes(ca_arr);

                // Firma con domain separation + versioning
                let wallet_pub_bytes = STANDARD
                    .decode(&wallet.public_key)
                    .map_err(|_| warp::reject::custom(ApiError::MasterKeyError))?;
                let mut message = b"WALLET_CERT_v1|".to_vec();
                message.extend_from_slice(&wallet_pub_bytes);

                let signature = ca_key.sign(&message);
                let cert_b64 = STANDARD.encode(signature.to_bytes());

                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "certificate": cert_b64,
                        "address": wallet.address,
                        "public_key": wallet.public_key,
                        "balance": wallet.balance,
                        "created_at": wallet.created_at,
                        "reputation": wallet.reputation
                    })),
                    warp::http::StatusCode::OK,
                ))
            })
    };

    // ------- Wallet secure new v2 (password nel body, no URL leakage) -------
    let wallet_secure_new_v2 = {
        warp::path!("api" / "v2" / "wallet_secure" / "new")
            .and(warp::post())
            .and(admin_guard(admin.clone()))
            .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
            .and(warp::body::json())
            .and_then(move |_guard: (), req: WalletSecureNewBody| async move {
                use crate::wallet_secure::SecureWallet;

                // Mainnet/public: OFF anche con admin token
                if public_mode {
                    return Err(warp::reject::custom(ApiError::Forbidden));
                }

                let password = req.password;

                if password.len() > 128 {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_data",
                            "message": "password_too_long"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let sk = SigningKey::generate(&mut OsRng);
                let sk_bytes = sk.to_bytes();
                let wallet = SecureWallet::encrypt(&sk_bytes, &password).map_err(|_| {
                    warp::reject::custom(ApiError::Internal("wallet_encrypt_failed"))
                })?;

                // Wallet CA dal keystore
                let ca_bytes = keystore::load_secret_bytes(KeyRole::WalletCA, false)
                    .map_err(|_| warp::reject::custom(ApiError::MasterKeyError))?;
                let ca_arr: &[u8; 32] = ca_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| warp::reject::custom(ApiError::MasterKeyError))?;
                let ca_key = SigningKey::from_bytes(ca_arr);

                // Firma con lo stesso formato della v1 (consistenza professionale)
                let wallet_pk_bytes = STANDARD
                    .decode(&wallet.public_key)
                    .map_err(|_| warp::reject::custom(ApiError::InvalidData))?;

                let mut message = b"WALLET_CERT_v1|".to_vec();
                message.extend_from_slice(&wallet_pk_bytes);

                let signature = ca_key.sign(&message);
                let cert_b64 = STANDARD.encode(signature.to_bytes());

                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "certificate": cert_b64,
                        "address": wallet.address,
                        "public_key": wallet.public_key,
                        "balance": wallet.balance,
                        "created_at": wallet.created_at,
                        "reputation": wallet.reputation
                    })),
                    warp::http::StatusCode::OK,
                ))
            })
    };

    // ------- Ultimo blocco (UI) -------
    let blockchain_last = warp::path!("api" / "blockchain" / "last")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let bc = lock_any!(ch);
            if let Some(last) = bc.chain.last() {
                warp::reply::json(&serde_json::json!({
                    "index": last.index,
                    "timestamp": last.timestamp,
                    "hash": last.hash,
                    "tx_count": last.transactions.len(),
                    "miner_pub_key": last.miner_pub_key
                }))
            } else {
                warp::reply::json(&serde_json::json!({"status":"empty_chain"}))
            }
        });

    // ------- Ultimo blocco FULL (audit/UI) -------
    // Include transactions + memo (DB-backed: chain in memoria caricata dal backend storage)
    let blockchain_last_full = warp::path!("api" / "blockchain" / "last_full")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let blk = {
                let bc = lock_any!(ch);
                bc.chain.last().cloned()
            };
            if let Some(b) = blk {
                warp::reply::json(&b)
            } else {
                warp::reply::json(&serde_json::json!({"status":"error","message":"empty_chain"}))
            }
        });

    // ------- Mempool list (UI) -------
    let mempool_route = warp::path!("api" / "mempool")
        .and(warp::get())
        .and(warp::query::<MempoolListQueryV1>())
        .and(with_mempool(mempool.clone()))
        .map(|q: MempoolListQueryV1, mp: Arc<Mutex<Mempool>>| {
            let limit = mempool_list_limit_v1(q.limit);
            let list = lock_any!(mp).get_limited(limit);
            warp::reply::json(&list)
        });

    // ------- Mempool limits (Step 49) -------
    let mempool_limits = warp::path!("api" / "v2" / "mempool" / "limits")
        .and(warp::get())
        .and(with_mempool(mempool.clone()))
        .map(|mp: Arc<Mutex<Mempool>>| {
            let mp = lock_any!(mp);
            let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) = mp.limits_snapshot();

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "limits": {
                    "max_mempool_size": max_size as u64,
                    "max_tx_per_sender": max_tx_per_sender as u64,
                    "max_mempool_bytes": max_bytes as u64,
                    "tx_ttl_secs": tx_ttl_secs
                }
            }))
        });

    // ------- Mempool stats (Step 49) -------
    let mempool_stats = warp::path!("api" / "v2" / "mempool" / "stats")
        .and(warp::get())
        .and(with_mempool(mempool.clone()))
        .map(|mp: Arc<Mutex<Mempool>>| {
            let mp = lock_any!(mp);
            let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) = mp.limits_snapshot();
            let drop_counters = mp.drop_counters_snapshot();
            let drop_total = drop_counters.drop_total();

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "size": mp.len() as u64,
                "total_bytes": mp.total_bytes() as u64,
                "drop_counters": drop_counters,
                "drop_total": drop_total,
                "limits": {
                    "max_mempool_size": max_size as u64,
                    "max_tx_per_sender": max_tx_per_sender as u64,
                    "max_mempool_bytes": max_bytes as u64,
                    "tx_ttl_secs": tx_ttl_secs
                }
            }))
        });

    // ------- Blocks pagination (v2, bounded) -------
    let blocks_v2 = warp::path!("api" / "v2" / "blocks")
        .and(warp::get())
        .and(warp::query::<BlocksQuery>())
        .and(with_chain(chain.clone()))
        .map(|q: BlocksQuery, ch: SharedChain| {
            let limit: usize = q
                .limit
                .unwrap_or(BLOCKS_V2_DEFAULT_LIMIT)
                .clamp(1, BLOCKS_V2_MAX_LIMIT);

            let order: &str = match q.order.as_deref() {
                Some("asc") => "asc",
                _ => "desc",
            };

            let bc = lock_any!(ch);
            if bc.chain.is_empty() {
                let page = BlocksPageV2 {
                    status: "empty_chain".to_string(),
                    tip_height: 0,
                    from_height: 0,
                    returned: 0,
                    next_from_height: None,
                    order: order.to_string(),
                    blocks: vec![],
                };
                return warp::reply::json(&page);
            }
            let tip_height = bc.chain.last().map(|b| b.index).unwrap_or(0);

            let from = match q.from_height {
                Some(h) => h.min(tip_height),
                None if order == "asc" => 0,
                None => tip_height,
            };

            let mut out: Vec<BlockSummaryV2> = Vec::with_capacity(limit);
            let mut next_from: Option<u64> = None;

            if order == "asc" {
                let end_excl =
                    (from.saturating_add(limit as u64)).min(tip_height.saturating_add(1));
                for h in from..end_excl {
                    if let Some(b) = bc.block_at_height(h) {
                        out.push(BlockSummaryV2 {
                            index: b.index,
                            timestamp: b.timestamp,
                            hash: b.hash.clone(),
                            previous_hash: b.previous_hash.clone(),
                            miner_pub_key: b.miner_pub_key.clone(),
                            tx_count: b.transactions.len(),
                        });
                    }
                }
                if end_excl <= tip_height {
                    next_from = Some(end_excl);
                }
            } else {
                // default: desc
                let mut h = from;
                for _ in 0..limit {
                    if let Some(b) = bc.block_at_height(h) {
                        out.push(BlockSummaryV2 {
                            index: b.index,
                            timestamp: b.timestamp,
                            hash: b.hash.clone(),
                            previous_hash: b.previous_hash.clone(),
                            miner_pub_key: b.miner_pub_key.clone(),
                            tx_count: b.transactions.len(),
                        });
                    } else {
                        break;
                    }

                    if h == 0 {
                        break;
                    }
                    h -= 1;
                }

                if let Some(last) = out.last() {
                    if last.index > 0 {
                        next_from = Some(last.index - 1);
                    }
                }
            }

            let page = BlocksPageV2 {
                status: "ok".to_string(),
                tip_height,
                from_height: from,
                returned: out.len(),
                next_from_height: next_from,
                order: order.to_string(),
                blocks: out,
            };

            warp::reply::json(&page)
        });

    // ------- Block by height (v2, storage-backed / prune-safe) -------
    let block_by_height_v2 = warp::path!("api" / "v2" / "block" / u64)
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|height: u64, ch: SharedChain| {
            let (lookup_res, base_height, tip_height, pruned_height) = {
                let bc = lock_any!(ch);
                (
                    bc.api_block_by_height_v2(height),
                    bc.base_height(),
                    bc.tip_height_u64(),
                    bc.is_pruned_height(height),
                )
            };

            match lookup_res {
                Ok(Some(b)) => {
                    let body = serde_json::json!({
                        "status": "ok",
                        "block": {
                            "index": b.index,
                            "timestamp": b.timestamp,
                            "hash": b.hash,
                            "previous_hash": b.previous_hash,
                            "miner_pub_key": b.miner_pub_key,
                            "tx_root": b.tx_root,
                            "state_root": b.state_root,
                            "tx_count": b.transactions.len(),
                            "transactions": b.transactions.iter().enumerate().map(|(i, tx)| {
                                serde_json::json!({
                                    "hash": tx.hash,
                                    "sender": tx.sender,
                                    "receiver": tx.receiver,
                                    "amount": tx.amount,
                                    "max_fee_per_tx": tx.max_fee_per_tx,
                                    "nonce": tx.nonce,
                                    "is_coinbase": tx.is_coinbase,
                                    "memo": tx.memo,
                                    "ft": ft_receipt_json_or_error(tx),
                                    "nft": nft_first_event_for_tx_from_block_v1(&b, &tx.hash, i),
                                    "nft_events": nft_event_values_for_tx_from_block_v1(&b, &tx.hash, i),
                                })
                            }).collect::<Vec<_>>(),
                            "nft_events": b.nft_events.clone()
                        }
                    });
                    warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&body),
                            warp::http::StatusCode::OK,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                }
                Ok(None) if pruned_height => {
                    let body = serde_json::json!({
                        "status": "pruned",
                        "message": "block_pruned_below_local_base_height",
                        "height": height,
                        "base_height": base_height,
                        "tip_height": tip_height
                    });
                    warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&body),
                            warp::http::StatusCode::GONE,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                }
                Ok(None) => {
                    let body = serde_json::json!({
                        "status": "not_found",
                        "message": "block_not_found",
                        "height": height,
                        "base_height": base_height,
                        "tip_height": tip_height
                    });
                    warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&body),
                            warp::http::StatusCode::NOT_FOUND,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                }
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": e,
                        "height": height,
                        "base_height": base_height,
                        "tip_height": tip_height
                    });
                    warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&body),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                }
            }
        });

    // ------- Blockchain full (UI) -------
    // Legacy endpoint: prima dumpava (quasi) tutta la chain, ed era un DoS triviale via lock contention.
    // Manteniamo il path per backward-compat, ma ora è un export BOUNDED e paginabile (admin-only).
    // Default: include_txs=true, limit più basso.
    let blockchain_all = warp::path!("api" / "blockchain" / "all")
        .and(warp::get())
        .and(admin_guard(admin.clone()))
        .and(warp::query::<ChainExportQuery>())
        .and(with_chain(chain.clone()))
        .and_then(
            |guard: (), q: ChainExportQuery, ch: SharedChain| async move {
                blockchain_export_handler(true, guard, q, ch).await
            },
        );

    // ------- Mine manuale (UI) -------
    // Versione v2: delega a mine_handler (safe, no panic su chain vuota)
    let mine_block = warp::path!("api" / "mine")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and_then(|_: (), chain, mempool, tx_p2p| mine_handler(chain, mempool, tx_p2p));

    // ------- Blockchain info (UI + mainnet-grade + Step8 compat) -------
    // Invarianti:
    // - campi canonici per tooling: best_height + tip_hash (Step8/monitor)
    // - alias legacy: last_block_hash
    // - no-cache: Cache-Control: no-store
    let blockchain_info = warp::path!("api" / "blockchain" / "info")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let body = {
                let bc = lock_any!(ch);
                build_blockchain_info_read_model(&bc)
            };
            let json = warp::reply::json(&body);
            warp::reply::with_header(json, "Cache-Control", "no-store")
        });

    // ------- Blockchain info (compat) -------
    // Alias per compatibilita con gli script/monitor che chiamano /api/v2/blockchain/info.
    // Payload identico a /api/blockchain/info per evitare drift (mainnet hygiene).
    let blockchain_info_v2 = warp::path!("api" / "v2" / "blockchain" / "info")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let bc = lock_any!(ch);
            let body = build_blockchain_info_read_model(&bc);
            let json = warp::reply::json(&body);
            warp::reply::with_header(json, "Cache-Control", "no-store")
        });

    // ------- Blockchain export snapshot (debug/UI) -------
    // Sostituisce la clonazione massiva di tutta la chain sotto lock.
    // Export bounded e paginabile (admin-only):
    //   /api/blockchain/full?from_height=TIP&limit=100&include_txs=false
    let blockchain_full = warp::path!("api" / "blockchain" / "full")
        .and(warp::get())
        .and(admin_guard(admin.clone()))
        .and(warp::query::<ChainExportQuery>())
        .and(with_chain(chain.clone()))
        .and_then(
            |guard: (), q: ChainExportQuery, ch: SharedChain| async move {
                blockchain_export_handler(false, guard, q, ch).await
            },
        );

    // ------- Treasury state (Step 35 - read only) -------
    let treasury_state = warp::path!("api" / "v2" / "treasury" / "state")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let body = {
                let bc = lock_any!(ch);
                build_treasury_state_read_model(&bc)
            };
            warp::reply::json(&body)
        });

    let economy_controller_contract = warp::path!("api" / "v2" / "economy" / "controller_contract")
        .and(warp::get())
        .map(|| warp::reply::json(&build_economy_controller_contract_read_model()));

    // ------- Economy dashboard (compat) -------
    // Alias per UI/monitor legacy che chiamano /api/v2/dashboard/economy.
    // Questo endpoint DEVE rimanere leggero: nessuna scansione lunga della chain, solo snapshot di policy/state.
    let economy_dashboard = warp::path!("api" / "v2" / "dashboard" / "economy")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let body = {
                let bc = lock_any!(ch);
                build_dashboard_economy_read_model(&bc)
            };
            warp::reply::json(&body)
        });

    // Serie economiche reali: telemetria downsampled per dashboard e audit runtime.
    let economy_series = warp::path!("api" / "v2" / "dashboard" / "economy_series")
        .and(warp::get())
        .and(warp::query::<EconomySeriesQuery>())
        .and(with_chain(chain.clone()))
        .map(|q: EconomySeriesQuery, ch: SharedChain| {
            let window_secs = q
                .window_secs
                .unwrap_or(24 * 60 * 60)
                .clamp(60, 30 * 24 * 60 * 60);
            let max_points = q.max_points.unwrap_or(512).clamp(1, 4096);
            let series = {
                let bc = lock_any!(ch);
                bc.economy_series(window_secs, max_points)
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "window_secs": window_secs,
                "max_points": max_points,
                "series": series
            }))
        });

    // ------- Security & Reputation metrics (Step 50A) -------
    let security_metrics = warp::path!("api" / "v2" / "security" / "metrics")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_sec_metrics".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/security/metrics"
            );

            let (security_rt, metrics_snapshot, rep_opt) = {
                let bc = lock_any!(ch);
                (
                    bc.security_runtime.clone(),
                    bc.snapshot_security_metrics(),
                    bc.reputation.clone(),
                )
            };

            let (event_counters, rep_verbose) = if let Some(arc) = rep_opt {
                let rep_manager = arc.lock().unwrap_or_else(|e| e.into_inner());
                let sec = rep_manager.snapshot_security_metrics();
                let verbose = rep_manager.snapshot();
                (sec, verbose)
            } else {
                (
                    crate::peer_reputation::SecurityMetrics {
                        total_peers: 0,
                        good: 0,
                        probation: 0,
                        banned: 0,
                        avg_score: 0.0,
                        events_invalid_block: 0,
                        events_spam: 0,
                        events_disconnect: 0,
                        events_slashed: 0,
                        total_ban_events: 0,
                        total_unban_events: 0,
                        wallet_bound_peers: 0,
                        wallet_subjects: 0,
                        pending_wallet_evidence: 0,
                    },
                    Vec::new(),
                )
            };

            let metrics = serde_json::json!({
                "min_fee_per_tx": security_rt.min_fee_per_tx,
                "min_fee_per_byte": security_rt.min_fee_per_byte,
                "max_block_size": security_rt.max_block_size,
                "peers_total": metrics_snapshot.peers_total,
                "good": metrics_snapshot.good,
                "probation": metrics_snapshot.probation,
                "banned": metrics_snapshot.banned,
                "ascore_avg": (metrics_snapshot.ascore_avg_x10 as f64) / 10.0,
                "slashing_events": metrics_snapshot.slashing_events,
                "events_invalid_block": event_counters.events_invalid_block,
                "events_spam": event_counters.events_spam,
                "events_disconnect": event_counters.events_disconnect,
                "events_slashed": event_counters.events_slashed,
                "total_ban_events": event_counters.total_ban_events,
                "total_unban_events": event_counters.total_unban_events,
                "wallet_bound_peers": event_counters.wallet_bound_peers,
                "wallet_subjects": event_counters.wallet_subjects,
                "pending_wallet_evidence": event_counters.pending_wallet_evidence,
                "reputation_snapshot_size": rep_verbose.len()
            });

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "metrics": metrics
            }))
        });

    let security_reputation = warp::path!("api" / "v2" / "security" / "reputation")
        .and(warp::get())
        .and(warp::query::<SecurityReputationQuery>())
        .and(with_chain(chain.clone()))
        .map(|q: SecurityReputationQuery, ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_sec_reputation".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/security/reputation"
            );
            let limit = q
                .limit
                .unwrap_or(SECURITY_REPUTATION_DEFAULT_LIMIT)
                .clamp(1, SECURITY_REPUTATION_MAX_LIMIT);
            let rep_opt = { lock_any!(ch).reputation.clone() };
            if let Some(arc) = rep_opt {
                let rep_manager = arc.lock().unwrap_or_else(|e| e.into_inner());
                let summary = rep_manager.summary();
                let metrics = rep_manager.snapshot_security_metrics();
                let (total_peers_available, peers) = rep_manager.snapshot_limited(limit);
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "summary": summary,
                    "metrics": metrics,
                    "limit": limit,
                    "total_peers_available": total_peers_available,
                    "truncated": total_peers_available > peers.len(),
                    "peers": peers,
                }))
            } else {
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "summary": {"total_peers":0,"good":0,"probation":0,"banned":0,"avg_score":0.0},
                    "metrics": {"total_peers":0,"good":0,"probation":0,"banned":0,"avg_score":0.0,
                                "events_invalid_block":0,"events_spam":0,"events_disconnect":0,
                                "events_slashed":0,"total_ban_events":0,"total_unban_events":0,
                                "wallet_bound_peers":0,"wallet_subjects":0,"pending_wallet_evidence":0},
                    "limit": limit,
                    "total_peers_available": 0,
                    "truncated": false,
                    "peers": []
                }))
            }
        });

    let perf_metrics_v2 = warp::path!("api" / "v2" / "perf" / "metrics")
        .and(warp::get())
        .map(|| {
            let perf = crate::perf_metrics::snapshot();
            warp::reply::with_header(
                warp::reply::json(&serde_json::json!({"status": "ok", "metrics": perf})),
                "Cache-Control",
                "no-store",
            )
        });

    let reputation_run = warp::path!("api" / "v2" / "reputation" / "run")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_rep_run".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/reputation/run"
            );
            let bc = lock_any!(ch);
            let (summary, wallets, pending_evidence) = bc.run_wallet_reputation_snapshot();
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "summary": summary,
                "wallets": wallets,
                "pending_evidence": pending_evidence,
            }))
        });

    let reputation_wallet = warp::path!("api" / "v2" / "reputation" / "wallet")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_rep_wallet".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/reputation/wallet"
            );
            let bc = lock_any!(ch);
            let wallets = bc.governance_wallet_reputation_snapshot();
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "wallets": wallets,
            }))
        });

    let reputation_canonical_nodes =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "nodes")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_canonical_nodes".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/nodes"
                );
                let bc = lock_any!(ch);
                let source_height = bc.finalized_height();
                let finalized_height = bc.finalized_height();
                let nodes = bc.canonical_node_reputation_surface_finalized_snapshot_v1();
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "canonical_node_reputation_surface_v1",
                    "source_height": source_height,
                    "finalized_height": finalized_height,
                    "source_commitment": "finalized",
                    "nodes": nodes,
                }))
            });

    let reputation_canonical_wallets =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "wallets")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_canonical_wallets".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/wallets"
                );
                let bc = lock_any!(ch);
                let source_height = bc.finalized_height();
                let finalized_height = bc.finalized_height();
                let wallets = bc.canonical_wallet_reputation_surface_finalized_snapshot_v1();
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "canonical_wallet_reputation_surface_v1",
                    "source_height": source_height,
                    "finalized_height": finalized_height,
                    "source_commitment": "finalized",
                    "wallets": wallets,
                }))
            });

    let reputation_canonical_eligibility =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "eligibility" / String)
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|subject: String, ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_canonical_eligibility".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/eligibility/:subject"
                );
                let normalized = crate::keyfmt::pk_hex_from_any(&subject)
                    .unwrap_or_else(|_| subject.trim().to_string());
                let bc = lock_any!(ch);
                let source_height = bc.finalized_height();
                let finalized_height = bc.finalized_height();
                let nodes = bc.canonical_node_reputation_surface_finalized_snapshot_v1();
                if let Some(node) = nodes.into_iter().find(|n| n.node_pubkey == normalized) {
                    return warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "found": true,
                        "subject_type": "node",
                        "subject": normalized,
                        "source_height": source_height,
                        "finalized_height": finalized_height,
                        "eligibility_state": node.eligibility_state.clone(),
                        "deny_reason": node.deny_reason.clone(),
                        "max_risk_class": node.max_risk_class.clone(),
                        "effective_score": node.effective_score,
                        "surface": node,
                    }));
                }
                let wallets = bc.canonical_wallet_reputation_surface_finalized_snapshot_v1();
                if let Some(wallet) = wallets.into_iter().find(|w| w.wallet_pubkey == normalized) {
                    return warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "found": true,
                        "subject_type": "wallet",
                        "subject": normalized,
                        "source_height": source_height,
                        "finalized_height": finalized_height,
                        "eligibility_state": wallet.eligibility_state.clone(),
                        "deny_reason": wallet.deny_reason.clone(),
                        "max_risk_class": wallet.max_risk_class.clone(),
                        "effective_score": wallet.effective_score,
                        "surface": wallet,
                    }));
                }
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "found": false,
                    "subject": normalized,
                    "source_height": source_height,
                    "finalized_height": finalized_height,
                    "error": "reputation_subject_not_found"
                }))
            });

    let reputation_canonical_workers = warp::path!(
        "api" / "v2" / "reputation" / "canonical" / "workers"
    )
    .and(warp::get())
    .and(with_chain(chain.clone()))
    .map(|ch: SharedChain| {
        ng_trace_throttle!(
            key: "api_rep_canonical_workers".to_string(),
            every_ms: 30000,
            target: "api.req",
            "GET /api/v2/reputation/canonical/workers"
        );
        let bc = lock_any!(ch);
        let (finalized_height, finalized_hash) = bc.finalized_view();
        let workers = bc.canonical_worker_eligibility_finalized_snapshot_v1();
        let workers_compat: Vec<serde_json::Value> = workers
            .iter()
            .map(canonical_worker_eligibility_compat_aliases_v1)
            .collect();
        let worker_onboarding: Vec<serde_json::Value> = workers
            .iter()
            .map(canonical_worker_eligibility_onboarding_guidance_v1)
            .collect();
        let registry = bc.canonical_e2_worker_registry_finalized_snapshot_v1();
        warp::reply::json(&serde_json::json!({
            "status": "ok",
            "surface": crate::reputation_score::WORKER_ELIGIBILITY_SURFACE_VERSION_V1,
            "registry_surface": crate::governance::E2WorkerOperatorBindingRecordV1::FORMAT_VERSION,
            "source_height": finalized_height,
            "sourceHeight": finalized_height,
            "finalized_height": finalized_height,
            "finalizedHeight": finalized_height,
            "finalized_hash": finalized_hash,
            "finalizedHash": finalized_hash,
            "source_commitment": "finalized",
            "sourceCommitment": "finalized",
            "registry": registry,
            "workers": workers,
            "workers_compat": workers_compat.clone(),
            "workersCompat": workers_compat,
            "worker_onboarding": worker_onboarding.clone(),
            "workerOnboarding": worker_onboarding,
            "field_naming": {
                "canonical": "snake_case",
                "compatibility_aliases": "camelCase",
                "canonical_semantics": "Both naming forms describe the same finalized L1 state."
            },
            "fieldNaming": {
                "canonical": "snake_case",
                "compatibilityAliases": "camelCase",
                "canonicalSemantics": "Both naming forms describe the same finalized L1 state."
            }
        }))
    });

    let reputation_canonical_worker_privileges =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "workers" / "privileges")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_canonical_worker_privileges".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/workers/privileges"
                );
                let bc = lock_any!(ch);
                let rows = bc.e2_worker_governed_privileges_finalized_snapshot_v1();
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "e2-worker-governed-privileges-v1",
                    "source_commitment": "finalized",
                    "finalized_height": bc.finalized_height(),
                    "workers": rows,
                }))
                .into_response()
            });

    let reputation_canonical_worker_eligibility =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "workers" / String / "eligibility")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|worker_pubkey: String, ch: SharedChain| {
                ng_trace_throttle!(
                    key: format!("api_rep_canonical_worker_eligibility:{}", worker_pubkey),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/workers/{}/eligibility",
                    worker_pubkey
                );
                let bc = lock_any!(ch);
                let (finalized_height, finalized_hash) = bc.finalized_view();
                match bc.canonical_worker_eligibility_finalized_for_worker_v1(&worker_pubkey) {
                    Some(worker) => {
                        let admission_status = if worker.eligible_for_non_probe {
                            "non_probe_allowed"
                        } else if worker.eligible_for_probe {
                            "probe_only"
                        } else {
                            "denied"
                        };
                        let onboarding = canonical_worker_eligibility_onboarding_guidance_v1(&worker);
                        let onboarding_stage = onboarding
                            .get("stage")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN_TO_CHAIN")
                            .to_string();
                        let onboarding_reason = onboarding
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("worker_not_currently_admitted")
                            .to_string();
                        let next_action = onboarding
                            .get("next_action")
                            .and_then(|v| v.as_str())
                            .unwrap_or("submit_worker_registration_or_wait_projection")
                            .to_string();
                        let worker_compat = canonical_worker_eligibility_compat_aliases_v1(&worker);
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": if worker.chain_known { "ok" } else { "not_found" },
                                "admission_status": admission_status,
                                "admissionStatus": admission_status,
                                "onboarding_stage": onboarding_stage.clone(),
                                "onboardingStage": onboarding_stage,
                                "onboarding_reason": onboarding_reason.clone(),
                                "onboardingReason": onboarding_reason,
                                "next_action": next_action.clone(),
                                "nextAction": next_action,
                                "surface": crate::reputation_score::WORKER_ELIGIBILITY_SURFACE_VERSION_V1,
                                "source_height": finalized_height,
                                "sourceHeight": finalized_height,
                                "finalized_height": finalized_height,
                                "finalizedHeight": finalized_height,
                                "finalized_hash": finalized_hash,
                                "finalizedHash": finalized_hash,
                                "source_commitment": "finalized",
                                "sourceCommitment": "finalized",
                                "worker": worker,
                                "worker_compat": worker_compat.clone(),
                                "workerCompat": worker_compat,
                                "onboarding": onboarding,
                                "field_naming": {
                                    "canonical": "snake_case",
                                    "compatibility_aliases": "camelCase",
                                    "canonical_semantics": "Both naming forms describe the same finalized L1 state."
                                },
                                "fieldNaming": {
                                    "canonical": "snake_case",
                                    "compatibilityAliases": "camelCase",
                                    "canonicalSemantics": "Both naming forms describe the same finalized L1 state."
                                }
                            })),
                            warp::http::StatusCode::OK,
                        )
                    },
                    None => warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "not_found",
                            "surface": crate::reputation_score::WORKER_ELIGIBILITY_SURFACE_VERSION_V1,
                            "source_height": finalized_height,
                            "finalized_height": finalized_height,
                            "finalized_hash": finalized_hash,
                            "source_commitment": "finalized",
                            "message": "worker_eligibility_surface_not_found_finalized",
                        })),
                        warp::http::StatusCode::NOT_FOUND,
                    ),
                }
            });

    let reputation_canonical_worker_privilege_debug =
        warp::path!("api" / "v2" / "reputation" / "canonical" / "workers" / String / "privilege-debug")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|worker_pubkey: String, ch: SharedChain| {
                ng_trace_throttle!(
                    key: format!("api_rep_canonical_worker_privilege_debug:{}", worker_pubkey),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/canonical/workers/{}/privilege-debug",
                    worker_pubkey
                );
                let bc = lock_any!(ch);
                let (finalized_height, finalized_hash) = bc.finalized_view();
                let worker_hex = crate::keyfmt::pk_hex_from_any(&worker_pubkey)
                    .unwrap_or_else(|_| worker_pubkey.trim().to_ascii_lowercase());
                let worker = bc.canonical_worker_eligibility_finalized_for_worker_v1(&worker_pubkey);
                let privilege_record = bc
                    .e2_worker_governed_privileges_finalized_snapshot_v1()
                    .into_iter()
                    .find(|r| {
                        crate::keyfmt::pk_hex_from_any(&r.worker_node_pubkey)
                            .unwrap_or_else(|_| r.worker_node_pubkey.trim().to_ascii_lowercase())
                            == worker_hex
                    });

                let mut cloud_unit_blockers: Vec<&'static str> = Vec::new();
                if worker.is_none() {
                    cloud_unit_blockers.push("worker_eligibility_not_found_finalized");
                }
                if privilege_record
                    .as_ref()
                    .map(|r| !r.cloud_unit_allowed)
                    .unwrap_or(true)
                {
                    cloud_unit_blockers.push("missing_governed_cloud_unit_grant");
                }
                if privilege_record
                    .as_ref()
                    .and_then(|r| r.cloud_unit_grant_proposal_id.as_deref())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    cloud_unit_blockers.push("missing_cloud_unit_grant_proposal_id");
                }
                if privilege_record
                    .as_ref()
                    .and_then(|r| r.cloud_unit_grant_payload_hash.as_deref())
                    .map(str::trim)
                    .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                    .is_none()
                {
                    cloud_unit_blockers.push("missing_or_invalid_cloud_unit_grant_payload_hash");
                }
                if let Some(w) = worker.as_ref() {
                    if !w.eligible_for_non_probe {
                        cloud_unit_blockers.push("worker_not_non_probe_eligible");
                    }
                    if w.effective_score < crate::reputation_score::WORKER_CLOUD_UNIT_MIN_SCORE_V1 {
                        cloud_unit_blockers.push("cloud_unit_score_below_threshold");
                    }
                    if w.cloud_unit_allowed {
                        cloud_unit_blockers.clear();
                    }
                }
                let cloud_unit_status = if worker.as_ref().map(|w| w.cloud_unit_allowed).unwrap_or(false) {
                    "allowed"
                } else if cloud_unit_blockers.is_empty() {
                    "blocked_unknown"
                } else {
                    "blocked"
                };

                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": if worker.is_some() { "ok" } else { "not_found" },
                        "surface": "canonical-worker-privilege-debug-v1",
                        "source_commitment": "finalized",
                        "source_height": finalized_height,
                        "finalized_height": finalized_height,
                        "finalized_hash": finalized_hash,
                        "worker_node_pubkey_query": worker_pubkey,
                        "worker_node_pubkey_hex": worker_hex,
                        "cloud_unit_status": cloud_unit_status,
                        "cloud_unit_blockers": cloud_unit_blockers,
                        "worker": worker,
                        "governed_privilege": privilege_record,
                        "semantics": {
                            "scope": "diagnostic_only",
                            "canonical_admission_source": "/api/v2/reputation/canonical/workers/{worker_node_pubkey}/eligibility",
                            "does_not_change_consensus_or_admission": true
                        }
                    })),
                    if worker.is_some() {
                        warp::http::StatusCode::OK
                    } else {
                        warp::http::StatusCode::NOT_FOUND
                    },
                )
                .into_response()
            });

    let reputation_bridge = build_reputation_bridge_route(chain.clone());

    let reputation_claims_canonical =
        warp::path!("api" / "v2" / "reputation" / "claims" / "canonical")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                let claims = bc.governance_wallet_reputation_claim_snapshot(512);
                warp::reply::json(&serde_json::json!({"status":"ok","claims":claims}))
            });

    let reputation_evidence_canonical =
        warp::path!("api" / "v2" / "reputation" / "evidence" / "canonical")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_evidence_canonical".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/evidence/canonical"
                );
                let bc = lock_any!(ch);
                let evidences = bc.governance_wallet_reputation_evidence_snapshot(512);
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "evidences": evidences,
                }))
            });

    let reputation_e2_worker_evidence_canonical =
        warp::path!("api" / "v2" / "reputation" / "e2" / "worker" / "evidence" / "canonical")
            .and(warp::get())
            .and(warp::query::<ReputationEvidenceLimitQuery>())
            .and(with_chain(chain.clone()))
            .map(|q: ReputationEvidenceLimitQuery, ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_rep_e2_worker_evidence_canonical".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/reputation/e2/worker/evidence/canonical"
                );
                let bc = lock_any!(ch);
                let source_height = bc.tip_height_u64();
                let finalized_height = bc.finalized_height();
                let limit = q.limit.unwrap_or(128).clamp(1, 1024);
                let evidences = bc.e2_worker_reputation_evidence_snapshot(limit);
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "e2_worker_reputation_evidence_v1_v2",
                    "source_height": source_height,
                    "finalized_height": finalized_height,
                    "limit": limit,
                    "evidences": evidences,
                }))
            });

    let reputation_e2_worker_evidence_ingest =
        warp::path!("api" / "v2" / "reputation" / "e2" / "worker" / "evidence")
            .and(warp::post())
            .and(admin_guard(admin.clone()))
            .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES * 8))
            .and(warp::body::json())
            .and(with_validator_key(
                validator_sk.clone(),
                validator_pk_b64.clone(),
            ))
            .and(with_chain(chain.clone()))
            .and(with_mempool(mempool.clone()))
            .and(with_p2p(tx_p2p.clone()))
            .map(
                |_g: (),
                 ev: crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1,
                 sk: Arc<SigningKey>,
                 local_pk_b64: String,
                 chain: SharedChain,
                 _mp: SharedMempool,
                 _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                    ng_trace_throttle!(
                        key: "api_rep_e2_worker_evidence_ingest".to_string(),
                        every_ms: 30000,
                        target: "api.req",
                        "POST /api/v2/reputation/e2/worker/evidence"
                    );
                    let mut ch = lock_any!(chain);

                    let preview = match ch.preview_e2_worker_reputation_evidence_v1(&ev) {
                        Ok(outcome) => outcome,
                        Err(err) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "surface": "e2_worker_reputation_evidence_v1_v2",
                                    "message": err,
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            )
                            .into_response();
                        }
                    };

                    if preview.status == "duplicate" {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "ok",
                                "surface": "e2_worker_reputation_evidence_v1_v2",
                                "path_class": "governed_manual_evidence_ingest",
                                "standard_evidence_build_unsigned_path": "/api/v2/e2/worker/evidence/build_unsigned",
                                "standard_evidence_submit_path": "/api/v2/tx/submit_signed",
                                "mode": "already_canonical",
                                "outcome": preview,
                            })),
                            warp::http::StatusCode::OK,
                        )
                        .into_response();
                    }

                    let (timelock, proposer) = match ch.governance.as_ref() {
                        Some(g) => {
                            if !g.protocol_council.is_member(&local_pk_b64) {
                                return warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": "not_protocol_council_member",
                                        "local_pk_b64": local_pk_b64,
                                    })),
                                    warp::http::StatusCode::FORBIDDEN,
                                )
                                .into_response();
                            }
                            (g.params.min_timelock_blocks, local_pk_b64.clone())
                        }
                        None => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "governance_disabled",
                                })),
                                warp::http::StatusCode::PRECONDITION_FAILED,
                            )
                            .into_response();
                        }
                    };

                    let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                    let next_height = prev_index + 1;
                    let effective_height = next_height.saturating_add(timelock);

                    let payload = crate::governance::E2WorkerReputationEvidenceIngestPayloadV1 {
                format_version:
                    crate::governance::E2_WORKER_REPUTATION_EVIDENCE_INGEST_PAYLOAD_VERSION_V1
                        .to_string(),
                evidences: vec![ev],
            };
                    if let Err(e) = payload.validate_contract_v1() {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "payload_validation_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )
                        .into_response();
                    }
                    let payload_bytes = match serde_json::to_vec(&payload) {
                        Ok(v) => v,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "payload_serialize_failed",
                                    "error": e.to_string(),
                                })),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            )
                            .into_response();
                        }
                    };

                    let proposal_kind = crate::governance::GovProposalKind::IngestE2WorkerReputationEvidence;
                    let proposal_id = governance_proposal_id_v1(
                        "e2-worker-rep-ingest",
                        &proposal_kind,
                        &proposer,
                        &payload_bytes,
                        next_height,
                        effective_height,
                        ch.pending_governance_queue_len_v1(),
                        &ch.genesis_hash,
                    );
                    let mut proposal = crate::governance::TxGovernanceProposal {
                        id: proposal_id.clone(),
                        kind: proposal_kind,
                        payload: payload_bytes,
                        created_at_height: next_height,
                        effective_height,
                        proposer: proposer.clone(),
                        signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
                    };
                    proposal.signature_domain = crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                    proposal.chain_id = crate::chain_identity::chain_id().to_string();
                    proposal.genesis_hash = ch.genesis_hash.clone();
                    let council = crate::governance::GovernanceCouncilKind::Protocol;
                    let msg =
                        match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                            Ok(m) => m,
                            Err(e) => {
                                return warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": "proposal_signing_bytes_failed",
                                        "error": e,
                                    })),
                                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                                )
                                .into_response();
                            }
                        };
                    proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());
                    let evidence_id = payload.evidences[0].evidence_hash().to_string();
                    let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                        Ok(v) => v,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": e.reason_code(),
                                    "error": e.to_string(),
                                    "proposal_id": proposal_id,
                                })),
                                warp::http::StatusCode::CONFLICT,
                            )
                            .into_response();
                        }
                    };

                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "accepted",
                            "surface": "e2_worker_reputation_evidence_v1_v2",
                            "path_class": "governed_manual_evidence_ingest",
                            "standard_evidence_build_unsigned_path": "/api/v2/e2/worker/evidence/build_unsigned",
                            "standard_evidence_submit_path": "/api/v2/tx/submit_signed",
                            "mode": "governance_proposal_queued",
                            "canonical_inclusion": "pending_block_production",
                            "proposal_id": proposal_id,
                            "governance_flow": governance_flow_response_v1(&proposal_id),
                            "evidence_id": evidence_id,
                            "provisional_created_at_height": next_height,
                            "provisional_effective_height": effective_height,
                            "effective_height_assigned_at_inclusion": true,
                            "timelock_blocks": timelock,
                            "queue_depth": ingress.queue_depth,
                            "preview": preview,
                        })),
                        warp::http::StatusCode::ACCEPTED,
                    )
                    .into_response()
                },
            );

    let gov_e2_worker_operator_bind =
        warp::path!("api" / "v2" / "gov" / "e2" / "worker-operator" / "bind")
            .and(warp::post())
            .and(admin_guard(admin.clone()))
            .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
            .and(warp::body::json())
            .and(with_validator_key(
                validator_sk.clone(),
                validator_pk_b64.clone(),
            ))
            .and(with_chain(chain.clone()))
            .and(with_mempool(mempool.clone()))
            .and(with_p2p(tx_p2p.clone()))
            .map(
                |_g: (),
                 body: serde_json::Value,
                 sk: Arc<SigningKey>,
                 local_pk_b64: String,
                 chain: SharedChain,
                 _mp: SharedMempool,
                 _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                    ng_trace_throttle!(
                        key: "api_gov_e2_worker_operator_bind".to_string(),
                        every_ms: 30000,
                        target: "api.req",
                        "POST /api/v2/gov/e2/worker-operator/bind"
                    );

                    let required_str = |key: &str| -> Result<String, warp::reply::Response> {
                        body.get(key)
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToOwned::to_owned)
                            .ok_or_else(|| {
                                warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": format!("missing_or_empty_{key}"),
                                    })),
                                    warp::http::StatusCode::BAD_REQUEST,
                                )
                                .into_response()
                            })
                    };

                    let worker_node_pubkey = match required_str("worker_node_pubkey") {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    let operator_wallet_pubkey = match required_str("operator_wallet_pubkey") {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    let reason = body
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned);
                    let requested_timelock = body.get("timelock_blocks").and_then(|v| v.as_u64());

                    let payload = crate::governance::E2WorkerOperatorBindingPayloadV1 {
                        format_version:
                            crate::governance::E2_WORKER_OPERATOR_BINDING_PAYLOAD_VERSION_V1
                                .to_string(),
                        worker_node_pubkey,
                        operator_wallet_pubkey,
                        reason,
                    };

                    if let Err(e) = payload.validate_contract_v1() {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "payload_validation_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )
                        .into_response();
                    }

                    let mut ch = lock_any!(chain);
                    let (timelock, proposer) = match ch.governance.as_ref() {
                        Some(g) => {
                            if !g.protocol_council.is_member(&local_pk_b64) {
                                return warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": "not_protocol_council_member",
                                        "local_pk_b64": local_pk_b64,
                                    })),
                                    warp::http::StatusCode::FORBIDDEN,
                                )
                                .into_response();
                            }
                            let min_tl = g.params.min_timelock_blocks;
                            (
                                requested_timelock.unwrap_or(min_tl).max(min_tl),
                                local_pk_b64.clone(),
                            )
                        }
                        None => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "governance_disabled",
                                })),
                                warp::http::StatusCode::PRECONDITION_FAILED,
                            )
                            .into_response();
                        }
                    };

                    let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                    let next_height = prev_index + 1;
                    let effective_height = next_height.saturating_add(timelock);
                    let payload_bytes = match serde_json::to_vec(&payload) {
                        Ok(v) => v,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "payload_serialize_failed",
                                    "error": e.to_string(),
                                })),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            )
                            .into_response();
                        }
                    };

                    let proposal_kind =
                        crate::governance::GovProposalKind::BindE2WorkerOperatorWallet;
                    let proposal_id = governance_proposal_id_v1(
                        "e2-worker-operator-bind",
                        &proposal_kind,
                        &proposer,
                        &payload_bytes,
                        next_height,
                        effective_height,
                        ch.pending_governance_queue_len_v1(),
                        &ch.genesis_hash,
                    );

                    let mut proposal = crate::governance::TxGovernanceProposal {
                        id: proposal_id.clone(),
                        kind: proposal_kind,
                        payload: payload_bytes,
                        created_at_height: next_height,
                        effective_height,
                        proposer: proposer.clone(),
                        signature_domain: String::new(),
                        chain_id: String::new(),
                        genesis_hash: String::new(),
                        signature: String::new(),
                    };

                    proposal.signature_domain =
                        crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                    proposal.chain_id = crate::chain_identity::chain_id().to_string();
                    proposal.genesis_hash = ch.genesis_hash.clone();
                    let council = crate::governance::GovernanceCouncilKind::Protocol;
                    let msg =
                        match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                            Ok(m) => m,
                            Err(e) => {
                                return warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": "proposal_signing_bytes_failed",
                                        "error": e,
                                    })),
                                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                                )
                                .into_response();
                            }
                        };
                    proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());

                    let worker_hex = crate::keyfmt::pk_hex_from_any(&payload.worker_node_pubkey)
                        .unwrap_or_else(|_| payload.worker_node_pubkey.trim().to_ascii_lowercase());
                    let operator_hex =
                        crate::keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey)
                            .unwrap_or_else(|_| {
                                payload.operator_wallet_pubkey.trim().to_ascii_lowercase()
                            });

                    let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                        Ok(v) => v,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": e.reason_code(),
                                    "error": e.to_string(),
                                    "proposal_id": proposal_id,
                                })),
                                warp::http::StatusCode::CONFLICT,
                            )
                            .into_response();
                        }
                    };

                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "accepted",
                            "surface": "e2_worker_operator_binding_v1",
                            "mode": "governance_proposal_queued",
                            "canonical_inclusion": "pending_block_production",
                            "requires_vote": true,
                            "required_council": "Protocol",
                            "show_proposal_path": format!("/api/v2/gov/proposals/{}", proposal_id),
                            "vote_path": format!("/api/v2/gov/proposals/{}/vote", proposal_id),
                            "vote_requires_proposal_hash_hex": true,
                            "proposal_hash_available_after_inclusion": true,
                            "proposal_id": proposal_id,
                            "governance_flow": governance_flow_response_v1(&proposal_id),
                            "worker_node_pubkey": worker_hex,
                            "operator_wallet_pubkey": operator_hex,
                            "provisional_created_at_height": next_height,
                            "provisional_effective_height": effective_height,
                            "effective_height_assigned_at_inclusion": true,
                            "timelock_blocks": timelock,
                            "queue_depth": ingress.queue_depth,
                        })),
                        warp::http::StatusCode::ACCEPTED,
                    )
                    .into_response()
                },
            );

    let gov_e2_worker_privilege = warp::path!("api" / "v2" / "gov" / "e2" / "worker" / "privilege")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .and(with_chain(chain.clone()))
        .map(
            |_g: (),
             body: serde_json::Value,
             sk: Arc<SigningKey>,
             local_pk_b64: String,
             chain: SharedChain| {
                ng_trace_throttle!(
                    key: "api_gov_e2_worker_privilege".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "POST /api/v2/gov/e2/worker/privilege"
                );

                let required_str = |key: &str| -> Result<String, warp::reply::Response> {
                    body.get(key)
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| {
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": format!("missing_or_empty_{key}"),
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            )
                            .into_response()
                        })
                };

                let worker_node_pubkey = match required_str("worker_node_pubkey") {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                let operator_wallet_pubkey = match required_str("operator_wallet_pubkey") {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                let privilege = match required_str("privilege") {
                    Ok(v) => v.to_ascii_lowercase(),
                    Err(resp) => return resp,
                };
                let action = match required_str("action") {
                    Ok(v) => v.to_ascii_lowercase(),
                    Err(resp) => return resp,
                };
                let proposal_kind = match (privilege.as_str(), action.as_str()) {
                    ("cloud_unit", "grant") | ("cloud", "grant") => {
                        crate::governance::GovProposalKind::GrantE2WorkerCloudUnit
                    }
                    ("cloud_unit", "revoke") | ("cloud", "revoke") => {
                        crate::governance::GovProposalKind::RevokeE2WorkerCloudUnit
                    }
                    ("gpu", "grant") | ("gpu_capability", "grant") => {
                        crate::governance::GovProposalKind::GrantE2WorkerGpuCapability
                    }
                    ("gpu", "revoke") | ("gpu_capability", "revoke") => {
                        crate::governance::GovProposalKind::RevokeE2WorkerGpuCapability
                    }
                    ("critical", "grant") | ("critical_workload", "grant") => {
                        crate::governance::GovProposalKind::GrantE2WorkerCriticalWorkload
                    }
                    ("critical", "revoke") | ("critical_workload", "revoke") => {
                        crate::governance::GovProposalKind::RevokeE2WorkerCriticalWorkload
                    }
                    _ => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "unsupported_privilege_action",
                                "allowed": [
                                    "cloud_unit/grant", "cloud_unit/revoke",
                                    "gpu/grant", "gpu/revoke",
                                    "critical/grant", "critical/revoke"
                                ],
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    }
                };
                let reason = body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned);
                let requested_timelock = body.get("timelock_blocks").and_then(|v| v.as_u64());

                let payload = crate::governance::E2WorkerGovernedPrivilegePayloadV1 {
                    format_version:
                        crate::governance::E2_WORKER_GOVERNED_PRIVILEGE_PAYLOAD_VERSION_V1
                            .to_string(),
                    request_id: body
                        .get("request_id")
                        .or_else(|| body.get("requestId"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    proposal_kind: Some(format!("{:?}", proposal_kind)),
                    proposal_action: Some(action.clone()),
                    requested_tier: body
                        .get("requested_tier")
                        .or_else(|| body.get("requestedTier"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    worker_id: body
                        .get("worker_id")
                        .or_else(|| body.get("workerId"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    worker_node_pubkey,
                    operator_wallet_pubkey,
                    capability_snapshot_hash: body
                        .get("capability_snapshot_hash")
                        .or_else(|| body.get("capabilitySnapshotHash"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty()),
                    critical_review_payload_hash: body
                        .get("critical_review_payload_hash")
                        .or_else(|| body.get("criticalReviewPayloadHash"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty()),
                    reason,
                };

                if let Err(e) = payload.validate_contract_v1() {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "payload_validation_failed",
                            "error": e,
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    )
                    .into_response();
                }

                let mut ch = lock_any!(chain);
                let (timelock, proposer) = match ch.governance.as_ref() {
                    Some(g) => {
                        if !g.protocol_council.is_member(&local_pk_b64) {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "not_protocol_council_member",
                                    "local_pk_b64": local_pk_b64,
                                })),
                                warp::http::StatusCode::FORBIDDEN,
                            )
                            .into_response();
                        }
                        let min_tl = g.params.min_timelock_blocks;
                        (
                            requested_timelock.unwrap_or(min_tl).max(min_tl),
                            local_pk_b64.clone(),
                        )
                    }
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "governance_disabled",
                            })),
                            warp::http::StatusCode::PRECONDITION_FAILED,
                        )
                        .into_response();
                    }
                };

                let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                let next_height = prev_index + 1;
                let effective_height = next_height.saturating_add(timelock);
                let payload_bytes = match serde_json::to_vec(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "payload_serialize_failed",
                                "error": e.to_string(),
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };

                let worker_hex = crate::keyfmt::pk_hex_from_any(&payload.worker_node_pubkey)
                    .unwrap_or_else(|_| payload.worker_node_pubkey.trim().to_ascii_lowercase());
                let operator_hex = crate::keyfmt::pk_hex_from_any(&payload.operator_wallet_pubkey)
                    .unwrap_or_else(|_| payload.operator_wallet_pubkey.trim().to_ascii_lowercase());

                if let Some(existing_queued) = ch
                    .pending_governance_proposal_by_kind_payload_v1(&proposal_kind, &payload_bytes)
                {
                    let existing_id = existing_queued.id.clone();
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "surface": "e2_worker_governed_privilege_v1",
                            "mode": "governance_proposal_already_queued",
                            "canonical_inclusion": "pending_block_production",
                            "requires_vote": true,
                            "required_council": "Protocol",
                            "show_proposal_path": format!("/api/v2/gov/proposals/{}", existing_id),
                            "vote_path": format!("/api/v2/gov/proposals/{}/vote", existing_id),
                            "vote_requires_proposal_hash_hex": true,
                            "proposal_hash_available_after_inclusion": true,
                            "proposal_id": existing_id,
                            "proposal_status": "Queued",
                            "provisional_created_at_height": existing_queued.created_at_height,
                            "provisional_effective_height": existing_queued.effective_height,
                            "effective_height_assigned_at_inclusion": true,
                            "governance_flow": governance_flow_response_v1(&existing_queued.id),
                            "worker_node_pubkey": worker_hex,
                            "operator_wallet_pubkey": operator_hex,
                            "privilege": privilege,
                            "action": action,
                            "idempotency": {
                                "scope": "same_kind_same_payload_pending_queue",
                                "behavior": "reused_existing_queued_proposal",
                                "safety": "does_not_change_governance_threshold_or_vote_lifecycle"
                            }
                        })),
                        warp::http::StatusCode::OK,
                    )
                    .into_response();
                }

                if let Some(existing) = ch.governance.as_ref().and_then(|g| {
                    g.proposals
                        .values()
                        .filter(|p| {
                            p.kind == proposal_kind
                                && p.payload == payload_bytes
                                && matches!(
                                    p.status,
                                    crate::governance::ProposalStatus::Pending
                                        | crate::governance::ProposalStatus::Applied
                                )
                        })
                        .max_by_key(|p| p.created_at_height)
                        .cloned()
                }) {
                    let existing_id = existing.id.clone();
                    let existing_hash = existing.proposal_hash_hex.clone();
                    let existing_status = format!("{:?}", existing.status);
                    let existing_requires_vote =
                        existing.status == crate::governance::ProposalStatus::Pending;
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "surface": "e2_worker_governed_privilege_v1",
                            "mode": "governance_proposal_already_exists",
                            "canonical_inclusion": "already_in_chain_state",
                            "requires_vote": existing_requires_vote,
                            "required_council": "Protocol",
                            "show_proposal_path": format!("/api/v2/gov/proposals/{}", existing_id),
                            "vote_path": format!("/api/v2/gov/proposals/{}/vote", existing_id),
                            "vote_requires_proposal_hash_hex": true,
                            "proposal_hash_available_after_inclusion": true,
                            "proposal_id": existing_id,
                            "proposal_hash_hex": existing_hash,
                            "proposal_status": existing_status,
                            "created_at_height": existing.created_at_height,
                            "effective_height": existing.effective_height,
                            "terminal_height": existing.terminal_height,
                            "governance_flow": governance_flow_response_v1(&existing.id),
                            "worker_node_pubkey": worker_hex,
                            "operator_wallet_pubkey": operator_hex,
                            "privilege": privilege,
                            "action": action,
                            "idempotency": {
                                "scope": "same_kind_same_payload",
                                "behavior": "reused_existing_pending_or_applied_proposal",
                                "safety": "does_not_change_governance_threshold_or_vote_lifecycle"
                            }
                        })),
                        warp::http::StatusCode::OK,
                    )
                    .into_response();
                }

                let proposal_id = governance_proposal_id_v1(
                    "e2-worker-privilege",
                    &proposal_kind,
                    &proposer,
                    &payload_bytes,
                    next_height,
                    effective_height,
                    ch.pending_governance_queue_len_v1(),
                    &ch.genesis_hash,
                );

                let mut proposal = crate::governance::TxGovernanceProposal {
                    id: proposal_id.clone(),
                    kind: proposal_kind,
                    payload: payload_bytes,
                    created_at_height: next_height,
                    effective_height,
                    proposer: proposer.clone(),
                    signature_domain: String::new(),
                    chain_id: String::new(),
                    genesis_hash: String::new(),
                    signature: String::new(),
                };

                proposal.signature_domain =
                    crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                proposal.chain_id = crate::chain_identity::chain_id().to_string();
                proposal.genesis_hash = ch.genesis_hash.clone();
                let council = crate::governance::GovernanceCouncilKind::Protocol;
                let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                    Ok(m) => m,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_signing_bytes_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };
                proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());

                let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": e.reason_code(),
                                "error": e.to_string(),
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }
                };

                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "accepted",
                        "surface": "e2_worker_governed_privilege_v1",
                        "mode": "governance_proposal_queued",
                        "canonical_inclusion": "pending_block_production",
                        "requires_vote": true,
                        "required_council": "Protocol",
                        "show_proposal_path": format!("/api/v2/gov/proposals/{}", proposal_id),
                        "vote_path": format!("/api/v2/gov/proposals/{}/vote", proposal_id),
                        "vote_requires_proposal_hash_hex": true,
                        "proposal_hash_available_after_inclusion": true,
                        "proposal_id": proposal_id,
                        "governance_flow": governance_flow_response_v1(&proposal_id),
                        "worker_node_pubkey": worker_hex,
                        "operator_wallet_pubkey": operator_hex,
                        "privilege": privilege,
                        "action": action,
                        "provisional_created_at_height": next_height,
                        "provisional_effective_height": effective_height,
                        "effective_height_assigned_at_inclusion": true,
                        "timelock_blocks": timelock,
                        "queue_depth": ingress.queue_depth,
                    })),
                    warp::http::StatusCode::ACCEPTED,
                )
                .into_response()
            },
        );

    let gov_proposals_list = warp::path!("api" / "v2" / "gov" / "proposals")
        .and(warp::get())
        .and(warp::query::<GovernanceProposalListQuery>())
        .and(with_chain(chain.clone()))
        .map(
            |query: GovernanceProposalListQuery, chain: Arc<Mutex<Blockchain>>| {
                let ch = lock_any!(chain);
                let Some(gov) = ch.governance.as_ref() else {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "governance_disabled",
                        })),
                        warp::http::StatusCode::PRECONDITION_FAILED,
                    )
                    .into_response();
                };

                let body = governance_proposals_list_response_v1(gov, &query);
                warp::reply::with_status(warp::reply::json(&body), warp::http::StatusCode::OK)
                    .into_response()
            },
        );

    let gov_proposal_get = warp::path!("api" / "v2" / "gov" / "proposals" / String)
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|proposal_id: String, chain: Arc<Mutex<Blockchain>>| {
            if !is_canonical_governance_proposal_id_for_api_v1(&proposal_id) {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "error",
                        "message": "invalid_proposal_id_canonical_required",
                        "proposal_id": proposal_id,
                    })),
                    warp::http::StatusCode::BAD_REQUEST,
                )
                .into_response();
            }

            let ch = lock_any!(chain);
            let Some(gov) = ch.governance.as_ref() else {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "error",
                        "message": "governance_disabled",
                        "proposal_id": proposal_id,
                    })),
                    warp::http::StatusCode::PRECONDITION_FAILED,
                )
                .into_response();
            };

            let Some(prop) = gov.proposals.get(&proposal_id) else {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "not_found",
                        "message": "proposal_not_found",
                        "proposal_id": proposal_id,
                    })),
                    warp::http::StatusCode::NOT_FOUND,
                )
                .into_response();
            };

            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "governance-proposal-detail-v1",
                    "proposal": governance_proposal_view_v1(gov, prop),
                })),
                warp::http::StatusCode::OK,
            )
            .into_response()
        });

    let gov_proposal_vote = warp::path!("api" / "v2" / "gov" / "proposals" / String / "vote")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))
        .and(with_chain(chain.clone()))
        .map(
            |proposal_id: String,
             _g: (),
             body: serde_json::Value,
             sk: Arc<SigningKey>,
             local_pk_b64: String,
             chain: Arc<Mutex<Blockchain>>| {
                if !is_canonical_governance_proposal_id_for_api_v1(&proposal_id) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "invalid_proposal_id_canonical_required",
                            "proposal_id": proposal_id,
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let approve = body
                    .get("approve")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if !approve {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "governance_rejection_vote_not_supported_v1",
                            "proposal_id": proposal_id,
                            "reason": "current TxGovernanceVote represents approval only; rejection requires an explicit contract extension",
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    )
                    .into_response();
                }

                let vote_reason = body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

                let supplied_proposal_hash_hex = match body
                    .get("proposal_hash_hex")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    Some(v) => v.to_string(),
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "missing_proposal_hash_hex",
                                "proposal_id": proposal_id,
                                "reason": "v1 governance vote requires the caller to explicitly confirm the proposal_hash_hex shown by GET /api/v2/gov/proposals/{proposal_id}",
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    }
                };

                if !is_canonical_lowercase_sha256_hex_v1(&supplied_proposal_hash_hex) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "invalid_proposal_hash_hex_canonical_lowercase_required",
                            "proposal_id": proposal_id,
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let mut ch = lock_any!(chain);

                let (proposal_hash_hex, council_kind, created_at_height, effective_height, threshold, already_recorded) = {
                    let Some(gov) = ch.governance.as_ref() else {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "governance_disabled",
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::PRECONDITION_FAILED,
                        )
                        .into_response();
                    };

                    let Some(prop) = gov.proposals.get(&proposal_id) else {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_not_found",
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::NOT_FOUND,
                        )
                        .into_response();
                    };

                    if prop.status != crate::governance::ProposalStatus::Pending {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_not_pending",
                                "proposal_id": proposal_id,
                                "proposal_status": format!("{:?}", prop.status),
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }

                    if prop.proposal_hash_hex.is_empty() {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "missing_proposal_hash",
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }

                    if prop.proposal_hash_hex.as_str() != supplied_proposal_hash_hex {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_hash_mismatch",
                                "proposal_id": proposal_id,
                                "expected_proposal_hash_hex": prop.proposal_hash_hex,
                                "supplied_proposal_hash_hex": supplied_proposal_hash_hex,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }

                    let (council, threshold, council_name) = match &prop.council {
                        crate::governance::GovernanceCouncilKind::Protocol => (
                            &gov.protocol_council,
                            gov.protocol_council.threshold,
                            "Protocol",
                        ),
                        crate::governance::GovernanceCouncilKind::Economy => (
                            &gov.economy_council,
                            gov.economy_council.threshold,
                            "Economy",
                        ),
                        crate::governance::GovernanceCouncilKind::Emergency => (
                            &gov.emergency_council,
                            gov.emergency_council.threshold,
                            "Emergency",
                        ),
                    };

                    if threshold == 0 {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "governance_council_threshold_zero",
                                "proposal_id": proposal_id,
                                "council": council_name,
                            })),
                            warp::http::StatusCode::PRECONDITION_FAILED,
                        )
                        .into_response();
                    }

                    if !council.is_member(&local_pk_b64) {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "not_proposal_council_member",
                                "proposal_id": proposal_id,
                                "required_council": council_name,
                                "local_pk_b64": local_pk_b64,
                            })),
                            warp::http::StatusCode::FORBIDDEN,
                        )
                        .into_response();
                    }

                    let voter_hex = match crate::keyfmt::pk_hex_from_any(&local_pk_b64) {
                        Ok(h) => h,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "local_voter_pubkey_invalid",
                                    "proposal_id": proposal_id,
                                    "error": e.to_string(),
                                })),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            )
                            .into_response();
                        }
                    };

                    let already_recorded = prop
                        .vote_records_v1
                        .get(&voter_hex)
                        .map(|record| {
                            record.proposal_hash_hex.as_str() == supplied_proposal_hash_hex.as_str()
                                && record.signature_domain.as_str() == prop.signature_domain.as_str()
                                && record.chain_id.as_str() == prop.chain_id.as_str()
                                && record.genesis_hash.as_str() == prop.genesis_hash.as_str()
                        })
                        .unwrap_or_else(|| {
                            // Legacy compatibility only for explicitly-enabled pre-audit records
                            // that have no vote_records_v1 at all. New votes must be
                            // hash/domain-auditable and cannot be hidden behind compact legacy votes.
                            crate::governance::legacy_governance_compact_votes_allowed_for_view_v1()
                                && prop.vote_records_v1.is_empty()
                                && prop.votes.contains_key(&voter_hex)
                        });

                    (
                        prop.proposal_hash_hex.clone(),
                        prop.council.clone(),
                        prop.created_at_height,
                        prop.effective_height,
                        threshold,
                        already_recorded,
                    )
                };

                let voter_hex = match crate::keyfmt::pk_hex_from_any(&local_pk_b64) {
                    Ok(h) => h,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "local_voter_pubkey_invalid",
                                "proposal_id": proposal_id,
                                "error": e.to_string(),
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };

                if already_recorded {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "mode": "governance_vote_already_recorded",
                            "proposal_id": proposal_id,
                            "voter_pubkey": voter_hex,
                            "approve": true,
                            "canonical_inclusion": "already_in_chain_state",
                            "proposal_hash_hex": proposal_hash_hex,
                            "proposal_hash_confirmed": true,
                            "threshold": threshold,
                            "created_at_height": created_at_height,
                            "effective_height": effective_height,
                        })),
                        warp::http::StatusCode::OK,
                    )
                    .into_response();
                }

                let mut vote = crate::governance::TxGovernanceVote {
                    proposal_id: proposal_id.clone(),
                    proposal_hash_hex: proposal_hash_hex.clone(),
                    voter: local_pk_b64.clone(),
                    signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
                    chain_id: crate::chain_identity::chain_id().to_string(),
                    genesis_hash: ch.genesis_hash.clone(),
                    signature: String::new(),
                };

                let vote_msg = match crate::governance::vote_signing_bytes_for_tx_v1(&vote) {
                    Ok(m) => m,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "vote_signing_bytes_failed",
                                "proposal_id": proposal_id,
                                "error": e,
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };
                vote.signature = STANDARD.encode(sk.sign(&vote_msg).to_bytes());

                let ingress = match ch.enqueue_governance_vote_v1(vote) {
                    Ok(v) => v,
                    Err(crate::blockchain::GovernanceIngressError::DuplicateVote { proposal_id: dup_id, voter_pubkey_hex }) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "accepted",
                                "mode": "governance_vote_already_queued",
                                "proposal_id": dup_id,
                                "voter_pubkey": voter_pubkey_hex,
                                "approve": true,
                                "canonical_inclusion": "pending_block_production",
                                "proposal_hash_hex": proposal_hash_hex,
                                "proposal_hash_confirmed": true,
                                "threshold": threshold,
                            })),
                            warp::http::StatusCode::ACCEPTED,
                        )
                        .into_response();
                    }
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": e.reason_code(),
                                "error": e.to_string(),
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }
                };

                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "accepted",
                        "mode": "governance_vote_queued",
                        "proposal_id": proposal_id,
                        "voter_pubkey": ingress.voter_pubkey_hex,
                        "approve": true,
                        "proposal_hash_hex": proposal_hash_hex,
                        "proposal_hash_confirmed": true,
                        "reason": vote_reason,
                        "reason_on_chain": false,
                        "required_council": format!("{:?}", council_kind),
                        "threshold": threshold,
                        "created_at_height": created_at_height,
                        "effective_height": effective_height,
                        "canonical_inclusion": "pending_block_production",
                        "queue_depth": ingress.queue_depth,
                    })),
                    warp::http::StatusCode::ACCEPTED,
                )
                .into_response()
            },
        );

    let gov_ingress_pending = warp::path!("api" / "v2" / "gov" / "ingress" / "pending")
        .and(warp::get())
        .and(admin_guard(admin.clone()))
        .and(with_chain(chain.clone()))
        .map(|_admin_ok: (), chain: Arc<Mutex<Blockchain>>| {
            let ch = lock_any!(chain);
            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "surface": "governance-ingress-pending-v1",
                    "snapshot": ch.pending_governance_ingress_snapshot_v1(),
                })),
                warp::http::StatusCode::OK,
            )
        });

    let compute_fiat_settlement_proof_ingest = warp::path!(
        "api" / "v2" / "e2" / "billing" / "settlement-proof"
    )
    .and(warp::post())
    .and(admin_guard(admin.clone()))
    .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES * 8))
    .and(warp::body::json())
    .and(with_validator_key(
        validator_sk.clone(),
        validator_pk_b64.clone(),
    ))
    .and(with_chain(chain.clone()))
    .and(with_mempool(mempool.clone()))
    .and(with_p2p(tx_p2p.clone()))
    .map(
        |_g: (),
         proof: crate::compute_contract::ComputeFiatSettlementProofV1,
         sk: Arc<SigningKey>,
         local_pk_b64: String,
         chain: SharedChain,
         _mp: SharedMempool,
         _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
            ng_trace_throttle!(
                key: "api_compute_fiat_settlement_proof_ingest".to_string(),
                every_ms: 30000,
                target: "api.req",
                "POST /api/v2/e2/billing/settlement-proof"
            );
            let mut ch = lock_any!(chain);

            let preview = match ch.preview_compute_fiat_settlement_proof_v1(&proof) {
                Ok(status) => status.to_string(),
                Err(err) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "surface": "compute_fiat_settlement_proof_v1",
                            "message": err,
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    )
                    .into_response();
                }
            };

            if preview == "duplicate" {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "surface": "compute_fiat_settlement_proof_v1",
                        "mode": "already_canonical",
                        "order_id": proof.order_id,
                    })),
                    warp::http::StatusCode::OK,
                )
                .into_response();
            }

            let (timelock, proposer) = match ch.governance.as_ref() {
                Some(g) => {
                    if !g.economy_council.is_member(&local_pk_b64) {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "not_economy_council_member",
                                "local_pk_b64": local_pk_b64,
                            })),
                            warp::http::StatusCode::FORBIDDEN,
                        )
                        .into_response();
                    }
                    (g.params.min_timelock_blocks, local_pk_b64.clone())
                }
                None => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "governance_disabled",
                        })),
                        warp::http::StatusCode::PRECONDITION_FAILED,
                    )
                    .into_response();
                }
            };

            let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
            let next_height = prev_index + 1;
            let effective_height = next_height.saturating_add(timelock);

            let payload = crate::compute_contract::ComputeFiatSettlementProofIngestPayloadV1 {
                format_version:
                    crate::compute_contract::COMPUTE_FIAT_SETTLEMENT_PROOF_INGEST_PAYLOAD_VERSION_V1
                        .to_string(),
                proofs: vec![proof],
            };
            if let Err(e) = payload.validate_contract_v1() {
                return warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "error",
                        "message": "payload_validation_failed",
                        "error": e,
                    })),
                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                )
                .into_response();
            }
            let order_id = payload.proofs[0].order_id.clone();
            let payload_bytes = match serde_json::to_vec(&payload) {
                Ok(v) => v,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "payload_serialize_failed",
                            "error": e.to_string(),
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response();
                }
            };

            let proposal_kind =
                crate::governance::GovProposalKind::IngestComputeFiatSettlementProof;
            let proposal_id = governance_proposal_id_v1(
                "compute-fiat-settlement-proof",
                &proposal_kind,
                &proposer,
                &payload_bytes,
                next_height,
                effective_height,
                ch.pending_governance_queue_len_v1(),
                &ch.genesis_hash,
            );
            let mut proposal = crate::governance::TxGovernanceProposal {
                id: proposal_id.clone(),
                kind: proposal_kind,
                payload: payload_bytes,
                created_at_height: next_height,
                effective_height,
                proposer: proposer.clone(),
                signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
            };
            proposal.signature_domain =
                crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
            proposal.chain_id = crate::chain_identity::chain_id().to_string();
            proposal.genesis_hash = ch.genesis_hash.clone();
            let council = crate::governance::GovernanceCouncilKind::Economy;
            let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                Ok(m) => m,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "proposal_signing_bytes_failed",
                            "error": e,
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response();
                }
            };
            proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());
            let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                Ok(v) => v,
                Err(e) => {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e.reason_code(),
                            "error": e.to_string(),
                            "proposal_id": proposal_id,
                        })),
                        warp::http::StatusCode::CONFLICT,
                    )
                    .into_response();
                }
            };

            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "accepted",
                    "surface": "compute_fiat_settlement_proof_v1",
                    "mode": "governance_proposal_queued",
                    "canonical_inclusion": "pending_block_production",
                    "proposal_id": proposal_id,
                    "governance_flow": governance_flow_response_v1(&proposal_id),
                    "order_id": order_id,
                    "provisional_created_at_height": next_height,
                    "provisional_effective_height": effective_height,
                    "effective_height_assigned_at_inclusion": true,
                    "timelock_blocks": timelock,
                    "queue_depth": ingress.queue_depth,
                    "preview": preview,
                })),
                warp::http::StatusCode::ACCEPTED,
            )
            .into_response()
        },
    );

    let compute_fiat_settlement_proof_canonical =
        warp::path!("api" / "v2" / "billing" / "settlement-proofs" / String)
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|order_id: String, ch: SharedChain| {
                ng_trace_throttle!(
                    key: format!("api_compute_fiat_settlement_proof_canonical:{}", order_id),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/billing/settlement-proofs/{}/", order_id
                );
                let bc = lock_any!(ch);
                let order_id_trimmed = order_id.trim();
                let proof = bc
                    .compute_fiat_settlement_proof_log
                    .iter()
                    .rev()
                    .find(|p| p.order_id.trim() == order_id_trimmed)
                    .cloned();
                let canonical_order_id_seen = bc
                    .compute_fiat_settlement_proof_order_ids
                    .contains(order_id_trimmed);
                warp::reply::json(&compute_fiat_settlement_proof_canonical_response_v1(
                    order_id_trimmed,
                    proof,
                    canonical_order_id_seen,
                ))
            });

    let gov_wallet_reputation_ingest_run = build_gov_wallet_reputation_ingest_run_route(
        admin.clone(),
        validator_sk.clone(),
        validator_pk_b64.clone(),
        chain.clone(),
        mempool.clone(),
        tx_p2p.clone(),
    );

    let governance_state_v2 = warp::path!("api" / "v2" / "governance" / "state")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_gov_state_v2".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/governance/state"
            );
            let bc = lock_any!(ch);

            let gov_json = match bc.governance.as_ref() {
                Some(g) => serde_json::to_value(g)
                    .unwrap_or_else(|_| serde_json::json!({"error":"governance_serialize_failed"})),
                None => serde_json::json!(null),
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "governance": gov_json
            }))
        });

    // ------- FT v1 (Gate 4) read-only endpoints -------
    // NOTE: query-based addressing avoids base64 "/" issues in path segments.
    // GET /api/v2/ft/token?id=1
    // GET /api/v2/ft/balance?token_id=1&addr=...
    // GET /api/v2/ft/allowance?token_id=1&owner=...&spender=...
    // GET /api/v2/ft/frozen?token_id=1&addr=...
    #[derive(Deserialize)]
    struct FtTokenQuery {
        id: u64,
    }
    #[derive(Deserialize)]
    struct FtBalanceQuery {
        token_id: u64,
        addr: String,
    }
    #[derive(Deserialize)]
    struct FtAllowanceQuery {
        token_id: u64,
        owner: String,
        spender: String,
    }
    #[derive(Deserialize)]
    struct FtFrozenQuery {
        token_id: u64,
        addr: String,
    }

    #[derive(Default, Deserialize)]
    struct FtMetricsQuery {
        window: Option<usize>,
    }

    let ft_token_v1 = warp::path!("api" / "v2" / "ft" / "token")
        .and(warp::get())
        .and(warp::query::<FtTokenQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: FtTokenQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::ft_api_token_read();
            let (height, head_hash, state_root_hex) = {
                let bc = lock_any!(ch);
                if let Some(last) = bc.chain.last() {
                    (last.index, last.hash.clone(), last.state_root.clone())
                } else {
                    (0u64, String::new(), String::new())
                }
            };

            if state_root_hex.trim().is_empty() {
                let body = serde_json::json!({"status":"error","message":"missing_state_root","height":height,"head_hash":head_hash});
                return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
            }
            let root = match bytes32_from_hex(state_root_hex.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"bad_state_root_hex","detail":e,"height":height,"head_hash":head_hash,"state_root":state_root_hex});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let smt = StateSmt::new(storage.state_node_store());
            let k_meta = ft::k_ft_meta(q.id);
            let st_meta = match smt.get_account(root, k_meta) {
                Ok(Some(st)) => st,
                Ok(None) => {
                    let body = serde_json::json!({"status":"error","message":"ft_token_not_found","token_id":q.id});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let meta = match ft::decode_meta_state_v1(&st_meta) {
                Ok(m) => m,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"ft_meta_decode_failed","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let cfg = match smt.get_account(root, ft::k_ft_cfg(q.id)) {
                Ok(Some(st)) => match ft::decode_cfg_state_v1(&st) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"ft_cfg_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => ft::FtTokenCfgV1::default(),
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let body = serde_json::json!({"status":"ok","token":meta,"cfg":cfg});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let ft_balance_v1 = warp::path!("api" / "v2" / "ft" / "balance")
        .and(warp::get())
        .and(warp::query::<FtBalanceQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: FtBalanceQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::ft_api_balance_read();
            let addr = normalize_pk_b64(&q.addr);
            let (height, head_hash, state_root_hex) = {
                let bc = lock_any!(ch);
                if let Some(last) = bc.chain.last() {
                    (last.index, last.hash.clone(), last.state_root.clone())
                } else {
                    (0u64, String::new(), String::new())
                }
            };

            if state_root_hex.trim().is_empty() {
                let body = serde_json::json!({"status":"error","message":"missing_state_root","height":height,"head_hash":head_hash});
                return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
            }
            let root = match bytes32_from_hex(state_root_hex.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"bad_state_root_hex","detail":e,"height":height,"head_hash":head_hash,"state_root":state_root_hex});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let smt = StateSmt::new(storage.state_node_store());
            let k_bal = ft::k_ft_balance(q.token_id, &addr);
            let amount = match smt.get_account(root, k_bal) {
                Ok(Some(st)) => match ft::decode_balance_amount_v1(&st) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"ft_balance_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => 0u128,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let decimals = match smt.get_account(root, ft::k_ft_meta(q.token_id)) {
                Ok(Some(st)) => ft::decode_meta_state_v1(&st).map(|m| m.decimals).unwrap_or(0),
                _ => 0,
            };
            let amount_dec = ft::format_ft_amount_atomic_to_decimal(amount, decimals);

            let body = serde_json::json!({"status":"ok","token_id":q.token_id,"addr":addr,"amount":amount.to_string(),"amount_dec":amount_dec,"decimals":decimals});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let ft_allowance_v1 = warp::path!("api" / "v2" / "ft" / "allowance")
        .and(warp::get())
        .and(warp::query::<FtAllowanceQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: FtAllowanceQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::ft_api_allowance_read();
            let owner = normalize_pk_b64(&q.owner);
            let spender = normalize_pk_b64(&q.spender);
            let (height, head_hash, state_root_hex) = {
                let bc = lock_any!(ch);
                if let Some(last) = bc.chain.last() {
                    (last.index, last.hash.clone(), last.state_root.clone())
                } else {
                    (0u64, String::new(), String::new())
                }
            };

            if state_root_hex.trim().is_empty() {
                let body = serde_json::json!({"status":"error","message":"missing_state_root","height":height,"head_hash":head_hash});
                return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
            }
            let root = match bytes32_from_hex(state_root_hex.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"bad_state_root_hex","detail":e,"height":height,"head_hash":head_hash,"state_root":state_root_hex});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let smt = StateSmt::new(storage.state_node_store());
            let k_allow = ft::k_ft_allowance(q.token_id, &owner, &spender);
            let amount = match smt.get_account(root, k_allow) {
                Ok(Some(st)) => match ft::decode_allowance_amount_v1(&st) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"ft_allowance_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => 0u128,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let decimals = match smt.get_account(root, ft::k_ft_meta(q.token_id)) {
                Ok(Some(st)) => ft::decode_meta_state_v1(&st).map(|m| m.decimals).unwrap_or(0),
                _ => 0,
            };
            let amount_dec = ft::format_ft_amount_atomic_to_decimal(amount, decimals);

            let body = serde_json::json!({"status":"ok","token_id":q.token_id,"owner":owner,"spender":spender,"amount":amount.to_string(),"amount_dec":amount_dec,"decimals":decimals});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let ft_frozen_v1 = warp::path!("api" / "v2" / "ft" / "frozen")
        .and(warp::get())
        .and(warp::query::<FtFrozenQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: FtFrozenQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::ft_api_frozen_read();
            let addr = normalize_pk_b64(&q.addr);
            let (height, head_hash, state_root_hex) = {
                let bc = lock_any!(ch);
                if let Some(last) = bc.chain.last() {
                    (last.index, last.hash.clone(), last.state_root.clone())
                } else {
                    (0u64, String::new(), String::new())
                }
            };

            if state_root_hex.trim().is_empty() {
                let body = serde_json::json!({"status":"error","message":"missing_state_root","height":height,"head_hash":head_hash});
                return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
            }
            let root = match bytes32_from_hex(state_root_hex.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"bad_state_root_hex","detail":e,"height":height,"head_hash":head_hash,"state_root":state_root_hex});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let smt = StateSmt::new(storage.state_node_store());
            let k_fr = ft::k_ft_frozen(q.token_id, &addr);
            let frozen = match smt.get_account(root, k_fr) {
                Ok(Some(st)) => match ft::decode_frozen_bool_v1(&st) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"ft_frozen_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => false,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let body = serde_json::json!({"status":"ok","token_id":q.token_id,"addr":addr,"frozen":frozen});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let ft_metrics_v1 = warp::path!("api" / "v2" / "ft" / "metrics")
        .and(warp::get())
        .and(
            warp::query::<FtMetricsQuery>()
                .or(warp::any().map(FtMetricsQuery::default))
                .unify(),
        )
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: FtMetricsQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::ft_api_metrics_read();
            let (tip_height, state_root_hex, params, blocks_len, recent_window, perf_ft) = {
                let bc = lock_any!(ch);
                let (tip_height, state_root_hex) = if let Some(last) = bc.chain.last() {
                    (last.index, last.state_root.clone())
                } else {
                    (0u64, String::new())
                };
                let params = bc.governance.as_ref().map(|g| g.params.clone());
                let recent_window = q.window.unwrap_or(128).clamp(1, 4096);
                let (recent_total_ft_txs, recent_ops) =
                    ft_recent_activity_from_blocks(&bc.chain, recent_window);
                let perf = crate::perf_metrics::snapshot();
                (
                    tip_height,
                    state_root_hex,
                    params,
                    bc.chain.len(),
                    (recent_total_ft_txs, recent_ops, recent_window),
                    perf,
                )
            };

            let total_tokens_created = match ft_total_tokens_created_from_state_root(&storage, &state_root_hex) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"ft_metrics_state_read_failed","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let (recent_total_ft_txs, recent_ops, recent_window) = recent_window;
            let activation_height = params.as_ref().map(|p| p.ft_activation_height).unwrap_or(u64::MAX);
            let create_fee_native = params.as_ref().map(|p| p.ft_create_fee_native).unwrap_or(0);
            let max_tokens_per_owner = params.as_ref().map(|p| p.ft_max_tokens_per_owner).unwrap_or(0);
            let create_cooldown_blocks = params.as_ref().map(|p| p.ft_create_cooldown_blocks).unwrap_or(0);
            let active = tip_height.saturating_add(1) >= activation_height;
            let window_from_height = tip_height.saturating_sub(recent_window.saturating_sub(1) as u64);

            let body = serde_json::json!({
                "status": "ok",
                "tip_height": tip_height,
                "chain_blocks": blocks_len,
                "ft": {
                    "active": active,
                    "activation_height": activation_height,
                    "create_fee_native": create_fee_native,
                    "max_tokens_per_owner": max_tokens_per_owner,
                    "create_cooldown_blocks": create_cooldown_blocks,
                    "total_tokens_created": total_tokens_created
                },
                "recent": {
                    "window_blocks": recent_window,
                    "from_height": window_from_height,
                    "to_height": tip_height,
                    "total_ft_txs": recent_total_ft_txs,
                    "ops": recent_ops
                },
                "api_counters": {
                    "token_reads": perf_ft.ft_api_token_reads,
                    "balance_reads": perf_ft.ft_api_balance_reads,
                    "allowance_reads": perf_ft.ft_api_allowance_reads,
                    "frozen_reads": perf_ft.ft_api_frozen_reads,
                    "metrics_reads": perf_ft.ft_api_metrics_reads
                }
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    // ------- NFT v1 (Gate 4B) read-only endpoints -------
    #[derive(Deserialize)]
    struct NftCollectionQuery {
        id: u64,
    }
    #[derive(Deserialize)]
    struct NftTokenQuery {
        collection_id: u64,
        serial: u64,
    }
    #[derive(Deserialize)]
    struct NftOwnerOfQuery {
        collection_id: u64,
        serial: u64,
    }
    #[derive(Deserialize)]
    struct NftApprovalQuery {
        collection_id: u64,
        serial: u64,
    }
    #[derive(Deserialize)]
    struct NftOperatorApprovalQuery {
        collection_id: u64,
        owner: String,
        operator: String,
    }
    #[derive(Deserialize)]
    struct NftWalletAssetsQuery {
        owner: String,
        cursor: Option<u64>,
        limit: Option<u64>,
    }
    #[derive(Deserialize)]
    struct NftOwnerCollectionsQuery {
        owner: String,
        cursor: Option<u64>,
        limit: Option<u64>,
    }
    #[derive(Deserialize)]
    struct NftCollectionTokensQuery {
        collection_id: u64,
        cursor: Option<u64>,
        limit: Option<u64>,
    }
    #[derive(Deserialize)]
    struct NftCollectionsQuery {
        cursor: Option<u64>,
        limit: Option<u64>,
    }
    #[derive(Deserialize)]
    struct NftRecentActivityQuery {
        window: Option<usize>,
        cursor: Option<u64>,
        limit: Option<u64>,
        collection_id: Option<u64>,
        owner: Option<String>,
    }
    #[derive(Default, Deserialize)]
    struct NftMetricsQuery {
        window: Option<usize>,
    }

    let nft_collection_v1 = warp::path!("api" / "v2" / "nft" / "collection")
        .and(warp::get())
        .and(warp::query::<NftCollectionQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftCollectionQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_collection_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;

            let smt = StateSmt::new(storage.state_node_store());
            let collection = match nft_collection_read_model_from_smt_v1(&smt, root, q.id) {
                Ok(v) => v,
                Err(e) if e.starts_with("nft_collection_not_found") => {
                    let body = serde_json::json!({"status":"error","message":"nft_collection_not_found","collection_id":q.id});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_collection_read_model_failed","detail":e,"collection_id":q.id});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let owner_for_links = collection.get("owner_b64").and_then(|v| v.as_str()).map(|v| v.to_string());
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "collection_id": q.id,
                "collection": collection,
                "links": nft_api_link_set_v1(q.id, None, owner_for_links.as_deref())
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_token_v1 = warp::path!("api" / "v2" / "nft" / "token")
        .and(warp::get())
        .and(warp::query::<NftTokenQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftTokenQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_token_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;

            let smt = StateSmt::new(storage.state_node_store());
            let token = match nft_token_read_model_from_smt_v1(&smt, root, q.collection_id, q.serial, ctx.finalized_height) {
                Ok(v) => v,
                Err(e) if e.starts_with("nft_token_not_found") || e.starts_with("nft_token_owner_missing") => {
                    let body = serde_json::json!({"status":"error","message":"nft_token_not_found","collection_id":q.collection_id,"serial":q.serial});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_token_read_model_failed","detail":e,"collection_id":q.collection_id,"serial":q.serial});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let owner_for_links = token.get("owner_b64").and_then(|v| v.as_str()).map(|v| v.to_string());
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "collection_id": q.collection_id,
                "serial": q.serial,
                "asset_id": nft::nft_asset_id_v1(q.collection_id, q.serial),
                "token": token,
                "links": nft_api_link_set_v1(q.collection_id, Some(q.serial), owner_for_links.as_deref())
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_owner_of_v1 = warp::path!("api" / "v2" / "nft" / "owner_of")
        .and(warp::get())
        .and(warp::query::<NftOwnerOfQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftOwnerOfQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_owner_of_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let token_meta = match smt.get_account(root, nft::k_nft_token_meta(q.collection_id, q.serial)) {
                Ok(Some(st)) => match nft::decode_token_meta_state_v1(&st) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_token_meta_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => {
                    let body = serde_json::json!({"status":"error","message":"nft_token_not_found","collection_id":q.collection_id,"serial":q.serial});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let effective_status = nft::nft_token_effective_status_v1(&token_meta, ctx.finalized_height);
            let owner = match smt.get_account(root, nft::k_nft_token_owner(q.collection_id, q.serial)) {
                Ok(Some(st)) => match nft::decode_token_owner_b64_v1(&st) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_token_owner_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) if matches!(token_meta.status, nft::NftTokenStatusV1::Burned | nft::NftTokenStatusV1::Revoked) => None,
                Ok(None) => {
                    let body = serde_json::json!({"status":"error","message":"nft_token_owner_missing","collection_id":q.collection_id,"serial":q.serial});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let owner_present = owner.is_some();
            let body = serde_json::json!({
                "status":"ok",
                "source":nft_public_read_source_json_v1(&ctx),
                "collection_id":q.collection_id,
                "serial":q.serial,
                "asset_id": nft::nft_asset_id_v1(q.collection_id, q.serial),
                "owner_b64":owner,
                "owner_present": owner_present,
                "stored_status": token_meta.status.as_str(),
                "effective_status": effective_status.as_str(),
                "token_status": effective_status.as_str(),
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_approval_v1 = warp::path!("api" / "v2" / "nft" / "approval")
        .and(warp::get())
        .and(warp::query::<NftApprovalQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftApprovalQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_approval_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let approved = match smt.get_account(root, nft::k_nft_token_approval(q.collection_id, q.serial)) {
                Ok(Some(st)) => match nft::decode_token_approval_b64_v1(&st) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_token_approval_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let body = serde_json::json!({"status":"ok","source":nft_public_read_source_json_v1(&ctx),"collection_id":q.collection_id,"serial":q.serial,"approved_b64":approved});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_operator_approval_v1 = warp::path!("api" / "v2" / "nft" / "operator_approval")
        .and(warp::get())
        .and(warp::query::<NftOperatorApprovalQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftOperatorApprovalQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_operator_approval_read();
            let owner = match nft::validate_nft_address_b64_v1("owner", &q.owner) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_owner_invalid","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let operator = match nft::validate_nft_address_b64_v1("operator", &q.operator) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_operator_invalid","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let approved = match smt.get_account(root, nft::k_nft_operator_approval(q.collection_id, &owner, &operator)) {
                Ok(Some(st)) => match nft::decode_bool_state_v1(&st) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_operator_approval_decode_failed","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                Ok(None) => false,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let body = serde_json::json!({"status":"ok","source":nft_public_read_source_json_v1(&ctx),"collection_id":q.collection_id,"owner_b64":owner,"operator_b64":operator,"approved":approved});
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_wallet_assets_v1 = warp::path!("api" / "v2" / "nft" / "wallet")
        .and(warp::get())
        .and(warp::query::<NftWalletAssetsQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftWalletAssetsQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_wallet_read();
            let owner = match nft::validate_nft_address_b64_v1("owner", &q.owner) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_owner_invalid","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let total = match smt.get_account(root, nft::k_nft_owner_token_count(&owner)) {
                Ok(Some(st)) => st.balance,
                Ok(None) => 0,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let cursor = q.cursor.unwrap_or(0).min(total);
            let limit = q.limit.unwrap_or(50).clamp(1, 200);
            let end = cursor.saturating_add(limit).min(total);
            let mut items = Vec::new();
            for idx in cursor..end {
                let st_ref = match smt.get_account(root, nft::k_nft_owner_token_item(&owner, idx)) {
                    Ok(Some(st)) => st,
                    Ok(None) => {
                        let body = serde_json::json!({"status":"error","message":"nft_owner_token_index_missing","owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let token_ref = match nft::decode_token_ref_state_v1(&st_ref) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_owner_token_index_decode_failed","detail":e,"owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let token = match nft_token_read_model_from_smt_v1(&smt, root, token_ref.collection_id, token_ref.serial, ctx.finalized_height) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_index_token_read_model_failed","detail":e,"collection_id":token_ref.collection_id,"serial":token_ref.serial,"owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let owner_link = token.get("owner_b64").and_then(|v| v.as_str()).map(|v| v.to_string());
                items.push(serde_json::json!({
                    "index": idx,
                    "collection_id": token_ref.collection_id,
                    "serial": token_ref.serial,
                    "asset_id": nft::nft_asset_id_v1(token_ref.collection_id, token_ref.serial),
                    "owner_b64": owner_link.clone().unwrap_or_else(|| owner.clone()),
                    "token": token,
                    "links": nft_api_link_set_v1(token_ref.collection_id, Some(token_ref.serial), owner_link.as_deref().or(Some(owner.as_str())))
                }));
            }
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "owner_b64":owner,
                "cursor":cursor,
                "limit":limit,
                "returned":items.len(),
                "total":total,
                "next_cursor": if end < total { serde_json::Value::from(end) } else { serde_json::Value::Null },
                "tokens": items
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_owner_collections_v1 = warp::path!("api" / "v2" / "nft" / "owner_collections")
        .and(warp::get())
        .and(warp::query::<NftOwnerCollectionsQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftOwnerCollectionsQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_owner_collection_read();
            let owner = match nft::validate_nft_address_b64_v1("owner", &q.owner) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_owner_invalid","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let total = match smt.get_account(root, nft::k_nft_owner_count(&owner)) {
                Ok(Some(st)) => st.balance,
                Ok(None) => 0,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let cursor = q.cursor.unwrap_or(0).min(total);
            let limit = q.limit.unwrap_or(50).clamp(1, 200);
            let end = cursor.saturating_add(limit).min(total);
            let mut items = Vec::new();
            for idx in cursor..end {
                let st_ref = match smt.get_account(root, nft::k_nft_owner_collection_item(&owner, idx)) {
                    Ok(Some(st)) => st,
                    Ok(None) => {
                        let body = serde_json::json!({"status":"error","message":"nft_owner_collection_index_missing","owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let collection_ref = match nft::decode_collection_ref_state_v1(&st_ref) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_owner_collection_index_decode_failed","detail":e,"owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let collection = match nft_collection_read_model_from_smt_v1(&smt, root, collection_ref.collection_id) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_index_collection_read_model_failed","detail":e,"collection_id":collection_ref.collection_id,"owner_b64":owner,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                items.push(serde_json::json!({"index":idx,"collection_id":collection_ref.collection_id,"collection":collection}));
            }
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "owner_b64":owner,
                "cursor":cursor,
                "limit":limit,
                "returned":items.len(),
                "total":total,
                "next_cursor": if end < total { serde_json::Value::from(end) } else { serde_json::Value::Null },
                "collections": items
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_collection_tokens_v1 = warp::path!("api" / "v2" / "nft" / "collection_tokens")
        .and(warp::get())
        .and(warp::query::<NftCollectionTokensQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftCollectionTokensQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_collection_token_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            match smt.get_account(root, nft::k_nft_collection_meta(q.collection_id)) {
                Ok(Some(st)) => {
                    if let Err(e) = nft::decode_collection_meta_state_v1(&st) {
                        let body = serde_json::json!({"status":"error","message":"nft_collection_meta_decode_failed","detail":e,"collection_id":q.collection_id});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                }
                Ok(None) => {
                    let body = serde_json::json!({"status":"error","message":"nft_collection_not_found","collection_id":q.collection_id});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            }
            let total = match smt.get_account(root, nft::k_nft_collection_token_count(q.collection_id)) {
                Ok(Some(st)) => st.balance,
                Ok(None) => 0,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let cursor = q.cursor.unwrap_or(0).min(total);
            let limit = q.limit.unwrap_or(50).clamp(1, 200);
            let end = cursor.saturating_add(limit).min(total);
            let mut items = Vec::new();
            for idx in cursor..end {
                let st_ref = match smt.get_account(root, nft::k_nft_collection_token_item(q.collection_id, idx)) {
                    Ok(Some(st)) => st,
                    Ok(None) => {
                        let body = serde_json::json!({"status":"error","message":"nft_collection_token_index_missing","collection_id":q.collection_id,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let token_ref = match nft::decode_token_ref_state_v1(&st_ref) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_collection_token_index_decode_failed","detail":e,"collection_id":q.collection_id,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let token = match nft_token_read_model_from_smt_v1(&smt, root, token_ref.collection_id, token_ref.serial, ctx.finalized_height) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_index_token_read_model_failed","detail":e,"collection_id":token_ref.collection_id,"serial":token_ref.serial,"index":idx});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                let owner_link = token.get("owner_b64").and_then(|v| v.as_str()).map(|v| v.to_string());
                items.push(serde_json::json!({
                    "index": idx,
                    "collection_id": token_ref.collection_id,
                    "serial": token_ref.serial,
                    "asset_id": nft::nft_asset_id_v1(token_ref.collection_id, token_ref.serial),
                    "owner_b64": owner_link.clone(),
                    "token": token,
                    "links": nft_api_link_set_v1(token_ref.collection_id, Some(token_ref.serial), owner_link.as_deref())
                }));
            }
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "collection_id":q.collection_id,
                "cursor":cursor,
                "limit":limit,
                "returned":items.len(),
                "total":total,
                "next_cursor": if end < total { serde_json::Value::from(end) } else { serde_json::Value::Null },
                "tokens": items
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_collections_v1 = warp::path!("api" / "v2" / "nft" / "collections")
        .and(warp::get())
        .and(warp::query::<NftCollectionsQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftCollectionsQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let root = ctx.finalized_root;
            let smt = StateSmt::new(storage.state_node_store());
            let next_collection_id = match smt.get_account(root, nft::k_nft_next_collection_id()) {
                Ok(Some(st)) => if st.balance == 0 { 1 } else { st.balance },
                Ok(None) => 1,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"smt_read_failed","detail":e.to_string()});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };
            let total = next_collection_id.saturating_sub(1);
            let cursor = q.cursor.unwrap_or(1).max(1);
            let limit = q.limit.unwrap_or(50).clamp(1, 200);
            let mut id = cursor;
            let mut returned = 0u64;
            let mut items = Vec::new();
            while id < next_collection_id && returned < limit {
                match nft_collection_read_model_from_smt_v1(&smt, root, id) {
                    Ok(v) => {
                        items.push(v);
                        returned = returned.saturating_add(1);
                    }
                    Err(e) if e.starts_with("nft_collection_not_found") => {}
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_collection_read_model_failed","detail":e,"collection_id":id});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                }
                id = id.saturating_add(1);
            }
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "cursor": cursor,
                "limit": limit,
                "returned": items.len(),
                "total_created": total,
                "next_cursor": if id < next_collection_id { serde_json::Value::from(id) } else { serde_json::Value::Null },
                "collections": items,
                "links": {
                    "self": format!("/api/v2/nft/collections?cursor={}&limit={}", cursor, limit),
                    "recent_activity": "/api/v2/nft/recent_activity?window=256&cursor=0&limit=50"
                }
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_recent_activity_v1 = warp::path!("api" / "v2" / "nft" / "recent_activity")
        .and(warp::get())
        .and(warp::query::<NftRecentActivityQuery>())
        .and(with_chain(chain.clone()))
        .map(|q: NftRecentActivityQuery, ch: SharedChain| {
            let owner = match q.owner.as_ref() {
                Some(raw) => match nft::validate_nft_address_b64_v1("owner", raw) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        let body = serde_json::json!({"status":"error","message":"nft_owner_invalid","detail":e});
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                },
                None => None,
            };
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let window = q.window.unwrap_or(256).clamp(1, 4096);
            let cursor = q.cursor.unwrap_or(0);
            let limit = q.limit.unwrap_or(50).clamp(1, 200);
            let (total_matched, items) = nft_recent_activity_items_from_blocks_v1(
                &ctx.finalized_blocks,
                window,
                cursor,
                limit,
                q.collection_id,
                owner.as_deref(),
            );
            let tip_height = ctx.tip_height;
            let returned = items.len();
            let next_cursor = cursor.saturating_add(returned as u64);
            let body = serde_json::json!({
                "status":"ok",
                "source": nft_public_read_source_json_v1(&ctx),
                "tip_height": tip_height,
                "window_blocks": window,
                "cursor": cursor,
                "limit": limit,
                "returned": returned,
                "total_matched": total_matched,
                "next_cursor": if next_cursor < total_matched { serde_json::Value::from(next_cursor) } else { serde_json::Value::Null },
                "filters": {
                    "collection_id": q.collection_id,
                    "owner_b64": owner,
                },
                "events": items,
            });
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    let nft_policy_v1 = warp::path!("api" / "v2" / "nft" / "policy")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(
            |chain: SharedChain| match nft_finalized_policy_snapshot_for_api_v1(&chain) {
                Ok(snap) => warp::reply::with_header(
                    warp::reply::json(&nft_policy_json_from_snapshot_v1(&snap)),
                    "Cache-Control",
                    "no-store",
                )
                .into_response(),
                Err(e) => nft_policy_unavailable_response_v1(e),
            },
        );

    let nft_metrics_v1 = warp::path!("api" / "v2" / "nft" / "metrics")
        .and(warp::get())
        .and(
            warp::query::<NftMetricsQuery>()
                .or(warp::any().map(NftMetricsQuery::default))
                .unify(),
        )
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|q: NftMetricsQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            crate::perf_metrics::nft_api_metrics_read();
            let ctx = match nft_finalized_public_read_context_v1(&ch) {
                Ok(ctx) => ctx,
                Err(e) => return nft_public_read_context_error_reply_v1(e),
            };
            let (governance_height, params, policy_hash, perf_nft) = {
                let bc = lock_any!(ch);
                let (governance_height, params) = match bc.finalized_governance_params_for_api_v1() {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({
                            "status":"error",
                            "message":"nft_metrics_governance_finalized_read_failed",
                            "detail": e,
                            "source_commitment":"finalized"
                        });
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                if let Err(e) = crate::governance::validate_nft_governance_policy_v1(&params) {
                    let body = serde_json::json!({
                        "status":"error",
                        "message":"nft_metrics_governance_policy_invalid",
                        "detail": e,
                        "source_commitment":"finalized"
                    });
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
                let policy_hash = match nft_governance_policy_hash_v1(&params) {
                    Ok(v) => v,
                    Err(e) => {
                        let body = serde_json::json!({
                            "status":"error",
                            "message":"nft_metrics_governance_policy_hash_failed",
                            "detail": e,
                            "source_commitment":"finalized"
                        });
                        return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                    }
                };
                (governance_height, params, policy_hash, crate::perf_metrics::snapshot())
            };
            if governance_height != ctx.finalized_height {
                let body = serde_json::json!({
                    "status":"error",
                    "message":"nft_metrics_governance_finalized_height_mismatch",
                    "governance_height": governance_height,
                    "finalized_height": ctx.finalized_height,
                    "source_commitment":"finalized"
                });
                return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
            }
            let tip_height = ctx.tip_height;
            let finalized_height = ctx.finalized_height;
            let state_root_hex = ctx.finalized_state_root.clone();
            let blocks_len = ctx.finalized_blocks.len();
            let recent_window = q.window.unwrap_or(128).clamp(1, 4096);
            let recent_window = {
                let (recent_total_nft_txs, recent_ops) =
                    nft_recent_activity_from_blocks(&ctx.finalized_blocks, recent_window);
                (recent_total_nft_txs, recent_ops, recent_window)
            };

            let total_collections_created = match nft_total_collections_created_from_state_root(&storage, &state_root_hex) {
                Ok(v) => v,
                Err(e) => {
                    let body = serde_json::json!({"status":"error","message":"nft_metrics_state_read_failed","detail":e});
                    return warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store");
                }
            };

            let (recent_total_nft_txs, recent_ops, recent_window) = recent_window;
            let activation_height = params.nft_activation_height;
            let create_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::CreateCollection {
                    symbol: "NFT".to_string(),
                    name: "NFT".to_string(),
                    max_supply: None,
                    base_uri: String::new(),
                    metadata_hash: [1u8; 32],
                    mintable: true,
                    burnable: false,
                    asset_type: crate::nft::NftAssetTypeV1::Collectible,
                    transfer_policy: crate::nft::NftTransferPolicyV1::Transferable,
                    revocable: false,
                },
                Some(&params),
            );
            let max_collections_per_owner = params.nft_max_collections_per_owner;
            let create_cooldown_blocks = params.nft_create_cooldown_blocks;
            let enabled = nft_policy_enabled_v1(Some(&params));
            let active = enabled && finalized_height >= activation_height;
            let window_from_height = finalized_height.saturating_sub(recent_window.saturating_sub(1) as u64);

            let mint_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::Mint {
                    collection_id: 1,
                    to_b64: crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
                    token_uri: String::new(),
                    metadata_hash: [1u8; 32],
                    expires_at_height: None,
                },
                Some(&params),
            );
            let transfer_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::Transfer {
                    collection_id: 1,
                    serial: 1,
                    to_b64: crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
                },
                Some(&params),
            );
            let approval_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::Approve {
                    collection_id: 1,
                    serial: 1,
                    approved_b64: None,
                },
                Some(&params),
            );
            let burn_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::Burn {
                    collection_id: 1,
                    serial: 1,
                },
                Some(&params),
            );
            let revoke_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::Revoke {
                    collection_id: 1,
                    serial: 1,
                },
                Some(&params),
            );
            let metadata_update_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::SetTokenUri {
                    collection_id: 1,
                    serial: 1,
                    token_uri: "ipfs://sample".to_string(),
                    metadata_hash: [1u8; 32],
                },
                Some(&params),
            );
            let freeze_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::FreezeToken {
                    collection_id: 1,
                    serial: 1,
                    frozen: true,
                },
                Some(&params),
            );
            let policy_update_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::SetCollectionPolicy {
                    collection_id: 1,
                    mintable: true,
                    burnable: true,
                    transfer_policy: crate::nft::NftTransferPolicyV1::Transferable,
                    revocable: true,
                },
                Some(&params),
            );
            let issuer_update_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::SetIssuer {
                    collection_id: 1,
                    issuer_b64: crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
                },
                Some(&params),
            );
            let pause_fee_native = nft_policy_fee_for_op_v1(
                &crate::nft::NftOpV1::SetPaused {
                    collection_id: 1,
                    paused: false,
                },
                Some(&params),
            );
            let governance = json_object_for_api_v1([
                ("source", nft_governance_public_read_source_json_v1(&ctx, governance_height)),
                ("policy_hash", json_value_for_api_v1(policy_hash)),
                ("activation_height", json_value_for_api_v1(activation_height)),
                ("enabled", json_value_for_api_v1(enabled)),
                ("public_create_enabled", json_value_for_api_v1(params.nft_public_create_enabled)),
                ("public_mint_enabled", json_value_for_api_v1(params.nft_public_mint_enabled)),
                ("public_transfer_enabled", json_value_for_api_v1(params.nft_public_transfer_enabled)),
                ("public_approval_enabled", json_value_for_api_v1(params.nft_public_approval_enabled)),
                ("public_burn_enabled", json_value_for_api_v1(params.nft_public_burn_enabled)),
                ("public_revoke_enabled", json_value_for_api_v1(params.nft_public_revoke_enabled)),
                ("public_metadata_update_enabled", json_value_for_api_v1(params.nft_public_metadata_update_enabled)),
                ("public_freeze_enabled", json_value_for_api_v1(params.nft_public_freeze_enabled)),
                ("public_policy_update_enabled", json_value_for_api_v1(params.nft_public_policy_update_enabled)),
                ("public_issuer_update_enabled", json_value_for_api_v1(params.nft_public_issuer_update_enabled)),
                ("public_pause_enabled", json_value_for_api_v1(params.nft_public_pause_enabled)),
                ("metadata_hash_required", json_value_for_api_v1(params.nft_metadata_hash_required)),
                ("max_memo_bytes", json_value_for_api_v1(params.nft_max_memo_bytes)),
                ("max_uri_bytes", json_value_for_api_v1(params.nft_max_uri_bytes)),
                ("max_name_bytes", json_value_for_api_v1(params.nft_max_name_bytes)),
                ("max_symbol_bytes", json_value_for_api_v1(params.nft_max_symbol_bytes)),
                ("max_tokens_per_collection", json_value_for_api_v1(params.nft_max_tokens_per_collection)),
                ("max_tokens_per_owner", json_value_for_api_v1(params.nft_max_tokens_per_owner)),
                ("create_fee_native", json_value_for_api_v1(create_fee_native)),
                ("mint_fee_native", json_value_for_api_v1(mint_fee_native)),
                ("transfer_fee_native", json_value_for_api_v1(transfer_fee_native)),
                ("approval_fee_native", json_value_for_api_v1(approval_fee_native)),
                ("burn_fee_native", json_value_for_api_v1(burn_fee_native)),
                ("revoke_fee_native", json_value_for_api_v1(revoke_fee_native)),
                ("metadata_update_fee_native", json_value_for_api_v1(metadata_update_fee_native)),
                ("freeze_fee_native", json_value_for_api_v1(freeze_fee_native)),
                ("policy_update_fee_native", json_value_for_api_v1(policy_update_fee_native)),
                ("issuer_update_fee_native", json_value_for_api_v1(issuer_update_fee_native)),
                ("pause_fee_native", json_value_for_api_v1(pause_fee_native)),
                ("max_collections_per_owner", json_value_for_api_v1(max_collections_per_owner)),
                ("create_cooldown_blocks", json_value_for_api_v1(create_cooldown_blocks)),
            ]);
            let totals = json_object_for_api_v1([(
                "collections_created",
                json_value_for_api_v1(total_collections_created),
            )]);
            let recent_activity = json_object_for_api_v1([
                ("window_blocks", json_value_for_api_v1(recent_window)),
                ("from_height", json_value_for_api_v1(window_from_height)),
                ("to_height", json_value_for_api_v1(finalized_height)),
                ("total_nft_events", json_value_for_api_v1(recent_total_nft_txs)),
                ("total_nft_txs", json_value_for_api_v1(recent_total_nft_txs)),
                ("ops", json_value_for_api_v1(recent_ops)),
            ]);
            let api_counters = json_object_for_api_v1([
                ("collection_reads", json_value_for_api_v1(perf_nft.nft_api_collection_reads)),
                ("token_reads", json_value_for_api_v1(perf_nft.nft_api_token_reads)),
                ("owner_of_reads", json_value_for_api_v1(perf_nft.nft_api_owner_of_reads)),
                ("approval_reads", json_value_for_api_v1(perf_nft.nft_api_approval_reads)),
                ("operator_approval_reads", json_value_for_api_v1(perf_nft.nft_api_operator_approval_reads)),
                ("wallet_reads", json_value_for_api_v1(perf_nft.nft_api_wallet_reads)),
                ("owner_collection_reads", json_value_for_api_v1(perf_nft.nft_api_owner_collection_reads)),
                ("collection_token_reads", json_value_for_api_v1(perf_nft.nft_api_collection_token_reads)),
                ("metrics_reads", json_value_for_api_v1(perf_nft.nft_api_metrics_reads)),
            ]);
            let body = json_object_for_api_v1([
                ("status", json_value_for_api_v1("ok")),
                ("source", nft_public_read_source_json_v1(&ctx)),
                ("module", json_value_for_api_v1("nft_v1")),
                ("active", json_value_for_api_v1(active)),
                ("tip_height", json_value_for_api_v1(tip_height)),
                ("chain_blocks", json_value_for_api_v1(blocks_len)),
                ("governance", governance),
                ("totals", totals),
                ("recent_activity", recent_activity),
                ("api_counters", api_counters),
            ]);
            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    // Compat: vecchio path (se ti serve /api/governance/state)
    let governance_state = warp::path!("api" / "governance" / "state")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_gov_state".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/governance/state"
            );
            let bc = lock_any!(ch);

            let gov_json = match bc.governance.as_ref() {
                Some(g) => serde_json::to_value(g)
                    .unwrap_or_else(|_| serde_json::json!({"error":"governance_serialize_failed"})),
                None => serde_json::json!(null),
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "governance": gov_json
            }))
        });

    // ------- PoS (Phase 2) state snapshot (read-only) -------
    // GET /api/v2/pos/state
    // Lightweight + no-store: used by Phase2 gate scripts to compare state_root/epoch/seed/committee.
    // GET /api/v2/pos/leader?slot=... [&epoch=...]
    // Deterministic leader preview derived from seed(epoch) + slot + committee(epoch).
    #[derive(Deserialize)]
    struct PosLeaderQuery {
        slot: u64,
        #[serde(default)]
        epoch: Option<u64>,
    }

    let pos_leader_v2 = warp::path!("api" / "v2" / "pos" / "leader")
        .and(warp::get())
        .and(warp::query::<PosLeaderQuery>())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(
            |q: PosLeaderQuery, ch: SharedChain, storage: std::sync::Arc<DbStore>| {
                let (height, head_hash, state_root_hex) = {
                    let bc = lock_any!(ch);
                    if let Some(last) = bc.chain.last() {
                        (last.index, last.hash.clone(), last.state_root.clone())
                    } else {
                        (0u64, String::new(), String::new())
                    }
                };

                if state_root_hex.trim().is_empty() {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": "missing_state_root",
                        "height": height,
                        "head_hash": head_hash
                    });
                    return warp::reply::with_header(
                        warp::reply::json(&body),
                        "Cache-Control",
                        "no-store",
                    );
                }

                let root = match bytes32_from_hex(state_root_hex.trim()) {
                    Ok(r) => r,
                    Err(e) => {
                        let body = serde_json::json!({
                            "status": "error",
                            "message": "bad_state_root_hex",
                            "detail": e,
                            "height": height,
                            "head_hash": head_hash,
                            "state_root": state_root_hex
                        });
                        return warp::reply::with_header(
                            warp::reply::json(&body),
                            "Cache-Control",
                            "no-store",
                        );
                    }
                };

                let smt = StateSmt::new(storage.state_node_store());

                let params_st = match smt.get_account(root, staking::k_stake_params()) {
                    Ok(Some(st)) => st,
                    Ok(None) => {
                        let body = serde_json::json!({
                            "status": "error",
                            "message": "missing_pos_params",
                            "height": height,
                            "head_hash": head_hash,
                            "state_root": state_root_hex
                        });
                        return warp::reply::with_header(
                            warp::reply::json(&body),
                            "Cache-Control",
                            "no-store",
                        );
                    }
                    Err(e) => {
                        let body = serde_json::json!({
                            "status": "error",
                            "message": "smt_read_failed",
                            "detail": e,
                            "height": height,
                            "head_hash": head_hash,
                            "state_root": state_root_hex
                        });
                        return warp::reply::with_header(
                            warp::reply::json(&body),
                            "Cache-Control",
                            "no-store",
                        );
                    }
                };

                let params = match staking::decode_params_state(&params_st) {
                    Ok(p) => p,
                    Err(e) => {
                        let body = serde_json::json!({
                            "status": "error",
                            "message": "pos_params_decode_failed",
                            "detail": e,
                            "height": height,
                            "head_hash": head_hash,
                            "state_root": state_root_hex
                        });
                        return warp::reply::with_header(
                            warp::reply::json(&body),
                            "Cache-Control",
                            "no-store",
                        );
                    }
                };

                let epoch_len = params.epoch_len.max(1);
                let epoch: u64 = q.epoch.unwrap_or(q.slot / epoch_len);

                // seed(epoch): if missing and epoch==0, use seed0
                let seed_epoch: [u8; 32] = smt
                    .get_account(root, pos::k_seed(epoch))
                    .ok()
                    .flatten()
                    .and_then(|st| pos::decode_seed_state(&st).ok())
                    .map(|s| s.seed)
                    .unwrap_or_else(|| {
                        pos::seed0_from_network_id(crate::chain_identity::network_id())
                    });

                let committee = smt
                    .get_account(root, pos::k_committee(epoch))
                    .ok()
                    .flatten()
                    .and_then(|st| pos::decode_committee_state(&st).ok())
                    .map(|c| c.members_pk_hex)
                    .unwrap_or_default();

                let leader = pos::leader_for_slot_v1(&seed_epoch, q.slot, &committee);

                let body = serde_json::json!({
                    "status": "ok",
                    "height": height,
                    "head_hash": head_hash,
                    "state_root": state_root_hex,
                    "slot": q.slot,
                    "epoch": epoch,
                    "epoch_len": epoch_len,
                    "seed_hex": hex::encode(seed_epoch),
                    "committee_size": committee.len() as u64,
                    "leader_pk_hex": leader
                });

                warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
            },
        );

    let pos_state_v2 = warp::path!("api" / "v2" / "pos" / "state")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .map(|ch: SharedChain, storage: std::sync::Arc<DbStore>| {
            let (height, head_hash, state_root_hex) = {
                let bc = lock_any!(ch);
                if let Some(last) = bc.chain.last() {
                    (last.index, last.hash.clone(), last.state_root.clone())
                } else {
                    (0u64, String::new(), String::new())
                }
            };

            if state_root_hex.trim().is_empty() {
                let body = serde_json::json!({
                    "status": "error",
                    "message": "missing_state_root",
                    "height": height,
                    "head_hash": head_hash
                });
                return warp::reply::with_header(
                    warp::reply::json(&body),
                    "Cache-Control",
                    "no-store",
                );
            }

            let root = match bytes32_from_hex(state_root_hex.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": "bad_state_root_hex",
                        "detail": e,
                        "height": height,
                        "head_hash": head_hash,
                        "state_root": state_root_hex
                    });
                    return warp::reply::with_header(
                        warp::reply::json(&body),
                        "Cache-Control",
                        "no-store",
                    );
                }
            };

            let smt = StateSmt::new(storage.state_node_store());

            let params_st = match smt.get_account(root, staking::k_stake_params()) {
                Ok(Some(st)) => st,
                Ok(None) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": "missing_pos_params",
                        "height": height,
                        "head_hash": head_hash,
                        "state_root": state_root_hex
                    });
                    return warp::reply::with_header(
                        warp::reply::json(&body),
                        "Cache-Control",
                        "no-store",
                    );
                }
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": "smt_read_failed",
                        "detail": e,
                        "height": height,
                        "head_hash": head_hash,
                        "state_root": state_root_hex
                    });
                    return warp::reply::with_header(
                        warp::reply::json(&body),
                        "Cache-Control",
                        "no-store",
                    );
                }
            };

            let params = match staking::decode_params_state(&params_st) {
                Ok(p) => p,
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "message": "pos_params_decode_failed",
                        "detail": e,
                        "height": height,
                        "head_hash": head_hash,
                        "state_root": state_root_hex
                    });
                    return warp::reply::with_header(
                        warp::reply::json(&body),
                        "Cache-Control",
                        "no-store",
                    );
                }
            };

            let epoch_len = params.epoch_len.max(1);
            let current_epoch: u64 = height / epoch_len;
            let next_epoch: u64 = current_epoch.saturating_add(1);
            let height_in_epoch: u64 = height % epoch_len;
            let epoch_end_height: u64 = next_epoch.saturating_mul(epoch_len).saturating_sub(1);

            // seed/current + seed/next (if present)
            let seed_cur_hex = smt
                .get_account(root, pos::k_seed(current_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_seed_state(&st).ok())
                .map(|s| hex::encode(s.seed));
            let seed_next_hex = smt
                .get_account(root, pos::k_seed(next_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_seed_state(&st).ok())
                .map(|s| hex::encode(s.seed));

            // committee/current + committee/next (if present)
            let committee_cur = smt
                .get_account(root, pos::k_committee(current_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_committee_state(&st).ok())
                .map(|c| c.members_pk_hex)
                .unwrap_or_default();
            let committee_next = smt
                .get_account(root, pos::k_committee(next_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_committee_state(&st).ok())
                .map(|c| c.members_pk_hex)
                .unwrap_or_default();

            // randao agg for current epoch
            let agg = smt
                .get_account(root, pos::k_randao_agg(current_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_randao_agg_state(&st).ok())
                .unwrap_or_default();
            let committers = smt
                .get_account(root, pos::k_randao_committers(current_epoch))
                .ok()
                .flatten()
                .and_then(|st| pos::decode_committers_state(&st).ok())
                .map(|c| c.pk_hex.len() as u64)
                .unwrap_or(0);

            let source = json_object_for_api_v1([
                ("source_commitment", json_value_for_api_v1("tip")),
                ("height", json_value_for_api_v1(height)),
                ("head_hash", json_value_for_api_v1(head_hash.clone())),
                ("state_root", json_value_for_api_v1(state_root_hex.clone())),
                (
                    "read_model_version",
                    json_value_for_api_v1("pos_state_read_model_v1"),
                ),
            ]);
            let pos_params = json_object_for_api_v1([
                ("min_stake", json_value_for_api_v1(params.min_stake)),
                (
                    "unbonding_epochs",
                    json_value_for_api_v1(params.unbonding_epochs),
                ),
                ("epoch_len", json_value_for_api_v1(params.epoch_len)),
                (
                    "committee_size",
                    json_value_for_api_v1(params.committee_size),
                ),
            ]);
            let epoch_json = json_object_for_api_v1([
                ("current", json_value_for_api_v1(current_epoch)),
                ("next", json_value_for_api_v1(next_epoch)),
                ("epoch_len", json_value_for_api_v1(epoch_len)),
                ("height_in_epoch", json_value_for_api_v1(height_in_epoch)),
                ("epoch_end_height", json_value_for_api_v1(epoch_end_height)),
            ]);
            let seed = json_object_for_api_v1([
                ("current_epoch", json_value_for_api_v1(current_epoch)),
                ("current_hex", json_value_for_api_v1(seed_cur_hex)),
                ("next_epoch", json_value_for_api_v1(next_epoch)),
                ("next_hex", json_value_for_api_v1(seed_next_hex)),
            ]);
            let committee_json = json_object_for_api_v1([
                ("current_epoch", json_value_for_api_v1(current_epoch)),
                ("current", json_value_for_api_v1(committee_cur)),
                ("next_epoch", json_value_for_api_v1(next_epoch)),
                ("next", json_value_for_api_v1(committee_next)),
            ]);
            let randao = json_object_for_api_v1([
                ("epoch", json_value_for_api_v1(current_epoch)),
                ("committers", json_value_for_api_v1(committers)),
                ("reveals", json_value_for_api_v1(agg.reveals as u64)),
                ("xor_hex", json_value_for_api_v1(hex::encode(agg.xor))),
            ]);
            let body = json_object_for_api_v1([
                ("status", json_value_for_api_v1("ok")),
                ("source", source),
                ("height", json_value_for_api_v1(height)),
                ("head_hash", json_value_for_api_v1(head_hash)),
                ("state_root", json_value_for_api_v1(state_root_hex)),
                ("pos_params", pos_params),
                ("epoch", epoch_json),
                ("seed", seed),
                ("committee", committee_json),
                ("randao", randao),
            ]);

            warp::reply::with_header(warp::reply::json(&body), "Cache-Control", "no-store")
        });

    // ------- Governance: validators (compat + v2) -------
    let governance_validators_v2 = warp::path!("api" / "v2" / "governance" / "validators")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_gov_validators_v2".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/governance/validators"
            );
            let bc = lock_any!(ch);

            let validators_json = match bc.governance.as_ref() {
                Some(g) => serde_json::to_value(&g.validator_set).unwrap_or_else(
                    |_| serde_json::json!({"error":"validator_set_serialize_failed"}),
                ),
                None => serde_json::json!(null),
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "validator_set": validators_json
            }))
        });

    // Compat: vecchio path (se ti serve /api/governance/validators)
    let governance_validators = warp::path!("api" / "governance" / "validators")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_gov_validators".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/governance/validators"
            );
            let bc = lock_any!(ch);

            let validators_json = match bc.governance.as_ref() {
                Some(g) => serde_json::to_value(&g.validator_set).unwrap_or_else(
                    |_| serde_json::json!({"error":"validator_set_serialize_failed"}),
                ),
                None => serde_json::json!(null),
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "validator_set": validators_json
            }))
        });

    // ------- Governance: ops log (audit trail) -------
    let governance_ops_log_v2 = warp::path!("api" / "v2" / "governance" / "ops-log")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_gov_ops_log_v2".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/governance/ops-log"
            );
            let bc = lock_any!(ch);
            let ops_json = match bc.governance.as_ref() {
                Some(g) => serde_json::to_value(&g.validator_ops_log)
                    .unwrap_or_else(|_| serde_json::json!({"error":"ops_log_serialize_failed"})),
                None => serde_json::json!(null),
            };
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "ops_log": ops_json
            }))
        });

    #[derive(Deserialize)]
    struct GovernanceExpectedProposerQuery {
        height: u64,
        slot: u64,
        #[serde(default)]
        round: Option<u32>,
    }

    // ------- Governance: consensus diagnostics -------
    let governance_consensus_status_v2 =
        warp::path!("api" / "v2" / "governance" / "consensus" / "status")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_gov_consensus_status_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/governance/consensus/status"
                );
                let bc = lock_any!(ch);
                match bc.governance_consensus_status_for_next_block() {
                    Ok(view) => warp::reply::with_header(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "height": view.height,
                            "at_height": view.at_height,
                            "epoch": view.epoch,
                            "resolution_mode": view.resolution_mode,
                            "committee_members": view.committee_members,
                            "committee_size": view.committee_size,
                            "expected_proposer_now": view.expected_proposer_now,
                            "slot": view.slot
                        })),
                        "Cache-Control",
                        "no-store",
                    ),
                    Err(e) => warp::reply::with_header(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e
                        })),
                        "Cache-Control",
                        "no-store",
                    ),
                }
            });

    let governance_expected_proposer_v2 =
        warp::path!("api" / "v2" / "governance" / "proposer" / "expected")
            .and(warp::get())
            .and(warp::query::<GovernanceExpectedProposerQuery>())
            .and(with_chain(chain.clone()))
            .map(|q: GovernanceExpectedProposerQuery, ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_gov_expected_proposer_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/governance/proposer/expected"
                );
                let bc = lock_any!(ch);
                match bc.governance_expected_proposer_view(q.height, q.slot, q.round.unwrap_or(0)) {
                    Ok(view) => warp::reply::with_header(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "height": view.height,
                            "epoch": view.epoch,
                            "resolution_mode": view.resolution_mode,
                            "committee_members": view.committee_members,
                            "committee_size": view.committee_size,
                            "proposer": view.proposer,
                            "slot": view.slot,
                            "round": view.round
                        })),
                        "Cache-Control",
                        "no-store",
                    ),
                    Err(e) => warp::reply::with_header(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e,
                            "height": q.height,
                            "slot": q.slot,
                            "round": q.round.unwrap_or(0)
                        })),
                        "Cache-Control",
                        "no-store",
                    ),
                }
            });

    // ------- Governance: validators status (active / revoked / jailed) -------
    let governance_validators_status_v2 =
        warp::path!("api" / "v2" / "governance" / "validators" / "status")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_gov_validators_status_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/governance/validators/status"
                );
                let bc = lock_any!(ch);
                let height = bc.chain.last().map(|b| b.index).unwrap_or(0u64);
                let at_height = height.saturating_add(1);

                let items = bc.governance_validator_status_views_for_next_block();
                let local_runtime = bc.local_consensus_runtime_view_for_next_block();

                warp::reply::with_header(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "height": height,
                        "at_height": at_height,
                        "local_runtime": local_runtime,
                        "items": items
                    })),
                    "Cache-Control",
                    "no-store",
                )
            });

    let governance_validators_status_finalized_v2 =
        warp::path!("api" / "v2" / "governance" / "validators" / "status" / "finalized")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                ng_trace_throttle!(
                    key: "api_gov_validators_status_finalized_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/governance/validators/status/finalized"
                );
                let bc = lock_any!(ch);
                let snap = bc.governance_validator_status_views_for_finalized_state();

                let body = serde_json::json!({
                    "status": if snap.source_state_available { "ok" } else { "degraded" },
                    "e2_contract_version": snap.e2_contract_version,
                    "finalized_height": snap.finalized_height,
                    "finalized_hash": snap.finalized_hash,
                    "at_height": snap.at_height,
                    "source_state_available": snap.source_state_available,
                    "unavailable_reason": snap.unavailable_reason,
                    "items": snap.items
                });

                let status = if snap.source_state_available {
                    warp::http::StatusCode::OK
                } else {
                    warp::http::StatusCode::SERVICE_UNAVAILABLE
                };

                warp::reply::with_header(
                    warp::reply::with_status(warp::reply::json(&body), status),
                    "Cache-Control",
                    "no-store",
                )
            });

    let e2_contract_v2 = warp::path!("api" / "v2" / "e2" / "contract")
        .and(warp::get())
        .map(|| {
            ng_trace_throttle!(
                key: "api_e2_contract_v2".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/e2/contract"
            );
            let snap = E2ContractSnapshotV1::current();
            warp::reply::with_header(
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "contract": snap
                })),
                "Cache-Control",
                "no-store",
            )
        });

    let e2_orders_v2 = warp::path!("api" / "v2" / "e2" / "orders")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            ng_trace_throttle!(
                key: "api_e2_orders_v2".to_string(),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/e2/orders"
            );
            let result = {
                let bc = lock_any!(ch);
                compute_orders_snapshot_v2_for_finalized_chain(&bc)
            };
            match result {
                Ok(snapshot) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "snapshot": snapshot
                        })),
                        warp::http::StatusCode::OK,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
                Err(e) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
            }
        });

    let e2_order_events_v2 = warp::path!("api" / "v2" / "e2" / "order-events")
        .and(warp::get())
        .and(warp::query::<E2OrderEventsQuery>())
        .and(with_chain(chain.clone()))
        .map(|query: E2OrderEventsQuery, ch: SharedChain| {
            ng_trace_throttle!(
                key: format!(
                    "api_e2_order_events_v2:{}:{}",
                    query.from_height.unwrap_or(0),
                    query.to_height.unwrap_or(0)
                ),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/e2/order-events"
            );
            let result = {
                let bc = lock_any!(ch);
                let (finalized_height, _) = bc.finalized_view();
                let from_height = query.from_height.unwrap_or(0);
                let to_height = query.to_height.unwrap_or(finalized_height);
                compute_order_events_snapshot_for_finalized_chain(&bc, from_height, to_height)
            };
            match result {
                Ok(snapshot) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "snapshot": snapshot
                        })),
                        warp::http::StatusCode::OK,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
                Err(e) if e.starts_with("invalid_range:") => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
                Err(e) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
            }
        });

    let e2_order_by_id_v2 = warp::path!("api" / "v2" / "e2" / "orders" / String)
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|order_id: String, ch: SharedChain| {
            ng_trace_throttle!(
                key: format!("api_e2_order_by_id_v2:{}", order_id),
                every_ms: 30000,
                target: "api.req",
                "GET /api/v2/e2/orders/{order_id}"
            );
            let result = {
                let bc = lock_any!(ch);
                compute_order_lookup_v2_for_finalized_chain(&bc, &order_id)
            };
            match result {
                Ok(lookup) if lookup.found => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "lookup": lookup
                        })),
                        warp::http::StatusCode::OK,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
                Ok(lookup) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "not_found",
                            "lookup": lookup
                        })),
                        warp::http::StatusCode::NOT_FOUND,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
                Err(e) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                    "Cache-Control",
                    "no-store",
                ),
            }
        });

    let e2_worker_admission_v2 = warp::path!("api" / "v2" / "e2" / "worker" / "admission" / String)
        .and(warp::get())
        .and(warp::query::<E2WorkerAdmissionQuery>())
        .and(with_chain(chain.clone()))
        .map(
            |worker_pubkey: String, query: E2WorkerAdmissionQuery, ch: SharedChain| {
                ng_trace_throttle!(
                    key: format!("api_e2_worker_admission_v2:{}:{}", worker_pubkey, query.order_id),
                    every_ms: 30000,
                    target: "api.req",
                    "GET /api/v2/e2/worker/admission/{worker_pubkey}"
                );
                let result = {
                    let bc = lock_any!(ch);
                    evaluate_compute_worker_admission_for_finalized_order_v1(
                        &bc,
                        &worker_pubkey,
                        &query.order_id,
                    )
                };
                match result {
                    Ok(decision) => {
                        let accepted = decision.accepted;
                        warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": if accepted { "ok" } else { "denied" },
                                    "decision": decision
                                })),
                                if accepted {
                                    warp::http::StatusCode::OK
                                } else {
                                    warp::http::StatusCode::UNPROCESSABLE_ENTITY
                                },
                            ),
                            "Cache-Control",
                            "no-store",
                        )
                    }
                    Err(e) if e.contains("order_not_found") => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "not_found",
                                "message": e
                            })),
                            warp::http::StatusCode::NOT_FOUND,
                        ),
                        "Cache-Control",
                        "no-store",
                    ),
                    Err(e) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ),
                        "Cache-Control",
                        "no-store",
                    ),
                }
            },
        );

    let e2_worker_register_build_unsigned_v1 = warp::path!("api" / "v2" / "e2" / "worker" / "register" / "build_unsigned")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES * 2))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and_then(
            |body: serde_json::Value,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>| async move {
                let Some(body_obj) = body.as_object() else {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "request_body_must_be_object"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                };
                let required_str = |field: &str| -> Result<String, String> {
                    body_obj
                        .get(field)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| format!("missing_{field}"))
                };
                let optional_str = |field: &str| -> Option<String> {
                    body_obj
                        .get(field)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                };

                let from_b64 = match required_str("from") {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let operator_wallet_pubkey = optional_str("operator_wallet_pubkey")
                    .unwrap_or_else(|| from_b64.clone());
                let from_hex = match crate::keyfmt::pk_hex_from_any(&from_b64) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"error",
                                "message":"invalid_from",
                                "error":e.to_string()
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let operator_hex = match crate::keyfmt::pk_hex_from_any(&operator_wallet_pubkey) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"error",
                                "message":"invalid_operator_wallet_pubkey",
                                "error":e.to_string()
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                if from_hex != operator_hex {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"error",
                            "message":"e2_worker_self_register_sender_operator_mismatch"
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                let worker_node_pubkey = match required_str("worker_node_pubkey") {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let capabilities_commitment_hash = match required_str("capabilities_commitment_hash") {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let runtime_class = match required_str("runtime_class") {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let (expected_chain_id, expected_genesis_hash, base_fee, admission_height) = {
                    let bc = lock_any!(chain);
                    let tip_h = bc.chain.last().map(|b| b.index).unwrap_or(0);
                    (
                        crate::chain_identity::chain_id().to_string(),
                        bc.genesis_hash.clone(),
                        bc.base_fee_per_tx(),
                        tip_h.saturating_add(1),
                    )
                };
                let chain_id = optional_str("chain_id").unwrap_or_else(|| expected_chain_id.clone());
                let genesis_hash = optional_str("genesis_hash").unwrap_or_else(|| expected_genesis_hash.clone());
                let worker_signature = optional_str("worker_signature").unwrap_or_default();
                let payload = crate::compute_contract::E2WorkerSelfRegistrationPayloadV1 {
                    format_version: crate::compute_contract::E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1.to_string(),
                    worker_node_pubkey: worker_node_pubkey.clone(),
                    operator_wallet_pubkey: operator_wallet_pubkey.clone(),
                    worker_signature: worker_signature.clone(),
                    capabilities_commitment_hash: capabilities_commitment_hash.clone(),
                    runtime_class: runtime_class.clone(),
                    chain_id,
                    genesis_hash,
                    region: optional_str("region"),
                    country: optional_str("country"),
                };
                if let Err(e) = payload.validate_unsigned_contract_v1(&expected_chain_id, &expected_genesis_hash) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"e2_worker_self_register_rejected",
                            "message":e
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let signing_bytes = match crate::compute_contract::e2_worker_self_registration_signing_bytes_v1(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"e2_worker_self_register_rejected",
                                "message":e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ))
                    }
                };
                if worker_signature.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"ok",
                            "surface":"e2_worker_self_register_signing_request_v1",
                            "step":"worker_signature_required",
                            "build_unsigned_path":"/api/v2/e2/worker/register/build_unsigned",
                            "submit_path":"/api/v2/tx/submit_signed",
                            "worker_signature_context":"E2_WORKER_SELF_REGISTER_V1",
                            "worker_signing_bytes_hex":hex::encode(&signing_bytes),
                            "worker_signing_bytes_sha256":hex::encode(Sha256::digest(&signing_bytes)),
                            "payload_without_worker_signature":payload,
                            "required_next_field":"worker_signature"
                        })),
                        warp::http::StatusCode::OK,
                    ));
                }
                if let Err(e) = payload.validate_contract_v1(&expected_chain_id, &expected_genesis_hash) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"e2_worker_self_register_rejected",
                            "message":e
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                let priority_fee = body_obj
                    .get("priority_fee")
                    .and_then(parse_amount_atomic)
                    .unwrap_or(0);
                let requested_max_fee = body_obj.get("max_fee_per_tx").and_then(parse_amount_atomic);
                let effective_max_fee = match requested_max_fee {
                    Some(v) if v < base_fee => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"invalid_max_fee_per_tx",
                                "required_at_least":base_fee,
                                "provided":v
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ))
                    }
                    Some(v) => v,
                    None => base_fee.saturating_add(priority_fee),
                };
                let admission = snapshot_sender_admission_state(&chain, &mp, &from_b64);
                let expected_nonce = admission.expected_next_nonce();
                let nonce = body_obj
                    .get("nonce")
                    .and_then(parse_amount_atomic)
                    .unwrap_or(expected_nonce);
                if nonce < expected_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"replay_or_old_nonce",
                            "expected_nonce":expected_nonce,
                            "provided_nonce":nonce
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                if nonce > expected_nonce.saturating_add(MAX_NONCE_GAP) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"nonce_gap_too_large",
                            "expected_nonce":expected_nonce,
                            "provided_nonce":nonce,
                            "max_gap":MAX_NONCE_GAP
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let memo_value = serde_json::json!({
                    "v":1,
                    "op":crate::compute_contract::E2_WORKER_SELF_REGISTER_OP_V1,
                    "format_version":crate::compute_contract::E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1,
                    "worker_node_pubkey":payload.worker_node_pubkey,
                    "operator_wallet_pubkey":payload.operator_wallet_pubkey,
                    "worker_signature":payload.worker_signature,
                    "capabilities_commitment_hash":payload.capabilities_commitment_hash,
                    "runtime_class":payload.runtime_class,
                    "chain_id":payload.chain_id,
                    "genesis_hash":payload.genesis_hash,
                    "region":payload.region,
                    "country":payload.country,
                });
                let memo = match serde_json::to_string(&memo_value) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"error",
                                "message":"memo_serialize_failed",
                                "error":e.to_string()
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                };
                let mut tx_preview = Transaction {
                    sender: from_b64.clone(),
                    receiver: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo.clone()),
                };
                tx_preview.hash = tx_preview.calculate_hash();
                {
                    let bc = lock_any!(chain);
                    if let Err(e) = validate_compute_tx_syntax(&tx_preview) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"e2_worker_self_register_rejected",
                                "message":e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                    if let Err(e) = validate_compute_tx_worker_admission_v1(&bc, &tx_preview, admission_height) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"e2_worker_self_register_rejected",
                                "message":e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                    if let Err(e) = bc.validate_e2_worker_self_registration_tx_v1(&tx_preview) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"e2_worker_self_register_rejected",
                                "message":e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                }
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    effective_max_fee,
                    0,
                    effective_max_fee,
                    0,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }
                let tx_payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: from_b64.clone(),
                    to: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    memo: Some(memo.clone()),
                };
                let signing_string = canonical_signing_string(&tx_payload);
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status":"ok",
                        "surface":"e2_worker_self_register_unsigned_tx_v1",
                        "path_class":"standard_worker_self_register_tx",
                        "build_unsigned_path":"/api/v2/e2/worker/register/build_unsigned",
                        "submit_path":"/api/v2/tx/submit_signed",
                        "payload":tx_payload,
                        "canonical_signing_string":signing_string,
                        "public_key_b64_field":"public_key_b64",
                        "signature_b64_field":"signature_b64",
                        "tx_hash":tx_preview.hash,
                        "memo":memo_value,
                        "memo_sha256":hex::encode(Sha256::digest(memo.as_bytes())),
                        "fee":{
                            "base_fee_per_tx":base_fee,
                            "max_fee_per_tx":effective_max_fee,
                            "required_total_native":effective_max_fee
                        },
                        "nonce":{
                            "selected":nonce,
                            "expected_next":expected_nonce
                        },
                        "admission_height":admission_height
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    let e2_worker_evidence_build_unsigned_v1 = warp::path!("api" / "v2" / "e2" / "worker" / "evidence" / "build_unsigned")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES * 8))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and_then(
            |body: serde_json::Value,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>| async move {
                let body_obj = match body.as_object() {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "request_body_must_be_object"
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let Some(evidence_value) = body_obj.get("evidence") else {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "missing_evidence"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                };
                let evidence: crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1 =
                    match serde_json::from_value(evidence_value.clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "invalid_evidence",
                                    "error": e.to_string()
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    };
                let evidence_is_v2 = matches!(
                    &evidence,
                    crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1::V2(_)
                );
                let ev_legacy = evidence.legacy_projection_v1();
                let bootstrap_probe_preflight =
                    e2_worker_evidence_bootstrap_probe_preflight_v1(&ev_legacy);
                let bootstrap_probe_errors = bootstrap_probe_preflight
                    .get("errors")
                    .and_then(|v| v.as_array())
                    .map(|v| v.len())
                    .unwrap_or(0);
                let is_bootstrap_probe_shape = evidence_is_v2
                    && bootstrap_probe_preflight
                        .get("is_bootstrap_probe_shape")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                if is_bootstrap_probe_shape && bootstrap_probe_errors > 0 {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "surface": "e2_worker_evidence_unsigned_tx_v1",
                            "message": "bootstrap_probe_evidence_preflight_failed",
                            "preflight": bootstrap_probe_preflight,
                            "repair": {
                                "job_kind": "probe:v1",
                                "jobKind": "probe:v1",
                                "order_id": bootstrap_probe_preflight.get("expected_order_id").cloned().unwrap_or(serde_json::Value::Null),
                                "orderId": bootstrap_probe_preflight.get("expectedOrderId").cloned().unwrap_or(serde_json::Value::Null),
                                "note": "Rebuild and sign the evidence with the canonical job_kind and order_id before calling build_unsigned. The API does not rewrite signed evidence."
                            }
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let from_b64 = body_obj
                    .get("from")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| ev_legacy.attester_pubkey.clone());
                let from_hex = match crate::keyfmt::pk_hex_from_any(&from_b64) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "invalid_from",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let attester_hex = match crate::keyfmt::pk_hex_from_any(&ev_legacy.attester_pubkey) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "invalid_evidence_attester",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                if from_hex != attester_hex {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "e2_worker_evidence_submit_sender_attester_mismatch"
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let priority_fee = body_obj
                    .get("priority_fee")
                    .and_then(parse_amount_atomic)
                    .unwrap_or(0);
                let requested_max_fee = body_obj.get("max_fee_per_tx").and_then(parse_amount_atomic);
                let admission = snapshot_sender_admission_state(&chain, &mp, &from_b64);
                let base_fee = admission.base_fee_per_tx;
                let effective_max_fee = match requested_max_fee {
                    Some(v) if v < base_fee => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_max_fee_per_tx",
                                "required_at_least": base_fee,
                                "provided": v
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ))
                    }
                    Some(v) => v,
                    None => base_fee.saturating_add(priority_fee),
                };
                let expected_nonce = admission.expected_next_nonce();
                let nonce = body_obj
                    .get("nonce")
                    .and_then(parse_amount_atomic)
                    .unwrap_or(expected_nonce);
                if nonce < expected_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "replay_or_old_nonce",
                            "expected_nonce": expected_nonce,
                            "provided_nonce": nonce
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                let max_allowed_nonce = match expected_nonce.checked_add(MAX_NONCE_GAP) {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nonce_gap_overflow",
                                "expected_nonce": expected_nonce,
                                "max_gap": MAX_NONCE_GAP
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                if nonce > max_allowed_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nonce_gap_too_large",
                            "expected_nonce": expected_nonce,
                            "provided_nonce": nonce,
                            "max_gap": MAX_NONCE_GAP
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let memo_value = serde_json::json!({
                    "v": 1,
                    "op": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_OP_V1,
                    "format_version": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_PAYLOAD_VERSION_V1,
                    "evidence": evidence,
                });
                let memo = match serde_json::to_string(&memo_value) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "memo_serialize_failed",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                };
                let mut tx_preview = Transaction {
                    sender: from_b64.clone(),
                    receiver: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo.clone()),
                };
                tx_preview.hash = tx_preview.calculate_hash();
                {
                    let bc = lock_any!(chain);
                    if let Err(e) = bc.validate_e2_worker_standard_evidence_tx_v1(&tx_preview) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "e2_worker_evidence_rejected",
                                "message": e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                }
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    effective_max_fee,
                    0,
                    effective_max_fee,
                    0,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }
                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: from_b64.clone(),
                    to: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    memo: Some(memo.clone()),
                };
                let signing_string = canonical_signing_string(&payload);
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "surface": "e2_worker_evidence_unsigned_tx_v1",
                        "path_class": "standard_evidence_tx",
                        "bootstrap_probe_preflight": bootstrap_probe_preflight.clone(),
                        "bootstrapProbePreflight": bootstrap_probe_preflight,
                        "build_unsigned_path": "/api/v2/e2/worker/evidence/build_unsigned",
                        "submit_path": "/api/v2/tx/submit_signed",
                        "payload": payload,
                        "canonical_signing_string": signing_string,
                        "public_key_b64_field": "public_key_b64",
                        "signature_b64_field": "signature_b64",
                        "tx_hash": tx_preview.hash,
                        "memo": memo_value,
                        "memo_sha256": hex::encode(Sha256::digest(memo.as_bytes())),
                        "fee": {
                            "base_fee_per_tx": base_fee,
                            "max_fee_per_tx": effective_max_fee,
                            "required_total_native": effective_max_fee
                        },
                        "nonce": {
                            "selected": nonce,
                            "expected_next": expected_nonce
                        }
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    let e2_worker_bootstrap_probe_contract_route_v1 =
        warp::path!("api" / "v2" / "e2" / "worker" / "evidence" / "bootstrap_probe" / "contract")
            .and(warp::get())
            .map(|| {
                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "contract": e2_worker_bootstrap_probe_contract_v1(),
                    })),
                    warp::http::StatusCode::OK,
                )
            });

    // ------- EPN history (Step 35 - stub, lista vuota) -------
    let epn_history = warp::path!("api" / "v2" / "epn" / "history")
        .and(warp::get())
        .map(|| {
            // In futuro qui ci sarà la lista vera delle EPN
            warp::reply::json(&serde_json::json!({
                            "status": "ok",
            "items": Vec::<serde_json::Value>::new()

            }))
        });

    // ------- Invio TX firmata dal NODO -------
    // (Questo blocco è corretto)
    let ui_send_tx = warp::path!("api" / "v2" / "wallet" / "send_from_node")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES)) // ⬅️ limite 4KB
        .and(warp::body::json())
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))

   .and_then(
    |_guard: (), body: serde_json::Value,
     mp: Arc<Mutex<Mempool>>,
     p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
     chain: Arc<Mutex<Blockchain>>,
     _storage: Arc<DbStore>,
     signer: Arc<SigningKey>,
     pk_b64: String| async move {


                let receiver = normalize_pk_b64(body["receiver"].as_str().unwrap_or(""));
                let amount = parse_amount_atomic(&body["amount"]).unwrap_or(0);
                let body_max_fee = parse_amount_atomic(&body["max_fee_per_tx"]).unwrap_or(0);
                let body_priority_fee = parse_amount_atomic(&body["priority_fee"]).unwrap_or(0);

                if receiver.is_empty() || amount == 0 {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"invalid_data",
                            "message":"missing_or_invalid_fields",
                            "hint":"amount can be an integer (atomic units) or a decimal string like 0.00057"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let pk_b64 = pk_b64.trim().to_string();

                // Snapshot chain+mempool values without nested locks.
                let admission = snapshot_sender_admission_state(&chain, &mp, &pk_b64);
                let base_fee = admission.base_fee_per_tx;

                // Allow caller to specify max_fee_per_tx or priority_fee, but never below consensus floor.
                let requested_max_fee = if body_max_fee > 0 {
                    body_max_fee
                } else {
                    base_fee.saturating_add(body_priority_fee)
                };
                let effective_max_fee = requested_max_fee.max(base_fee);

                // Server-signed tx must reserve the effective fee (>= base fee)
                // and cannot overspend versus already-pending mempool reservations.
                let total_required = amount.saturating_add(effective_max_fee);
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    total_required,
                    amount,
                    effective_max_fee,
                    0,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }

                let expected_nonce = admission.expected_next_nonce();

               let sk = signer.as_ref();


                let mut tx = Transaction {
                    sender: pk_b64.clone(),
                    receiver,
                    amount,
                    max_fee_per_tx: effective_max_fee, // caller fee (or priority fee) with base fee floor
                    nonce: expected_nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: None,
                };

                // 🔒 Firma canonica come nel wallet v2
                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: tx.sender.clone(), // = public_key_b64 del nodo
                    to: tx.receiver.clone(),
                    amount: tx.amount,
                    max_fee_per_tx: tx.max_fee_per_tx, // must cover base fee
                    nonce: tx.nonce,
                    memo: None,
                };

                let msg = canonical_signing_string(&payload);
                let sig = sk.sign(msg.as_bytes());
                tx.signature = STANDARD.encode(sig.to_bytes());
                tx.hash = tx.calculate_hash();

                // 🔐 Step 53 – firewall fee minimo (security)
                if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "fee_too_low_for_security",
                            "required_min_fee": fee_err.required_min_fee,
                            "provided_max_fee_per_tx": fee_err.provided_max_fee,
                            "tx_size_bytes": fee_err.tx_size_bytes
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                if tx.verify_signature() {
                    // STEP 49 — rispetta i limiti del mempool
                    // STEP 49 — rispetta i limiti del mempool
                    let mut mp_lock = lock_any!(mp);
                    let accepted = mp_lock.add(tx.clone());

                    if !accepted {
                        let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) =
                            mp_lock.limits_snapshot();
                        let cur_size = mp_lock.len();
                        let cur_bytes = mp_lock.total_bytes();
                        drop(mp_lock);

                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "rejected",
                                "reason": "mempool_limits",
                                "mempool": {
                                    "size": cur_size as u64,
                                    "total_bytes": cur_bytes as u64
                                },
                                "limits": {
                                    "max_mempool_size": max_size as u64,
                                    "max_tx_per_sender": max_tx_per_sender as u64,
                                    "max_mempool_bytes": max_bytes as u64,
                                    "tx_ttl_secs": tx_ttl_secs
                                }
                            })),
                            warp::http::StatusCode::TOO_MANY_REQUESTS,
                        ));
                    }

                    drop(mp_lock);

                    let _ = p2p.send(NetMsg::NewTx(tx.clone()));

                    Ok::<_, warp::Rejection>(warp::reply::with_status(warp::reply::json(&serde_json::json!({
                        "status":"ok",
                        "tx_hash": tx.hash,
                        "sender": pk_b64,
                        "nonce_used": expected_nonce,
                        "max_fee_per_tx": effective_max_fee
                    })), warp::http::StatusCode::OK))
                } else {
                    Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"invalid_signature_creation"})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            },
        );

    // ------- FT v1: invio TX "system-op" firmata dal NODO (admin-only) -------
    // POST /api/v2/ft/send_from_node
    // Body examples:
    // {"op":"create_token","symbol":"GEMS","decimals":0,"max_supply":"1000000","initial_supply":"1000","mintable":true,"burnable":true,"freeze_enabled":true}
    // {"op":"transfer","token_id":1,"to":"<addr_b64>","amount":"25"}
    let ft_send_from_node = warp::path!("api" / "v2" / "ft" / "send_from_node")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))
        .and_then(
            |_guard: (),
             body: serde_json::Value,
             mp: Arc<Mutex<Mempool>>,
             p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
             chain: Arc<Mutex<Blockchain>>,
             storage: std::sync::Arc<DbStore>,
             signer: Arc<SigningKey>,
             pk_b64: String| async move {
                let op = body["op"].as_str().unwrap_or("").to_string();
                if op.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_data",
                            "message": "missing_op",
                            "hint": "op must be one of: create_token, transfer, mint, burn, approve, transfer_from, pause, freeze"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let allow_before_activation = body
                    .get("allow_before_activation")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Normalize base64 fields that might be passed via query/JSON ("+" may become space)
                let norm_b64 = |s: &str| normalize_pk_b64(s);

                // Snapshot chain values
                let pk_b64 = pk_b64.trim().to_string();
                let (tip_h, state_root_hex, base_fee, _last_chain_nonce, _current_balance, ft_act_h, ft_create_fee) = {
                    let bc = lock_any!(chain);
                    let tip_h = bc.chain.last().map(|b| b.index).unwrap_or(0);
                    let state_root_hex = bc
                        .chain
                        .last()
                        .map(|b| b.state_root.clone())
                        .unwrap_or_else(String::new);
                    let base_fee = bc.base_fee_per_tx();
                    let last_chain_nonce = bc.get_last_nonce(&pk_b64);
                    let bal_i128 = bc.get_balance(&pk_b64);
                    let current_balance = if bal_i128 < 0 { 0 } else { bal_i128 as u64 };

                    let gov_act = bc
                        .governance
                        .as_ref()
                        .map(|g| g.params.ft_activation_height)
                        .unwrap_or(u64::MAX);
                    let ft_act_h = std::env::var("NEWGEN_FT_ACTIVATION_HEIGHT")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(gov_act);

                    let gov_fee = bc
                        .governance
                        .as_ref()
                        .map(|g| g.params.ft_create_fee_native)
                        .unwrap_or(0);
                    let ft_create_fee = std::env::var("NEWGEN_FT_CREATE_FEE_NATIVE")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(gov_fee);

                    (tip_h, state_root_hex, base_fee, last_chain_nonce, current_balance, ft_act_h, ft_create_fee)
                };

                // FT amount parsing: accept decimal strings using token decimals (no floats).
                // - If `<field>_atomic` is provided, it is treated as atomic units (u128).
                // - Otherwise `<field>` is interpreted as a human amount (e.g. "5.50" or "5") and scaled by 10^decimals.
                let ft_token_decimals = |token_id: u64| -> Result<u8, String> {
                    if token_id == 0 {
                        return Err("invalid_token_id".to_string());
                    }
                    if state_root_hex.trim().is_empty() {
                        return Err("missing_state_root".to_string());
                    }
                    let root = bytes32_from_hex(state_root_hex.trim())
                        .map_err(|_| "bad_state_root_hex".to_string())?;
                    let smt = StateSmt::new(storage.state_node_store());
                    let st_meta = smt
                        .get_account(root, ft::k_ft_meta(token_id))
                        .map_err(|_| "smt_read_failed".to_string())?
                        .ok_or_else(|| "ft_token_not_found".to_string())?;
                    let meta = ft::decode_meta_state_v1(&st_meta)
                        .map_err(|_| "ft_meta_decode_failed".to_string())?;
                    Ok(meta.decimals)
                };

                let parse_ft_amount_value = |val: &serde_json::Value, decimals: u8| -> Result<u128, String> {
                    if val.is_u64() {
                        let whole = val.as_u64().unwrap() as u128;
                        let scale = ft::ft_scale_u128(decimals)?;
                        return whole
                            .checked_mul(scale)
                            .ok_or_else(|| "amount_overflow".to_string());
                    }
                    if val.is_string() {
                        let s0 = val.as_str().unwrap().trim();
                        if s0.is_empty() {
                            return Err("empty_amount".to_string());
                        }
                        if s0.contains('.') || s0.contains(',') {
                            return ft::parse_ft_amount_decimal_to_atomic(s0, decimals);
                        }
                        let whole: u128 = s0
                            .parse::<u128>()
                            .map_err(|_| "invalid_u128_decimal".to_string())?;
                        let scale = ft::ft_scale_u128(decimals)?;
                        return whole
                            .checked_mul(scale)
                            .ok_or_else(|| "amount_overflow".to_string());
                    }
                    Err("missing_or_invalid_field".to_string())
                };

                let parse_ft_amount_field = |v: &serde_json::Value, key: &str, decimals: u8| -> Result<u128, String> {
                    let atomic_key = format!("{}_atomic", key);
                    if let Some(x) = v.get(&atomic_key) {
                        return match x {
                            x if x.is_u64() => Ok(x.as_u64().unwrap() as u128),
                            x if x.is_string() => x
                                .as_str()
                                .unwrap()
                                .trim()
                                .parse::<u128>()
                                .map_err(|_| format!("invalid_u128_decimal: {}", atomic_key)),
                            _ => Err(format!("missing_or_invalid_field: {}", atomic_key)),
                        };
                    }
                    let x = v.get(key).ok_or_else(|| format!("missing_or_invalid_field: {}", key))?;
                    parse_ft_amount_value(x, decimals).map_err(|e| format!("{}_{}", key, e))
                };

                let parse_ft_amount_field_opt = |v: &serde_json::Value, key: &str, decimals: u8| -> Result<Option<u128>, String> {
                    match v.get(key) {
                        None => Ok(None),
                        Some(x) if x.is_null() => Ok(None),
                        Some(_) => Ok(Some(parse_ft_amount_field(v, key, decimals)?)),
                    }
                };



                if !allow_before_activation && tip_h.saturating_add(1) < ft_act_h {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ft_not_activated",
                            "message": "FT v1 is not activated at this height",
                            "tip_height": tip_h,
                            "ft_activation_height": ft_act_h,
                            "hint": "set ft_activation_height or pass allow_before_activation=true for dev testing"
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }

                // Fees (same policy as /wallet/send_from_node)
                let body_max_fee = parse_amount_atomic(&body["max_fee_per_tx"]).unwrap_or(0);
                let body_priority_fee = parse_amount_atomic(&body["priority_fee"]).unwrap_or(0);
                let requested_max_fee = if body_max_fee > 0 {
                    body_max_fee
                } else {
                    base_fee.saturating_add(body_priority_fee)
                };
                let effective_max_fee = requested_max_fee.max(base_fee);

                let extra_native = if op == "create_token" { ft_create_fee } else { 0 };
                let total_required = effective_max_fee.saturating_add(extra_native);
                let admission = snapshot_sender_admission_state(&chain, &mp, &pk_b64);
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    total_required,
                    0,
                    effective_max_fee,
                    extra_native,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }

                let expected_nonce = admission.expected_next_nonce();

                // Build deterministic memo JSON in a fixed key order
                let memo_v = match op.as_str() {
                    "create_token" => {
                        let symbol = body["symbol"].as_str().unwrap_or("").trim().to_string();
                        let decimals_u64 = body["decimals"].as_u64().unwrap_or(0);
                        if decimals_u64 > 18 {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"invalid_data","message":"decimals_out_of_range","max":18})),
                                warp::http::StatusCode::BAD_REQUEST,
                            ));
                        }
                        let decimals = decimals_u64 as u8;
                        let max_supply = parse_ft_amount_field_opt(&body, "max_supply", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let initial_supply = match body.get("initial_supply") {
                            None => 0u128,
                            Some(x) if x.is_null() => 0u128,
                            Some(_) => parse_ft_amount_field(&body, "initial_supply", decimals)
                                .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?,
                        };
                        let mintable = body
                            .get("mintable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        let burnable = body
                            .get("burnable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        let freeze_enabled = body
                            .get("freeze_enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let metadata_hash_hex = body
                            .get("metadata_hash_hex")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();

                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_CREATE,
                            "op": "create_token",
                            "symbol": symbol,
                            "decimals": decimals,
                            "max_supply": max_supply.map(|x| x.to_string()),
                            "initial_supply": initial_supply.to_string(),
                            "mintable": mintable,
                            "burnable": burnable,
                            "freeze_enabled": freeze_enabled,
                            "metadata_hash_hex": metadata_hash_hex
                        })
                    }
                    "transfer" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let to_b64 = norm_b64(body["to"].as_str().unwrap_or(""));
                        let decimals = ft_token_decimals(token_id)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let amount = parse_ft_amount_field(&body, "amount", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_TRANSFER,
                            "op": "transfer",
                            "token_id": token_id,
                            "to": to_b64,
                            "amount": amount.to_string()
                        })
                    }
                    "mint" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let to_b64 = norm_b64(body["to"].as_str().unwrap_or(""));
                        let decimals = ft_token_decimals(token_id)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let amount = parse_ft_amount_field(&body, "amount", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_MINT,
                            "op": "mint",
                            "token_id": token_id,
                            "to": to_b64,
                            "amount": amount.to_string()
                        })
                    }
                    "burn" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let decimals = ft_token_decimals(token_id)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let amount = parse_ft_amount_field(&body, "amount", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_BURN,
                            "op": "burn",
                            "token_id": token_id,
                            "amount": amount.to_string()
                        })
                    }
                    "approve" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let spender_b64 = norm_b64(body["spender"].as_str().unwrap_or(""));
                        let decimals = ft_token_decimals(token_id)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let amount = parse_ft_amount_field(&body, "amount", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_APPROVE,
                            "op": "approve",
                            "token_id": token_id,
                            "spender": spender_b64,
                            "amount": amount.to_string()
                        })
                    }
                    "transfer_from" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let from_b64 = norm_b64(body["from"].as_str().unwrap_or(""));
                        let to_b64 = norm_b64(body["to"].as_str().unwrap_or(""));
                        let decimals = ft_token_decimals(token_id)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        let amount = parse_ft_amount_field(&body, "amount", decimals)
                            .map_err(|_e| warp::reject::custom(ApiError::InvalidData))?;
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_TRANSFER_FROM,
                            "op": "transfer_from",
                            "token_id": token_id,
                            "from": from_b64,
                            "to": to_b64,
                            "amount": amount.to_string()
                        })
                    }
                    "pause" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let paused = body.get("paused").and_then(|v| v.as_bool()).unwrap_or(true);
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_PAUSE,
                            "op": "pause",
                            "token_id": token_id,
                            "paused": paused
                        })
                    }
                    "freeze" => {
                        let token_id = body["token_id"].as_u64().unwrap_or(0);
                        let addr_b64 = norm_b64(body["addr"].as_str().unwrap_or(""));
                        let frozen = body.get("frozen").and_then(|v| v.as_bool()).unwrap_or(true);
                        serde_json::json!({
                            "v": 1,
                            "ctx": ft::CTX_FT_FREEZE,
                            "op": "freeze",
                            "token_id": token_id,
                            "addr": addr_b64,
                            "frozen": frozen
                        })
                    }
                    _ => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_data",
                                "message": "unknown_op",
                                "op": op
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ));
                    }
                };

                let memo_str = match serde_json::to_string(&memo_v) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "memo_serialize_failed",
                                "detail": e.to_string()
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }
                };

                let sk = signer.as_ref();

                let mut tx = Transaction {
                    sender: pk_b64.clone(),
                    receiver: ft::FT_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce: expected_nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo_str.clone()),
                };

                // Canonical signature (includes memo)
                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: tx.sender.clone(),
                    to: tx.receiver.clone(),
                    amount: tx.amount,
                    max_fee_per_tx: tx.max_fee_per_tx,
                    nonce: tx.nonce,
                    memo: tx.memo.clone(),
                };
                let msg = canonical_signing_string(&payload);
                let sig = sk.sign(msg.as_bytes());
                tx.signature = STANDARD.encode(sig.to_bytes());
                tx.hash = tx.calculate_hash();

                // Security: minimal fee floor check
                if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "fee_too_low_for_security",
                            "required_min_fee": fee_err.required_min_fee,
                            "provided_max_fee_per_tx": fee_err.provided_max_fee,
                            "tx_size_bytes": fee_err.tx_size_bytes
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                // Syntax validation (should always pass since we build memo, but keep defense-in-depth)
                if let Err(e) = ft::validate_ft_tx_syntax(&tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_data",
                            "message": "ft_memo_invalid",
                            "detail": e
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                if !tx.verify_signature() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"invalid_signature_creation"})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                }

                // Add to mempool with limits
                let mut mp_lock = lock_any!(mp);
                let accepted = mp_lock.add(tx.clone());
                if !accepted {
                    let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) = mp_lock.limits_snapshot();
                    let cur_size = mp_lock.len();
                    let cur_bytes = mp_lock.total_bytes();
                    drop(mp_lock);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "rejected",
                            "reason": "mempool_limits",
                            "mempool": {"size": cur_size as u64, "total_bytes": cur_bytes as u64},
                            "limits": {
                                "max_mempool_size": max_size as u64,
                                "max_tx_per_sender": max_tx_per_sender as u64,
                                "max_mempool_bytes": max_bytes as u64,
                                "tx_ttl_secs": tx_ttl_secs
                            }
                        })),
                        warp::http::StatusCode::TOO_MANY_REQUESTS,
                    ));
                }
                drop(mp_lock);

                let _ = p2p.send(NetMsg::NewTx(tx.clone()));
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status":"ok",
                        "tx_hash": tx.hash,
                        "sender": pk_b64,
                        "nonce_used": expected_nonce,
                        "max_fee_per_tx": effective_max_fee,
                        "ft_create_fee_native": extra_native,
                        "required_total_native": total_required,
                        "ft_activation_height": ft_act_h,
                        "memo": serde_json::from_str::<serde_json::Value>(&memo_str).unwrap_or(serde_json::Value::Null)
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    // ------- NFT v1: wallet pubblico non-custodial -------
    // POST /api/v2/nft/estimate_fee
    // Non-custodial NFT fee/policy estimator. It never signs and never mutates state.
    let nft_estimate_fee_v1 = warp::path!("api" / "v2" / "nft" / "estimate_fee")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and_then(
            |body: serde_json::Value,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>| async move {
                let body_obj = match body.as_object() {
                    Some(v) => v,
                    None => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_request_not_object", "request body must be a JSON object")),
                };
                let from_raw = match nft_api_required_nonempty_str_raw_v1(body_obj, "from") {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_from", e)),
                };
                let from_b64 = match nft::validate_nft_address_b64_v1("from", &from_raw) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_from", e)),
                };
                if let Err(e) = nft_api_reject_unsupported_public_field_v1(body_obj, "allow_before_activation") {
                    return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_unsupported_field", e));
                }
                let op = match nft_api_parse_op_from_body_v1(body_obj, &["from", "max_fee_per_tx", "priority_fee"]) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_operation", e)),
                };
                let memo_str = match nft::nft_memo_json_v1(&op) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_memo_invalid", e)),
                };
                let policy_snapshot = match nft_finalized_policy_snapshot_for_api_v1(&chain) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_policy_unavailable",
                                "message": e,
                                "policy_source_commitment": "finalized"
                            })),
                            warp::http::StatusCode::PRECONDITION_FAILED,
                        ));
                    }
                };
                let tip_h = policy_snapshot.tip_height;
                let base_fee = policy_snapshot.base_fee_per_tx;
                let nft_act_h = policy_snapshot.params.nft_activation_height;
                let nft_params = Some(policy_snapshot.params.clone());
                let policy_source = nft_policy_source_json_from_snapshot_v1(&policy_snapshot);
                let admission_height = tip_h.saturating_add(1);
                if admission_height < nft_act_h {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_not_activated",
                            "message": "NFT v1 is not activated at this height",
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                if let crate::nft::NftOpV1::Mint { expires_at_height: Some(exp), .. } = &op {
                    if *exp <= admission_height {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_invalid_expires_at_height",
                            format!("expires_at_height must be greater than next inclusion height: expires_at_height={} next_height={}", exp, admission_height),
                        ));
                    }
                }
                if let Err(e) = nft_policy_validate_request_v1(&op, &memo_str, nft_params.as_ref()) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_policy_rejected",
                            "message": e,
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                let priority_fee = match nft_api_optional_u64_v1(body_obj, "priority_fee") {
                    Ok(v) => v.unwrap_or(0),
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_priority_fee", e)),
                };
                let requested_max_fee = match nft_api_optional_u64_v1(body_obj, "max_fee_per_tx") {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_max_fee_per_tx", e)),
                };
                let suggested_max_fee = match nft_api_effective_unsigned_max_fee_v1(
                    requested_max_fee,
                    priority_fee,
                    base_fee,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_max_fee_per_tx",
                                "message": e,
                                "required_at_least": base_fee,
                                "provided": requested_max_fee.unwrap_or(0)
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                let tx_preview = Transaction {
                    sender: from_b64.clone(),
                    receiver: nft::NFT_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: suggested_max_fee,
                    nonce: 0,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo_str.clone()),
                };
                let nft_extra_fee_native = {
                    let bc = lock_any!(chain);
                    match bc.validate_nft_tx_state_admission_policy_v1(&tx_preview, admission_height) {
                        Ok(v) => v,
                        Err(e) => return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_policy_rejected",
                                "message": e,
                                "admission_height": admission_height
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )),
                    }
                };
                let admission = snapshot_sender_admission_state(&chain, &mp, &from_b64);
                let required_total_native = match suggested_max_fee.checked_add(nft_extra_fee_native) {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_required_total_overflow",
                                "message": "suggested_max_fee_per_tx + nft_extra_fee_native overflowed u64",
                                "suggested_max_fee_per_tx": suggested_max_fee,
                                "nft_extra_fee_native": nft_extra_fee_native
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                let available = admission.available_balance_after_pending();
                let can_cover = available >= required_total_native;
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "surface": "nft_fee_estimate_v1",
                        "policy_source": policy_source,
                        "network_id": chain_identity::network_id(),
                        "from": from_b64,
                        "receiver": nft::NFT_RECEIVER,
                        "amount": 0,
                        "op": nft::nft_op_name_v1(&op),
                        "memo": serde_json::from_str::<serde_json::Value>(&memo_str).unwrap_or(serde_json::Value::Null),
                        "memo_sha256": hex::encode(Sha256::digest(memo_str.as_bytes())),
                        "base_fee_per_tx": base_fee,
                        "suggested_max_fee_per_tx": suggested_max_fee,
                        "nft_extra_fee_native": nft_extra_fee_native,
                        "required_total_native": required_total_native,
                        "next_nonce": admission.expected_next_nonce(),
                        "admission_height": admission_height,
                        "chain_balance": admission.chain_balance,
                        "pending_reserved_total": admission.pending_reserved_total,
                        "available_balance_after_pending": available,
                        "can_cover": can_cover,
                        "submit_path": "/api/v2/tx/submit_signed"
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    // POST /api/v2/nft/build_unsigned
    // Non-custodial NFT transaction builder. It returns the exact wallet v2 payload to sign.
    let nft_build_unsigned_v1 = warp::path!("api" / "v2" / "nft" / "build_unsigned")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and_then(
            |body: serde_json::Value,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>| async move {
                let body_obj = match body.as_object() {
                    Some(v) => v,
                    None => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_request_not_object", "request body must be a JSON object")),
                };
                let from_raw = match nft_api_required_nonempty_str_raw_v1(body_obj, "from") {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_from", e)),
                };
                let from_b64 = match nft::validate_nft_address_b64_v1("from", &from_raw) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_from", e)),
                };
                if let Err(e) = nft_api_reject_unsupported_public_field_v1(body_obj, "allow_before_activation") {
                    return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_unsupported_field", e));
                }
                let op = match nft_api_parse_op_from_body_v1(body_obj, &["from", "max_fee_per_tx", "priority_fee", "nonce"]) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_operation", e)),
                };
                let memo_str = match nft::nft_memo_json_v1(&op) {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_memo_invalid", e)),
                };
                let policy_snapshot = match nft_finalized_policy_snapshot_for_api_v1(&chain) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_policy_unavailable",
                                "message": e,
                                "policy_source_commitment": "finalized"
                            })),
                            warp::http::StatusCode::PRECONDITION_FAILED,
                        ));
                    }
                };
                let tip_h = policy_snapshot.tip_height;
                let base_fee = policy_snapshot.base_fee_per_tx;
                let nft_act_h = policy_snapshot.params.nft_activation_height;
                let nft_params = Some(policy_snapshot.params.clone());
                let policy_source = nft_policy_source_json_from_snapshot_v1(&policy_snapshot);
                let admission_height = tip_h.saturating_add(1);
                if admission_height < nft_act_h {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_not_activated",
                            "message": "NFT v1 is not activated at this height",
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                if let crate::nft::NftOpV1::Mint { expires_at_height: Some(exp), .. } = &op {
                    if *exp <= admission_height {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_invalid_expires_at_height",
                            format!("expires_at_height must be greater than next inclusion height: expires_at_height={} next_height={}", exp, admission_height),
                        ));
                    }
                }
                if let Err(e) = nft_policy_validate_request_v1(&op, &memo_str, nft_params.as_ref()) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_policy_rejected",
                            "message": e,
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                let priority_fee = match nft_api_optional_u64_v1(body_obj, "priority_fee") {
                    Ok(v) => v.unwrap_or(0),
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_priority_fee", e)),
                };
                let requested_max_fee = match nft_api_optional_u64_v1(body_obj, "max_fee_per_tx") {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_max_fee_per_tx", e)),
                };
                let effective_max_fee = match nft_api_effective_unsigned_max_fee_v1(
                    requested_max_fee,
                    priority_fee,
                    base_fee,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_max_fee_per_tx",
                                "message": e,
                                "required_at_least": base_fee,
                                "provided": requested_max_fee.unwrap_or(0)
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                let admission = snapshot_sender_admission_state(&chain, &mp, &from_b64);
                let expected_nonce = admission.expected_next_nonce();
                let nonce = match nft_api_optional_u64_v1(body_obj, "nonce") {
                    Ok(Some(v)) => v,
                    Ok(None) => expected_nonce,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_nonce", e)),
                };
                if nonce < expected_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "replay_or_old_nonce",
                            "expected_nonce": expected_nonce,
                            "provided_nonce": nonce
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }
                let max_allowed_nonce = match expected_nonce.checked_add(MAX_NONCE_GAP) {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nonce_gap_overflow",
                                "expected_nonce": expected_nonce,
                                "max_gap": MAX_NONCE_GAP
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                if nonce > max_allowed_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nonce_gap_too_large",
                            "expected_nonce": expected_nonce,
                            "provided_nonce": nonce,
                            "max_gap": MAX_NONCE_GAP
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }
                let mut tx_preview = Transaction {
                    sender: from_b64.clone(),
                    receiver: nft::NFT_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo_str.clone()),
                };
                tx_preview.hash = tx_preview.calculate_hash();
                let nft_extra_fee_native = {
                    let bc = lock_any!(chain);
                    match bc.validate_nft_tx_state_admission_policy_v1(&tx_preview, admission_height) {
                        Ok(v) => v,
                        Err(e) => return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_policy_rejected",
                                "message": e,
                                "admission_height": admission_height
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )),
                    }
                };
                let required_total_native = match effective_max_fee.checked_add(nft_extra_fee_native) {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nft_required_total_overflow",
                                "message": "effective_max_fee + nft_extra_fee_native overflowed u64",
                                "max_fee_per_tx": effective_max_fee,
                                "nft_extra_fee_native": nft_extra_fee_native
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                };
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    required_total_native,
                    0,
                    effective_max_fee,
                    nft_extra_fee_native,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }
                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: from_b64.clone(),
                    to: nft::NFT_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce,
                    memo: Some(memo_str.clone()),
                };
                let signing_string = canonical_signing_string(&payload);
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "surface": "nft_unsigned_tx_v1",
                        "policy_source": policy_source,
                        "policy_source_commitment": "finalized",
                        "tip_height": tip_h,
                        "finalized_height": policy_snapshot.finalized_height,
                        "governance_height": policy_snapshot.governance_height,
                        "policy_hash": policy_snapshot.policy_hash,
                        "submit_path": "/api/v2/tx/submit_signed",
                        "payload": payload,
                        "canonical_signing_string": signing_string,
                        "public_key_b64_field": "public_key_b64",
                        "signature_b64_field": "signature_b64",
                        "tx_hash": tx_preview.hash,
                        "op": nft::nft_op_name_v1(&op),
                        "memo": serde_json::from_str::<serde_json::Value>(&memo_str).unwrap_or(serde_json::Value::Null),
                        "memo_sha256": hex::encode(Sha256::digest(memo_str.as_bytes())),
                        "fee": {
                            "base_fee_per_tx": base_fee,
                            "max_fee_per_tx": effective_max_fee,
                            "nft_extra_fee_native": nft_extra_fee_native,
                            "required_total_native": required_total_native
                        },
                        "nonce": {
                            "selected": nonce,
                            "expected_next": expected_nonce
                        },
                        "admission_height": admission_height
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    // ------- NFT v1: invio TX "system-op" firmata dal NODO (admin/dev-only) -------
    // POST /api/v2/nft/send_from_node
    let nft_send_from_node = warp::path!("api" / "v2" / "nft" / "send_from_node")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and(with_chain(chain.clone()))
        .and(with_storage(storage.clone()))
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))
        .and_then(
            |_guard: (),
             body: serde_json::Value,
             mp: Arc<Mutex<Mempool>>,
             p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
             chain: Arc<Mutex<Blockchain>>,
             _storage: std::sync::Arc<DbStore>,
             signer: Arc<SigningKey>,
             pk_b64: String| async move {
                let body_obj = match body.as_object() {
                    Some(v) => v,
                    None => {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_request_not_object",
                            "request body must be a JSON object",
                        ));
                    }
                };

                let op = match nft_api_required_nonempty_str_raw_v1(body_obj, "op") {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("missing_op", e)),
                };

                let allow_before_activation = match nft_api_optional_bool_v1(body_obj, "allow_before_activation") {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_invalid_common_field",
                            e,
                        ));
                    }
                };

                let op_spec_keys: &[&str] = match op.as_str() {
                    "create_collection" => &[
                        "allow_before_activation",
                        "asset_type",
                        "base_uri",
                        "burnable",
                        "max_fee_per_tx",
                        "max_supply",
                        "metadata_hash_hex",
                        "mintable",
                        "name",
                        "op",
                        "priority_fee",
                        "revocable",
                        "symbol",
                        "transfer_policy",
                    ],
                    "mint" => &[
                        "allow_before_activation",
                        "collection_id",
                        "max_fee_per_tx",
                        "metadata_hash_hex",
                        "expires_at_height",
                        "op",
                        "priority_fee",
                        "to",
                        "token_uri",
                    ],
                    "transfer" => &[
                        "allow_before_activation",
                        "collection_id",
                        "max_fee_per_tx",
                        "op",
                        "priority_fee",
                        "serial",
                        "to",
                    ],
                    "approve" => &[
                        "allow_before_activation",
                        "approved",
                        "collection_id",
                        "max_fee_per_tx",
                        "op",
                        "priority_fee",
                        "serial",
                    ],
                    "set_approval_for_all" => &[
                        "allow_before_activation",
                        "approved",
                        "collection_id",
                        "max_fee_per_tx",
                        "op",
                        "operator",
                        "priority_fee",
                    ],
                    "burn" | "revoke" => &[
                        "allow_before_activation",
                        "collection_id",
                        "max_fee_per_tx",
                        "op",
                        "priority_fee",
                        "serial",
                    ],
                    "set_token_uri" => &[
                        "allow_before_activation",
                        "collection_id",
                        "max_fee_per_tx",
                        "metadata_hash_hex",
                        "op",
                        "priority_fee",
                        "serial",
                        "token_uri",
                    ],
                    "set_collection_uri" => &[
                        "allow_before_activation",
                        "base_uri",
                        "collection_id",
                        "max_fee_per_tx",
                        "metadata_hash_hex",
                        "op",
                        "priority_fee",
                    ],
                    "freeze_token" => &[
                        "allow_before_activation",
                        "collection_id",
                        "frozen",
                        "max_fee_per_tx",
                        "op",
                        "priority_fee",
                        "serial",
                    ],
                    "set_collection_policy" => &[
                        "allow_before_activation",
                        "burnable",
                        "collection_id",
                        "max_fee_per_tx",
                        "mintable",
                        "op",
                        "priority_fee",
                        "revocable",
                        "transfer_policy",
                    ],
                    "set_issuer" => &[
                        "allow_before_activation",
                        "collection_id",
                        "issuer",
                        "max_fee_per_tx",
                        "op",
                        "priority_fee",
                    ],
                    "pause" => &[
                        "allow_before_activation",
                        "collection_id",
                        "max_fee_per_tx",
                        "op",
                        "paused",
                        "priority_fee",
                    ],
                    _ => {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "unknown_op",
                            op,
                        ));
                    }
                };
                if let Err(e) = nft_api_exact_keys_v1(body_obj, op_spec_keys) {
                    return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                        "nft_unknown_request_field",
                        e,
                    ));
                }

                let pk_b64 = match nft::validate_nft_address_b64_v1("sender", &pk_b64) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_node_identity",
                                "message": "nft_sender_not_canonical",
                                "detail": e
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }
                };
                let (tip_h, base_fee, _last_chain_nonce, _current_balance, nft_act_h, nft_params) = {
                    let bc = lock_any!(chain);
                    let tip_h = bc.chain.last().map(|b| b.index).unwrap_or(0);
                    let base_fee = bc.base_fee_per_tx();
                    let last_chain_nonce = bc.get_last_nonce(&pk_b64);
                    let bal_i128 = bc.get_balance(&pk_b64);
                    let current_balance = if bal_i128 < 0 { 0 } else { bal_i128 as u64 };
                    let nft_params = bc.governance.as_ref().map(|g| g.params.clone());

                    let nft_act_h = nft_params
                        .as_ref()
                        .map(|p| p.nft_activation_height)
                        .unwrap_or(u64::MAX);

                    (tip_h, base_fee, last_chain_nonce, current_balance, nft_act_h, nft_params)
                };

                if !allow_before_activation && tip_h.saturating_add(1) < nft_act_h {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_not_activated",
                            "message": "NFT v1 is not activated at this height",
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h,
                            "hint": "set nft_activation_height or pass allow_before_activation=true for dev testing"
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }

                let body_max_fee = parse_amount_atomic(&body["max_fee_per_tx"]).unwrap_or(0);
                let body_priority_fee = parse_amount_atomic(&body["priority_fee"]).unwrap_or(0);
                let requested_max_fee = if body_max_fee > 0 {
                    body_max_fee
                } else {
                    base_fee.saturating_add(body_priority_fee)
                };
                let effective_max_fee = requested_max_fee.max(base_fee);

                let nft_op = match op.as_str() {
                    "create_collection" => {
                        let metadata_hash_hex = match nft_api_required_nonempty_str_raw_v1(body_obj, "metadata_hash_hex") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        let metadata_hash = match nft::parse_nft_hash32_hex_v1("metadata_hash_hex", &metadata_hash_hex) {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        crate::nft::NftOpV1::CreateCollection {
                            symbol: match nft_api_required_nonempty_str_raw_v1(body_obj, "symbol") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_symbol", e)),
                            },
                            name: match nft_api_required_nonempty_str_raw_v1(body_obj, "name") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_name", e)),
                            },
                            max_supply: match nft_api_optional_nullable_u64_v1(body_obj, "max_supply") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_max_supply", e)),
                            },
                            base_uri: match nft_api_required_str_raw_v1(body_obj, "base_uri") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_base_uri", e)),
                            },
                            metadata_hash,
                            mintable: match nft_api_required_bool_v1(body_obj, "mintable") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_mintable", e)),
                            },
                            burnable: match nft_api_required_bool_v1(body_obj, "burnable") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_burnable", e)),
                            },
                            asset_type: match nft_api_required_nonempty_str_raw_v1(body_obj, "asset_type")
                                .and_then(|v| crate::nft::NftAssetTypeV1::parse_raw(&v))
                            {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_asset_type", e)),
                            },
                            transfer_policy: match nft_api_required_nonempty_str_raw_v1(body_obj, "transfer_policy")
                                .and_then(|v| crate::nft::NftTransferPolicyV1::parse_raw(&v))
                            {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_transfer_policy", e)),
                            },
                            revocable: match nft_api_required_bool_v1(body_obj, "revocable") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_revocable", e)),
                            },
                        }
                    },
                    "mint" => {
                        let metadata_hash_hex = match nft_api_required_nonempty_str_raw_v1(body_obj, "metadata_hash_hex") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        let metadata_hash = match nft::parse_nft_hash32_hex_v1("metadata_hash_hex", &metadata_hash_hex) {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        crate::nft::NftOpV1::Mint {
                            collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                            },
                            to_b64: match nft_api_required_nonempty_str_raw_v1(body_obj, "to") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_to", e)),
                            },
                            token_uri: match nft_api_required_str_raw_v1(body_obj, "token_uri") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_token_uri", e)),
                            },
                            metadata_hash,
                            expires_at_height: match nft_api_optional_nullable_u64_v1(body_obj, "expires_at_height") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_expires_at_height", e)),
                            },
                        }
                    },
                    "transfer" => crate::nft::NftOpV1::Transfer {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                        },
                        to_b64: match nft_api_required_nonempty_str_raw_v1(body_obj, "to") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_to", e)),
                        },
                    },
                    "approve" => crate::nft::NftOpV1::Approve {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                        },
                        approved_b64: match nft_api_required_nullable_str_raw_v1(body_obj, "approved") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_approved", e)),
                        },
                    },
                    "set_approval_for_all" => crate::nft::NftOpV1::SetApprovalForAll {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        operator_b64: match nft_api_required_nonempty_str_raw_v1(body_obj, "operator") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_operator", e)),
                        },
                        approved: match nft_api_required_bool_v1(body_obj, "approved") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_approved", e)),
                        },
                    },
                    "burn" => crate::nft::NftOpV1::Burn {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                        },
                    },
                    "revoke" => crate::nft::NftOpV1::Revoke {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                        },
                    },
                    "set_token_uri" => {
                        let metadata_hash_hex = match nft_api_required_nonempty_str_raw_v1(body_obj, "metadata_hash_hex") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        let metadata_hash = match nft::parse_nft_hash32_hex_v1("metadata_hash_hex", &metadata_hash_hex) {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        crate::nft::NftOpV1::SetTokenUri {
                            collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                            },
                            serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                            },
                            token_uri: match nft_api_required_str_raw_v1(body_obj, "token_uri") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_token_uri", e)),
                            },
                            metadata_hash,
                        }
                    },
                    "set_collection_uri" => {
                        let metadata_hash_hex = match nft_api_required_nonempty_str_raw_v1(body_obj, "metadata_hash_hex") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        let metadata_hash = match nft::parse_nft_hash32_hex_v1("metadata_hash_hex", &metadata_hash_hex) {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_metadata_hash", e)),
                        };
                        crate::nft::NftOpV1::SetCollectionUri {
                            collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                            },
                            base_uri: match nft_api_required_str_raw_v1(body_obj, "base_uri") {
                                Ok(v) => v,
                                Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_base_uri", e)),
                            },
                            metadata_hash,
                        }
                    },
                    "freeze_token" => crate::nft::NftOpV1::FreezeToken {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        serial: match nft_api_required_nonzero_u64_v1(body_obj, "serial") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_serial", e)),
                        },
                        frozen: match nft_api_required_bool_v1(body_obj, "frozen") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_frozen", e)),
                        },
                    },
                    "set_collection_policy" => crate::nft::NftOpV1::SetCollectionPolicy {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        mintable: match nft_api_required_bool_v1(body_obj, "mintable") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_mintable", e)),
                        },
                        burnable: match nft_api_required_bool_v1(body_obj, "burnable") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_burnable", e)),
                        },
                        transfer_policy: match nft_api_required_nonempty_str_raw_v1(body_obj, "transfer_policy")
                            .and_then(|v| crate::nft::NftTransferPolicyV1::parse_raw(&v))
                        {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_transfer_policy", e)),
                        },
                        revocable: match nft_api_required_bool_v1(body_obj, "revocable") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_revocable", e)),
                        },
                    },
                    "set_issuer" => crate::nft::NftOpV1::SetIssuer {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        issuer_b64: match nft_api_required_nonempty_str_raw_v1(body_obj, "issuer") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_issuer", e)),
                        },
                    },
                    "pause" => crate::nft::NftOpV1::SetPaused {
                        collection_id: match nft_api_required_nonzero_u64_v1(body_obj, "collection_id") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_collection_id", e)),
                        },
                        paused: match nft_api_required_bool_v1(body_obj, "paused") {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::Rejection>(nft_api_bad_request_v1("nft_invalid_paused", e)),
                        },
                    },
                    _ => unreachable!("op already validated"),
                };

                if let crate::nft::NftOpV1::Mint { expires_at_height: Some(exp), .. } = &nft_op {
                    let inclusion_height = tip_h.saturating_add(1);
                    if *exp <= inclusion_height {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_invalid_expires_at_height",
                            format!(
                                "expires_at_height must be greater than next inclusion height: expires_at_height={} next_height={}",
                                exp, inclusion_height
                            ),
                        ));
                    }
                }

                let memo_str = match nft::nft_memo_json_v1(&nft_op) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(nft_api_bad_request_v1(
                            "nft_memo_invalid",
                            e,
                        ));
                    }
                };
                if let Err(e) = nft_policy_validate_request_v1(&nft_op, &memo_str, nft_params.as_ref()) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "nft_policy_rejected",
                            "message": e,
                            "tip_height": tip_h,
                            "nft_activation_height": nft_act_h
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }

                let extra_native = nft_policy_fee_for_op_v1(&nft_op, nft_params.as_ref());
                let total_required = effective_max_fee.saturating_add(extra_native);
                let admission = snapshot_sender_admission_state(&chain, &mp, &pk_b64);
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    total_required,
                    0,
                    effective_max_fee,
                    extra_native,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }

                let expected_nonce = admission.expected_next_nonce();

                let sk = signer.as_ref();
                let mut tx = Transaction {
                    sender: pk_b64.clone(),
                    receiver: nft::NFT_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: effective_max_fee,
                    nonce: expected_nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo_str.clone()),
                };

                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: tx.sender.clone(),
                    to: tx.receiver.clone(),
                    amount: tx.amount,
                    max_fee_per_tx: tx.max_fee_per_tx,
                    nonce: tx.nonce,
                    memo: tx.memo.clone(),
                };
                let msg = canonical_signing_string(&payload);
                let sig = sk.sign(msg.as_bytes());
                tx.signature = STANDARD.encode(sig.to_bytes());
                tx.hash = tx.calculate_hash();

                if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "fee_too_low_for_security",
                            "required_min_fee": fee_err.required_min_fee,
                            "provided_max_fee_per_tx": fee_err.provided_max_fee,
                            "tx_size_bytes": fee_err.tx_size_bytes
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                if let Err(e) = nft::validate_nft_tx_syntax(&tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_data",
                            "message": "nft_memo_invalid",
                            "detail": e
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                if !tx.verify_signature() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"invalid_signature_creation"})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                }

                let mut mp_lock = lock_any!(mp);
                let accepted = mp_lock.add(tx.clone());
                if !accepted {
                    let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) = mp_lock.limits_snapshot();
                    let cur_size = mp_lock.len();
                    let cur_bytes = mp_lock.total_bytes();
                    drop(mp_lock);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "rejected",
                            "reason": "mempool_limits",
                            "mempool": {"size": cur_size as u64, "total_bytes": cur_bytes as u64},
                            "limits": {
                                "max_mempool_size": max_size as u64,
                                "max_tx_per_sender": max_tx_per_sender as u64,
                                "max_mempool_bytes": max_bytes as u64,
                                "tx_ttl_secs": tx_ttl_secs
                            }
                        })),
                        warp::http::StatusCode::TOO_MANY_REQUESTS,
                    ));
                }
                drop(mp_lock);

                let _ = p2p.send(NetMsg::NewTx(tx.clone()));
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status":"ok",
                        "tx_hash": tx.hash,
                        "sender": pk_b64,
                        "nonce_used": expected_nonce,
                        "max_fee_per_tx": effective_max_fee,
                        "nft_extra_fee_native": extra_native,
                        "required_total_native": total_required,
                        "nft_activation_height": nft_act_h,
                        "memo": serde_json::from_str::<serde_json::Value>(&memo_str).unwrap_or(serde_json::Value::Null)
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    // ------- Next nonce helper v2 -------
    let get_next_nonce = warp::path!("api" / "v2" / "wallet" / "next_nonce" / String)
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .map(next_nonce_handler);

    let get_next_nonce_legacy = warp::path!("api" / "v2" / "tx" / "get_next_nonce" / String)
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .map(next_nonce_handler);
    // ⚠️ LEGACY / DEV-ONLY. Per i client reali usare /api/v2/tx/submit_signed.
    // ------- Invio TX firmata dal CLIENT v2 (schema legacy, max_fee_per_tx=0) -------
    let tx_submit = warp::path!("api" / "v2" / "tx" / "submit")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_TX_BODY_BYTES))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and_then(
            |_guard: (),
             body: serde_json::Value,
             ch: SharedChain,
             mp: Arc<Mutex<Mempool>>,
             p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| async move {
                let sender = body["sender"].as_str().unwrap_or("").to_string();
                let receiver = body["receiver"].as_str().unwrap_or("").to_string();
                let amount = parse_amount_atomic(&body["amount"]).unwrap_or(0);
                let signature_b64 = body["signature"].as_str().unwrap_or("").to_string();
                let nonce = body["nonce"].as_u64().unwrap_or(0);

                if sender.is_empty()
                    || receiver.is_empty()
                    || amount == 0
                    || signature_b64.is_empty()
                {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"invalid_data"})),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                // Costruiamo la TX legacy → max_fee_per_tx = 0, nessun memo
                let mut tx = Transaction {
                    sender: sender.clone(),
                    receiver: receiver.clone(),
                    amount,
                    max_fee_per_tx: 0, // TX legacy: nessun max esplicito
                    signature: signature_b64.clone(),
                    hash: String::new(),
                    is_coinbase: false,
                    nonce,
                    memo: None,
                };

                // 1) verifica firma
                if !tx.verify_signature() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"invalid_signature"})),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                // 2) Snapshot chain+mempool e nonce policy (fail-closed su pending-spend)
                let admission = snapshot_sender_admission_state(&ch, &mp, &sender);
                let expected_next_nonce = admission.expected_next_nonce();

                if nonce < expected_next_nonce {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"replay_or_old_nonce",
                            "expected_nonce": expected_next_nonce
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }

                if nonce > expected_next_nonce.saturating_add(MAX_NONCE_GAP) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"nonce_gap_too_large",
                            "expected_nonce": expected_next_nonce,
                            "max_gap": MAX_NONCE_GAP
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                // 3) conflitti nel mempool (stesso sender+nonce)
                let mem_lock = lock_any!(mp);
                if let Some(existing) = mem_lock.find_by_sender_nonce(&sender, nonce) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"error",
                            "message":"nonce_conflict_in_mempool",
                            "existing_tx_hash": existing.hash
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ));
                }

                // 4) calcolo hash e firewall fee minimo
                tx.hash = tx.calculate_hash();

                let required_total = amount.saturating_add(admission.base_fee_per_tx);
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    required_total,
                    amount,
                    admission.base_fee_per_tx,
                    0,
                ) {
                    drop(mem_lock);
                    return Ok::<_, warp::Rejection>(reply);
                }

                // 🔐 Step 53 – firewall fee minimo (security)
                if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                    // rilasciamo il lock perché stiamo uscendo dal ramo
                    drop(mem_lock);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "fee_too_low_for_security",
                            "required_min_fee": fee_err.required_min_fee,
                            "provided_max_fee_per_tx": fee_err.provided_max_fee,
                            "tx_size_bytes": fee_err.tx_size_bytes
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                // 5) Compute firewall: keep receiver-specific semantics fail-closed
                if let Err(e) = validate_compute_tx_syntax(&tx) {
                    drop(mem_lock);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_data",
                            "message": "compute_memo_invalid",
                            "detail": e
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }
                drop(mem_lock);
                {
                    let bc = lock_any!(ch);
                    let admission_height = bc.tip_height_u64().saturating_add(1);
                    if let Err(e) =
                        validate_compute_tx_worker_admission_v1(&bc, &tx, admission_height)
                    {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "compute_worker_admission_rejected",
                                "message": e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }
                }

                // 6) aggiunta al mempool (rispetta limiti step 49) con motivo dettagliato
                let mut mem_lock = lock_any!(mp);
                let add_result = mem_lock.add_detailed(tx.clone());

                if !add_result.accepted() {
                    let body = mempool_reject_json(&add_result, &mem_lock);
                    let code = mempool_reject_status(&add_result);
                    drop(mem_lock);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&body),
                        code,
                    ));
                }
                drop(mem_lock);

                // 6) broadcast in P2P solo dopo che il mempool ha accettato
                let _ = p2p.send(NetMsg::NewTx(tx.clone()));

                // 7) risposta OK finale
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status":"ok",
                        "tx_hash": tx.hash
                    })),
                    warp::http::StatusCode::OK,
                ))
            },
        );

    // ------- Invio TX firmata dal CLIENT (schema canonico SignedTransaction) -------
    // Endpoint ufficiale per il wallet v2 client-signed.

    // ------- Invio TX firmata dal CLIENT v3 (schema canonico SignedTransaction) -------
    let tx_submit_signed = warp::path!("api" / "v2" / "tx" / "submit_signed")
            .and(warp::post())
            .and(warp::body::content_length_limit(MAX_TX_BODY_BYTES)) // hard cap anti-DoS
            .and(warp::body::json())
            .and(with_chain(chain.clone()))
            .and(with_mempool(mempool.clone()))
            .and(with_p2p(tx_p2p.clone()))
            .and_then(
                |signed: crate::wallet::SignedTransaction,
                 ch: SharedChain,
                 mp: Arc<Mutex<Mempool>>,
                 p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| async move {
                    // 1) Verifica crittografica: firma e dominio canonico del payload v2.
                    if let Err(err_msg) = crate::wallet::verify_signed_transaction(&signed) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_signature",
                                "error": err_msg
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }

                    // 2) Enforce schema v2 (network_id/fee/memo)
                    let payload = &signed.payload;

                    // Network binding: STRICT by default; optional devnet compatibility via env.
                    if payload.network_id != chain_identity::network_id() {
                        let compat = allow_legacy_network_id();
                        let empty = payload.network_id.trim().is_empty();
                        if !(compat && empty) {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "invalid_network_id",
                                    "expected": chain_identity::network_id(),
                                    "provided": payload.network_id,
                                    "hint": "client must sign using the exact network_id returned by the node"
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            ));
                        }
                    }

                let admission = snapshot_sender_admission_state(&ch, &mp, &payload.from);
                let base_fee_u64 = admission.base_fee_per_tx;
                if payload.max_fee_per_tx < base_fee_u64 {
                    record_gateway_fee_low_rejection(&mp);
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_max_fee_per_tx",
                            "required_at_least": base_fee_u64,
                            "provided": payload.max_fee_per_tx
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                let amount_u64: u64 = payload.amount;
                let required_total_u64: u64 = amount_u64.saturating_add(payload.max_fee_per_tx);
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    required_total_u64,
                    amount_u64,
                    payload.max_fee_per_tx,
                    0,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }

                    let sender = payload.from.clone();
                    let receiver = payload.to.clone();
                    let amount = payload.amount;
                    let nonce = payload.nonce;

                    // 3) Nonce policy: stesso schema del tx_submit server-side
                    let expected_next_nonce = admission.expected_next_nonce();

                    if nonce < expected_next_nonce {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "replay_or_old_nonce",
                                "expected_nonce": expected_next_nonce
                            })),
                            warp::http::StatusCode::CONFLICT,
                        ));
                    }

                    if nonce > expected_next_nonce.saturating_add(MAX_NONCE_GAP) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "nonce_gap_too_large",
                                "expected_nonce": expected_next_nonce,
                                "provided_nonce": nonce,
                                "max_gap": MAX_NONCE_GAP
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }

                    // 4) Mempool nonce conflict (stesso sender+nonce già presente)
                    {
                        let mem_lock = lock_any!(mp);
                        if let Some(existing) = mem_lock.find_by_sender_nonce(&sender, nonce) {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "nonce_conflict_in_mempool",

                                    "existing_tx_hash": existing.hash
                                })),
                                warp::http::StatusCode::CONFLICT,
                            ));
                        }
                    }

                    // 5) Costruzione Transaction interna
                    let mut tx = Transaction {
                        sender: sender.clone(),
                        receiver: receiver.clone(),
                        amount,
                        max_fee_per_tx: payload.max_fee_per_tx, // client-provided cap (>= base fee)
                        signature: signed.signature_b64.clone(),
                        hash: String::new(),
                        is_coinbase: false,
                        nonce,
                        memo: payload.memo.clone(),
                    };
                    tx.hash = tx.calculate_hash();

                    // 6) Step 53 – firewall fee minimo (security)
                    if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "fee_too_low_for_security",
                                "required_min_fee": fee_err.required_min_fee,
                                "provided_max_fee_per_tx": fee_err.provided_max_fee,
                                "tx_size_bytes": fee_err.tx_size_bytes
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }

                    // 7) NFT policy firewall: reject policy-invalid raw signed NFT tx before mempool/gossip.
                    let nft_extra_fee_native = {
                        let bc = lock_any!(ch);
                        let admission_height = bc.tip_height_u64().saturating_add(1);
                        match bc.validate_nft_tx_state_admission_policy_v1(&tx, admission_height) {
                            Ok(extra) => extra,
                            Err(e) => {
                                return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "nft_policy_rejected",
                                        "message": e,
                                        "admission_height": admission_height
                                    })),
                                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                                ));
                            }
                        }
                    };
                    if nft_extra_fee_native > 0 {
                        let admission = snapshot_sender_admission_state(&ch, &mp, &sender);
                        let required_total = match amount_u64
                            .checked_add(payload.max_fee_per_tx)
                            .and_then(|v| v.checked_add(nft_extra_fee_native))
                        {
                            Some(v) => v,
                            None => {
                                return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "nft_required_total_overflow",
                                        "message": "amount + max_fee_per_tx + nft_extra_fee_native overflowed u64",
                                        "amount": amount_u64,
                                        "max_fee_per_tx": payload.max_fee_per_tx,
                                        "nft_extra_fee_native": nft_extra_fee_native
                                    })),
                                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                                ));
                            }
                        };
                        if let Some(reply) = reject_if_sender_cannot_cover_pending(
                            &admission,
                            required_total,
                            amount_u64,
                            payload.max_fee_per_tx,
                            nft_extra_fee_native,
                        ) {
                            return Ok::<_, warp::Rejection>(reply);
                        }
                    }

                    // 8) Compute firewall: keep receiver-specific semantics fail-closed
                    if let Err(e) = validate_compute_tx_syntax(&tx) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_data",
                                "message": "compute_memo_invalid",
                                "detail": e
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ));
                    }
                    {
                        let bc = lock_any!(ch);
                        let admission_height = bc.tip_height_u64().saturating_add(1);
                        if let Err(e) = validate_compute_tx_worker_admission_v1(&bc, &tx, admission_height) {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "compute_worker_admission_rejected",
                                    "message": e
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            ));
                        }
                    }

                    // 8) Inserimento in mempool con motivo dettagliato di reject
                    let mut mem_lock = lock_any!(mp);
                    let add_result = mem_lock.add_detailed(tx.clone());

                    if !add_result.accepted() {
                        let body = mempool_reject_json(&add_result, &mem_lock);
                        let code = mempool_reject_status(&add_result);
                        drop(mem_lock);
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&body),
                            code,
                        ));
                    }
                    drop(mem_lock);

                    // 8) Propagazione P2P
                    let _ = p2p.send(NetMsg::NewTx(tx.clone()));

                    Ok::<_, warp::Rejection>(warp::reply::with_status(warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "tx_hash": tx.hash
                    })), warp::http::StatusCode::OK))
                },
            );
    // ------- Admin/local-only signer for arbitrary canonical wallet-v2 payloads -------
    // This is intentionally NOT a public wallet API. It exists for private/lab operator flows
    // where the node owns the local wallet key and an external subsystem already built a
    // bounded TransactionPayload, e.g. E2 worker self-registration.
    //
    // Safety boundaries:
    // - mounted only with admin routes;
    // - requires x-admin-token through admin_guard;
    // - requires explicit NEWGEN_ENABLE_LOCAL_TX_SIGNER=1;
    // - refuses payload.from != local wallet pubkey;
    // - does not mutate mempool; callers must submit via /api/v2/tx/submit_signed.
    let tx_sign_from_node = warp::path!("api" / "v2" / "tx" / "sign_from_node")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_TX_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .map(
            |_guard: (), body: serde_json::Value, signer: Arc<SigningKey>, pk_b64: String| {
                if !env_flag_true_v1("NEWGEN_ENABLE_LOCAL_TX_SIGNER") {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "local_tx_signer_disabled",
                            "required_env": "NEWGEN_ENABLE_LOCAL_TX_SIGNER=1",
                            "surface": "admin_local_tx_signer_v1"
                        })),
                        warp::http::StatusCode::FORBIDDEN,
                    );
                }

                let payload_value = match body.get("payload").cloned() {
                    Some(v) => v,
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "missing_payload",
                                "expected": {"payload": "TransactionPayload"}
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        );
                    }
                };

                let payload: TransactionPayload = match serde_json::from_value(payload_value) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "invalid_payload",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        );
                    }
                };

                let local_pk = normalize_pk_b64(&pk_b64);
                if payload.from.trim() != local_pk {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "from_mismatch_local_wallet",
                            "payload_from": payload.from,
                            "local_wallet_pubkey": local_pk,
                            "hint": "the node will only sign payloads whose from equals its local wallet public key"
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    );
                }

                if payload.network_id != chain_identity::network_id() {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "invalid_network_id",
                            "expected": chain_identity::network_id(),
                            "provided": payload.network_id
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    );
                }

                let canonical = canonical_signing_string(&payload);
                let sig = signer.sign(canonical.as_bytes());
                let signature_b64 = STANDARD.encode(sig.to_bytes());
                let signed = crate::wallet::SignedTransaction {
                    payload: payload.clone(),
                    public_key_b64: local_pk.clone(),
                    signature_b64: signature_b64.clone(),
                };

                if let Err(e) = crate::wallet::verify_signed_transaction(&signed) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "local_signature_self_verify_failed",
                            "error": e
                        })),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }

                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "surface": "admin_local_tx_signer_v1",
                        "public_key_b64": local_pk,
                        "signature_b64": signature_b64,
                        "canonical_signing_string": canonical,
                        "payload": payload,
                        "signed": signed,
                        "submit_path": "/api/v2/tx/submit_signed"
                    })),
                    warp::http::StatusCode::OK,
                )
            },
        );

    let tx_by_hash_route = warp::path!("api" / "v2" / "tx" / "by-hash" / String)
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and_then(tx_by_hash_handler);

    let tx_by_hash_route_legacy = warp::path!("api" / "v2" / "tx" / "by_hash" / String)
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and_then(tx_by_hash_handler);

    let light_headers_route = warp::path!("api" / "v2" / "light" / "headers")
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and(warp::query::<LightHeadersQuery>())
        .and_then(light_headers_handler);

    let light_tx_proof_route = warp::path!("api" / "v2" / "light" / "tx-proof" / String)
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and_then(light_tx_proof_handler);

    let light_state_proof_route = warp::path!("api" / "v2" / "light" / "state-proof" / String)
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and(warp::query::<LightStateHeightQuery>())
        .and_then(light_state_proof_handler);

    let light_state_proof_query_route = warp::path!("api" / "v2" / "light" / "state" / "proof")
        .and(warp::get())
        .and(with_storage(storage.clone()))
        .and(warp::query::<LightStateProofQuery>())
        .and_then(light_state_proof_query_handler);

    // ------- Info wallet del NODO v2 -------
    let get_node_wallet_info = warp::path!("api" / "v2" / "wallet" / "info")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .map(
            |chain: Arc<Mutex<Blockchain>>, _sk: Arc<SigningKey>, pk_b64: String| {
                let pk_b64 = pk_b64.trim().to_string();
                let balance_i128 = lock_any!(chain).get_balance(&pk_b64);
                let balance = if balance_i128 < 0 {
                    0
                } else {
                    balance_i128 as u64
                };
                warp::reply::json(&serde_json::json!({
                    "address": pk_b64,
                    "balance": balance
                }))
            },
        );

    // ------- Faucet testnet (solo debug) -------
    #[cfg(debug_assertions)]
    let faucet_request = warp::path!("api" / "v2" / "faucet" / "request")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES)) // ⬅️ AGGIUNTA
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .map(
            |body: serde_json::Value,
             _chain: SharedChain,
             _mp: Arc<Mutex<Mempool>>,
             _p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                let receiver = body["receiver"].as_str().unwrap_or("").to_string();
                let amount = parse_amount_atomic(&body["amount"]).unwrap_or(0);

                if receiver.is_empty() || amount == 0 || amount > 5000 {
                    return warp::reply::json(&serde_json::json!({
                        "status":"error","message":"invalid_amount"
                    }));
                }

                // V187 hardening: the debug faucet must never manufacture a
                // coinbase transaction and submit it through mempool/gossip.
                // Funding must use the admin chain route or a real signed faucet
                // key path, not a synthetic mempool coinbase.
                warp::reply::json(&debug_faucet_mempool_disabled_response_v1(receiver, amount))
            },
        );

    // ------- Bilancio v2 route -------
    let get_v2_wallet_balance = get_v2_wallet_balance_route(chain.clone());

    // ------- CORS -------
    // In produzione evitare allow_any_origin: usa una allowlist via env.
    // Esempio:
    //   NEWGEN_CORS_ALLOW_ORIGINS="https://app.example.com,https://explorer.example.com"
    let cors = {
        let allowlist_env = std::env::var("NEWGEN_CORS_ALLOW_ORIGINS").ok();

        match allowlist_env.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                let allow: std::sync::Arc<std::collections::HashSet<String>> = std::sync::Arc::new(
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                );

                let mut cors = warp::cors()
                    .allow_methods(vec!["GET", "POST", "OPTIONS"])
                    .allow_headers(vec![
                        "content-type",
                        "authorization",
                        "accept",
                        "origin",
                        "x-requested-with",
                        "x-admin-token",
                    ])
                    .max_age(3600);

                for o in allow.iter() {
                    cors = cors.allow_origin(o.as_str());
                }

                cors
            }
            _ => {
                // Dev-friendly default: in debug allow_any_origin.
                // In release, senza allowlist non inviamo header CORS (browser UI deve essere same-origin o settare env).
                let base = warp::cors()
                    .allow_methods(vec!["GET", "POST", "OPTIONS"])
                    .allow_headers(vec![
                        "content-type",
                        "authorization",
                        "accept",
                        "origin",
                        "x-requested-with",
                        "x-admin-token",
                    ])
                    .max_age(3600);

                if crate::utils::debug_cors_allow_any_for_mode_v1("API", public_mode) {
                    base.allow_any_origin()
                } else {
                    // Safe default: allow local Explorer UI origin (api_port + 1000) on loopback only.
                    // This keeps release mode usable for local ops without requiring NEWGEN_CORS_ALLOW_ORIGINS.
                    let explorer_port = api_port.saturating_add(1000);
                    let o1 = format!("http://127.0.0.1:{}", explorer_port);
                    let o2 = format!("http://localhost:{}", explorer_port);
                    base.allow_origin(o1.as_str()).allow_origin(o2.as_str())
                }
            }
        }
    };
    // /health e /status per test rapidi
    // /health: check banalissimo, solo per dire "processo vivo"
    let health = warp::path("health").and(warp::get()).map(|| {
        warp::reply::json(&serde_json::json!({
            "status":"ok",
            "build_fingerprint": build_fingerprint(),
            "runtime_surface": runtime_surface_json()
        }))
    });

    // /readyz: readiness NON bloccante (diagnostico)
    // Non usa lock bloccanti: se chain/mempool sono occupati risponde comunque subito.
    let readyz = warp::path("readyz")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .map(|ch: SharedChain, mp: Arc<Mutex<Mempool>>| {
            use std::sync::TryLockError;

            let v = VersionInfo::current();

            let (chain_lock, height, tip) = match ch.try_lock() {
                Ok(bc) => {
                    let (h, t) = if let Some(last) = bc.chain.last() {
                        (last.index, last.hash.clone())
                    } else {
                        (0u64, String::new())
                    };
                    ("ok", Some(h), Some(t))
                }
                Err(TryLockError::WouldBlock) => ("busy", None, None),
                Err(TryLockError::Poisoned(poison)) => {
                    let bc = poison.into_inner();
                    let (h, t) = if let Some(last) = bc.chain.last() {
                        (last.index, last.hash.clone())
                    } else {
                        (0u64, String::new())
                    };
                    ("poisoned_recovered", Some(h), Some(t))
                }
            };

            let (mempool_lock, mempool_size, mempool_bytes) = match mp.try_lock() {
                Ok(mp) => ("ok", Some(mp.len() as u64), Some(mp.total_bytes() as u64)),
                Err(TryLockError::WouldBlock) => ("busy", None, None),
                Err(TryLockError::Poisoned(poison)) => {
                    let mp = poison.into_inner();
                    (
                        "poisoned_recovered",
                        Some(mp.len() as u64),
                        Some(mp.total_bytes() as u64),
                    )
                }
            };

            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "service": "readyz",
                "api_contract": API_CONTRACT,
                "api_contract_version": API_CONTRACT_VERSION,
                "software_version": v.software_version,
                "build_fingerprint": build_fingerprint(),
                "runtime_surface": runtime_surface_json(),
                "network_id": chain_identity::network_id(),
                "chain_lock": chain_lock,
                "mempool_lock": mempool_lock,
                "height": height,
                "last_block_hash": tip,
                "mempool_size": mempool_size,
                "mempool_bytes": mempool_bytes
            }))
        });

    // /status: endpoint di osservabilità "ricco" ma stabile.
    // Mainnet hardening: non deve mai restare appeso se la chain è occupata in
    // snapshot/export/sync/replay. Se il lock chain non è immediatamente disponibile,
    // risponde da cache con status=degraded invece di bloccare il thread HTTP.
    let status = warp::path("status")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .map({
            move |ch: SharedChain, mp: Arc<Mutex<Mempool>>| {
                let mempool_degraded_snapshot = match mp.try_lock() {
                    Ok(mp) => Some((mp.len() as u64, mp.total_bytes() as u64)),
                    Err(TryLockError::Poisoned(poison)) => {
                        let mp = poison.into_inner();
                        Some((mp.len() as u64, mp.total_bytes() as u64))
                    }
                    Err(TryLockError::WouldBlock) => None,
                };

                // Snapshot veloce chain (scalari + clone hash), poi rilascio lock.
                let (
                    height,
                    last_hash,
                    finalized_height,
                    finalized_hash,
                    total_blocks,
                    total_txs,
                    status_economy,
                    local_runtime,
                    build_fingerprint,
                ) = match ch.try_lock() {
                    Ok(bc) => {
                        // V202: /status also refreshes the runtime status cache used by
                        // RRv3 latest snapshot serving. Height must come from the
                        // logical tip abstraction, not raw chain.last(), so pruned
                        // nodes do not publish height=0/stale cache values.
                        let height = bc.tip_height_u64();
                        let last_hash = bc
                            .chain
                            .last()
                            .map(|last| last.hash.clone())
                            .unwrap_or_default();
                        let (finalized_height, finalized_hash) = bc.finalized_view();

                        (
                            height,
                            last_hash,
                            finalized_height,
                            finalized_hash,
                            bc.chain.len() as u64,
                            bc.total_txs_cached(),
                            status_economy_supply_binding_v210(&bc),
                            bc.local_consensus_runtime_view_for_next_block(),
                            build_fingerprint(),
                        )
                    }
                    Err(TryLockError::Poisoned(poison)) => {
                        eprintln!(
                            "⚠️ chain mutex poisoned in /status; recovering with into_inner()"
                        );
                        let bc = poison.into_inner();
                        // V202: keep poisoned-lock recovery consistent with the normal
                        // branch and with provider snapshot staleness checks.
                        let height = bc.tip_height_u64();
                        let last_hash = bc
                            .chain
                            .last()
                            .map(|last| last.hash.clone())
                            .unwrap_or_default();
                        let (finalized_height, finalized_hash) = bc.finalized_view();

                        (
                            height,
                            last_hash,
                            finalized_height,
                            finalized_hash,
                            bc.chain.len() as u64,
                            bc.total_txs_cached(),
                            status_economy_supply_binding_v210(&bc),
                            bc.local_consensus_runtime_view_for_next_block(),
                            build_fingerprint(),
                        )
                    }
                    Err(TryLockError::WouldBlock) => {
                        let cache = runtime_status_cache_read_v1();
                        let degraded = build_degraded_status_from_cache_v1(
                            &cache,
                            "chain_lock_busy",
                            mempool_degraded_snapshot,
                        );
                        return warp::reply::json(&degraded);
                    }
                };

                // Snapshot veloce mempool, poi rilascio lock. Anche questo non deve bloccare /status.
                let (mempool_size, mempool_bytes, limits_json) = match mp.try_lock() {
                    Ok(mp) => {
                        let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) =
                            mp.limits_snapshot();
                        (
                            mp.len() as u64,
                            mp.total_bytes() as u64,
                            serde_json::json!({
                                "max_mempool_size": max_size as u64,
                                "max_tx_per_sender": max_tx_per_sender as u64,
                                "max_mempool_bytes": max_bytes as u64,
                                "tx_ttl_secs": tx_ttl_secs
                            }),
                        )
                    }
                    Err(TryLockError::Poisoned(poison)) => {
                        let mp = poison.into_inner();
                        let (max_size, max_tx_per_sender, max_bytes, tx_ttl_secs) =
                            mp.limits_snapshot();
                        (
                            mp.len() as u64,
                            mp.total_bytes() as u64,
                            serde_json::json!({
                                "max_mempool_size": max_size as u64,
                                "max_tx_per_sender": max_tx_per_sender as u64,
                                "max_mempool_bytes": max_bytes as u64,
                                "tx_ttl_secs": tx_ttl_secs
                            }),
                        )
                    }
                    Err(TryLockError::WouldBlock) => {
                        let (size, bytes) = mempool_degraded_snapshot.unwrap_or((0, 0));
                        (
                            size,
                            bytes,
                            serde_json::json!({
                                "status": "degraded",
                                "reason": "mempool_lock_busy"
                            }),
                        )
                    }
                };

                let local_runtime_json = json_value_for_api_v1(local_runtime);
                let status_body = json_object_for_api_v1([
                    ("status", json_value_for_api_v1("ok")),
                    (
                        "software_version",
                        json_value_for_api_v1(VersionInfo::current().software_version),
                    ),
                    (
                        "protocol_version",
                        json_value_for_api_v1(VersionInfo::current().protocol_version),
                    ),
                    (
                        "min_supported_protocol_version",
                        json_value_for_api_v1(
                            VersionInfo::current().min_supported_protocol_version,
                        ),
                    ),
                    ("api_contract", json_value_for_api_v1(API_CONTRACT)),
                    (
                        "api_contract_version",
                        json_value_for_api_v1(API_CONTRACT_VERSION),
                    ),
                    ("height", json_value_for_api_v1(height)),
                    // V315: expose the canonical tip hash under both the stable
                    // field (`last_block_hash`) and the legacy monitor aliases
                    // (`hash`, `tip_hash`).  This is intentionally API/status
                    // only: it does not mutate chain state, runtime readiness,
                    // quorum, mining, snapshot import, or finality.
                    ("hash", json_value_for_api_v1(last_hash.clone())),
                    ("tip_hash", json_value_for_api_v1(last_hash.clone())),
                    ("last_block_hash", json_value_for_api_v1(last_hash)),
                    ("finalized_height", json_value_for_api_v1(finalized_height)),
                    ("finalized_hash", json_value_for_api_v1(finalized_hash)),
                    ("total_blocks", json_value_for_api_v1(total_blocks)),
                    ("total_transactions", json_value_for_api_v1(total_txs)),
                    (
                        "network_id",
                        json_value_for_api_v1(chain_identity::network_id()),
                    ),
                    (
                        "base_fee_per_tx",
                        json_value_for_api_v1(status_economy.base_fee_per_tx),
                    ),
                    ("mempool_size", json_value_for_api_v1(mempool_size)),
                    ("mempool_bytes", json_value_for_api_v1(mempool_bytes)),
                    ("mempool_limits", limits_json),
                    (
                        "net_issued_supply",
                        json_value_for_api_v1(status_economy.net_issued_supply),
                    ),
                    (
                        "total_supply",
                        json_value_for_api_v1(status_economy.total_supply),
                    ),
                    (
                        "legacy_total_supply_alias_deprecated",
                        json_value_for_api_v1(true),
                    ),
                    (
                        "treasury_balance",
                        json_value_for_api_v1(status_economy.treasury_balance),
                    ),
                    (
                        "economy_supply_source",
                        json_value_for_api_v1(status_economy.supply_source),
                    ),
                    (
                        "economy_status_reason_codes",
                        json_value_for_api_v1(status_economy.reason_codes.clone()),
                    ),
                    (
                        "observed_local_total_supply",
                        json_value_for_api_v1(status_economy.local_observed_total_supply),
                    ),
                    (
                        "observed_local_base_fee_per_tx",
                        json_value_for_api_v1(status_economy.local_observed_base_fee_per_tx),
                    ),
                    (
                        "observed_local_treasury_balance",
                        json_value_for_api_v1(status_economy.local_observed_treasury_balance),
                    ),
                    ("local_runtime", local_runtime_json),
                    (
                        "build_fingerprint",
                        json_value_for_api_v1(build_fingerprint),
                    ),
                    ("runtime_surface", runtime_surface_json()),
                ]);

                runtime_status_cache_update_v1(runtime_status_cache_from_status_body_v1(
                    &status_body,
                ));

                warp::reply::json(&status_body)
            }
        });

    let root = warp::path::end().and(warp::get()).map(|| {
        warp::reply::json(&serde_json::json!({
            "status":"ok",
            "service":"NewGen Engine API v2",
            "hint":"usa /api/blockchain/last, /api/blockchain/last_full, /api/v2/dashboard/economy, /health",
            "build_fingerprint": build_fingerprint(),
            "runtime_surface": runtime_surface_json()
        }))
    });

    let runtime_fingerprint_v2 = warp::path!("api" / "v2" / "runtime" / "fingerprint")
        .and(warp::get())
        .map(|| {
            let v = VersionInfo::current();
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "software_version": v.software_version,
                "protocol_version": v.protocol_version,
                "min_supported_protocol_version": v.min_supported_protocol_version,
                "api_contract": API_CONTRACT,
                "api_contract_version": API_CONTRACT_VERSION,
                "build_fingerprint": build_fingerprint(),
                "runtime_surface": runtime_surface_json()
            }))
        });

    // ✅ Endpoint: /api/v2/wallet/local_pubkey
    let local_pubkey = warp::path!("api" / "v2" / "wallet" / "local_pubkey")
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .map(|_sk: Arc<SigningKey>, pk_b64: String| {
            warp::reply::json(&serde_json::json!({ "pub_key_b64": pk_b64 }))
        });

    // ==========================================================
    // Mainnet-grade: Update Validators via on-chain Governance
    //   POST /api/v2/gov/validators/update
    //
    // Nota: questa API MINA un blocco governance immediatamente.
    // Per coerenza slot-based, la chiamata deve avvenire quando questo nodo
    // è il proposer atteso per lo slot corrente (altrimenti 409).
    // ==========================================================
    let gov_validators_update = warp::path!("api" / "v2" / "gov" / "validators" / "update")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(admin_guard(admin.clone()))
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .map(
            |req: GovUpdateValidatorsReq,
             _g: (),
             chain: Arc<Mutex<Blockchain>>,
             _mp: Arc<Mutex<Mempool>>,
             _tx_p2p: UnboundedSender<NetMsg>,
             sk: Arc<SigningKey>,
             local_pk_b64: String| {
                ng_trace_throttle!(
                    key: "api_gov_validators_update_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "POST /api/v2/gov/validators/update"
                );

                if req.entries.is_empty() {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "empty_entries"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    );
                }
                if req.entries.len() > 256 {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "too_many_entries",
                            "max": 256
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    );
                }
                if req.entries.iter().any(|e| e.weight == 0) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "invalid_weight_zero"
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    );
                }

                let mut ch = lock_any!(chain);

                // Governance must be enabled.
                let (timelock, current_version) = match ch.governance.as_ref() {
                    Some(g) => {
                        // Must be Protocol Council member.
                        if !g.protocol_council.is_member(&local_pk_b64) {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "not_protocol_council_member",
                                    "local_pk_b64": local_pk_b64
                                })),
                                warp::http::StatusCode::FORBIDDEN,
                            );
                        }
                        (g.params.min_timelock_blocks, g.validator_set.version)
                    }
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "governance_disabled"
                            })),
                            warp::http::StatusCode::FAILED_DEPENDENCY,
                        );
                    }
                };

                // Compute deterministic heights for proposal inclusion (this call mines next block).
                let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                let next_height = prev_index + 1;
                let effective_height = next_height + timelock;

                // Version: explicit (must be > current) or auto-increment.
                let new_version = match req.version {
                    Some(v) => {
                        if v <= current_version {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "invalid_version",
                                    "current_version": current_version,
                                    "provided_version": v
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            );
                        }
                        v
                    }
                    None => current_version.saturating_add(1),
                };

                // Slot-proposer gate: this call must not mine "out of turn".
                // We derive local miner pubkey from policy.miner_sk_b64.
                let _miner_pub_hex = match STANDARD.decode(&ch.policy.miner_sk_b64) {
                    Ok(sk_bytes) => {
                        if sk_bytes.len() != 32 {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "miner_sk_invalid_len",
                                    "len": sk_bytes.len()
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            );
                        }
                        let sk_arr: [u8; 32] = match sk_bytes.try_into() {
                            Ok(a) => a,
                            Err(_) => {
                                return warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": "error",
                                        "message": "miner_sk_invalid_bytes"
                                    })),
                                    warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                                );
                            }
                        };
                        let miner_sk = SigningKey::from_bytes(&sk_arr);
                        hex::encode(miner_sk.verifying_key().to_bytes())
                    }
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "miner_sk_b64_decode_failed",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        );
                    }
                };

                let payload = crate::governance::ValidatorSetPayload {
                    version: new_version,
                    entries: req.entries,
                };
                let payload_bytes = match serde_json::to_vec(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "payload_serialize_failed",
                                "error": e.to_string()
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };

                let proposal_kind = crate::governance::GovProposalKind::UpdateValidators;
                let proposal_id = governance_proposal_id_v1(
                    "valset",
                    &proposal_kind,
                    &local_pk_b64,
                    &payload_bytes,
                    next_height,
                    effective_height,
                    ch.pending_governance_queue_len_v1(),
                    &ch.genesis_hash,
                );
                let mut proposal = crate::governance::TxGovernanceProposal {
                    id: proposal_id.clone(),
                    kind: proposal_kind,
                    payload: payload_bytes,
                    created_at_height: next_height,
                    effective_height,
                    proposer: local_pk_b64.clone(),
                    signature_domain: String::new(),
                    chain_id: String::new(),
                    genesis_hash: String::new(),
                    signature: String::new(),
                };

                // Canonical signature bytes v1.
                proposal.signature_domain =
                    crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                proposal.chain_id = crate::chain_identity::chain_id().to_string();
                proposal.genesis_hash = ch.genesis_hash.clone();
                let council = crate::governance::GovernanceCouncilKind::Protocol;
                let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                    Ok(m) => m,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_signing_bytes_failed",
                                "error": e
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        );
                    }
                };
                let sig = sk.sign(&msg);
                proposal.signature = STANDARD.encode(sig.to_bytes());

                let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": e.reason_code(),
                                "error": e.to_string(),
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        );
                    }
                };

                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({
                        "status": "accepted",
                        "mode": "governance_proposal_queued",
                        "canonical_inclusion": "pending_block_production",
                        "proposal_id": proposal_id,
                        "governance_flow": governance_flow_response_v1(&proposal_id),
                        "provisional_created_at_height": next_height,
                        "provisional_effective_height": effective_height,
                        "effective_height_assigned_at_inclusion": true,
                        "timelock_blocks": timelock,
                        "queue_depth": ingress.queue_depth,
                        "new_validator_set_version": new_version,
                        "entries": payload.entries.len()
                    })),
                    warp::http::StatusCode::ACCEPTED,
                )
            },
        );

    // ==========================================================
    // Mainnet-grade: NFT governance policy proposal surface
    //   POST /api/v2/gov/nft/policy/propose
    //
    // This route does not mutate governance state directly. It builds and signs
    // an UpdateGovernanceParams proposal with an NFT-only delta, validates the
    // staged policy, and queues it for the normal governance/timelock/vote path.
    // ==========================================================
    let gov_nft_policy_propose = warp::path!("api" / "v2" / "gov" / "nft" / "policy" / "propose")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .map(
            |_g: (),
             body: serde_json::Value,
             sk: Arc<SigningKey>,
             local_pk_b64: String,
             chain: SharedChain,
             _mp: SharedMempool,
             _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                ng_trace_throttle!(
                    key: "api_gov_nft_policy_propose_v1".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "POST /api/v2/gov/nft/policy/propose"
                );

                let body_obj = match body.as_object() {
                    Some(v) => v,
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "body_must_be_json_object",
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    }
                };
                if let Err(e) = reject_unknown_json_object_keys_v1(
                    body_obj,
                    nft_governance_policy_request_allowed_keys_v1(),
                    "request",
                ) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "unknown_request_field",
                            "error": e,
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let delta_value = match body_obj.get("delta") {
                    Some(v) => v,
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "missing_delta",
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    }
                };
                let delta_obj = match delta_value.as_object() {
                    Some(v) => v,
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "delta_must_be_json_object",
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    }
                };
                if let Err(e) = reject_unknown_json_object_keys_v1(
                    delta_obj,
                    nft_governance_policy_delta_allowed_keys_v1(),
                    "delta",
                ) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "nft_policy_delta_contains_non_nft_or_unknown_field",
                            "error": e,
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let delta: crate::governance::GovernanceParamsDelta =
                    match serde_json::from_value(delta_value.clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "delta_decode_failed",
                                    "error": e.to_string(),
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            )
                            .into_response();
                        }
                    };
                if nft_governance_delta_is_empty_v1(&delta) {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "empty_nft_policy_delta",
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let requested_timelock = match body_obj.get("timelock_blocks") {
                    Some(v) => match v.as_u64() {
                        Some(n) => Some(n),
                        None => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "invalid_timelock_blocks",
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            )
                            .into_response();
                        }
                    },
                    None => None,
                };
                let reason = body_obj
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned);
                if reason.as_ref().map(|s| s.len()).unwrap_or(0) > 512 {
                    return warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "reason_too_long",
                            "max_bytes": 512,
                        })),
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                    .into_response();
                }

                let mut ch = lock_any!(chain);
                let (min_timelock, current_params) = match ch.governance.as_ref() {
                    Some(g) => {
                        if !g.protocol_council.is_member(&local_pk_b64) {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "not_protocol_council_member",
                                    "local_pk_b64": local_pk_b64,
                                })),
                                warp::http::StatusCode::FORBIDDEN,
                            )
                            .into_response();
                        }
                        (g.params.min_timelock_blocks, g.params.clone())
                    }
                    None => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "governance_disabled",
                            })),
                            warp::http::StatusCode::FAILED_DEPENDENCY,
                        )
                        .into_response();
                    }
                };

                let timelock = requested_timelock.unwrap_or(min_timelock).max(min_timelock);
                let staged_params =
                    match preview_nft_governance_delta_for_api_v1(&current_params, &delta) {
                        Ok(params) => params,
                        Err(e) => {
                            return warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "nft_policy_validation_failed",
                                    "error": e,
                                })),
                                warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                            )
                            .into_response();
                        }
                    };
                let policy_hash_before = match nft_governance_policy_hash_v1(&current_params) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "policy_hash_before_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };
                let policy_hash_after = match nft_governance_policy_hash_v1(&staged_params) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "policy_hash_after_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };

                let payload_bytes = match serde_json::to_vec(delta_value) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "payload_serialize_failed",
                                "error": e.to_string(),
                            })),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into_response();
                    }
                };

                let payload_hash = hex::encode(Sha256::digest(&payload_bytes));
                let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                let next_height = prev_index + 1;
                let effective_height = next_height.saturating_add(timelock);
                let proposal_kind = crate::governance::GovProposalKind::UpdateGovernanceParams;
                let proposal_id = governance_proposal_id_v1(
                    "nft-policy-update",
                    &proposal_kind,
                    &local_pk_b64,
                    &payload_bytes,
                    next_height,
                    effective_height,
                    ch.pending_governance_queue_len_v1(),
                    &ch.genesis_hash,
                );
                let mut proposal = crate::governance::TxGovernanceProposal {
                    id: proposal_id.clone(),
                    kind: proposal_kind,
                    payload: payload_bytes,
                    created_at_height: next_height,
                    effective_height,
                    proposer: local_pk_b64.clone(),
                    signature_domain: String::new(),
                    chain_id: String::new(),
                    genesis_hash: String::new(),
                    signature: String::new(),
                };
                proposal.signature_domain =
                    crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                proposal.chain_id = crate::chain_identity::chain_id().to_string();
                proposal.genesis_hash = ch.genesis_hash.clone();
                let council = crate::governance::GovernanceCouncilKind::Protocol;
                let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                    Ok(m) => m,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "proposal_signing_bytes_failed",
                                "error": e,
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )
                        .into_response();
                    }
                };
                let proposal_hash_hex = hex::encode(Sha256::digest(&msg));
                proposal.signature = STANDARD.encode(sk.sign(&msg).to_bytes());
                let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": e.reason_code(),
                                "error": e.to_string(),
                                "proposal_id": proposal_id,
                            })),
                            warp::http::StatusCode::CONFLICT,
                        )
                        .into_response();
                    }
                };

                warp::reply::with_status(
                    warp::reply::json(&json_object_for_api_v1([
                        ("status", json_value_for_api_v1("accepted")),
                        (
                            "surface",
                            json_value_for_api_v1("nft_governance_policy_proposal_v1"),
                        ),
                        ("mode", json_value_for_api_v1("governance_proposal_queued")),
                        (
                            "canonical_inclusion",
                            json_value_for_api_v1("pending_block_production"),
                        ),
                        ("proposal_id", json_value_for_api_v1(proposal_id.clone())),
                        (
                            "proposal_hash_hex",
                            json_value_for_api_v1(proposal_hash_hex),
                        ),
                        (
                            "proposal_kind",
                            json_value_for_api_v1("UpdateGovernanceParams"),
                        ),
                        ("council", json_value_for_api_v1("Protocol")),
                        ("governance_flow", governance_flow_response_v1(&proposal_id)),
                        (
                            "provisional_created_at_height",
                            json_value_for_api_v1(next_height),
                        ),
                        (
                            "provisional_effective_height",
                            json_value_for_api_v1(effective_height),
                        ),
                        (
                            "effective_height_assigned_at_inclusion",
                            json_value_for_api_v1(true),
                        ),
                        ("timelock_blocks", json_value_for_api_v1(timelock)),
                        ("min_timelock_blocks", json_value_for_api_v1(min_timelock)),
                        ("queue_depth", json_value_for_api_v1(ingress.queue_depth)),
                        (
                            "policy_hash_before",
                            json_value_for_api_v1(policy_hash_before),
                        ),
                        (
                            "policy_hash_after",
                            json_value_for_api_v1(policy_hash_after),
                        ),
                        ("payload_hash", json_value_for_api_v1(payload_hash)),
                        (
                            "vote_path",
                            json_value_for_api_v1(format!(
                                "/api/v2/gov/proposals/{}/vote",
                                proposal_id
                            )),
                        ),
                        (
                            "proposal_path",
                            json_value_for_api_v1(format!("/api/v2/gov/proposals/{}", proposal_id)),
                        ),
                        ("reason", json_value_for_api_v1(reason)),
                    ])),
                    warp::http::StatusCode::ACCEPTED,
                )
                .into_response()
            },
        );

    // Admin helper: ritorna la pubkey validator locale (b64 + hex)
    let gov_local_validator_pubkey = warp::path!("api" / "v2" / "gov" / "local_validator_pubkey")
        .and(warp::get())
        .and(admin_guard(admin.clone()))
        .and(with_validator_key(
            validator_sk.clone(),
            validator_pk_b64.clone(),
        ))
        .map(|_g: (), _sk: Arc<SigningKey>, pk_b64: String| {
            let pk_hex = match STANDARD.decode(pk_b64.as_bytes()) {
                Ok(b) => hex::encode(b),
                Err(_) => String::new(),
            };
            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "validator_pk_b64": pk_b64,
                    "validator_pk_hex": pk_hex
                })),
                warp::http::StatusCode::OK,
            )
        });

    // ✅ DEBUG ENDPOINT: Governance on-chain (UpdateMempoolPolicy) + mining automatico
    #[cfg(debug_assertions)]
let gov_mempool_update = warp::path!("api" / "v2" / "gov" / "mempool" / "update")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .map(
            |_u: (),
             body: serde_json::Value,
             sk: Arc<SigningKey>,
             local_pk_b64: String,
             chain: Arc<Mutex<Blockchain>>,
             _mp: Arc<Mutex<Mempool>>,
             _tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                // --- Parse helper: supporta missing / null / number ---
                let opt_u64 = |k: &str| -> Option<u64> {
                    match body.get(k) {
                        None => None,
                        Some(v) if v.is_null() => None,
                        Some(v) => v.as_u64(),
                    }
                };

                // Accetta update parziale; richiedi almeno un campo valorizzato
                let max_tx_per_sender = opt_u64("max_tx_per_sender");
                let max_mempool_size = opt_u64("max_mempool_size");
                let max_mempool_bytes = opt_u64("max_mempool_bytes");
                let tx_ttl_secs = opt_u64("tx_ttl_secs");

                if max_tx_per_sender.is_none()
                    && max_mempool_size.is_none()
                    && max_mempool_bytes.is_none()
                    && tx_ttl_secs.is_none()
                {
                    return warp::reply::json(&serde_json::json!({
                        "status": "error",
                        "message": "empty_delta",
                        "example": { "max_tx_per_sender": 8 }
                    }));
                }

                // Validazione minima (puoi allargarla quando vuoi)
                if let Some(v) = max_tx_per_sender {
                    if !(1..=1024).contains(&v) {
                        return warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "invalid_max_tx_per_sender",
                            "min": 1,
                            "max": 1024,
                            "got": v
                        }));
                    }
                }

                ng_trace_throttle!(
                    key: "api_gov_mempool_update_v2".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "POST /api/v2/gov/mempool/update"
                );

                let mut ch = lock_any!(chain);

                let (timelock, proposer) = match ch.governance.as_ref() {
                    Some(g) => {
                        // Mainnet-grade: la proposal deve essere firmata dal validator locale e
                        // il proposer deve essere un membro del Protocol Council (check per-bytes).
                        if !g.protocol_council.is_member(&local_pk_b64) {
                            return warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "not_protocol_council_member",
                                "local_pk_b64": local_pk_b64
                            }));
                        }
                        (g.params.min_timelock_blocks, local_pk_b64.clone())
                    }
                    None => {
                        return warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "governance_disabled"
                        }));
                    }
                };

                let prev_index = ch.chain.last().map(|b| b.index).unwrap_or(0);
                let next_height = prev_index + 1;
                let effective_height = next_height + timelock;

                // ✅ DELTA costruito dal BODY (non hardcoded!)
                let delta = crate::governance::MempoolPolicyDelta {
                    max_mempool_bytes,
                    max_mempool_size,
                    max_tx_per_sender,
                    tx_ttl_secs,
                };

                ng_debug_throttle!(
                    key: "api_gov_mempool_delta".to_string(),
                    every_ms: 30000,
                    target: "api.req",
                    "mempool.update delta max_tx_per_sender={:?} max_mempool_size={:?} max_mempool_bytes={:?} tx_ttl_secs={:?}",
                    max_tx_per_sender,
                    max_mempool_size,
                    max_mempool_bytes,
                    tx_ttl_secs
                );

                let payload = serde_json::to_vec(&delta).unwrap_or_default();
                let proposal_kind = crate::governance::GovProposalKind::UpdateMempoolPolicy;
                let proposal_id = governance_proposal_id_v1(
                    "dbg-mempool",
                    &proposal_kind,
                    &proposer,
                    &payload,
                    next_height,
                    effective_height,
                    ch.pending_governance_queue_len_v1(),
                    &ch.genesis_hash,
                );

                let mut proposal = crate::governance::TxGovernanceProposal {
                    id: proposal_id.clone(),
                    kind: proposal_kind,
                    payload,
                    created_at_height: next_height,
                    effective_height,
                    proposer,
                    signature_domain: String::new(),
                chain_id: String::new(),
                genesis_hash: String::new(),
                signature: String::new(),
                };

                // Firma deterministica (ed25519, base64(64)) su bytes canonici v1.
                proposal.signature_domain = crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string();
                proposal.chain_id = crate::chain_identity::chain_id().to_string();
                proposal.genesis_hash = ch.genesis_hash.clone();
                let council = crate::governance::GovernanceCouncilKind::Protocol;
                let msg = match crate::governance::proposal_signing_bytes_v1(&proposal, &council) {
                    Ok(m) => m,
                    Err(e) => {
                        return warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "proposal_signing_bytes_failed",
                            "error": e
                        }));
                    }
                };
                let sig = sk.sign(&msg);
                proposal.signature = STANDARD.encode(sig.to_bytes());

                let ingress = match ch.enqueue_governance_proposal_v1(proposal) {
                    Ok(v) => v,
                    Err(e) => {
                        return warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": e.reason_code(),
                            "error": e.to_string(),
                            "proposal_id": proposal_id,
                        }));
                    }
                };

                // Risposta: la policy sarà applicata canonicalmente dopo inclusione/finality/timelock.
                warp::reply::json(&serde_json::json!({
                    "status": "accepted",
                    "mode": "governance_proposal_queued",
                    "canonical_inclusion": "pending_block_production",
                    "proposal_id": proposal_id,
                    "governance_flow": governance_flow_response_v1(&proposal_id),
                    "timelock_blocks": timelock,
                    "provisional_effective_height": effective_height,
                    "effective_height_assigned_at_inclusion": true,
                    "queue_depth": ingress.queue_depth,
                    "delta": delta
                }))
            },
        );

    // ✅ DEBUG ENDPOINT: mine blocchi vuoti (solo debug, mai in release)
    #[cfg(debug_assertions)]
    let debug_mine_empty_v2 = warp::path!("api" / "v2" / "debug" / "mine_empty")
        .and(warp::post())
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .map(
            |req: MineEmptyReq,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>,
             tx_p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>| {
                let count = req.count.unwrap_or(1).clamp(1, 10_000);

                let before = {
                    let ch = lock_any!(chain);
                    let h = ch.chain.len().saturating_sub(1) as u64;
                    let hash = ch.chain.last().map(|b| b.hash.clone()).unwrap_or_default();
                    (h, hash)
                };

                for _ in 0..count {
                    let mut ch = lock_any!(chain);
                    ch.mine_governance_block(vec![], &mp, &tx_p2p, true);
                }

                let after = {
                    let ch = lock_any!(chain);
                    let h = ch.chain.len().saturating_sub(1) as u64;
                    let hash = ch.chain.last().map(|b| b.hash.clone()).unwrap_or_default();
                    (h, hash)
                };

                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "mined": count,
                    "before_height": before.0,
                    "after_height": after.0,
                    "before_hash": before.1,
                    "after_hash": after.1
                }))
            },
        );

    // ------- PoS (Phase 2) — server-signed RANDAO helpers (admin-only) -------
    // Questi endpoint sono SOLO per tool locali / gate di test (Phase2_Randao_Gate.ps1).
    // In produzione, i validator firmano client-side e inviano via /api/v2/tx/submit_signed.
    let pos_randao_commit_from_node = warp::path!("api" / "v2" / "pos" / "randao" / "commit_from_node")
        .and(warp::post())
        .and(admin_guard(admin.clone()))
        .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
        .and(warp::body::json())
        .and(with_chain(chain.clone()))
        .and(with_mempool(mempool.clone()))
        .and(with_p2p(tx_p2p.clone()))
        .and(with_validator_key(validator_sk.clone(), validator_pk_b64.clone()))
        .and_then(
            |_guard: (),
             req: RandaoFromNodeReq,
             chain: Arc<Mutex<Blockchain>>,
             mp: Arc<Mutex<Mempool>>,
             p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
             signer: Arc<SigningKey>,
             pk_b64: String| async move {
                // Decode/normalize secret (32B)
                let secret = match crate::keyfmt::decode_pk_any(&req.secret_b64) {
                    Ok(s) => s,
                    Err(_) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "error",
                                "message": "bad_secret",
                                "expected": "32 bytes (base64 o hex)"
                            })),
                            warp::http::StatusCode::BAD_REQUEST,
                        ));
                    }
                };

                let commit = pos::commit_hash_v1(&secret);
                let commit_b64 = STANDARD.encode(commit);

                let memo = serde_json::json!({
                    "v": 1,
                    "op": "randao_commit",
                    "epoch": req.epoch,
                    "commit_b64": commit_b64
                })
                .to_string();

                let pk_b64 = pk_b64.trim().to_string();

                let admission = snapshot_sender_admission_state(&chain, &mp, &pk_b64);
                let base_fee = admission.base_fee_per_tx;
                let total_required = base_fee;
                if let Some(reply) = reject_if_sender_cannot_cover_pending(
                    &admission,
                    total_required,
                    0,
                    base_fee,
                    0,
                ) {
                    return Ok::<_, warp::Rejection>(reply);
                }

                let expected_nonce = admission.expected_next_nonce();

                let sk = signer.as_ref();

                let mut tx = Transaction {
                    sender: pk_b64.clone(),
                    receiver: staking::STAKE_RECEIVER.to_string(),
                    amount: 0,
                    max_fee_per_tx: base_fee,
                    nonce: expected_nonce,
                    signature: String::new(),
                    hash: String::new(),
                    is_coinbase: false,
                    memo: Some(memo.clone()),
                };

                let payload = TransactionPayload {
                    network_id: chain_identity::network_id().to_string(),
                    from: tx.sender.clone(),
                    to: tx.receiver.clone(),
                    amount: tx.amount,
                    max_fee_per_tx: tx.max_fee_per_tx,
                    nonce: tx.nonce,
                    memo: tx.memo.clone(),
                };

                let msg = canonical_signing_string(&payload);
                let sig = sk.sign(msg.as_bytes());
                tx.signature = STANDARD.encode(sig.to_bytes());
                tx.hash = tx.calculate_hash();

                // Security: enforce minimal fee
                if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "fee_too_low_for_security",
                            "required_min_fee": fee_err.required_min_fee,
                            "provided_max_fee_per_tx": fee_err.provided_max_fee,
                            "tx_size_bytes": fee_err.tx_size_bytes
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                if !tx.verify_signature() {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "invalid_signature"
                        })),
                        warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                    ));
                }

                // Add to mempool + gossip
                let accepted = {
                    let mut mp_lock = lock_any!(mp);
                    mp_lock.add(tx.clone())
                };

                if accepted {
                    let _ = p2p.send(NetMsg::NewTx(tx.clone()));
                    Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "ok",
                            "epoch": req.epoch,
                            "commit_b64": tx.memo.as_ref().and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok()).and_then(|v| v.get("commit_b64").and_then(|x| x.as_str()).map(|s| s.to_string())).unwrap_or_default(),
                            "tx_hash": tx.hash,
                            "sender": tx.sender,
                            "nonce": tx.nonce,
                            "base_fee_per_tx": base_fee
                        })),
                        warp::http::StatusCode::OK,
                    ))
                } else {
                    Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status": "mempool_full_or_rejected"
                        })),
                        warp::http::StatusCode::CONFLICT,
                    ))
                }
            },
        );

    let pos_randao_reveal_from_node =
        warp::path!("api" / "v2" / "pos" / "randao" / "reveal_from_node")
            .and(warp::post())
            .and(admin_guard(admin.clone()))
            .and(warp::body::content_length_limit(MAX_SMALL_BODY_BYTES))
            .and(warp::body::json())
            .and(with_chain(chain.clone()))
            .and(with_mempool(mempool.clone()))
            .and(with_p2p(tx_p2p.clone()))
            .and(with_validator_key(
                validator_sk.clone(),
                validator_pk_b64.clone(),
            ))
            .and_then(
                |_guard: (),
                 req: RandaoFromNodeReq,
                 chain: Arc<Mutex<Blockchain>>,
                 mp: Arc<Mutex<Mempool>>,
                 p2p: tokio::sync::mpsc::UnboundedSender<NetMsg>,
                 signer: Arc<SigningKey>,
                 pk_b64: String| async move {
                    // Decode/normalize secret (32B) and canonicalize to base64 for memo
                    let secret = match crate::keyfmt::decode_pk_any(&req.secret_b64) {
                        Ok(s) => s,
                        Err(_) => {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "bad_secret",
                                    "expected": "32 bytes (base64 o hex)"
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ));
                        }
                    };
                    let secret_b64 = STANDARD.encode(secret);

                    let memo = serde_json::json!({
                        "v": 1,
                        "op": "randao_reveal",
                        "epoch": req.epoch,
                        "secret_b64": secret_b64
                    })
                    .to_string();

                    let pk_b64 = pk_b64.trim().to_string();

                    let admission = snapshot_sender_admission_state(&chain, &mp, &pk_b64);
                    let base_fee = admission.base_fee_per_tx;
                    let total_required = base_fee;
                    if let Some(reply) = reject_if_sender_cannot_cover_pending(
                        &admission,
                        total_required,
                        0,
                        base_fee,
                        0,
                    ) {
                        return Ok::<_, warp::Rejection>(reply);
                    }

                    let expected_nonce = admission.expected_next_nonce();

                    let sk = signer.as_ref();

                    let mut tx = Transaction {
                        sender: pk_b64.clone(),
                        receiver: staking::STAKE_RECEIVER.to_string(),
                        amount: 0,
                        max_fee_per_tx: base_fee,
                        nonce: expected_nonce,
                        signature: String::new(),
                        hash: String::new(),
                        is_coinbase: false,
                        memo: Some(memo.clone()),
                    };

                    let payload = TransactionPayload {
                        network_id: chain_identity::network_id().to_string(),
                        from: tx.sender.clone(),
                        to: tx.receiver.clone(),
                        amount: tx.amount,
                        max_fee_per_tx: tx.max_fee_per_tx,
                        nonce: tx.nonce,
                        memo: tx.memo.clone(),
                    };

                    let msg = canonical_signing_string(&payload);
                    let sig = sk.sign(msg.as_bytes());
                    tx.signature = STANDARD.encode(sig.to_bytes());
                    tx.hash = tx.calculate_hash();

                    if let Err(fee_err) = enforce_security_fee_with_mempool_snapshot(&mp, &tx) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "fee_too_low_for_security",
                                "required_min_fee": fee_err.required_min_fee,
                                "provided_max_fee_per_tx": fee_err.provided_max_fee,
                                "tx_size_bytes": fee_err.tx_size_bytes
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }

                    if !tx.verify_signature() {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "invalid_signature"
                            })),
                            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
                        ));
                    }

                    let accepted = {
                        let mut mp_lock = lock_any!(mp);
                        mp_lock.add(tx.clone())
                    };

                    if accepted {
                        let _ = p2p.send(NetMsg::NewTx(tx.clone()));
                        Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "ok",
                                "epoch": req.epoch,
                                "tx_hash": tx.hash,
                                "sender": tx.sender,
                                "nonce": tx.nonce,
                                "base_fee_per_tx": base_fee
                            })),
                            warp::http::StatusCode::OK,
                        ))
                    } else {
                        Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status": "mempool_full_or_rejected"
                            })),
                            warp::http::StatusCode::CONFLICT,
                        ))
                    }
                },
            );

    // ------- Consensus Finality (Phase 3C) -------
    // Stable endpoint used by Step 3C strict runner to assert invariants during partition/rejoin.
    // Exposed both under /api/v1 and /api/v2 for tooling compatibility.
    let consensus_finality_v1 = warp::path!("api" / "v1" / "consensus" / "finality")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let view = {
                let bc = lock_any!(ch);
                bc.cognitive_consensus_finality_view_v1()
            };

            match view {
                Ok(view) => match validate_api_cognitive_consensus_finality_view_v1(&view) {
                    Ok(()) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&CognitiveViewEnvelopeV1 {
                                status: "ok",
                                format_version: view.format_version,
                                view,
                            }),
                            warp::http::StatusCode::OK,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                },
                Err(e) => {
                    cognitive_api_error_reply_v1(e, warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        });

    let consensus_finality_v2 = warp::path!("api" / "v2" / "consensus" / "finality")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let view = {
                let bc = lock_any!(ch);
                bc.cognitive_consensus_finality_view_v1()
            };

            match view {
                Ok(view) => match validate_api_cognitive_consensus_finality_view_v1(&view) {
                    Ok(()) => {
                        let hash_ready =
                            view.finalized_height == 0 || !view.finalized_hash.trim().is_empty();
                        let status = if hash_ready {
                            warp::http::StatusCode::OK
                        } else {
                            warp::http::StatusCode::SERVICE_UNAVAILABLE
                        };
                        warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&CognitiveConsensusFinalityEnvelopeV2 {
                                    status: if hash_ready { "ok" } else { "degraded" },
                                    format_version: view.format_version,
                                    view,
                                    e2_ready: hash_ready,
                                    unavailable_reason: if hash_ready {
                                        None
                                    } else {
                                        Some("finalized_hash_unavailable".to_string())
                                    },
                                }),
                                status,
                            ),
                            "Cache-Control",
                            "no-store",
                        )
                        .into_response()
                    }
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                },
                Err(e) => {
                    cognitive_api_error_reply_v1(e, warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        });

    let cognitive_contract_v2 = warp::path!("api" / "v2" / "cognitive" / "contract")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let bc = lock_any!(ch);
            match bc.cognitive_contract_snapshot_v1() {
                Ok(view) => match validate_api_cognitive_contract_snapshot_v1(&view) {
                    Ok(()) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&CognitiveViewEnvelopeV1 {
                                status: "ok",
                                format_version: view.format_version,
                                view,
                            }),
                            warp::http::StatusCode::OK,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                },
                Err(e) => {
                    cognitive_api_error_reply_v1(e, warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        });

    // ------- Cognitive Registry (read-only, finality-aware) -------
    let cognitive_registry_object_v2 =
        warp::path!("api" / "v2" / "cognitive" / "registry" / "object" / String)
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|object_hash: String, ch: SharedChain| {
                if let Err(e) = validate_sha256_hex_field("object_hash", &object_hash) {
                    return cognitive_api_error_reply_v1(e, warp::http::StatusCode::BAD_REQUEST);
                }
                let bc = lock_any!(ch);
                crate::perf_metrics::cognitive_registry_object_read();
                match bc.get_cognitive_registry_object_view_by_object_hash_v1(&object_hash) {
                    Ok(Some(view)) => match validate_api_cognitive_object_view_v1(&view) {
                        Ok(()) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&CognitiveViewEnvelopeV1 {
                                    status: "ok",
                                    format_version: view.format_version,
                                    view,
                                }),
                                warp::http::StatusCode::OK,
                            ),
                            "Cache-Control",
                            "no-store",
                        )
                        .into_response(),
                        Err(e) => cognitive_api_error_reply_v1(
                            e,
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    },
                    Ok(None) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&CognitiveNotFoundEnvelopeV1 {
                                status: "not_found",
                                format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
                                object_hash,
                            }),
                            warp::http::StatusCode::NOT_FOUND,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                }
            });

    let cognitive_registry_claim_v2 =
        warp::path!("api" / "v2" / "cognitive" / "registry" / "claim" / String)
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|claim_hash: String, ch: SharedChain| {
                if let Err(e) = validate_sha256_hex_field("claim_hash", &claim_hash) {
                    return warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response();
                }
                let bc = lock_any!(ch);
                crate::perf_metrics::cognitive_registry_claim_read();
                match bc.get_cognitive_registry_claim_view_by_claim_hash_v1(&claim_hash) {
                    Ok(view) => match validate_api_cognitive_claim_view_v1(&view) {
                        Ok(()) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&CognitiveViewEnvelopeV1 {
                                    status: "ok",
                                    format_version: view.reconciliation_context.format_version,
                                    view,
                                }),
                                warp::http::StatusCode::OK,
                            ),
                            "Cache-Control",
                            "no-store",
                        )
                        .into_response(),
                        Err(e) => cognitive_api_error_reply_v1(
                            e,
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    },
                    Err(e) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                }
            });

    let cognitive_registry_status_v2 =
        warp::path!("api" / "v2" / "cognitive" / "registry" / "status" / String)
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|object_hash: String, ch: SharedChain| {
                if let Err(e) = validate_sha256_hex_field("object_hash", &object_hash) {
                    return cognitive_api_error_reply_v1(e, warp::http::StatusCode::BAD_REQUEST);
                }
                let bc = lock_any!(ch);
                crate::perf_metrics::cognitive_registry_status_read();
                match bc.get_cognitive_registry_status_view_by_object_hash_v1(&object_hash) {
                    Ok(Some(view)) => match validate_api_cognitive_status_view_v1(&view) {
                        Ok(()) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&CognitiveViewEnvelopeV1 {
                                    status: "ok",
                                    format_version: view.format_version,
                                    view,
                                }),
                                warp::http::StatusCode::OK,
                            ),
                            "Cache-Control",
                            "no-store",
                        )
                        .into_response(),
                        Err(e) => cognitive_api_error_reply_v1(
                            e,
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    },
                    Ok(None) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&CognitiveNotFoundEnvelopeV1 {
                                status: "not_found",
                                format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
                                object_hash,
                            }),
                            warp::http::StatusCode::NOT_FOUND,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                }
            });

    let cognitive_registry_meta_v2 = warp::path!("api" / "v2" / "cognitive" / "registry" / "meta")
        .and(warp::get())
        .and(with_chain(chain.clone()))
        .map(|ch: SharedChain| {
            let bc = lock_any!(ch);
            crate::perf_metrics::cognitive_registry_meta_read();
            match bc.cognitive_registry_meta_view_v1() {
                Ok(view) => match validate_api_cognitive_reconciliation_context_v1(&view) {
                    Ok(()) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&CognitiveViewEnvelopeV1 {
                                status: "ok",
                                format_version: view.format_version,
                                view,
                            }),
                            warp::http::StatusCode::OK,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => cognitive_api_error_reply_v1(
                        e,
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                },
                Err(e) => warp::reply::with_header(
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                    "Cache-Control",
                    "no-store",
                )
                .into_response(),
            }
        });

    let cognitive_registry_events_v2 =
        warp::path!("api" / "v2" / "cognitive" / "registry" / "events")
            .and(warp::get())
            .and(warp::query::<CognitiveRegistryEventsQuery>())
            .and(with_chain(chain.clone()))
            .map(|q: CognitiveRegistryEventsQuery, ch: SharedChain| {
                let from_height = q.from_height.unwrap_or(0);
                let limit = q
                    .limit
                    .unwrap_or(COGNITIVE_REGISTRY_EVENTS_DEFAULT_LIMIT)
                    .min(COGNITIVE_REGISTRY_EVENTS_MAX_LIMIT)
                    .max(1);
                let bc = lock_any!(ch);
                crate::perf_metrics::cognitive_registry_events_read();
                match bc.get_cognitive_registry_events_since(from_height, limit) {
                    Ok(events) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "status":"ok",
                                "from_height": from_height,
                                "limit": limit,
                                "returned": events.len(),
                                "events": events
                            })),
                            warp::http::StatusCode::OK,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                    Err(e) => warp::reply::with_header(
                        warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                        "Cache-Control",
                        "no-store",
                    )
                    .into_response(),
                }
            });

    // ------- Merge rotte -------

    // Normalizziamo tutte le rotte a un unico tipo concreto (warp::reply::Response),
    // così possiamo comporre `.or(...)` senza incappare in `Either<...>` annidati e E0308.
    use warp::filters::BoxedFilter;
    use warp::reply::Response;
    use warp::Reply;

    type RespFilter = BoxedFilter<(Response,)>;

    fn as_response<F, R>(f: F) -> RespFilter
    where
        F: Filter<Extract = (R,), Error = warp::Rejection> + Clone + Send + Sync + 'static,
        R: Reply + 'static,
    {
        f.map(|r: R| r.into_response()).boxed()
    }

    fn merge_resp_filters(filters: Vec<RespFilter>) -> RespFilter {
        let mut iter = filters.into_iter();
        let mut acc = iter
            .next()
            .expect("merge_resp_filters requires at least one filter");
        for filter in iter {
            acc = acc.or(filter).unify().boxed();
        }
        acc
    }

    // Rotte "core" (pubbliche, stabili) — sempre esposte
    let core_routes: RespFilter = merge_resp_filters(vec![
        as_response(mempool_route),
        as_response(blockchain_last),
        as_response(blockchain_last_full),
        as_response(blockchain_info),
        as_response(blockchain_info_v2),
        as_response(blocks_v2),
        as_response(block_by_height_v2),
        as_response(wallet_history),
        as_response(treasury_state),
        as_response(economy_controller_contract),
        as_response(economy_dashboard),
        as_response(economy_series),
        as_response(security_metrics),
        as_response(security_reputation),
        as_response(reputation_run),
        as_response(reputation_wallet),
        as_response(reputation_canonical_nodes),
        as_response(reputation_canonical_wallets),
        as_response(reputation_canonical_eligibility),
        as_response(reputation_canonical_workers),
        as_response(reputation_canonical_worker_privileges),
        as_response(reputation_canonical_worker_eligibility),
        as_response(reputation_canonical_worker_privilege_debug),
        reputation_bridge.clone(),
        as_response(reputation_claims_canonical),
        as_response(reputation_evidence_canonical),
        as_response(reputation_e2_worker_evidence_canonical),
        as_response(e2_worker_register_build_unsigned_v1),
        as_response(e2_worker_evidence_build_unsigned_v1),
        as_response(e2_worker_bootstrap_probe_contract_route_v1),
        as_response(reputation_e2_worker_evidence_ingest),
        as_response(compute_fiat_settlement_proof_ingest),
        as_response(compute_fiat_settlement_proof_canonical),
        gov_wallet_reputation_ingest_run.clone(),
        as_response(perf_metrics_v2),
        as_response(governance_state_v2),
        as_response(gov_proposals_list.clone()),
        as_response(gov_proposal_get.clone()),
        as_response(ft_token_v1),
        as_response(ft_balance_v1),
        as_response(ft_allowance_v1),
        as_response(ft_frozen_v1),
        as_response(ft_metrics_v1),
        as_response(nft_collection_v1),
        as_response(nft_token_v1),
        as_response(nft_owner_of_v1),
        as_response(nft_approval_v1),
        as_response(nft_operator_approval_v1),
        as_response(nft_wallet_assets_v1),
        as_response(nft_owner_collections_v1),
        as_response(nft_collection_tokens_v1),
        as_response(nft_collections_v1),
        as_response(nft_recent_activity_v1),
        as_response(nft_estimate_fee_v1),
        as_response(nft_build_unsigned_v1),
        as_response(nft_policy_v1),
        as_response(nft_metrics_v1),
        as_response(governance_state),
        as_response(pos_state_v2),
        as_response(pos_leader_v2),
        as_response(consensus_finality_v1),
        as_response(consensus_finality_v2),
        as_response(cognitive_contract_v2),
        as_response(cognitive_registry_object_v2),
        as_response(cognitive_registry_claim_v2),
        as_response(cognitive_registry_status_v2),
        as_response(cognitive_registry_meta_v2),
        as_response(cognitive_registry_events_v2),
        as_response(governance_validators_v2),
        as_response(governance_ops_log_v2),
        as_response(governance_consensus_status_v2),
        as_response(governance_expected_proposer_v2),
        as_response(governance_validators_status_v2),
        as_response(governance_validators_status_finalized_v2),
        as_response(e2_contract_v2),
        as_response(e2_orders_v2),
        as_response(e2_order_events_v2),
        as_response(e2_order_by_id_v2),
        as_response(e2_worker_admission_v2),
        as_response(governance_validators),
        as_response(epn_history),
        as_response(tx_submit_signed),
        as_response(tx_by_hash_route),
        as_response(tx_by_hash_route_legacy),
        as_response(light_headers_route),
        as_response(light_tx_proof_route),
        as_response(light_state_proof_route),
        as_response(light_state_proof_query_route),
        as_response(get_next_nonce),
        as_response(get_next_nonce_legacy),
        as_response(get_v2_wallet_balance),
        as_response(health),
        as_response(readyz),
        as_response(root),
        as_response(runtime_fingerprint_v2),
        as_response(status),
        as_response(mempool_limits),
        as_response(mempool_stats),
    ]);

    // Rotte ad alto impatto (admin/dev): non devono essere parte della superficie pubblica.
    // In release vengono montate SOLO se NEWGEN_API_ADMIN_TOKEN è impostato.
    let admin_routes: RespFilter = {
        let admin_routes: RespFilter = merge_resp_filters(vec![
            as_response(blockchain_full),
            as_response(blockchain_all),
        ]);

        let admin_routes: RespFilter = if follower_mode {
            admin_routes
        } else if public_mode {
            // Public mode keeps governed/admin proposal surfaces, but never mounts
            // node-local transaction signer, faucet/wallet generators, manual mining,
            // or node-signed FT/NFT convenience endpoints.
            merge_resp_filters(vec![
                as_response(gov_validators_update),
                as_response(gov_nft_policy_propose),
                as_response(gov_e2_worker_operator_bind),
                as_response(gov_e2_worker_privilege),
                as_response(gov_proposal_vote),
                as_response(gov_ingress_pending),
                as_response(gov_local_validator_pubkey),
                admin_routes,
            ])
        } else {
            merge_resp_filters(vec![
                as_response(mine_block),
                as_response(wallet_secure_new),
                as_response(wallet_secure_new_v2),
                as_response(ui_send_tx),
                as_response(tx_sign_from_node),
                as_response(ft_send_from_node),
                as_response(nft_send_from_node),
                as_response(pos_randao_commit_from_node),
                as_response(pos_randao_reveal_from_node),
                as_response(tx_submit),
                as_response(gov_validators_update),
                as_response(gov_nft_policy_propose),
                as_response(gov_e2_worker_operator_bind),
                as_response(gov_e2_worker_privilege),
                as_response(gov_proposal_vote),
                as_response(gov_ingress_pending),
                as_response(gov_local_validator_pubkey),
                admin_routes,
            ])
        };

        #[cfg(debug_assertions)]
        let admin_routes: RespFilter = if follower_mode || public_mode {
            admin_routes
        } else {
            merge_resp_filters(vec![admin_routes, as_response(gov_mempool_update)])
        };

        admin_routes
    };

    // Start: solo core
    let mut routes: RespFilter = core_routes;

    if !follower_mode && !public_mode {
        let signer_core_routes: RespFilter = merge_resp_filters(vec![
            as_response(get_node_wallet_info),
            as_response(local_pubkey),
        ]);
        routes = merge_resp_filters(vec![routes, signer_core_routes]);
    } else if public_mode {
        eprintln!(
            "⚠️ [API BOOT] node-local wallet info/pubkey routes not mounted because public_mode=true"
        );
    }

    // In debug aggiungiamo i tool da laboratorio (compilati solo in debug).
    // Anche in debug non devono essere montati se il nodo gira in public_mode.
    #[cfg(debug_assertions)]
    {
        if !public_mode {
            let debug_tools: RespFilter = as_response(debug_mine_empty_v2);

            routes = merge_resp_filters(vec![routes, debug_tools]);
        } else {
            eprintln!("⚠️ [API DEV] debug_mine_empty_v2 not mounted because public_mode=true");
        }
    }

    // Admin endpoints: abilitati in debug oppure se token presente
    if admin_enabled {
        routes = merge_resp_filters(vec![routes, admin_routes]);
    }

    // In debug: esponi anche generatori chiavi / faucet solo in dev/local mode.
    #[cfg(debug_assertions)]
    {
        if !public_mode {
            let dev_tools: RespFilter = merge_resp_filters(vec![
                as_response(wallet_new),
                as_response(wallet_new_b64),
                as_response(faucet_request),
            ]);

            routes = merge_resp_filters(vec![routes, dev_tools]);
        } else {
            eprintln!(
                "⚠️ [API DEV] wallet/faucet debug endpoints not mounted because public_mode=true"
            );
        }
    }

    // Preflight OPTIONS catch-all (Angular/browser friendly)
    // NOTE: do NOT leak MethodNotAllowed for non-OPTIONS requests, otherwise unknown routes become 405 instead of 404.
    let preflight: RespFilter = warp::any()
        .and(warp::method())
        .and_then(|m: Method| async move {
            if m == Method::OPTIONS {
                Ok::<Response, warp::Rejection>(warp::reply().into_response())
            } else {
                Err(warp::reject::not_found())
            }
        })
        .boxed();

    let routes: RespFilter = merge_resp_filters(vec![routes, preflight]);

    // ----- Abuse-resistance gate (rate limit + concurrency) -----
    let api_guard_cfg = ApiGuardConfig::resolve(public_mode);
    eprintln!(
        "ℹ️ [API BOOT] abuse_guard_profile={} general={:.1}/{:.1} heavy={:.1}/{:.1} tx_submit={:.1}/{:.1} max_in_flight={}",
        api_guard_cfg.profile.as_str(),
        api_guard_cfg.general.rps,
        api_guard_cfg.general.burst,
        api_guard_cfg.heavy_read.rps,
        api_guard_cfg.heavy_read.burst,
        api_guard_cfg.tx_submit.rps,
        api_guard_cfg.tx_submit.burst,
        api_guard_cfg.max_in_flight,
    );
    let rate_limiter = Arc::new(RateLimiter::new(&api_guard_cfg));
    let sem = Arc::new(Semaphore::new(api_guard_cfg.max_in_flight));

    // Evaluate guard BEFORE executing route handlers.
    let guard = warp::addr::remote()
        .and(warp::path::full())
        .and(warp::method())
        .and(with_rate_limiter(rate_limiter.clone()))
        .and(with_semaphore(sem.clone()))
        .and_then(abuse_guard);

    // Attach headers after handler completes; keep permit alive until response is built.
    let routes: RespFilter = guard
        .and(routes)
        .map(
            |(path, method, _permit): (FullPath, Method, OwnedSemaphorePermit),
             mut resp: Response| {
                apply_common_headers(path.as_str(), &method, &mut resp);
                resp
            },
        )
        .boxed();

    // Bind address:
    // - default: 127.0.0.1 (safe for native/local runs)
    // - Docker/chaos: set NEWGEN_API_BIND_ADDR=0.0.0.0 in compose
    let api_bind_host = std::env::var("NEWGEN_API_BIND_ADDR")
        .or_else(|_| std::env::var("NEWGEN_API_HOST"))
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let api_bind_ip = api_bind_host
        .parse::<std::net::IpAddr>()
        .unwrap_or_else(|_| {
            eprintln!(
                "⚠️ [API] NEWGEN_API_BIND_ADDR='{}' non valido → fallback 127.0.0.1",
                api_bind_host
            );
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });

    let addr = std::net::SocketAddr::new(api_bind_ip, api_port);
    enforce_admin_public_bind_policy_v1(public_mode, admin_enabled, api_bind_ip);
    println!("🌍 API HTTP (v2) attiva su http://{}", addr);

    // ------ Avvio con error handler PRIMA del CORS ------
    warp::serve(routes.recover(error_handler).with(cors))
        .run(addr)
        .await;
}

#[cfg(test)]
mod api_tests {
    use super::*;

    #[cfg(debug_assertions)]
    #[test]
    fn debug_faucet_mempool_path_is_disabled_v188() {
        let reply = debug_faucet_mempool_disabled_response_v1("wallet-receiver".to_string(), 123);
        assert_eq!(reply["status"].as_str(), Some("error"));
        assert_eq!(
            reply["message"].as_str(),
            Some("debug_faucet_mempool_path_disabled")
        );
        assert_eq!(
            reply["reason"].as_str(),
            Some("coinbase_transactions_are_block_rewards_only")
        );
        assert_eq!(reply["to"].as_str(), Some("wallet-receiver"));
        assert_eq!(reply["amount"].as_u64(), Some(123));
        let encoded = serde_json::to_string(&reply).unwrap();
        assert!(!encoded.contains("is_coinbase"));
        assert!(!encoded.contains("\"coinbase\":true"));
    }
    use crate::block::Block;
    use std::sync::{Mutex as StdMutex, OnceLock};
    use warp::Reply;

    fn env_test_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    fn mk_block(height: u64, txs: Vec<Transaction>) -> Block {
        Block {
            index: height,
            timestamp: 1000 + height,
            transactions: txs,
            previous_hash: format!("prev-{}", height.saturating_sub(1)),
            hash: format!("hash-{}", height),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: "MINER".to_string(),
            signature: None,
            governance_txs: vec![],
            cognitive_txs: vec![],
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: vec![],
            nft_events: vec![],
        }
    }

    fn mk_ft_tx(sender: &str, memo: serde_json::Value, nonce: u64) -> Transaction {
        Transaction::new(
            sender.to_string(),
            crate::ft::FT_RECEIVER.to_string(),
            0,
            nonce,
            0,
            String::new(),
            false,
            Some(serde_json::to_string(&memo).unwrap()),
        )
    }

    #[test]
    fn e2_bootstrap_probe_preflight_exposes_repair_contract_without_relaxing_validation() {
        let ev = crate::e2_worker_evidence::E2WorkerExecutionEvidenceV1 {
            format_version: crate::e2_worker_evidence::E2_WORKER_EVIDENCE_FORMAT_VERSION_V2
                .to_string(),
            chain_id: "newgen-local".to_string(),
            genesis_hash: "ab".repeat(32),
            e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
            order_id: "00".repeat(32),
            job_id: "probe-job-1".to_string(),
            job_kind: "health_probe".to_string(),
            worker_node_pubkey: "worker".to_string(),
            operator_wallet_pubkey: "operator".to_string(),
            payer_wallet: "operator".to_string(),
            order_created_height: 0,
            order_claimed_height: 0,
            order_terminal_height: 0,
            result_hash: Some("11".repeat(32)),
            artifact_root_hash: None,
            receipt_hash: None,
            execution_status: "COMPLETED".to_string(),
            failure_class: crate::e2_worker_evidence::FAILURE_SUCCESS.to_string(),
            sla_ms: 1,
            max_time_ms: 1,
            coordinator_id: "coord".to_string(),
            attester_pubkey: "attester".to_string(),
            evidence_timestamp_ms: 1,
            evidence_hash: String::new(),
            signature: String::new(),
        };
        let preflight = e2_worker_evidence_bootstrap_probe_preflight_v1(&ev);
        assert_eq!(preflight["is_bootstrap_probe_shape"], true);
        assert_eq!(preflight["job_kind_allowed"], false);
        assert_eq!(preflight["order_id_matches"], false);
        assert_eq!(preflight["canonical_job_kind"], "probe:v1");
        assert!(preflight["expected_order_id"].as_str().unwrap().len() == 64);
        assert!(preflight["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("e2_worker_probe_bootstrap_job_kind_not_allowlisted")));
        assert!(preflight["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("e2_worker_probe_bootstrap_order_id_mismatch")));
    }

    #[test]
    fn worker_eligibility_response_guidance_keeps_probe_only_promotion_explicit() {
        let worker = crate::reputation_score::CanonicalWorkerEligibilityV1 {
            format_version: crate::reputation_score::WORKER_ELIGIBILITY_SURFACE_VERSION_V1
                .to_string(),
            worker_node_pubkey: "worker".to_string(),
            operator_wallet_pubkey: "operator".to_string(),
            source_height: 12,
            finalized_height: 12,
            source_commitment: "finalized".to_string(),
            registration_source: "SELF_REGISTERED".to_string(),
            chain_known: true,
            eligible_for_probe: true,
            eligible_for_non_probe: false,
            wallet_reputation_score: 600,
            node_reliability_score: 600,
            effective_score: 600,
            role_score_projection_version: Some(
                crate::reputation_score::OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string(),
            ),
            operator_reputation: 600,
            validator_score: None,
            compute_score: 600,
            cloud_unit_score: 0,
            gpu_score: 0,
            critical_score: 0,
            eligibility_state: "PROBATION".to_string(),
            tier: "PROBATION".to_string(),
            max_risk_class: "NONE".to_string(),
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
            max_parallel_jobs: 0,
            max_job_duration_sec: 0,
            successful_probe_jobs: 1,
            successful_real_jobs: 0,
            successful_cloud_unit_jobs: 0,
            successful_gpu_evidence_jobs: 0,
            successful_critical_workload_jobs: 0,
            total_evidence_count: 1,
            observation_window: 0,
            uptime_window: 0,
            deny_reason: Some("minimum_evidence_count_not_met".to_string()),
            next_recovery_action: Some("collect_more_evidence".to_string()),
            policy_version: crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1
                .to_string(),
        };
        let aliases = canonical_worker_eligibility_compat_aliases_v1(&worker);
        assert_eq!(aliases["chainKnown"], true);
        assert_eq!(aliases["eligibleForProbe"], true);
        assert_eq!(aliases["eligibleForNonProbe"], false);
        let guidance = canonical_worker_eligibility_onboarding_guidance_v1(&worker);
        assert_eq!(guidance["stage"], "PROMOTION_PENDING");
        assert_eq!(guidance["nextAction"], "collect_more_evidence");
        assert!(guidance["missingRequirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["code"] == "minimum_evidence_count_not_met"));
    }

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    #[test]
    fn compute_fiat_settlement_canonical_response_reports_pruned_seen_order_as_found() {
        let body = compute_fiat_settlement_proof_canonical_response_v1("order-1", None, true);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["found"], true);
        assert_eq!(body["canonical"], true);
        assert_eq!(body["pruned"], true);
        assert!(body["proof"].is_null());
    }

    #[test]
    fn compute_fiat_settlement_canonical_response_reports_absent_order_as_not_found() {
        let body = compute_fiat_settlement_proof_canonical_response_v1("order-1", None, false);
        assert_eq!(body["found"], false);
        assert_eq!(body["canonical"], false);
        assert_eq!(body["pruned"], false);
        assert!(body["proof"].is_null());
    }

    #[test]
    fn economy_series_route_returns_non_empty_series_when_history_present() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            bc.economy_history
                .push_back(crate::blockchain::EconomyPoint {
                    ts: 1_700_000_000,
                    height: 42,
                    source: crate::blockchain::EconomyApplySource::LocalMined,
                    block_hash: "h42".to_string(),
                    parent_hash: "h41".to_string(),
                    user_txs: 3,
                    base_fee_per_tx: 105,
                    base_fee_before: 100,
                    base_fee_after: 105,
                    reward: 17,
                    burn_bps: 5,
                    burn_bps_before: 5,
                    burn_bps_after: 5,
                    treasury_pct_base_bps_before: 3000,
                    treasury_pct_base_bps_after: 3000,
                    burned: 2,
                    treasury_balance_before: 10,
                    treasury_balance_after: 15,
                    treasury_delta: 5,
                    reward_to_treasury: 4,
                    reward_to_miner_base: 13,
                    coinbase_amount: 21,
                    regime: "warm".to_string(),
                    regime_before: "steady".to_string(),
                    regime_after: "warm".to_string(),
                    stability_score_ppm: 900_000,
                    total_supply: 1000,
                    total_supply_before: 990,
                    total_supply_after: 1000,
                    fill_ppm: 1234,
                    mempool_len: 7,
                });
        }

        let route = warp::path!("api" / "v2" / "dashboard" / "economy_series")
            .and(warp::get())
            .and(warp::query::<EconomySeriesQuery>())
            .and(with_chain(chain.clone()))
            .map(|q: EconomySeriesQuery, ch: SharedChain| {
                let window_secs = q
                    .window_secs
                    .unwrap_or(24 * 60 * 60)
                    .clamp(60, 30 * 24 * 60 * 60);
                let max_points = q.max_points.unwrap_or(512).clamp(1, 4096);
                let series = {
                    let bc = lock_any!(ch);
                    bc.economy_series(window_secs, max_points)
                };
                warp::reply::json(&serde_json::json!({
                    "status": "ok",
                    "series": series
                }))
            });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/dashboard/economy_series?window_secs=3600&max_points=32")
                .reply(&route),
        );
        assert_eq!(response.status(), warp::http::StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        let series = json["series"].as_array().unwrap();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0]["base_fee_before"], 100);
        assert_eq!(series[0]["base_fee_after"], 105);
        assert_eq!(series[0]["burn_bps_before"], 5);
        assert_eq!(series[0]["burn_bps_after"], 5);
        assert_eq!(series[0]["treasury_pct_base_bps_before"], 3000);
        assert_eq!(series[0]["treasury_pct_base_bps_after"], 3000);
        assert_eq!(series[0]["treasury_balance_before"], 10);
        assert_eq!(series[0]["treasury_delta"], 5);
        assert_eq!(series[0]["total_supply_before"], 990);
        assert_eq!(series[0]["total_supply_after"], 1000);
    }

    #[test]
    fn economy_dashboard_exposes_emission_read_only_fields() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            bc.policy.emission_controller.enabled = true;
            bc.policy.emission_state.reward_multiplier_bps = 11_250;
            bc.policy.emission_state.phase = crate::blockchain::EmissionSunsetPhase::Taper;
            bc.policy.emission_state.validator_fee_budget_ma30 = 777;
            bc.policy.emission_state.target_validator_budget_day = 999;
            bc.policy.emission_window.consecutive_sustainable_days = 12;
            bc.policy.emission_controller.hard_cap_days = 180;
            bc.policy.emission_controller.taper_days = 30;
            bc.policy.emission_state.phase_start_day_index = Some(5);
            bc.policy.emission_window.current_day_index = 10;
            bc.chain.push(crate::block::Block::default());
        }

        let route = warp::path!("api" / "v2" / "dashboard" / "economy")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_dashboard_economy_read_model(&bc))
            });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/dashboard/economy")
                .reply(&route),
        );
        assert_eq!(response.status(), warp::http::StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert!(json["canonical_chain_economy"]["emission_controller_enabled"].is_null());
        assert!(json["canonical_chain_economy"]["emission_phase"].is_null());
        assert!(json["canonical_chain_economy"]["reward_multiplier_bps"].is_null());
        assert_eq!(
            json["local_node_observation"]["prospective_emission_phase"],
            "Taper"
        );
        assert_eq!(
            json["local_node_observation"]["prospective_reward_multiplier_bps"],
            11250
        );
        assert_eq!(
            json["derived_runtime_projection"]["validator_fee_budget_ma30"],
            777
        );
        assert_eq!(
            json["derived_runtime_projection"]["target_validator_budget_day"],
            999
        );
        assert_eq!(
            json["read_model_contract"]["controller_contract_version"],
            crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
        );
        assert_eq!(json["read_model_contract"]["policy_version"], 1);
        assert_eq!(json["read_model_contract"]["policy_compat_version"], 1);
        assert_eq!(json["read_model_contract"]["supported_policy_version"], 1);
        assert_eq!(
            json["read_model_contract"]["supported_policy_compat_version"],
            1
        );
        assert_eq!(json["read_model_contract"]["policy_version_status"], "ok");
        assert_eq!(
            json["read_model_contract"]["policy_version_reason_code"],
            "ok"
        );
        assert!(json["read_model_contract"]["policy_version_error"].is_null());
        assert!(json.get("pressure_state").is_none());
        assert!(json.get("budget_state").is_none());
        assert!(json.get("fee_controller_action").is_none());
        assert!(json.get("fee_controller_reason_code").is_none());
        assert!(json.get("emission_controller_action").is_none());
        assert!(json.get("emission_controller_reason_code").is_none());
        assert!(json["local_node_observation"]["last_fee_controller_apply_height"].is_u64());
        assert!(json["local_node_observation"]["last_emission_controller_apply_height"].is_u64());
        assert_eq!(
            json["canonical_chain_economy"]["scope"],
            "finalized_chain_derived"
        );
        assert!(json["canonical_chain_economy"]
            .get("controller_contract_version")
            .is_none());
        assert!(json["canonical_chain_economy"]
            .get("policy_version")
            .is_none());
        assert_eq!(
            json["read_model_contract"]["scope"],
            "runtime_contract_metadata"
        );
        assert_eq!(
            json["local_node_observation"]["scope"],
            "node_local_transient"
        );
        assert_eq!(
            json["derived_runtime_projection"]["consecutive_sustainable_days"],
            12
        );
        assert_eq!(json["derived_runtime_projection"]["hard_cap_day"], 180);
        assert_eq!(
            json["derived_runtime_projection"]["taper_days_remaining"],
            25
        );
    }

    #[test]
    fn treasury_state_exposes_emission_read_only_fields() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            bc.policy.emission_controller.enabled = true;
            bc.policy.emission_state.reward_multiplier_bps = 10_500;
            bc.policy.emission_state.phase = crate::blockchain::EmissionSunsetPhase::Launch;
            bc.policy.emission_state.validator_fee_budget_ma30 = 321;
            bc.policy.emission_state.target_validator_budget_day = 654;
            bc.policy.emission_window.consecutive_sustainable_days = 7;
            bc.policy.emission_controller.hard_cap_days = 180;
            bc.chain.push(crate::block::Block::default());
        }

        let route = warp::path!("api" / "v2" / "treasury" / "state")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_treasury_state_read_model(&bc))
            });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/treasury/state")
                .reply(&route),
        );
        assert_eq!(response.status(), warp::http::StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert!(json["canonical_chain_economy"]["emission_controller_enabled"].is_null());
        assert!(json["canonical_chain_economy"]["emission_phase"].is_null());
        assert!(json["canonical_chain_economy"]["reward_multiplier_bps"].is_null());
        assert!(json.get("derived_runtime_projection").is_none());
        assert!(json["canonical_chain_economy"]["unavailable_reason_codes"].is_array());
        assert_eq!(
            json["read_model_contract"]["controller_contract_version"],
            crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
        );
        assert_eq!(json["read_model_contract"]["policy_version"], 1);
        assert_eq!(json["read_model_contract"]["policy_compat_version"], 1);
        assert_eq!(json["read_model_contract"]["supported_policy_version"], 1);
        assert_eq!(
            json["read_model_contract"]["supported_policy_compat_version"],
            1
        );
        assert_eq!(json["read_model_contract"]["policy_version_status"], "ok");
        assert_eq!(
            json["read_model_contract"]["policy_version_reason_code"],
            "ok"
        );
        assert!(json["read_model_contract"]["policy_version_error"].is_null());
        assert!(json.get("pressure_state").is_none());
        assert!(json.get("budget_state").is_none());
        assert!(json.get("fee_controller_action").is_none());
        assert!(json.get("fee_controller_reason_code").is_none());
        assert!(json.get("emission_controller_action").is_none());
        assert!(json.get("emission_controller_reason_code").is_none());
        assert!(json.get("last_fee_controller_apply_height").is_none());
        assert!(json.get("last_emission_controller_apply_height").is_none());
        assert!(json.get("local_node_observation").is_none());
        assert_eq!(
            json["canonical_chain_economy"]["scope"],
            "finalized_chain_derived"
        );
        assert!(json["canonical_chain_economy"]
            .get("controller_contract_version")
            .is_none());
        assert_eq!(
            json["read_model_contract"]["scope"],
            "runtime_contract_metadata"
        );
        assert!(json.get("derived_runtime_projection").is_none());
    }

    #[test]
    fn dashboard_and_treasury_read_only_fields_track_real_emission_sequence_state() {
        let chain = Arc::new(Mutex::new(
            crate::blockchain::Blockchain::test_make_emission_chain(),
        ));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            bc.policy.base_fee_per_tx = 100;
            bc.policy.burn_bps = 0;
            bc.policy.treasury_pct_base_bps = 0;
            bc.policy.emission_controller.blocks_per_day = 2;
            bc.policy.emission_controller.window_days = 4;
            bc.policy.emission_controller.consecutive_days_required = 2;
            bc.policy.emission_controller.taper_days = 2;
            bc.policy.emission_controller.hard_cap_days = 10;
            bc.sync_emission_controller_fields();
            bc.test_apply_emission_sequence(2, &[20, 20, 0]);
        }

        let dashboard = warp::path!("api" / "v2" / "dashboard" / "economy")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_dashboard_economy_read_model(&bc))
            });

        let treasury = warp::path!("api" / "v2" / "treasury" / "state")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_treasury_state_read_model(&bc))
            });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dash = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/dashboard/economy")
                .reply(&dashboard),
        );
        let treasury_resp = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/treasury/state")
                .reply(&treasury),
        );

        assert_eq!(dash.status(), warp::http::StatusCode::OK);
        assert_eq!(treasury_resp.status(), warp::http::StatusCode::OK);
        let dash_json: serde_json::Value = serde_json::from_slice(dash.body()).unwrap();
        let treasury_json: serde_json::Value =
            serde_json::from_slice(treasury_resp.body()).unwrap();

        assert_eq!(
            dash_json["canonical_chain_economy"]["emission_controller_enabled"],
            true
        );
        assert_eq!(
            dash_json["canonical_chain_economy"]["emission_phase"],
            "Taper"
        );
        assert_eq!(
            dash_json["canonical_chain_economy"]["reward_multiplier_bps"],
            treasury_json["canonical_chain_economy"]["reward_multiplier_bps"]
        );
        assert_eq!(
            dash_json["canonical_chain_economy"]["current_applied_reward_base_schedule"],
            treasury_json["canonical_chain_economy"]["current_applied_reward_base_schedule"]
        );
        assert_eq!(
            dash_json["canonical_chain_economy"]["current_applied_reward_effective"],
            treasury_json["canonical_chain_economy"]["current_applied_reward_effective"]
        );
        assert!(
            dash_json["derived_runtime_projection"]["validator_fee_budget_ma30"].is_u64()
                || dash_json["derived_runtime_projection"]["validator_fee_budget_ma30"].is_number()
        );
        assert!(treasury_json.get("derived_runtime_projection").is_none());
        assert!(
            dash_json["derived_runtime_projection"]["target_validator_budget_day"].is_u64()
                || dash_json["derived_runtime_projection"]["target_validator_budget_day"]
                    .is_number()
        );
        assert_eq!(
            dash_json["read_model_contract"]["controller_contract_version"],
            treasury_json["read_model_contract"]["controller_contract_version"]
        );
        assert!(dash_json["derived_runtime_projection"]["current_budget_state"].is_string());
        assert!(
            dash_json["derived_runtime_projection"]["consecutive_sustainable_days"].is_u64()
                || dash_json["derived_runtime_projection"]["consecutive_sustainable_days"]
                    .is_number()
        );
        assert!(dash_json.get("base_fee_per_tx").is_none());
        assert!(dash_json["canonical_chain_economy"]["base_fee_per_tx"].is_number());
        assert_eq!(dash_json["binding_kind"], "finalized");
        assert!(dash_json["binding_height"].as_u64().is_some());
        assert!(dash_json["local_node_observation"]["current_pressure_state"].is_string());
        assert!(dash_json["local_node_observation"]["last_fee_controller_action"].is_string());
        assert!(dash_json["local_node_observation"]["last_fee_controller_reason_code"].is_string());
        assert!(dash_json["local_node_observation"]["last_fee_controller_apply_height"].is_u64());
        assert!(dash_json["local_node_observation"]["last_emission_controller_action"].is_string());
        assert!(
            dash_json["local_node_observation"]["last_emission_controller_reason_code"].is_string()
        );
        assert!(
            dash_json["local_node_observation"]["last_emission_controller_apply_height"].is_u64()
        );
        assert_eq!(dash_json["derived_runtime_projection"]["hard_cap_day"], 10);
        assert_eq!(
            dash_json["derived_runtime_projection"]["taper_days_remaining"],
            1
        );
        assert!(
            dash_json["canonical_chain_economy"]["current_applied_reward_effective"]
                .as_u64()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn emission_read_only_endpoints_use_real_server_routes_and_distinguish_applied_vs_projected_rewards(
    ) {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(
                crate::blockchain::Blockchain::test_make_emission_chain(),
            ));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                bc.policy.base_fee_per_tx = 100;
                bc.policy.burn_bps = 0;
                bc.policy.treasury_pct_base_bps = 0;
                bc.policy.emission_controller.blocks_per_day = 2;
                bc.policy.emission_controller.window_days = 4;
                bc.policy.emission_controller.consecutive_days_required = 2;
                bc.policy.emission_controller.taper_days = 2;
                bc.policy.emission_controller.hard_cap_days = 10;
                bc.sync_emission_controller_fields();
                bc.test_apply_emission_sequence(2, &[20, 20, 0]);
            }

            let mempool = Arc::new(Mutex::new(crate::mempool::Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let storage = open_empty_test_storage();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain.clone(),
                mempool,
                tx_p2p,
                port,
                storage,
                false,
                true,
            ));

            wait_for_server_ready(port, "/api/v2/dashboard/economy").await;
            let dash_json = http_get_json_via_server(port, "/api/v2/dashboard/economy").await;
            let treasury_json = http_get_json_via_server(port, "/api/v2/treasury/state").await;

            server.abort();
            let _ = server.await;

            assert_eq!(dash_json["status"], "ok");
            assert_eq!(treasury_json["status"], "ok");
            assert_eq!(
                dash_json["canonical_chain_economy"]["emission_controller_enabled"],
                true
            );
            assert_eq!(
                dash_json["canonical_chain_economy"]["emission_phase"],
                treasury_json["canonical_chain_economy"]["emission_phase"]
            );
            assert_eq!(
                dash_json["canonical_chain_economy"]["reward_multiplier_bps"],
                treasury_json["canonical_chain_economy"]["reward_multiplier_bps"]
            );
            assert_eq!(
                dash_json["canonical_chain_economy"]["current_applied_reward_base_schedule"],
                treasury_json["canonical_chain_economy"]["current_applied_reward_base_schedule"]
            );
            assert_eq!(
                dash_json["canonical_chain_economy"]["current_applied_reward_effective"],
                treasury_json["canonical_chain_economy"]["current_applied_reward_effective"]
            );
            assert!(treasury_json.get("derived_runtime_projection").is_none());
            assert!(
                dash_json["derived_runtime_projection"]["next_projected_reward_base_schedule"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                dash_json["derived_runtime_projection"]["next_projected_reward_effective"].is_u64()
                    || dash_json["derived_runtime_projection"]["next_projected_reward_effective"]
                        .is_number()
            );
            assert!(
                dash_json["derived_runtime_projection"]["validator_fee_budget_ma30"].is_u64()
                    || dash_json["derived_runtime_projection"]["validator_fee_budget_ma30"]
                        .is_number()
            );
            assert!(
                dash_json["derived_runtime_projection"]["target_validator_budget_day"].is_u64()
                    || dash_json["derived_runtime_projection"]["target_validator_budget_day"]
                        .is_number()
            );
            assert_eq!(
                dash_json["read_model_contract"]["controller_contract_version"],
                treasury_json["read_model_contract"]["controller_contract_version"]
            );
            assert!(dash_json["derived_runtime_projection"]["current_budget_state"].is_string());
            assert!(
                dash_json["derived_runtime_projection"]["consecutive_sustainable_days"].is_u64()
                    || dash_json["derived_runtime_projection"]["consecutive_sustainable_days"]
                        .is_number()
            );
            assert!(dash_json["local_node_observation"]["current_pressure_state"].is_string());
            assert!(dash_json["local_node_observation"]["last_fee_controller_action"].is_string());
            assert!(
                dash_json["local_node_observation"]["last_emission_controller_action"].is_string()
            );
            assert!(
                dash_json["canonical_chain_economy"]["current_applied_reward_effective"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                dash_json["derived_runtime_projection"]["next_projected_reward_effective"].is_u64()
                    || dash_json["derived_runtime_projection"]["next_projected_reward_effective"]
                        .is_number()
            );
        });
    }

    #[test]
    fn economy_read_models_publish_versioned_finalized_binding_metadata() {
        let chain = Arc::new(Mutex::new(
            crate::blockchain::Blockchain::test_make_emission_chain(),
        ));

        let dashboard = warp::path!("api" / "v2" / "dashboard" / "economy")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_dashboard_economy_read_model(&bc))
            });

        let treasury = warp::path!("api" / "v2" / "treasury" / "state")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_treasury_state_read_model(&bc))
            });

        let blockchain_info = warp::path!("api" / "blockchain" / "info")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_blockchain_info_read_model(&bc))
            });

        let blockchain_info_v2 = warp::path!("api" / "v2" / "blockchain" / "info")
            .and(warp::get())
            .and(with_chain(chain.clone()))
            .map(|ch: SharedChain| {
                let bc = lock_any!(ch);
                warp::reply::json(&build_blockchain_info_read_model(&bc))
            });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dash = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/dashboard/economy")
                .reply(&dashboard),
        );
        let treasury_resp = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/treasury/state")
                .reply(&treasury),
        );
        let info = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/blockchain/info")
                .reply(&blockchain_info),
        );
        let info_v2 = rt.block_on(
            warp::test::request()
                .method("GET")
                .path("/api/v2/blockchain/info")
                .reply(&blockchain_info_v2),
        );

        let dash_json: serde_json::Value = serde_json::from_slice(dash.body()).unwrap();
        let treasury_json: serde_json::Value =
            serde_json::from_slice(treasury_resp.body()).unwrap();
        let info_json: serde_json::Value = serde_json::from_slice(info.body()).unwrap();
        let info_v2_json: serde_json::Value = serde_json::from_slice(info_v2.body()).unwrap();

        for json in [&dash_json, &treasury_json, &info_json, &info_v2_json] {
            assert_eq!(json["schema_version"], ECONOMY_HTTP_SCHEMA_VERSION);
            assert_eq!(json["read_model_version"], ECONOMY_HTTP_READ_MODEL_VERSION);
            assert_eq!(json["binding_kind"], ECONOMY_HTTP_BINDING_KIND_FINALIZED);
            assert!(json["binding_height"].is_u64());
            assert!(json["binding_hash"].is_string());
            assert!(!json["binding_hash"].as_str().unwrap_or_default().is_empty());
            assert_eq!(json["binding_status"], "ok");
            assert!(json["binding_reason_codes"].is_array());
            assert_eq!(json["binding_reason_codes"].as_array().unwrap().len(), 0);
            assert_eq!(json["snapshot_status"], "ok");
            assert!(json["snapshot_reason_codes"].is_array());
            assert_eq!(json["snapshot_reason_codes"].as_array().unwrap().len(), 0);
            assert_eq!(json["contract_status"], "ok");
            assert!(json["contract_reason_codes"].is_array());
            assert_eq!(json["contract_reason_codes"].as_array().unwrap().len(), 0);
        }

        let mut info_cmp = info_json.clone();
        let mut info_v2_cmp = info_v2_json.clone();
        if let Some(obj) = info_cmp.as_object_mut() {
            obj.remove("now_unix_ms");
        }
        if let Some(obj) = info_v2_cmp.as_object_mut() {
            obj.remove("now_unix_ms");
        }
        assert_eq!(info_cmp, info_v2_cmp);
        assert!(info_json["now_unix_ms"].is_u64());
        assert!(info_v2_json["now_unix_ms"].is_u64());
        assert_eq!(dash_json["binding_height"], treasury_json["binding_height"]);
        assert_eq!(dash_json["binding_hash"], treasury_json["binding_hash"]);
        assert_eq!(dash_json["binding_height"], info_json["binding_height"]);
        assert_eq!(dash_json["binding_hash"], info_json["binding_hash"]);
    }

    #[test]
    fn blockchain_info_keeps_observed_tip_counters_out_of_finalized_binding_surface() {
        let bc = crate::blockchain::Blockchain::test_make_emission_chain();
        let info = build_blockchain_info_read_model(&bc);

        assert_eq!(info["binding_kind"], ECONOMY_HTTP_BINDING_KIND_FINALIZED);
        assert!(info.get("total_blocks").is_none());
        assert!(info.get("total_transactions").is_none());
        assert!(info.get("observed_tip_height").is_none());
        assert!(info.get("observed_tip_hash").is_none());

        let observed = &info["observed_tip"];
        assert_eq!(observed["scope"], "node_local_observed_tip");
        assert!(observed["height"].is_u64());
        assert!(observed["hash"].is_string());
        assert!(observed["total_blocks"].is_u64());
        assert!(observed["total_transactions"].is_u64());
    }

    #[test]
    fn economy_read_model_meta_exposes_separate_binding_snapshot_and_contract_statuses() {
        let mut bc = crate::blockchain::Blockchain::test_make_emission_chain();
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        let info = build_blockchain_info_read_model(&bc);
        assert_eq!(dash["binding_status"], "ok");
        assert_eq!(dash["snapshot_status"], "ok");
        assert_eq!(dash["contract_status"], "ok");
        assert!(dash["binding_reason_codes"].as_array().unwrap().is_empty());
        assert!(dash["snapshot_reason_codes"].as_array().unwrap().is_empty());
        assert!(dash["contract_reason_codes"].as_array().unwrap().is_empty());
        assert_eq!(info["binding_status"], "ok");
        assert_eq!(info["snapshot_status"], "ok");
        assert_eq!(info["contract_status"], "ok");

        bc.policy.policy_version = 0;
        let dash_invalid = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        assert_eq!(dash_invalid["binding_status"], "ok");
        assert_eq!(dash_invalid["snapshot_status"], "ok");
        assert_eq!(dash_invalid["contract_status"], "degraded");
        assert_eq!(
            dash_invalid["contract_reason_codes"][0],
            "invalid_policy_version"
        );
    }

    #[test]
    fn status_supply_binding_prefers_finalized_economy_snapshot_v210() {
        let mut bc = crate::blockchain::Blockchain::test_make_emission_chain();
        let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
        let canonical = bc
            .finalized_economy_snapshot_for_api()
            .expect("finalized economy snapshot available in test");

        let bogus_local_supply = canonical.total_supply.saturating_add(16_000_000_000_000);
        bc.total_supply = bogus_local_supply;

        let binding = status_economy_supply_binding_v210(&bc);

        assert_eq!(binding.supply_source, "finalized_economy_snapshot");
        assert_eq!(binding.total_supply, canonical.total_supply);
        assert_eq!(binding.net_issued_supply, canonical.total_supply);
        assert_eq!(binding.local_observed_total_supply, bogus_local_supply);
        assert_ne!(binding.total_supply, binding.local_observed_total_supply);
        assert!(binding.reason_codes.is_empty());
    }

    #[test]
    fn economy_read_models_fail_closed_when_finalized_snapshot_is_unavailable() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            bc.chain.clear();
        }

        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        let treasury = serde_json::to_value(build_treasury_state_read_model(&bc)).unwrap();
        let info = build_blockchain_info_read_model(&bc);

        for json in [&dash, &treasury, &info] {
            assert_eq!(json["status"], "degraded");
            assert_eq!(json["binding_kind"], ECONOMY_HTTP_BINDING_KIND_FINALIZED);
            assert_eq!(json["binding_status"], "degraded");
            assert_eq!(json["snapshot_status"], "degraded");
            assert_eq!(json["contract_status"], "ok");
            assert!(json["binding_height"].is_null());
            assert!(json["binding_hash"].is_null());
            assert!(json["binding_reason_codes"].is_array());
            assert!(json["snapshot_reason_codes"].is_array());
            assert!(json["contract_reason_codes"].is_array());
            assert!(json["contract_reason_codes"].as_array().unwrap().is_empty());
            assert!(!json["binding_reason_codes"].as_array().unwrap().is_empty());
        }

        assert!(dash["canonical_chain_economy"]["total_supply"].is_null());
        assert!(dash["canonical_chain_economy"]["treasury_balance"].is_null());
        assert!(dash["canonical_chain_economy"]["base_fee_per_tx"].is_null());
        assert!(dash["canonical_chain_economy"]["unavailable_reason_codes"].is_array());
        assert!(!dash["canonical_chain_economy"]["unavailable_reason_codes"]
            .as_array()
            .unwrap()
            .is_empty());

        assert!(info["economy"]["total_supply"].is_null());
        assert!(info["economy"]["treasury_balance"].is_null());
        assert!(info["economy"]["base_fee_per_tx"].is_null());
        assert!(info["economy_unavailable_reason_codes"].is_array());
        assert!(!info["economy_unavailable_reason_codes"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn economy_read_models_fail_closed_when_finalized_base_fee_is_not_provably_derived() {
        let chain = Arc::new(Mutex::new(
            crate::blockchain::Blockchain::test_make_emission_chain(),
        ));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
            let finalized_height = bc.finalized_view().0;
            let block = bc
                .chain
                .iter_mut()
                .find(|b| b.index == finalized_height)
                .expect("finalized block present in test chain");
            let coinbase = block
                .transactions
                .iter_mut()
                .find(|tx| tx.is_coinbase)
                .expect("coinbase tx present");
            coinbase.memo = None;
        }

        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        let info = build_blockchain_info_read_model(&bc);

        assert!(dash["canonical_chain_economy"]["base_fee_per_tx"].is_null());
        assert!(info["economy"]["base_fee_per_tx"].is_null());

        let dash_codes = dash["canonical_chain_economy"]["unavailable_reason_codes"]
            .as_array()
            .expect("dashboard unavailable codes array");
        assert!(dash_codes
            .iter()
            .any(|v| v == "finalized_base_fee_unavailable"));

        let info_codes = info["economy_unavailable_reason_codes"]
            .as_array()
            .expect("blockchain info unavailable codes array");
        assert!(info_codes
            .iter()
            .any(|v| v == "finalized_base_fee_unavailable"));
    }

    #[test]
    fn economy_dashboard_separates_canonical_chain_state_from_local_observation() {
        let chain = Arc::new(Mutex::new(
            crate::blockchain::Blockchain::test_make_emission_chain(),
        ));
        let canonical_base_fee;
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
            canonical_base_fee = bc
                .finalized_economy_snapshot_for_api()
                .expect("finalized economy snapshot available in test")
                .base_fee_per_tx
                .expect("finalized canonical base fee available in test");
            bc.policy.base_fee_per_tx = canonical_base_fee.saturating_add(7);
            bc.policy.current_regime = "congested".to_string();
            bc.policy.backlog_ratio_ppm = bc.policy.backlog_congested_enter_ppm;
            bc.policy.ema.ema_mempool = 77;
            bc.policy.ema.stability_score_ppm = 654_321;
        }

        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        assert!(dash.get("base_fee_per_tx").is_none());
        assert_eq!(
            dash["canonical_chain_economy"]["base_fee_per_tx"],
            canonical_base_fee
        );
        assert_eq!(
            dash["local_node_observation"]["prospective_base_fee_per_tx"],
            canonical_base_fee.saturating_add(7)
        );
        assert_eq!(
            dash["local_node_observation"]["tip_applied_base_fee_per_tx"],
            canonical_base_fee
        );
        assert!(dash["local_node_observation"]["tip_applied_fee_height"].is_u64());
        assert!(dash["local_node_observation"]["finalized_fee_lag_blocks"].is_u64());
        assert_eq!(dash["local_node_observation"]["regime"], "congested");
        assert_eq!(dash["local_node_observation"]["mempool_ema"], 77);
        assert_eq!(
            dash["committed"]["canonical_base_fee_per_tx"],
            canonical_base_fee
        );
        assert_eq!(
            dash["controller_local"]["prospective_base_fee_per_tx"],
            canonical_base_fee.saturating_add(7)
        );
        assert_eq!(
            dash["controller_local"]["tip_applied_base_fee_per_tx"],
            canonical_base_fee
        );
        assert!(dash["controller_local"]["tip_applied_fee_height"].is_u64());
        assert!(dash["controller_local"]["finalized_fee_lag_blocks"].is_u64());
        assert_eq!(
            dash["controller_local"]["prospective_fee_action"],
            dash["local_node_observation"]["last_fee_controller_action"]
        );
        assert_eq!(
            dash["controller_local"]["prospective_fee_reason_code"],
            dash["local_node_observation"]["last_fee_controller_reason_code"]
        );
        assert_eq!(
            dash["controller_local"]["controller_fee_action_semantics"],
            "last_controller_decision"
        );
        assert_eq!(
            dash["local_node_observation"]["controller_fee_action_semantics"],
            "last_controller_decision"
        );
        assert_eq!(dash["committed"]["scope"], "finalized_committed_delta");
        assert_eq!(
            dash["controller_local"]["scope"],
            "controller_local_prospective"
        );
        assert!(dash["committed"].get("prospective_fee_action").is_none());
        assert!(dash["controller_local"]
            .get("committed_fee_action")
            .is_none());
        assert!(dash.get("regime").is_none());
        assert!(dash.get("current_pressure_state").is_none());
        assert!(dash.get("last_fee_controller_reason_code").is_none());
    }

    #[test]
    fn committed_delta_helper_does_not_use_local_controller_reasoning() {
        assert_eq!(
            derive_committed_action_reason(Some(100), Some(110), "fee"),
            ("raise".to_string(), "canonical_fee_increased".to_string())
        );
        assert_eq!(
            derive_committed_action_reason(Some(110), Some(100), "fee"),
            ("lower".to_string(), "canonical_fee_decreased".to_string())
        );
        assert_eq!(
            derive_committed_action_reason(Some(100), Some(100), "fee"),
            ("hold".to_string(), "canonical_fee_unchanged".to_string())
        );
        assert_eq!(
            derive_committed_action_reason(None, Some(100), "fee"),
            (
                "hold".to_string(),
                "canonical_fee_baseline_unavailable".to_string()
            )
        );
    }

    #[test]
    fn economy_dashboard_contract_separates_committed_from_controller_local() {
        let chain = Arc::new(Mutex::new(
            crate::blockchain::Blockchain::test_make_emission_chain(),
        ));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
            bc.policy.last_fee_action = crate::blockchain::EconomicControllerAction::Raise;
            bc.policy.last_fee_reason_code =
                crate::blockchain::EconomicControllerReasonCode::RaiseSignalApplied;
            bc.policy.last_fee_apply_height = 10;
            bc.policy.last_fee_decision_height = 20;
        }

        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();

        assert!(dash.get("committed").is_some());
        assert!(dash.get("controller_local").is_some());
        assert!(dash["committed"]
            .get("last_fee_controller_action")
            .is_none());
        assert!(dash["committed"]
            .get("last_fee_controller_reason_code")
            .is_none());
        assert_eq!(dash["controller_local"]["prospective_fee_action"], "raise");
        assert_eq!(dash["controller_local"]["controller_fee_action"], "raise");
        assert_eq!(
            dash["controller_local"]["last_controller_fee_action"],
            "raise"
        );
        assert_eq!(
            dash["controller_local"]["controller_fee_action_semantics"],
            "last_controller_decision"
        );
        assert_eq!(
            dash["controller_local"]["prospective_fee_reason_code"],
            "raise_signal_applied"
        );
        assert_eq!(
            dash["controller_local"]["last_controller_fee_reason_code"],
            "raise_signal_applied"
        );
        assert_eq!(dash["controller_local"]["controller_decision_height"], 20);
        assert_eq!(
            dash["controller_local"]["last_controller_fee_decision_height"],
            20
        );
        assert_eq!(dash["controller_local"]["prospective_fee_apply_height"], 10);
        assert_ne!(
            dash["committed"]["committed_fee_reason_code"],
            dash["controller_local"]["prospective_fee_reason_code"]
        );
    }

    #[test]
    fn economy_read_models_serialize_consistently() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            let storage = open_empty_test_storage();
            bc.attach_storage(storage);
            bc.seed_attached_storage_with_genesis_state_for_tests()
                .expect("seed test storage from genesis state");
            bc.policy.emission_controller.enabled = true;
            bc.policy.policy_version = 3;
            bc.policy.policy_compat_version = 1;
            bc.policy.emission_state.target_validator_budget_day = 444;
            bc.policy.emission_window.consecutive_sustainable_days = 9;
        }
        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        let treasury = serde_json::to_value(build_treasury_state_read_model(&bc)).unwrap();
        assert_eq!(dash["status"], "ok");
        assert_eq!(treasury["status"], "ok");
        assert_eq!(dash["read_model_contract"]["policy_version"], 3);
        assert_eq!(treasury["read_model_contract"]["policy_compat_version"], 1);
        assert_eq!(dash["read_model_contract"]["supported_policy_version"], 1);
        assert_eq!(
            dash["read_model_contract"]["supported_policy_compat_version"],
            1
        );
        assert_eq!(dash["read_model_contract"]["policy_version_status"], "ok");
        assert_eq!(
            dash["read_model_contract"]["policy_version_reason_code"],
            "ok"
        );
        assert!(dash["read_model_contract"]["policy_version_error"].is_null());
        assert!(dash.get("pressure_state").is_none());
        assert!(dash.get("fee_controller_action").is_none());
        assert!(dash.get("current_pressure_state").is_none());
        assert!(dash.get("last_fee_controller_action").is_none());
        assert!(dash.get("canonical_chain_economy").is_some());
        assert!(dash.get("local_node_observation").is_some());
        assert!(treasury.get("budget_state").is_none());
        assert!(treasury.get("emission_controller_action").is_none());
        assert!(dash.get("derived_runtime_projection").is_some());
        assert!(treasury.get("treasury_pct_base_bps").is_some());
    }

    #[test]
    fn finalized_block_roots_for_api_is_fail_closed() {
        let mut bc = crate::blockchain::Blockchain::test_make_emission_chain();
        let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
        let roots = bc.finalized_block_roots_for_api().unwrap();
        assert!(roots.is_some());

        let finalized_height = bc.finalized_view().0;
        let block = bc
            .chain
            .iter_mut()
            .find(|b| b.index == finalized_height)
            .expect("finalized block present");
        block.tx_root.clear();
        assert!(bc.finalized_block_roots_for_api().is_err());

        let block = bc
            .chain
            .iter_mut()
            .find(|b| b.index == finalized_height)
            .expect("finalized block present");
        block.state_root.clear();
        let err = bc.finalized_block_roots_for_api().unwrap_err();
        assert!(
            err.contains("finalized_block_roots_missing")
                || err.contains("finalized_state_root_missing")
        );

        bc.chain.clear();
        assert!(matches!(bc.finalized_block_roots_for_api(), Ok(None)));
    }

    #[test]
    fn finalized_api_accessors_are_strict_and_do_not_silently_degrade_snapshot_errors() {
        let mut bc = crate::blockchain::Blockchain::test_make_emission_chain();
        let _ = bc.test_apply_real_economy_block(1, 3, 40, false);
        let snapshot = bc
            .finalized_economy_snapshot_for_api()
            .expect("finalized economy snapshot available in test");
        assert!(snapshot.base_fee_per_tx.is_some());
        assert!(snapshot.emission_phase.is_some());
        assert!(snapshot.reward_multiplier_bps.is_some());
        assert!(snapshot.current_applied_validator_fee_budget.is_some());
        assert!(snapshot.current_applied_reward_base_schedule.is_some());
        assert!(snapshot.current_applied_reward_effective.is_some());

        bc.chain.clear();
        assert!(bc.finalized_economy_snapshot_for_api().is_err());
    }

    #[test]
    fn economy_read_model_contract_metadata_is_separate_from_canonical_chain_economy() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
            let storage = open_empty_test_storage();
            bc.attach_storage(storage);
            bc.seed_attached_storage_with_genesis_state_for_tests()
                .expect("seed test storage from genesis state");
        }
        let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
        let dash = serde_json::to_value(build_dashboard_economy_read_model(&bc)).unwrap();
        let treasury = serde_json::to_value(build_treasury_state_read_model(&bc)).unwrap();
        let info = build_blockchain_info_read_model(&bc);

        for json in [&dash, &treasury] {
            assert!(json["canonical_chain_economy"]
                .get("controller_contract_version")
                .is_none());
            assert!(json["canonical_chain_economy"]
                .get("policy_version")
                .is_none());
            assert_eq!(
                json["read_model_contract"]["scope"],
                "runtime_contract_metadata"
            );
            assert_eq!(
                json["read_model_contract"]["controller_contract_version"],
                crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
            );
            assert_eq!(json["read_model_contract"]["policy_version_status"], "ok");
        }

        assert_eq!(
            info["read_model_contract"]["scope"],
            "runtime_contract_metadata"
        );
        assert_eq!(
            info["read_model_contract"]["controller_contract_version"],
            crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
        );
        assert!(info["economy"].get("controller_contract_version").is_none());
    }

    #[test]
    fn economy_controller_contract_read_model_is_frozen() {
        let json = serde_json::to_value(build_economy_controller_contract_read_model()).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["controller_contract_version"], 4);
        assert_eq!(
            json["fee_action_values"],
            serde_json::json!(["hold", "raise", "lower"])
        );
        assert_eq!(
            json["emission_action_values"],
            serde_json::json!(["hold", "raise", "lower"])
        );
        assert_eq!(
            json["reason_code_values"][8],
            "lower_suppressed_backlog_hot_or_congested"
        );
    }

    #[test]
    fn economy_controller_contract_route_exposes_frozen_values() {
        let route = warp::path!("api" / "v2" / "economy" / "controller_contract")
            .and(warp::get())
            .map(|| warp::reply::json(&build_economy_controller_contract_read_model()));

        run_async_test(async {
            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/economy/controller_contract")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), 200);
            let json: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(json["controller_contract_version"], 4);
            assert_eq!(json["fee_action_values"][0], "hold");
            assert_eq!(
                json["reason_code_values"][8],
                "lower_suppressed_backlog_hot_or_congested"
            );
        });
    }

    #[test]
    fn economy_integration_harness_real_blocks_backlog_apply_api_series_and_carry_are_consistent() {
        run_async_test(async {
            crate::logging::clear_test_log_capture();
            let chain = Arc::new(Mutex::new(
                crate::blockchain::Blockchain::test_make_emission_chain(),
            ));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                bc.policy.base_fee_per_tx = 100;
                bc.policy.base_fee_shadow = 100 * 1_000_000;
                bc.policy.policy_version = 9;
                bc.policy.policy_compat_version = 1;
                bc.policy.reward_schedule = crate::blockchain::RewardSchedule {
                    initial_per_block: 1,
                    floor_per_block: 1,
                    reward_to_treasury_bps: 0,
                    empty_block_reward_bps: 10_000,
                    ..crate::blockchain::RewardSchedule::default()
                };
                bc.policy.emission_state.reward_multiplier_bps = 10_500;
                bc.policy.emission_state.reward_shadow_bps_fp = 10_500u128 * 1_000_000u128;
                bc.sync_emission_controller_fields();

                for height in 1..=8u64 {
                    let _ = bc.test_apply_real_economy_block(height, 3, 40, height % 2 == 0);
                }

                assert!(bc.policy.backlog_ratio_ppm >= bc.policy.backlog_congested_enter_ppm);
                assert_eq!(bc.current_pressure_state_for_api(), "hot");
                assert!(matches!(bc.fee_action_for_api(), "hold" | "raise"));
                assert!(
                    bc.finalized_economy_snapshot_for_api()
                        .expect("finalized economy snapshot available in test")
                        .current_applied_reward_effective
                        .unwrap_or(0)
                        > 0
                );
                assert!(
                    bc.policy.emission_state.reward_effective_carry_fp < 10_000u128 * 10_000u128
                );
                drop(bc);
            }

            let mempool = Arc::new(Mutex::new(crate::mempool::Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let storage = open_empty_test_storage();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain.clone(),
                mempool,
                tx_p2p,
                port,
                storage,
                false,
                true,
            ));

            wait_for_server_ready(port, "/api/v2/dashboard/economy").await;
            let dash_json = http_get_json_via_server(port, "/api/v2/dashboard/economy").await;
            let treasury_json = http_get_json_via_server(port, "/api/v2/treasury/state").await;
            let contract_json =
                http_get_json_via_server(port, "/api/v2/economy/controller_contract").await;
            let series_json = http_get_json_via_server(
                port,
                "/api/v2/dashboard/economy_series?window_secs=7200&max_points=128",
            )
            .await;

            server.abort();
            let _ = server.await;

            assert_eq!(contract_json["controller_contract_version"], 4);
            assert_eq!(
                dash_json["read_model_contract"]["controller_contract_version"],
                crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
            );
            assert_eq!(
                treasury_json["read_model_contract"]["controller_contract_version"],
                crate::blockchain::ECONOMIC_CONTROLLER_CONTRACT_VERSION
            );
            assert_eq!(dash_json["read_model_contract"]["policy_version"], 9);
            assert_eq!(dash_json["read_model_contract"]["policy_compat_version"], 1);
            assert_eq!(
                dash_json["read_model_contract"]["supported_policy_version"],
                1
            );
            assert_eq!(
                dash_json["read_model_contract"]["supported_policy_compat_version"],
                1
            );

            assert_eq!(
                dash_json["local_node_observation"]["current_pressure_state"],
                "hot"
            );
            let expected_budget_state = {
                let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                serde_json::Value::String(bc.current_budget_state_for_api().to_string())
            };
            assert_eq!(
                dash_json["derived_runtime_projection"]["current_budget_state"],
                expected_budget_state
            );
            let (expected_next_reward_base_schedule, expected_next_reward_effective) = {
                let bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                (
                    bc.next_projected_reward_base_schedule_for_api(),
                    bc.next_projected_reward_effective_for_api(),
                )
            };
            assert_eq!(
                dash_json["derived_runtime_projection"]["next_projected_reward_base_schedule"]
                    .as_u64()
                    .unwrap(),
                expected_next_reward_base_schedule
            );
            assert_eq!(
                dash_json["derived_runtime_projection"]["next_projected_reward_effective"]
                    .as_u64()
                    .unwrap(),
                expected_next_reward_effective
            );

            assert!(
                dash_json["local_node_observation"]["last_fee_controller_apply_height"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                dash_json["local_node_observation"]["last_emission_controller_apply_height"]
                    .as_u64()
                    .unwrap()
                    > 0
            );

            let fee_reason = dash_json["local_node_observation"]["last_fee_controller_reason_code"]
                .as_str()
                .unwrap();
            let fee_action = dash_json["local_node_observation"]["last_fee_controller_action"]
                .as_str()
                .unwrap();
            let emission_reason = dash_json["local_node_observation"]
                ["last_emission_controller_reason_code"]
                .as_str()
                .unwrap();
            let emission_action = dash_json["local_node_observation"]
                ["last_emission_controller_action"]
                .as_str()
                .unwrap();

            assert!(contract_json["reason_code_values"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(fee_reason)));
            assert!(contract_json["fee_action_values"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(fee_action)));
            assert!(contract_json["reason_code_values"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(emission_reason)));
            assert!(contract_json["emission_action_values"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(emission_action)));

            assert!(
                dash_json["canonical_chain_economy"]["current_applied_reward_effective"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                dash_json["derived_runtime_projection"]["next_projected_reward_effective"].is_u64()
                    || dash_json["derived_runtime_projection"]["next_projected_reward_effective"]
                        .is_number()
            );

            let series = series_json["series"].as_array().unwrap();
            assert!(series.len() >= 4);
            assert!(series
                .iter()
                .any(|p| p["user_txs"].as_u64().unwrap_or(0) > 0));
            assert!(series.iter().any(|p| {
                matches!(
                    p["source"].as_str(),
                    Some("remote_applied") | Some("local_mined")
                )
            }));
            assert!(series.iter().all(|p| p["reward"].as_u64().unwrap_or(0) > 0));

            let captured_logs = crate::logging::snapshot_test_log_capture();
            assert!(captured_logs.iter().any(|line| {
                line.contains("target=eco.ctrl")
                    && (line.contains("event=controller_apply")
                        || line.contains("event=controller_hold"))
            }));
            assert!(captured_logs.iter().any(|line| {
                line.contains("target=eco.emission.ctrl") && line.contains("event=controller_apply")
            }));
            assert!(captured_logs.iter().any(|line| {
                line.contains("target=eco.ctrl")
                    && line.contains(&format!("reason_code={}", fee_reason))
                    && line.contains(&format!("action={}", fee_action))
            }));
            assert!(captured_logs.iter().any(|line| {
                line.contains("target=eco.emission.ctrl")
                    && line.contains(&format!("reason_code={}", emission_reason))
                    && line.contains(&format!("action={}", emission_action))
            }));
        });
    }

    #[test]
    fn api_guard_profile_forces_production_in_public_mode() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_RL_GENERAL_RPS",
            "NEWGEN_API_RL_GENERAL_BURST",
            "NEWGEN_API_RL_HEAVY_RPS",
            "NEWGEN_API_RL_HEAVY_BURST",
            "NEWGEN_API_RL_TX_RPS",
            "NEWGEN_API_RL_TX_BURST",
            "NEWGEN_API_MAX_IN_FLIGHT",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        let cfg = ApiGuardConfig::resolve(true);
        assert_eq!(cfg.profile, ApiGuardProfile::Production);
        assert_eq!(cfg.tx_submit.rps, 2.0);
        assert_eq!(cfg.tx_submit.burst, 4.0);
        assert_eq!(cfg.max_in_flight, 128);
    }

    #[test]
    fn api_guard_profile_trusted_benchmark_local_uses_high_submit_limits() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_RL_GENERAL_RPS",
            "NEWGEN_API_RL_GENERAL_BURST",
            "NEWGEN_API_RL_HEAVY_RPS",
            "NEWGEN_API_RL_HEAVY_BURST",
            "NEWGEN_API_RL_TX_RPS",
            "NEWGEN_API_RL_TX_BURST",
            "NEWGEN_API_MAX_IN_FLIGHT",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        let cfg = ApiGuardConfig::resolve(false);
        assert_eq!(cfg.profile, ApiGuardProfile::TrustedBenchmarkLocal);
        assert_eq!(cfg.tx_submit.rps, 1000.0);
        assert_eq!(cfg.tx_submit.burst, 2000.0);
        assert_eq!(cfg.max_in_flight, 4096);
    }

    #[test]
    fn api_guard_profile_defaults_to_legacy_non_public_in_dev_mode() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_RL_GENERAL_RPS",
            "NEWGEN_API_RL_GENERAL_BURST",
            "NEWGEN_API_RL_HEAVY_RPS",
            "NEWGEN_API_RL_HEAVY_BURST",
            "NEWGEN_API_RL_TX_RPS",
            "NEWGEN_API_RL_TX_BURST",
            "NEWGEN_API_MAX_IN_FLIGHT",
        ]);
        std::env::remove_var("NEWGEN_API_GUARD_PROFILE");
        let cfg = ApiGuardConfig::resolve(false);
        assert_eq!(cfg.profile, ApiGuardProfile::LegacyNonPublic);
        assert_eq!(cfg.tx_submit.rps, 8.0);
        assert_eq!(cfg.tx_submit.burst, 16.0);
        assert_eq!(cfg.max_in_flight, 512);
    }

    #[test]
    fn rate_limited_rejection_exposes_profile_and_policy() {
        let err = RateLimited {
            retry_after_secs: 2,
            scope: "tx_submit",
            profile: "trusted_benchmark_local",
            policy_rps: 1000.0,
            policy_burst: 2000.0,
        };
        let reply = error_handler(warp::reject::custom(err));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = rt.block_on(reply).expect("reply").into_response();
        assert_eq!(response.status(), warp::http::StatusCode::TOO_MANY_REQUESTS);
        let body = warp::hyper::body::to_bytes(response.into_body());
        let bytes = rt.block_on(body).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "rate_limited");
        assert_eq!(json["scope"], "tx_submit");
        assert_eq!(json["profile"], "trusted_benchmark_local");
        assert_eq!(json["policy_rps"], 1000.0);
        assert_eq!(json["policy_burst"], 2000.0);
        assert_eq!(json["retry_after_secs"], 2);
    }

    #[test]
    fn submit_rejects_insufficient_funds_before_mining() {
        let state = SenderAdmissionState {
            chain_balance: 1_165,
            base_fee_per_tx: 84,
            last_chain_nonce: 189,
            last_mempool_nonce: 189,
            pending_reserved_total: 1_000,
            pending_count: 3,
        };
        let reply = reject_if_sender_cannot_cover_pending(&state, 168, 1, 168, 0)
            .expect("underfunded sender must be rejected before mempool/mining");
        let response = reply.into_response();
        assert_eq!(
            response.status(),
            warp::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = response.into_body();
        let body = warp::hyper::body::to_bytes(body);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bytes = rt.block_on(body).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "insufficient_funds_after_pending");
        assert_eq!(json["chain_balance"], 1165);
        assert_eq!(json["pending_reserved_total"], 1000);
        assert_eq!(json["available_balance_after_pending"], 165);
        assert_eq!(json["required_additional"], 168);
    }

    #[test]
    fn snapshot_sender_admission_state_reads_pending_spend_and_expected_nonce() {
        let chain = Arc::new(Mutex::new(Blockchain::new()));
        {
            let mut bc = chain.lock().unwrap();
            let mut funding = Block::default();
            funding.index = 1;
            funding.hash = "funding-1".to_string();
            funding.transactions = vec![Transaction::new(
                "coinbase".to_string(),
                "ALICE".to_string(),
                1_000,
                0,
                0,
                String::new(),
                true,
                None,
            )];
            bc.chain.push(funding);
        }
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        {
            let mut mp = mempool.lock().unwrap();
            let mut tx1 = Transaction::new(
                "ALICE".to_string(),
                "BOB".to_string(),
                10,
                1,
                120,
                String::new(),
                false,
                None,
            );
            tx1.hash = tx1.calculate_hash();
            let mut tx2 = Transaction::new(
                "ALICE".to_string(),
                "CAROL".to_string(),
                15,
                2,
                130,
                String::new(),
                false,
                None,
            );
            tx2.hash = tx2.calculate_hash();
            assert!(mp.add(tx1));
            assert!(mp.add(tx2));
        }
        let state = snapshot_sender_admission_state(&chain, &mempool, "ALICE");
        assert_eq!(state.chain_balance, 1000);
        assert_eq!(state.pending_count, 2);
        assert_eq!(state.pending_reserved_total, 10 + 120 + 15 + 130);
        assert_eq!(state.last_chain_nonce, 0);
        assert_eq!(state.last_mempool_nonce, 2);
        assert_eq!(state.expected_next_nonce(), 3);
        assert_eq!(state.available_balance_after_pending(), 725);
    }
    #[test]
    fn gateway_fee_low_rejection_is_counted_by_enforcement_helper() {
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        {
            let mut mp = mempool.lock().unwrap();
            mp.set_base_fee_per_tx_hint(10);
        }

        let tx = Transaction::new(
            "ALICE".to_string(),
            "BOB".to_string(),
            1,
            1,
            1,
            String::new(),
            false,
            None,
        );

        assert!(enforce_security_fee_with_mempool_snapshot(&mempool, &tx).is_err());
        let mp = mempool.lock().unwrap();
        let counters = mp.drop_counters_snapshot();
        assert_eq!(counters.drop_fee_too_low_total, 1);
        assert_eq!(counters.accepted_total, 0);
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn gateway_invalid_max_fee_rejection_counter_can_be_recorded_before_mempool() {
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        record_gateway_fee_low_rejection(&mempool);

        let mp = mempool.lock().unwrap();
        let counters = mp.drop_counters_snapshot();
        assert_eq!(counters.drop_fee_too_low_total, 1);
        assert_eq!(counters.accepted_total, 0);
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn ft_recent_activity_counts_only_window() {
        let b1 = mk_block(
            1,
            vec![mk_ft_tx(
                "ALICE",
                serde_json::json!({"v":1,"ctx":crate::ft::CTX_FT_TRANSFER,"op":"transfer","token_id":1,"to":"BOB","amount":"5"}),
                1,
            )],
        );
        let b2 = mk_block(
            2,
            vec![mk_ft_tx(
                "ALICE",
                serde_json::json!({"v":1,"ctx":crate::ft::CTX_FT_APPROVE,"op":"approve","token_id":1,"spender":"SP","amount":"9"}),
                2,
            )],
        );
        let (total, counts) = ft_recent_activity_from_blocks(&[b1, b2], 1);
        assert_eq!(total, 1);
        assert_eq!(counts.get("ft_approve").copied(), Some(1));
        assert!(!counts.contains_key("ft_transfer"));
    }

    #[test]
    fn ft_receipt_json_or_error_marks_non_ft_as_none() {
        let tx = Transaction::new(
            "ALICE".to_string(),
            "BOB".to_string(),
            10,
            1,
            1,
            String::new(),
            false,
            None,
        );
        assert!(ft_receipt_json_or_error(&tx).is_none());
    }

    #[test]
    fn nft_admin_request_schema_rejects_unknown_fields() {
        let body = serde_json::json!({
            "op": "mint",
            "collection_id": 1,
            "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "extra": true
        });
        let obj = body.as_object().unwrap();
        let allowed = &[
            "allow_before_activation",
            "collection_id",
            "max_fee_per_tx",
            "metadata_hash_hex",
            "op",
            "priority_fee",
            "to",
            "token_uri",
        ];
        assert!(nft_api_exact_keys_v1(obj, allowed).is_err());
    }

    #[test]
    fn nft_admin_request_schema_rejects_missing_or_wrong_typed_fields() {
        let body = serde_json::json!({
            "op": "mint",
            "collection_id": "1",
            "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null
        });
        let obj = body.as_object().unwrap();
        assert!(nft_api_required_nonzero_u64_v1(obj, "collection_id").is_err());
        assert!(nft_api_required_nonempty_str_raw_v1(obj, "missing").is_err());
    }

    #[test]
    fn nft_admin_request_schema_builds_canonical_memo_with_builder() {
        let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
        let body = serde_json::json!({
            "op": "mint",
            "collection_id": 1,
            "to": to,
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null
        });
        let obj = body.as_object().unwrap();
        let metadata_hash_hex =
            nft_api_required_nonempty_str_raw_v1(obj, "metadata_hash_hex").unwrap();
        let op = crate::nft::NftOpV1::Mint {
            collection_id: nft_api_required_nonzero_u64_v1(obj, "collection_id").unwrap(),
            to_b64: nft_api_required_nonempty_str_raw_v1(obj, "to").unwrap(),
            token_uri: nft_api_required_str_raw_v1(obj, "token_uri").unwrap(),
            metadata_hash: crate::nft::parse_nft_hash32_hex_v1(
                "metadata_hash_hex",
                &metadata_hash_hex,
            )
            .unwrap(),
            expires_at_height: None,
        };
        let memo = crate::nft::nft_memo_json_v1(&op).unwrap();
        let tx = Transaction::new(
            crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            0,
            String::new(),
            false,
            Some(memo),
        );
        assert!(crate::nft::validate_nft_tx_syntax(&tx).is_ok());
    }

    #[test]
    fn nft_admin_utility_schema_rejects_unknown_fields() {
        let body = serde_json::json!({
            "op": "set_token_uri",
            "collection_id": 1,
            "serial": 1,
            "token_uri": "ipfs://token/updated",
            "metadata_hash_hex": "22".repeat(32),
            "unexpected": true
        });
        let obj = body.as_object().unwrap();
        let allowed = &[
            "allow_before_activation",
            "collection_id",
            "max_fee_per_tx",
            "metadata_hash_hex",
            "op",
            "priority_fee",
            "serial",
            "token_uri",
        ];
        assert!(nft_api_exact_keys_v1(obj, allowed).is_err());
    }

    #[test]
    fn nft_admin_utility_schema_rejects_missing_and_wrong_typed_fields() {
        let missing = serde_json::json!({
            "op": "freeze_token",
            "collection_id": 1,
            "frozen": true
        });
        let missing_obj = missing.as_object().unwrap();
        assert!(nft_api_required_nonzero_u64_v1(missing_obj, "serial").is_err());

        let wrong = serde_json::json!({
            "op": "set_collection_policy",
            "collection_id": "1",
            "mintable": "true",
            "burnable": true,
            "transfer_policy": "transferable",
            "revocable": true
        });
        let wrong_obj = wrong.as_object().unwrap();
        assert!(nft_api_required_nonzero_u64_v1(wrong_obj, "collection_id").is_err());
        assert!(nft_api_required_bool_v1(wrong_obj, "mintable").is_err());
    }

    #[test]
    fn nft_admin_utility_schema_rejects_bad_hash_uri_or_issuer() {
        let sender = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        // Do not use the canonical memo builder for negative schema fixtures: the builder is
        // intentionally strict and must reject malformed operations before serialization.
        let bad_hash_memo = serde_json::json!({
            "v": 1,
            "ctx": crate::nft::CTX_NFT_SET_TOKEN_URI,
            "op": "set_token_uri",
            "collection_id": 1,
            "serial": 1,
            "token_uri": "ipfs://token/updated",
            "metadata_hash_hex": "00".repeat(32),
        })
        .to_string();
        let tx = Transaction::new(
            sender.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            0,
            String::new(),
            false,
            Some(bad_hash_memo),
        );
        assert!(crate::nft::validate_nft_tx_syntax(&tx).is_err());

        let bad_uri_memo = serde_json::json!({
            "v": 1,
            "ctx": crate::nft::CTX_NFT_SET_COLLECTION_URI,
            "op": "set_collection_uri",
            "collection_id": 1,
            "base_uri": "ftp://not-allowed/",
            "metadata_hash_hex": "22".repeat(32),
        })
        .to_string();
        let tx = Transaction::new(
            sender.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            1,
            String::new(),
            false,
            Some(bad_uri_memo),
        );
        assert!(crate::nft::validate_nft_tx_syntax(&tx).is_err());

        let bad_issuer_memo = serde_json::json!({
            "v": 1,
            "ctx": crate::nft::CTX_NFT_SET_ISSUER,
            "op": "set_issuer",
            "collection_id": 1,
            "issuer": "not-canonical-key",
        })
        .to_string();
        let tx = Transaction::new(
            sender,
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            2,
            String::new(),
            false,
            Some(bad_issuer_memo),
        );
        assert!(crate::nft::validate_nft_tx_syntax(&tx).is_err());
    }

    #[test]
    fn nft_admin_utility_schema_builds_canonical_memos_with_builder() {
        let issuer = crate::keyfmt::pk_b64_from_bytes(&[8u8; 32]);
        let ops = [
            crate::nft::NftOpV1::SetTokenUri {
                collection_id: 1,
                serial: 1,
                token_uri: "ipfs://token/new".to_string(),
                metadata_hash: [0x23; 32],
            },
            crate::nft::NftOpV1::SetCollectionUri {
                collection_id: 1,
                base_uri: "newgen://collection/new".to_string(),
                metadata_hash: [0x24; 32],
            },
            crate::nft::NftOpV1::FreezeToken {
                collection_id: 1,
                serial: 1,
                frozen: true,
            },
            crate::nft::NftOpV1::SetCollectionPolicy {
                collection_id: 1,
                mintable: true,
                burnable: true,
                transfer_policy: crate::nft::NftTransferPolicyV1::Soulbound,
                revocable: true,
            },
            crate::nft::NftOpV1::SetIssuer {
                collection_id: 1,
                issuer_b64: issuer.clone(),
            },
        ];
        for (idx, op) in ops.iter().enumerate() {
            let tx = Transaction::new(
                issuer.clone(),
                crate::nft::NFT_RECEIVER.to_string(),
                0,
                1,
                idx as u64,
                String::new(),
                false,
                Some(crate::nft::nft_memo_json_v1(op).unwrap()),
            );
            assert!(
                crate::nft::validate_nft_tx_syntax(&tx).is_ok(),
                "op {:?} must be canonical",
                op
            );
        }
    }

    #[test]
    fn nft_wallet_api_parse_op_rejects_unknown_fields_and_string_numbers() {
        let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
        let body = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "mint",
            "collection_id": "1",
            "to": to,
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null,
            "extra": true
        });
        let obj = body.as_object().unwrap();
        assert!(nft_api_parse_op_from_body_v1(
            obj,
            &["from", "max_fee_per_tx", "priority_fee", "nonce"]
        )
        .is_err());

        let body = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "mint",
            "collection_id": "1",
            "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null
        });
        let obj = body.as_object().unwrap();
        assert!(nft_api_parse_op_from_body_v1(
            obj,
            &["from", "max_fee_per_tx", "priority_fee", "nonce"]
        )
        .is_err());
    }

    #[test]
    fn nft_wallet_api_parse_op_builds_canonical_mint_memo() {
        let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
        let body = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "mint",
            "collection_id": 1,
            "to": to,
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null,
            "max_fee_per_tx": 100,
            "nonce": 1
        });
        let obj = body.as_object().unwrap();
        let op = nft_api_parse_op_from_body_v1(
            obj,
            &["from", "max_fee_per_tx", "priority_fee", "nonce"],
        )
        .expect("wallet NFT op parse");
        let memo = crate::nft::nft_memo_json_v1(&op).expect("canonical NFT memo");
        let tx = Transaction::new(
            crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            100,
            String::new(),
            false,
            Some(memo),
        );
        assert!(crate::nft::validate_nft_tx_syntax(&tx).is_ok());
    }

    #[test]
    fn nft_wallet_create_accepts_missing_or_null_max_supply_as_none() {
        for include_null in [false, true] {
            let mut body = serde_json::json!({
                "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
                "op": "create_collection",
                "symbol": "TST",
                "name": "Test Collection",
                "base_uri": "ipfs://collection/",
                "metadata_hash_hex": "11".repeat(32),
                "mintable": true,
                "burnable": true,
                "asset_type": "collectible",
                "transfer_policy": "transferable",
                "revocable": false,
                "max_fee_per_tx": 100,
                "nonce": 1
            });
            if include_null {
                body["max_supply"] = serde_json::Value::Null;
            }
            let obj = body.as_object().unwrap();
            let op = nft_api_parse_op_from_body_v1(
                obj,
                &["from", "max_fee_per_tx", "priority_fee", "nonce"],
            )
            .expect("create collection should accept missing/null max_supply");
            match op {
                crate::nft::NftOpV1::CreateCollection { max_supply, .. } => {
                    assert_eq!(max_supply, None);
                }
                other => panic!("unexpected op: {:?}", other),
            }
        }
    }

    #[test]
    fn nft_wallet_mint_accepts_missing_or_null_expires_at_height_as_none() {
        for include_null in [false, true] {
            let mut body = serde_json::json!({
                "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
                "op": "mint",
                "collection_id": 1,
                "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
                "token_uri": "ipfs://token/1",
                "metadata_hash_hex": "11".repeat(32),
                "max_fee_per_tx": 100,
                "nonce": 1
            });
            if include_null {
                body["expires_at_height"] = serde_json::Value::Null;
            }
            let obj = body.as_object().unwrap();
            let op = nft_api_parse_op_from_body_v1(
                obj,
                &["from", "max_fee_per_tx", "priority_fee", "nonce"],
            )
            .expect("mint should accept missing/null expires_at_height");
            match op {
                crate::nft::NftOpV1::Mint {
                    expires_at_height, ..
                } => {
                    assert_eq!(expires_at_height, None);
                }
                other => panic!("unexpected op: {:?}", other),
            }
        }
    }

    #[test]
    fn nft_wallet_optional_nullable_u64_rejects_wrong_types() {
        let create = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "create_collection",
            "symbol": "TST",
            "name": "Test Collection",
            "base_uri": "ipfs://collection/",
            "metadata_hash_hex": "11".repeat(32),
            "mintable": true,
            "burnable": true,
            "asset_type": "collectible",
            "transfer_policy": "transferable",
            "revocable": false,
            "max_supply": "100"
        });
        assert!(nft_api_parse_op_from_body_v1(
            create.as_object().unwrap(),
            &["from", "max_fee_per_tx", "priority_fee", "nonce"]
        )
        .is_err());

        let mint = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "mint",
            "collection_id": 1,
            "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": "100"
        });
        assert!(nft_api_parse_op_from_body_v1(
            mint.as_object().unwrap(),
            &["from", "max_fee_per_tx", "priority_fee", "nonce"]
        )
        .is_err());
    }

    #[test]
    fn nft_wallet_api_rejects_string_fee_and_nonce_fields() {
        let body = serde_json::json!({
            "max_fee_per_tx": "100",
            "nonce": "1",
            "priority_fee": "2"
        });
        let obj = body.as_object().unwrap();
        assert!(nft_api_optional_u64_v1(obj, "max_fee_per_tx").is_err());
        assert!(nft_api_optional_u64_v1(obj, "nonce").is_err());
        assert!(nft_api_optional_u64_v1(obj, "priority_fee").is_err());
    }

    #[test]
    fn nft_wallet_unsigned_payload_uses_submit_signed_schema() {
        let from = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let op = crate::nft::NftOpV1::Transfer {
            collection_id: 1,
            serial: 1,
            to_b64: crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]),
        };
        let memo = crate::nft::nft_memo_json_v1(&op).unwrap();
        let payload = TransactionPayload {
            network_id: chain_identity::network_id().to_string(),
            from: from.clone(),
            to: crate::nft::NFT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 123,
            nonce: 9,
            memo: Some(memo.clone()),
        };
        let signing_string = canonical_signing_string(&payload);
        assert!(signing_string.contains(crate::nft::NFT_RECEIVER));
        assert!(signing_string.contains(&memo));

        let mut tx = Transaction {
            sender: from,
            receiver: crate::nft::NFT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 123,
            nonce: 9,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(memo),
        };
        tx.hash = tx.calculate_hash();
        assert_eq!(tx.receiver, payload.to);
        assert_eq!(tx.max_fee_per_tx, payload.max_fee_per_tx);
        assert_eq!(tx.nonce, payload.nonce);
        assert_eq!(tx.memo, payload.memo);
    }

    #[test]
    fn nft_wallet_build_unsigned_fee_contract_is_explicit_and_fail_closed() {
        assert_eq!(
            nft_api_effective_unsigned_max_fee_v1(None, 3, 100).unwrap(),
            103
        );
        assert_eq!(
            nft_api_effective_unsigned_max_fee_v1(Some(100), 999, 100).unwrap(),
            100
        );
        let err = nft_api_effective_unsigned_max_fee_v1(Some(99), 0, 100).unwrap_err();
        assert!(err.contains("max_fee_per_tx_below_base_fee"));
    }

    #[test]
    fn nft_wallet_public_endpoints_reject_allow_before_activation_field() {
        let body = serde_json::json!({
            "from": crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            "op": "mint",
            "collection_id": 1,
            "to": crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]),
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null,
            "allow_before_activation": true
        });
        let obj = body.as_object().unwrap();
        assert!(
            nft_api_reject_unsupported_public_field_v1(obj, "allow_before_activation").is_err()
        );
        assert!(nft_api_parse_op_from_body_v1(
            obj,
            &["from", "max_fee_per_tx", "priority_fee", "nonce"]
        )
        .is_err());
    }

    #[test]
    fn nft_wallet_policy_rejects_nft_disabled_and_op_disabled() {
        let from = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
        let op = crate::nft::NftOpV1::Mint {
            collection_id: 1,
            to_b64: to,
            token_uri: "ipfs://token/1".to_string(),
            metadata_hash: [0x11; 32],
            expires_at_height: None,
        };
        let memo = crate::nft::nft_memo_json_v1(&op).unwrap();
        let mut gov = test_governance_with_validator(&from);
        gov.params.nft_enabled = false;
        gov.params.nft_public_mint_enabled = true;
        gov.params.nft_metadata_hash_required = true;
        assert_eq!(
            nft_policy_validate_request_v1(&op, &memo, Some(&gov.params)).unwrap_err(),
            "nft_disabled"
        );

        gov.params.nft_enabled = true;
        gov.params.nft_public_mint_enabled = false;
        let err = nft_policy_validate_request_v1(&op, &memo, Some(&gov.params)).unwrap_err();
        assert!(err.contains("nft_op_disabled: mint"));
    }

    fn configure_nft_wallet_test_chain(
        bc: &mut Blockchain,
        storage: Arc<DbStore>,
        owner_b64: &str,
        balance: u64,
        base_fee: u64,
        nft_mint_fee_native: u64,
        nft_enabled: bool,
        nft_public_mint_enabled: bool,
    ) {
        bc.policy.base_fee_per_tx = base_fee;
        let mut gov = test_governance_with_validator(owner_b64);
        gov.params.nft_activation_height = 0;
        gov.params.nft_enabled = nft_enabled;
        gov.params.nft_public_create_enabled = true;
        gov.params.nft_public_mint_enabled = nft_public_mint_enabled;
        gov.params.nft_metadata_hash_required = true;
        gov.params.nft_max_memo_bytes = crate::nft::NFTV1_MEMO_MAX_BYTES as u32;
        gov.params.nft_max_uri_bytes = crate::nft::NFTV1_URI_MAX_BYTES as u32;
        gov.params.nft_max_name_bytes = crate::nft::NFTV1_NAME_MAX_BYTES as u32;
        gov.params.nft_max_symbol_bytes = crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32;
        gov.params.nft_max_collections_per_owner = 10_000;
        gov.params.nft_max_tokens_per_collection = 10_000;
        gov.params.nft_max_tokens_per_owner = 10_000;
        gov.params.nft_create_fee_native = 0;
        gov.params.nft_mint_fee_native = nft_mint_fee_native;
        bc.governance = Some(gov.clone());
        bc.governance_bootstrap = Some(gov.clone());
        bc.attach_storage(storage);
        // attach_storage may restore economy policy defaults from config/storage.
        // Re-apply the explicit test fee floor after attach so NFT wallet fixtures
        // remain deterministic and do not depend on the host config/economy_policy.json.
        bc.policy.base_fee_per_tx = base_fee;
        bc.governance = Some(gov.clone());
        bc.governance_bootstrap = Some(gov);

        let coinbase = Transaction::new(
            "COINBASE".to_string(),
            owner_b64.to_string(),
            balance,
            0,
            0,
            String::new(),
            true,
            None,
        );
        let create_op = crate::nft::NftOpV1::CreateCollection {
            symbol: "TEST".to_string(),
            name: "Test Collection".to_string(),
            max_supply: Some(100),
            base_uri: "ipfs://collection/".to_string(),
            metadata_hash: [0x22; 32],
            mintable: true,
            burnable: true,
            asset_type: crate::nft::NftAssetTypeV1::Collectible,
            transfer_policy: crate::nft::NftTransferPolicyV1::Transferable,
            revocable: true,
        };
        let create = Transaction::new(
            owner_b64.to_string(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            0,
            0,
            String::new(),
            false,
            Some(crate::nft::nft_memo_json_v1(&create_op).expect("create collection memo")),
        );
        bc.chain.push(mk_block(1, vec![coinbase, create]));
        bc.test_recompute_all_state_roots_from_blocks()
            .expect("test chain state roots");
    }

    fn configure_nft_wallet_account_only_test_chain(
        bc: &mut Blockchain,
        storage: Arc<DbStore>,
        owner_b64: &str,
        balance: u64,
        base_fee: u64,
        nft_create_fee_native: u64,
        nft_enabled: bool,
    ) {
        bc.policy.base_fee_per_tx = base_fee;
        let mut gov = test_governance_with_validator(owner_b64);
        gov.params.nft_activation_height = 0;
        gov.params.nft_enabled = nft_enabled;
        gov.params.nft_public_create_enabled = true;
        gov.params.nft_public_mint_enabled = true;
        gov.params.nft_public_transfer_enabled = true;
        gov.params.nft_metadata_hash_required = true;
        gov.params.nft_max_memo_bytes = crate::nft::NFTV1_MEMO_MAX_BYTES as u32;
        gov.params.nft_max_uri_bytes = crate::nft::NFTV1_URI_MAX_BYTES as u32;
        gov.params.nft_max_name_bytes = crate::nft::NFTV1_NAME_MAX_BYTES as u32;
        gov.params.nft_max_symbol_bytes = crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32;
        gov.params.nft_max_collections_per_owner = 10_000;
        gov.params.nft_max_tokens_per_collection = 10_000;
        gov.params.nft_max_tokens_per_owner = 10_000;
        gov.params.nft_create_fee_native = nft_create_fee_native;
        gov.params.nft_mint_fee_native = 0;
        bc.governance = Some(gov.clone());
        bc.governance_bootstrap = Some(gov.clone());
        bc.attach_storage(storage);
        // attach_storage may restore economy policy defaults from config/storage.
        // Re-apply the explicit test fee floor after attach so NFT wallet fixtures
        // remain deterministic and do not depend on the host config/economy_policy.json.
        bc.policy.base_fee_per_tx = base_fee;
        bc.governance = Some(gov.clone());
        bc.governance_bootstrap = Some(gov);

        let coinbase = Transaction::new(
            "COINBASE".to_string(),
            owner_b64.to_string(),
            balance,
            0,
            0,
            String::new(),
            true,
            None,
        );
        bc.chain.push(mk_block(1, vec![coinbase]));
        bc.test_recompute_all_state_roots_from_blocks()
            .expect("test account-only chain state roots");
    }

    fn nft_wallet_mint_body(from: &str, to: &str) -> serde_json::Value {
        serde_json::json!({
            "from": from,
            "op": "mint",
            "collection_id": 1,
            "to": to,
            "token_uri": "ipfs://token/1",
            "metadata_hash_hex": "11".repeat(32),
            "expires_at_height": null
        })
    }

    fn nft_wallet_create_collection_body(from: &str) -> serde_json::Value {
        serde_json::json!({
            "from": from,
            "op": "create_collection",
            "symbol": "PUB",
            "name": "Public Wallet Collection",
            "max_supply": 100,
            "base_uri": "ipfs://public-wallet/",
            "metadata_hash_hex": "33".repeat(32),
            "mintable": true,
            "burnable": true,
            "asset_type": "collectible",
            "transfer_policy": "transferable",
            "revocable": true
        })
    }

    #[test]
    fn nft_wallet_public_routes_reject_low_fee_and_unsupported_activation_bypass() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_BIND_ADDR",
            "NEWGEN_API_HOST",
            "NEWGEN_API_ADMIN_TOKEN",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        std::env::set_var("NEWGEN_API_BIND_ADDR", "127.0.0.1");
        std::env::remove_var("NEWGEN_API_ADMIN_TOKEN");

        run_async_test(async {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let from = STANDARD.encode(sk.verifying_key().to_bytes());
            let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
            let storage = open_empty_test_storage();
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                configure_nft_wallet_test_chain(
                    &mut bc,
                    storage.clone(),
                    &from,
                    1_000,
                    100,
                    0,
                    true,
                    true,
                );
            }
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain, mempool, tx_p2p, port, storage, false, true,
            ));
            wait_for_server_ready(port, "/health").await;

            let mut low_fee = nft_wallet_mint_body(&from, &to);
            low_fee["max_fee_per_tx"] = serde_json::json!(99);
            let (status, json) =
                http_post_json_via_server(port, "/api/v2/nft/build_unsigned", &low_fee).await;
            assert_eq!(status, warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(json["status"], "invalid_max_fee_per_tx");
            assert_eq!(json["required_at_least"], 100);
            assert_eq!(json["provided"], 99);

            let mut bypass = nft_wallet_mint_body(&from, &to);
            bypass["allow_before_activation"] = serde_json::json!(true);
            let (status, json) =
                http_post_json_via_server(port, "/api/v2/nft/estimate_fee", &bypass).await;
            assert_eq!(status, warp::http::StatusCode::BAD_REQUEST);
            assert_eq!(json["message"], "nft_unsupported_field");

            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn nft_operator_approval_read_rejects_noncanonical_owner_and_operator() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_BIND_ADDR",
            "NEWGEN_API_HOST",
            "NEWGEN_API_ADMIN_TOKEN",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        std::env::set_var("NEWGEN_API_BIND_ADDR", "127.0.0.1");
        std::env::remove_var("NEWGEN_API_ADMIN_TOKEN");

        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let port = pick_unused_local_port();
            let storage = open_empty_test_storage();
            let server = tokio::spawn(serve_api(
                chain, mempool, tx_p2p, port, storage, false, true,
            ));
            wait_for_server_ready(port, "/health").await;

            let operator = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
            let rejected_owner = http_get_json_via_server(
                port,
                &format!(
                    "/api/v2/nft/operator_approval?collection_id=1&owner=bad&operator={}",
                    operator
                ),
            )
            .await;
            assert_eq!(rejected_owner["status"], "error");
            assert_eq!(rejected_owner["message"], "nft_owner_invalid");

            let owner = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
            let rejected_operator = http_get_json_via_server(
                port,
                &format!(
                    "/api/v2/nft/operator_approval?collection_id=1&owner={}&operator=bad",
                    owner
                ),
            )
            .await;
            assert_eq!(rejected_operator["status"], "error");
            assert_eq!(rejected_operator["message"], "nft_operator_invalid");

            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn nft_wallet_build_unsigned_then_submit_signed_accepts_and_rejects_tamper() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_BIND_ADDR",
            "NEWGEN_API_HOST",
            "NEWGEN_API_ADMIN_TOKEN",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        std::env::set_var("NEWGEN_API_BIND_ADDR", "127.0.0.1");
        std::env::remove_var("NEWGEN_API_ADMIN_TOKEN");

        run_async_test(async {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let sk_b64 = STANDARD.encode(sk.to_bytes());
            let from = STANDARD.encode(sk.verifying_key().to_bytes());
            let storage = open_empty_test_storage();
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                configure_nft_wallet_account_only_test_chain(
                    &mut bc,
                    storage.clone(),
                    &from,
                    1_000,
                    100,
                    0,
                    true,
                );
            }
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain, mempool, tx_p2p, port, storage, false, true,
            ));
            wait_for_server_ready(port, "/health").await;

            let mut build_req = nft_wallet_create_collection_body(&from);
            build_req["priority_fee"] = serde_json::json!(3);
            let (status, built) =
                http_post_json_via_server(port, "/api/v2/nft/build_unsigned", &build_req).await;
            assert_eq!(
                status,
                warp::http::StatusCode::OK,
                "nft build_unsigned response body: {}",
                built
            );
            assert_eq!(built["payload"]["max_fee_per_tx"], 103);
            assert_eq!(built["fee"]["required_total_native"], 103);
            let payload: TransactionPayload =
                serde_json::from_value(built["payload"].clone()).expect("payload");
            let signature_b64 =
                crate::wallet::sign_payload_ed25519(&sk_b64, &payload).expect("wallet signature");
            let signed = serde_json::json!({
                "payload": payload,
                "public_key_b64": from,
                "signature_b64": signature_b64
            });
            let (status, submitted) =
                http_post_json_via_server(port, "/api/v2/tx/submit_signed", &signed).await;
            assert_eq!(
                status,
                warp::http::StatusCode::OK,
                "submit_signed response body: {}",
                submitted
            );
            assert_eq!(submitted["status"], "ok");

            let mut tampered = signed.clone();
            let original_memo = tampered["payload"]["memo"].as_str().unwrap().to_string();
            tampered["payload"]["memo"] = serde_json::json!(format!("{} ", original_memo));
            let (status, rejected) =
                http_post_json_via_server(port, "/api/v2/tx/submit_signed", &tampered).await;
            assert_eq!(status, warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(rejected["status"], "invalid_signature");

            let mut wrong_signature = signed.clone();
            wrong_signature["signature_b64"] = serde_json::json!(STANDARD.encode([0u8; 64]));
            let (status, rejected) =
                http_post_json_via_server(port, "/api/v2/tx/submit_signed", &wrong_signature).await;
            assert_eq!(status, warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(rejected["status"], "invalid_signature");

            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn nft_wallet_routes_cover_extra_fee_in_estimate_and_build_admission() {
        let _lock = env_test_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            "NEWGEN_API_GUARD_PROFILE",
            "NEWGEN_API_BIND_ADDR",
            "NEWGEN_API_HOST",
            "NEWGEN_API_ADMIN_TOKEN",
        ]);
        std::env::set_var("NEWGEN_API_GUARD_PROFILE", "trusted_benchmark_local");
        std::env::set_var("NEWGEN_API_BIND_ADDR", "127.0.0.1");
        std::env::remove_var("NEWGEN_API_ADMIN_TOKEN");

        run_async_test(async {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let from = STANDARD.encode(sk.verifying_key().to_bytes());
            let to = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
            let storage = open_empty_test_storage();
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                configure_nft_wallet_test_chain(
                    &mut bc,
                    storage.clone(),
                    &from,
                    100,
                    100,
                    7,
                    true,
                    true,
                );
            }
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain, mempool, tx_p2p, port, storage, false, true,
            ));
            wait_for_server_ready(port, "/health").await;

            let body = nft_wallet_mint_body(&from, &to);
            let (status, estimate) =
                http_post_json_via_server(port, "/api/v2/nft/estimate_fee", &body).await;
            assert_eq!(status, warp::http::StatusCode::OK);
            assert_eq!(estimate["suggested_max_fee_per_tx"], 100);
            assert_eq!(estimate["nft_extra_fee_native"], 7);
            assert_eq!(estimate["required_total_native"], 107);
            assert_eq!(estimate["can_cover"], false);

            let (status, rejected) =
                http_post_json_via_server(port, "/api/v2/nft/build_unsigned", &body).await;
            assert_eq!(status, warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(rejected["status"], "insufficient_funds_after_pending");
            assert_eq!(rejected["extra_native_required"], 7);
            assert_eq!(rejected["required_additional"], 107);

            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn nft_recent_activity_counts_only_window() {
        let alice = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let bob = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let carol = crate::keyfmt::pk_b64_from_bytes(&[3u8; 32]);
        let tx1 = Transaction::new(
            alice.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            0,
            String::new(),
            false,
            Some(
                crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Mint {
                    collection_id: 1,
                    to_b64: bob.clone(),
                    token_uri: "ipfs://a".to_string(),
                    metadata_hash: [0x41; 32],
                    expires_at_height: None,
                })
                .unwrap(),
            ),
        );
        let mut b1 = mk_block(1, vec![tx1.clone()]);
        let mut ev1 = crate::nft::NftEventV1::base("nft_token_minted", "mint", 1, &tx1.hash, 0);
        ev1.collection_id = Some(1);
        ev1.serial = Some(1);
        ev1.owner_b64 = Some(bob);
        b1.nft_events = vec![ev1];

        let tx2 = Transaction::new(
            alice,
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            2,
            0,
            String::new(),
            false,
            Some(
                crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Transfer {
                    collection_id: 1,
                    serial: 1,
                    to_b64: carol.clone(),
                })
                .unwrap(),
            ),
        );
        let mut b2 = mk_block(2, vec![tx2.clone()]);
        let mut ev2 =
            crate::nft::NftEventV1::base("nft_token_transferred", "transfer", 2, &tx2.hash, 0);
        ev2.collection_id = Some(1);
        ev2.serial = Some(1);
        ev2.to_b64 = Some(carol);
        b2.nft_events = vec![ev2];

        let (total, counts) = nft_recent_activity_from_blocks(&[b1, b2], 1);
        assert_eq!(total, 1);
        assert_eq!(counts.get("nft_token_transferred").copied(), Some(1));
        assert!(!counts.contains_key("nft_token_minted"));
    }

    #[test]
    fn nft_block9_link_helpers_are_url_safe_and_explorer_ready() {
        let owner = crate::keyfmt::pk_b64_from_bytes(&[255u8; 32]);
        let links = nft_api_link_set_v1(7, Some(3), Some(&owner));
        assert_eq!(
            links.get("collection").and_then(|v| v.as_str()),
            Some("/nft/collection/7")
        );
        assert_eq!(
            links.get("token").and_then(|v| v.as_str()),
            Some("/nft/collection/7/token/3")
        );
        let wallet_api = links
            .get("wallet_assets_api")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(wallet_api.starts_with("/api/v2/nft/wallet?owner="));
        let encoded_owner = wallet_api
            .split("owner=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        assert!(
            !encoded_owner.contains('+'),
            "base64 owner must be query encoded"
        );
        assert!(
            !encoded_owner.contains('/'),
            "base64 owner must be query encoded"
        );
        assert!(
            encoded_owner.contains("%"),
            "non-url-safe base64 characters should be percent-encoded"
        );
    }

    #[test]
    fn nft_block9_recent_activity_helper_filters_and_paginates_state_events() {
        let owner_a = crate::keyfmt::pk_b64_from_bytes(&[10u8; 32]);
        let owner_b = crate::keyfmt::pk_b64_from_bytes(&[11u8; 32]);
        let tx = Transaction::new(
            owner_a.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            0,
            String::new(),
            false,
            None,
        );
        let mut b = mk_block(10, vec![tx.clone()]);
        let mut ev1 = crate::nft::NftEventV1::base("nft_token_minted", "mint", 10, &tx.hash, 0);
        ev1.collection_id = Some(1);
        ev1.serial = Some(1);
        ev1.asset_id = Some(crate::nft::nft_asset_id_v1(1, 1));
        ev1.owner_b64 = Some(owner_a.clone());
        let mut ev2 =
            crate::nft::NftEventV1::base("nft_token_transferred", "transfer", 10, &tx.hash, 0);
        ev2.collection_id = Some(2);
        ev2.serial = Some(1);
        ev2.asset_id = Some(crate::nft::nft_asset_id_v1(2, 1));
        ev2.from_b64 = Some(owner_a.clone());
        ev2.to_b64 = Some(owner_b.clone());
        b.nft_events = vec![ev1, ev2];

        let (total, items) = nft_recent_activity_items_from_blocks_v1(
            &[b.clone()],
            1,
            0,
            10,
            Some(2),
            Some(&owner_b),
        );
        assert_eq!(total, 1);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].get("kind").and_then(|v| v.as_str()),
            Some("nft_token_transferred")
        );
        assert_eq!(
            items[0].get("asset_id").and_then(|v| v.as_str()),
            Some("nft:2:1")
        );
        assert!(items[0].get("links").is_some());

        let (total_all, page) = nft_recent_activity_items_from_blocks_v1(&[b], 1, 1, 1, None, None);
        assert_eq!(total_all, 2);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn nft_block9_recent_activity_owner_filter_matches_approved_and_operator() {
        let owner = crate::keyfmt::pk_b64_from_bytes(&[3u8; 32]);
        let approved = crate::keyfmt::pk_b64_from_bytes(&[4u8; 32]);
        let operator = crate::keyfmt::pk_b64_from_bytes(&[5u8; 32]);
        let mut approve =
            crate::nft::NftEventV1::base("nft_token_approved", "approve", 12, "tx3", 0);
        approve.collection_id = Some(9);
        approve.serial = Some(1);
        approve.owner_b64 = Some(owner.clone());
        approve.approved_b64 = Some(approved.clone());
        approve.asset_id = Some(crate::nft::nft_asset_id_v1(9, 1));
        let mut op = crate::nft::NftEventV1::base(
            "nft_operator_approval_set",
            "set_approval_for_all",
            13,
            "tx4",
            0,
        );
        op.collection_id = Some(9);
        op.owner_b64 = Some(owner);
        op.operator_b64 = Some(operator.clone());
        op.approved = Some(true);
        let mut b = mk_block(13, vec![]);
        b.nft_events = vec![approve, op];

        let (approved_total, approved_items) =
            nft_recent_activity_items_from_blocks_v1(&[b.clone()], 1, 0, 10, None, Some(&approved));
        assert_eq!(approved_total, 1);
        assert_eq!(
            approved_items[0].get("kind").and_then(|v| v.as_str()),
            Some("nft_token_approved")
        );

        let (operator_total, operator_items) =
            nft_recent_activity_items_from_blocks_v1(&[b], 1, 0, 10, None, Some(&operator));
        assert_eq!(operator_total, 1);
        assert_eq!(
            operator_items[0].get("kind").and_then(|v| v.as_str()),
            Some("nft_operator_approval_set")
        );
    }

    #[test]
    fn nft_metrics_governance_source_metadata_is_finalized() {
        let ctx = NftPublicReadContextV1 {
            source_commitment: "finalized",
            finalized_height: 77,
            finalized_hash: "finalized-hash".to_string(),
            finalized_state_root: "00".repeat(32),
            tip_height: 81,
            tip_hash: "tip-hash".to_string(),
            finalized_root: [0u8; 32],
            finalized_blocks: vec![],
        };
        let source = nft_governance_public_read_source_json_v1(&ctx, 77);
        assert_eq!(
            source.get("source_commitment").and_then(|v| v.as_str()),
            Some("finalized")
        );
        assert_eq!(
            source.get("governance_height").and_then(|v| v.as_u64()),
            Some(77)
        );
        assert_eq!(
            source.get("finalized_height").and_then(|v| v.as_u64()),
            Some(77)
        );
        assert_eq!(source.get("tip_height").and_then(|v| v.as_u64()), Some(81));
        assert_eq!(
            source.get("read_model_version").and_then(|v| v.as_str()),
            Some("nft_governance_policy_read_model_v1")
        );
    }

    #[test]
    fn nft_block9_public_source_metadata_is_finalized() {
        let ctx = NftPublicReadContextV1 {
            source_commitment: "finalized",
            finalized_height: 42,
            finalized_hash: "finalized-hash".to_string(),
            finalized_state_root: "00".repeat(32),
            tip_height: 45,
            tip_hash: "tip-hash".to_string(),
            finalized_root: [0u8; 32],
            finalized_blocks: vec![],
        };
        let source = nft_public_read_source_json_v1(&ctx);
        assert_eq!(
            source.get("source_commitment").and_then(|v| v.as_str()),
            Some("finalized")
        );
        assert_eq!(
            source.get("finalized_height").and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(source.get("tip_height").and_then(|v| v.as_u64()), Some(45));
        assert_eq!(
            source.get("read_model_version").and_then(|v| v.as_str()),
            Some("nft_public_read_model_v1")
        );
    }

    #[test]
    fn nft_api_helpers_use_block_events_not_memo_preview() {
        let owner = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let receiver = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let tx = Transaction::new(
            owner.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            0,
            String::new(),
            false,
            Some(
                crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Transfer {
                    collection_id: 7,
                    serial: 3,
                    to_b64: receiver.clone(),
                })
                .unwrap(),
            ),
        );

        let block_without_applied_events = mk_block(10, vec![tx.clone()]);
        assert!(
            nft_first_event_for_tx_from_block_v1(&block_without_applied_events, &tx.hash, 0)
                .is_none(),
            "NFT API receipt helper must not synthesize memo-derived receipts"
        );
        assert!(
            nft_event_values_for_tx_from_block_v1(&block_without_applied_events, &tx.hash, 0)
                .is_empty()
        );

        let mut wrong_event = crate::nft::NftEventV1::base(
            "nft_token_transferred",
            "transfer",
            10,
            "other-tx-hash",
            0,
        );
        wrong_event.collection_id = Some(7);
        wrong_event.serial = Some(3);
        wrong_event.asset_id = Some(crate::nft::nft_asset_id_v1(7, 3));
        let mut block_with_wrong_event = mk_block(10, vec![tx.clone()]);
        block_with_wrong_event.nft_events = vec![wrong_event];
        assert!(
            nft_event_values_for_tx_from_block_v1(&block_with_wrong_event, &tx.hash, 0).is_empty()
        );

        let mut applied_event =
            crate::nft::NftEventV1::base("nft_token_transferred", "transfer", 10, &tx.hash, 0);
        applied_event.collection_id = Some(7);
        applied_event.serial = Some(3);
        applied_event.asset_id = Some(crate::nft::nft_asset_id_v1(7, 3));
        applied_event.from_b64 = Some(owner);
        applied_event.to_b64 = Some(receiver.clone());
        applied_event.owner_b64 = Some(receiver);
        let mut block_with_applied_event = mk_block(10, vec![tx.clone()]);
        block_with_applied_event.nft_events = vec![applied_event];
        let values = nft_event_values_for_tx_from_block_v1(&block_with_applied_event, &tx.hash, 0);
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0].get("kind").and_then(|v| v.as_str()),
            Some("nft_token_transferred")
        );
        assert_eq!(
            values[0].get("asset_id").and_then(|v| v.as_str()),
            Some("nft:7:3")
        );
    }

    fn nft_block10_api_seed_read_model() -> (StateSmt, [u8; 32], String) {
        let smt = StateSmt::ephemeral();
        let owner = crate::keyfmt::pk_b64_from_bytes(&[7u8; 32]);
        let mut root = smt.empty_root();
        let collection = nft::NftCollectionMetaV1 {
            id: 1,
            owner_b64: owner.clone(),
            symbol: "B10API".to_string(),
            name: "Block 10 API".to_string(),
            max_supply: Some(10),
            total_minted: 2,
            live_supply: 2,
            created_height: 3,
            metadata_hash: [0xabu8; 32],
            base_uri: "newgen://b10api/".to_string(),
            issuer_b64: owner.clone(),
            asset_type: nft::NftAssetTypeV1::Collectible,
            transfer_policy: nft::NftTransferPolicyV1::Transferable,
            revocable: true,
        };
        root = smt
            .update_account(
                root,
                nft::k_nft_collection_meta(1),
                nft::encode_collection_meta_state_v1(&collection).unwrap(),
            )
            .unwrap();
        root = smt
            .update_account(
                root,
                nft::k_nft_collection_cfg(1),
                nft::encode_collection_cfg_state_v1(&nft::NftCollectionCfgV1 {
                    mintable: true,
                    burnable: true,
                    paused: false,
                })
                .unwrap(),
            )
            .unwrap();
        root = smt
            .update_account(
                root,
                nft::k_nft_collection_next_serial(1),
                crate::account::AccountState {
                    nonce: 0,
                    balance: 3,
                    data: vec![],
                },
            )
            .unwrap();
        root = smt
            .update_account(
                root,
                nft::k_nft_collection_token_count(1),
                crate::account::AccountState {
                    nonce: 0,
                    balance: 2,
                    data: vec![],
                },
            )
            .unwrap();
        root = smt
            .update_account(
                root,
                nft::k_nft_owner_token_count(&owner),
                crate::account::AccountState {
                    nonce: 0,
                    balance: 2,
                    data: vec![],
                },
            )
            .unwrap();
        for serial in 1..=2u64 {
            let token = nft::NftTokenMetaV1 {
                collection_id: 1,
                serial,
                minted_height: 4,
                metadata_hash: [0xacu8.saturating_add(serial as u8); 32],
                token_uri: format!("newgen://b10api/{serial}"),
                status: nft::NftTokenStatusV1::Active,
                expires_at_height: None,
            };
            let token_ref = nft::NftTokenRefV1 {
                collection_id: 1,
                serial,
            };
            root = smt
                .update_account(
                    root,
                    nft::k_nft_token_meta(1, serial),
                    nft::encode_token_meta_state_v1(&token).unwrap(),
                )
                .unwrap();
            root = smt
                .update_account(
                    root,
                    nft::k_nft_token_owner(1, serial),
                    nft::encode_token_owner_state_v1(&owner).unwrap(),
                )
                .unwrap();
            root = smt
                .update_account(
                    root,
                    nft::k_nft_collection_token_item(1, serial - 1),
                    nft::encode_token_ref_state_v1(&token_ref).unwrap(),
                )
                .unwrap();
            root = smt
                .update_account(
                    root,
                    nft::k_nft_owner_token_item(&owner, serial - 1),
                    nft::encode_token_ref_state_v1(&token_ref).unwrap(),
                )
                .unwrap();
            root = smt
                .update_account(
                    root,
                    nft::k_nft_token_index_ref(1, serial),
                    nft::encode_token_index_ref_state_v1(&nft::NftTokenIndexRefV1 {
                        owner_b64: owner.clone(),
                        owner_index: serial - 1,
                        collection_index: serial - 1,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        (smt, root, owner)
    }

    #[test]
    fn nft_api_collection_token_owner_ok() {
        let (smt, root, owner) = nft_block10_api_seed_read_model();
        let collection = nft_collection_read_model_from_smt_v1(&smt, root, 1).unwrap();
        assert_eq!(collection["id"].as_u64(), Some(1));
        assert_eq!(collection["owner_b64"].as_str(), Some(owner.as_str()));
        let expected_collection_hash = "ab".repeat(32);
        assert_eq!(
            collection["metadata_hash_hex"].as_str(),
            Some(expected_collection_hash.as_str())
        );
        assert_eq!(collection["token_count_indexed"].as_u64(), Some(2));

        let token = nft_token_read_model_from_smt_v1(&smt, root, 1, 2, 10).unwrap();
        assert_eq!(token["asset_id"].as_str(), Some("nft:1:2"));
        assert_eq!(token["owner_b64"].as_str(), Some(owner.as_str()));
        assert_eq!(token["collection"]["symbol"].as_str(), Some("B10API"));
        let expected_token_hash = "ae".repeat(32);
        assert_eq!(
            token["metadata_hash_hex"].as_str(),
            Some(expected_token_hash.as_str())
        );
        assert!(token["links"]["owner_of_api"]
            .as_str()
            .unwrap()
            .contains("collection_id=1"));
    }

    #[test]
    fn nft_api_token_read_model_handles_terminal_tombstone_without_owner() {
        let (smt, mut root, _owner) = nft_block10_api_seed_read_model();
        let token = nft::NftTokenMetaV1 {
            collection_id: 1,
            serial: 3,
            minted_height: 5,
            metadata_hash: [0xbdu8; 32],
            token_uri: "newgen://b10api/3".to_string(),
            status: nft::NftTokenStatusV1::Burned,
            expires_at_height: None,
        };
        root = smt
            .update_account(
                root,
                nft::k_nft_token_meta(1, 3),
                nft::encode_token_meta_state_v1(&token).unwrap(),
            )
            .unwrap();

        let model = nft_token_read_model_from_smt_v1(&smt, root, 1, 3, 10).unwrap();
        assert_eq!(model["asset_id"].as_str(), Some("nft:1:3"));
        assert!(model["owner_b64"].is_null());
        assert_eq!(model["owner_present"].as_bool(), Some(false));
        assert_eq!(model["owner_state"].as_str(), Some("terminal_tombstone"));
        assert_eq!(model["stored_status"].as_str(), Some("burned"));
        assert_eq!(model["effective_status"].as_str(), Some("burned"));
        assert_eq!(model["status"].as_str(), Some("burned"));
        assert!(model["approved_b64"].is_null());
    }

    #[test]
    fn nft_api_token_read_model_reports_effective_expired_status() {
        let (smt, mut root, owner) = nft_block10_api_seed_read_model();
        let token = nft::NftTokenMetaV1 {
            collection_id: 1,
            serial: 4,
            minted_height: 5,
            metadata_hash: [0xbeu8; 32],
            token_uri: "newgen://b10api/4".to_string(),
            status: nft::NftTokenStatusV1::Active,
            expires_at_height: Some(8),
        };
        root = smt
            .update_account(
                root,
                nft::k_nft_token_meta(1, 4),
                nft::encode_token_meta_state_v1(&token).unwrap(),
            )
            .unwrap();
        root = smt
            .update_account(
                root,
                nft::k_nft_token_owner(1, 4),
                nft::encode_token_owner_state_v1(&owner).unwrap(),
            )
            .unwrap();

        let model = nft_token_read_model_from_smt_v1(&smt, root, 1, 4, 10).unwrap();
        assert_eq!(model["owner_b64"].as_str(), Some(owner.as_str()));
        assert_eq!(model["stored_status"].as_str(), Some("active"));
        assert_eq!(model["effective_status"].as_str(), Some("expired"));
        assert_eq!(model["status"].as_str(), Some("expired"));
        assert_eq!(model["expires_at_height"].as_u64(), Some(8));
    }

    #[test]
    fn nft_api_wallet_assets_pagination_ok() {
        let (smt, root, owner) = nft_block10_api_seed_read_model();
        let total = smt
            .get_account(root, nft::k_nft_owner_token_count(&owner))
            .unwrap()
            .unwrap()
            .balance;
        assert_eq!(total, 2);
        let cursor = 1u64;
        let limit = 1u64;
        let end = cursor.saturating_add(limit).min(total);
        let st_ref = smt
            .get_account(root, nft::k_nft_owner_token_item(&owner, cursor))
            .unwrap()
            .unwrap();
        let token_ref = nft::decode_token_ref_state_v1(&st_ref).unwrap();
        let token = nft_token_read_model_from_smt_v1(
            &smt,
            root,
            token_ref.collection_id,
            token_ref.serial,
            10,
        )
        .unwrap();
        let item = serde_json::json!({
            "index": cursor,
            "collection_id": token_ref.collection_id,
            "serial": token_ref.serial,
            "asset_id": nft::nft_asset_id_v1(token_ref.collection_id, token_ref.serial),
            "owner_b64": token["owner_b64"].clone(),
            "token": token,
            "links": nft_api_link_set_v1(token_ref.collection_id, Some(token_ref.serial), Some(&owner)),
        });
        assert_eq!(end, 2);
        assert!(
            end >= total,
            "second page should not advertise another cursor"
        );
        assert_eq!(item["index"].as_u64(), Some(1));
        assert_eq!(item["serial"].as_u64(), Some(2));
        assert_eq!(item["asset_id"].as_str(), Some("nft:1:2"));
        assert!(item["links"]["wallet_assets_api"]
            .as_str()
            .unwrap()
            .contains("cursor=0"));
    }

    #[test]
    fn nft_event_values_for_non_nft_tx_are_empty() {
        let tx = Transaction::new(
            "ALICE".to_string(),
            "BOB".to_string(),
            10,
            1,
            1,
            String::new(),
            false,
            None,
        );
        let block = mk_block(1, vec![tx.clone()]);
        assert!(nft_first_event_for_tx_from_block_v1(&block, &tx.hash, 0).is_none());
        assert!(nft_event_values_for_tx_from_block_v1(&block, &tx.hash, 0).is_empty());
    }

    pub(crate) fn run_async_test<F>(fut: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut);
    }

    pub(crate) fn open_empty_test_storage() -> Arc<DbStore> {
        Arc::new(crate::storage::open_clean_test_dbstore("api-test").unwrap())
    }

    pub(crate) fn pick_unused_local_port() -> u16 {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    pub(crate) async fn http_get_json_via_server(port: u16, path: &str) -> serde_json::Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn split_http_response(raw: &[u8]) -> (&[u8], &[u8]) {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                return (&raw[..pos], &raw[pos + 4..]);
            }
            if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
                return (&raw[..pos], &raw[pos + 2..]);
            }
            panic!("http body split");
        }

        fn decode_chunked_body(body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            let mut cursor = body;
            loop {
                let Some(line_end) = cursor.windows(2).position(|w| w == b"\r\n") else {
                    panic!("chunk header terminator missing");
                };
                let size_line = std::str::from_utf8(&cursor[..line_end])
                    .expect("chunk header utf8")
                    .split(';')
                    .next()
                    .expect("chunk size token")
                    .trim();
                let size = usize::from_str_radix(size_line, 16).expect("chunk size hex");
                cursor = &cursor[line_end + 2..];
                if size == 0 {
                    return out;
                }
                assert!(cursor.len() >= size + 2, "chunk payload truncated");
                out.extend_from_slice(&cursor[..size]);
                assert_eq!(&cursor[size..size + 2], b"\r\n", "chunk trailer missing");
                cursor = &cursor[size + 2..];
            }
        }

        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect test server");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            path, port
        );
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        let (headers_raw, body_raw) = split_http_response(&buf);
        let headers = String::from_utf8(headers_raw.to_vec()).expect("utf8 headers");
        let body = if headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            decode_chunked_body(body_raw)
        } else {
            body_raw.to_vec()
        };
        serde_json::from_slice(&body).expect("json body")
    }

    pub(crate) async fn http_post_json_via_server(
        port: u16,
        path: &str,
        body: &serde_json::Value,
    ) -> (warp::http::StatusCode, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn split_http_response(raw: &[u8]) -> (&[u8], &[u8]) {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                return (&raw[..pos], &raw[pos + 4..]);
            }
            if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
                return (&raw[..pos], &raw[pos + 2..]);
            }
            panic!("http body split");
        }

        fn decode_chunked_body(body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            let mut cursor = body;
            loop {
                let Some(line_end) = cursor.windows(2).position(|w| w == b"\r\n") else {
                    panic!("chunk header terminator missing");
                };
                let size_line = std::str::from_utf8(&cursor[..line_end])
                    .expect("chunk header utf8")
                    .split(';')
                    .next()
                    .expect("chunk size token")
                    .trim();
                let size = usize::from_str_radix(size_line, 16).expect("chunk size hex");
                cursor = &cursor[line_end + 2..];
                if size == 0 {
                    return out;
                }
                assert!(cursor.len() >= size + 2, "chunk payload truncated");
                out.extend_from_slice(&cursor[..size]);
                assert_eq!(&cursor[size..size + 2], b"\r\n", "chunk trailer missing");
                cursor = &cursor[size + 2..];
            }
        }

        let body_bytes = serde_json::to_vec(body).expect("json body encode");
        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect test server");
        let req_head = format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            port,
            body_bytes.len()
        );
        stream
            .write_all(req_head.as_bytes())
            .await
            .expect("write request head");
        stream
            .write_all(&body_bytes)
            .await
            .expect("write request body");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        let (headers_raw, body_raw) = split_http_response(&buf);
        let headers = String::from_utf8(headers_raw.to_vec()).expect("utf8 headers");
        let status_line = headers.lines().next().expect("http status line");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .and_then(|v| warp::http::StatusCode::from_u16(v).ok())
            .expect("status code");
        let body = if headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            decode_chunked_body(body_raw)
        } else {
            body_raw.to_vec()
        };
        let json = serde_json::from_slice(&body).expect("json body");
        (status_code, json)
    }

    pub(crate) async fn wait_for_server_ready(port: u16, path: &str) {
        for _ in 0..80u32 {
            match tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await {
                Ok(_) => {
                    let _ = http_get_json_via_server(port, path).await;
                    return;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        panic!("test api server did not become ready on port {}", port);
    }

    fn test_governance_with_validator(pub_key: &str) -> crate::governance::GovernanceState {
        crate::governance::GovernanceState::new(
            crate::governance::Council {
                members: vec!["protocol_member".to_string()],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["economy_member".to_string()],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["emergency_member".to_string()],
                threshold: 1,
            },
            crate::governance::GovernanceParams {
                min_timelock_blocks: 0,
                max_proposal_lifetime_blocks: 100_000,
                max_emergency_duration_blocks: 0,
                wallet_reputation_promotion_quorum: 2,
                e2_worker_admission_activation_height: 0,
                validator_compute_transition_min_active_validators: 2,
                validator_compute_transition_min_finality_quorum: 2,
                validator_compute_transition_validator_quality_floor: 600,
                validator_compute_transition_exit_cooldown_blocks: 10,
                validator_compute_transition_max_finality_lag_blocks: 2,
                validator_compute_transition_max_recent_missed_slots: 3,
                ft_activation_height: u64::MAX,
                ft_max_tokens_per_owner: 0,
                ft_create_cooldown_blocks: 0,
                ft_create_fee_native: 0,
                nft_activation_height: u64::MAX,
                nft_max_collections_per_owner: 0,
                nft_create_cooldown_blocks: 0,
                nft_create_fee_native: 0,
                nft_enabled: false,
                nft_public_create_enabled: false,
                nft_public_mint_enabled: false,
                nft_public_transfer_enabled: false,
                nft_public_approval_enabled: false,
                nft_public_burn_enabled: false,
                nft_public_revoke_enabled: false,
                nft_public_metadata_update_enabled: false,
                nft_public_freeze_enabled: false,
                nft_public_policy_update_enabled: false,
                nft_public_issuer_update_enabled: false,
                nft_public_pause_enabled: false,
                nft_metadata_hash_required: true,
                nft_max_memo_bytes: crate::nft::NFTV1_MEMO_MAX_BYTES as u32,
                nft_max_uri_bytes: crate::nft::NFTV1_URI_MAX_BYTES as u32,
                nft_max_name_bytes: crate::nft::NFTV1_NAME_MAX_BYTES as u32,
                nft_max_symbol_bytes: crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32,
                nft_max_tokens_per_collection: 0,
                nft_max_tokens_per_owner: 0,
                nft_mint_fee_native: 0,
                nft_transfer_fee_native: 0,
                nft_approval_fee_native: 0,
                nft_burn_fee_native: 0,
                nft_revoke_fee_native: 0,
                nft_metadata_update_fee_native: 0,
                nft_freeze_fee_native: 0,
                nft_policy_update_fee_native: 0,
                nft_issuer_update_fee_native: 0,
                nft_pause_fee_native: 0,
            },
            crate::governance::ValidatorSet {
                entries: vec![crate::governance::ValidatorEntry {
                    pub_key: pub_key.to_string(),
                    weight: 1,
                    alias: Some(pub_key.to_string()),
                }],
                version: 1,
            },
        )
    }

    fn build_status_view_state_root(storage: &Arc<DbStore>, committee: &[(String, u64)]) -> String {
        let smt = crate::state_smt::StateSmt::new(storage.state_node_store());
        let mut root = smt.empty_root();

        let params = crate::staking::PosParamsV1 {
            min_stake: 1,
            unbonding_epochs: 1,
            epoch_len: 100,
            committee_size: committee.len() as u64,
        };
        root = smt
            .update_account(
                root,
                crate::staking::k_stake_params(),
                crate::staking::encode_params_state(&params).unwrap(),
            )
            .unwrap();

        let seed = [11u8; 32];
        root = smt
            .update_account(
                root,
                crate::pos::k_seed(0),
                crate::pos::encode_seed_state(&seed).unwrap(),
            )
            .unwrap();

        let committee_state = crate::pos::CommitteeV2 {
            members: committee
                .iter()
                .map(|(pk, stake)| crate::pos::CommitteeMemberV2 {
                    pk_hex: pk.clone(),
                    stake: *stake,
                })
                .collect(),
        };
        root = smt
            .update_account(
                root,
                crate::pos::k_committee(0),
                crate::pos::encode_committee_state_v2(&committee_state).unwrap(),
            )
            .unwrap();

        for (idx, (pk, stake)) in committee.iter().enumerate() {
            let rec = crate::staking::ValidatorRecordV1 {
                owner: format!("owner-{}", idx),
                consensus_pubkey_b64: pk.clone(),
                net_addr: String::new(),
                commission_bps: 0,
                status: crate::staking::ValidatorStatusV1::Active,
                bonded: *stake,
                jailed_until_epoch: 0,
                metadata: String::new(),
            };
            root = smt
                .update_account(
                    root,
                    crate::staking::k_validator(pk),
                    crate::staking::encode_validator_state(&rec).unwrap(),
                )
                .unwrap();
        }

        hex::encode(root)
    }

    fn test_governance_with_validators(
        validators: &[(String, u32)],
    ) -> crate::governance::GovernanceState {
        crate::governance::GovernanceState::new(
            crate::governance::Council {
                members: vec!["protocol_member".to_string()],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["economy_member".to_string()],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["emergency_member".to_string()],
                threshold: 1,
            },
            crate::governance::GovernanceParams {
                min_timelock_blocks: 0,
                max_proposal_lifetime_blocks: 100_000,
                max_emergency_duration_blocks: 0,
                wallet_reputation_promotion_quorum: 2,
                e2_worker_admission_activation_height: 0,
                validator_compute_transition_min_active_validators: 2,
                validator_compute_transition_min_finality_quorum: 2,
                validator_compute_transition_validator_quality_floor: 600,
                validator_compute_transition_exit_cooldown_blocks: 10,
                validator_compute_transition_max_finality_lag_blocks: 2,
                validator_compute_transition_max_recent_missed_slots: 3,
                ft_activation_height: u64::MAX,
                ft_max_tokens_per_owner: 0,
                ft_create_cooldown_blocks: 0,
                ft_create_fee_native: 0,
                nft_activation_height: u64::MAX,
                nft_max_collections_per_owner: 0,
                nft_create_cooldown_blocks: 0,
                nft_create_fee_native: 0,
                nft_enabled: false,
                nft_public_create_enabled: false,
                nft_public_mint_enabled: false,
                nft_public_transfer_enabled: false,
                nft_public_approval_enabled: false,
                nft_public_burn_enabled: false,
                nft_public_revoke_enabled: false,
                nft_public_metadata_update_enabled: false,
                nft_public_freeze_enabled: false,
                nft_public_policy_update_enabled: false,
                nft_public_issuer_update_enabled: false,
                nft_public_pause_enabled: false,
                nft_metadata_hash_required: true,
                nft_max_memo_bytes: crate::nft::NFTV1_MEMO_MAX_BYTES as u32,
                nft_max_uri_bytes: crate::nft::NFTV1_URI_MAX_BYTES as u32,
                nft_max_name_bytes: crate::nft::NFTV1_NAME_MAX_BYTES as u32,
                nft_max_symbol_bytes: crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32,
                nft_max_tokens_per_collection: 0,
                nft_max_tokens_per_owner: 0,
                nft_mint_fee_native: 0,
                nft_transfer_fee_native: 0,
                nft_approval_fee_native: 0,
                nft_burn_fee_native: 0,
                nft_revoke_fee_native: 0,
                nft_metadata_update_fee_native: 0,
                nft_freeze_fee_native: 0,
                nft_policy_update_fee_native: 0,
                nft_issuer_update_fee_native: 0,
                nft_pause_fee_native: 0,
            },
            crate::governance::ValidatorSet {
                entries: validators
                    .iter()
                    .map(|(pub_key, weight)| crate::governance::ValidatorEntry {
                        pub_key: pub_key.clone(),
                        weight: *weight,
                        alias: Some(pub_key.clone()),
                    })
                    .collect(),
                version: 1,
            },
        )
    }

    fn mk_wallet_rep_pending_state(
        pending_wallet_evidence: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
            "peers": [],
            "wallet_bindings": [],
            "pending_wallet_evidence": pending_wallet_evidence,
        })
    }

    fn seed_chain_pending_wallet_evidence_from_json(
        chain: &Arc<Mutex<Blockchain>>,
        label: &str,
        state: serde_json::Value,
    ) {
        let path = std::env::temp_dir().join(format!(
            "newgen-wallet-rep-api-test-{}-{}.json",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let rep = crate::peer_reputation::PeerReputationManager::new(
            crate::peer_reputation::ReputationConfig {
                persist_path: path.to_string_lossy().into_owned(),
                ..crate::peer_reputation::ReputationConfig::default()
            },
        );
        let mut bc = chain.lock().unwrap();
        bc.reputation = Some(Arc::new(Mutex::new(rep)));
    }

    fn test_governance_with_protocol_member_and_attesters(
        protocol_member: String,
        attesters: Vec<String>,
    ) -> crate::governance::GovernanceState {
        crate::governance::GovernanceState::new(
            crate::governance::Council {
                members: vec![protocol_member],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["economy_member".to_string()],
                threshold: 1,
            },
            crate::governance::Council {
                members: vec!["emergency_member".to_string()],
                threshold: 1,
            },
            crate::governance::GovernanceParams {
                min_timelock_blocks: 0,
                max_proposal_lifetime_blocks: 100_000,
                max_emergency_duration_blocks: 0,
                wallet_reputation_promotion_quorum: 2,
                e2_worker_admission_activation_height: 0,
                validator_compute_transition_min_active_validators: 2,
                validator_compute_transition_min_finality_quorum: 2,
                validator_compute_transition_validator_quality_floor: 600,
                validator_compute_transition_exit_cooldown_blocks: 10,
                validator_compute_transition_max_finality_lag_blocks: 2,
                validator_compute_transition_max_recent_missed_slots: 3,
                ft_activation_height: u64::MAX,
                ft_max_tokens_per_owner: 0,
                ft_create_cooldown_blocks: 0,
                ft_create_fee_native: 0,
                nft_activation_height: u64::MAX,
                nft_max_collections_per_owner: 0,
                nft_create_cooldown_blocks: 0,
                nft_create_fee_native: 0,
                nft_enabled: false,
                nft_public_create_enabled: false,
                nft_public_mint_enabled: false,
                nft_public_transfer_enabled: false,
                nft_public_approval_enabled: false,
                nft_public_burn_enabled: false,
                nft_public_revoke_enabled: false,
                nft_public_metadata_update_enabled: false,
                nft_public_freeze_enabled: false,
                nft_public_policy_update_enabled: false,
                nft_public_issuer_update_enabled: false,
                nft_public_pause_enabled: false,
                nft_metadata_hash_required: true,
                nft_max_memo_bytes: crate::nft::NFTV1_MEMO_MAX_BYTES as u32,
                nft_max_uri_bytes: crate::nft::NFTV1_URI_MAX_BYTES as u32,
                nft_max_name_bytes: crate::nft::NFTV1_NAME_MAX_BYTES as u32,
                nft_max_symbol_bytes: crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32,
                nft_max_tokens_per_collection: 0,
                nft_max_tokens_per_owner: 0,
                nft_mint_fee_native: 0,
                nft_transfer_fee_native: 0,
                nft_approval_fee_native: 0,
                nft_burn_fee_native: 0,
                nft_revoke_fee_native: 0,
                nft_metadata_update_fee_native: 0,
                nft_freeze_fee_native: 0,
                nft_policy_update_fee_native: 0,
                nft_issuer_update_fee_native: 0,
                nft_pause_fee_native: 0,
            },
            crate::governance::ValidatorSet {
                entries: attesters
                    .into_iter()
                    .map(|pub_key| crate::governance::ValidatorEntry {
                        alias: Some(pub_key.clone()),
                        pub_key,
                        weight: 1,
                    })
                    .collect(),
                version: 1,
            },
        )
    }

    fn wallet_reputation_surface_for_test(
        admin_token: &str,
        validator_sk: Arc<SigningKey>,
        validator_pk: String,
        chain: Arc<Mutex<Blockchain>>,
    ) -> warp::filters::BoxedFilter<(warp::reply::Response,)> {
        let admin = Arc::new(AdminConfig {
            admin_token: Some(admin_token.to_string()),
        });
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel();
        build_reputation_bridge_route(chain.clone())
            .or(build_gov_wallet_reputation_ingest_run_route(
                admin,
                validator_sk,
                validator_pk,
                chain,
                mempool,
                tx_p2p,
            ))
            .unify()
            .boxed()
    }

    fn wallet_reputation_bridge_route_for_test(
        chain: Arc<Mutex<Blockchain>>,
    ) -> warp::filters::BoxedFilter<(warp::reply::Response,)> {
        let validator_sk = Arc::new(SigningKey::from_bytes(&[250u8; 32]));
        let validator_pk = hex::encode(validator_sk.verifying_key().to_bytes());
        wallet_reputation_surface_for_test("admin-token", validator_sk, validator_pk, chain)
    }

    fn wallet_reputation_ingest_run_route_for_test(
        admin_token: &str,
        validator_sk: Arc<SigningKey>,
        validator_pk: String,
        chain: Arc<Mutex<Blockchain>>,
    ) -> warp::filters::BoxedFilter<(warp::reply::Response,)> {
        wallet_reputation_surface_for_test(admin_token, validator_sk, validator_pk, chain)
    }

    fn enable_test_bft_finality(bc: &mut Blockchain) {
        bc.slot_pacing.slot_pacing_enabled = true;
        bc.slot_pacing.pos_finality_bft_activation_epoch = 0;
        if let Some(last) = bc.chain.last_mut() {
            last.pos_epoch = 0;
        }
    }

    fn seed_pruned_unresolved_finalized_checkpoint(
        bc: &mut Blockchain,
        finalized_height: u64,
        tip_height: u64,
    ) {
        assert!(tip_height > finalized_height);
        let mut tip = crate::block::Block::default();
        tip.index = tip_height;
        tip.hash = format!("{:064x}", tip_height);
        tip.previous_hash = String::new();
        tip.pos_epoch = 0;
        bc.chain = vec![tip];
        bc.base_height = tip_height;
        enable_test_bft_finality(bc);
        bc.set_test_finality_meta(
            finalized_height,
            String::new(),
            tip_height,
            0,
            String::new(),
        );
    }

    #[test]
    fn wallet_balance_route_surfaces_typed_internal_error_on_poisoned_chain_lock() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let poisoned = chain.clone();
            let join = std::thread::spawn(move || {
                let _guard = poisoned.lock().unwrap();
                panic!("intentional poison");
            })
            .join();
            assert!(join.is_err());
            assert!(chain.lock().is_err());

            let route = get_v2_wallet_balance_route(chain).recover(error_handler);
            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/wallet/balance/ALICE")
                .reply(&route)
                .await;

            assert_eq!(resp.status(), warp::http::StatusCode::INTERNAL_SERVER_ERROR);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "error");
            assert_eq!(body["message"], "chain_lock_poisoned");
        });
    }

    #[test]
    fn next_nonce_routes_canonical_and_legacy_alias_match() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let mempool = Arc::new(Mutex::new(Mempool::new()));

            let canonical = warp::path!("api" / "v2" / "wallet" / "next_nonce" / String)
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .and(with_mempool(mempool.clone()))
                .map(next_nonce_handler);

            let legacy = warp::path!("api" / "v2" / "tx" / "get_next_nonce" / String)
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .and(with_mempool(mempool.clone()))
                .map(next_nonce_handler);

            let canonical_resp = warp::test::request()
                .method("GET")
                .path("/api/v2/wallet/next_nonce/ALICE")
                .reply(&canonical)
                .await;

            let legacy_resp = warp::test::request()
                .method("GET")
                .path("/api/v2/tx/get_next_nonce/ALICE")
                .reply(&legacy)
                .await;

            assert_eq!(canonical_resp.status(), warp::http::StatusCode::OK);
            assert_eq!(legacy_resp.status(), warp::http::StatusCode::OK);

            let canonical_json: serde_json::Value =
                serde_json::from_slice(canonical_resp.body()).unwrap();
            let legacy_json: serde_json::Value =
                serde_json::from_slice(legacy_resp.body()).unwrap();

            assert_eq!(canonical_json, legacy_json);
            assert_eq!(canonical_json["address"], "ALICE");
            assert_eq!(canonical_json["next_nonce"], 1);
        });
    }

    #[test]
    fn tx_by_hash_routes_canonical_and_legacy_alias_match_on_not_found() {
        run_async_test(async {
            let storage = open_empty_test_storage();

            let canonical = warp::path!("api" / "v2" / "tx" / "by-hash" / String)
                .and(warp::get())
                .and(with_storage(storage.clone()))
                .and_then(tx_by_hash_handler);

            let legacy = warp::path!("api" / "v2" / "tx" / "by_hash" / String)
                .and(warp::get())
                .and(with_storage(storage.clone()))
                .and_then(tx_by_hash_handler);

            let canonical_resp = warp::test::request()
                .method("GET")
                .path("/api/v2/tx/by-hash/deadbeef")
                .reply(&canonical)
                .await;

            let legacy_resp = warp::test::request()
                .method("GET")
                .path("/api/v2/tx/by_hash/deadbeef")
                .reply(&legacy)
                .await;

            assert_eq!(canonical_resp.status(), warp::http::StatusCode::NOT_FOUND);
            assert_eq!(legacy_resp.status(), warp::http::StatusCode::NOT_FOUND);

            let canonical_json: serde_json::Value =
                serde_json::from_slice(canonical_resp.body()).unwrap();
            let legacy_json: serde_json::Value =
                serde_json::from_slice(legacy_resp.body()).unwrap();

            assert_eq!(canonical_json, legacy_json);
            assert_eq!(canonical_json["status"], "not_found");
            assert_eq!(canonical_json["hash"], "deadbeef");
        });
    }

    #[test]
    fn apply_common_headers_treats_tx_by_hash_alias_as_cacheable_get() {
        let mut canonical = warp::reply::reply().into_response();
        apply_common_headers(
            "/api/v2/tx/by-hash/deadbeef",
            &warp::http::Method::GET,
            &mut canonical,
        );

        let mut legacy = warp::reply::reply().into_response();
        apply_common_headers(
            "/api/v2/tx/by_hash/deadbeef",
            &warp::http::Method::GET,
            &mut legacy,
        );

        let canonical_cache = canonical.headers().get("cache-control").unwrap();
        let legacy_cache = legacy.headers().get("cache-control").unwrap();

        assert_eq!(canonical_cache, "public, max-age=60");
        assert_eq!(legacy_cache, canonical_cache);
    }

    #[test]
    fn cognitive_registry_status_route_returns_reconciliation_context() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let object_hash = "11".repeat(32);
            let claim_hash = "22".repeat(32);
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());
                let entry = crate::cognitive_chain::CognitiveRegistryEntryV1 {
                    object_hash_hex: object_hash.clone(),
                    claim_hash_hex: claim_hash.clone(),
                    lifecycle_state:
                        crate::cognitive_chain::CognitiveRegistryLifecycleStateV1::Active,
                    policy_id: "policy-a".to_string(),
                    anchor_height: 0,
                    anchor_block_hash: "33".repeat(32),
                    evidence_root_hex: "44".repeat(32),
                    context_hash_hex: "55".repeat(32),
                    model_manifest_hash_hex: "66".repeat(32),
                    supersedes: None,
                    superseded_by: None,
                    dispute_ref: None,
                    revoke_ref: None,
                    updated_at_height: 0,
                };
                storage.cognitive_registry_put_entry(&entry).unwrap();
                storage
                    .cognitive_registry_put_claim_index(&claim_hash, &vec![object_hash.clone()])
                    .unwrap();
                storage
                    .cognitive_registry_set_last_applied_height(0)
                    .unwrap();
                storage.cognitive_registry_set_last_event_seq(1).unwrap();
            }

            let route = warp::path!("api" / "v2" / "cognitive" / "registry" / "status" / String)
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|object_hash: String, ch: SharedChain| {
                    if let Err(e) = validate_sha256_hex_field("object_hash", &object_hash) {
                        return warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                                warp::http::StatusCode::BAD_REQUEST,
                            ),
                            "Cache-Control",
                            "no-store",
                        );
                    }
                    let bc = lock_any!(ch);
                    match bc.get_cognitive_registry_status_view_by_object_hash_v1(&object_hash) {
                        Ok(Some(view)) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"ok","view":view})),
                                warp::http::StatusCode::OK,
                            ),
                            "Cache-Control",
                            "no-store",
                        ),
                        Ok(None) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"not_found","object_hash":object_hash})),
                                warp::http::StatusCode::NOT_FOUND,
                            ),
                            "Cache-Control",
                            "no-store",
                        ),
                        Err(e) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            ),
                            "Cache-Control",
                            "no-store",
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path(&format!(
                    "/api/v2/cognitive/registry/status/{}",
                    object_hash
                ))
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["view"]["object_hash_hex"], object_hash);
            assert_eq!(body["view"]["claim_hash_hex"], claim_hash);
            assert_eq!(
                body["view"]["reconciliation_context"]["registry_last_event_seq"],
                1
            );
            assert!(body["view"]["reconciliation_context"]["chain_id"].is_string());
        });
    }

    #[test]
    fn cognitive_registry_meta_route_returns_registry_progress() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());
                storage
                    .cognitive_registry_set_last_applied_height(7)
                    .unwrap();
                storage.cognitive_registry_set_last_event_seq(19).unwrap();
            }
            let route = warp::path!("api" / "v2" / "cognitive" / "registry" / "meta")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let bc = lock_any!(ch);
                    match bc.cognitive_registry_meta_view_v1() {
                        Ok(view) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"status":"ok","view":view})),
                                warp::http::StatusCode::OK,
                            ),
                            "Cache-Control",
                            "no-store",
                        ),
                        Err(e) => warp::reply::with_header(
                            warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"status":"error","message":e}),
                                ),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            ),
                            "Cache-Control",
                            "no-store",
                        ),
                    }
                });
            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/cognitive/registry/meta")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["view"]["registry_last_applied_height"], 7);
            assert_eq!(body["view"]["registry_last_event_seq"], 19);
            assert!(body["view"]["finalized_hash"].is_string());
        });
    }

    #[test]
    fn cognitive_contract_route_exposes_snapshot_and_format_version() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let route = warp::path!("api" / "v2" / "cognitive" / "contract")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let bc = lock_any!(ch);
                    match bc.cognitive_contract_snapshot_v1() {
                        Ok(view) => match validate_api_cognitive_contract_snapshot_v1(&view) {
                            Ok(()) => warp::reply::with_header(
                                warp::reply::with_status(
                                    warp::reply::json(&CognitiveViewEnvelopeV1 {
                                        status: "ok",
                                        format_version: view.format_version,
                                        view,
                                    }),
                                    warp::http::StatusCode::OK,
                                ),
                                "Cache-Control",
                                "no-store",
                            )
                            .into_response(),
                            Err(e) => cognitive_api_error_reply_v1(
                                e,
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            ),
                        },
                        Err(e) => cognitive_api_error_reply_v1(
                            e,
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/cognitive/contract")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(
                body["format_version"],
                COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
            );
            assert_eq!(
                body["view"]["format_version"],
                COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
            );
            assert!(body["view"]["registry_features"].as_array().unwrap().len() >= 1);
            assert!(
                body["view"]["finality_binding_rules"]
                    .as_array()
                    .unwrap()
                    .len()
                    >= 1
            );
        });
    }

    #[test]
    fn consensus_finality_route_v2_exposes_contractual_view_wrapper() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let route = warp::path!("api" / "v2" / "consensus" / "finality")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let view = {
                        let bc = lock_any!(ch);
                        bc.cognitive_consensus_finality_view_v1()
                    };
                    match view {
                        Ok(view) => {
                            match validate_api_cognitive_consensus_finality_view_v1(&view) {
                                Ok(()) => {
                                    let hash_ready = view.finalized_height == 0
                                        || !view.finalized_hash.trim().is_empty();
                                    let status = if hash_ready {
                                        warp::http::StatusCode::OK
                                    } else {
                                        warp::http::StatusCode::SERVICE_UNAVAILABLE
                                    };
                                    warp::reply::with_header(
                                        warp::reply::with_status(
                                            warp::reply::json(
                                                &CognitiveConsensusFinalityEnvelopeV2 {
                                                    status: if hash_ready {
                                                        "ok"
                                                    } else {
                                                        "degraded"
                                                    },
                                                    format_version: view.format_version,
                                                    view,
                                                    e2_ready: hash_ready,
                                                    unavailable_reason: if hash_ready {
                                                        None
                                                    } else {
                                                        Some(
                                                            "finalized_hash_unavailable"
                                                                .to_string(),
                                                        )
                                                    },
                                                },
                                            ),
                                            status,
                                        ),
                                        "Cache-Control",
                                        "no-store",
                                    )
                                    .into_response()
                                }
                                Err(e) => cognitive_api_error_reply_v1(
                                    e,
                                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                                ),
                            }
                        }
                        Err(e) => cognitive_api_error_reply_v1(
                            e,
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/consensus/finality")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(
                body["format_version"],
                COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
            );
            assert_eq!(
                body["view"]["format_version"],
                COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
            );
            assert!(body["view"]["tip_height"].is_u64());
            assert!(body["view"]["finalized_height"].is_u64());
            assert_eq!(body["e2_ready"], true);
        });
    }

    #[test]
    fn e2_contract_route_exposes_minimum_contract_surface() {
        run_async_test(async {
            let route = warp::path!("api" / "v2" / "e2" / "contract")
                .and(warp::get())
                .map(|| {
                    let snap = E2ContractSnapshotV1::current();
                    warp::reply::with_header(
                        warp::reply::json(&serde_json::json!({"status":"ok","contract":snap})),
                        "Cache-Control",
                        "no-store",
                    )
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/e2/contract")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(
                body["contract"]["e2_contract_version"],
                crate::version::E2_CONTRACT_VERSION
            );
            assert_eq!(
                body["contract"]["reputation_score_scale"],
                crate::reputation_score::REPUTATION_SCORE_SCALE_V1
            );
            assert_eq!(
                body["contract"]["reputation_score_max"],
                crate::reputation_score::REPUTATION_SCORE_MAX_V1
            );
            assert_eq!(
                body["contract"]["worker_penalty_taxonomy"],
                crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1
            );
            assert_eq!(
                body["contract"]["node_reputation_score_formula_version"],
                crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1
            );
            assert_eq!(
                body["contract"]["wallet_reputation_score_formula_version"],
                crate::reputation_score::WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1
            );
            assert_eq!(
                body["contract"]["worker_eligibility_policy_version"],
                crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1
            );
            assert_eq!(
                body["contract"]["capabilities"]["compute_orders_canonical"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["compute_order_event_feed_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["block_by_height_prune_safe_v1"],
                true
            );
            assert_eq!(body["contract"]["capabilities"]["fee_params_v1"], true);
            assert_eq!(
                body["contract"]["capabilities"]["wallet_next_nonce_v1"],
                true
            );
            assert_eq!(body["contract"]["capabilities"]["signed_tx_relay_v1"], true);
            assert_eq!(
                body["contract"]["capabilities"]["e2_worker_reputation_evidence_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["e2_worker_standard_evidence_tx_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["e2_worker_bootstrap_probe_contract_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["e2_worker_governed_evidence_ingest_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["e2_worker_self_registration_v1"],
                true
            );
            assert_eq!(
                body["contract"]["capabilities"]["canonical_worker_eligibility_v1"],
                true
            );
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("canonical_worker_eligibility_v1")));
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("e2_worker_reputation_evidence_v1")));
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("e2_worker_standard_evidence_tx_v1")));
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("e2_worker_bootstrap_probe_contract_v1")));
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("e2_worker_governed_evidence_ingest_v1")));
            assert!(body["contract"]["supported_capabilities"]
                .as_array()
                .expect("supported_capabilities array")
                .iter()
                .any(|v| v.as_str() == Some("e2_worker_self_registration_v1")));
            assert_eq!(body["contract"]["canonical_paths"]["fee_params"], "/status");
            assert_eq!(
                body["contract"]["canonical_paths"]["wallet_next_nonce"],
                "/api/v2/wallet/next_nonce/{address}"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["tx_submit_signed"],
                "/api/v2/tx/submit_signed"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_orders"],
                "/api/v2/e2/orders"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_order_by_id"],
                "/api/v2/e2/orders/{order_id}"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_order_events"],
                "/api/v2/e2/order-events"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_reputation_evidence"],
                "/api/v2/e2/worker/evidence/build_unsigned"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_standard_evidence_build_unsigned"],
                "/api/v2/e2/worker/evidence/build_unsigned"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_standard_evidence_submit"],
                "/api/v2/tx/submit_signed"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_bootstrap_probe_contract"],
                "/api/v2/e2/worker/evidence/bootstrap_probe/contract"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_governed_evidence_ingest"],
                "/api/v2/reputation/e2/worker/evidence"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_self_registration"],
                "/api/v2/e2/worker/register/build_unsigned"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_self_registration_build_unsigned"],
                "/api/v2/e2/worker/register/build_unsigned"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["e2_worker_self_registration_submit"],
                "/api/v2/tx/submit_signed"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["canonical_worker_eligibility"],
                "/api/v2/reputation/canonical/workers"
            );
            assert_eq!(
                body["contract"]["canonical_paths"]["canonical_worker_eligibility_by_worker"],
                "/api/v2/reputation/canonical/workers/{worker_node_pubkey}/eligibility"
            );
        });
    }

    #[test]
    fn e2_orders_lookup_route_returns_not_found_when_order_missing() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let route = warp::path!("api" / "v2" / "e2" / "orders" / String)
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|order_id: String, ch: SharedChain| {
                    let result = {
                        let bc = lock_any!(ch);
                        compute_order_lookup_v2_for_finalized_chain(&bc, &order_id)
                    };
                    match result {
                        Ok(lookup) if lookup.found => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"ok","lookup":lookup})),
                            warp::http::StatusCode::OK,
                        ),
                        Ok(lookup) => warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"status":"not_found","lookup":lookup}),
                            ),
                            warp::http::StatusCode::NOT_FOUND,
                        ),
                        Err(e) => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/e2/orders/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::NOT_FOUND);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "not_found");
            assert_eq!(body["lookup"]["found"], false);
        });
    }

    #[test]
    fn e2_order_events_route_rejects_invalid_range() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let route = warp::path!("api" / "v2" / "e2" / "order-events")
                .and(warp::get())
                .and(warp::query::<E2OrderEventsQuery>())
                .and(with_chain(chain.clone()))
                .map(|query: E2OrderEventsQuery, ch: SharedChain| {
                    let result = {
                        let bc = lock_any!(ch);
                        let (finalized_height, _) = bc.finalized_view();
                        let from_height = query.from_height.unwrap_or(0);
                        let to_height = query.to_height.unwrap_or(finalized_height);
                        compute_order_events_snapshot_for_finalized_chain(
                            &bc,
                            from_height,
                            to_height,
                        )
                    };
                    match result {
                        Ok(snapshot) => warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"status":"ok","snapshot":snapshot}),
                            ),
                            warp::http::StatusCode::OK,
                        ),
                        Err(e) if e.starts_with("invalid_range:") => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ),
                        Err(e) => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/e2/order-events?from_height=9&to_height=1")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn e2_order_events_route_returns_events_snapshot() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());

                let mut b1 = crate::block::Block::default();
                b1.index = 1;
                b1.hash = "11".repeat(32);
                b1.previous_hash = "00".repeat(32);
                let create = crate::transaction::Transaction::new(
                    "payer-a".to_string(),
                    "COMPUTE".to_string(),
                    10,
                    1,
                    0,
                    "sig".to_string(),
                    false,
                    Some(r#"{"v":1,"op":"order_create","job_spec_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_time_ms":1000,"job_kind":"hash_sha256_v1"}"#.to_string()),
                );
                let order_id = create.hash.clone();
                b1.transactions = vec![create.clone()];
                storage.append_block(&b1).unwrap();

                let mut b2 = crate::block::Block::default();
                b2.index = 2;
                b2.hash = "22".repeat(32);
                b2.previous_hash = b1.hash.clone();
                let claim = crate::transaction::Transaction::new(
                    "worker-a".to_string(),
                    "COMPUTE".to_string(),
                    0,
                    1,
                    1,
                    "sig".to_string(),
                    false,
                    Some(format!(
                        r#"{{"v":1,"op":"order_claim","order_id":"{}"}}"#,
                        order_id
                    )),
                );
                b2.transactions = vec![claim];
                storage.append_block(&b2).unwrap();

                let mut genesis = crate::block::Block::default();
                genesis.index = 0;
                genesis.hash = "00".repeat(32);
                bc.chain = vec![genesis, b1.clone(), b2.clone()];
                bc.base_height = 0;
                enable_test_bft_finality(&mut bc);
                bc.set_test_finality_meta(2, b2.hash.clone(), 2, 0, String::new());
            }

            let route = warp::path!("api" / "v2" / "e2" / "order-events")
                .and(warp::get())
                .and(warp::query::<E2OrderEventsQuery>())
                .and(with_chain(chain.clone()))
                .map(|query: E2OrderEventsQuery, ch: SharedChain| {
                    let result = {
                        let bc = lock_any!(ch);
                        let (finalized_height, _) = bc.finalized_view();
                        let from_height = query.from_height.unwrap_or(0);
                        let to_height = query.to_height.unwrap_or(finalized_height);
                        compute_order_events_snapshot_for_finalized_chain(
                            &bc,
                            from_height,
                            to_height,
                        )
                    };
                    match result {
                        Ok(snapshot) => warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"status":"ok","snapshot":snapshot}),
                            ),
                            warp::http::StatusCode::OK,
                        ),
                        Err(e) if e.starts_with("invalid_range:") => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ),
                        Err(e) => warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"status":"error","message":e})),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/e2/order-events?from_height=1&to_height=2")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["snapshot"]["events"].as_array().unwrap().len(), 2);
        });
    }

    #[test]
    fn governance_validators_status_route_exposes_local_runtime_without_contaminating_peer_rows() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let seed_a = [0x31u8; 32];
            let seed_b = [0x32u8; 32];
            let a = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&seed_a)
                    .verifying_key()
                    .to_bytes(),
            );
            let b = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&seed_b)
                    .verifying_key()
                    .to_bytes(),
            );
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());

                let mut prev = crate::block::Block::default();
                prev.index = 3;
                prev.hash = "12".repeat(32);
                prev.previous_hash = "34".repeat(32);
                prev.state_root = "56".repeat(32);
                storage.append_block(&prev).unwrap();
                bc.chain = vec![prev.clone()];
                bc.base_height = 3;
                bc.governance = Some(test_governance_with_validators(&[
                    (a.clone(), 7),
                    (b.clone(), 5),
                ]));
                bc.policy.miner_sk_b64 = STANDARD.encode(seed_a);
                bc.set_runtime_bootstrap_complete(true);
                bc.set_runtime_sync_caught_up(false);
            }

            let route = warp::path!("api" / "v2" / "governance" / "validators" / "status")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let bc = lock_any!(ch);
                    let height = bc.chain.last().map(|b| b.index).unwrap_or(0u64);
                    let at_height = height.saturating_add(1);
                    let items = bc.governance_validator_status_views_for_next_block();
                    let local_runtime = bc.local_consensus_runtime_view_for_next_block();
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "height": height,
                        "at_height": at_height,
                        "local_runtime": local_runtime,
                        "items": items
                    }))
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/governance/validators/status")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["local_runtime"]["validator_pubkey"], a);
            assert_eq!(body["local_runtime"]["runtime_bootstrap_complete"], true);
            assert_eq!(body["local_runtime"]["runtime_sync_caught_up"], false);
            assert_eq!(body["local_runtime"]["consensus_ready"], false);
            assert_eq!(body["local_runtime"]["consensus_bootstrap_ready"], false);
            assert!(body["local_runtime"]
                .get("consensus_bootstrap_fault")
                .is_some());

            let items = body["items"].as_array().unwrap();
            let local_row = items.iter().find(|item| item["pub_key"] == a).unwrap();
            let peer_row = items.iter().find(|item| item["pub_key"] == b).unwrap();
            assert_eq!(local_row["local_validator"], true);
            assert_eq!(local_row["runtime_bootstrap_complete"], true);
            assert_eq!(local_row["runtime_sync_caught_up"], false);
            assert_eq!(local_row["consensus_ready"], false);
            assert_eq!(local_row["active"], false);
            assert!(peer_row.get("local_validator").is_none());
            assert!(peer_row.get("runtime_bootstrap_complete").is_none());
            assert!(peer_row.get("runtime_sync_caught_up").is_none());
            assert_eq!(peer_row["consensus_ready"], false);
            assert_eq!(peer_row["active"], false);
        });
    }

    #[test]
    fn governance_validators_status_route_overlays_remote_runtime_readiness_cluster_wide() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let seed_a = [0x51u8; 32];
            let seed_b = [0x52u8; 32];
            let a = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&seed_a)
                    .verifying_key()
                    .to_bytes(),
            );
            let b = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&seed_b)
                    .verifying_key()
                    .to_bytes(),
            );
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());

                let committee = vec![(a.clone(), 7u64), (b.clone(), 5u64)];
                let state_root = build_status_view_state_root(&storage, &committee);
                let mut prev = crate::block::Block::default();
                prev.index = 4;
                prev.hash = "ab".repeat(32);
                prev.previous_hash = "cd".repeat(32);
                prev.state_root = state_root;
                storage.append_block(&prev).unwrap();
                bc.chain = vec![prev.clone()];
                bc.base_height = 4;
                bc.governance = Some(test_governance_with_validators(&[
                    (a.clone(), 7),
                    (b.clone(), 5),
                ]));
                bc.policy.miner_sk_b64 = STANDARD.encode(seed_a);
                bc.set_proposal_gate_open(true);
                bc.set_p2p_ready_for_mining(true);
                bc.set_runtime_bootstrap_complete(true);
                bc.set_runtime_sync_caught_up(true);
                let vsh = bc.current_validator_set_hash_hex();
                assert!(bc.record_validator_runtime_observation(
                    &b,
                    false,
                    false,
                    false,
                    "peer-b",
                    &vsh,
                    4,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                ));
            }

            let route = warp::path!("api" / "v2" / "governance" / "validators" / "status")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let bc = lock_any!(ch);
                    let height = bc.chain.last().map(|b| b.index).unwrap_or(0u64);
                    let at_height = height.saturating_add(1);
                    let items = bc.governance_validator_status_views_for_next_block();
                    let local_runtime = bc.local_consensus_runtime_view_for_next_block();
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "height": height,
                        "at_height": at_height,
                        "local_runtime": local_runtime,
                        "items": items
                    }))
                });
            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/governance/validators/status")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            let items = body["items"].as_array().unwrap();
            let local_row = items.iter().find(|item| item["pub_key"] == a).unwrap();
            let remote_row = items.iter().find(|item| item["pub_key"] == b).unwrap();

            assert_eq!(local_row["runtime_readiness_observed"], true);
            assert_eq!(local_row["consensus_ready"], true);
            assert_eq!(local_row["active"], true);

            assert_eq!(remote_row["runtime_readiness_observed"], true);
            assert_eq!(remote_row["runtime_bootstrap_complete"], false);
            assert_eq!(remote_row["runtime_sync_caught_up"], false);
            assert_eq!(remote_row["consensus_ready"], false);
            assert_eq!(remote_row["active"], false);
        });
    }

    #[test]
    fn governance_validators_status_route_preserves_distinct_last_seen_height() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            let seed_a = [0x41u8; 32];
            let a = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&seed_a)
                    .verifying_key()
                    .to_bytes(),
            );
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());

                let mut prev = crate::block::Block::default();
                prev.index = 6;
                prev.hash = "ab".repeat(32);
                prev.previous_hash = "cd".repeat(32);
                prev.state_root = "ef".repeat(32);
                storage.append_block(&prev).unwrap();
                bc.chain = vec![prev.clone()];
                bc.base_height = 6;
                let mut gov = test_governance_with_validators(&[(a.clone(), 7)]);
                gov.validator_reputation.insert(
                    a.clone(),
                    crate::governance::ValidatorGovReputation {
                        last_produced_height: 15,
                        last_seen_height: 18,
                        ..crate::governance::ValidatorGovReputation::default()
                    },
                );
                bc.governance = Some(gov);
                bc.policy.miner_sk_b64 = STANDARD.encode(seed_a);
                bc.set_runtime_bootstrap_complete(true);
                bc.set_runtime_sync_caught_up(true);
            }

            let route = warp::path!("api" / "v2" / "governance" / "validators" / "status")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let bc = lock_any!(ch);
                    let height = bc.chain.last().map(|b| b.index).unwrap_or(0u64);
                    let at_height = height.saturating_add(1);
                    let items = bc.governance_validator_status_views_for_next_block();
                    let local_runtime = bc.local_consensus_runtime_view_for_next_block();
                    warp::reply::json(&serde_json::json!({
                        "status": "ok",
                        "height": height,
                        "at_height": at_height,
                        "local_runtime": local_runtime,
                        "items": items
                    }))
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/governance/validators/status")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            let items = body["items"].as_array().unwrap();
            let row = items.iter().find(|item| item["pub_key"] == a).unwrap();
            assert_eq!(row["last_produced_height"], serde_json::json!(15));
            assert_eq!(row["last_seen_height"], serde_json::json!(18));
        });
    }

    #[test]
    fn governance_validators_status_finalized_route_uses_finalized_anchor() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                let storage = open_empty_test_storage();
                bc.attach_storage(storage.clone());

                let mut prev = crate::block::Block::default();
                prev.index = 3;
                prev.hash = "12".repeat(32);
                prev.previous_hash = "34".repeat(32);
                prev.state_root = "56".repeat(32);
                storage.append_block(&prev).unwrap();
                bc.chain = vec![prev.clone()];
                bc.base_height = 3;
                enable_test_bft_finality(&mut bc);
                bc.set_test_finality_meta(3, String::new(), 4, 0, String::new());

                bc.governance = Some(test_governance_with_validator(&"aa".repeat(32)));
            }

            let route =
                warp::path!("api" / "v2" / "governance" / "validators" / "status" / "finalized")
                    .and(warp::get())
                    .and(with_chain(chain.clone()))
                    .map(|ch: SharedChain| {
                        let bc = lock_any!(ch);
                        let snap = bc.governance_validator_status_views_for_finalized_state();
                        let body = serde_json::json!({
                            "status": if snap.source_state_available { "ok" } else { "degraded" },
                            "finalized_height": snap.finalized_height,
                            "finalized_hash": snap.finalized_hash,
                            "at_height": snap.at_height,
                            "source_state_available": snap.source_state_available,
                            "unavailable_reason": snap.unavailable_reason,
                            "items": snap.items
                        });
                        let status = if snap.source_state_available {
                            warp::http::StatusCode::OK
                        } else {
                            warp::http::StatusCode::SERVICE_UNAVAILABLE
                        };
                        warp::reply::with_status(warp::reply::json(&body), status)
                    });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/governance/validators/status/finalized")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["source_state_available"], true);
            assert_eq!(body["finalized_height"], 3);
            assert_eq!(body["finalized_hash"], "12".repeat(32));
            assert_eq!(body["at_height"], 4);
            assert!(body.get("local_runtime").is_none());
            let first = body["items"].as_array().unwrap().first().unwrap();
            assert!(first.get("local_validator").is_none());
            assert!(first.get("runtime_bootstrap_complete").is_none());
            assert!(first.get("runtime_sync_caught_up").is_none());
            assert!(first.get("consensus_ready").is_none());
        });
    }

    #[test]
    fn governance_validators_status_finalized_route_degrades_when_state_is_unavailable() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                seed_pruned_unresolved_finalized_checkpoint(&mut bc, 7, 8);
            }

            let route =
                warp::path!("api" / "v2" / "governance" / "validators" / "status" / "finalized")
                    .and(warp::get())
                    .and(with_chain(chain.clone()))
                    .map(|ch: SharedChain| {
                        let bc = lock_any!(ch);
                        let snap = bc.governance_validator_status_views_for_finalized_state();
                        let body = serde_json::json!({
                            "status": if snap.source_state_available { "ok" } else { "degraded" },
                            "finalized_height": snap.finalized_height,
                            "finalized_hash": snap.finalized_hash,
                            "source_state_available": snap.source_state_available,
                            "unavailable_reason": snap.unavailable_reason,
                            "items": snap.items
                        });
                        let status = if snap.source_state_available {
                            warp::http::StatusCode::OK
                        } else {
                            warp::http::StatusCode::SERVICE_UNAVAILABLE
                        };
                        warp::reply::with_status(warp::reply::json(&body), status)
                    });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/governance/validators/status/finalized")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::SERVICE_UNAVAILABLE);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "degraded");
            assert_eq!(body["source_state_available"], false);
            assert_eq!(body["unavailable_reason"], "finalized_hash_unavailable");
        });
    }

    #[test]
    fn consensus_finality_route_degrades_when_finalized_hash_is_unavailable() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                seed_pruned_unresolved_finalized_checkpoint(&mut bc, 9, 10);
            }

            let route = warp::path!("api" / "v2" / "consensus" / "finality")
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|ch: SharedChain| {
                    let snap = {
                        let bc = lock_any!(ch);
                        bc.consensus_finality_snapshot_v1()
                    };
                    let hash_ready = snap.finalized_height == 0 || !snap.finalized_hash.trim().is_empty();
                    let body = serde_json::json!({
                        "status": if hash_ready { "ok" } else { "degraded" },
                        "finalized_height": snap.finalized_height,
                        "finalized_hash": snap.finalized_hash,
                        "e2_ready": hash_ready,
                        "unavailable_reason": if hash_ready { serde_json::Value::Null } else { serde_json::Value::String("finalized_hash_unavailable".to_string()) }
                    });
                    let status = if hash_ready { warp::http::StatusCode::OK } else { warp::http::StatusCode::SERVICE_UNAVAILABLE };
                    warp::reply::with_status(warp::reply::json(&body), status)
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/consensus/finality")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::SERVICE_UNAVAILABLE);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "degraded");
            assert_eq!(body["e2_ready"], false);
            assert_eq!(body["unavailable_reason"], "finalized_hash_unavailable");
        });
    }

    #[test]
    fn wallet_reputation_bridge_route_reports_pending_evidence() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            seed_chain_pending_wallet_evidence_from_json(
                &chain,
                "bridge-pending",
                mk_wallet_rep_pending_state(vec![serde_json::json!({
                    "claim_id": "claim-a",
                    "evidence_id": "evidence-a",
                    "source_node_id": "node-A",
                    "source_attester_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "source_attester_sig_b64": "sig-a",
                    "wallet_pubkey": "wallet-a",
                    "peer_id": "peer-a",
                    "event": "Spam",
                    "score_before": 500,
                    "score_after": 498,
                    "applied_delta": -2,
                    "trust_tier": "Tier0",
                    "observed_at_secs": 123,
                    "binding_source": "pulse_runtime_telemetry"
                })]),
            );
            let route = wallet_reputation_bridge_route_for_test(chain.clone());
            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/reputation/bridge")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["run"]["pending_evidence"].as_array().unwrap().len(), 1);
            assert_eq!(
                body["run"]["pending_evidence"][0]["source_node_id"],
                "node-A"
            );
            assert_eq!(
                body["run"]["pending_evidence"][0]["source_attester_pubkey"],
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
        });
    }

    #[test]
    fn wallet_reputation_ingest_run_route_rejects_missing_requested_wallet_evidence_ids() {
        run_async_test(async {
            let validator_sk = Arc::new(SigningKey::from_bytes(&[21u8; 32]));
            let validator_pk = hex::encode(validator_sk.verifying_key().to_bytes());
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                bc.governance = Some(test_governance_with_protocol_member_and_attesters(
                    validator_pk.clone(),
                    vec![
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ],
                ));
            }
            seed_chain_pending_wallet_evidence_from_json(
                &chain,
                "missing-ids",
                mk_wallet_rep_pending_state(vec![serde_json::json!({
                    "claim_id": "claim-a",
                    "evidence_id": "evidence-a",
                    "source_node_id": "node-A",
                    "source_attester_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "source_attester_sig_b64": "sig-a",
                    "wallet_pubkey": "wallet-a",
                    "peer_id": "peer-a",
                    "event": "Spam",
                    "score_before": 500,
                    "score_after": 498,
                    "applied_delta": -2,
                    "trust_tier": "Tier0",
                    "observed_at_secs": 123,
                    "binding_source": "pulse_runtime_telemetry"
                })]),
            );
            let route = wallet_reputation_ingest_run_route_for_test(
                "admin-token",
                validator_sk,
                validator_pk,
                chain.clone(),
            );
            let resp = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/reputation/wallet/ingest_run")
                .header("x-admin-token", "admin-token")
                .json(&serde_json::json!({"evidence_ids":["missing-id"]}))
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["message"], "missing_requested_wallet_evidence_ids");
        });
    }

    #[test]
    fn wallet_reputation_ingest_run_route_rejects_mixed_source_node_ids() {
        run_async_test(async {
            let validator_sk = Arc::new(SigningKey::from_bytes(&[22u8; 32]));
            let validator_pk = hex::encode(validator_sk.verifying_key().to_bytes());
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                bc.governance = Some(test_governance_with_protocol_member_and_attesters(
                    validator_pk.clone(),
                    vec![
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ],
                ));
            }
            seed_chain_pending_wallet_evidence_from_json(
                &chain,
                "mixed-node-ids",
                mk_wallet_rep_pending_state(vec![
                    serde_json::json!({
                        "claim_id": "claim-a",
                        "evidence_id": "evidence-a",
                        "source_node_id": "node-A",
                        "source_attester_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "source_attester_sig_b64": "sig-a",
                        "wallet_pubkey": "wallet-a",
                        "peer_id": "peer-a",
                        "event": "Spam",
                        "score_before": 500,
                        "score_after": 498,
                        "applied_delta": -2,
                        "trust_tier": "Tier0",
                        "observed_at_secs": 123,
                        "binding_source": "pulse_runtime_telemetry"
                    }),
                    serde_json::json!({
                        "claim_id": "claim-b",
                        "evidence_id": "evidence-b",
                        "source_node_id": "node-B",
                        "source_attester_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "source_attester_sig_b64": "sig-b",
                        "wallet_pubkey": "wallet-a",
                        "peer_id": "peer-b",
                        "event": "Spam",
                        "score_before": 500,
                        "score_after": 497,
                        "applied_delta": -3,
                        "trust_tier": "Tier0",
                        "observed_at_secs": 124,
                        "binding_source": "pulse_runtime_telemetry"
                    }),
                ]),
            );
            let route = wallet_reputation_ingest_run_route_for_test(
                "admin-token",
                validator_sk,
                validator_pk,
                chain.clone(),
            );
            let resp = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/reputation/wallet/ingest_run")
                .header("x-admin-token", "admin-token")
                .json(&serde_json::json!({}))
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["message"], "mixed_source_node_ids_not_allowed");
        });
    }

    #[test]
    fn wallet_reputation_ingest_run_route_rejects_mixed_source_attester_pubkeys() {
        run_async_test(async {
            let validator_sk = Arc::new(SigningKey::from_bytes(&[23u8; 32]));
            let validator_pk = hex::encode(validator_sk.verifying_key().to_bytes());
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                bc.governance = Some(test_governance_with_protocol_member_and_attesters(
                    validator_pk.clone(),
                    vec![
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    ],
                ));
            }
            seed_chain_pending_wallet_evidence_from_json(
                &chain,
                "mixed-attesters",
                mk_wallet_rep_pending_state(vec![
                    serde_json::json!({
                        "claim_id": "claim-a",
                        "evidence_id": "evidence-a",
                        "source_node_id": "node-A",
                        "source_attester_pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "source_attester_sig_b64": "sig-a",
                        "wallet_pubkey": "wallet-a",
                        "peer_id": "peer-a",
                        "event": "Spam",
                        "score_before": 500,
                        "score_after": 498,
                        "applied_delta": -2,
                        "trust_tier": "Tier0",
                        "observed_at_secs": 123,
                        "binding_source": "pulse_runtime_telemetry"
                    }),
                    serde_json::json!({
                        "claim_id": "claim-b",
                        "evidence_id": "evidence-b",
                        "source_node_id": "node-A",
                        "source_attester_pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "source_attester_sig_b64": "sig-b",
                        "wallet_pubkey": "wallet-a",
                        "peer_id": "peer-b",
                        "event": "Spam",
                        "score_before": 500,
                        "score_after": 497,
                        "applied_delta": -3,
                        "trust_tier": "Tier0",
                        "observed_at_secs": 124,
                        "binding_source": "pulse_runtime_telemetry"
                    }),
                ]),
            );
            let route = wallet_reputation_ingest_run_route_for_test(
                "admin-token",
                validator_sk,
                validator_pk,
                chain.clone(),
            );
            let resp = warp::test::request()
                .method("POST")
                .path("/api/v2/gov/reputation/wallet/ingest_run")
                .header("x-admin-token", "admin-token")
                .json(&serde_json::json!({}))
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::UNPROCESSABLE_ENTITY);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["message"], "mixed_source_attester_pubkeys_not_allowed");
        });
    }

    #[test]
    fn block_by_height_route_distinguishes_pruned_from_not_found() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap();
                bc.base_height = 10;
                let mut tip = crate::block::Block::default();
                tip.index = 10;
                tip.hash = "aa".repeat(32);
                bc.chain = vec![tip];
            }

            let route = warp::path!("api" / "v2" / "block" / u64)
                .and(warp::get())
                .and(with_chain(chain.clone()))
                .map(|height: u64, ch: SharedChain| {
                    let (lookup_res, base_height, tip_height, pruned_height) = {
                        let bc = lock_any!(ch);
                        (
                            bc.api_block_by_height_v2(height),
                            bc.base_height(),
                            bc.tip_height_u64(),
                            bc.is_pruned_height(height),
                        )
                    };
                    match lookup_res {
                        Ok(Some(_)) => warp::reply::with_status(warp::reply::json(&serde_json::json!({"status":"ok"})), warp::http::StatusCode::OK),
                        Ok(None) if pruned_height => warp::reply::with_status(warp::reply::json(&serde_json::json!({"status":"pruned","base_height":base_height,"tip_height":tip_height})), warp::http::StatusCode::GONE),
                        Ok(None) => warp::reply::with_status(warp::reply::json(&serde_json::json!({"status":"not_found","base_height":base_height,"tip_height":tip_height})), warp::http::StatusCode::NOT_FOUND),
                        Err(e) => warp::reply::with_status(warp::reply::json(&serde_json::json!({"status":"error","message":e})), warp::http::StatusCode::INTERNAL_SERVER_ERROR),
                    }
                });

            let resp = warp::test::request()
                .method("GET")
                .path("/api/v2/block/5")
                .reply(&route)
                .await;
            assert_eq!(resp.status(), warp::http::StatusCode::GONE);
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            assert_eq!(body["status"], "pruned");
        });
    }

    fn mk_governance_proposal_record_for_api_test(
        id: &str,
        kind: crate::governance::GovProposalKind,
        status: crate::governance::ProposalStatus,
        created_at_height: u64,
    ) -> crate::governance::GovProposalRecord {
        crate::governance::GovProposalRecord {
            id: id.to_string(),
            kind,
            council: crate::governance::GovernanceCouncilKind::Protocol,
            payload: br#"{"format_version":"test-v1"}"#.to_vec(),
            created_at_height,
            effective_height: created_at_height.saturating_add(10),
            proposer: "test-proposer".to_string(),
            signature: "test-signature".to_string(),
            signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: "00".repeat(32),
            proposal_hash_hex: format!("{:064x}", created_at_height),
            status,
            votes: std::collections::HashMap::new(),
            vote_records_v1: std::collections::HashMap::new(),
            terminal_height: None,
        }
    }

    fn gov_with_api_test_proposals(
        records: Vec<crate::governance::GovProposalRecord>,
    ) -> crate::governance::GovernanceState {
        let mut chain = Blockchain::new();
        let gov = chain.governance.as_mut().expect("governance enabled");
        gov.proposals.clear();
        for record in records {
            gov.proposals.insert(record.id.clone(), record);
        }
        gov.clone()
    }

    fn fixed_proposal_id_for_api_test(
        proposer: &str,
        payload: &[u8],
        chain_id: &str,
        genesis_hash: &str,
    ) -> String {
        governance_proposal_id_from_entropy_v1(
            "Bind E2!",
            &crate::governance::GovProposalKind::BindE2WorkerOperatorWallet,
            proposer,
            payload,
            10,
            20,
            3,
            chain_id,
            genesis_hash,
            123_456_789,
            42,
        )
    }

    #[test]
    fn governance_proposal_id_changes_when_payload_changes() {
        let a = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"a"}"#,
            "chain-a",
            "genesis-a",
        );
        let b = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"b"}"#,
            "chain-a",
            "genesis-a",
        );
        assert_ne!(a, b);
        assert!(a.starts_with("bind-e2-govp-"));
        let suffix = a.rsplit_once("-govp-").expect("proposal id suffix").1;
        assert_eq!(suffix.len(), 32);
        assert!(suffix
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn governance_proposal_id_changes_when_proposer_changes() {
        let a = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"a"}"#,
            "chain-a",
            "genesis-a",
        );
        let b = fixed_proposal_id_for_api_test(
            "proposer-b",
            br#"{"worker":"a"}"#,
            "chain-a",
            "genesis-a",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn governance_proposal_id_changes_when_chain_or_genesis_changes() {
        let base = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"a"}"#,
            "chain-a",
            "genesis-a",
        );
        let chain_changed = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"a"}"#,
            "chain-b",
            "genesis-a",
        );
        let genesis_changed = fixed_proposal_id_for_api_test(
            "proposer-a",
            br#"{"worker":"a"}"#,
            "chain-a",
            "genesis-b",
        );
        assert_ne!(base, chain_changed);
        assert_ne!(base, genesis_changed);
        assert_ne!(chain_changed, genesis_changed);
    }

    #[test]
    fn governance_proposal_id_is_not_bound_to_provisional_queue_heights() {
        let kind = crate::governance::GovProposalKind::BindE2WorkerOperatorWallet;
        let payload = br#"{"worker":"a"}"#;
        let a = governance_proposal_id_from_entropy_v1(
            "Bind E2!",
            &kind,
            "proposer-a",
            payload,
            10,
            20,
            3,
            "chain-a",
            "genesis-a",
            123_456_789,
            42,
        );
        let b = governance_proposal_id_from_entropy_v1(
            "Bind E2!",
            &kind,
            "proposer-a",
            payload,
            11,
            21,
            999,
            "chain-a",
            "genesis-a",
            123_456_789,
            42,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn gov_proposals_list_applies_limit() {
        let gov = gov_with_api_test_proposals(vec![
            mk_governance_proposal_record_for_api_test(
                "api-old-govp-00000000000000000000000000000001",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                1,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-new-govp-00000000000000000000000000000002",
                crate::governance::GovProposalKind::BindE2WorkerOperatorWallet,
                crate::governance::ProposalStatus::Pending,
                3,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-mid-govp-00000000000000000000000000000003",
                crate::governance::GovProposalKind::UpdateMempoolPolicy,
                crate::governance::ProposalStatus::Applied,
                2,
            ),
        ]);

        let body = governance_proposals_list_response_v1(
            &gov,
            &GovernanceProposalListQuery {
                limit: Some(1),
                status: None,
                kind: None,
            },
        );

        assert_eq!(body["status"], "ok");
        assert_eq!(body["limit"], 1);
        assert_eq!(body["returned"], 1);
        assert_eq!(body["total_matching"], 3);
        assert_eq!(
            body["proposals"][0]["proposal_id"],
            "api-new-govp-00000000000000000000000000000002"
        );
    }

    #[test]
    fn gov_proposals_list_orders_same_height_by_proposal_id() {
        let gov = gov_with_api_test_proposals(vec![
            mk_governance_proposal_record_for_api_test(
                "api-b-govp-00000000000000000000000000000004",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                5,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-a-govp-00000000000000000000000000000005",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                5,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-newer-govp-00000000000000000000000000000006",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                6,
            ),
        ]);

        let body = governance_proposals_list_response_v1(
            &gov,
            &GovernanceProposalListQuery {
                limit: Some(10),
                status: None,
                kind: None,
            },
        );

        assert_eq!(body["returned"], 3);
        assert_eq!(
            body["proposals"][0]["proposal_id"],
            "api-newer-govp-00000000000000000000000000000006"
        );
        assert_eq!(
            body["proposals"][1]["proposal_id"],
            "api-a-govp-00000000000000000000000000000005"
        );
        assert_eq!(
            body["proposals"][2]["proposal_id"],
            "api-b-govp-00000000000000000000000000000004"
        );
    }

    #[test]
    fn gov_proposals_list_filters_by_status() {
        let gov = gov_with_api_test_proposals(vec![
            mk_governance_proposal_record_for_api_test(
                "api-pending-govp-00000000000000000000000000000007",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                1,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-applied-govp-00000000000000000000000000000008",
                crate::governance::GovProposalKind::UpdateMempoolPolicy,
                crate::governance::ProposalStatus::Applied,
                2,
            ),
        ]);

        let body = governance_proposals_list_response_v1(
            &gov,
            &GovernanceProposalListQuery {
                limit: Some(10),
                status: Some("Applied".to_string()),
                kind: None,
            },
        );

        assert_eq!(body["returned"], 1);
        assert_eq!(body["total_matching"], 1);
        assert_eq!(body["filters"]["status"], "applied");
        assert_eq!(
            body["proposals"][0]["proposal_id"],
            "api-applied-govp-00000000000000000000000000000008"
        );
        assert_eq!(body["proposals"][0]["proposal_status"], "Applied");
    }

    #[test]
    fn gov_proposals_list_filters_by_kind() {
        let gov = gov_with_api_test_proposals(vec![
            mk_governance_proposal_record_for_api_test(
                "api-bind-govp-00000000000000000000000000000009",
                crate::governance::GovProposalKind::BindE2WorkerOperatorWallet,
                crate::governance::ProposalStatus::Pending,
                1,
            ),
            mk_governance_proposal_record_for_api_test(
                "api-policy-govp-0000000000000000000000000000000a",
                crate::governance::GovProposalKind::UpdateSecurityPolicy,
                crate::governance::ProposalStatus::Pending,
                2,
            ),
        ]);

        let body = governance_proposals_list_response_v1(
            &gov,
            &GovernanceProposalListQuery {
                limit: Some(10),
                status: None,
                kind: Some("BindE2WorkerOperatorWallet".to_string()),
            },
        );

        assert_eq!(body["returned"], 1);
        assert_eq!(body["total_matching"], 1);
        assert_eq!(body["filters"]["kind"], "binde2workeroperatorwallet");
        assert_eq!(
            body["proposals"][0]["proposal_id"],
            "api-bind-govp-00000000000000000000000000000009"
        );
        assert_eq!(
            body["proposals"][0]["proposal_type"],
            "BindE2WorkerOperatorWallet"
        );
    }

    #[test]
    fn api_proposal_id_path_requires_raw_canonical_value() {
        let id = "api-path-govp-00000000000000000000000000000001";
        assert!(is_canonical_governance_proposal_id_for_api_v1(id));
        assert!(!is_canonical_governance_proposal_id_for_api_v1(&format!(
            " {id}"
        )));
        assert!(!is_canonical_governance_proposal_id_for_api_v1(&format!(
            "{id} "
        )));
        assert!(!is_canonical_governance_proposal_id_for_api_v1("p-legacy"));
        assert!(!is_canonical_governance_proposal_id_for_api_v1(
            "api-path-govp-ABCDEFABCDEFABCDEFABCDEFABCDEFAB"
        ));
    }

    #[test]
    fn vote_rejects_uppercase_proposal_hash() {
        let lower = "ab".repeat(32);
        let upper = lower.to_ascii_uppercase();
        assert!(is_canonical_lowercase_sha256_hex_v1(&lower));
        assert!(!is_canonical_lowercase_sha256_hex_v1(&upper));
        assert!(!is_canonical_lowercase_sha256_hex_v1(&"aa".repeat(31)));
        assert!(!is_canonical_lowercase_sha256_hex_v1(
            &("aa".repeat(31) + "gg")
        ));
    }

    #[test]
    fn vote_rejects_whitespace_wrapped_proposal_hash() {
        let lower = "ab".repeat(32);
        assert!(!is_canonical_lowercase_sha256_hex_v1(&format!(" {lower}")));
        assert!(!is_canonical_lowercase_sha256_hex_v1(&format!("{lower} ")));
        assert!(!is_canonical_lowercase_sha256_hex_v1(&format!(
            "\n{lower}\n"
        )));
    }

    fn governance_tool_script_for_test_v189(name: &str) -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools")
            .join("gov")
            .join(name);
        match std::fs::read_to_string(&path) {
            Ok(script) => Some(script),
            Err(err) => {
                eprintln!(
                    "[test-skip] governance tool script not present in this checkout/source bundle: {} ({})",
                    path.display(),
                    err
                );
                None
            }
        }
    }

    #[test]
    fn governance_tools_reject_noncanonical_proposal_ids() {
        let mut checked = 0usize;
        for script_name in [
            "show_proposal.ps1",
            "vote_proposal.ps1",
            "wait_proposal_visible.ps1",
            "wait_proposal_applied.ps1",
        ] {
            let Some(script) = governance_tool_script_for_test_v189(script_name) else {
                continue;
            };
            checked += 1;
            assert!(script.contains("Require-CanonicalProposalId $ProposalId"));
            assert!(script.contains("<prefix>-govp-<32 lowercase hex>"));
            assert!(script.contains("[0-9a-f]{32}"));
        }
        if checked == 0 {
            eprintln!(
                "[test-skip] governance tool script assertions skipped because tools/gov is not present"
            );
        }
    }

    #[test]
    fn vote_tool_rejects_use_displayed_hash_without_lab_ack() {
        let Some(script) = governance_tool_script_for_test_v189("vote_proposal.ps1") else {
            eprintln!(
                "[test-skip] vote_proposal.ps1 assertions skipped because tools/gov is not present"
            );
            return;
        };
        assert!(script.contains("[switch]$UseDisplayedHash"));
        assert!(script.contains("[switch]$IUnderstandThisIsLabOnly"));
        assert!(script.contains("if (-not $IUnderstandThisIsLabOnly)"));
        assert!(script.contains("requires -IUnderstandThisIsLabOnly"));
        assert!(script.contains("Local/lab only override"));
        assert!(script.contains("Require-CanonicalProposalId $ProposalId"));
        assert!(script.contains("<prefix>-govp-<32 lowercase hex>"));
        assert!(!script.contains("$ProposalHashHex = $ProposalHashHex.Trim()"));
        assert!(!script.contains("$shownHashCanonical = $shownHash.Trim()"));
    }
}

#[cfg(test)]
mod economy_api_surface_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::api::api_tests::{
        http_get_json_via_server, open_empty_test_storage, pick_unused_local_port, run_async_test,
        wait_for_server_ready,
    };

    #[test]
    fn public_economy_api_does_not_expose_controller_mode() {
        let src = include_str!("api.rs");
        assert!(!src.contains("\"controller_mode\": \"shadow\""));
    }

    #[test]
    fn economy_read_models_expose_invalid_policy_version_state_without_panicking() {
        run_async_test(async {
            let chain = Arc::new(Mutex::new(Blockchain::new()));
            {
                let mut bc = chain.lock().unwrap_or_else(|e| e.into_inner());
                bc.policy.policy_version = 0;
                bc.policy.policy_compat_version = 0;
            }

            let mempool = Arc::new(Mutex::new(crate::mempool::Mempool::new()));
            let (tx_p2p, _rx_p2p) = tokio::sync::mpsc::unbounded_channel::<NetMsg>();
            let storage = open_empty_test_storage();
            let port = pick_unused_local_port();
            let server = tokio::spawn(serve_api(
                chain.clone(),
                mempool,
                tx_p2p,
                port,
                storage,
                false,
                true,
            ));

            wait_for_server_ready(port, "/api/v2/dashboard/economy").await;
            let dash = http_get_json_via_server(port, "/api/v2/dashboard/economy").await;
            let treasury = http_get_json_via_server(port, "/api/v2/treasury/state").await;

            server.abort();
            let _ = server.await;

            assert_eq!(dash["status"], "degraded");
            assert_eq!(treasury["status"], "degraded");
            assert_eq!(dash["read_model_contract"]["policy_version"], 0);
            assert_eq!(treasury["read_model_contract"]["policy_compat_version"], 0);
            assert_eq!(
                dash["read_model_contract"]["policy_version_status"],
                "invalid"
            );
            assert_eq!(
                treasury["read_model_contract"]["policy_version_status"],
                "invalid"
            );
            assert_eq!(
                dash["read_model_contract"]["policy_version_reason_code"],
                "invalid_policy_version"
            );
            assert_eq!(
                treasury["read_model_contract"]["policy_version_reason_code"],
                "invalid_policy_version"
            );
            assert_eq!(dash["contract_status"], "degraded");
            assert_eq!(treasury["contract_status"], "degraded");
            assert_eq!(dash["contract_reason_codes"][0], "invalid_policy_version");
            assert_eq!(
                treasury["contract_reason_codes"][0],
                "invalid_policy_version"
            );
            assert!(dash["read_model_contract"]["policy_version_error"]
                .as_str()
                .unwrap()
                .contains("policy_version must be >= 1"));
            assert!(treasury["read_model_contract"]["policy_version_error"]
                .as_str()
                .unwrap()
                .contains("policy_version must be >= 1"));
        });
    }
}

#[cfg(test)]
mod nft_public_policy_endpoint_contract_tests_v44 {
    use super::*;

    fn valid_enabled_nft_params_for_policy_test() -> crate::governance::GovernanceParams {
        let mut params = crate::governance::GovernanceParams::default();
        params.nft_enabled = true;
        params.nft_activation_height = 7;
        params.nft_public_create_enabled = true;
        params.nft_public_mint_enabled = true;
        params.nft_public_transfer_enabled = true;
        params.nft_metadata_hash_required = true;
        params.nft_max_collections_per_owner = 10;
        params.nft_max_tokens_per_collection = 1_000;
        params.nft_max_tokens_per_owner = 500;
        params.nft_max_memo_bytes = crate::nft::NFTV1_MEMO_MAX_BYTES as u32;
        params.nft_max_uri_bytes = crate::nft::NFTV1_URI_MAX_BYTES as u32;
        params.nft_max_name_bytes = crate::nft::NFTV1_NAME_MAX_BYTES as u32;
        params.nft_max_symbol_bytes = crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32;
        params.nft_create_fee_native = 11;
        params.nft_mint_fee_native = 12;
        params.nft_transfer_fee_native = 13;
        params
    }

    #[test]
    fn nft_policy_response_exposes_finalized_wallet_preflight_contract_v44() {
        let params = valid_enabled_nft_params_for_policy_test();
        crate::governance::validate_nft_governance_policy_v1(&params).unwrap();
        let snap = NftPolicySnapshotV1 {
            source_commitment: "finalized",
            tip_height: 9,
            finalized_height: 8,
            finalized_hash: "ab".repeat(32),
            governance_height: 8,
            base_fee_per_tx: 100,
            policy_hash: "cd".repeat(32),
            params,
        };
        let body = nft_policy_json_from_snapshot_v1(&snap);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["source_commitment"], "finalized");
        assert_eq!(body["enabled"], true);
        assert_eq!(body["active"], true);
        assert_eq!(body["activation_height"], 7);
        assert_eq!(body["public_create_enabled"], true);
        assert_eq!(body["public_mint_enabled"], true);
        assert_eq!(body["public_transfer_enabled"], true);
        assert_eq!(body["metadata_hash_required"], true);
        assert_eq!(body["caps"]["max_collections_per_owner"], 10);
        assert_eq!(body["caps"]["max_tokens_per_collection"], 1_000);
        assert_eq!(body["caps"]["max_tokens_per_owner"], 500);
        assert_eq!(body["fees"]["base_fee_per_tx"], 100);
        assert_eq!(body["fees"]["create_fee_native"], 11);
        assert_eq!(body["fees"]["mint_fee_native"], 12);
        assert_eq!(body["fees"]["transfer_fee_native"], 13);
        assert_eq!(body["governance_height"], 8);
        assert_eq!(body["finalized_height"], 8);
        assert_eq!(body["tip_height"], 9);
        assert_eq!(body["policy_hash"], "cd".repeat(32));
        assert_eq!(body["policy_source"]["source_commitment"], "finalized");
    }

    #[test]
    fn nft_policy_unavailable_uses_service_unavailable_status_v46() {
        let resp = nft_policy_unavailable_response_v1("finalized_governance_unavailable");
        assert_eq!(resp.status(), warp::http::StatusCode::SERVICE_UNAVAILABLE);
        let cache = resp
            .headers()
            .get("Cache-Control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cache, "no-store");
    }

    #[test]
    fn status_cache_extracts_runtime_sync_state_for_degraded_status_v183() {
        let status_body = serde_json::json!({
            "height": 42,
            "finalized_height": 40,
            "last_block_hash": "aa",
            "finalized_hash": "bb",
            "local_runtime": {
                "runtime_sync_caught_up": false,
                "p2p_ready_for_mining": false,
                "proposal_gate_open": false,
                "consensus_ready": false
            }
        });

        let cache = runtime_status_cache_from_status_body_v1(&status_body);
        assert_eq!(cache.height, Some(42));
        assert_eq!(cache.finalized_height, Some(40));
        assert_eq!(cache.last_block_hash.as_deref(), Some("aa"));
        assert_eq!(cache.finalized_hash.as_deref(), Some("bb"));
        assert_eq!(cache.boot_phase.as_deref(), Some("sync_or_bootstrap"));
        assert_eq!(cache.sync_state.as_deref(), Some("catching_up"));
        assert!(cache.updated_at_ms.unwrap_or_default() > 0);
    }

    #[test]
    fn status_degraded_response_is_api_alive_and_uses_cached_height_v183() {
        let cache = RuntimeStatusCache {
            height: Some(123),
            finalized_height: Some(120),
            last_block_hash: Some("tip".to_string()),
            finalized_hash: Some("final".to_string()),
            boot_phase: Some("sync_or_bootstrap".to_string()),
            sync_state: Some("catching_up".to_string()),
            last_snapshot_error: Some("snapshot_busy".to_string()),
            last_state_sync_error: Some("sync_backoff".to_string()),
            updated_at_ms: Some(999),
        };

        let body = build_degraded_status_from_cache_v1(&cache, "chain_lock_busy", Some((7, 77)));
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["reason"], "chain_lock_busy");
        assert_eq!(body["api_alive"], true);
        assert_eq!(body["last_cached_height"], 123);
        assert_eq!(body["last_cached_finalized_height"], 120);
        assert_eq!(body["mempool_size"], 7);
        assert_eq!(body["mempool_bytes"], 77);
        assert_eq!(body["cache"]["sync_state"], "catching_up");
        assert_eq!(body["cache"]["last_snapshot_error"], "snapshot_busy");
    }

    #[test]
    fn status_cache_preserves_runtime_errors_across_height_updates_v185() {
        record_runtime_snapshot_error_v1("snapshot_meta_oversize");
        let next = RuntimeStatusCache {
            height: Some(777),
            finalized_height: Some(770),
            last_block_hash: Some("tip777".to_string()),
            finalized_hash: Some("final770".to_string()),
            boot_phase: Some("steady_state".to_string()),
            sync_state: Some("steady".to_string()),
            last_snapshot_error: None,
            last_state_sync_error: None,
            updated_at_ms: Some(1234),
        };
        runtime_status_cache_update_v1(next);
        let cache = runtime_status_cache_read_v1();
        assert_eq!(cache.height, Some(777));
        assert_eq!(
            cache.last_snapshot_error.as_deref(),
            Some("snapshot_meta_oversize")
        );
    }

    #[test]
    fn nft_policy_api_preview_uses_core_governance_delta_preview_v44() {
        let current = crate::governance::GovernanceParams::default();
        let delta = crate::governance::GovernanceParamsDelta {
            nft_enabled: Some(true),
            nft_activation_height: Some(10),
            nft_public_create_enabled: Some(true),
            nft_public_mint_enabled: Some(true),
            nft_public_transfer_enabled: Some(true),
            nft_metadata_hash_required: Some(true),
            nft_max_collections_per_owner: Some(2),
            nft_max_tokens_per_collection: Some(100),
            nft_max_tokens_per_owner: Some(50),
            ..crate::governance::GovernanceParamsDelta::default()
        };
        let via_api = preview_nft_governance_delta_for_api_v1(&current, &delta).unwrap();
        let via_core =
            crate::governance::preview_governance_params_delta_v1(&current, &delta).unwrap();
        assert_eq!(via_api.nft_enabled, via_core.nft_enabled);
        assert_eq!(
            via_api.nft_activation_height,
            via_core.nft_activation_height
        );
        assert_eq!(
            via_api.nft_max_tokens_per_collection,
            via_core.nft_max_tokens_per_collection
        );
    }
}
