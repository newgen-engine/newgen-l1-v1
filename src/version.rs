// src/version.rs

/// Versione del software (semver). Deriva da Cargo.toml.
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Commit git (opzionale) per diagnosi.
pub const GIT_COMMIT: Option<&'static str> = option_env!("GIT_COMMIT");

/// Versione del protocollo (consenso / formati blocco/tx / wire invariants).
/// Bump solo quando introduci breaking changes di protocollo.
pub const PROTOCOL_VERSION: u32 = 3;

/// Min protocol accettato da questo nodo.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 3;

/// Contratto HTTP pubblico principale esposto dal nodo.
pub const API_CONTRACT: &str = "v2";
pub const API_CONTRACT_VERSION: &str = "2.0.0";

/// Contratto minimo ufficiale tra chain (E1) e Compute Hub (E2).
pub const E2_CONTRACT_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionInfo {
    pub software_version: String,
    pub git_commit: Option<String>,
    pub protocol_version: u32,
    pub min_supported_protocol_version: u32,
}

impl VersionInfo {
    pub fn current() -> Self {
        Self {
            software_version: SOFTWARE_VERSION.to_string(),
            git_commit: GIT_COMMIT.map(|s| s.to_string()),
            protocol_version: PROTOCOL_VERSION,
            min_supported_protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct E2ContractCapabilitiesV1 {
    pub governance_finalized_v1: bool,
    pub compute_memo_events_v1: bool,
    pub compute_orders_canonical: bool,
    pub compute_orders_surface_v2: bool,
    pub compute_order_required_workload_class_v1: bool,
    pub compute_order_event_feed_v1: bool,
    pub block_by_height_prune_safe_v1: bool,
    pub fee_params_v1: bool,
    pub wallet_next_nonce_v1: bool,
    pub signed_tx_relay_v1: bool,
    pub tx_lookup_v1: bool,
    pub e2_worker_reputation_evidence_v1: bool,
    pub e2_worker_standard_evidence_tx_v1: bool,
    pub e2_worker_bootstrap_probe_contract_v1: bool,
    pub e2_worker_governed_evidence_ingest_v1: bool,
    pub e2_worker_self_registration_v1: bool,
    pub e2_worker_governed_privileges_v1: bool,
    pub canonical_worker_eligibility_v1: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct E2ContractPathsV1 {
    pub consensus_finality: String,
    pub governance_validators_status_finalized: String,
    pub block_by_height: String,
    pub fee_params: String,
    pub wallet_next_nonce: String,
    pub tx_submit_signed: String,
    pub tx_by_hash: String,
    pub e2_orders: String,
    pub e2_order_by_id: String,
    pub e2_order_events: String,
    pub e2_worker_reputation_evidence: String,
    pub e2_worker_standard_evidence_build_unsigned: String,
    pub e2_worker_standard_evidence_submit: String,
    pub e2_worker_bootstrap_probe_contract: String,
    pub e2_worker_governed_evidence_ingest: String,
    pub e2_worker_self_registration: String,
    pub e2_worker_self_registration_build_unsigned: String,
    pub e2_worker_self_registration_submit: String,
    pub e2_worker_governed_privilege: String,
    pub canonical_worker_eligibility: String,
    pub canonical_worker_privileges: String,
    pub canonical_worker_eligibility_by_worker: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct E2ContractSnapshotV1 {
    pub api_contract: String,
    pub api_contract_version: String,
    pub e2_contract_version: String,
    pub software_version: String,
    pub git_commit: Option<String>,
    pub protocol_version: u32,
    pub min_supported_protocol_version: u32,
    pub reputation_score_scale: String,
    pub reputation_score_max: i32,
    pub worker_penalty_taxonomy: String,
    pub node_reputation_score_formula_version: String,
    pub wallet_reputation_score_formula_version: String,
    pub worker_eligibility_policy_version: String,
    pub supported_capabilities: Vec<String>,
    pub capabilities: E2ContractCapabilitiesV1,
    pub canonical_paths: E2ContractPathsV1,
}

impl E2ContractSnapshotV1 {
    pub fn current() -> Self {
        let capabilities = E2ContractCapabilitiesV1 {
            governance_finalized_v1: true,
            compute_memo_events_v1: true,
            compute_orders_canonical: true,
            compute_orders_surface_v2: true,
            compute_order_required_workload_class_v1: true,
            compute_order_event_feed_v1: true,
            block_by_height_prune_safe_v1: true,
            fee_params_v1: true,
            wallet_next_nonce_v1: true,
            signed_tx_relay_v1: true,
            tx_lookup_v1: true,
            e2_worker_reputation_evidence_v1: true,
            e2_worker_standard_evidence_tx_v1: true,
            e2_worker_bootstrap_probe_contract_v1: true,
            e2_worker_governed_evidence_ingest_v1: true,
            e2_worker_self_registration_v1: true,
            e2_worker_governed_privileges_v1: true,
            canonical_worker_eligibility_v1: true,
        };
        let mut supported_capabilities = Vec::new();
        if capabilities.governance_finalized_v1 {
            supported_capabilities.push("governance_finalized_v1".to_string());
        }
        if capabilities.compute_memo_events_v1 {
            supported_capabilities.push("compute_memo_events_v1".to_string());
        }
        if capabilities.compute_orders_canonical {
            supported_capabilities.push("compute_orders_v1".to_string());
            supported_capabilities.push("compute_orders_canonical".to_string());
        }
        if capabilities.compute_orders_surface_v2 {
            supported_capabilities.push("compute_orders_surface_v2".to_string());
        }
        if capabilities.compute_order_required_workload_class_v1 {
            supported_capabilities.push("compute_order_required_workload_class_v1".to_string());
        }
        if capabilities.compute_order_event_feed_v1 {
            supported_capabilities.push("compute_order_event_feed_v1".to_string());
        }
        if capabilities.block_by_height_prune_safe_v1 {
            supported_capabilities.push("block_by_height_prune_safe_v1".to_string());
        }
        if capabilities.fee_params_v1 {
            supported_capabilities.push("fee_params_v1".to_string());
        }
        if capabilities.wallet_next_nonce_v1 {
            supported_capabilities.push("wallet_next_nonce_v1".to_string());
        }
        if capabilities.signed_tx_relay_v1 {
            supported_capabilities.push("signed_tx_relay_v1".to_string());
        }
        if capabilities.tx_lookup_v1 {
            supported_capabilities.push("tx_lookup_v1".to_string());
        }
        if capabilities.e2_worker_reputation_evidence_v1 {
            supported_capabilities.push("e2_worker_reputation_evidence_v1".to_string());
        }
        if capabilities.e2_worker_standard_evidence_tx_v1 {
            supported_capabilities.push("e2_worker_standard_evidence_tx_v1".to_string());
        }
        if capabilities.e2_worker_bootstrap_probe_contract_v1 {
            supported_capabilities.push("e2_worker_bootstrap_probe_contract_v1".to_string());
        }
        if capabilities.e2_worker_governed_evidence_ingest_v1 {
            supported_capabilities.push("e2_worker_governed_evidence_ingest_v1".to_string());
        }
        if capabilities.e2_worker_self_registration_v1 {
            supported_capabilities.push("e2_worker_self_registration_v1".to_string());
        }
        if capabilities.e2_worker_governed_privileges_v1 {
            supported_capabilities.push("e2_worker_governed_privileges_v1".to_string());
        }
        if capabilities.canonical_worker_eligibility_v1 {
            supported_capabilities.push("canonical_worker_eligibility_v1".to_string());
        }

        Self {
            api_contract: API_CONTRACT.to_string(),
            api_contract_version: API_CONTRACT_VERSION.to_string(),
            e2_contract_version: E2_CONTRACT_VERSION.to_string(),
            software_version: SOFTWARE_VERSION.to_string(),
            git_commit: GIT_COMMIT.map(|s| s.to_string()),
            protocol_version: PROTOCOL_VERSION,
            min_supported_protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            reputation_score_scale: crate::reputation_score::REPUTATION_SCORE_SCALE_V1.to_string(),
            reputation_score_max: crate::reputation_score::REPUTATION_SCORE_MAX_V1,
            worker_penalty_taxonomy: crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1
                .to_string(),
            node_reputation_score_formula_version:
                crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            wallet_reputation_score_formula_version:
                crate::reputation_score::WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            worker_eligibility_policy_version:
                crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1.to_string(),
            supported_capabilities,
            capabilities,
            canonical_paths: E2ContractPathsV1 {
                consensus_finality: "/api/v2/consensus/finality".to_string(),
                governance_validators_status_finalized:
                    "/api/v2/governance/validators/status/finalized".to_string(),
                block_by_height: "/api/v2/block/{height}".to_string(),
                fee_params: "/status".to_string(),
                wallet_next_nonce: "/api/v2/wallet/next_nonce/{address}".to_string(),
                tx_submit_signed: "/api/v2/tx/submit_signed".to_string(),
                tx_by_hash: "/api/v2/tx/by-hash/{hash}".to_string(),
                e2_orders: "/api/v2/e2/orders".to_string(),
                e2_order_by_id: "/api/v2/e2/orders/{order_id}".to_string(),
                e2_order_events: "/api/v2/e2/order-events".to_string(),
                // Standard E2 worker evidence is an ordinary signed L1 tx.
                // The governed/manual ingest endpoint remains available, but it is not the default E2 evidence path.
                e2_worker_reputation_evidence: "/api/v2/e2/worker/evidence/build_unsigned"
                    .to_string(),
                e2_worker_standard_evidence_build_unsigned:
                    "/api/v2/e2/worker/evidence/build_unsigned".to_string(),
                e2_worker_standard_evidence_submit: "/api/v2/tx/submit_signed".to_string(),
                e2_worker_bootstrap_probe_contract:
                    "/api/v2/e2/worker/evidence/bootstrap_probe/contract".to_string(),
                e2_worker_governed_evidence_ingest: "/api/v2/reputation/e2/worker/evidence"
                    .to_string(),
                e2_worker_self_registration: "/api/v2/e2/worker/register/build_unsigned"
                    .to_string(),
                e2_worker_self_registration_build_unsigned:
                    "/api/v2/e2/worker/register/build_unsigned".to_string(),
                e2_worker_self_registration_submit: "/api/v2/tx/submit_signed".to_string(),
                e2_worker_governed_privilege: "/api/v2/gov/e2/worker/privilege".to_string(),
                canonical_worker_eligibility: "/api/v2/reputation/canonical/workers".to_string(),
                canonical_worker_privileges: "/api/v2/reputation/canonical/workers/privileges"
                    .to_string(),
                canonical_worker_eligibility_by_worker:
                    "/api/v2/reputation/canonical/workers/{worker_node_pubkey}/eligibility"
                        .to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_matches_constants() {
        let cur = VersionInfo::current();
        assert_eq!(cur.software_version, SOFTWARE_VERSION);
        assert_eq!(cur.git_commit, GIT_COMMIT.map(|s| s.to_string()));
        assert_eq!(cur.protocol_version, PROTOCOL_VERSION);
        assert_eq!(
            cur.min_supported_protocol_version,
            MIN_SUPPORTED_PROTOCOL_VERSION
        );
        assert!(cur.min_supported_protocol_version <= cur.protocol_version);
    }

    #[test]
    fn e2_contract_snapshot_exposes_capabilities_and_paths() {
        let snap = E2ContractSnapshotV1::current();
        assert_eq!(snap.api_contract, API_CONTRACT);
        assert_eq!(snap.api_contract_version, API_CONTRACT_VERSION);
        assert_eq!(snap.e2_contract_version, E2_CONTRACT_VERSION);
        assert_eq!(
            snap.reputation_score_scale,
            crate::reputation_score::REPUTATION_SCORE_SCALE_V1
        );
        assert_eq!(
            snap.reputation_score_max,
            crate::reputation_score::REPUTATION_SCORE_MAX_V1
        );
        assert_eq!(
            snap.worker_penalty_taxonomy,
            crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1
        );
        assert_eq!(
            snap.node_reputation_score_formula_version,
            crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1
        );
        assert_eq!(
            snap.wallet_reputation_score_formula_version,
            crate::reputation_score::WALLET_REPUTATION_SCORE_FORMULA_VERSION_V1
        );
        assert_eq!(
            snap.worker_eligibility_policy_version,
            crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1
        );
        assert!(snap.capabilities.governance_finalized_v1);
        assert!(snap.capabilities.compute_memo_events_v1);
        assert!(snap.capabilities.compute_orders_canonical);
        assert!(snap.capabilities.compute_orders_surface_v2);
        assert!(snap.capabilities.compute_order_required_workload_class_v1);
        assert!(snap.capabilities.compute_order_event_feed_v1);
        assert!(snap.capabilities.block_by_height_prune_safe_v1);
        assert!(snap.capabilities.fee_params_v1);
        assert!(snap.capabilities.wallet_next_nonce_v1);
        assert!(snap.capabilities.signed_tx_relay_v1);
        assert!(snap.capabilities.tx_lookup_v1);
        assert!(snap.capabilities.e2_worker_reputation_evidence_v1);
        assert!(snap.capabilities.e2_worker_standard_evidence_tx_v1);
        assert!(snap.capabilities.e2_worker_governed_evidence_ingest_v1);
        assert!(snap.capabilities.e2_worker_self_registration_v1);
        assert!(snap.capabilities.canonical_worker_eligibility_v1);
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "governance_finalized_v1"));
        assert_eq!(
            snap.canonical_paths.governance_validators_status_finalized,
            "/api/v2/governance/validators/status/finalized"
        );
        assert_eq!(snap.canonical_paths.fee_params, "/status");
        assert_eq!(
            snap.canonical_paths.wallet_next_nonce,
            "/api/v2/wallet/next_nonce/{address}"
        );
        assert_eq!(
            snap.canonical_paths.tx_submit_signed,
            "/api/v2/tx/submit_signed"
        );
        assert_eq!(snap.canonical_paths.e2_orders, "/api/v2/e2/orders");
        assert_eq!(
            snap.canonical_paths.e2_order_events,
            "/api/v2/e2/order-events"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_reputation_evidence,
            "/api/v2/e2/worker/evidence/build_unsigned"
        );
        assert_eq!(
            snap.canonical_paths
                .e2_worker_standard_evidence_build_unsigned,
            "/api/v2/e2/worker/evidence/build_unsigned"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_standard_evidence_submit,
            "/api/v2/tx/submit_signed"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_bootstrap_probe_contract,
            "/api/v2/e2/worker/evidence/bootstrap_probe/contract"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_governed_evidence_ingest,
            "/api/v2/reputation/e2/worker/evidence"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_self_registration,
            "/api/v2/e2/worker/register/build_unsigned"
        );
        assert_eq!(
            snap.canonical_paths
                .e2_worker_self_registration_build_unsigned,
            "/api/v2/e2/worker/register/build_unsigned"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_self_registration_submit,
            "/api/v2/tx/submit_signed"
        );
        assert_eq!(
            snap.canonical_paths.e2_worker_governed_privilege,
            "/api/v2/gov/e2/worker/privilege"
        );
        assert_eq!(
            snap.canonical_paths.canonical_worker_eligibility,
            "/api/v2/reputation/canonical/workers"
        );
        assert_eq!(
            snap.canonical_paths.canonical_worker_privileges,
            "/api/v2/reputation/canonical/workers/privileges"
        );
        assert_eq!(
            snap.canonical_paths.canonical_worker_eligibility_by_worker,
            "/api/v2/reputation/canonical/workers/{worker_node_pubkey}/eligibility"
        );
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "compute_orders_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "compute_orders_surface_v2"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "compute_order_required_workload_class_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "compute_order_event_feed_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "fee_params_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "wallet_next_nonce_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "e2_worker_reputation_evidence_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "e2_worker_standard_evidence_tx_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "e2_worker_bootstrap_probe_contract_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "e2_worker_governed_evidence_ingest_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "e2_worker_self_registration_v1"));
        assert!(snap
            .supported_capabilities
            .iter()
            .any(|c| c == "canonical_worker_eligibility_v1"));
    }
}
