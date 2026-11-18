use newgen_canonical_contracts::cognitive_registry_surface_v1::{
    validate_chain_consensus_finality_view_v1, validate_chain_registry_object_view_v1,
    ChainConsensusFinalityViewV1, ChainRegistryEffectiveStatusV1,
    ChainRegistryObjectEntryV1, ChainRegistryObjectViewV1,
    ChainRegistryReconciliationContextV1, ChainRegistryStatusViewV1, ChainAnchorV1,
    COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
};

fn sample_context() -> ChainRegistryReconciliationContextV1 {
    ChainRegistryReconciliationContextV1 {
        format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
        chain_id: "newgen-devnet-slot".to_string(),
        genesis_hash: "aa".repeat(32),
        tip_height: 120,
        tip_hash: "bb".repeat(32),
        finalized_height: 118,
        finalized_hash: "cc".repeat(32),
        highest_qc_height: 118,
        highest_qc_round: 9,
        highest_qc_block_hash: "dd".repeat(32),
        registry_last_applied_height: Some(118),
        registry_last_event_seq: Some(77),
    }
}

#[test]
fn cognitive_finality_golden_v1() {
    let view = ChainConsensusFinalityViewV1 {
        format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
        tip_height: 120,
        tip_hash: "bb".repeat(32),
        finalized_height: 118,
        finalized_hash: "cc".repeat(32),
        highest_qc_height: 118,
        highest_qc_round: 9,
        highest_qc_block_hash: "dd".repeat(32),
        bft_active: true,
    };
    validate_chain_consensus_finality_view_v1(&view).unwrap();
    let rendered = serde_json::to_string_pretty(&view).unwrap();
    assert!(rendered.contains("\"format_version\": 1"));
    assert!(rendered.contains("\"finalized_height\": 118"));
}

#[test]
fn cognitive_context_backcompat_without_format_version() {
    let legacy = serde_json::json!({
        "chain_id": "newgen-devnet-slot",
        "genesis_hash": "aa".repeat(32),
        "tip_height": 120,
        "tip_hash": "bb".repeat(32),
        "finalized_height": 118,
        "finalized_hash": "cc".repeat(32),
        "highest_qc_height": 118,
        "highest_qc_round": 9,
        "highest_qc_block_hash": "dd".repeat(32),
        "registry_last_applied_height": 118,
        "registry_last_event_seq": 77
    });
    let parsed: ChainRegistryReconciliationContextV1 = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1);
}

#[test]
fn cognitive_surface_rejects_unknown_fields() {
    let bad = serde_json::json!({
        "format_version": 1,
        "chain_id": "newgen-devnet-slot",
        "genesis_hash": "aa".repeat(32),
        "tip_height": 120,
        "tip_hash": "bb".repeat(32),
        "finalized_height": 118,
        "finalized_hash": "cc".repeat(32),
        "highest_qc_height": 118,
        "highest_qc_round": 9,
        "highest_qc_block_hash": "dd".repeat(32),
        "unexpected": true
    });
    let err = serde_json::from_value::<ChainRegistryReconciliationContextV1>(bad).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn cognitive_object_view_validator_accepts_consistent_payload() {
    let ctx = sample_context();
    let view = ChainRegistryObjectViewV1 {
        format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
        entry: ChainRegistryObjectEntryV1 {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            object_hash_hex: "11".repeat(32),
            claim_hash_hex: "22".repeat(32),
            lifecycle_state: "active".to_string(),
            policy_id: "policy-a".to_string(),
            anchor_height: 118,
            anchor_block_hash: "33".repeat(32),
            evidence_root_hex: "44".repeat(32),
            context_hash_hex: "55".repeat(32),
            model_manifest_hash_hex: "66".repeat(32),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 118,
        },
        status_view: ChainRegistryStatusViewV1 {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            object_hash_hex: "11".repeat(32),
            claim_hash_hex: "22".repeat(32),
            lifecycle_state: "active".to_string(),
            effective_status: ChainRegistryEffectiveStatusV1::AnchoredFinal,
            anchor_height: 118,
            anchor_block_hash: "33".repeat(32),
            policy_id: "policy-a".to_string(),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 118,
            is_finalized: true,
            reconciliation_context: ctx,
        },
    };
    validate_chain_registry_object_view_v1(&view).unwrap();
}

#[test]
fn cognitive_anchor_backcompat_without_format_version() {
    let legacy = serde_json::json!({
        "object_hash_hex": "11".repeat(32),
        "claim_hash_hex": "22".repeat(32),
        "anchor_height": 118,
        "anchor_block_hash": "33".repeat(32),
        "finalized_height": 118,
        "tip_height": 120
    });
    let parsed: ChainAnchorV1 = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.format_version, COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1);
}
