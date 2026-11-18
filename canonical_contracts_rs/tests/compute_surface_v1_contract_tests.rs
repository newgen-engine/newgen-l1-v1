use newgen_canonical_contracts::compute_surface_v1::{
    validate_compute_order_events_snapshot_v1, validate_compute_orders_snapshot_v1,
    ComputeOrderEventV1, ComputeOrderEventsSnapshotV1, ComputeOrderLookupResponseV1,
    ComputeOrderRecordV1, ComputeOrderStatusV1, ComputeOrdersSnapshotV1, ComputePolicyV1,
    COMPUTE_SURFACE_FORMAT_VERSION_V1,
};

#[test]
fn compute_orders_snapshot_golden_v1() {
    let snapshot = ComputeOrdersSnapshotV1 {
        format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
        e2_contract_version: "2.0.0".to_string(),
        finalized_height: 42,
        finalized_hash: "ab".repeat(32),
        orders: vec![ComputeOrderRecordV1 {
            format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
            order_id: "order-1".to_string(),
            payer: "wallet-1".to_string(),
            amount: 100,
            job_spec_hash: "cd".repeat(32),
            max_time_ms: 1_000,
            policy: ComputePolicyV1::default(),
            status: ComputeOrderStatusV1::Open,
            created_height: 42,
            claimed_worker: None,
            claim_height: None,
            completed_height: None,
            result_hash: None,
            artifact_root_hash: None,
            receipt_hash: None,
            fail_reason: None,
        }],
    };
    validate_compute_orders_snapshot_v1(&snapshot).unwrap();
    let rendered = serde_json::to_string_pretty(&snapshot).unwrap();
    let expected = format!(
        "{{\n  \"format_version\": 1,\n  \"e2_contract_version\": \"2.0.0\",\n  \"finalized_height\": 42,\n  \"finalized_hash\": \"{}\",\n  \"orders\": [\n    {{\n      \"format_version\": 1,\n      \"order_id\": \"order-1\",\n      \"payer\": \"wallet-1\",\n      \"amount\": 100,\n      \"job_spec_hash\": \"{}\",\n      \"max_time_ms\": 1000,\n      \"policy\": {{\n        \"require_trusted\": false,\n        \"min_score\": 0.0,\n        \"min_reputation\": 0.0,\n        \"max_failures\": 0\n      }},\n      \"status\": \"open\",\n      \"created_height\": 42,\n      \"claimed_worker\": null,\n      \"claim_height\": null,\n      \"completed_height\": null,\n      \"result_hash\": null,\n      \"artifact_root_hash\": null,\n      \"receipt_hash\": null,\n      \"fail_reason\": null\n    }}\n  ]\n}}",
        "ab".repeat(32),
        "cd".repeat(32)
    );
    assert_eq!(rendered, expected);
}

#[test]
fn compute_orders_snapshot_backcompat_without_format_version() {
    let legacy = serde_json::json!({
        "e2_contract_version": "2.0.0",
        "finalized_height": 0,
        "finalized_hash": "",
        "orders": [{
            "order_id": "order-1",
            "payer": "wallet-1",
            "amount": 100,
            "job_spec_hash": "cd".repeat(32),
            "max_time_ms": 1000,
            "policy": {
                "require_trusted": false,
                "min_score": 0.0,
                "min_reputation": 0.0,
                "max_failures": 0
            },
            "status": "open",
            "created_height": 42,
            "claimed_worker": null,
            "claim_height": null,
            "completed_height": null,
            "result_hash": null,
            "artifact_root_hash": null,
            "receipt_hash": null,
            "fail_reason": null
        }]
    });
    let parsed: ComputeOrdersSnapshotV1 = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.format_version, COMPUTE_SURFACE_FORMAT_VERSION_V1);
    assert_eq!(parsed.orders[0].format_version, COMPUTE_SURFACE_FORMAT_VERSION_V1);
    validate_compute_orders_snapshot_v1(&parsed).unwrap();
}

#[test]
fn compute_surface_rejects_unknown_fields() {
    let bad = serde_json::json!({
        "format_version": 1,
        "e2_contract_version": "2.0.0",
        "finalized_height": 0,
        "finalized_hash": "",
        "orders": [],
        "unexpected": true
    });
    let err = serde_json::from_value::<ComputeOrdersSnapshotV1>(bad).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn compute_events_snapshot_validator_rejects_invalid_range() {
    let snapshot = ComputeOrderEventsSnapshotV1 {
        format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
        e2_contract_version: "2.0.0".to_string(),
        finalized_height: 10,
        finalized_hash: "aa".repeat(32),
        from_height: 9,
        to_height: 8,
        events: vec![ComputeOrderEventV1 {
            format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
            order_id: "order-1".to_string(),
            event_type: "create".to_string(),
            tx_hash: "bb".repeat(32),
            height: 9,
            block_hash: "cc".repeat(32),
            sender: "wallet-1".to_string(),
            payer: Some("wallet-1".to_string()),
            amount: Some(100),
            job_spec_hash: Some("dd".repeat(32)),
            max_time_ms: Some(1_000),
            policy: Some(ComputePolicyV1::default()),
            job_kind: Some("wasm".to_string()),
            job_payload: Some(serde_json::json!({"hello":"world"})),
            claimed_worker: None,
            result_hash: None,
            artifact_root_hash: None,
            exit_code: None,
            receipt_hash: None,
            fail_reason: None,
        }],
    };
    let err = validate_compute_order_events_snapshot_v1(&snapshot).unwrap_err();
    assert!(err.contains("to_height must be >= from_height"));
}

#[test]
fn compute_lookup_backcompat_without_format_version() {
    let legacy = serde_json::json!({
        "e2_contract_version": "2.0.0",
        "finalized_height": 1,
        "finalized_hash": "aa".repeat(32),
        "found": false,
        "order": null
    });
    let parsed: ComputeOrderLookupResponseV1 = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.format_version, COMPUTE_SURFACE_FORMAT_VERSION_V1);
}
