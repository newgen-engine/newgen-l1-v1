use newgen_canonical_contracts::ai_e2_gateway_v1::{
    validate_intent_envelope_v1, AiE2ChainAnchorV1, AiE2InferenceSettlementOrderRefV1,
    AiE2IntentCommonV1, AiE2IntentEnvelopeV1, AiE2RequestedCapabilityV1,
    InferenceJobIntentV1, AI_E2_GATEWAY_CONTRACT_VERSION_V1,
    AI_E2_GATEWAY_FORMAT_VERSION_V1,
};

fn common(anchor: Option<AiE2ChainAnchorV1>) -> AiE2IntentCommonV1 {
    AiE2IntentCommonV1 {
        format_version: AI_E2_GATEWAY_FORMAT_VERSION_V1,
        tenant_id: "tenant-a".to_string(),
        org_id: Some("org-a".to_string()),
        project_id: Some("project-a".to_string()),
        user_id: "user-a".to_string(),
        scope_id: "chat-session:chat-a".to_string(),
        requested_capability: AiE2RequestedCapabilityV1::Inference,
        budget_limit: 1,
        time_limit_ms: 1_000,
        input_refs: Vec::new(),
        required_chain_anchor: anchor,
        policy_profile: "strict".to_string(),
        idempotency_key: "ai-e2:v1:chat:chat-a:message:message-a:action:0:intent:inference_job:prompt:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:policy:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
    }
}

fn runtime_parameters() -> serde_json::Value {
    serde_json::json!({
        "runtime": {
            "modelRuntimeHash": "aa".repeat(32),
            "tokenizerHash": "bb".repeat(32),
            "checkpointHash": "cc".repeat(32)
        }
    })
}

#[test]
fn ai_e2_gateway_contract_version_is_settlement_ref_capable_v1() {
    assert_eq!(AI_E2_GATEWAY_CONTRACT_VERSION_V1, "1.2.0");
}

#[test]
fn inference_intent_accepts_typed_settlement_ref_with_chain_anchor_v1() {
    let settlement_ref = AiE2InferenceSettlementOrderRefV1::compute_order("11".repeat(32));
    let intent = AiE2IntentEnvelopeV1::InferenceJob(InferenceJobIntentV1 {
        common: common(Some(AiE2ChainAnchorV1 {
            finalized_height: 42,
            finalized_hash: "dd".repeat(32),
        })),
        prompt: "settled inference".to_string(),
        inference_parameters: Some(runtime_parameters()),
        settlement_ref: Some(settlement_ref),
    });

    validate_intent_envelope_v1(&intent).unwrap();
    let rendered = serde_json::to_value(&intent).unwrap();
    assert_eq!(
        rendered.pointer("/settlementRef/orderId").and_then(|v| v.as_str()),
        Some("1111111111111111111111111111111111111111111111111111111111111111")
    );
}

#[test]
fn inference_settlement_ref_requires_chain_anchor_v1() {
    let intent = AiE2IntentEnvelopeV1::InferenceJob(InferenceJobIntentV1 {
        common: common(None),
        prompt: "settled inference".to_string(),
        inference_parameters: Some(runtime_parameters()),
        settlement_ref: Some(AiE2InferenceSettlementOrderRefV1::compute_order("11".repeat(32))),
    });

    let err = validate_intent_envelope_v1(&intent).unwrap_err();
    assert!(err.contains("requires_required_chain_anchor"));
}

#[test]
fn inference_settlement_ref_rejects_non_bytes32_lower_hex_order_id_v1() {
    let bad = AiE2InferenceSettlementOrderRefV1::compute_order("ORDER-1");
    let err = bad.validate_contract_v1().unwrap_err();
    assert!(err.contains("32_byte_lower_hex"));
}

#[test]
fn inference_parameters_cannot_smuggle_settlement_or_order_fields_v1() {
    let intent = AiE2IntentEnvelopeV1::InferenceJob(InferenceJobIntentV1 {
        common: common(Some(AiE2ChainAnchorV1 {
            finalized_height: 42,
            finalized_hash: "dd".repeat(32),
        })),
        prompt: "bad inference".to_string(),
        inference_parameters: Some(serde_json::json!({
            "runtime": {
                "modelRuntimeHash": "aa".repeat(32),
                "tokenizerHash": "bb".repeat(32),
                "checkpointHash": "cc".repeat(32)
            },
            "orderId": "11".repeat(32)
        })),
        settlement_ref: Some(AiE2InferenceSettlementOrderRefV1::compute_order("11".repeat(32))),
    });

    let err = validate_intent_envelope_v1(&intent).unwrap_err();
    assert!(err.contains("inference_parameters_must_not_contain"));
}
