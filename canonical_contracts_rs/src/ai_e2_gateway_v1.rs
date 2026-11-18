pub const AI_E2_GATEWAY_FORMAT_VERSION_V1: u16 = 1;
pub const AI_E2_GATEWAY_CONTRACT_VERSION_V1: &str = "1.2.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiE2RequestedCapabilityV1 {
    CpuWasm,
    GpuWasm,
    Retrieval,
    Inference,
    ChainAwareWasm,
    TrustedGpu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiE2FinalStatusV1 {
    Pending,
    Running,
    Succeeded,
    Failed,
    Canceled,
}


impl Default for AiE2FinalStatusV1 {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiE2WorkflowStateV1 {
    IntentAccepted,
    JobAccepted,
    JobRunning,
    ArtifactProduced,
    ArtifactAttested,
    Failed,
    Canceled,
}

impl Default for AiE2WorkflowStateV1 {
    fn default() -> Self {
        Self::IntentAccepted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiE2CanonicalStateV1 {
    OffchainOnly,
    NotSubmitted,
    SettlementSubmitted,
    SettlementFinalized,
    SettlementRejected,
}

impl Default for AiE2CanonicalStateV1 {
    fn default() -> Self {
        Self::OffchainOnly
    }
}

impl AiE2CanonicalStateV1 {
    pub fn is_final(self) -> bool {
        matches!(self, Self::SettlementFinalized | Self::SettlementRejected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2FinalityBindingV1 {
    #[serde(default)]
    pub settlement_kind: Option<String>,
    #[serde(default)]
    pub settlement_tx_hash: Option<String>,
    #[serde(default)]
    pub settlement_height: Option<u64>,
    #[serde(default)]
    pub settlement_block_hash: Option<String>,
    #[serde(default)]
    pub finalized_height: Option<u64>,
    #[serde(default)]
    pub finalized_hash: Option<String>,
    #[serde(default)]
    pub receipt_hash: Option<String>,
    #[serde(default)]
    pub attestation_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiE2IntentKindV1 {
    Compute,
    Retrieval,
    ArtifactQuery,
    InferenceJob,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2ChainAnchorV1 {
    pub finalized_height: u64,
    pub finalized_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2InputRefV1 {
    pub input_ref: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2IntentCommonV1 {
    pub format_version: u16,
    pub tenant_id: String,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    pub user_id: String,
    pub scope_id: String,
    pub requested_capability: AiE2RequestedCapabilityV1,
    pub budget_limit: u64,
    pub time_limit_ms: u64,
    #[serde(default)]
    pub input_refs: Vec<AiE2InputRefV1>,
    #[serde(default)]
    pub required_chain_anchor: Option<AiE2ChainAnchorV1>,
    pub policy_profile: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeIntentV1 {
    #[serde(flatten)]
    pub common: AiE2IntentCommonV1,
    pub job_payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrievalIntentV1 {
    #[serde(flatten)]
    pub common: AiE2IntentCommonV1,
    pub query: String,
    #[serde(default)]
    pub top_k: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactQueryIntentV1 {
    #[serde(flatten)]
    pub common: AiE2IntentCommonV1,
    pub artifact_ref: String,
}

pub const AI_E2_INFERENCE_SETTLEMENT_ORDER_REF_FORMAT_VERSION_V1: &str =
    "newgen-ai-e2-inference-settlement-order-ref-v1";
pub const AI_E2_INFERENCE_SETTLEMENT_KIND_COMPUTE_ORDER_V1: &str = "compute_order_v1";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2InferenceSettlementOrderRefV1 {
    pub format_version: String,
    pub settlement_kind: String,
    pub order_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl AiE2InferenceSettlementOrderRefV1 {
    pub fn compute_order(order_id: impl Into<String>) -> Self {
        Self {
            format_version: AI_E2_INFERENCE_SETTLEMENT_ORDER_REF_FORMAT_VERSION_V1.to_string(),
            settlement_kind: AI_E2_INFERENCE_SETTLEMENT_KIND_COMPUTE_ORDER_V1.to_string(),
            order_id: order_id.into(),
            required: Some(true),
        }
    }

    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.format_version != AI_E2_INFERENCE_SETTLEMENT_ORDER_REF_FORMAT_VERSION_V1 {
            return Err(
                "unsupported_ai_e2_inference_settlement_order_ref_format_version".to_string(),
            );
        }
        if self.settlement_kind != AI_E2_INFERENCE_SETTLEMENT_KIND_COMPUTE_ORDER_V1 {
            return Err("unsupported_ai_e2_inference_settlement_kind".to_string());
        }
        require_bytes32_lower_hex_v1("settlement_ref.order_id", &self.order_id)?;
        if self.required == Some(false) {
            return Err("ai_e2_inference_settlement_order_ref_must_be_required".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferenceJobIntentV1 {
    #[serde(flatten)]
    pub common: AiE2IntentCommonV1,
    pub prompt: String,
    #[serde(default)]
    pub inference_parameters: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_ref: Option<AiE2InferenceSettlementOrderRefV1>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "intentKind", rename_all = "snake_case")]
pub enum AiE2IntentEnvelopeV1 {
    Compute(ComputeIntentV1),
    Retrieval(RetrievalIntentV1),
    ArtifactQuery(ArtifactQueryIntentV1),
    InferenceJob(InferenceJobIntentV1),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactLocatorV1 {
    pub artifact_id: String,
    pub role: String,
    pub content_type: String,
    pub artifact_hash: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub download_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReceiptV1 {
    pub job_id: String,
    #[serde(default)]
    pub workflow_state: AiE2WorkflowStateV1,
    #[serde(default)]
    pub canonical_state: AiE2CanonicalStateV1,
    pub final_status: AiE2FinalStatusV1,
    #[serde(default)]
    pub worker_capability_class: Option<String>,
    #[serde(default)]
    pub chain_anchor_used: Option<AiE2ChainAnchorV1>,
    #[serde(default)]
    pub attestation_ref: Option<String>,
    #[serde(default)]
    pub report_hash: Option<String>,
    #[serde(default)]
    pub finality_binding: Option<AiE2FinalityBindingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeResultArtifactV1 {
    pub job_id: String,
    pub receipt: ExecutionReceiptV1,
    #[serde(default)]
    pub primary_artifact: Option<ArtifactLocatorV1>,
    #[serde(default)]
    pub additional_artifacts: Vec<ArtifactLocatorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeResultReportV1 {
    pub job_id: String,
    #[serde(default)]
    pub workflow_state: AiE2WorkflowStateV1,
    #[serde(default)]
    pub canonical_state: AiE2CanonicalStateV1,
    pub final_status: AiE2FinalStatusV1,
    pub intent_kind: AiE2IntentKindV1,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub report_hash: Option<String>,
    #[serde(default)]
    pub worker_capability_class: Option<String>,
    #[serde(default)]
    pub chain_anchor_used: Option<AiE2ChainAnchorV1>,
    #[serde(default)]
    pub attestation_ref: Option<String>,
    #[serde(default)]
    pub finality_binding: Option<AiE2FinalityBindingV1>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2GatewayResultEnvelopeV1 {
    pub report: ComputeResultReportV1,
    #[serde(default)]
    pub artifact: Option<ComputeResultArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiE2GatewayContractSnapshotV1 {
    pub format_version: u16,
    pub gateway_contract_version: String,
    pub required_auth_header: String,
    pub max_input_refs: usize,
    pub max_budget_limit: u64,
    pub max_time_limit_ms: u64,
    pub supported_intents: Vec<AiE2IntentKindV1>,
    pub supported_requested_capabilities: Vec<AiE2RequestedCapabilityV1>,
    #[serde(default)]
    pub supported_workflow_states: Vec<AiE2WorkflowStateV1>,
    #[serde(default)]
    pub supported_canonical_states: Vec<AiE2CanonicalStateV1>,
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

fn is_bytes32_lower_hex_v1(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 64
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require_bytes32_lower_hex_v1(field: &str, value: &str) -> Result<(), String> {
    if is_bytes32_lower_hex_v1(value) {
        Ok(())
    } else {
        Err(format!("{field}_must_be_32_byte_lower_hex"))
    }
}

fn normalize_payload_binding_key_v1(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn is_forbidden_inference_parameters_binding_key_v1(key: &str) -> bool {
    let normalized = normalize_payload_binding_key_v1(key);
    [
        "settlement",
        "billing",
        "canonical",
        "finality",
        "receipt",
        "anchor",
        "order",
        "proof",
        "execution",
    ]
    .iter()
    .any(|family| normalized.contains(family))
}

fn reject_inference_parameters_binding_fields_v1(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            for key in map.keys() {
                if is_forbidden_inference_parameters_binding_key_v1(key) {
                    return Err(format!(
                        "inference_parameters_must_not_contain_settlement_or_canonical_binding_field_{key}"
                    ));
                }
            }
            for nested in map.values() {
                reject_inference_parameters_binding_fields_v1(nested)?;
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                reject_inference_parameters_binding_fields_v1(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_common(common: &AiE2IntentCommonV1) -> Result<(), String> {
    if common.format_version != AI_E2_GATEWAY_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&common.tenant_id) {
        return Err("tenant_id is required".to_string());
    }
    if is_blank(&common.user_id) {
        return Err("user_id is required".to_string());
    }
    if is_blank(&common.scope_id) {
        return Err("scope_id is required".to_string());
    }
    if common.budget_limit == 0 {
        return Err("budget_limit must be > 0".to_string());
    }
    if common.time_limit_ms == 0 {
        return Err("time_limit_ms must be > 0".to_string());
    }
    if is_blank(&common.policy_profile) {
        return Err("policy_profile is required".to_string());
    }
    if is_blank(&common.idempotency_key) {
        return Err("idempotency_key is required".to_string());
    }
    for input in &common.input_refs {
        if is_blank(&input.input_ref) {
            return Err("input_refs[].input_ref is required".to_string());
        }
    }
    if let Some(anchor) = &common.required_chain_anchor {
        if anchor.finalized_height == 0 {
            return Err("required_chain_anchor.finalized_height must be > 0".to_string());
        }
        if is_blank(&anchor.finalized_hash) {
            return Err("required_chain_anchor.finalized_hash is required".to_string());
        }
    }
    Ok(())
}

pub fn validate_intent_envelope_v1(intent: &AiE2IntentEnvelopeV1) -> Result<(), String> {
    match intent {
        AiE2IntentEnvelopeV1::Compute(req) => {
            validate_common(&req.common)?;
            if req.job_payload.is_null() {
                return Err("job_payload is required".to_string());
            }
        }
        AiE2IntentEnvelopeV1::Retrieval(req) => {
            validate_common(&req.common)?;
            if is_blank(&req.query) {
                return Err("query is required".to_string());
            }
            if matches!(req.top_k, Some(0)) {
                return Err("top_k must be > 0 when provided".to_string());
            }
        }
        AiE2IntentEnvelopeV1::ArtifactQuery(req) => {
            validate_common(&req.common)?;
            if is_blank(&req.artifact_ref) {
                return Err("artifact_ref is required".to_string());
            }
        }
        AiE2IntentEnvelopeV1::InferenceJob(req) => {
            validate_common(&req.common)?;
            if is_blank(&req.prompt) {
                return Err("prompt is required".to_string());
            }
            if let Some(params) = req.inference_parameters.as_ref() {
                reject_inference_parameters_binding_fields_v1(params)?;
            }
            if let Some(settlement_ref) = req.settlement_ref.as_ref() {
                settlement_ref.validate_contract_v1()?;
                if req.common.required_chain_anchor.is_none() {
                    return Err(
                        "inference_settlement_ref_requires_required_chain_anchor".to_string(),
                    );
                }
            }
        }
    }
    Ok(())
}
