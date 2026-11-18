pub const COMPUTE_SURFACE_FORMAT_VERSION_V1: u16 = 1;
pub const COMPUTE_RECEIVER: &str = "COMPUTE";
pub const NGBIN_MEMO_PREFIX: &str = "NGBIN1:";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeOrderStatusV1 {
    Open,
    Claimed,
    Completed,
    Failed,
    Refunded,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputePolicyV1 {
    #[serde(default)]
    pub require_trusted: bool,
    #[serde(default)]
    pub min_score: f64,
    #[serde(default)]
    pub min_reputation: f64,
    #[serde(default)]
    pub max_failures: i32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderRecordV1 {
    #[serde(default = "default_compute_surface_format_version_v1")]
    pub format_version: u16,
    pub order_id: String,
    pub payer: String,
    pub amount: u64,
    pub job_spec_hash: String,
    pub max_time_ms: u64,
    pub policy: ComputePolicyV1,
    pub status: ComputeOrderStatusV1,
    pub created_height: u64,
    pub claimed_worker: Option<String>,
    pub claim_height: Option<u64>,
    pub completed_height: Option<u64>,
    pub result_hash: Option<String>,
    pub artifact_root_hash: Option<String>,
    pub receipt_hash: Option<String>,
    pub fail_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrdersSnapshotV1 {
    #[serde(default = "default_compute_surface_format_version_v1")]
    pub format_version: u16,
    pub e2_contract_version: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub orders: Vec<ComputeOrderRecordV1>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderLookupResponseV1 {
    #[serde(default = "default_compute_surface_format_version_v1")]
    pub format_version: u16,
    pub e2_contract_version: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub found: bool,
    pub order: Option<ComputeOrderRecordV1>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderEventV1 {
    #[serde(default = "default_compute_surface_format_version_v1")]
    pub format_version: u16,
    pub order_id: String,
    pub event_type: String,
    pub tx_hash: String,
    pub height: u64,
    pub block_hash: String,
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_spec_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<ComputePolicyV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_worker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_root_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderEventsSnapshotV1 {
    #[serde(default = "default_compute_surface_format_version_v1")]
    pub format_version: u16,
    pub e2_contract_version: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub from_height: u64,
    pub to_height: u64,
    pub events: Vec<ComputeOrderEventV1>,
}


fn default_compute_surface_format_version_v1() -> u16 {
    COMPUTE_SURFACE_FORMAT_VERSION_V1
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

pub fn validate_compute_policy_v1(policy: &ComputePolicyV1) -> Result<(), String> {
    if !policy.min_score.is_finite() {
        return Err("policy.min_score must be finite".to_string());
    }
    if !policy.min_reputation.is_finite() {
        return Err("policy.min_reputation must be finite".to_string());
    }
    if policy.min_score < 0.0 {
        return Err("policy.min_score must be >= 0".to_string());
    }
    if policy.min_reputation < 0.0 {
        return Err("policy.min_reputation must be >= 0".to_string());
    }
    if policy.max_failures < 0 {
        return Err("policy.max_failures must be >= 0".to_string());
    }
    Ok(())
}

pub fn validate_compute_order_record_v1(record: &ComputeOrderRecordV1) -> Result<(), String> {
    if record.format_version != COMPUTE_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&record.order_id) {
        return Err("order_id is required".to_string());
    }
    if is_blank(&record.payer) {
        return Err("payer is required".to_string());
    }
    if is_blank(&record.job_spec_hash) {
        return Err("job_spec_hash is required".to_string());
    }
    if record.max_time_ms == 0 {
        return Err("max_time_ms must be > 0".to_string());
    }
    validate_compute_policy_v1(&record.policy)?;
    Ok(())
}

pub fn validate_compute_orders_snapshot_v1(snapshot: &ComputeOrdersSnapshotV1) -> Result<(), String> {
    if snapshot.format_version != COMPUTE_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&snapshot.e2_contract_version) {
        return Err("e2_contract_version is required".to_string());
    }
    if snapshot.finalized_height > 0 && is_blank(&snapshot.finalized_hash) {
        return Err("finalized_hash is required when finalized_height > 0".to_string());
    }
    for record in &snapshot.orders {
        validate_compute_order_record_v1(record)?;
    }
    Ok(())
}

pub fn validate_compute_order_lookup_response_v1(response: &ComputeOrderLookupResponseV1) -> Result<(), String> {
    if response.format_version != COMPUTE_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&response.e2_contract_version) {
        return Err("e2_contract_version is required".to_string());
    }
    if response.finalized_height > 0 && is_blank(&response.finalized_hash) {
        return Err("finalized_hash is required when finalized_height > 0".to_string());
    }
    if response.found != response.order.is_some() {
        return Err("found must match order presence".to_string());
    }
    if let Some(order) = &response.order {
        validate_compute_order_record_v1(order)?;
    }
    Ok(())
}

pub fn validate_compute_order_event_v1(event: &ComputeOrderEventV1) -> Result<(), String> {
    if event.format_version != COMPUTE_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&event.order_id) {
        return Err("order_id is required".to_string());
    }
    if is_blank(&event.event_type) {
        return Err("event_type is required".to_string());
    }
    if is_blank(&event.tx_hash) {
        return Err("tx_hash is required".to_string());
    }
    if is_blank(&event.block_hash) {
        return Err("block_hash is required".to_string());
    }
    if is_blank(&event.sender) {
        return Err("sender is required".to_string());
    }
    if let Some(policy) = &event.policy {
        validate_compute_policy_v1(policy)?;
    }
    Ok(())
}

pub fn validate_compute_order_events_snapshot_v1(snapshot: &ComputeOrderEventsSnapshotV1) -> Result<(), String> {
    if snapshot.format_version != COMPUTE_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&snapshot.e2_contract_version) {
        return Err("e2_contract_version is required".to_string());
    }
    if snapshot.to_height < snapshot.from_height {
        return Err("to_height must be >= from_height".to_string());
    }
    if snapshot.finalized_height > 0 && is_blank(&snapshot.finalized_hash) {
        return Err("finalized_hash is required when finalized_height > 0".to_string());
    }
    for event in &snapshot.events {
        validate_compute_order_event_v1(event)?;
    }
    Ok(())
}

pub fn validate_compute_call_v1(call: &ComputeCallV1) -> Result<(), String> {
    match call {
        ComputeCallV1::OrderCreate { job_spec_hash, max_time_ms, policy, .. } => {
            if is_blank(job_spec_hash) {
                return Err("job_spec_hash is required".to_string());
            }
            if *max_time_ms == 0 {
                return Err("max_time_ms must be > 0".to_string());
            }
            validate_compute_policy_v1(policy)?;
        }
        ComputeCallV1::OrderClaim { order_id } => {
            if is_blank(order_id) {
                return Err("order_id is required".to_string());
            }
        }
        ComputeCallV1::OrderComplete { order_id, result_hash, .. } => {
            if is_blank(order_id) {
                return Err("order_id is required".to_string());
            }
            if is_blank(result_hash) {
                return Err("result_hash is required".to_string());
            }
        }
        ComputeCallV1::OrderFail { order_id, reason, .. } => {
            if is_blank(order_id) {
                return Err("order_id is required".to_string());
            }
            if is_blank(reason) {
                return Err("reason is required".to_string());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComputeCallV1 {
    OrderCreate {
        job_spec_hash: String,
        max_time_ms: u64,
        #[serde(default)]
        policy: ComputePolicyV1,
        #[serde(default)]
        job_kind: Option<String>,
        #[serde(default)]
        job_payload: Option<serde_json::Value>,
    },
    OrderClaim {
        order_id: String,
    },
    OrderComplete {
        order_id: String,
        result_hash: String,
        #[serde(default)]
        artifact_root_hash: Option<String>,
        #[serde(default)]
        exit_code: i32,
        #[serde(default)]
        receipt_hash: Option<String>,
    },
    OrderFail {
        order_id: String,
        reason: String,
        #[serde(default)]
        receipt_hash: Option<String>,
    },
}
