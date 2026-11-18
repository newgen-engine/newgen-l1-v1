use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::transaction::Transaction;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

include!("../canonical_contracts_rs/src/compute_surface_v1.rs");

fn get_u64(v: &Value, k: &str) -> Result<u64, String> {
    v.get(k)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", k))
}

fn get_str_opt(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn get_str(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", k))
}

fn is_ngbin_memo(memo: &str) -> bool {
    memo.starts_with(NGBIN_MEMO_PREFIX)
}

pub const COMPUTE_WORKER_ADMISSION_SURFACE_VERSION_V1: &str = "compute-worker-admission-v1";
pub const COMPUTE_ORDER_SURFACE_VERSION_V2: &str = "compute-order-surface-v2";
pub const COMPUTE_WORKLOAD_CLASS_POLICY_VERSION_V1: &str = "compute-workload-class-policy-v1";

pub const COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1: &str =
    "compute-fiat-settlement-proof-v1";
pub const COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1: &str = "compute-fiat-settlement-policy-v1";
pub const COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED: &str = "SIMULATED";
pub const COMPUTE_FIAT_SETTLEMENT_MODE_TESTNET: &str = "TESTNET";
pub const COMPUTE_FIAT_SETTLEMENT_MODE_FIAT_LIVE: &str = "FIAT_LIVE";
pub const COMPUTE_FIAT_SETTLEMENT_PROOF_INGEST_PAYLOAD_VERSION_V1: &str =
    "compute-fiat-settlement-proof-ingest-v1";
pub const COMPUTE_FIAT_SETTLEMENT_PROOF_INGEST_MAX_ITEMS_V1: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeFiatSettlementProofV1 {
    pub format_version: String,
    pub settlement_mode: String,
    pub settlement_policy_version: String,
    pub order_id: String,
    pub job_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    pub worker_operator_wallet: String,
    pub billing_quote_hash: String,
    pub billing_ref_hash: String,
    pub currency: String,
    pub gross_amount_cents: u64,
    pub worker_payout_cents: u64,
    pub protocol_fee_cents: u64,
    pub reserve_cents: u64,
    pub burn_cents: u64,
    pub payment_ref_hash: Option<String>,
    pub payout_ref_hash: Option<String>,
    pub receipt_hash: String,
    pub finalized_height: u64,
}

fn validate_optional_64_hex_ref_v1(field: &str, value: &Option<String>) -> Result<(), String> {
    if let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        if value.len() != 64 || hex::decode(value).is_err() {
            return Err(format!("compute_fiat_settlement_{}_hash_invalid", field));
        }
    }
    Ok(())
}

pub fn compute_fiat_settlement_billing_ref_hash_v1(
    proof: &ComputeFiatSettlementProofV1,
) -> Result<String, String> {
    let quote_id = proof
        .quote_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("");
    let payload = serde_json::json!({
        "format_version": COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1,
        "settlement_policy_version": proof.settlement_policy_version.trim(),
        "settlement_mode": proof.settlement_mode.trim(),
        "order_id": proof.order_id.trim(),
        "job_id": proof.job_id.trim(),
        "quote_id": quote_id,
        "worker_operator_wallet": proof.worker_operator_wallet.trim(),
        "billing_quote_hash": proof.billing_quote_hash.trim(),
        "currency": proof.currency.trim(),
        "gross_amount_cents": proof.gross_amount_cents,
        "worker_payout_cents": proof.worker_payout_cents,
        "protocol_fee_cents": proof.protocol_fee_cents,
        "reserve_cents": proof.reserve_cents,
        "burn_cents": proof.burn_cents,
        "payment_ref_hash": proof.payment_ref_hash.as_deref().map(str::trim).unwrap_or(""),
        "payout_ref_hash": proof.payout_ref_hash.as_deref().map(str::trim).unwrap_or(""),
        "receipt_hash": proof.receipt_hash.trim(),
        "finalized_height": proof.finalized_height,
    });
    let encoded = serde_json::to_vec(&payload)
        .map_err(|e| format!("compute_fiat_settlement_billing_ref_hash_serialize:{e}"))?;
    Ok(hex::encode(Sha256::digest(&encoded)))
}

impl ComputeFiatSettlementProofV1 {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        self.validate_contract_with_fiat_live_policy_v1(false)
    }

    pub fn validate_contract_with_fiat_live_policy_v1(
        &self,
        allow_fiat_live: bool,
    ) -> Result<(), String> {
        if self.format_version.trim() != COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1 {
            return Err("compute_fiat_settlement_format_version_mismatch".to_string());
        }
        if self.settlement_policy_version.trim() != COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1 {
            return Err("compute_fiat_settlement_policy_version_mismatch".to_string());
        }
        match self.settlement_mode.trim() {
            COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED | COMPUTE_FIAT_SETTLEMENT_MODE_TESTNET => {}
            COMPUTE_FIAT_SETTLEMENT_MODE_FIAT_LIVE if allow_fiat_live => {}
            COMPUTE_FIAT_SETTLEMENT_MODE_FIAT_LIVE => {
                return Err("compute_fiat_settlement_fiat_live_disabled".to_string())
            }
            other => return Err(format!("compute_fiat_settlement_mode_invalid:{other}")),
        }
        if self.currency.trim() != "EUR" {
            return Err("compute_fiat_settlement_currency_must_be_eur".to_string());
        }
        for (field, value) in [
            ("order_id", self.order_id.as_str()),
            ("job_id", self.job_id.as_str()),
            (
                "worker_operator_wallet",
                self.worker_operator_wallet.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(format!("compute_fiat_settlement_{field}_invalid"));
            }
        }
        if let Some(quote_id) = self.quote_id.as_deref() {
            if quote_id.trim().is_empty() || quote_id.len() > 128 {
                return Err("compute_fiat_settlement_quote_id_invalid".to_string());
            }
        }
        if self.billing_quote_hash.len() != 64 || hex::decode(&self.billing_quote_hash).is_err() {
            return Err("compute_fiat_settlement_billing_quote_hash_invalid".to_string());
        }
        if self.billing_ref_hash.len() != 64 || hex::decode(&self.billing_ref_hash).is_err() {
            return Err("compute_fiat_settlement_billing_ref_hash_invalid".to_string());
        }
        let expected_billing_ref = compute_fiat_settlement_billing_ref_hash_v1(self)?;
        if !self
            .billing_ref_hash
            .eq_ignore_ascii_case(&expected_billing_ref)
        {
            return Err("compute_fiat_settlement_billing_ref_hash_mismatch".to_string());
        }
        if self.receipt_hash.len() != 64 || hex::decode(&self.receipt_hash).is_err() {
            return Err("compute_fiat_settlement_receipt_hash_invalid".to_string());
        }
        validate_optional_64_hex_ref_v1("payment_ref", &self.payment_ref_hash)?;
        validate_optional_64_hex_ref_v1("payout_ref", &self.payout_ref_hash)?;
        let split_total = self
            .worker_payout_cents
            .checked_add(self.protocol_fee_cents)
            .and_then(|v| v.checked_add(self.reserve_cents))
            .and_then(|v| v.checked_add(self.burn_cents))
            .ok_or_else(|| "compute_fiat_settlement_split_overflow".to_string())?;
        if split_total != self.gross_amount_cents {
            return Err(format!(
                "compute_fiat_settlement_split_mismatch:{}!={}",
                split_total, self.gross_amount_cents
            ));
        }
        if self.gross_amount_cents > 0 && self.worker_payout_cents == 0 {
            return Err(
                "compute_fiat_settlement_worker_payout_required_for_positive_gross".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeFiatSettlementProofIngestPayloadV1 {
    pub format_version: String,
    pub proofs: Vec<ComputeFiatSettlementProofV1>,
}

impl ComputeFiatSettlementProofIngestPayloadV1 {
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.format_version.trim() != COMPUTE_FIAT_SETTLEMENT_PROOF_INGEST_PAYLOAD_VERSION_V1 {
            return Err("compute_fiat_settlement_ingest_format_version_mismatch".to_string());
        }
        if self.proofs.is_empty() {
            return Err("compute_fiat_settlement_ingest_empty".to_string());
        }
        if self.proofs.len() > COMPUTE_FIAT_SETTLEMENT_PROOF_INGEST_MAX_ITEMS_V1 {
            return Err("compute_fiat_settlement_ingest_too_many_items".to_string());
        }
        let mut order_ids = std::collections::BTreeSet::new();
        for proof in &self.proofs {
            proof.validate_contract_v1()?;
            if !order_ids.insert(proof.order_id.trim().to_string()) {
                return Err("compute_fiat_settlement_ingest_duplicate_order_id".to_string());
            }
        }
        Ok(())
    }
}

pub const E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1: &str = "e2-worker-self-register-v1";
pub const E2_WORKER_SELF_REGISTER_OP_V1: &str = "worker_register_v1";
pub const E2_WORKER_SELF_REGISTER_SIGNATURE_CONTEXT_V1: &[u8] = b"E2_WORKER_SELF_REGISTER_V1";
pub const E2_WORKER_SELF_REGISTER_MAX_RUNTIME_CLASS_BYTES_V1: usize = 64;
pub const E2_WORKER_SELF_REGISTER_MAX_REGION_BYTES_V1: usize = 64;
pub const E2_WORKER_SELF_REGISTER_MAX_COUNTRY_BYTES_V1: usize = 16;

pub const E2_WORKER_EVIDENCE_SUBMIT_PAYLOAD_VERSION_V1: &str = "e2-worker-evidence-submit-v1";
pub const E2_WORKER_EVIDENCE_SUBMIT_OP_V1: &str = "worker_evidence_submit_v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerEvidenceSubmitPayloadV1 {
    pub format_version: String,
    pub evidence: crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1,
}

impl E2WorkerEvidenceSubmitPayloadV1 {
    pub fn validate_contract_shape_v1(&self) -> Result<(), String> {
        if self.format_version.trim() != E2_WORKER_EVIDENCE_SUBMIT_PAYLOAD_VERSION_V1 {
            return Err("e2_worker_evidence_submit_bad_format_version".to_string());
        }
        crate::e2_worker_evidence::verify_e2_worker_evidence_signature_any_v1(&self.evidence)
            .map_err(|e| format!("e2_worker_evidence_submit_evidence_invalid:{e}"))?;
        Ok(())
    }
}

fn parse_e2_worker_evidence_submit_payload_from_value_v1(
    v: &Value,
) -> Result<E2WorkerEvidenceSubmitPayloadV1, String> {
    let mut payload = v.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("v");
        obj.remove("op");
    }
    serde_json::from_value(payload)
        .map_err(|e| format!("e2_worker_evidence_submit_payload_invalid:{e}"))
}

pub fn parse_e2_worker_evidence_submit_tx_v1(
    tx: &Transaction,
) -> Result<Option<E2WorkerEvidenceSubmitPayloadV1>, String> {
    if tx.receiver != COMPUTE_RECEIVER {
        return Ok(None);
    }
    let Some(memo) = tx.memo.as_ref() else {
        return Ok(None);
    };
    if is_ngbin_memo(memo) {
        return Ok(None);
    }
    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("compute_memo_json_invalid: {e}"))?;
    let ver = v.get("v").and_then(|x| x.as_u64()).unwrap_or(0);
    if ver != 1 {
        return Ok(None);
    }
    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("");
    if op != E2_WORKER_EVIDENCE_SUBMIT_OP_V1 {
        return Ok(None);
    }
    Ok(Some(parse_e2_worker_evidence_submit_payload_from_value_v1(
        &v,
    )?))
}

pub fn is_e2_worker_evidence_submit_tx_v1(tx: &Transaction) -> bool {
    matches!(parse_e2_worker_evidence_submit_tx_v1(tx), Ok(Some(_)))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2WorkerSelfRegistrationPayloadV1 {
    pub format_version: String,
    pub worker_node_pubkey: String,
    pub operator_wallet_pubkey: String,
    pub worker_signature: String,
    pub capabilities_commitment_hash: String,
    pub runtime_class: String,
    pub chain_id: String,
    pub genesis_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

fn is_lower_hex_64_v1(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn validate_compute_token_v1(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_bytes {
        return Err(format!("e2_worker_self_register_{field}_invalid"));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(format!("e2_worker_self_register_{field}_invalid_chars"));
    }
    Ok(())
}

impl E2WorkerSelfRegistrationPayloadV1 {
    pub fn canonical_identities_v1(&self) -> Result<(String, String), String> {
        let worker_hex = crate::keyfmt::pk_hex_from_any(&self.worker_node_pubkey)
            .map_err(|e| format!("e2_worker_self_register_worker_invalid:{e}"))?;
        let operator_hex = crate::keyfmt::pk_hex_from_any(&self.operator_wallet_pubkey)
            .map_err(|e| format!("e2_worker_self_register_operator_invalid:{e}"))?;
        if worker_hex == operator_hex {
            return Err("e2_worker_self_register_requires_distinct_identities".to_string());
        }
        Ok((worker_hex, operator_hex))
    }

    pub fn validate_unsigned_contract_shape_v1(&self) -> Result<(String, String), String> {
        if self.format_version.trim() != E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1 {
            return Err("e2_worker_self_register_bad_format_version".to_string());
        }
        let (worker_hex, operator_hex) = self.canonical_identities_v1()?;
        let cap = self.capabilities_commitment_hash.trim();
        if !is_lower_hex_64_v1(cap) {
            return Err("e2_worker_self_register_capabilities_commitment_hash_invalid".to_string());
        }
        validate_compute_token_v1(
            "runtime_class",
            &self.runtime_class,
            E2_WORKER_SELF_REGISTER_MAX_RUNTIME_CLASS_BYTES_V1,
        )?;
        validate_compute_token_v1("chain_id", &self.chain_id, 128)?;
        let genesis = self.genesis_hash.trim();
        if !is_lower_hex_64_v1(genesis) {
            return Err("e2_worker_self_register_genesis_hash_invalid".to_string());
        }
        if let Some(region) = self.region.as_deref() {
            validate_compute_token_v1(
                "region",
                region,
                E2_WORKER_SELF_REGISTER_MAX_REGION_BYTES_V1,
            )?;
        }
        if let Some(country) = self.country.as_deref() {
            validate_compute_token_v1(
                "country",
                country,
                E2_WORKER_SELF_REGISTER_MAX_COUNTRY_BYTES_V1,
            )?;
        }
        Ok((worker_hex, operator_hex))
    }

    pub fn validate_unsigned_contract_v1(
        &self,
        expected_chain_id: &str,
        expected_genesis_hash: &str,
    ) -> Result<(String, String), String> {
        let ids = self.validate_unsigned_contract_shape_v1()?;
        if self.chain_id.trim() != expected_chain_id.trim() {
            return Err("e2_worker_self_register_chain_id_mismatch".to_string());
        }
        if self.genesis_hash.trim() != expected_genesis_hash.trim() {
            return Err("e2_worker_self_register_genesis_hash_mismatch".to_string());
        }
        Ok(ids)
    }

    pub fn validate_contract_shape_v1(&self) -> Result<(String, String), String> {
        let ids = self.validate_unsigned_contract_shape_v1()?;
        self.verify_worker_signature_v1()?;
        Ok(ids)
    }

    pub fn validate_contract_v1(
        &self,
        expected_chain_id: &str,
        expected_genesis_hash: &str,
    ) -> Result<(String, String), String> {
        let ids = self.validate_unsigned_contract_v1(expected_chain_id, expected_genesis_hash)?;
        self.verify_worker_signature_v1()?;
        Ok(ids)
    }

    pub fn verify_worker_signature_v1(&self) -> Result<(), String> {
        crate::crypto::verify_ds_b64(
            &self.worker_node_pubkey,
            &self.worker_signature,
            E2_WORKER_SELF_REGISTER_SIGNATURE_CONTEXT_V1,
            &e2_worker_self_registration_signing_bytes_v1(self)?,
        )
        .map_err(|e| format!("e2_worker_self_register_worker_signature_invalid:{e}"))
    }
}

pub fn e2_worker_self_registration_signing_bytes_v1(
    payload: &E2WorkerSelfRegistrationPayloadV1,
) -> Result<Vec<u8>, String> {
    let (worker_hex, operator_hex) = payload.canonical_identities_v1()?;
    let region = payload.region.as_deref().map(str::trim).unwrap_or("");
    let country = payload.country.as_deref().map(str::trim).unwrap_or("");
    Ok(format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1,
        payload.chain_id.trim(),
        payload.genesis_hash.trim(),
        worker_hex,
        operator_hex,
        payload.capabilities_commitment_hash.trim(),
        payload.runtime_class.trim(),
        region,
        country
    )
    .into_bytes())
}

fn parse_e2_worker_self_registration_payload_from_value_v1(
    v: &Value,
) -> Result<E2WorkerSelfRegistrationPayloadV1, String> {
    let mut payload = v.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("v");
        obj.remove("op");
    }
    serde_json::from_value(payload)
        .map_err(|e| format!("e2_worker_self_register_payload_invalid:{e}"))
}

pub fn parse_e2_worker_self_registration_tx_v1(
    tx: &Transaction,
) -> Result<Option<E2WorkerSelfRegistrationPayloadV1>, String> {
    if tx.receiver != COMPUTE_RECEIVER {
        return Ok(None);
    }
    let Some(memo) = tx.memo.as_ref() else {
        return Ok(None);
    };
    if is_ngbin_memo(memo) {
        return Ok(None);
    }
    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("compute_memo_json_invalid: {e}"))?;
    let ver = v.get("v").and_then(|x| x.as_u64()).unwrap_or(0);
    if ver != 1 {
        return Ok(None);
    }
    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("");
    if op != E2_WORKER_SELF_REGISTER_OP_V1 {
        return Ok(None);
    }
    Ok(Some(
        parse_e2_worker_self_registration_payload_from_value_v1(&v)?,
    ))
}

pub fn is_e2_worker_self_registration_tx_v1(tx: &Transaction) -> bool {
    matches!(parse_e2_worker_self_registration_tx_v1(tx), Ok(Some(_)))
}

fn default_compute_admission_source_commitment_v1() -> String {
    "finalized".to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeWorkerAdmissionDecisionV1 {
    pub surface_version: String,
    pub order_id: Option<String>,
    pub worker_pubkey: String,
    pub worker_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_wallet_pubkey: Option<String>,
    #[serde(default)]
    pub cloud_unit_allowed: bool,
    #[serde(default)]
    pub gpu_allowed: bool,
    #[serde(default)]
    pub long_running_allowed: bool,
    pub accepted: bool,
    pub deny_reason: Option<String>,
    pub required_min_score: i32,
    pub required_risk_class: String,
    pub policy_require_trusted: bool,
    pub policy_max_failures: i32,
    pub source_height: u64,
    #[serde(default = "default_compute_admission_source_commitment_v1")]
    pub source_commitment: String,
    pub reputation_surface_version: String,
    pub score_formula_version: String,
    pub policy_version: String,
    pub effective_score: i32,
    pub eligibility_state: String,
    pub max_risk_class: String,
    pub accepted_negative_run_evidence_count: u64,
}

fn normalize_compute_policy_reputation_score_v1(value: f64) -> Result<i32, String> {
    if !value.is_finite() || value < 0.0 {
        return Err("compute_admission_policy_score_invalid".to_string());
    }
    let normalized = if value <= 1.0 {
        value * crate::reputation_score::REPUTATION_SCORE_MAX_V1 as f64
    } else {
        value
    };
    if normalized > crate::reputation_score::REPUTATION_SCORE_MAX_V1 as f64 {
        return Err("compute_admission_policy_score_out_of_range".to_string());
    }
    Ok(normalized.ceil() as i32)
}

#[allow(dead_code)]
fn normalize_compute_policy_score_bps_v1(value: f64) -> Result<i32, String> {
    normalize_compute_policy_reputation_score_v1(value)
}

fn compute_risk_rank_v1(risk: &str) -> Option<u8> {
    match risk.trim().to_ascii_uppercase().as_str() {
        "NONE" => Some(0),
        "LOW" => Some(1),
        "STANDARD" => Some(2),
        "HIGH" => Some(3),
        "CRITICAL" => Some(4),
        _ => None,
    }
}

fn required_compute_risk_class_v1(
    policy: &ComputePolicyV1,
    required_min_score: i32,
) -> &'static str {
    if policy.require_trusted || required_min_score >= 950 {
        "CRITICAL"
    } else if required_min_score >= 920 {
        "HIGH"
    } else if required_min_score >= 850 {
        "STANDARD"
    } else {
        "LOW"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredComputeWorkloadClassV1 {
    Base,
    CloudUnit,
    LongRunning,
    Gpu,
    Critical,
}

fn required_compute_workload_class_v1(
    policy: &ComputePolicyV1,
    required_min_score: i32,
    requested_max_time_ms: u64,
) -> RequiredComputeWorkloadClassV1 {
    if policy.require_trusted
        || required_min_score >= crate::reputation_score::WORKER_CRITICAL_MIN_SCORE_V1
    {
        RequiredComputeWorkloadClassV1::Critical
    } else if required_min_score >= crate::reputation_score::WORKER_GPU_MIN_SCORE_V1 {
        RequiredComputeWorkloadClassV1::Gpu
    } else if required_min_score >= crate::reputation_score::WORKER_LONG_RUNNING_MIN_SCORE_V1
        || requested_max_time_ms > 3_600_000
    {
        RequiredComputeWorkloadClassV1::LongRunning
    } else if required_min_score >= crate::reputation_score::WORKER_CLOUD_UNIT_MIN_SCORE_V1 {
        RequiredComputeWorkloadClassV1::CloudUnit
    } else {
        RequiredComputeWorkloadClassV1::Base
    }
}

fn required_compute_workload_class_from_job_kind_v1(
    job_kind: Option<&str>,
) -> Result<RequiredComputeWorkloadClassV1, String> {
    let raw = job_kind
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "compute_job_kind_missing".to_string())?;
    if raw.len() > 64 {
        return Err("compute_job_kind_too_long".to_string());
    }
    let kind = raw
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(':', "_");

    let class = match kind.as_str() {
        "hash_sha256_v1" | "json_validate_v1" | "text_stats_v1" | "manifest_verify_v1" | "wasm"
        | "wasm_v1" | "wasm_job_v1" | "base_cpu" | "base_cpu_v1" => {
            RequiredComputeWorkloadClassV1::Base
        }
        "cloud_unit"
        | "cloud_unit_v1"
        | "cloud_unit_lease_v1"
        | "cloud_unit_session_v1"
        | "cloud_unit_native_v1"
        | "compute_instance_v1"
        | "compute_instance_lease_v1" => RequiredComputeWorkloadClassV1::CloudUnit,
        "cloud_unit_long_running_v1"
        | "long_running_v1"
        | "long_running_service_v1"
        | "http_service_v1"
        | "jupyter_session_v1"
        | "persistent_session_v1" => RequiredComputeWorkloadClassV1::LongRunning,
        "gpu"
        | "gpu_v1"
        | "gpu_job_v1"
        | "gpu_inference_v1"
        | "gpu_training_v1"
        | "gpu_lease_v1"
        | "gpu_runtime_benchmark_v1" => RequiredComputeWorkloadClassV1::Gpu,
        "critical"
        | "critical_v1"
        | "critical_workload_v1"
        | "critical_job_v1"
        | "critical_inference_v1" => RequiredComputeWorkloadClassV1::Critical,
        _ => {
            return Err(format!("compute_job_kind_unknown_or_unclassified:{raw}"));
        }
    };
    Ok(class)
}

fn required_compute_workload_class_for_order_v1(
    policy: &ComputePolicyV1,
    required_min_score: i32,
    requested_max_time_ms: u64,
    job_kind: Option<&str>,
) -> Result<RequiredComputeWorkloadClassV1, String> {
    let policy_class =
        required_compute_workload_class_v1(policy, required_min_score, requested_max_time_ms);
    let job_class = required_compute_workload_class_from_job_kind_v1(job_kind)?;
    Ok(policy_class.max(job_class))
}

fn validate_compute_order_create_policy_and_kind_v1(
    policy: &ComputePolicyV1,
    max_time_ms: u64,
    job_kind: Option<&str>,
) -> Result<(), String> {
    let required_min_score = normalize_compute_policy_reputation_score_v1(policy.min_score)?
        .max(normalize_compute_policy_reputation_score_v1(
            policy.min_reputation,
        )?)
        .max(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
    required_compute_workload_class_for_order_v1(policy, required_min_score, max_time_ms, job_kind)
        .map(|_| ())
}

fn required_compute_workload_class_name_v1(class: RequiredComputeWorkloadClassV1) -> &'static str {
    match class {
        RequiredComputeWorkloadClassV1::Base => "BASE",
        RequiredComputeWorkloadClassV1::CloudUnit => "CLOUD_UNIT",
        RequiredComputeWorkloadClassV1::LongRunning => "LONG_RUNNING",
        RequiredComputeWorkloadClassV1::Gpu => "GPU",
        RequiredComputeWorkloadClassV1::Critical => "CRITICAL",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderRuntimeMetadataV1 {
    pub job_kind: String,
    pub required_workload_class: RequiredComputeWorkloadClassV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderStateStoreV1 {
    pub format_version: String,
    pub e2_contract_version: String,
    pub first_applied_height: u64,
    pub last_applied_height: u64,
    pub last_applied_hash: String,
    pub complete_from_genesis: bool,
    pub required_job_kind_activation_height: u64,
    pub orders: BTreeMap<String, ComputeOrderRecordV1>,
    pub metadata_by_order_id: BTreeMap<String, ComputeOrderRuntimeMetadataV1>,
    #[serde(default)]
    pub events_by_height: BTreeMap<u64, Vec<ComputeOrderEventV1>>,
    #[serde(default)]
    pub block_hash_by_height: BTreeMap<u64, String>,
}

impl Default for ComputeOrderStateStoreV1 {
    fn default() -> Self {
        Self {
            format_version: "compute-order-state-store-v1".to_string(),
            e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
            first_applied_height: 0,
            last_applied_height: 0,
            last_applied_hash: String::new(),
            complete_from_genesis: false,
            required_job_kind_activation_height: 0,
            orders: BTreeMap::new(),
            metadata_by_order_id: BTreeMap::new(),
            events_by_height: BTreeMap::new(),
            block_hash_by_height: BTreeMap::new(),
        }
    }
}

struct ComputeOrdersInternalSnapshotV1 {
    snapshot: ComputeOrdersSnapshotV1,
    metadata_by_order_id: BTreeMap<String, ComputeOrderRuntimeMetadataV1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderRecordV2 {
    #[serde(flatten)]
    pub order: ComputeOrderRecordV1,
    pub job_kind: String,
    pub required_workload_class: String,
    pub workload_class_policy_version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrdersSnapshotV2 {
    pub format_version: String,
    pub legacy_format_version: String,
    pub e2_contract_version: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub orders: Vec<ComputeOrderRecordV2>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOrderLookupResponseV2 {
    pub format_version: String,
    pub legacy_format_version: String,
    pub e2_contract_version: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<ComputeOrderRecordV2>,
}

fn compute_order_record_v2_from_record_and_metadata_v1(
    order: ComputeOrderRecordV1,
    metadata: &ComputeOrderRuntimeMetadataV1,
) -> ComputeOrderRecordV2 {
    ComputeOrderRecordV2 {
        order,
        job_kind: metadata.job_kind.clone(),
        required_workload_class: required_compute_workload_class_name_v1(
            metadata.required_workload_class,
        )
        .to_string(),
        workload_class_policy_version: COMPUTE_WORKLOAD_CLASS_POLICY_VERSION_V1.to_string(),
    }
}

#[cfg(test)]
fn evaluate_compute_worker_admission_against_node_surface_v1(
    worker_pubkey: &str,
    order_id: Option<String>,
    policy: &ComputePolicyV1,
    surface: &crate::reputation_score::CanonicalNodeReputationSurfaceV1,
) -> Result<ComputeWorkerAdmissionDecisionV1, String> {
    let worker_hex = crate::keyfmt::pk_hex_from_any(worker_pubkey)
        .unwrap_or_else(|_| worker_pubkey.trim().to_ascii_lowercase());
    let required_min_score = normalize_compute_policy_reputation_score_v1(policy.min_score)?.max(
        normalize_compute_policy_reputation_score_v1(policy.min_reputation)?,
    );
    let required_risk_class =
        required_compute_risk_class_v1(policy, required_min_score).to_string();
    let mut accepted = true;
    let mut deny_reason: Option<String> = None;

    if surface.node_pubkey != worker_hex {
        accepted = false;
        deny_reason = Some("WORKER_SURFACE_ID_MISMATCH".to_string());
    } else if surface.eligibility_state != "ELIGIBLE" {
        accepted = false;
        deny_reason = Some(format!(
            "WORKER_NOT_ELIGIBLE:{}:{}",
            surface.eligibility_state,
            surface
                .deny_reason
                .clone()
                .unwrap_or_else(|| "n/a".to_string())
        ));
    } else if surface.effective_score < required_min_score {
        accepted = false;
        deny_reason = Some(format!(
            "WORKER_SCORE_BELOW_POLICY:{}<{}",
            surface.effective_score, required_min_score
        ));
    } else {
        let worker_rank = compute_risk_rank_v1(&surface.max_risk_class)
            .ok_or_else(|| "compute_worker_reputation_surface_bad_risk_class".to_string())?;
        let required_rank = compute_risk_rank_v1(&required_risk_class)
            .ok_or_else(|| "compute_required_risk_class_invalid".to_string())?;
        if worker_rank < required_rank {
            accepted = false;
            deny_reason = Some(format!(
                "WORKER_RISK_CLASS_TOO_LOW:{}<{}",
                surface.max_risk_class, required_risk_class
            ));
        }
    }

    if accepted && policy.max_failures >= 0 {
        let max_failures = policy.max_failures as u64;
        if surface.accepted_negative_run_evidence_count > max_failures {
            accepted = false;
            deny_reason = Some(format!(
                "WORKER_FAILURE_COUNT_EXCEEDS_POLICY:{}>{}",
                surface.accepted_negative_run_evidence_count, max_failures
            ));
        }
    }

    Ok(ComputeWorkerAdmissionDecisionV1 {
        surface_version: COMPUTE_WORKER_ADMISSION_SURFACE_VERSION_V1.to_string(),
        order_id,
        worker_pubkey: worker_pubkey.trim().to_string(),
        worker_pubkey_hex: worker_hex,
        operator_wallet_pubkey: None,
        cloud_unit_allowed: accepted,
        gpu_allowed: false,
        long_running_allowed: false,
        accepted,
        deny_reason,
        required_min_score,
        required_risk_class,
        policy_require_trusted: policy.require_trusted,
        policy_max_failures: policy.max_failures,
        source_height: surface.source_height,
        source_commitment: "finalized".to_string(),
        reputation_surface_version: surface.reputation_surface_version.clone(),
        score_formula_version: surface.score_formula_version.clone(),
        policy_version: surface.policy_version.clone(),
        effective_score: surface.effective_score,
        eligibility_state: surface.eligibility_state.clone(),
        max_risk_class: surface.max_risk_class.clone(),
        accepted_negative_run_evidence_count: surface.accepted_negative_run_evidence_count,
    })
}

fn evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
    worker_pubkey: &str,
    order_id: Option<String>,
    policy: &ComputePolicyV1,
    eligibility: &crate::reputation_score::CanonicalWorkerEligibilityV1,
    requested_max_time_ms: u64,
    job_kind: Option<&str>,
) -> Result<ComputeWorkerAdmissionDecisionV1, String> {
    eligibility.validate_contract_v1()?;

    let worker_hex = crate::keyfmt::pk_hex_from_any(worker_pubkey)
        .unwrap_or_else(|_| worker_pubkey.trim().to_ascii_lowercase());
    let required_min_score = normalize_compute_policy_reputation_score_v1(policy.min_score)?
        .max(normalize_compute_policy_reputation_score_v1(
            policy.min_reputation,
        )?)
        .max(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
    let required_risk_class =
        required_compute_risk_class_v1(policy, required_min_score).to_string();
    let required_workload_class = required_compute_workload_class_for_order_v1(
        policy,
        required_min_score,
        requested_max_time_ms,
        job_kind,
    )?;
    let mut accepted = true;
    let mut deny_reason: Option<String> = None;

    if eligibility.worker_node_pubkey != worker_hex {
        accepted = false;
        deny_reason = Some("WORKER_ELIGIBILITY_ID_MISMATCH".to_string());
    } else if !eligibility
        .source_commitment
        .trim()
        .eq_ignore_ascii_case("finalized")
        || eligibility.source_height > eligibility.finalized_height
    {
        accepted = false;
        deny_reason = Some("WORKER_REPUTATION_VIEW_NOT_FINALIZED".to_string());
    } else if eligibility.eligibility_state != "ACTIVE" {
        accepted = false;
        let detail = eligibility
            .deny_reason
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or("unspecified");
        deny_reason = Some(format!(
            "WORKER_NOT_ACTIVE:{}:{}",
            eligibility.eligibility_state, detail
        ));
    } else if !eligibility.eligible_for_non_probe {
        accepted = false;
        deny_reason = eligibility
            .deny_reason
            .clone()
            .or_else(|| Some("WORKER_NON_PROBE_NOT_ALLOWED".to_string()));
    } else if policy.require_trusted && !eligibility.critical_workload_allowed {
        accepted = false;
        deny_reason = Some("WORKER_CRITICAL_WORKLOAD_NOT_ALLOWED".to_string());
    } else if requested_max_time_ms > 0 {
        let allowed_ms = eligibility.max_job_duration_sec.saturating_mul(1_000);
        if allowed_ms == 0 || requested_max_time_ms > allowed_ms {
            accepted = false;
            deny_reason = Some(format!(
                "WORKER_JOB_DURATION_EXCEEDS_ELIGIBILITY:{}>{}",
                requested_max_time_ms, allowed_ms
            ));
        }
    }

    if accepted {
        if eligibility.effective_score < required_min_score {
            accepted = false;
            deny_reason = Some(format!(
                "WORKER_SCORE_BELOW_POLICY:{}<{}",
                eligibility.effective_score, required_min_score
            ));
        } else {
            match required_workload_class {
                RequiredComputeWorkloadClassV1::Base => {}
                RequiredComputeWorkloadClassV1::CloudUnit if !eligibility.cloud_unit_allowed => {
                    accepted = false;
                    deny_reason = Some("WORKER_CLOUD_UNIT_NOT_ALLOWED".to_string());
                }
                RequiredComputeWorkloadClassV1::LongRunning
                    if !eligibility.long_running_allowed =>
                {
                    accepted = false;
                    deny_reason = Some("WORKER_LONG_RUNNING_NOT_ALLOWED".to_string());
                }
                RequiredComputeWorkloadClassV1::Gpu if !eligibility.gpu_allowed => {
                    accepted = false;
                    deny_reason = Some("WORKER_GPU_NOT_ALLOWED".to_string());
                }
                RequiredComputeWorkloadClassV1::Critical
                    if !eligibility.critical_workload_allowed =>
                {
                    accepted = false;
                    deny_reason = Some("WORKER_CRITICAL_WORKLOAD_NOT_ALLOWED".to_string());
                }
                _ => {}
            }
            if accepted {
                let worker_rank = compute_risk_rank_v1(&eligibility.max_risk_class)
                    .ok_or_else(|| "compute_worker_eligibility_bad_risk_class".to_string())?;
                let required_rank = compute_risk_rank_v1(&required_risk_class)
                    .ok_or_else(|| "compute_required_risk_class_invalid".to_string())?;
                if worker_rank < required_rank {
                    accepted = false;
                    deny_reason = Some(format!(
                        "WORKER_RISK_CLASS_TOO_LOW:{}<{}:{}",
                        eligibility.max_risk_class,
                        required_risk_class,
                        required_compute_workload_class_name_v1(required_workload_class)
                    ));
                }
            }
        }
    }

    Ok(ComputeWorkerAdmissionDecisionV1 {
        surface_version: COMPUTE_WORKER_ADMISSION_SURFACE_VERSION_V1.to_string(),
        order_id,
        worker_pubkey: worker_pubkey.trim().to_string(),
        worker_pubkey_hex: worker_hex,
        operator_wallet_pubkey: Some(eligibility.operator_wallet_pubkey.clone()),
        cloud_unit_allowed: eligibility.cloud_unit_allowed,
        gpu_allowed: eligibility.gpu_allowed,
        long_running_allowed: eligibility.long_running_allowed,
        accepted,
        deny_reason,
        required_min_score,
        required_risk_class,
        policy_require_trusted: policy.require_trusted,
        policy_max_failures: policy.max_failures,
        source_height: eligibility.source_height,
        source_commitment: "finalized".to_string(),
        reputation_surface_version: eligibility.format_version.clone(),
        score_formula_version: crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1
            .to_string(),
        policy_version: eligibility.policy_version.clone(),
        effective_score: eligibility.effective_score,
        eligibility_state: eligibility.eligibility_state.clone(),
        max_risk_class: eligibility.max_risk_class.clone(),
        accepted_negative_run_evidence_count: 0,
    })
}

fn evaluate_compute_worker_admission_against_worker_eligibility_with_order_limits_v1(
    worker_pubkey: &str,
    order_id: Option<String>,
    policy: &ComputePolicyV1,
    eligibility: &crate::reputation_score::CanonicalWorkerEligibilityV1,
    requested_max_time_ms: u64,
) -> Result<ComputeWorkerAdmissionDecisionV1, String> {
    evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
        worker_pubkey,
        order_id,
        policy,
        eligibility,
        requested_max_time_ms,
        Some("base_cpu_v1"),
    )
}

pub fn evaluate_compute_worker_admission_against_worker_eligibility_v1(
    worker_pubkey: &str,
    order_id: Option<String>,
    policy: &ComputePolicyV1,
    eligibility: &crate::reputation_score::CanonicalWorkerEligibilityV1,
) -> Result<ComputeWorkerAdmissionDecisionV1, String> {
    evaluate_compute_worker_admission_against_worker_eligibility_with_order_limits_v1(
        worker_pubkey,
        order_id,
        policy,
        eligibility,
        0,
    )
}

pub fn evaluate_compute_worker_admission_for_finalized_order_v1(
    bc: &Blockchain,
    worker_pubkey: &str,
    order_id: &str,
) -> Result<ComputeWorkerAdmissionDecisionV1, String> {
    let internal = compute_orders_internal_snapshot_for_finalized_chain(bc)?;
    let Some(order) = internal
        .snapshot
        .orders
        .iter()
        .find(|o| o.order_id == order_id)
        .cloned()
    else {
        return Err("compute_worker_admission_order_not_found_finalized".to_string());
    };
    if order.status != ComputeOrderStatusV1::Open {
        return Err("compute_worker_admission_order_not_open_finalized".to_string());
    }
    let metadata = internal
        .metadata_by_order_id
        .get(order_id)
        .ok_or_else(|| "compute_order_required_workload_class_missing_finalized".to_string())?;
    let eligibility = bc
        .canonical_worker_eligibility_finalized_for_worker_v1(worker_pubkey)
        .ok_or_else(|| "compute_worker_eligibility_surface_not_found_finalized".to_string())?;
    let decision =
        evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
            worker_pubkey,
            Some(order_id.to_string()),
            &order.policy,
            &eligibility,
            order.max_time_ms,
            Some(metadata.job_kind.as_str()),
        )?;
    let required_name = required_compute_workload_class_name_v1(metadata.required_workload_class);
    if decision.accepted {
        let accepted_class = required_compute_workload_class_for_order_v1(
            &order.policy,
            decision.required_min_score,
            order.max_time_ms,
            Some(metadata.job_kind.as_str()),
        )?;
        if accepted_class != metadata.required_workload_class {
            return Err(format!(
                "compute_order_required_workload_class_mismatch:{}!={}",
                required_compute_workload_class_name_v1(accepted_class),
                required_name
            ));
        }
    }
    Ok(decision)
}

pub fn validate_compute_tx_worker_admission_v1(
    bc: &Blockchain,
    tx: &Transaction,
    height: u64,
) -> Result<(), String> {
    if !is_compute_tx(tx) {
        return Ok(());
    }
    if let Some(payload) = parse_e2_worker_evidence_submit_tx_v1(tx)? {
        if tx.amount != 0 {
            return Err("e2_worker_evidence_submit_amount_must_be_0".to_string());
        }
        payload.validate_contract_shape_v1()?;
        bc.validate_e2_worker_standard_evidence_tx_v1(tx)?;
        return Ok(());
    }
    if let Some(payload) = parse_e2_worker_self_registration_tx_v1(tx)? {
        if tx.amount != 0 {
            return Err("e2_worker_self_register_amount_must_be_0".to_string());
        }
        payload.validate_contract_v1(crate::chain_identity::chain_id(), &bc.genesis_hash)?;
        let (_worker_hex, operator_hex) = payload.canonical_identities_v1()?;
        let sender_hex = crate::keyfmt::pk_hex_from_any(&tx.sender)
            .map_err(|e| format!("e2_worker_self_register_sender_invalid:{e}"))?;
        if sender_hex != operator_hex {
            return Err("e2_worker_self_register_sender_operator_mismatch".to_string());
        }
        return Ok(());
    }

    let activation_height = bc
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    if height < activation_height {
        return Ok(());
    }

    let call = decode_compute_call_v1(tx)?;
    if let ComputeCallV1::OrderClaim { order_id } = call {
        let decision =
            evaluate_compute_worker_admission_for_finalized_order_v1(bc, &tx.sender, &order_id)?;
        if !decision.accepted {
            return Err(decision
                .deny_reason
                .unwrap_or_else(|| "compute_worker_admission_denied".to_string()));
        }
    }
    Ok(())
}

enum ComputeMemoOpV1 {
    OrderCreate = 1,
    OrderClaim = 2,
    OrderComplete = 3,
    OrderFail = 4,
}

struct ByteCursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn rem(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.rem() < n {
            return Err("compute_ngbin_truncated".to_string());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16_le(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32_le(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64_le(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
    fn i32_le(&mut self) -> Result<i32, String> {
        let s = self.take(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn f64_le(&mut self) -> Result<f64, String> {
        let s = self.take(8)?;
        Ok(f64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
    fn bytes32(&mut self) -> Result<[u8; 32], String> {
        let s = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn string_u16(&mut self, max_len: usize) -> Result<Option<String>, String> {
        let n = self.u16_le()? as usize;
        if n == 0 {
            return Ok(None);
        }
        if n > max_len {
            return Err("compute_ngbin_string_too_long".to_string());
        }
        let s = self.take(n)?;
        let st =
            std::str::from_utf8(s).map_err(|_| "compute_ngbin_string_utf8_invalid".to_string())?;
        Ok(Some(st.to_string()))
    }
    fn blob_u32(&mut self, max_len: usize) -> Result<Option<Vec<u8>>, String> {
        let n = self.u32_le()? as usize;
        if n == 0 {
            return Ok(None);
        }
        if n > max_len {
            return Err("compute_ngbin_blob_too_long".to_string());
        }
        Ok(Some(self.take(n)?.to_vec()))
    }
}

fn decode_compute_memo_ngbin_v1(memo: &str) -> Result<ComputeCallV1, String> {
    let raw_b64 = memo
        .strip_prefix(NGBIN_MEMO_PREFIX)
        .ok_or_else(|| "compute_ngbin_bad_prefix".to_string())?;
    let raw = STANDARD
        .decode(raw_b64)
        .map_err(|e| format!("compute_ngbin_b64_invalid:{e}"))?;
    let mut c = ByteCursor::new(&raw);
    let version = c.u8()?;
    if version != 1 {
        return Err("compute_bad_version".to_string());
    }
    match c.u8()? {
        x if x == ComputeMemoOpV1::OrderCreate as u8 => {
            let spec = c.bytes32()?;
            let max_time_ms = c.u64_le()?;
            if max_time_ms == 0 || max_time_ms > 7 * 24 * 3600_000 {
                return Err("compute_max_time_ms_out_of_range".to_string());
            }
            let require_trusted = c.u8()? != 0;
            let min_score = c.f64_le()?;
            let min_rep = c.f64_le()?;
            let max_failures = c.i32_le()?;
            let job_kind = c.string_u16(64)?;
            let _job_payload_json = c.blob_u32(4096)?;
            if c.rem() != 0 {
                return Err("compute_ngbin_trailing_bytes".to_string());
            }
            Ok(ComputeCallV1::OrderCreate {
                job_spec_hash: hex::encode(spec),
                max_time_ms,
                policy: ComputePolicyV1 {
                    require_trusted,
                    min_score,
                    min_reputation: min_rep,
                    max_failures,
                },
                job_kind,
                job_payload: None,
            })
        }
        x if x == ComputeMemoOpV1::OrderClaim as u8 => {
            let oid = c.bytes32()?;
            if c.rem() != 0 {
                return Err("compute_ngbin_trailing_bytes".to_string());
            }
            Ok(ComputeCallV1::OrderClaim {
                order_id: hex::encode(oid),
            })
        }
        x if x == ComputeMemoOpV1::OrderComplete as u8 => {
            let oid = c.bytes32()?;
            let res = c.bytes32()?;
            let has_art = c.u8()?;
            let art = if has_art != 0 {
                Some(hex::encode(c.bytes32()?))
            } else {
                None
            };
            let exit_code = c.i32_le()?;
            let has_receipt = c.u8()?;
            let receipt_hash = if has_receipt != 0 {
                Some(hex::encode(c.bytes32()?))
            } else {
                None
            };
            if c.rem() != 0 {
                return Err("compute_ngbin_trailing_bytes".to_string());
            }
            Ok(ComputeCallV1::OrderComplete {
                order_id: hex::encode(oid),
                result_hash: hex::encode(res),
                artifact_root_hash: art,
                exit_code,
                receipt_hash,
            })
        }
        x if x == ComputeMemoOpV1::OrderFail as u8 => {
            let oid = c.bytes32()?;
            let reason = c
                .string_u16(256)?
                .ok_or_else(|| "compute_fail_reason_missing".to_string())?;
            let has_receipt = c.u8()?;
            let receipt_hash = if has_receipt != 0 {
                Some(hex::encode(c.bytes32()?))
            } else {
                None
            };
            if c.rem() != 0 {
                return Err("compute_ngbin_trailing_bytes".to_string());
            }
            Ok(ComputeCallV1::OrderFail {
                order_id: hex::encode(oid),
                reason,
                receipt_hash,
            })
        }
        _ => Err("compute_unknown_op".to_string()),
    }
}

pub fn is_compute_tx(tx: &Transaction) -> bool {
    tx.receiver == COMPUTE_RECEIVER
}

fn validate_compute_tx_syntax_inner_v1(
    tx: &Transaction,
    allow_legacy_missing_order_create_job_kind: bool,
) -> Result<(), String> {
    if tx.receiver != COMPUTE_RECEIVER {
        return Ok(());
    }
    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "compute_missing_memo".to_string())?;
    if memo.len() > 4096 {
        return Err("compute_memo_too_large".to_string());
    }
    if is_ngbin_memo(memo) {
        let call = decode_compute_memo_ngbin_v1(memo)?;
        match call {
            ComputeCallV1::OrderCreate {
                max_time_ms,
                policy,
                job_kind,
                ..
            } => {
                if tx.amount == 0 {
                    return Err("compute_create_amount_must_be_gt_0".to_string());
                }
                let effective_job_kind = if allow_legacy_missing_order_create_job_kind
                    && job_kind
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .is_none()
                {
                    Some("base_cpu_v1")
                } else {
                    job_kind.as_deref()
                };
                validate_compute_order_create_policy_and_kind_v1(
                    &policy,
                    max_time_ms,
                    effective_job_kind,
                )?;
            }
            ComputeCallV1::OrderClaim { .. }
            | ComputeCallV1::OrderComplete { .. }
            | ComputeCallV1::OrderFail { .. } => {
                if tx.amount != 0 {
                    return Err("compute_noncreate_amount_must_be_0".to_string());
                }
            }
        }
        return Ok(());
    }
    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("compute_memo_json_invalid: {e}"))?;
    let ver = v.get("v").and_then(|x| x.as_u64()).unwrap_or(0);
    if ver != 1 {
        return Err("compute_bad_version".to_string());
    }
    let op = v
        .get("op")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "compute_missing_op".to_string())?;
    match op {
        E2_WORKER_EVIDENCE_SUBMIT_OP_V1 => {
            if tx.amount != 0 {
                return Err("e2_worker_evidence_submit_amount_must_be_0".to_string());
            }
            let payload = parse_e2_worker_evidence_submit_payload_from_value_v1(&v)?;
            payload.validate_contract_shape_v1()?;
            Ok(())
        }
        E2_WORKER_SELF_REGISTER_OP_V1 => {
            if tx.amount != 0 {
                return Err("e2_worker_self_register_amount_must_be_0".to_string());
            }
            let payload = parse_e2_worker_self_registration_payload_from_value_v1(&v)?;
            payload.validate_contract_shape_v1()?;
            Ok(())
        }
        "order_create" => {
            if tx.amount == 0 {
                return Err("compute_create_amount_must_be_gt_0".to_string());
            }
            let job_spec_hash = get_str(&v, "job_spec_hash")?;
            if job_spec_hash.len() != 64 || hex::decode(&job_spec_hash).is_err() {
                return Err("compute_job_spec_hash_invalid".to_string());
            }
            let max_time_ms = get_u64(&v, "max_time_ms")?;
            if max_time_ms == 0 || max_time_ms > 7 * 24 * 3600_000 {
                return Err("compute_max_time_ms_out_of_range".to_string());
            }
            let policy = v
                .get("policy")
                .and_then(|p| p.as_object())
                .map(|p| ComputePolicyV1 {
                    require_trusted: p
                        .get("require_trusted")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                    min_score: p.get("min_score").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    min_reputation: p
                        .get("min_reputation")
                        .and_then(|x| x.as_f64())
                        .unwrap_or(0.0),
                    max_failures: p.get("max_failures").and_then(|x| x.as_i64()).unwrap_or(0)
                        as i32,
                })
                .unwrap_or_default();
            let job_kind = get_str_opt(&v, "job_kind");
            let effective_job_kind = if allow_legacy_missing_order_create_job_kind
                && job_kind
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_none()
            {
                Some("base_cpu_v1")
            } else {
                job_kind.as_deref()
            };
            validate_compute_order_create_policy_and_kind_v1(
                &policy,
                max_time_ms,
                effective_job_kind,
            )?;
            Ok(())
        }
        "order_claim" => {
            if tx.amount != 0 {
                return Err("compute_claim_amount_must_be_0".to_string());
            }
            let order_id = get_str(&v, "order_id")?;
            if order_id.len() != 64 || hex::decode(&order_id).is_err() {
                return Err("compute_order_id_invalid".to_string());
            }
            Ok(())
        }
        "order_complete" => {
            if tx.amount != 0 {
                return Err("compute_complete_amount_must_be_0".to_string());
            }
            let order_id = get_str(&v, "order_id")?;
            if order_id.len() != 64 || hex::decode(&order_id).is_err() {
                return Err("compute_order_id_invalid".to_string());
            }
            let result_hash = get_str(&v, "result_hash")?;
            if result_hash.len() != 64 || hex::decode(&result_hash).is_err() {
                return Err("compute_result_hash_invalid".to_string());
            }
            if let Some(art) = get_str_opt(&v, "artifact_root_hash") {
                if art.len() != 64 || hex::decode(&art).is_err() {
                    return Err("compute_artifact_root_hash_invalid".to_string());
                }
            }
            if let Some(rh) = get_str_opt(&v, "receipt_hash") {
                if rh.len() != 64 || hex::decode(&rh).is_err() {
                    return Err("compute_receipt_hash_invalid".to_string());
                }
            }
            Ok(())
        }
        "order_fail" => {
            if tx.amount != 0 {
                return Err("compute_fail_amount_must_be_0".to_string());
            }
            let order_id = get_str(&v, "order_id")?;
            if order_id.len() != 64 || hex::decode(&order_id).is_err() {
                return Err("compute_order_id_invalid".to_string());
            }
            let reason = get_str(&v, "reason")?;
            if reason.len() > 256 {
                return Err("compute_fail_reason_too_long".to_string());
            }
            if let Some(rh) = get_str_opt(&v, "receipt_hash") {
                if rh.len() != 64 || hex::decode(&rh).is_err() {
                    return Err("compute_receipt_hash_invalid".to_string());
                }
            }
            Ok(())
        }
        _ => Err("compute_unknown_op".to_string()),
    }
}

pub fn validate_compute_tx_syntax(tx: &Transaction) -> Result<(), String> {
    validate_compute_tx_syntax_inner_v1(tx, false)
}

pub fn validate_compute_tx_syntax_at_height_v1(
    tx: &Transaction,
    height: u64,
    required_job_kind_activation_height: u64,
) -> Result<(), String> {
    validate_compute_tx_syntax_inner_v1(tx, height < required_job_kind_activation_height)
}

fn decode_compute_call_inner_v1(
    tx: &Transaction,
    allow_legacy_missing_order_create_job_kind: bool,
) -> Result<ComputeCallV1, String> {
    if tx.receiver != COMPUTE_RECEIVER {
        return Err("not_compute_tx".to_string());
    }
    validate_compute_tx_syntax_inner_v1(tx, allow_legacy_missing_order_create_job_kind)?;
    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "compute_missing_memo".to_string())?;
    if is_ngbin_memo(memo) {
        return decode_compute_memo_ngbin_v1(memo);
    }
    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("compute_memo_json_invalid: {e}"))?;
    let op = v
        .get("op")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "compute_missing_op".to_string())?;
    match op {
        "order_create" => {
            let job_spec_hash = get_str(&v, "job_spec_hash")?;
            let max_time_ms = get_u64(&v, "max_time_ms")?;
            let pol_v = v.get("policy").cloned().unwrap_or(Value::Null);
            let policy = if let Some(p) = pol_v.as_object() {
                ComputePolicyV1 {
                    require_trusted: p
                        .get("require_trusted")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                    min_score: p.get("min_score").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    min_reputation: p
                        .get("min_reputation")
                        .and_then(|x| x.as_f64())
                        .unwrap_or(0.0),
                    max_failures: p.get("max_failures").and_then(|x| x.as_i64()).unwrap_or(0)
                        as i32,
                }
            } else {
                ComputePolicyV1::default()
            };
            Ok(ComputeCallV1::OrderCreate {
                job_spec_hash,
                max_time_ms,
                policy,
                job_kind: get_str_opt(&v, "job_kind"),
                job_payload: v.get("job_payload").cloned(),
            })
        }
        "order_claim" => Ok(ComputeCallV1::OrderClaim {
            order_id: get_str(&v, "order_id")?,
        }),
        "order_complete" => Ok(ComputeCallV1::OrderComplete {
            order_id: get_str(&v, "order_id")?,
            result_hash: get_str(&v, "result_hash")?,
            artifact_root_hash: get_str_opt(&v, "artifact_root_hash"),
            exit_code: v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
            receipt_hash: get_str_opt(&v, "receipt_hash"),
        }),
        "order_fail" => Ok(ComputeCallV1::OrderFail {
            order_id: get_str(&v, "order_id")?,
            reason: get_str(&v, "reason")?,
            receipt_hash: get_str_opt(&v, "receipt_hash"),
        }),
        _ => Err("compute_unknown_op".to_string()),
    }
}

pub fn decode_compute_call_v1(tx: &Transaction) -> Result<ComputeCallV1, String> {
    decode_compute_call_inner_v1(tx, false)
}

fn decode_compute_call_at_height_v1(
    tx: &Transaction,
    height: u64,
    required_job_kind_activation_height: u64,
) -> Result<ComputeCallV1, String> {
    decode_compute_call_inner_v1(tx, height < required_job_kind_activation_height)
}

fn apply_compute_tx_to_orders(
    orders: &mut BTreeMap<String, ComputeOrderRecordV1>,
    metadata_by_order_id: &mut BTreeMap<String, ComputeOrderRuntimeMetadataV1>,
    tx: &Transaction,
    height: u64,
    required_job_kind_activation_height: u64,
) -> Result<(), String> {
    if !is_compute_tx(tx) {
        return Ok(());
    }
    if is_e2_worker_self_registration_tx_v1(tx) || is_e2_worker_evidence_submit_tx_v1(tx) {
        return Ok(());
    }
    let call = decode_compute_call_at_height_v1(tx, height, required_job_kind_activation_height)?;
    match call {
        ComputeCallV1::OrderCreate {
            job_spec_hash,
            max_time_ms,
            policy,
            job_kind,
            ..
        } => {
            let legacy_missing_job_kind = job_kind
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_none()
                && height < required_job_kind_activation_height;
            let canonical_job_kind = if legacy_missing_job_kind {
                "base_cpu_v1".to_string()
            } else {
                job_kind
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| "compute_job_kind_missing".to_string())?
                    .to_string()
            };
            validate_compute_order_create_policy_and_kind_v1(
                &policy,
                max_time_ms,
                Some(canonical_job_kind.as_str()),
            )?;
            let required_min_score =
                normalize_compute_policy_reputation_score_v1(policy.min_score)?
                    .max(normalize_compute_policy_reputation_score_v1(
                        policy.min_reputation,
                    )?)
                    .max(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
            let required_workload_class = required_compute_workload_class_for_order_v1(
                &policy,
                required_min_score,
                max_time_ms,
                Some(canonical_job_kind.as_str()),
            )?;
            let order_id = tx.hash.clone();
            let rec = ComputeOrderRecordV1 {
                format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                order_id: order_id.clone(),
                payer: tx.sender.clone(),
                amount: tx.amount,
                job_spec_hash,
                max_time_ms,
                policy,
                status: ComputeOrderStatusV1::Open,
                created_height: height,
                claimed_worker: None,
                claim_height: None,
                completed_height: None,
                result_hash: None,
                artifact_root_hash: None,
                receipt_hash: None,
                fail_reason: None,
            };
            orders.entry(order_id.clone()).or_insert(rec);
            metadata_by_order_id
                .entry(order_id)
                .or_insert(ComputeOrderRuntimeMetadataV1 {
                    job_kind: canonical_job_kind,
                    required_workload_class,
                });
        }
        ComputeCallV1::OrderClaim { order_id } => {
            if let Some(rec) = orders.get_mut(&order_id) {
                if rec.status == ComputeOrderStatusV1::Open {
                    rec.status = ComputeOrderStatusV1::Claimed;
                    rec.claimed_worker = Some(tx.sender.clone());
                    rec.claim_height = Some(height);
                }
            }
        }
        ComputeCallV1::OrderComplete {
            order_id,
            result_hash,
            artifact_root_hash,
            receipt_hash,
            ..
        } => {
            if let Some(rec) = orders.get_mut(&order_id) {
                if rec.status == ComputeOrderStatusV1::Claimed
                    && rec.claimed_worker.as_deref() == Some(tx.sender.as_str())
                {
                    rec.status = ComputeOrderStatusV1::Completed;
                    rec.completed_height = Some(height);
                    rec.result_hash = Some(result_hash);
                    rec.artifact_root_hash = artifact_root_hash;
                    rec.receipt_hash = receipt_hash;
                }
            }
        }
        ComputeCallV1::OrderFail {
            order_id,
            reason,
            receipt_hash,
        } => {
            if let Some(rec) = orders.get_mut(&order_id) {
                if rec.status == ComputeOrderStatusV1::Claimed
                    && rec.claimed_worker.as_deref() == Some(tx.sender.as_str())
                {
                    rec.status = ComputeOrderStatusV1::Failed;
                    rec.completed_height = Some(height);
                    rec.fail_reason = Some(reason);
                    rec.receipt_hash = receipt_hash;
                }
            }
        }
    }
    Ok(())
}

fn compute_events_for_block(
    block: &Block,
    required_job_kind_activation_height: u64,
) -> Result<Vec<ComputeOrderEventV1>, String> {
    let mut events = Vec::new();
    for tx in &block.transactions {
        if !is_compute_tx(tx) {
            continue;
        }
        if is_e2_worker_self_registration_tx_v1(tx) || is_e2_worker_evidence_submit_tx_v1(tx) {
            continue;
        }
        let call =
            decode_compute_call_at_height_v1(tx, block.index, required_job_kind_activation_height)?;
        match call {
            ComputeCallV1::OrderCreate {
                job_spec_hash,
                max_time_ms,
                policy,
                job_kind,
                job_payload,
            } => {
                events.push(ComputeOrderEventV1 {
                    format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                    order_id: tx.hash.clone(),
                    event_type: "create".to_string(),
                    tx_hash: tx.hash.clone(),
                    height: block.index,
                    block_hash: block.hash.clone(),
                    sender: tx.sender.clone(),
                    payer: Some(tx.sender.clone()),
                    amount: Some(tx.amount),
                    job_spec_hash: Some(job_spec_hash),
                    max_time_ms: Some(max_time_ms),
                    policy: Some(policy),
                    job_kind,
                    job_payload,
                    claimed_worker: None,
                    result_hash: None,
                    artifact_root_hash: None,
                    exit_code: None,
                    receipt_hash: None,
                    fail_reason: None,
                });
            }
            ComputeCallV1::OrderClaim { order_id } => {
                events.push(ComputeOrderEventV1 {
                    format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                    order_id,
                    event_type: "claim".to_string(),
                    tx_hash: tx.hash.clone(),
                    height: block.index,
                    block_hash: block.hash.clone(),
                    sender: tx.sender.clone(),
                    payer: None,
                    amount: None,
                    job_spec_hash: None,
                    max_time_ms: None,
                    policy: None,
                    job_kind: None,
                    job_payload: None,
                    claimed_worker: Some(tx.sender.clone()),
                    result_hash: None,
                    artifact_root_hash: None,
                    exit_code: None,
                    receipt_hash: None,
                    fail_reason: None,
                });
            }
            ComputeCallV1::OrderComplete {
                order_id,
                result_hash,
                artifact_root_hash,
                exit_code,
                receipt_hash,
            } => {
                events.push(ComputeOrderEventV1 {
                    format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                    order_id,
                    event_type: "complete".to_string(),
                    tx_hash: tx.hash.clone(),
                    height: block.index,
                    block_hash: block.hash.clone(),
                    sender: tx.sender.clone(),
                    payer: None,
                    amount: None,
                    job_spec_hash: None,
                    max_time_ms: None,
                    policy: None,
                    job_kind: None,
                    job_payload: None,
                    claimed_worker: Some(tx.sender.clone()),
                    result_hash: Some(result_hash),
                    artifact_root_hash,
                    exit_code: Some(exit_code),
                    receipt_hash,
                    fail_reason: None,
                });
            }
            ComputeCallV1::OrderFail {
                order_id,
                reason,
                receipt_hash,
            } => {
                events.push(ComputeOrderEventV1 {
                    format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                    order_id,
                    event_type: "fail".to_string(),
                    tx_hash: tx.hash.clone(),
                    height: block.index,
                    block_hash: block.hash.clone(),
                    sender: tx.sender.clone(),
                    payer: None,
                    amount: None,
                    job_spec_hash: None,
                    max_time_ms: None,
                    policy: None,
                    job_kind: None,
                    job_payload: None,
                    claimed_worker: Some(tx.sender.clone()),
                    result_hash: None,
                    artifact_root_hash: None,
                    exit_code: None,
                    receipt_hash,
                    fail_reason: Some(reason),
                });
            }
        }
    }
    Ok(events)
}

fn finalized_hash_for_height(
    bc: &Blockchain,
    height: u64,
    preferred: &str,
) -> Result<String, String> {
    if !preferred.trim().is_empty() {
        return Ok(preferred.to_string());
    }
    if let Some(block) = bc.api_block_by_height_v2(height)? {
        if !block.hash.trim().is_empty() {
            return Ok(block.hash);
        }
    }
    if height == 0 {
        return Ok(String::new());
    }
    Ok(String::new())
}

pub fn compute_order_state_store_apply_block_v1(
    store: &mut ComputeOrderStateStoreV1,
    block: &Block,
    required_job_kind_activation_height: u64,
) -> Result<(), String> {
    if store.last_applied_hash.is_empty()
        && store.orders.is_empty()
        && store.metadata_by_order_id.is_empty()
    {
        // Fresh store. If it starts above genesis it is safe for forward application,
        // but not safe for finalized order surfaces/admission; snapshot reads will
        // fail-closed until a genesis-complete store or canonical sidecar is restored.
        store.first_applied_height = block.index;
        store.complete_from_genesis = block.index == 0;
    } else if block.index <= store.last_applied_height {
        if block.index == store.last_applied_height && store.last_applied_hash == block.hash {
            return Ok(());
        }
        return Err(format!(
            "compute_order_state_store_replay_non_monotonic:store_height={}:block_height={}",
            store.last_applied_height, block.index
        ));
    } else if block.index != store.last_applied_height.saturating_add(1) {
        return Err(format!(
            "compute_order_state_store_replay_gap:store_height={}:block_height={}",
            store.last_applied_height, block.index
        ));
    }

    let events = compute_events_for_block(block, required_job_kind_activation_height)?;
    apply_block_orders(
        &mut store.orders,
        &mut store.metadata_by_order_id,
        block,
        required_job_kind_activation_height,
    )?;
    store.events_by_height.insert(block.index, events);
    store
        .block_hash_by_height
        .insert(block.index, block.hash.clone());
    store.format_version = "compute-order-state-store-v1".to_string();
    store.e2_contract_version = crate::version::E2_CONTRACT_VERSION.to_string();
    store.required_job_kind_activation_height = required_job_kind_activation_height;
    if store.last_applied_hash.is_empty() {
        store.first_applied_height = block.index;
        store.complete_from_genesis = block.index == 0;
    }
    store.last_applied_height = block.index;
    store.last_applied_hash = block.hash.clone();
    Ok(())
}

pub fn compute_order_state_store_rebuild_from_blocks_v1(
    blocks: &[Block],
    required_job_kind_activation_height: u64,
) -> Result<ComputeOrderStateStoreV1, String> {
    let mut store = ComputeOrderStateStoreV1::default();
    for block in blocks {
        compute_order_state_store_apply_block_v1(
            &mut store,
            block,
            required_job_kind_activation_height,
        )?;
    }
    Ok(store)
}

fn apply_compute_order_event_to_state_v1(
    orders: &mut BTreeMap<String, ComputeOrderRecordV1>,
    metadata_by_order_id: &mut BTreeMap<String, ComputeOrderRuntimeMetadataV1>,
    event: &ComputeOrderEventV1,
    required_job_kind_activation_height: u64,
) -> Result<(), String> {
    match event.event_type.as_str() {
        "create" => {
            let policy = event.policy.clone().ok_or_else(|| {
                format!(
                    "compute_order_event_create_missing_policy:{}",
                    event.order_id
                )
            })?;
            let max_time_ms = event.max_time_ms.ok_or_else(|| {
                format!(
                    "compute_order_event_create_missing_max_time_ms:{}",
                    event.order_id
                )
            })?;
            let job_spec_hash = event.job_spec_hash.clone().ok_or_else(|| {
                format!(
                    "compute_order_event_create_missing_job_spec_hash:{}",
                    event.order_id
                )
            })?;
            let legacy_missing_job_kind = event
                .job_kind
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_none()
                && event.height < required_job_kind_activation_height;
            let canonical_job_kind = if legacy_missing_job_kind {
                "base_cpu_v1".to_string()
            } else {
                event
                    .job_kind
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        format!(
                            "compute_order_event_create_missing_job_kind:{}",
                            event.order_id
                        )
                    })?
                    .to_string()
            };
            validate_compute_order_create_policy_and_kind_v1(
                &policy,
                max_time_ms,
                Some(canonical_job_kind.as_str()),
            )?;
            let required_min_score =
                normalize_compute_policy_reputation_score_v1(policy.min_score)?
                    .max(normalize_compute_policy_reputation_score_v1(
                        policy.min_reputation,
                    )?)
                    .max(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
            let required_workload_class = required_compute_workload_class_for_order_v1(
                &policy,
                required_min_score,
                max_time_ms,
                Some(canonical_job_kind.as_str()),
            )?;
            let rec = ComputeOrderRecordV1 {
                format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                order_id: event.order_id.clone(),
                payer: event.payer.clone().unwrap_or_else(|| event.sender.clone()),
                amount: event.amount.unwrap_or(0),
                job_spec_hash,
                max_time_ms,
                policy,
                status: ComputeOrderStatusV1::Open,
                created_height: event.height,
                claimed_worker: None,
                claim_height: None,
                completed_height: None,
                result_hash: None,
                artifact_root_hash: None,
                receipt_hash: None,
                fail_reason: None,
            };
            orders.entry(event.order_id.clone()).or_insert(rec);
            metadata_by_order_id
                .entry(event.order_id.clone())
                .or_insert(ComputeOrderRuntimeMetadataV1 {
                    job_kind: canonical_job_kind,
                    required_workload_class,
                });
        }
        "claim" => {
            if let Some(rec) = orders.get_mut(&event.order_id) {
                if rec.status == ComputeOrderStatusV1::Open {
                    rec.status = ComputeOrderStatusV1::Claimed;
                    rec.claimed_worker = event
                        .claimed_worker
                        .clone()
                        .or_else(|| Some(event.sender.clone()));
                    rec.claim_height = Some(event.height);
                }
            }
        }
        "complete" => {
            if let Some(rec) = orders.get_mut(&event.order_id) {
                let worker = event
                    .claimed_worker
                    .as_deref()
                    .unwrap_or(event.sender.as_str());
                if rec.status == ComputeOrderStatusV1::Claimed
                    && rec.claimed_worker.as_deref() == Some(worker)
                {
                    rec.status = ComputeOrderStatusV1::Completed;
                    rec.completed_height = Some(event.height);
                    rec.result_hash = event.result_hash.clone();
                    rec.artifact_root_hash = event.artifact_root_hash.clone();
                    rec.receipt_hash = event.receipt_hash.clone();
                }
            }
        }
        "fail" => {
            if let Some(rec) = orders.get_mut(&event.order_id) {
                let worker = event
                    .claimed_worker
                    .as_deref()
                    .unwrap_or(event.sender.as_str());
                if rec.status == ComputeOrderStatusV1::Claimed
                    && rec.claimed_worker.as_deref() == Some(worker)
                {
                    rec.status = ComputeOrderStatusV1::Failed;
                    rec.completed_height = Some(event.height);
                    rec.fail_reason = event.fail_reason.clone();
                    rec.receipt_hash = event.receipt_hash.clone();
                }
            }
        }
        other => {
            return Err(format!(
                "compute_order_event_type_unknown:{}:{}",
                event.order_id, other
            ));
        }
    }
    Ok(())
}

pub fn compute_order_state_store_bound_to_height_v1(
    store: &ComputeOrderStateStoreV1,
    target_height: u64,
    target_hash: &str,
) -> Result<ComputeOrderStateStoreV1, String> {
    if !store.complete_from_genesis || store.first_applied_height != 0 {
        return Err(format!(
            "compute_order_state_store_not_genesis_complete:first_applied_height={}:complete_from_genesis={}",
            store.first_applied_height, store.complete_from_genesis
        ));
    }
    if store.last_applied_height < target_height {
        return Err(format!(
            "compute_order_state_store_stale:store_height={}:target_height={}",
            store.last_applied_height, target_height
        ));
    }
    let bound_hash = target_hash.trim();
    if bound_hash.is_empty() && target_height > 0 {
        return Err(format!(
            "compute_order_state_store_target_hash_missing:target_height={}",
            target_height
        ));
    }
    if let Some(known_hash) = store.block_hash_by_height.get(&target_height) {
        if !bound_hash.is_empty() && known_hash != bound_hash {
            return Err(format!(
                "compute_order_state_store_target_hash_mismatch:store={} target={}",
                known_hash, bound_hash
            ));
        }
    } else if target_height == store.last_applied_height {
        if !bound_hash.is_empty() && store.last_applied_hash != bound_hash {
            return Err(format!(
                "compute_order_state_store_target_hash_mismatch:store={} target={}",
                store.last_applied_hash, bound_hash
            ));
        }
    } else {
        return Err(format!(
            "compute_order_state_store_target_hash_unavailable:target_height={}",
            target_height
        ));
    }

    let mut bounded = ComputeOrderStateStoreV1 {
        format_version: store.format_version.clone(),
        e2_contract_version: store.e2_contract_version.clone(),
        first_applied_height: 0,
        last_applied_height: target_height,
        last_applied_hash: bound_hash.to_string(),
        complete_from_genesis: true,
        required_job_kind_activation_height: store.required_job_kind_activation_height,
        orders: BTreeMap::new(),
        metadata_by_order_id: BTreeMap::new(),
        events_by_height: BTreeMap::new(),
        block_hash_by_height: BTreeMap::new(),
    };
    for (height, hash) in store.block_hash_by_height.range(..=target_height) {
        bounded.block_hash_by_height.insert(*height, hash.clone());
    }
    for (height, events) in store.events_by_height.range(..=target_height) {
        bounded.events_by_height.insert(*height, events.clone());
    }

    // V208: V207 compacts snapshot sidecars by keeping materialized E2 order
    // state while dropping the unbounded historical event journal from the
    // snapshot header.  Binding such a sidecar exactly at its own tip must use
    // the materialized state directly; replaying an empty compacted journal
    // would incorrectly erase imported orders.  For older targets we still
    // require full event coverage and fail closed when history was compacted.
    if target_height == store.last_applied_height {
        bounded.orders = store.orders.clone();
        bounded.metadata_by_order_id = store.metadata_by_order_id.clone();
        return Ok(bounded);
    }

    for height in store.first_applied_height..=target_height {
        if !store.events_by_height.contains_key(&height) {
            return Err(format!(
                "compute_order_state_store_event_history_unavailable:target_height={}:missing_height={}:store_height={}",
                target_height, height, store.last_applied_height
            ));
        }
    }

    for (_height, events) in store.events_by_height.range(..=target_height) {
        for event in events {
            apply_compute_order_event_to_state_v1(
                &mut bounded.orders,
                &mut bounded.metadata_by_order_id,
                event,
                store.required_job_kind_activation_height,
            )?;
        }
    }
    Ok(bounded)
}

fn compute_order_state_store_snapshot_v1(
    bc: &Blockchain,
    store: &ComputeOrderStateStoreV1,
    finalized_height: u64,
    finalized_hash: String,
) -> Result<ComputeOrdersInternalSnapshotV1, String> {
    if !store.complete_from_genesis || store.first_applied_height != 0 {
        return Err(format!(
            "compute_order_state_store_not_genesis_complete:first_applied_height={}:complete_from_genesis={}",
            store.first_applied_height, store.complete_from_genesis
        ));
    }
    if store.last_applied_height < finalized_height {
        return Err(format!(
            "compute_order_state_store_stale:store_height={}:finalized_height={}",
            store.last_applied_height, finalized_height
        ));
    }
    let expected_activation = bc
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    if store.required_job_kind_activation_height != expected_activation {
        return Err(format!(
            "compute_order_state_store_activation_height_mismatch:{}!={}",
            store.required_job_kind_activation_height, expected_activation
        ));
    }
    let bounded = compute_order_state_store_bound_to_height_v1(
        store,
        finalized_height,
        finalized_hash.as_str(),
    )?;
    let orders: Vec<ComputeOrderRecordV1> = bounded.orders.values().cloned().collect();
    Ok(ComputeOrdersInternalSnapshotV1 {
        snapshot: ComputeOrdersSnapshotV1 {
            format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
            e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
            finalized_height,
            finalized_hash,
            orders,
        },
        metadata_by_order_id: bounded.metadata_by_order_id,
    })
}

fn apply_block_orders(
    orders: &mut BTreeMap<String, ComputeOrderRecordV1>,
    metadata_by_order_id: &mut BTreeMap<String, ComputeOrderRuntimeMetadataV1>,
    block: &Block,
    required_job_kind_activation_height: u64,
) -> Result<(), String> {
    for tx in &block.transactions {
        apply_compute_tx_to_orders(
            orders,
            metadata_by_order_id,
            tx,
            block.index,
            required_job_kind_activation_height,
        )?;
    }
    Ok(())
}

fn compute_orders_require_unpruned_replay_window_v1(
    bc: &Blockchain,
    from_height: u64,
    to_height: u64,
) -> Result<(), String> {
    // Fallback block replay is only safe when the requested window is fully
    // available. Pruned chains may replay only ranges fully inside their retained
    // block window; ranges before base_height require an imported materialized
    // sidecar and must fail closed instead of returning a partial E2 surface.
    if bc.base_height > 0 && from_height < bc.base_height {
        return Err(format!(
            "compute_order_state_index_required_for_pruned_chain:base_height={}:from={}:to={}",
            bc.base_height, from_height, to_height
        ));
    }
    Ok(())
}

fn compute_order_event_history_covers_range_v207(
    store: &ComputeOrderStateStoreV1,
    from_height: u64,
    to_height: u64,
) -> bool {
    if from_height > to_height {
        return false;
    }
    (from_height..=to_height).all(|height| store.events_by_height.contains_key(&height))
}

fn compute_orders_internal_snapshot_for_finalized_chain(
    bc: &Blockchain,
) -> Result<ComputeOrdersInternalSnapshotV1, String> {
    let (finalized_height, finalized_hash_raw) = bc.finalized_view();
    let finalized_hash = finalized_hash_for_height(bc, finalized_height, &finalized_hash_raw)?;

    if bc.compute_order_state_store.complete_from_genesis || bc.base_height > 0 {
        match compute_order_state_store_snapshot_v1(
            bc,
            &bc.compute_order_state_store,
            finalized_height,
            finalized_hash.clone(),
        ) {
            Ok(snapshot) => return Ok(snapshot),
            Err(err) => {
                // A pruned chain cannot reconstruct missing compute-order history, so the
                // sidecar remains mandatory and fail-closed. A full-history test/runtime
                // can safely derive the finalized compute surface from canonical blocks
                // when the sidecar is stale because callers mutated/replayed blocks before
                // the incremental index caught up.
                if bc.base_height > 0 {
                    return Err(err);
                }
                let recoverable_full_history_sidecar_error = err
                    .starts_with("compute_order_state_store_stale:")
                    || err.starts_with("compute_order_state_store_target_hash_unavailable:")
                    || err.starts_with("compute_order_state_store_target_hash_mismatch:")
                    || err.starts_with("compute_order_state_store_activation_height_mismatch:")
                    || err.starts_with("compute_order_state_store_not_genesis_complete:");
                if !recoverable_full_history_sidecar_error {
                    return Err(err);
                }
            }
        }
    }

    compute_orders_require_unpruned_replay_window_v1(bc, 0, finalized_height)?;
    let mut orders = BTreeMap::new();
    let mut metadata_by_order_id = BTreeMap::new();
    let required_job_kind_activation_height = bc
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    for h in 0..=finalized_height {
        match bc.api_block_by_height_v2(h)? {
            Some(block) => apply_block_orders(
                &mut orders,
                &mut metadata_by_order_id,
                &block,
                required_job_kind_activation_height,
            )?,
            None if h == 0 && finalized_height == 0 => {}
            None => return Err(format!("finalized_block_unavailable:{}", h)),
        }
    }
    Ok(ComputeOrdersInternalSnapshotV1 {
        snapshot: ComputeOrdersSnapshotV1 {
            format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
            e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
            finalized_height,
            finalized_hash,
            orders: orders.into_values().collect(),
        },
        metadata_by_order_id,
    })
}

pub fn compute_orders_snapshot_for_finalized_chain(
    bc: &Blockchain,
) -> Result<ComputeOrdersSnapshotV1, String> {
    Ok(compute_orders_internal_snapshot_for_finalized_chain(bc)?.snapshot)
}

pub fn compute_order_lookup_for_finalized_chain(
    bc: &Blockchain,
    order_id: &str,
) -> Result<ComputeOrderLookupResponseV1, String> {
    let internal = compute_orders_internal_snapshot_for_finalized_chain(bc)?;
    let order = internal
        .snapshot
        .orders
        .iter()
        .find(|o| o.order_id == order_id)
        .cloned();
    Ok(ComputeOrderLookupResponseV1 {
        format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
        e2_contract_version: internal.snapshot.e2_contract_version,
        finalized_height: internal.snapshot.finalized_height,
        finalized_hash: internal.snapshot.finalized_hash,
        found: order.is_some(),
        order,
    })
}

pub fn compute_orders_snapshot_v2_for_finalized_chain(
    bc: &Blockchain,
) -> Result<ComputeOrdersSnapshotV2, String> {
    let internal = compute_orders_internal_snapshot_for_finalized_chain(bc)?;
    let mut orders = Vec::with_capacity(internal.snapshot.orders.len());
    for order in internal.snapshot.orders.iter().cloned() {
        let metadata = internal
            .metadata_by_order_id
            .get(&order.order_id)
            .ok_or_else(|| {
                format!(
                    "compute_order_required_workload_class_missing:{}",
                    order.order_id
                )
            })?;
        orders.push(compute_order_record_v2_from_record_and_metadata_v1(
            order, metadata,
        ));
    }
    Ok(ComputeOrdersSnapshotV2 {
        format_version: COMPUTE_ORDER_SURFACE_VERSION_V2.to_string(),
        legacy_format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1.to_string(),
        e2_contract_version: internal.snapshot.e2_contract_version,
        finalized_height: internal.snapshot.finalized_height,
        finalized_hash: internal.snapshot.finalized_hash,
        orders,
    })
}

pub fn compute_order_lookup_v2_for_finalized_chain(
    bc: &Blockchain,
    order_id: &str,
) -> Result<ComputeOrderLookupResponseV2, String> {
    let internal = compute_orders_internal_snapshot_for_finalized_chain(bc)?;
    let order = internal
        .snapshot
        .orders
        .iter()
        .find(|o| o.order_id == order_id)
        .cloned();
    let order = match order {
        Some(order) => {
            let metadata = internal
                .metadata_by_order_id
                .get(&order.order_id)
                .ok_or_else(|| {
                    format!(
                        "compute_order_required_workload_class_missing:{}",
                        order.order_id
                    )
                })?;
            Some(compute_order_record_v2_from_record_and_metadata_v1(
                order, metadata,
            ))
        }
        None => None,
    };
    Ok(ComputeOrderLookupResponseV2 {
        format_version: COMPUTE_ORDER_SURFACE_VERSION_V2.to_string(),
        legacy_format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1.to_string(),
        e2_contract_version: internal.snapshot.e2_contract_version,
        finalized_height: internal.snapshot.finalized_height,
        finalized_hash: internal.snapshot.finalized_hash,
        found: order.is_some(),
        order,
    })
}

fn compute_order_events_snapshot_from_state_store_v1(
    bc: &Blockchain,
    store: &ComputeOrderStateStoreV1,
    from_height: u64,
    to_height: u64,
    finalized_height: u64,
    finalized_hash: String,
) -> Result<ComputeOrderEventsSnapshotV1, String> {
    if !store.complete_from_genesis || store.first_applied_height != 0 {
        return Err(format!(
            "compute_order_event_state_store_not_genesis_complete:first_applied_height={}:complete_from_genesis={}",
            store.first_applied_height, store.complete_from_genesis
        ));
    }
    if store.last_applied_height < to_height {
        return Err(format!(
            "compute_order_event_state_store_stale:store_height={}:to_height={}",
            store.last_applied_height, to_height
        ));
    }
    let expected_activation = bc
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    if store.required_job_kind_activation_height != expected_activation {
        return Err(format!(
            "compute_order_event_state_store_activation_height_mismatch:{}!={}",
            store.required_job_kind_activation_height, expected_activation
        ));
    }
    let mut events = Vec::new();
    for h in from_height..=to_height {
        if let Some(v) = store.events_by_height.get(&h) {
            events.extend(v.iter().cloned());
        }
    }
    Ok(ComputeOrderEventsSnapshotV1 {
        format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
        e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
        finalized_height,
        finalized_hash,
        from_height,
        to_height,
        events,
    })
}

pub fn compute_order_events_snapshot_for_finalized_chain(
    bc: &Blockchain,
    from_height: u64,
    to_height: u64,
) -> Result<ComputeOrderEventsSnapshotV1, String> {
    let (finalized_height, finalized_hash_raw) = bc.finalized_view();
    let finalized_hash = finalized_hash_for_height(bc, finalized_height, &finalized_hash_raw)?;
    let required_job_kind_activation_height = bc
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    if from_height > to_height {
        return Err("invalid_range:from_height_gt_to_height".to_string());
    }
    if to_height > finalized_height {
        return Err(format!(
            "invalid_range:to_height_exceeds_finalized:{}>{}",
            to_height, finalized_height
        ));
    }
    if bc.compute_order_state_store.complete_from_genesis || bc.base_height > 0 {
        let event_history_covers_range = compute_order_event_history_covers_range_v207(
            &bc.compute_order_state_store,
            from_height,
            to_height,
        );
        if event_history_covers_range {
            match compute_order_events_snapshot_from_state_store_v1(
                bc,
                &bc.compute_order_state_store,
                from_height,
                to_height,
                finalized_height,
                finalized_hash.clone(),
            ) {
                Ok(snapshot) => return Ok(snapshot),
                Err(err) => {
                    if bc.base_height > 0 {
                        return Err(err);
                    }
                    let recoverable_full_history_sidecar_error = err
                        .starts_with("compute_order_event_state_store_stale:")
                        || err.starts_with(
                            "compute_order_event_state_store_activation_height_mismatch:",
                        )
                        || err.starts_with("compute_order_event_state_store_not_genesis_complete:");
                    if !recoverable_full_history_sidecar_error {
                        return Err(err);
                    }
                }
            }
        } else if bc.base_height > 0 && from_height < bc.base_height {
            return Err(format!(
                "compute_order_event_history_compacted_unavailable:base_height={}:from={}:to={}",
                bc.base_height, from_height, to_height
            ));
        }
    }
    compute_orders_require_unpruned_replay_window_v1(bc, from_height, to_height)?;
    let mut events = Vec::new();
    for h in from_height..=to_height {
        match bc.api_block_by_height_v2(h)? {
            Some(block) => events.extend(compute_events_for_block(
                &block,
                required_job_kind_activation_height,
            )?),
            None if h == 0 && finalized_height == 0 => {}
            None => return Err(format!("finalized_block_unavailable:{}", h)),
        }
    }
    Ok(ComputeOrderEventsSnapshotV1 {
        format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
        e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
        finalized_height,
        finalized_hash,
        from_height,
        to_height,
        events,
    })
}

#[cfg(test)]
fn finalize_billing_ref_hash(proof: &mut ComputeFiatSettlementProofV1) {
    proof.billing_ref_hash = compute_fiat_settlement_billing_ref_hash_v1(proof).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn compute_order_event_history_coverage_v207_requires_every_height_key() {
        let mut store = ComputeOrderStateStoreV1::default();
        store.events_by_height.insert(10, Vec::new());
        store.events_by_height.insert(11, Vec::new());
        assert!(compute_order_event_history_covers_range_v207(
            &store, 10, 11
        ));
        assert!(!compute_order_event_history_covers_range_v207(
            &store, 10, 12
        ));
    }

    #[test]
    fn compute_order_bound_tip_uses_materialized_compact_state_v208() {
        let mut store = ComputeOrderStateStoreV1::default();
        store.complete_from_genesis = true;
        store.first_applied_height = 0;
        store.last_applied_height = 100;
        store.last_applied_hash = "hash100".to_string();
        store.required_job_kind_activation_height = 77;
        store.block_hash_by_height.insert(99, "hash99".to_string());
        store
            .block_hash_by_height
            .insert(100, "hash100".to_string());
        store.orders.insert(
            "order-1".to_string(),
            ComputeOrderRecordV1 {
                format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
                order_id: "order-1".to_string(),
                payer: "payer".to_string(),
                amount: 42,
                job_spec_hash: "job-hash".to_string(),
                max_time_ms: 1000,
                policy: ComputePolicyV1::default(),
                status: ComputeOrderStatusV1::Open,
                created_height: 10,
                claimed_worker: None,
                claim_height: None,
                completed_height: None,
                result_hash: None,
                artifact_root_hash: None,
                receipt_hash: None,
                fail_reason: None,
            },
        );
        store.metadata_by_order_id.insert(
            "order-1".to_string(),
            ComputeOrderRuntimeMetadataV1 {
                job_kind: "base_cpu_v1".to_string(),
                required_workload_class: RequiredComputeWorkloadClassV1::Base,
            },
        );

        let tip_bound = compute_order_state_store_bound_to_height_v1(&store, 100, "hash100")
            .expect("compacted materialized state must bind at its own tip");
        assert_eq!(tip_bound.orders.len(), 1);
        assert_eq!(tip_bound.metadata_by_order_id.len(), 1);
        assert!(tip_bound.events_by_height.is_empty());

        let older = compute_order_state_store_bound_to_height_v1(&store, 99, "hash99")
            .expect_err("compacted event history must not answer older target heights");
        assert!(older.starts_with("compute_order_state_store_event_history_unavailable:"));
    }

    #[test]
    fn decode_json_compute_create() {
        let tx = Transaction::new(
            "sender".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(r#"{"v":1,"op":"order_create","job_spec_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_time_ms":1000,"job_kind":"hash_sha256_v1"}"#.to_string()),
        );
        let call = decode_compute_call_v1(&tx).unwrap();
        match call {
            ComputeCallV1::OrderCreate {
                job_spec_hash,
                max_time_ms,
                ..
            } => {
                assert_eq!(job_spec_hash.len(), 64);
                assert_eq!(max_time_ms, 1000);
            }
            _ => panic!("unexpected call"),
        }
    }

    #[test]
    fn compute_events_for_block_emits_create_claim_complete() {
        let create = Transaction::new(
            "payer-a".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(r#"{"v":1,"op":"order_create","job_spec_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_time_ms":1000,"job_kind":"hash_sha256_v1"}"#.to_string()),
        );
        let order_id = create.hash.clone();
        let claim = Transaction::new(
            "worker-a".to_string(),
            COMPUTE_RECEIVER.to_string(),
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
        let complete = Transaction::new(
            "worker-a".to_string(),
            COMPUTE_RECEIVER.to_string(),
            0,
            1,
            2,
            "sig".to_string(),
            false,
            Some(format!(
                r#"{{"v":1,"op":"order_complete","order_id":"{}","result_hash":"{}","exit_code":0}}"#,
                order_id, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
        );
        let mut block = Block::default();
        block.index = 10;
        block.hash = "cc".repeat(32);
        block.transactions = vec![create, claim, complete];
        let events = compute_events_for_block(&block, 0).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "create");
        assert_eq!(events[1].event_type, "claim");
        assert_eq!(events[2].event_type, "complete");
    }

    #[test]
    fn validate_compute_tx_syntax_rejects_missing_memo() {
        let tx = Transaction::new(
            "sender".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            None,
        );
        let err = validate_compute_tx_syntax(&tx).unwrap_err();
        assert!(err.contains("compute_missing_memo"));
    }

    fn self_register_test_key(byte: u8) -> (ed25519_dalek::SigningKey, String) {
        let seed = [byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk_b64 = STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, pk_b64)
    }

    fn self_register_test_payload(
        worker_sk: &ed25519_dalek::SigningKey,
        worker_pk_b64: &str,
        operator_pk_b64: &str,
    ) -> E2WorkerSelfRegistrationPayloadV1 {
        let mut payload = E2WorkerSelfRegistrationPayloadV1 {
            format_version: E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1.to_string(),
            worker_node_pubkey: worker_pk_b64.to_string(),
            operator_wallet_pubkey: operator_pk_b64.to_string(),
            worker_signature: String::new(),
            capabilities_commitment_hash: "b".repeat(64),
            runtime_class: "native-v1".to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: "a".repeat(64),
            region: Some("eu-west-1".to_string()),
            country: Some("IT".to_string()),
        };
        payload.worker_signature = crate::crypto::sign_ds_b64(
            worker_sk,
            E2_WORKER_SELF_REGISTER_SIGNATURE_CONTEXT_V1,
            &e2_worker_self_registration_signing_bytes_v1(&payload).unwrap(),
        );
        payload
    }

    fn self_register_test_tx(
        payload: &E2WorkerSelfRegistrationPayloadV1,
        operator_pk_b64: &str,
        amount: u64,
    ) -> Transaction {
        let memo = serde_json::json!({
            "v": 1,
            "op": E2_WORKER_SELF_REGISTER_OP_V1,
            "format_version": payload.format_version.clone(),
            "worker_node_pubkey": payload.worker_node_pubkey.clone(),
            "operator_wallet_pubkey": payload.operator_wallet_pubkey.clone(),
            "worker_signature": payload.worker_signature.clone(),
            "capabilities_commitment_hash": payload.capabilities_commitment_hash.clone(),
            "runtime_class": payload.runtime_class.clone(),
            "chain_id": payload.chain_id.clone(),
            "genesis_hash": payload.genesis_hash.clone(),
            "region": payload.region.clone(),
            "country": payload.country.clone(),
        })
        .to_string();
        Transaction::new(
            operator_pk_b64.to_string(),
            COMPUTE_RECEIVER.to_string(),
            amount,
            1,
            0,
            "sig".to_string(),
            false,
            Some(memo),
        )
    }

    #[test]
    fn worker_self_register_unsigned_shape_does_not_require_worker_signature_v1() {
        let (_worker_sk, worker_pk) = self_register_test_key(0x31);
        let (_operator_sk, operator_pk) = self_register_test_key(0x32);
        let payload = E2WorkerSelfRegistrationPayloadV1 {
            format_version: E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1.to_string(),
            worker_node_pubkey: worker_pk,
            operator_wallet_pubkey: operator_pk,
            worker_signature: String::new(),
            capabilities_commitment_hash: "b".repeat(64),
            runtime_class: "native-v1".to_string(),
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: "a".repeat(64),
            region: Some("eu-west-1".to_string()),
            country: Some("IT".to_string()),
        };
        payload
            .validate_unsigned_contract_v1(crate::chain_identity::chain_id(), &"a".repeat(64))
            .expect(
                "unsigned self-register shape should be usable before worker_signature is attached",
            );
        assert!(payload.validate_contract_shape_v1().is_err());
    }

    #[test]
    fn validate_compute_tx_syntax_accepts_worker_self_register_v1() {
        let (worker_sk, worker_pk) = self_register_test_key(0x21);
        let (_operator_sk, operator_pk) = self_register_test_key(0x22);
        let payload = self_register_test_payload(&worker_sk, &worker_pk, &operator_pk);
        let tx = self_register_test_tx(&payload, &operator_pk, 0);
        validate_compute_tx_syntax(&tx).unwrap();
        let parsed = parse_e2_worker_self_registration_tx_v1(&tx)
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::keyfmt::pk_hex_from_any(&parsed.worker_node_pubkey).unwrap(),
            crate::keyfmt::pk_hex_from_any(&worker_pk).unwrap()
        );
    }

    #[test]
    fn validate_compute_tx_syntax_rejects_worker_self_register_bad_amount_v1() {
        let (worker_sk, worker_pk) = self_register_test_key(0x23);
        let (_operator_sk, operator_pk) = self_register_test_key(0x24);
        let payload = self_register_test_payload(&worker_sk, &worker_pk, &operator_pk);
        let tx = self_register_test_tx(&payload, &operator_pk, 1);
        let err = validate_compute_tx_syntax(&tx).unwrap_err();
        assert!(err.contains("e2_worker_self_register_amount_must_be_0"));
    }

    #[test]
    fn validate_compute_tx_syntax_rejects_worker_self_register_bad_worker_signature_v1() {
        let (worker_sk, worker_pk) = self_register_test_key(0x25);
        let (_operator_sk, operator_pk) = self_register_test_key(0x26);
        let mut payload = self_register_test_payload(&worker_sk, &worker_pk, &operator_pk);
        payload.runtime_class = "native-v2".to_string();
        let tx = self_register_test_tx(&payload, &operator_pk, 0);
        let err = validate_compute_tx_syntax(&tx).unwrap_err();
        assert!(err.contains("e2_worker_self_register_worker_signature_invalid"));
    }

    #[test]
    fn validate_compute_tx_syntax_accepts_ngbin_create() {
        let raw = {
            let mut raw = Vec::new();
            raw.push(1u8); // version
            raw.push(1u8); // order_create
            raw.extend_from_slice(&[0xAA; 32]); // job spec hash
            raw.extend_from_slice(&1000u64.to_le_bytes()); // max_time_ms
            raw.push(0u8); // require_trusted
            raw.extend_from_slice(&0.0f64.to_le_bytes()); // min_score
            raw.extend_from_slice(&0.0f64.to_le_bytes()); // min_rep
            raw.extend_from_slice(&0i32.to_le_bytes()); // max_failures
            raw.extend_from_slice(&4u16.to_le_bytes()); // job_kind len
            raw.extend_from_slice(b"wasm");
            raw.extend_from_slice(&0u32.to_le_bytes()); // no payload
            raw
        };
        let memo = format!("{}{}", NGBIN_MEMO_PREFIX, STANDARD.encode(raw));
        let tx = Transaction::new(
            "sender".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(memo),
        );
        validate_compute_tx_syntax(&tx).unwrap();
    }
}

#[cfg(test)]
mod reputation_admission_tests {
    use super::*;

    fn surface(
        score: i32,
        state: &str,
        risk: &str,
        negatives: u64,
    ) -> crate::reputation_score::CanonicalNodeReputationSurfaceV1 {
        crate::reputation_score::CanonicalNodeReputationSurfaceV1 {
            reputation_surface_version: crate::reputation_score::REPUTATION_SURFACE_VERSION_V1
                .to_string(),
            score_formula_version:
                crate::reputation_score::NODE_REPUTATION_SCORE_FORMULA_VERSION_V1.to_string(),
            policy_version: crate::reputation_score::NODE_REPUTATION_POLICY_VERSION_V1.to_string(),
            node_pubkey: "worker-a".to_string(),
            source_height: 42,
            validator_set_member: true,
            active: true,
            revoked: false,
            jailed: false,
            misbehavior_points: 0,
            slashed_count: 0,
            last_slash_height: 0,
            consecutive_missed_turns: 0,
            last_seen_height: 42,
            last_produced_height: 40,
            accepted_positive_run_evidence_count: 0,
            accepted_negative_run_evidence_count: negatives,
            accepted_run_evidence_delta_total: 0,
            last_evidence_height: None,
            effective_score: score,
            eligibility_state: state.to_string(),
            deny_reason: None,
            max_risk_class: risk.to_string(),
        }
    }

    #[test]
    fn compute_worker_admission_accepts_eligible_trusted_worker() {
        let policy = ComputePolicyV1 {
            require_trusted: true,
            min_score: 0.85,
            min_reputation: 0.0,
            max_failures: 2,
        };
        let decision = evaluate_compute_worker_admission_against_node_surface_v1(
            "worker-a",
            Some("order-a".to_string()),
            &policy,
            &surface(910, "ELIGIBLE", "CRITICAL", 0),
        )
        .unwrap();
        assert!(decision.accepted, "{decision:?}");
        assert_eq!(decision.required_min_score, 850);
        assert_eq!(decision.required_risk_class, "CRITICAL");
        assert_eq!(decision.source_commitment, "finalized");
    }

    #[test]
    fn compute_worker_admission_accepts_bound_non_validator_worker_surface() {
        let policy = ComputePolicyV1 {
            require_trusted: false,
            min_score: 0.70,
            min_reputation: 0.0,
            max_failures: -1,
        };
        let mut s = surface(760, "ELIGIBLE", "STANDARD", 0);
        s.validator_set_member = false;
        let decision = evaluate_compute_worker_admission_against_node_surface_v1(
            "worker-a",
            Some("order-e2-worker".to_string()),
            &policy,
            &s,
        )
        .unwrap();
        assert!(decision.accepted, "{decision:?}");
        assert_eq!(decision.required_min_score, 700);
        assert_eq!(decision.required_risk_class, "LOW");
    }

    #[test]
    fn compute_worker_admission_rejects_worker_below_required_risk_class() {
        let policy = ComputePolicyV1 {
            require_trusted: true,
            min_score: 0.0,
            min_reputation: 0.0,
            max_failures: -1,
        };
        let decision = evaluate_compute_worker_admission_against_node_surface_v1(
            "worker-a",
            Some("order-a".to_string()),
            &policy,
            &surface(8_000, "ELIGIBLE", "HIGH", 0),
        )
        .unwrap();
        assert!(!decision.accepted);
        assert!(decision
            .deny_reason
            .unwrap()
            .starts_with("WORKER_RISK_CLASS_TOO_LOW"));
    }

    #[test]
    fn compute_worker_admission_rejects_ineligible_worker_fail_closed() {
        let policy = ComputePolicyV1::default();
        let decision = evaluate_compute_worker_admission_against_node_surface_v1(
            "worker-a",
            None,
            &policy,
            &surface(350, "PROBATION", "STANDARD", 0),
        )
        .unwrap();
        assert!(!decision.accepted);
        assert!(decision
            .deny_reason
            .unwrap()
            .starts_with("WORKER_NOT_ELIGIBLE"));
    }

    #[test]
    fn compute_worker_admission_enforces_policy_max_failures() {
        let policy = ComputePolicyV1 {
            require_trusted: false,
            min_score: 0.0,
            min_reputation: 0.0,
            max_failures: 1,
        };
        let decision = evaluate_compute_worker_admission_against_node_surface_v1(
            "worker-a",
            None,
            &policy,
            &surface(950, "ELIGIBLE", "CRITICAL", 2),
        )
        .unwrap();
        assert!(!decision.accepted);
        assert!(decision
            .deny_reason
            .unwrap()
            .starts_with("WORKER_FAILURE_COUNT_EXCEEDS_POLICY"));
    }

    fn worker_eligibility(score: i32) -> crate::reputation_score::CanonicalWorkerEligibilityV1 {
        crate::reputation_score::CanonicalWorkerEligibilityV1 {
            format_version: crate::reputation_score::WORKER_ELIGIBILITY_SURFACE_VERSION_V1
                .to_string(),
            worker_node_pubkey: "worker-a".to_string(),
            operator_wallet_pubkey: "operator-a".to_string(),
            source_height: 42,
            finalized_height: 42,
            source_commitment: "finalized".to_string(),
            registration_source: "GOVERNANCE_BIND".to_string(),
            chain_known: true,
            eligible_for_probe: true,
            eligible_for_non_probe: true,
            wallet_reputation_score: score,
            node_reliability_score: score,
            effective_score: score,
            role_score_projection_version: Some(
                crate::reputation_score::OPERATOR_ROLE_SCORE_PROJECTION_VERSION_V2.to_string(),
            ),
            operator_reputation: score,
            validator_score: None,
            compute_score: score,
            cloud_unit_score: if score >= crate::reputation_score::WORKER_CLOUD_UNIT_MIN_SCORE_V1 {
                score
            } else {
                0
            },
            gpu_score: if score >= crate::reputation_score::WORKER_GPU_MIN_SCORE_V1 {
                score
            } else {
                0
            },
            critical_score: if score >= crate::reputation_score::WORKER_CRITICAL_MIN_SCORE_V1 {
                score
            } else {
                0
            },
            eligibility_state: "ACTIVE".to_string(),
            tier: "ACTIVE".to_string(),
            max_risk_class: if score >= 950 {
                "CRITICAL"
            } else if score >= 920 {
                "HIGH"
            } else if score >= 850 {
                "STANDARD"
            } else {
                "LOW"
            }
            .to_string(),
            cloud_unit_allowed: score >= 850,
            cloud_unit_grant_proposal_id: (score >= 850).then(|| "cloud-proposal-test".to_string()),
            cloud_unit_grant_payload_hash: (score >= 850).then(|| "aa".repeat(32)),
            long_running_allowed: score >= 900 && score >= 850,
            gpu_allowed: score >= 920,
            gpu_grant_proposal_id: (score >= 920).then(|| "gpu-proposal-test".to_string()),
            gpu_grant_payload_hash: (score >= 920).then(|| "bb".repeat(32)),
            critical_workload_allowed: score >= 950,
            critical_workload_grant_proposal_id: (score >= 950)
                .then(|| "critical-proposal-test".to_string()),
            critical_workload_grant_payload_hash: (score >= 950).then(|| "cc".repeat(32)),
            critical_workload_review_proposal_id: (score >= 950)
                .then(|| "critical-review-proposal-test".to_string()),
            critical_workload_review_payload_hash: (score >= 950).then(|| "dd".repeat(32)),
            max_parallel_jobs: if score >= 950 {
                16
            } else if score >= 920 {
                8
            } else if score >= 850 {
                4
            } else {
                1
            },
            max_job_duration_sec: if score >= 950 {
                86_400
            } else if score >= 900 {
                21_600
            } else if score >= 850 {
                3_600
            } else {
                900
            },
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
            policy_version: crate::reputation_score::WORKER_ELIGIBILITY_POLICY_VERSION_V1
                .to_string(),
        }
    }

    #[test]
    fn compute_worker_admission_accepts_active_base_worker_at_650_v1() {
        let policy = ComputePolicyV1::default();
        let eligibility =
            worker_eligibility(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            Some("order-active-base".to_string()),
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(decision.accepted, "{decision:?}");
        assert_eq!(
            decision.required_min_score,
            crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1
        );
        assert_eq!(decision.required_risk_class, "LOW");
    }

    #[test]
    fn compute_worker_admission_rejects_worker_below_active_base_floor_v1() {
        let policy = ComputePolicyV1::default();
        let mut eligibility =
            worker_eligibility(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1 - 1);
        eligibility.eligible_for_non_probe = false;
        eligibility.eligibility_state = "PROBATION".to_string();
        eligibility.tier = "PROBATION".to_string();
        eligibility.max_risk_class = "NONE".to_string();
        eligibility.max_parallel_jobs = 0;
        eligibility.max_job_duration_sec = 0;
        eligibility.deny_reason = Some("base_non_probe_score_below_threshold".to_string());
        eligibility.next_recovery_action = Some("collect_more_evidence".to_string());

        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            Some("order-below-active-base".to_string()),
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(!decision.accepted);
        assert!(decision
            .deny_reason
            .unwrap()
            .starts_with("WORKER_NOT_ACTIVE:PROBATION:base_non_probe_score_below_threshold"));
    }

    #[test]
    fn compute_worker_admission_rejects_malformed_worker_eligibility_surface() {
        let policy = ComputePolicyV1::default();
        let mut eligibility = worker_eligibility(950);
        eligibility.eligibility_state = "PROBATION".to_string();
        eligibility.tier = "PROBATION".to_string();
        let err = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            None,
            &policy,
            &eligibility,
        )
        .unwrap_err();
        assert!(err.contains("worker_eligibility_non_probe_bad_state"));
    }

    #[test]
    fn compute_worker_admission_accepts_finalized_commitment_case_insensitively() {
        let policy = ComputePolicyV1::default();
        let mut eligibility = worker_eligibility(950);
        eligibility.source_commitment = "FINALIZED".to_string();
        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            None,
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(decision.accepted, "{decision:?}");
    }

    #[test]
    fn compute_worker_admission_rejects_duration_above_worker_limit() {
        let policy = ComputePolicyV1::default();
        let eligibility = worker_eligibility(880);
        let decision =
            evaluate_compute_worker_admission_against_worker_eligibility_with_order_limits_v1(
                "worker-a",
                Some("order-a".to_string()),
                &policy,
                &eligibility,
                3_600_001,
            )
            .unwrap();
        assert!(!decision.accepted);
        assert!(decision
            .deny_reason
            .unwrap()
            .starts_with("WORKER_JOB_DURATION_EXCEEDS_ELIGIBILITY"));
    }

    #[test]
    fn compute_worker_admission_requires_exact_cloud_unit_capability_v1() {
        let policy = ComputePolicyV1 {
            require_trusted: false,
            min_score: crate::reputation_score::WORKER_CLOUD_UNIT_MIN_SCORE_V1 as f64,
            min_reputation: 0.0,
            max_failures: -1,
        };
        let mut eligibility = worker_eligibility(crate::reputation_score::WORKER_GPU_MIN_SCORE_V1);
        eligibility.cloud_unit_allowed = false;
        eligibility.cloud_unit_score = 0;
        eligibility.cloud_unit_grant_proposal_id = None;
        eligibility.cloud_unit_grant_payload_hash = None;
        eligibility.long_running_allowed = false;
        eligibility.max_risk_class = "HIGH".to_string();
        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            Some("order-cloud-exact".to_string()),
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_CLOUD_UNIT_NOT_ALLOWED")
        );
    }

    #[test]
    fn compute_worker_admission_requires_exact_gpu_capability_v1() {
        let policy = ComputePolicyV1 {
            require_trusted: false,
            min_score: crate::reputation_score::WORKER_GPU_MIN_SCORE_V1 as f64,
            min_reputation: 0.0,
            max_failures: -1,
        };
        let mut eligibility =
            worker_eligibility(crate::reputation_score::WORKER_CRITICAL_MIN_SCORE_V1);
        eligibility.gpu_allowed = false;
        eligibility.gpu_score = 0;
        eligibility.gpu_grant_proposal_id = None;
        eligibility.gpu_grant_payload_hash = None;
        eligibility.max_risk_class = "CRITICAL".to_string();
        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            Some("order-gpu-exact".to_string()),
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_GPU_NOT_ALLOWED")
        );
    }

    #[test]
    fn compute_worker_admission_rejects_trusted_policy_without_critical_capability() {
        let policy = ComputePolicyV1 {
            require_trusted: true,
            min_score: 0.0,
            min_reputation: 0.0,
            max_failures: -1,
        };
        let eligibility = worker_eligibility(920);
        let decision = evaluate_compute_worker_admission_against_worker_eligibility_v1(
            "worker-a",
            Some("order-a".to_string()),
            &policy,
            &eligibility,
        )
        .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_CRITICAL_WORKLOAD_NOT_ALLOWED")
        );
    }

    #[test]
    fn fiat_settlement_proof_simulated_validates_without_real_money() {
        let mut proof = ComputeFiatSettlementProofV1 {
            format_version: COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1.to_string(),
            settlement_mode: COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED.to_string(),
            settlement_policy_version: COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1.to_string(),
            order_id: "order-1".to_string(),
            job_id: "job-1".to_string(),
            quote_id: Some("quote-1".to_string()),
            worker_operator_wallet: "worker-wallet".to_string(),
            billing_quote_hash: "44".repeat(32),
            billing_ref_hash: String::new(),
            currency: "EUR".to_string(),
            gross_amount_cents: 1000,
            worker_payout_cents: 800,
            protocol_fee_cents: 150,
            reserve_cents: 50,
            burn_cents: 0,
            payment_ref_hash: Some("11".repeat(32)),
            payout_ref_hash: None,
            receipt_hash: "22".repeat(32),
            finalized_height: 42,
        };
        finalize_billing_ref_hash(&mut proof);
        proof.validate_contract_v1().unwrap();
    }

    #[test]
    fn fiat_settlement_billing_ref_hash_binds_billing_quote_hash() {
        let mut proof = ComputeFiatSettlementProofV1 {
            format_version: COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1.to_string(),
            settlement_mode: COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED.to_string(),
            settlement_policy_version: COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1.to_string(),
            order_id: "order-1".to_string(),
            job_id: "job-1".to_string(),
            quote_id: Some("quote-1".to_string()),
            worker_operator_wallet: "wallet-1".to_string(),
            billing_quote_hash: "11".repeat(32),
            billing_ref_hash: String::new(),
            currency: "EUR".to_string(),
            gross_amount_cents: 1000,
            worker_payout_cents: 800,
            protocol_fee_cents: 150,
            reserve_cents: 50,
            burn_cents: 0,
            payment_ref_hash: Some("22".repeat(32)),
            payout_ref_hash: Some("33".repeat(32)),
            receipt_hash: "44".repeat(32),
            finalized_height: 42,
        };
        let h1 = compute_fiat_settlement_billing_ref_hash_v1(&proof).unwrap();
        proof.billing_quote_hash = "55".repeat(32);
        let h2 = compute_fiat_settlement_billing_ref_hash_v1(&proof).unwrap();
        assert_eq!(h1.len(), 64);
        assert_eq!(
            h1, "b4767239c624faa5125ae14a6f2965e760a10afdfb17a952e8aeb1c0674a752e",
            "L1 billing_ref_hash contract vector must stay byte-for-byte compatible with E2",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn fiat_settlement_proof_rejects_live_until_explicitly_enabled() {
        let mut proof = ComputeFiatSettlementProofV1 {
            format_version: COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1.to_string(),
            settlement_mode: COMPUTE_FIAT_SETTLEMENT_MODE_FIAT_LIVE.to_string(),
            settlement_policy_version: COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1.to_string(),
            order_id: "order-1".to_string(),
            job_id: "job-1".to_string(),
            quote_id: Some("quote-1".to_string()),
            worker_operator_wallet: "worker-wallet".to_string(),
            billing_quote_hash: "44".repeat(32),
            billing_ref_hash: String::new(),
            currency: "EUR".to_string(),
            gross_amount_cents: 1000,
            worker_payout_cents: 800,
            protocol_fee_cents: 150,
            reserve_cents: 50,
            burn_cents: 0,
            payment_ref_hash: Some("11".repeat(32)),
            payout_ref_hash: Some("33".repeat(32)),
            receipt_hash: "22".repeat(32),
            finalized_height: 42,
        };
        finalize_billing_ref_hash(&mut proof);
        let err = proof.validate_contract_v1().unwrap_err();
        assert_eq!(err, "compute_fiat_settlement_fiat_live_disabled");
        proof
            .validate_contract_with_fiat_live_policy_v1(true)
            .unwrap();
    }

    #[test]
    fn fiat_settlement_proof_rejects_billing_quote_hash_invalid() {
        let mut proof = ComputeFiatSettlementProofV1 {
            format_version: COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1.to_string(),
            settlement_mode: COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED.to_string(),
            settlement_policy_version: COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1.to_string(),
            order_id: "order-1".to_string(),
            job_id: "job-1".to_string(),
            quote_id: Some("quote-1".to_string()),
            worker_operator_wallet: "worker-wallet".to_string(),
            billing_quote_hash: "not-hex".to_string(),
            billing_ref_hash: String::new(),
            currency: "EUR".to_string(),
            gross_amount_cents: 1000,
            worker_payout_cents: 800,
            protocol_fee_cents: 150,
            reserve_cents: 50,
            burn_cents: 0,
            payment_ref_hash: Some("11".repeat(32)),
            payout_ref_hash: None,
            receipt_hash: "22".repeat(32),
            finalized_height: 42,
        };
        proof.billing_ref_hash = "00".repeat(32);
        let err = proof.validate_contract_v1().unwrap_err();
        assert_eq!(err, "compute_fiat_settlement_billing_quote_hash_invalid");
    }

    #[test]
    fn fiat_settlement_proof_rejects_split_mismatch() {
        let mut proof = ComputeFiatSettlementProofV1 {
            format_version: COMPUTE_FIAT_SETTLEMENT_PROOF_FORMAT_VERSION_V1.to_string(),
            settlement_mode: COMPUTE_FIAT_SETTLEMENT_MODE_SIMULATED.to_string(),
            settlement_policy_version: COMPUTE_FIAT_SETTLEMENT_POLICY_VERSION_V1.to_string(),
            order_id: "order-1".to_string(),
            job_id: "job-1".to_string(),
            quote_id: Some("quote-1".to_string()),
            worker_operator_wallet: "worker-wallet".to_string(),
            billing_quote_hash: "44".repeat(32),
            billing_ref_hash: String::new(),
            currency: "EUR".to_string(),
            gross_amount_cents: 1000,
            worker_payout_cents: 700,
            protocol_fee_cents: 150,
            reserve_cents: 50,
            burn_cents: 0,
            payment_ref_hash: None,
            payout_ref_hash: None,
            receipt_hash: "22".repeat(32),
            finalized_height: 42,
        };
        finalize_billing_ref_hash(&mut proof);
        let err = proof.validate_contract_v1().unwrap_err();
        assert!(err.contains("compute_fiat_settlement_split_mismatch"));
    }

    #[test]
    fn compute_worker_admission_rejects_underdeclared_cloud_unit_job_kind_v1() {
        let policy = ComputePolicyV1::default();
        let eligibility =
            worker_eligibility(crate::reputation_score::WORKER_ACTIVE_BASE_MIN_SCORE_V1);
        let decision =
            evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
                "worker-a",
                Some("order-underdeclared-cloud".to_string()),
                &policy,
                &eligibility,
                60_000,
                Some("cloud_unit_lease_v1"),
            )
            .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_CLOUD_UNIT_NOT_ALLOWED")
        );
    }

    #[test]
    fn compute_worker_admission_rejects_underdeclared_gpu_job_kind_v1() {
        let policy = ComputePolicyV1::default();
        let eligibility =
            worker_eligibility(crate::reputation_score::WORKER_CLOUD_UNIT_MIN_SCORE_V1);
        let decision =
            evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
                "worker-a",
                Some("order-underdeclared-gpu".to_string()),
                &policy,
                &eligibility,
                60_000,
                Some("gpu_inference_v1"),
            )
            .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_GPU_NOT_ALLOWED")
        );
    }

    #[test]
    fn compute_worker_admission_rejects_underdeclared_critical_job_kind_v1() {
        let policy = ComputePolicyV1::default();
        let eligibility = worker_eligibility(crate::reputation_score::WORKER_GPU_MIN_SCORE_V1);
        let decision =
            evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
                "worker-a",
                Some("order-underdeclared-critical".to_string()),
                &policy,
                &eligibility,
                60_000,
                Some("critical_workload_v1"),
            )
            .unwrap();
        assert!(!decision.accepted);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some("WORKER_CRITICAL_WORKLOAD_NOT_ALLOWED")
        );
    }

    #[test]
    fn compute_worker_admission_rejects_unknown_job_kind_fail_closed_v1() {
        let policy = ComputePolicyV1::default();
        let eligibility = worker_eligibility(crate::reputation_score::WORKER_CRITICAL_MIN_SCORE_V1);
        let err =
            evaluate_compute_worker_admission_against_worker_eligibility_with_order_context_v1(
                "worker-a",
                Some("order-unknown-kind".to_string()),
                &policy,
                &eligibility,
                60_000,
                Some("unknown_privileged_kind_v1"),
            )
            .unwrap_err();
        assert!(err.contains("compute_job_kind_unknown_or_unclassified"));
    }

    #[test]
    fn validate_compute_tx_syntax_rejects_missing_order_create_job_kind_v1() {
        let tx = Transaction::new(
            "sender".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(r#"{"v":1,"op":"order_create","job_spec_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_time_ms":1000}"#.to_string()),
        );
        let err = validate_compute_tx_syntax(&tx).unwrap_err();
        assert_eq!(err, "compute_job_kind_missing");
    }

    #[test]
    fn validate_compute_tx_syntax_rejects_unknown_order_create_job_kind_v1() {
        let tx = Transaction::new(
            "sender".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(r#"{"v":1,"op":"order_create","job_spec_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_time_ms":1000,"job_kind":"unknown_privileged_kind_v1"}"#.to_string()),
        );
        let err = validate_compute_tx_syntax(&tx).unwrap_err();
        assert!(err.contains("compute_job_kind_unknown_or_unclassified"));
    }
}

#[cfg(test)]
mod v34_compute_order_surface_tests {
    use super::*;

    #[test]
    fn required_workload_class_from_job_kind_missing_fails_closed_v34() {
        let err = required_compute_workload_class_from_job_kind_v1(None).unwrap_err();
        assert_eq!(err, "compute_job_kind_missing");
    }

    #[test]
    fn required_workload_class_from_job_kind_unknown_fails_closed_v34() {
        let err = required_compute_workload_class_from_job_kind_v1(Some("unknown_gpuish_work"))
            .unwrap_err();
        assert!(err.starts_with("compute_job_kind_unknown_or_unclassified:"));
    }

    #[test]
    fn order_record_v2_flattens_legacy_order_and_adds_canonical_class_v34() {
        let policy = ComputePolicyV1::default();
        let rec = ComputeOrderRecordV1 {
            format_version: COMPUTE_SURFACE_FORMAT_VERSION_V1,
            order_id: "order-v34".to_string(),
            payer: "payer".to_string(),
            amount: 1,
            job_spec_hash: "11".repeat(32),
            max_time_ms: 60_000,
            policy,
            status: ComputeOrderStatusV1::Open,
            created_height: 1,
            claimed_worker: None,
            claim_height: None,
            completed_height: None,
            result_hash: None,
            artifact_root_hash: None,
            receipt_hash: None,
            fail_reason: None,
        };
        let metadata = ComputeOrderRuntimeMetadataV1 {
            job_kind: "hash_sha256_v1".to_string(),
            required_workload_class: RequiredComputeWorkloadClassV1::Base,
        };
        let v2 = compute_order_record_v2_from_record_and_metadata_v1(rec, &metadata);
        assert_eq!(v2.order.order_id, "order-v34");
        assert_eq!(v2.job_kind, "hash_sha256_v1");
        assert_eq!(v2.required_workload_class, "BASE");
        assert_eq!(
            v2.workload_class_policy_version,
            COMPUTE_WORKLOAD_CLASS_POLICY_VERSION_V1
        );
    }
}

#[cfg(test)]
mod v36_compute_order_state_store_tests {
    use super::*;

    fn compute_create_tx_v36(job_kind: &str) -> Transaction {
        Transaction::new(
            "payer".to_string(),
            COMPUTE_RECEIVER.to_string(),
            10,
            1,
            0,
            "sig".to_string(),
            false,
            Some(format!(
                "{{\"v\":1,\"op\":\"order_create\",\"job_spec_hash\":\"{}\",\"max_time_ms\":1000,\"job_kind\":\"{}\"}}",
                "aa".repeat(32),
                job_kind
            )),
        )
    }

    #[test]
    fn compute_order_state_store_rebuild_from_genesis_is_surface_complete_v36() {
        let mut genesis = Block::default();
        genesis.index = 0;
        genesis.hash = "00".repeat(32);

        let mut block1 = Block::default();
        block1.index = 1;
        block1.previous_hash = genesis.hash.clone();
        block1.hash = "01".repeat(32);
        let tx = compute_create_tx_v36("hash_sha256_v1");
        let order_id = tx.hash.clone();
        block1.transactions.push(tx);

        let store = compute_order_state_store_rebuild_from_blocks_v1(&[genesis, block1], 0)
            .expect("full-history store rebuild must pass");
        assert!(store.complete_from_genesis);
        assert_eq!(store.first_applied_height, 0);
        assert_eq!(store.last_applied_height, 1);
        assert!(store.orders.contains_key(&order_id));
        assert_eq!(
            store
                .metadata_by_order_id
                .get(&order_id)
                .unwrap()
                .required_workload_class,
            RequiredComputeWorkloadClassV1::Base
        );
        let events = store
            .events_by_height
            .get(&1)
            .expect("block1 compute events indexed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "create");
        assert_eq!(events[0].order_id, order_id);
    }

    #[test]
    fn compute_order_state_store_started_above_genesis_is_forward_only_not_surface_complete_v36() {
        let mut block10 = Block::default();
        block10.index = 10;
        block10.hash = "10".repeat(32);

        let mut store = ComputeOrderStateStoreV1::default();
        compute_order_state_store_apply_block_v1(&mut store, &block10, 0)
            .expect("forward-only pruned store may keep applying new blocks");
        assert_eq!(store.first_applied_height, 10);
        assert!(!store.complete_from_genesis);
    }
}

#[cfg(test)]
mod v38_compute_order_finalized_prefix_tests {
    use super::*;

    fn tx_with_memo(sender: &str, amount: u64, nonce: u64, memo: String) -> Transaction {
        Transaction::new(
            sender.to_string(),
            COMPUTE_RECEIVER.to_string(),
            amount,
            nonce,
            0,
            "sig".to_string(),
            false,
            Some(memo),
        )
    }

    #[test]
    fn compute_order_state_store_bound_to_finalized_height_excludes_future_complete_v38() {
        let mut genesis = Block::default();
        genesis.index = 0;
        genesis.hash = "00".repeat(32);

        let create = tx_with_memo(
            "payer",
            10,
            1,
            format!(
                r#"{{"v":1,"op":"order_create","job_spec_hash":"{}","max_time_ms":1000,"job_kind":"hash_sha256_v1"}}"#,
                "aa".repeat(32)
            ),
        );
        let order_id = create.hash.clone();

        let claim = tx_with_memo(
            "worker",
            0,
            2,
            format!(r#"{{"v":1,"op":"order_claim","order_id":"{}"}}"#, order_id),
        );
        let complete = tx_with_memo(
            "worker",
            0,
            3,
            format!(
                r#"{{"v":1,"op":"order_complete","order_id":"{}","result_hash":"{}","exit_code":0}}"#,
                order_id,
                "bb".repeat(32)
            ),
        );

        let mut block1 = Block::default();
        block1.index = 1;
        block1.previous_hash = genesis.hash.clone();
        block1.hash = "01".repeat(32);
        block1.transactions.push(create);

        let mut block2 = Block::default();
        block2.index = 2;
        block2.previous_hash = block1.hash.clone();
        block2.hash = "02".repeat(32);
        block2.transactions.push(claim);

        let mut block3 = Block::default();
        block3.index = 3;
        block3.previous_hash = block2.hash.clone();
        block3.hash = "03".repeat(32);
        block3.transactions.push(complete);

        let store = compute_order_state_store_rebuild_from_blocks_v1(
            &[genesis, block1, block2.clone(), block3.clone()],
            0,
        )
        .expect("store rebuild must pass");
        assert_eq!(store.last_applied_height, 3);

        let finalized_prefix =
            compute_order_state_store_bound_to_height_v1(&store, 2, block2.hash.as_str())
                .expect("prefix bind at finalized height must pass");
        let order_at_2 = finalized_prefix.orders.get(&order_id).unwrap();
        assert_eq!(order_at_2.status, ComputeOrderStatusV1::Claimed);
        assert_eq!(order_at_2.completed_height, None);

        let tip_view =
            compute_order_state_store_bound_to_height_v1(&store, 3, block3.hash.as_str())
                .expect("tip bind must pass");
        let order_at_3 = tip_view.orders.get(&order_id).unwrap();
        assert_eq!(order_at_3.status, ComputeOrderStatusV1::Completed);
        assert_eq!(order_at_3.completed_height, Some(3));
    }
}
