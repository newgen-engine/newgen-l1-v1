use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN_COG_ATTEST_ENVELOPE_V1: &str = "cog_attest_envelope_v1";
const DOMAIN_COG_DISPUTE_V1: &str = "cog_dispute_v1";
const DOMAIN_COG_REVOKE_V1: &str = "cog_revoke_v1";
const DOMAIN_COG_SUPERSEDE_V1: &str = "cog_supersede_v1";
const DOMAIN_COG_ATTEST_CERT_V1: &str = "cog_attest_cert_v1";

pub const COGNITIVE_REGISTRY_ENTRY_KEY_PREFIX: &str = "entry:";
pub const COGNITIVE_REGISTRY_CLAIM_INDEX_KEY_PREFIX: &str = "claim:";
pub const COGNITIVE_REGISTRY_EVENT_KEY_PREFIX: &str = "event:";
pub const COGNITIVE_REGISTRY_META_LAST_APPLIED_HEIGHT_KEY: &[u8] = b"meta:last_applied_height";
pub const COGNITIVE_REGISTRY_META_LAST_EVENT_SEQ_KEY: &[u8] = b"meta:last_event_seq";

pub mod canonical_cognitive_surface_v1 {
    include!("../canonical_contracts_rs/src/cognitive_registry_surface_v1.rs");
}

pub use canonical_cognitive_surface_v1::ChainRegistryEffectiveStatusV1 as CognitiveRegistryEffectiveStatusV1;
pub use canonical_cognitive_surface_v1::COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CognitiveRegistryLifecycleStateV1 {
    Active,
    Contested,
    Revoked,
    Superseded,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CognitiveTxKindV1 {
    Anchor,
    Dispute,
    Revoke,
    Supersede,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveAttestationEnvelopeV1 {
    pub chain_id: String,
    pub genesis_hash: String,
    pub object_hash_hex: String,
    pub claim_hash_hex: String,
    pub evidence_root_hex: String,
    pub context_hash_hex: String,
    pub policy_id: String,
    pub model_manifest_hash_hex: String,
    pub created_at_height: u64,
    pub created_at_ts: u64,
}

impl CognitiveAttestationEnvelopeV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty_no_separator("chain_id", &self.chain_id)?;
        validate_sha256_hex_field("genesis_hash", &self.genesis_hash)?;
        validate_sha256_hex_field("object_hash_hex", &self.object_hash_hex)?;
        validate_sha256_hex_field("claim_hash_hex", &self.claim_hash_hex)?;
        validate_sha256_hex_field("evidence_root_hex", &self.evidence_root_hex)?;
        validate_sha256_hex_field("context_hash_hex", &self.context_hash_hex)?;
        validate_non_empty_no_separator("policy_id", &self.policy_id)?;
        validate_sha256_hex_field("model_manifest_hash_hex", &self.model_manifest_hash_hex)?;
        Ok(())
    }

    pub fn canonical_string(&self) -> Result<String, String> {
        self.validate()?;
        Ok(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            DOMAIN_COG_ATTEST_ENVELOPE_V1,
            self.chain_id,
            self.genesis_hash,
            self.object_hash_hex,
            self.claim_hash_hex,
            self.evidence_root_hex,
            self.context_hash_hex,
            self.policy_id,
            self.model_manifest_hash_hex,
            self.created_at_height,
            self.created_at_ts
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.canonical_string()?.into_bytes())
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveAttestationSigV1 {
    pub signer_public_key_b64: String,
    pub signature_b64: String,
}

impl CognitiveAttestationSigV1 {
    pub fn validate_format(&self) -> Result<(), String> {
        let pk = STANDARD
            .decode(&self.signer_public_key_b64)
            .map_err(|e| format!("signer_public_key_b64 decode failed: {e}"))?;
        if pk.len() != 32 {
            return Err(format!(
                "signer_public_key_b64 len={} (expected 32)",
                pk.len()
            ));
        }
        let sig = STANDARD
            .decode(&self.signature_b64)
            .map_err(|e| format!("signature_b64 decode failed: {e}"))?;
        if sig.len() != 64 {
            return Err(format!("signature_b64 len={} (expected 64)", sig.len()));
        }
        Ok(())
    }

    pub fn signer_public_key_hex(&self) -> Result<String, String> {
        self.validate_format()?;
        let pk = STANDARD
            .decode(&self.signer_public_key_b64)
            .map_err(|e| format!("signer_public_key_b64 decode failed: {e}"))?;
        Ok(hex::encode(pk))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveAttestationCertV1 {
    pub envelope: CognitiveAttestationEnvelopeV1,
    /// Canonical order: sorted ascending by signer_public_key_b64.
    pub sigs: Vec<CognitiveAttestationSigV1>,
}

impl CognitiveAttestationCertV1 {
    pub fn canonical_string(&self) -> Result<String, String> {
        self.envelope.validate()?;
        if self.sigs.is_empty() {
            return Err("attestation cert must contain at least one signature".to_string());
        }
        let envelope_hash = self.envelope.canonical_hash_hex()?;
        let mut prev_signer: Option<&str> = None;
        let mut parts = vec![DOMAIN_COG_ATTEST_CERT_V1.to_string(), envelope_hash];
        for sig in &self.sigs {
            sig.validate_format()?;
            if let Some(prev) = prev_signer {
                if sig.signer_public_key_b64.as_str() < prev {
                    return Err(
                        "attestation cert signatures are not sorted canonically".to_string()
                    );
                }
            }
            prev_signer = Some(sig.signer_public_key_b64.as_str());
            parts.push(sig.signer_public_key_b64.clone());
            parts.push(sig.signature_b64.clone());
        }
        Ok(parts.join("|"))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.canonical_string()?.into_bytes())
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn validate(&self, min_signatures: usize) -> Result<(), String> {
        if min_signatures == 0 {
            return Err("min_signatures must be >= 1".to_string());
        }
        self.envelope.validate()?;
        if self.sigs.len() < min_signatures {
            return Err(format!(
                "attestation cert signatures insufficient: got {} need {}",
                self.sigs.len(),
                min_signatures
            ));
        }

        let canonical = self.envelope.canonical_bytes()?;
        let mut prev_signer: Option<&str> = None;
        let mut seen = std::collections::HashSet::new();
        for sig in &self.sigs {
            sig.validate_format()?;
            if let Some(prev) = prev_signer {
                if sig.signer_public_key_b64.as_str() < prev {
                    return Err(
                        "attestation cert signatures are not sorted canonically".to_string()
                    );
                }
            }
            prev_signer = Some(sig.signer_public_key_b64.as_str());
            let signer_hex = sig.signer_public_key_hex()?;
            if !seen.insert(signer_hex) {
                return Err("duplicate signer in attestation cert".to_string());
            }
            verify_ed25519_b64_signature(
                &canonical,
                &sig.signer_public_key_b64,
                &sig.signature_b64,
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveTxAnchorV1 {
    pub attestation_cert: CognitiveAttestationCertV1,
}

impl CognitiveTxAnchorV1 {
    pub fn validate(&self, min_signatures: usize) -> Result<(), String> {
        self.attestation_cert.validate(min_signatures)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveTxDisputeV1 {
    pub target_object_hash_hex: String,
    pub reason_code: String,
    pub dispute_evidence_root_hex: String,
    pub submitter_public_key_b64: String,
    pub signature_b64: String,
}

impl CognitiveTxDisputeV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_sha256_hex_field("target_object_hash_hex", &self.target_object_hash_hex)?;
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        validate_sha256_hex_field("dispute_evidence_root_hex", &self.dispute_evidence_root_hex)?;
        validate_ed25519_signature_fields(
            &self.submitter_public_key_b64,
            &self.signature_b64,
            &self.canonical_bytes()?,
        )?;
        Ok(())
    }

    pub fn canonical_string(&self) -> Result<String, String> {
        validate_sha256_hex_field("target_object_hash_hex", &self.target_object_hash_hex)?;
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        validate_sha256_hex_field("dispute_evidence_root_hex", &self.dispute_evidence_root_hex)?;
        Ok(format!(
            "{}|{}|{}|{}",
            DOMAIN_COG_DISPUTE_V1,
            self.target_object_hash_hex,
            self.reason_code,
            self.dispute_evidence_root_hex
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.canonical_string()?.into_bytes())
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveTxRevokeV1 {
    pub target_object_hash_hex: String,
    pub reason_code: String,
    pub authority_public_key_b64: String,
    pub signature_b64: String,
}

impl CognitiveTxRevokeV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_sha256_hex_field("target_object_hash_hex", &self.target_object_hash_hex)?;
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        validate_ed25519_signature_fields(
            &self.authority_public_key_b64,
            &self.signature_b64,
            &self.canonical_bytes()?,
        )?;
        Ok(())
    }

    pub fn canonical_string(&self) -> Result<String, String> {
        validate_sha256_hex_field("target_object_hash_hex", &self.target_object_hash_hex)?;
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        Ok(format!(
            "{}|{}|{}",
            DOMAIN_COG_REVOKE_V1, self.target_object_hash_hex, self.reason_code
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.canonical_string()?.into_bytes())
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveTxSupersedeV1 {
    pub old_object_hash_hex: String,
    pub new_object_hash_hex: String,
    pub reason_code: String,
    pub authority_public_key_b64: String,
    pub signature_b64: String,
}

impl CognitiveTxSupersedeV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_sha256_hex_field("old_object_hash_hex", &self.old_object_hash_hex)?;
        validate_sha256_hex_field("new_object_hash_hex", &self.new_object_hash_hex)?;
        if self.old_object_hash_hex == self.new_object_hash_hex {
            return Err(
                "supersede old_object_hash_hex must differ from new_object_hash_hex".to_string(),
            );
        }
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        validate_ed25519_signature_fields(
            &self.authority_public_key_b64,
            &self.signature_b64,
            &self.canonical_bytes()?,
        )?;
        Ok(())
    }

    pub fn canonical_string(&self) -> Result<String, String> {
        validate_sha256_hex_field("old_object_hash_hex", &self.old_object_hash_hex)?;
        validate_sha256_hex_field("new_object_hash_hex", &self.new_object_hash_hex)?;
        if self.old_object_hash_hex == self.new_object_hash_hex {
            return Err(
                "supersede old_object_hash_hex must differ from new_object_hash_hex".to_string(),
            );
        }
        validate_non_empty_no_separator("reason_code", &self.reason_code)?;
        Ok(format!(
            "{}|{}|{}|{}",
            DOMAIN_COG_SUPERSEDE_V1,
            self.old_object_hash_hex,
            self.new_object_hash_hex,
            self.reason_code
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.canonical_string()?.into_bytes())
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CognitiveTxV1 {
    Anchor(CognitiveTxAnchorV1),
    Dispute(CognitiveTxDisputeV1),
    Revoke(CognitiveTxRevokeV1),
    Supersede(CognitiveTxSupersedeV1),
}

impl CognitiveTxV1 {
    pub fn kind(&self) -> CognitiveTxKindV1 {
        match self {
            CognitiveTxV1::Anchor(_) => CognitiveTxKindV1::Anchor,
            CognitiveTxV1::Dispute(_) => CognitiveTxKindV1::Dispute,
            CognitiveTxV1::Revoke(_) => CognitiveTxKindV1::Revoke,
            CognitiveTxV1::Supersede(_) => CognitiveTxKindV1::Supersede,
        }
    }

    pub fn validate(&self, min_anchor_signatures: usize) -> Result<(), String> {
        match self {
            CognitiveTxV1::Anchor(v) => v.validate(min_anchor_signatures),
            CognitiveTxV1::Dispute(v) => v.validate(),
            CognitiveTxV1::Revoke(v) => v.validate(),
            CognitiveTxV1::Supersede(v) => v.validate(),
        }
    }

    pub fn canonical_hash_hex(&self) -> Result<String, String> {
        match self {
            CognitiveTxV1::Anchor(v) => v.attestation_cert.canonical_hash_hex(),
            CognitiveTxV1::Dispute(v) => v.canonical_hash_hex(),
            CognitiveTxV1::Revoke(v) => v.canonical_hash_hex(),
            CognitiveTxV1::Supersede(v) => v.canonical_hash_hex(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveRegistryEntryV1 {
    pub object_hash_hex: String,
    pub claim_hash_hex: String,
    pub lifecycle_state: CognitiveRegistryLifecycleStateV1,
    pub policy_id: String,
    pub anchor_height: u64,
    pub anchor_block_hash: String,
    pub evidence_root_hex: String,
    pub context_hash_hex: String,
    pub model_manifest_hash_hex: String,
    pub supersedes: Option<String>,
    pub superseded_by: Option<String>,
    pub dispute_ref: Option<String>,
    pub revoke_ref: Option<String>,
    pub updated_at_height: u64,
}

impl CognitiveRegistryEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_sha256_hex_field("object_hash_hex", &self.object_hash_hex)?;
        validate_sha256_hex_field("claim_hash_hex", &self.claim_hash_hex)?;
        validate_non_empty_no_separator("policy_id", &self.policy_id)?;
        validate_sha256_hex_field("anchor_block_hash", &self.anchor_block_hash)?;
        validate_sha256_hex_field("evidence_root_hex", &self.evidence_root_hex)?;
        validate_sha256_hex_field("context_hash_hex", &self.context_hash_hex)?;
        validate_sha256_hex_field("model_manifest_hash_hex", &self.model_manifest_hash_hex)?;
        validate_optional_sha256_hex_field("supersedes", &self.supersedes)?;
        validate_optional_sha256_hex_field("superseded_by", &self.superseded_by)?;
        validate_optional_sha256_hex_field("dispute_ref", &self.dispute_ref)?;
        validate_optional_sha256_hex_field("revoke_ref", &self.revoke_ref)?;

        if let Some(v) = &self.supersedes {
            if v == &self.object_hash_hex {
                return Err("supersedes must differ from object_hash_hex".to_string());
            }
        }
        if let Some(v) = &self.superseded_by {
            if v == &self.object_hash_hex {
                return Err("superseded_by must differ from object_hash_hex".to_string());
            }
        }
        if let (Some(left), Some(right)) = (&self.supersedes, &self.superseded_by) {
            if left == right {
                return Err(
                    "supersedes and superseded_by must not point to the same object".to_string(),
                );
            }
        }

        match self.lifecycle_state {
            CognitiveRegistryLifecycleStateV1::Active => {}
            CognitiveRegistryLifecycleStateV1::Contested => {
                if self.dispute_ref.is_none() {
                    return Err("contested registry entry requires dispute_ref".to_string());
                }
            }
            CognitiveRegistryLifecycleStateV1::Revoked => {
                if self.revoke_ref.is_none() {
                    return Err("revoked registry entry requires revoke_ref".to_string());
                }
            }
            CognitiveRegistryLifecycleStateV1::Superseded => {
                if self.superseded_by.is_none() {
                    return Err("superseded registry entry requires superseded_by".to_string());
                }
            }
        }
        Ok(())
    }

    pub fn effective_status(&self, finalized_height: u64) -> CognitiveRegistryEffectiveStatusV1 {
        effective_status_for(self.lifecycle_state, self.anchor_height, finalized_height)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveRegistryEventV1 {
    pub block_height: u64,
    pub event_seq: u64,
    pub tx_kind: CognitiveTxKindV1,
    pub object_hash_hex: String,
    pub claim_hash_hex: String,
    pub old_lifecycle_state: Option<CognitiveRegistryLifecycleStateV1>,
    pub new_lifecycle_state: CognitiveRegistryLifecycleStateV1,
    pub related_object_hash_hex: Option<String>,
    pub reason_code: Option<String>,
    pub block_hash: String,
}

impl CognitiveRegistryEventV1 {
    pub fn validate(&self) -> Result<(), String> {
        validate_sha256_hex_field("object_hash_hex", &self.object_hash_hex)?;
        validate_sha256_hex_field("claim_hash_hex", &self.claim_hash_hex)?;
        validate_optional_sha256_hex_field(
            "related_object_hash_hex",
            &self.related_object_hash_hex,
        )?;
        validate_optional_non_empty_no_separator("reason_code", &self.reason_code)?;
        validate_sha256_hex_field("block_hash", &self.block_hash)?;
        let allowed = match self.old_lifecycle_state {
            Some(old) => is_allowed_lifecycle_transition(Some(old), self.new_lifecycle_state),
            None => is_allowed_lifecycle_transition(None, self.new_lifecycle_state),
        };
        if !allowed {
            return Err("registry event old/new lifecycle transition is not allowed".to_string());
        }

        match self.tx_kind {
            CognitiveTxKindV1::Anchor => {
                if self.old_lifecycle_state.is_some()
                    && self.new_lifecycle_state != CognitiveRegistryLifecycleStateV1::Active
                {
                    return Err("anchor event must transition into Active".to_string());
                }
                if self.reason_code.is_some() {
                    return Err("anchor event must not carry reason_code".to_string());
                }
                if self.related_object_hash_hex.is_some() {
                    return Err("anchor event must not carry related_object_hash_hex".to_string());
                }
            }
            CognitiveTxKindV1::Dispute => {
                if self.new_lifecycle_state != CognitiveRegistryLifecycleStateV1::Contested {
                    return Err("dispute event must transition into Contested".to_string());
                }
                if self.reason_code.is_none() {
                    return Err("dispute event requires reason_code".to_string());
                }
                if self.related_object_hash_hex.is_some() {
                    return Err("dispute event must not carry related_object_hash_hex".to_string());
                }
            }
            CognitiveTxKindV1::Revoke => {
                if self.new_lifecycle_state != CognitiveRegistryLifecycleStateV1::Revoked {
                    return Err("revoke event must transition into Revoked".to_string());
                }
                if self.reason_code.is_none() {
                    return Err("revoke event requires reason_code".to_string());
                }
                if self.related_object_hash_hex.is_some() {
                    return Err("revoke event must not carry related_object_hash_hex".to_string());
                }
            }
            CognitiveTxKindV1::Supersede => {
                if self.new_lifecycle_state != CognitiveRegistryLifecycleStateV1::Superseded {
                    return Err("supersede event must transition into Superseded".to_string());
                }
                if self.reason_code.is_none() {
                    return Err("supersede event requires reason_code".to_string());
                }
                if self.related_object_hash_hex.is_none() {
                    return Err("supersede event requires related_object_hash_hex".to_string());
                }
            }
        }
        Ok(())
    }
}

pub type CognitiveRegistryReconciliationContextV1 =
    canonical_cognitive_surface_v1::ChainRegistryReconciliationContextV1;
pub type CognitiveRegistryStatusViewV1 = canonical_cognitive_surface_v1::ChainRegistryStatusViewV1;
pub type CognitiveRegistryObjectViewV1 = canonical_cognitive_surface_v1::ChainRegistryObjectViewV1;
pub type CognitiveRegistryMetaViewV1 = canonical_cognitive_surface_v1::ChainRegistryMetaViewV1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveRegistryClaimRowViewV1 {
    pub entry: CognitiveRegistryEntryV1,
    pub status_view: CognitiveRegistryStatusViewV1,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CognitiveRegistryClaimViewV1 {
    pub claim_hash_hex: String,
    pub reconciliation_context: CognitiveRegistryReconciliationContextV1,
    pub rows: Vec<CognitiveRegistryClaimRowViewV1>,
}

pub fn cognitive_registry_lifecycle_state_label_v1(
    state: CognitiveRegistryLifecycleStateV1,
) -> &'static str {
    match state {
        CognitiveRegistryLifecycleStateV1::Active => "active",
        CognitiveRegistryLifecycleStateV1::Contested => "contested",
        CognitiveRegistryLifecycleStateV1::Revoked => "revoked",
        CognitiveRegistryLifecycleStateV1::Superseded => "superseded",
    }
}

pub fn cognitive_registry_entry_to_object_view_entry_v1(
    entry: &CognitiveRegistryEntryV1,
) -> canonical_cognitive_surface_v1::ChainRegistryObjectEntryV1 {
    canonical_cognitive_surface_v1::ChainRegistryObjectEntryV1 {
        format_version:
            canonical_cognitive_surface_v1::COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
        object_hash_hex: entry.object_hash_hex.clone(),
        claim_hash_hex: entry.claim_hash_hex.clone(),
        lifecycle_state: cognitive_registry_lifecycle_state_label_v1(entry.lifecycle_state)
            .to_string(),
        policy_id: entry.policy_id.clone(),
        anchor_height: entry.anchor_height,
        anchor_block_hash: entry.anchor_block_hash.clone(),
        evidence_root_hex: entry.evidence_root_hex.clone(),
        context_hash_hex: entry.context_hash_hex.clone(),
        model_manifest_hash_hex: entry.model_manifest_hash_hex.clone(),
        supersedes: entry.supersedes.clone(),
        superseded_by: entry.superseded_by.clone(),
        dispute_ref: entry.dispute_ref.clone(),
        revoke_ref: entry.revoke_ref.clone(),
        updated_at_height: entry.updated_at_height,
    }
}

pub fn validate_sha256_hex_field(field_name: &str, value: &str) -> Result<(), String> {
    validate_lower_hex_field(field_name, value, 64)
}

pub fn validate_optional_sha256_hex_field(
    field_name: &str,
    value: &Option<String>,
) -> Result<(), String> {
    if let Some(v) = value {
        validate_sha256_hex_field(field_name, v)?;
    }
    Ok(())
}

pub fn validate_lower_hex_field(
    field_name: &str,
    value: &str,
    expected_len: usize,
) -> Result<(), String> {
    if value.len() != expected_len {
        return Err(format!(
            "{field_name} invalid hex length: got {} expected {}",
            value.len(),
            expected_len
        ));
    }
    if !value
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{field_name} must be lowercase hex"));
    }
    Ok(())
}

pub fn validate_non_empty_no_separator(field_name: &str, value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    if v != value {
        return Err(format!(
            "{field_name} must not contain leading or trailing whitespace"
        ));
    }
    if v.contains('|') {
        return Err(format!("{field_name} contains invalid separator '|'"));
    }
    Ok(())
}

pub fn validate_optional_non_empty_no_separator(
    field_name: &str,
    value: &Option<String>,
) -> Result<(), String> {
    if let Some(v) = value {
        validate_non_empty_no_separator(field_name, v)?;
    }
    Ok(())
}

pub fn verify_ed25519_b64_signature(
    message: &[u8],
    signer_public_key_b64: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let pk_bytes = STANDARD
        .decode(signer_public_key_b64)
        .map_err(|e| format!("signer_public_key_b64 decode failed: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(format!(
            "signer_public_key_b64 len={} (expected 32)",
            pk_bytes.len()
        ));
    }

    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|e| format!("signature_b64 decode failed: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature_b64 len={} (expected 64)",
            sig_bytes.len()
        ));
    }

    let vk = VerifyingKey::from_bytes(
        &pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signer_public_key_b64 is not 32 bytes".to_string())?,
    )
    .map_err(|e| format!("verifying key parse failed: {e}"))?;

    let sig = Signature::from_bytes(
        &sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature_b64 is not 64 bytes".to_string())?,
    );

    vk.verify_strict(message, &sig)
        .map_err(|e| format!("signature verify failed: {e}"))?;
    Ok(())
}

pub fn validate_ed25519_signature_fields(
    signer_public_key_b64: &str,
    signature_b64: &str,
    canonical_message: &[u8],
) -> Result<(), String> {
    verify_ed25519_b64_signature(canonical_message, signer_public_key_b64, signature_b64)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn effective_status_for(
    lifecycle_state: CognitiveRegistryLifecycleStateV1,
    anchor_height: u64,
    finalized_height: u64,
) -> CognitiveRegistryEffectiveStatusV1 {
    match lifecycle_state {
        CognitiveRegistryLifecycleStateV1::Active => {
            if anchor_height <= finalized_height {
                CognitiveRegistryEffectiveStatusV1::AnchoredFinal
            } else {
                CognitiveRegistryEffectiveStatusV1::AnchoredPending
            }
        }
        CognitiveRegistryLifecycleStateV1::Contested => {
            CognitiveRegistryEffectiveStatusV1::Contested
        }
        CognitiveRegistryLifecycleStateV1::Revoked => CognitiveRegistryEffectiveStatusV1::Revoked,
        CognitiveRegistryLifecycleStateV1::Superseded => {
            CognitiveRegistryEffectiveStatusV1::Superseded
        }
    }
}

pub fn is_allowed_lifecycle_transition(
    old_state: Option<CognitiveRegistryLifecycleStateV1>,
    new_state: CognitiveRegistryLifecycleStateV1,
) -> bool {
    match (old_state, new_state) {
        (None, CognitiveRegistryLifecycleStateV1::Active) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Active),
            CognitiveRegistryLifecycleStateV1::Active,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Active),
            CognitiveRegistryLifecycleStateV1::Contested,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Active),
            CognitiveRegistryLifecycleStateV1::Revoked,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Active),
            CognitiveRegistryLifecycleStateV1::Superseded,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Contested),
            CognitiveRegistryLifecycleStateV1::Contested,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Contested),
            CognitiveRegistryLifecycleStateV1::Revoked,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Contested),
            CognitiveRegistryLifecycleStateV1::Superseded,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Revoked),
            CognitiveRegistryLifecycleStateV1::Revoked,
        ) => true,
        (
            Some(CognitiveRegistryLifecycleStateV1::Superseded),
            CognitiveRegistryLifecycleStateV1::Superseded,
        ) => true,
        _ => false,
    }
}

pub fn cognitive_registry_entry_storage_key(object_hash_hex: &str) -> Result<Vec<u8>, String> {
    validate_sha256_hex_field("object_hash_hex", object_hash_hex)?;
    Ok(format!("{}{}", COGNITIVE_REGISTRY_ENTRY_KEY_PREFIX, object_hash_hex).into_bytes())
}

pub fn cognitive_registry_claim_index_storage_key(claim_hash_hex: &str) -> Result<Vec<u8>, String> {
    validate_sha256_hex_field("claim_hash_hex", claim_hash_hex)?;
    Ok(format!(
        "{}{}",
        COGNITIVE_REGISTRY_CLAIM_INDEX_KEY_PREFIX, claim_hash_hex
    )
    .into_bytes())
}

pub fn cognitive_registry_event_storage_key(block_height: u64, event_seq: u64) -> Vec<u8> {
    format!(
        "{}{block_height:020}:{event_seq:020}",
        COGNITIVE_REGISTRY_EVENT_KEY_PREFIX
    )
    .into_bytes()
}

pub fn cognitive_registry_meta_last_applied_height_key() -> &'static [u8] {
    COGNITIVE_REGISTRY_META_LAST_APPLIED_HEIGHT_KEY
}

pub fn cognitive_registry_meta_last_event_seq_key() -> &'static [u8] {
    COGNITIVE_REGISTRY_META_LAST_EVENT_SEQ_KEY
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_hash(ch: char) -> String {
        std::iter::repeat(ch).take(64).collect()
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_envelope() -> CognitiveAttestationEnvelopeV1 {
        CognitiveAttestationEnvelopeV1 {
            chain_id: "newgen-devnet".to_string(),
            genesis_hash: sample_hash('a'),
            object_hash_hex: sample_hash('b'),
            claim_hash_hex: sample_hash('c'),
            evidence_root_hex: sample_hash('d'),
            context_hash_hex: sample_hash('e'),
            policy_id: "verified-response-v1".to_string(),
            model_manifest_hash_hex: sample_hash('f'),
            created_at_height: 42,
            created_at_ts: 1_700_000_000,
        }
    }

    #[test]
    fn envelope_canonical_hash_is_stable() {
        let env = sample_envelope();
        let h1 = env.canonical_hash_hex().unwrap();
        let h2 = env.canonical_hash_hex().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn attestation_cert_validate_roundtrip() {
        let sk = signing_key();
        let env = sample_envelope();
        let msg = env.canonical_bytes().unwrap();
        let sig = sk.sign(&msg);
        let cert = CognitiveAttestationCertV1 {
            envelope: env,
            sigs: vec![CognitiveAttestationSigV1 {
                signer_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
                signature_b64: B64.encode(sig.to_bytes()),
            }],
        };
        cert.validate(1).unwrap();
    }

    #[test]
    fn dispute_validate_roundtrip() {
        let sk = signing_key();
        let mut tx = CognitiveTxDisputeV1 {
            target_object_hash_hex: sample_hash('1'),
            reason_code: "evidence_conflict".to_string(),
            dispute_evidence_root_hex: sample_hash('2'),
            submitter_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
            signature_b64: String::new(),
        };
        let sig = sk.sign(&tx.canonical_bytes().unwrap());
        tx.signature_b64 = B64.encode(sig.to_bytes());
        tx.validate().unwrap();
    }

    #[test]
    fn revoke_and_supersede_validate_roundtrip() {
        let sk = signing_key();
        let mut revoke = CognitiveTxRevokeV1 {
            target_object_hash_hex: sample_hash('3'),
            reason_code: "policy_revoke".to_string(),
            authority_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
            signature_b64: String::new(),
        };
        let revoke_sig = sk.sign(&revoke.canonical_bytes().unwrap());
        revoke.signature_b64 = B64.encode(revoke_sig.to_bytes());
        revoke.validate().unwrap();

        let mut supersede = CognitiveTxSupersedeV1 {
            old_object_hash_hex: sample_hash('4'),
            new_object_hash_hex: sample_hash('5'),
            reason_code: "better_evidence".to_string(),
            authority_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
            signature_b64: String::new(),
        };
        let supersede_sig = sk.sign(&supersede.canonical_bytes().unwrap());
        supersede.signature_b64 = B64.encode(supersede_sig.to_bytes());
        supersede.validate().unwrap();
    }

    #[test]
    fn text_validation_rejects_unsafe_whitespace() {
        assert!(validate_non_empty_no_separator("policy_id", " bad").is_err());
        assert!(validate_non_empty_no_separator("policy_id", "bad ").is_err());
        assert!(validate_non_empty_no_separator("policy_id", "ok").is_ok());
    }

    #[test]
    fn registry_entry_validate_enforces_state_specific_refs() {
        let mut entry = CognitiveRegistryEntryV1 {
            object_hash_hex: sample_hash('a'),
            claim_hash_hex: sample_hash('b'),
            lifecycle_state: CognitiveRegistryLifecycleStateV1::Contested,
            policy_id: "verified-response-v1".to_string(),
            anchor_height: 10,
            anchor_block_hash: sample_hash('c'),
            evidence_root_hex: sample_hash('d'),
            context_hash_hex: sample_hash('e'),
            model_manifest_hash_hex: sample_hash('f'),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 11,
        };
        assert!(entry.validate().is_err());
        entry.dispute_ref = Some(sample_hash('1'));
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn registry_event_validate_enforces_tx_shape() {
        let event = CognitiveRegistryEventV1 {
            block_height: 12,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Supersede,
            object_hash_hex: sample_hash('1'),
            claim_hash_hex: sample_hash('2'),
            old_lifecycle_state: Some(CognitiveRegistryLifecycleStateV1::Active),
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Superseded,
            related_object_hash_hex: Some(sample_hash('3')),
            reason_code: Some("better_evidence".to_string()),
            block_hash: sample_hash('4'),
        };
        assert!(event.validate().is_ok());
    }
    #[test]
    fn effective_status_is_finality_aware() {
        assert_eq!(
            effective_status_for(CognitiveRegistryLifecycleStateV1::Active, 10, 9),
            CognitiveRegistryEffectiveStatusV1::AnchoredPending
        );
        assert_eq!(
            effective_status_for(CognitiveRegistryLifecycleStateV1::Active, 10, 10),
            CognitiveRegistryEffectiveStatusV1::AnchoredFinal
        );
    }

    #[test]
    fn lifecycle_transition_policy_matches_registry_rules() {
        assert!(is_allowed_lifecycle_transition(
            None,
            CognitiveRegistryLifecycleStateV1::Active
        ));
        assert!(is_allowed_lifecycle_transition(
            Some(CognitiveRegistryLifecycleStateV1::Active),
            CognitiveRegistryLifecycleStateV1::Contested
        ));
        assert!(is_allowed_lifecycle_transition(
            Some(CognitiveRegistryLifecycleStateV1::Contested),
            CognitiveRegistryLifecycleStateV1::Revoked
        ));
        assert!(!is_allowed_lifecycle_transition(
            Some(CognitiveRegistryLifecycleStateV1::Revoked),
            CognitiveRegistryLifecycleStateV1::Active
        ));
    }

    #[test]
    fn storage_keys_are_stable() {
        let object_hash = sample_hash('a');
        let claim_hash = sample_hash('b');
        assert_eq!(
            cognitive_registry_entry_storage_key(&object_hash).unwrap(),
            format!("entry:{}", object_hash).into_bytes()
        );
        assert_eq!(
            cognitive_registry_claim_index_storage_key(&claim_hash).unwrap(),
            format!("claim:{}", claim_hash).into_bytes()
        );
        assert_eq!(
            String::from_utf8(cognitive_registry_event_storage_key(12, 3)).unwrap(),
            "event:00000000000000000012:00000000000000000003"
        );
    }
}
