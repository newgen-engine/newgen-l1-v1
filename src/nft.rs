// src/nft.rs
//
// Phase 4B — Native Non-Fungible Tokens (NFT v1)
//
// Design goals:
// - NO protocol break of legacy user tx format (Transaction remains unchanged)
// - NFT ops are encoded as consensus-critical "system ops" via receiver sentinel + memo JSON
// - Deterministic, bounded, mainnet-grade validation
// - Activation gated (height-based) via governance params/env
//
// IMPORTANT:
// - This module only defines syntax + state keys + deterministic encoding helpers.
// - The actual state transitions are applied in blockchain.rs (SMT path), gated by activation height.

use crate::account::AccountState;
use crate::keyfmt;
use crate::state_smt::sys_key;
use crate::transaction::Transaction;
use bincode::Options;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftEventV1 {
    pub v: u8,
    pub event_version: u8,
    pub kind: String,
    pub op: String,
    pub block_height: u64,
    pub tx_hash: String,
    pub tx_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_owner_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_issuer_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_issuer_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frozen: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mintable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burnable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_supply: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_height: Option<u64>,
}

impl NftEventV1 {
    pub fn base(kind: &str, op: &str, block_height: u64, tx_hash: &str, tx_index: u32) -> Self {
        Self {
            v: 1,
            event_version: 1,
            kind: kind.to_string(),
            op: op.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            tx_index,
            collection_id: None,
            serial: None,
            asset_id: None,
            owner_b64: None,
            previous_owner_b64: None,
            from_b64: None,
            to_b64: None,
            issuer_b64: None,
            old_issuer_b64: None,
            new_issuer_b64: None,
            approved_b64: None,
            operator_b64: None,
            approved: None,
            frozen: None,
            status: None,
            asset_type: None,
            transfer_policy: None,
            revocable: None,
            mintable: None,
            burnable: None,
            paused: None,
            symbol: None,
            name: None,
            max_supply: None,
            token_uri: None,
            base_uri: None,
            metadata_hash: None,
            expires_at_height: None,
        }
    }
}

pub fn nft_asset_id_v1(collection_id: u64, serial: u64) -> String {
    format!("nft:{}:{}", collection_id, serial)
}

pub fn nft_event_json_v1(event: &NftEventV1) -> Result<Value, String> {
    serde_json::to_value(event).map_err(|e| format!("nft_event_json_v1 failed: {e}"))
}

pub fn nft_events_for_tx_v1<'a>(
    events: &'a [NftEventV1],
    tx_hash: &str,
    tx_index: u32,
) -> Vec<&'a NftEventV1> {
    events
        .iter()
        .filter(|e| e.tx_hash == tx_hash && e.tx_index == tx_index)
        .collect()
}

/// Receiver sentinel for NFT operations.
pub const NFT_RECEIVER: &str = "NFT";

pub const NFTV1_MEMO_MAX_BYTES: usize = 16 * 1024;
pub const NFTV1_SYMBOL_MAX_BYTES: usize = 16;
pub const NFTV1_NAME_MAX_BYTES: usize = 128;
pub const NFTV1_URI_MAX_BYTES: usize = 512;

// Domain separation tags (signed inside memo string).
pub const CTX_NFT_CREATE_COLLECTION: &str = "NEWGEN:NFTV1:CREATE_COLLECTION";
pub const CTX_NFT_MINT: &str = "NEWGEN:NFTV1:MINT";
pub const CTX_NFT_TRANSFER: &str = "NEWGEN:NFTV1:TRANSFER";
pub const CTX_NFT_APPROVE: &str = "NEWGEN:NFTV1:APPROVE";
pub const CTX_NFT_APPROVE_ALL: &str = "NEWGEN:NFTV1:APPROVE_ALL";
pub const CTX_NFT_BURN: &str = "NEWGEN:NFTV1:BURN";
pub const CTX_NFT_REVOKE: &str = "NEWGEN:NFTV1:REVOKE";
pub const CTX_NFT_SET_TOKEN_URI: &str = "NEWGEN:NFTV1:SET_TOKEN_URI";
pub const CTX_NFT_SET_COLLECTION_URI: &str = "NEWGEN:NFTV1:SET_COLLECTION_URI";
pub const CTX_NFT_FREEZE_TOKEN: &str = "NEWGEN:NFTV1:FREEZE_TOKEN";
pub const CTX_NFT_SET_COLLECTION_POLICY: &str = "NEWGEN:NFTV1:SET_COLLECTION_POLICY";
pub const CTX_NFT_SET_ISSUER: &str = "NEWGEN:NFTV1:SET_ISSUER";
pub const CTX_NFT_PAUSE: &str = "NEWGEN:NFTV1:PAUSE";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NftAssetTypeV1 {
    Collectible,
    Badge,
    AccessPass,
    Certificate,
    Receipt,
    Membership,
    ComputeProofCertificate,
    AIAccessPass,
}

impl NftAssetTypeV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collectible => "collectible",
            Self::Badge => "badge",
            Self::AccessPass => "access_pass",
            Self::Certificate => "certificate",
            Self::Receipt => "receipt",
            Self::Membership => "membership",
            Self::ComputeProofCertificate => "compute_proof_certificate",
            Self::AIAccessPass => "ai_access_pass",
        }
    }

    pub fn parse_raw(value: &str) -> Result<Self, String> {
        if value.is_empty() || value != value.trim() || contains_ascii_whitespace(value) {
            return Err("nft_asset_type_not_raw_canonical".to_string());
        }
        match value {
            "collectible" => Ok(Self::Collectible),
            "badge" => Ok(Self::Badge),
            "access_pass" => Ok(Self::AccessPass),
            "certificate" => Ok(Self::Certificate),
            "receipt" => Ok(Self::Receipt),
            "membership" => Ok(Self::Membership),
            "compute_proof_certificate" => Ok(Self::ComputeProofCertificate),
            "ai_access_pass" => Ok(Self::AIAccessPass),
            _ => Err(format!("unsupported_nft_asset_type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NftTransferPolicyV1 {
    Transferable,
    Soulbound,
    IssuerOnlyTransfer,
    Frozen,
}

impl NftTransferPolicyV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transferable => "transferable",
            Self::Soulbound => "soulbound",
            Self::IssuerOnlyTransfer => "issuer_only_transfer",
            Self::Frozen => "frozen",
        }
    }

    pub fn parse_raw(value: &str) -> Result<Self, String> {
        if value.is_empty() || value != value.trim() || contains_ascii_whitespace(value) {
            return Err("nft_transfer_policy_not_raw_canonical".to_string());
        }
        match value {
            "transferable" => Ok(Self::Transferable),
            "soulbound" => Ok(Self::Soulbound),
            "issuer_only_transfer" => Ok(Self::IssuerOnlyTransfer),
            "frozen" => Ok(Self::Frozen),
            _ => Err(format!("unsupported_nft_transfer_policy: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NftTokenStatusV1 {
    Active,
    Frozen,
    Burned,
    Revoked,
    Expired,
}

impl NftTokenStatusV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Burned => "burned",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftCollectionMetaV1 {
    pub id: u64,
    pub owner_b64: String,
    pub issuer_b64: String,
    pub asset_type: NftAssetTypeV1,
    pub transfer_policy: NftTransferPolicyV1,
    pub revocable: bool,
    pub symbol: String,
    pub name: String,
    pub max_supply: Option<u64>,
    pub total_minted: u64,
    pub live_supply: u64,
    pub created_height: u64,
    pub metadata_hash: [u8; 32],
    pub base_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftCollectionCfgV1 {
    pub mintable: bool,
    pub burnable: bool,
    pub paused: bool,
}

impl Default for NftCollectionCfgV1 {
    fn default() -> Self {
        Self {
            mintable: true,
            burnable: false,
            paused: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftTokenMetaV1 {
    pub collection_id: u64,
    pub serial: u64,
    pub minted_height: u64,
    pub metadata_hash: [u8; 32],
    pub token_uri: String,
    pub status: NftTokenStatusV1,
    pub expires_at_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NftOpV1 {
    CreateCollection {
        symbol: String,
        name: String,
        max_supply: Option<u64>,
        base_uri: String,
        metadata_hash: [u8; 32],
        mintable: bool,
        burnable: bool,
        asset_type: NftAssetTypeV1,
        transfer_policy: NftTransferPolicyV1,
        revocable: bool,
    },
    Mint {
        collection_id: u64,
        to_b64: String,
        token_uri: String,
        metadata_hash: [u8; 32],
        expires_at_height: Option<u64>,
    },
    Transfer {
        collection_id: u64,
        serial: u64,
        to_b64: String,
    },
    Approve {
        collection_id: u64,
        serial: u64,
        approved_b64: Option<String>,
    },
    SetApprovalForAll {
        collection_id: u64,
        operator_b64: String,
        approved: bool,
    },
    Burn {
        collection_id: u64,
        serial: u64,
    },
    Revoke {
        collection_id: u64,
        serial: u64,
    },
    SetTokenUri {
        collection_id: u64,
        serial: u64,
        token_uri: String,
        metadata_hash: [u8; 32],
    },
    SetCollectionUri {
        collection_id: u64,
        base_uri: String,
        metadata_hash: [u8; 32],
    },
    FreezeToken {
        collection_id: u64,
        serial: u64,
        frozen: bool,
    },
    SetCollectionPolicy {
        collection_id: u64,
        mintable: bool,
        burnable: bool,
        transfer_policy: NftTransferPolicyV1,
        revocable: bool,
    },
    SetIssuer {
        collection_id: u64,
        issuer_b64: String,
    },
    SetPaused {
        collection_id: u64,
        paused: bool,
    },
}

fn object_v1<'a>(v: &'a Value) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| "nft_tx_memo_not_object".to_string())
}

fn require_exact_keys(map: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    for key in map.keys() {
        if !allowed.iter().any(|k| *k == key) {
            return Err(format!("nft_unknown_field: {}", key));
        }
    }
    Ok(())
}

fn contains_ascii_whitespace(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_whitespace())
}

fn ensure_raw_no_boundary_ws(key: &str, s: &str) -> Result<(), String> {
    if s != s.trim() {
        return Err(format!("nft_field_not_raw_canonical: {}", key));
    }
    Ok(())
}

fn get_required_str_raw(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    let s = map
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))?;
    ensure_raw_no_boundary_ws(key, s)?;
    Ok(s.to_string())
}

fn get_required_nonempty_str_raw(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    let s = get_required_str_raw(map, key)?;
    if s.is_empty() {
        return Err(format!("missing_or_invalid_field: {}", key));
    }
    Ok(s)
}

fn get_optional_nullable_str_raw(
    map: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match map.get(key) {
        None => Err(format!("missing_or_invalid_field: {}", key)),
        Some(v) if v.is_null() => Ok(None),
        Some(v) if v.is_string() => {
            let s = v.as_str().unwrap();
            ensure_raw_no_boundary_ws(key, s)?;
            if s.is_empty() {
                return Err(format!("missing_or_invalid_field: {}", key));
            }
            Ok(Some(s.to_string()))
        }
        _ => Err(format!("missing_or_invalid_field: {}", key)),
    }
}

fn get_required_bool(map: &Map<String, Value>, key: &str) -> Result<bool, String> {
    map.get(key)
        .and_then(|x| x.as_bool())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

fn get_required_u64(map: &Map<String, Value>, key: &str) -> Result<u64, String> {
    map.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

fn get_optional_u64(map: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(x) if x.is_null() => Ok(None),
        Some(x) if x.is_u64() => Ok(Some(x.as_u64().unwrap())),
        _ => Err(format!("missing_or_invalid_field: {}", key)),
    }
}

fn get_required_nonzero_u64(map: &Map<String, Value>, key: &str) -> Result<u64, String> {
    let n = get_required_u64(map, key)?;
    if n == 0 {
        return Err(format!("missing_or_invalid_field: {}", key));
    }
    Ok(n)
}

fn is_lowercase_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn ensure_hash32_nonzero(key: &str, hash: &[u8; 32]) -> Result<(), String> {
    if hash == &[0u8; 32] {
        return Err(format!("invalid_zero_hash32: {}", key));
    }
    Ok(())
}

pub fn parse_nft_hash32_hex_v1(key: &str, value: &str) -> Result<[u8; 32], String> {
    if value.is_empty() || value != value.trim() || !is_lowercase_hex64(value) {
        return Err(format!("invalid_lowercase_hex32: {}", key));
    }
    let bytes = hex::decode(value).map_err(|e| format!("invalid_hex32: {} ({})", key, e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    ensure_hash32_nonzero(key, &out)?;
    Ok(out)
}

fn parse_hash32_hex_required(map: &Map<String, Value>, key: &str) -> Result<[u8; 32], String> {
    let s = get_required_nonempty_str_raw(map, key)?;
    parse_nft_hash32_hex_v1(key, &s)
}

pub fn validate_nft_address_b64_v1(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() || contains_ascii_whitespace(value) || value != value.trim() {
        return Err(format!("nft_address_not_raw_canonical: {}", key));
    }
    let canonical = keyfmt::pk_b64_from_any(value)
        .map_err(|e| format!("nft_address_invalid: {} ({})", key, e))?;
    if canonical != value {
        return Err(format!("nft_address_not_canonical_b64: {}", key));
    }
    Ok(value.to_string())
}

fn is_symbol_ok(sym: &str) -> bool {
    let n = sym.len();
    if !(3..=16).contains(&n) {
        return false;
    }
    sym.bytes()
        .all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn is_name_ok(name: &str) -> bool {
    let n = name.len();
    if !(1..=64).contains(&n) {
        return false;
    }
    name == name.trim() && !name.chars().any(|c| c.is_control())
}

fn is_uri_ok(uri: &str) -> bool {
    if uri.is_empty() {
        return true;
    }
    if uri != uri.trim() || uri.len() > 512 || uri.chars().any(|c| c.is_control()) {
        return false;
    }
    uri.starts_with("ipfs://") || uri.starts_with("https://") || uri.starts_with("newgen://")
}

fn validate_op_ctx(
    op: &str,
    expected_op: &str,
    ctx: &str,
    expected_ctx: &str,
) -> Result<(), String> {
    if op != expected_op {
        return Err("nft_op_internal_mismatch".to_string());
    }
    if contains_ascii_whitespace(op) || contains_ascii_whitespace(ctx) {
        return Err("nft_op_or_ctx_not_raw_canonical".to_string());
    }
    if ctx != expected_ctx {
        return Err("nft_ctx_mismatch".to_string());
    }
    Ok(())
}

fn validate_nft_expiry_v1(expires_at_height: Option<u64>) -> Result<(), String> {
    if let Some(h) = expires_at_height {
        if h == 0 {
            return Err("nft_expires_at_height_zero".to_string());
        }
    }
    Ok(())
}

pub fn validate_asset_type_transfer_policy_matrix_v1(
    asset_type: &NftAssetTypeV1,
    transfer_policy: &NftTransferPolicyV1,
) -> Result<(), String> {
    match asset_type {
        NftAssetTypeV1::Collectible => Ok(()),
        NftAssetTypeV1::Badge
        | NftAssetTypeV1::Certificate
        | NftAssetTypeV1::Receipt
        | NftAssetTypeV1::ComputeProofCertificate => {
            if *transfer_policy == NftTransferPolicyV1::Transferable {
                return Err("nft_asset_type_requires_nontransferable_policy".to_string());
            }
            Ok(())
        }
        // Access and membership passes may be transferable, issuer-only, soulbound, or frozen.
        // Keeping this explicit prevents silent drift in future asset classes.
        NftAssetTypeV1::AccessPass | NftAssetTypeV1::Membership | NftAssetTypeV1::AIAccessPass => {
            Ok(())
        }
    }
}

pub fn nft_token_effective_status_v1(meta: &NftTokenMetaV1, at_height: u64) -> NftTokenStatusV1 {
    if meta.status != NftTokenStatusV1::Active {
        return meta.status.clone();
    }
    if let Some(exp) = meta.expires_at_height {
        if at_height >= exp {
            return NftTokenStatusV1::Expired;
        }
    }
    NftTokenStatusV1::Active
}

pub fn ensure_nft_token_active_at_height_v1(
    meta: &NftTokenMetaV1,
    at_height: u64,
) -> Result<(), String> {
    match nft_token_effective_status_v1(meta, at_height) {
        NftTokenStatusV1::Active => Ok(()),
        NftTokenStatusV1::Frozen => Err("nft_token_frozen".to_string()),
        status => Err(format!("nft_token_not_active: {}", status.as_str())),
    }
}

pub fn ensure_nft_token_cleanup_allowed_at_height_v1(
    meta: &NftTokenMetaV1,
    at_height: u64,
) -> Result<(), String> {
    match &meta.status {
        NftTokenStatusV1::Active | NftTokenStatusV1::Expired => {}
        NftTokenStatusV1::Frozen => {
            return Err("nft_token_frozen".to_string());
        }
        NftTokenStatusV1::Burned | NftTokenStatusV1::Revoked => {
            return Err(format!(
                "nft_token_not_cleanup_eligible: {}",
                meta.status.as_str()
            ));
        }
    }
    match nft_token_effective_status_v1(meta, at_height) {
        NftTokenStatusV1::Active | NftTokenStatusV1::Expired => Ok(()),
        status => Err(format!(
            "nft_token_not_cleanup_eligible: {}",
            status.as_str()
        )),
    }
}

pub fn ensure_nft_token_revoke_allowed_at_height_v1(
    meta: &NftTokenMetaV1,
    at_height: u64,
) -> Result<(), String> {
    match &meta.status {
        NftTokenStatusV1::Active | NftTokenStatusV1::Expired | NftTokenStatusV1::Frozen => {}
        NftTokenStatusV1::Burned | NftTokenStatusV1::Revoked => {
            return Err(format!(
                "nft_token_not_revoke_eligible: {}",
                meta.status.as_str()
            ));
        }
    }
    match nft_token_effective_status_v1(meta, at_height) {
        NftTokenStatusV1::Active | NftTokenStatusV1::Expired | NftTokenStatusV1::Frozen => Ok(()),
        status => Err(format!(
            "nft_token_not_revoke_eligible: {}",
            status.as_str()
        )),
    }
}

fn validate_nft_op_fields_v1(op: &NftOpV1) -> Result<(), String> {
    match op {
        NftOpV1::CreateCollection {
            symbol,
            name,
            max_supply,
            base_uri,
            metadata_hash,
            asset_type,
            transfer_policy,
            ..
        } => {
            if !is_symbol_ok(symbol) {
                return Err("nft_symbol_invalid".to_string());
            }
            if !is_name_ok(name) {
                return Err("nft_name_invalid".to_string());
            }
            if !is_uri_ok(base_uri) {
                return Err("nft_base_uri_invalid".to_string());
            }
            if let Some(m) = max_supply {
                if *m == 0 {
                    return Err("nft_max_supply_must_be_positive".to_string());
                }
            }
            validate_asset_type_transfer_policy_matrix_v1(asset_type, transfer_policy)?;
            ensure_hash32_nonzero("metadata_hash_hex", metadata_hash)?;
        }
        NftOpV1::Mint {
            collection_id,
            to_b64,
            token_uri,
            metadata_hash,
            expires_at_height,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            validate_nft_address_b64_v1("to", to_b64)?;
            if !is_uri_ok(token_uri) {
                return Err("nft_token_uri_invalid".to_string());
            }
            validate_nft_expiry_v1(*expires_at_height)?;
            ensure_hash32_nonzero("metadata_hash_hex", metadata_hash)?;
        }
        NftOpV1::Transfer {
            collection_id,
            serial,
            to_b64,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            if *serial == 0 {
                return Err("missing_or_invalid_field: serial".to_string());
            }
            validate_nft_address_b64_v1("to", to_b64)?;
        }
        NftOpV1::Approve {
            collection_id,
            serial,
            approved_b64,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            if *serial == 0 {
                return Err("missing_or_invalid_field: serial".to_string());
            }
            if let Some(a) = approved_b64 {
                validate_nft_address_b64_v1("approved", a)?;
            }
        }
        NftOpV1::SetApprovalForAll {
            collection_id,
            operator_b64,
            ..
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            validate_nft_address_b64_v1("operator", operator_b64)?;
        }
        NftOpV1::Burn {
            collection_id,
            serial,
        }
        | NftOpV1::Revoke {
            collection_id,
            serial,
        }
        | NftOpV1::FreezeToken {
            collection_id,
            serial,
            ..
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            if *serial == 0 {
                return Err("missing_or_invalid_field: serial".to_string());
            }
        }
        NftOpV1::SetTokenUri {
            collection_id,
            serial,
            token_uri,
            metadata_hash,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            if *serial == 0 {
                return Err("missing_or_invalid_field: serial".to_string());
            }
            if !is_uri_ok(token_uri) {
                return Err("nft_token_uri_invalid".to_string());
            }
            ensure_hash32_nonzero("metadata_hash_hex", metadata_hash)?;
        }
        NftOpV1::SetCollectionUri {
            collection_id,
            base_uri,
            metadata_hash,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            if !is_uri_ok(base_uri) {
                return Err("nft_base_uri_invalid".to_string());
            }
            ensure_hash32_nonzero("metadata_hash_hex", metadata_hash)?;
        }
        NftOpV1::SetCollectionPolicy {
            collection_id,
            transfer_policy,
            ..
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            let _ = transfer_policy.as_str();
        }
        NftOpV1::SetIssuer {
            collection_id,
            issuer_b64,
        } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
            validate_nft_address_b64_v1("issuer", issuer_b64)?;
        }
        NftOpV1::SetPaused { collection_id, .. } => {
            if *collection_id == 0 {
                return Err("missing_or_invalid_field: collection_id".to_string());
            }
        }
    }
    Ok(())
}

pub fn nft_memo_json_v1(op: &NftOpV1) -> Result<String, String> {
    validate_nft_op_fields_v1(op)?;
    let v = match op {
        NftOpV1::CreateCollection {
            symbol,
            name,
            max_supply,
            base_uri,
            metadata_hash,
            mintable,
            burnable,
            asset_type,
            transfer_policy,
            revocable,
        } => serde_json::json!({
            "asset_type": asset_type.as_str(),
            "base_uri": base_uri,
            "burnable": burnable,
            "ctx": CTX_NFT_CREATE_COLLECTION,
            "max_supply": max_supply,
            "metadata_hash_hex": hex::encode(metadata_hash),
            "mintable": mintable,
            "name": name,
            "op": "create_collection",
            "revocable": revocable,
            "symbol": symbol,
            "transfer_policy": transfer_policy.as_str(),
            "v": 1
        }),
        NftOpV1::Mint {
            collection_id,
            to_b64,
            token_uri,
            metadata_hash,
            expires_at_height,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_MINT,
            "expires_at_height": expires_at_height,
            "metadata_hash_hex": hex::encode(metadata_hash),
            "op": "mint",
            "to": to_b64,
            "token_uri": token_uri,
            "v": 1
        }),
        NftOpV1::Transfer {
            collection_id,
            serial,
            to_b64,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_TRANSFER,
            "op": "transfer",
            "serial": serial,
            "to": to_b64,
            "v": 1
        }),
        NftOpV1::Approve {
            collection_id,
            serial,
            approved_b64,
        } => serde_json::json!({
            "approved": approved_b64,
            "collection_id": collection_id,
            "ctx": CTX_NFT_APPROVE,
            "op": "approve",
            "serial": serial,
            "v": 1
        }),
        NftOpV1::SetApprovalForAll {
            collection_id,
            operator_b64,
            approved,
        } => serde_json::json!({
            "approved": approved,
            "collection_id": collection_id,
            "ctx": CTX_NFT_APPROVE_ALL,
            "op": "set_approval_for_all",
            "operator": operator_b64,
            "v": 1
        }),
        NftOpV1::Burn {
            collection_id,
            serial,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_BURN,
            "op": "burn",
            "serial": serial,
            "v": 1
        }),
        NftOpV1::Revoke {
            collection_id,
            serial,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_REVOKE,
            "op": "revoke",
            "serial": serial,
            "v": 1
        }),
        NftOpV1::SetTokenUri {
            collection_id,
            serial,
            token_uri,
            metadata_hash,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_SET_TOKEN_URI,
            "metadata_hash_hex": hex::encode(metadata_hash),
            "op": "set_token_uri",
            "serial": serial,
            "token_uri": token_uri,
            "v": 1
        }),
        NftOpV1::SetCollectionUri {
            collection_id,
            base_uri,
            metadata_hash,
        } => serde_json::json!({
            "base_uri": base_uri,
            "collection_id": collection_id,
            "ctx": CTX_NFT_SET_COLLECTION_URI,
            "metadata_hash_hex": hex::encode(metadata_hash),
            "op": "set_collection_uri",
            "v": 1
        }),
        NftOpV1::FreezeToken {
            collection_id,
            serial,
            frozen,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_FREEZE_TOKEN,
            "frozen": frozen,
            "op": "freeze_token",
            "serial": serial,
            "v": 1
        }),
        NftOpV1::SetCollectionPolicy {
            collection_id,
            mintable,
            burnable,
            transfer_policy,
            revocable,
        } => serde_json::json!({
            "burnable": burnable,
            "collection_id": collection_id,
            "ctx": CTX_NFT_SET_COLLECTION_POLICY,
            "mintable": mintable,
            "op": "set_collection_policy",
            "revocable": revocable,
            "transfer_policy": transfer_policy.as_str(),
            "v": 1
        }),
        NftOpV1::SetIssuer {
            collection_id,
            issuer_b64,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_SET_ISSUER,
            "issuer": issuer_b64,
            "op": "set_issuer",
            "v": 1
        }),
        NftOpV1::SetPaused {
            collection_id,
            paused,
        } => serde_json::json!({
            "collection_id": collection_id,
            "ctx": CTX_NFT_PAUSE,
            "op": "pause",
            "paused": paused,
            "v": 1
        }),
    };
    serde_json::to_string(&v).map_err(|e| format!("nft_memo_serialize_failed: {}", e))
}

/// True if tx uses NFT receiver sentinel.
pub fn is_nft_tx(tx: &Transaction) -> bool {
    tx.receiver == NFT_RECEIVER
}

/// Parse NFT memo JSON into NftOpV1.
pub fn parse_nft_memo_v1(tx: &Transaction) -> Result<NftOpV1, String> {
    if tx.receiver != NFT_RECEIVER {
        return Err("nft_tx_receiver_not_canonical".to_string());
    }
    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "nft_tx_missing_memo".to_string())?;

    if memo.len() > NFTV1_MEMO_MAX_BYTES {
        return Err("nft_tx_memo_too_large".to_string());
    }
    if memo.trim() != memo {
        return Err("nft_tx_memo_not_raw_canonical".to_string());
    }

    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("nft_tx_memo_not_json: {}", e))?;
    let map = object_v1(&v)?;
    let ver = get_required_u64(map, "v")?;
    if ver != 1 {
        return Err(format!("unsupported_nft_memo_version: {}", ver));
    }

    let op = get_required_nonempty_str_raw(map, "op")?;
    let ctx = get_required_nonempty_str_raw(map, "ctx")?;

    let parsed =
        match op.as_str() {
            "create_collection" => {
                require_exact_keys(
                    map,
                    &[
                        "asset_type",
                        "base_uri",
                        "burnable",
                        "ctx",
                        "max_supply",
                        "metadata_hash_hex",
                        "mintable",
                        "name",
                        "op",
                        "revocable",
                        "symbol",
                        "transfer_policy",
                        "v",
                    ],
                )?;
                validate_op_ctx(&op, "create_collection", &ctx, CTX_NFT_CREATE_COLLECTION)?;
                let symbol = get_required_nonempty_str_raw(map, "symbol")?;
                let name = get_required_nonempty_str_raw(map, "name")?;
                let max_supply = get_optional_u64(map, "max_supply")?;
                let base_uri = get_required_str_raw(map, "base_uri")?;
                let metadata_hash = parse_hash32_hex_required(map, "metadata_hash_hex")?;
                let mintable = get_required_bool(map, "mintable")?;
                let burnable = get_required_bool(map, "burnable")?;
                let asset_type =
                    NftAssetTypeV1::parse_raw(&get_required_nonempty_str_raw(map, "asset_type")?)?;
                let transfer_policy = NftTransferPolicyV1::parse_raw(
                    &get_required_nonempty_str_raw(map, "transfer_policy")?,
                )?;
                let revocable = get_required_bool(map, "revocable")?;

                let out = NftOpV1::CreateCollection {
                    symbol,
                    name,
                    max_supply,
                    base_uri,
                    metadata_hash,
                    mintable,
                    burnable,
                    asset_type,
                    transfer_policy,
                    revocable,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "mint" => {
                require_exact_keys(
                    map,
                    &[
                        "collection_id",
                        "ctx",
                        "expires_at_height",
                        "metadata_hash_hex",
                        "op",
                        "to",
                        "token_uri",
                        "v",
                    ],
                )?;
                validate_op_ctx(&op, "mint", &ctx, CTX_NFT_MINT)?;
                let collection_id = get_required_nonzero_u64(map, "collection_id")?;
                let to_b64 =
                    validate_nft_address_b64_v1("to", &get_required_nonempty_str_raw(map, "to")?)?;
                let token_uri = get_required_str_raw(map, "token_uri")?;
                let metadata_hash = parse_hash32_hex_required(map, "metadata_hash_hex")?;
                let expires_at_height = get_optional_u64(map, "expires_at_height")?;
                let out = NftOpV1::Mint {
                    collection_id,
                    to_b64,
                    token_uri,
                    metadata_hash,
                    expires_at_height,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "transfer" => {
                require_exact_keys(map, &["collection_id", "ctx", "op", "serial", "to", "v"])?;
                validate_op_ctx(&op, "transfer", &ctx, CTX_NFT_TRANSFER)?;
                let out = NftOpV1::Transfer {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                    to_b64: validate_nft_address_b64_v1(
                        "to",
                        &get_required_nonempty_str_raw(map, "to")?,
                    )?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "approve" => {
                require_exact_keys(
                    map,
                    &["approved", "collection_id", "ctx", "op", "serial", "v"],
                )?;
                validate_op_ctx(&op, "approve", &ctx, CTX_NFT_APPROVE)?;
                let approved_b64 = match get_optional_nullable_str_raw(map, "approved")? {
                    Some(raw) => Some(validate_nft_address_b64_v1("approved", &raw)?),
                    None => None,
                };
                let out = NftOpV1::Approve {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                    approved_b64,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "set_approval_for_all" => {
                require_exact_keys(
                    map,
                    &["approved", "collection_id", "ctx", "op", "operator", "v"],
                )?;
                validate_op_ctx(&op, "set_approval_for_all", &ctx, CTX_NFT_APPROVE_ALL)?;
                let out = NftOpV1::SetApprovalForAll {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    operator_b64: validate_nft_address_b64_v1(
                        "operator",
                        &get_required_nonempty_str_raw(map, "operator")?,
                    )?,
                    approved: get_required_bool(map, "approved")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "burn" => {
                require_exact_keys(map, &["collection_id", "ctx", "op", "serial", "v"])?;
                validate_op_ctx(&op, "burn", &ctx, CTX_NFT_BURN)?;
                let out = NftOpV1::Burn {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "revoke" => {
                require_exact_keys(map, &["collection_id", "ctx", "op", "serial", "v"])?;
                validate_op_ctx(&op, "revoke", &ctx, CTX_NFT_REVOKE)?;
                let out = NftOpV1::Revoke {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "set_token_uri" => {
                require_exact_keys(
                    map,
                    &[
                        "collection_id",
                        "ctx",
                        "metadata_hash_hex",
                        "op",
                        "serial",
                        "token_uri",
                        "v",
                    ],
                )?;
                validate_op_ctx(&op, "set_token_uri", &ctx, CTX_NFT_SET_TOKEN_URI)?;
                let metadata_hash = parse_hash32_hex_required(map, "metadata_hash_hex")?;
                let out = NftOpV1::SetTokenUri {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                    token_uri: get_required_str_raw(map, "token_uri")?,
                    metadata_hash,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "set_collection_uri" => {
                require_exact_keys(
                    map,
                    &[
                        "base_uri",
                        "collection_id",
                        "ctx",
                        "metadata_hash_hex",
                        "op",
                        "v",
                    ],
                )?;
                validate_op_ctx(&op, "set_collection_uri", &ctx, CTX_NFT_SET_COLLECTION_URI)?;
                let metadata_hash = parse_hash32_hex_required(map, "metadata_hash_hex")?;
                let out = NftOpV1::SetCollectionUri {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    base_uri: get_required_str_raw(map, "base_uri")?,
                    metadata_hash,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "freeze_token" => {
                require_exact_keys(
                    map,
                    &["collection_id", "ctx", "frozen", "op", "serial", "v"],
                )?;
                validate_op_ctx(&op, "freeze_token", &ctx, CTX_NFT_FREEZE_TOKEN)?;
                let out = NftOpV1::FreezeToken {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    serial: get_required_nonzero_u64(map, "serial")?,
                    frozen: get_required_bool(map, "frozen")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "set_collection_policy" => {
                require_exact_keys(
                    map,
                    &[
                        "burnable",
                        "collection_id",
                        "ctx",
                        "mintable",
                        "op",
                        "revocable",
                        "transfer_policy",
                        "v",
                    ],
                )?;
                validate_op_ctx(
                    &op,
                    "set_collection_policy",
                    &ctx,
                    CTX_NFT_SET_COLLECTION_POLICY,
                )?;
                let transfer_policy = NftTransferPolicyV1::parse_raw(
                    &get_required_nonempty_str_raw(map, "transfer_policy")?,
                )?;
                let out = NftOpV1::SetCollectionPolicy {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    mintable: get_required_bool(map, "mintable")?,
                    burnable: get_required_bool(map, "burnable")?,
                    transfer_policy,
                    revocable: get_required_bool(map, "revocable")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "set_issuer" => {
                require_exact_keys(map, &["collection_id", "ctx", "issuer", "op", "v"])?;
                validate_op_ctx(&op, "set_issuer", &ctx, CTX_NFT_SET_ISSUER)?;
                let out = NftOpV1::SetIssuer {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    issuer_b64: validate_nft_address_b64_v1(
                        "issuer",
                        &get_required_nonempty_str_raw(map, "issuer")?,
                    )?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            "pause" => {
                require_exact_keys(map, &["collection_id", "ctx", "op", "paused", "v"])?;
                validate_op_ctx(&op, "pause", &ctx, CTX_NFT_PAUSE)?;
                let out = NftOpV1::SetPaused {
                    collection_id: get_required_nonzero_u64(map, "collection_id")?,
                    paused: get_required_bool(map, "paused")?,
                };
                validate_nft_op_fields_v1(&out)?;
                out
            }
            _ => return Err("unsupported_nft_op".to_string()),
        };

    let canonical = nft_memo_json_v1(&parsed)?;
    if canonical != memo.as_str() {
        return Err("nft_tx_memo_not_canonical_json".to_string());
    }

    Ok(parsed)
}

/// Syntax validation for receiver=NFT txs.
/// Does not touch state. Consensus-critical.
pub fn validate_nft_tx_syntax(tx: &Transaction) -> Result<(), String> {
    if !is_nft_tx(tx) {
        return Ok(());
    }

    if tx.is_coinbase {
        return Err("nft_tx_cannot_be_coinbase".to_string());
    }

    if tx.amount != 0 {
        return Err("nft_tx_amount_must_be_0".to_string());
    }

    validate_nft_address_b64_v1("sender", &tx.sender)?;

    let _ = parse_nft_memo_v1(tx)?;
    Ok(())
}

// ----------------------------
// SMT keys (reserved sys space)
// ----------------------------

pub fn k_nft_next_collection_id() -> [u8; 32] {
    sys_key("nft/next_collection_id")
}

pub fn k_nft_collection_meta(collection_id: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/meta", collection_id))
}

pub fn k_nft_collection_cfg(collection_id: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/cfg", collection_id))
}

pub fn k_nft_collection_next_serial(collection_id: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/next_serial", collection_id))
}

pub fn k_nft_owner_count(owner_b64: &str) -> [u8; 32] {
    sys_key(&format!("nft/owner/{}/count", owner_b64))
}

pub fn k_nft_owner_last_create(owner_b64: &str) -> [u8; 32] {
    sys_key(&format!("nft/owner/{}/last_create", owner_b64))
}

pub fn k_nft_owner_collection_item(owner_b64: &str, index: u64) -> [u8; 32] {
    sys_key(&format!("nft/owner/{}/collection/{}", owner_b64, index))
}

pub fn k_nft_owner_token_count(owner_b64: &str) -> [u8; 32] {
    sys_key(&format!("nft/owner/{}/tokens/count", owner_b64))
}

pub fn k_nft_owner_token_item(owner_b64: &str, index: u64) -> [u8; 32] {
    sys_key(&format!("nft/owner/{}/tokens/{}", owner_b64, index))
}

pub fn k_nft_collection_token_count(collection_id: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/tokens/count", collection_id))
}

pub fn k_nft_collection_token_item(collection_id: u64, index: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/tokens/{}", collection_id, index))
}

pub fn k_nft_token_index_ref(collection_id: u64, serial: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/token/{}/index", collection_id, serial))
}

pub fn k_nft_token_meta(collection_id: u64, serial: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/token/{}/meta", collection_id, serial))
}

pub fn k_nft_token_owner(collection_id: u64, serial: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/token/{}/owner", collection_id, serial))
}

pub fn k_nft_token_approval(collection_id: u64, serial: u64) -> [u8; 32] {
    sys_key(&format!("nft/{}/token/{}/approval", collection_id, serial))
}

pub fn k_nft_operator_approval(
    collection_id: u64,
    owner_b64: &str,
    operator_b64: &str,
) -> [u8; 32] {
    sys_key(&format!(
        "nft/{}/opall/{}/{}",
        collection_id, owner_b64, operator_b64
    ))
}

// ----------------------------
// Deterministic state codec (bincode fixed LE)
// ----------------------------

pub const NFT_DATA_VERSION_V1: u8 = 1;
const TAG_COLLECTION_META: u8 = 1;
const TAG_COLLECTION_CFG: u8 = 2;
const TAG_TOKEN_META: u8 = 3;
const TAG_TOKEN_OWNER: u8 = 4;
const TAG_TOKEN_APPROVAL: u8 = 5;
const TAG_BOOL: u8 = 6;
const TAG_TOKEN_REF: u8 = 7;
const TAG_COLLECTION_REF: u8 = 8;
const TAG_TOKEN_INDEX_REF: u8 = 9;

fn bincode_fixed_le() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

fn enc_record<T: Serialize>(tag: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.push(NFT_DATA_VERSION_V1);
    out.push(tag);
    let payload = bincode_fixed_le()
        .serialize(v)
        .map_err(|e| format!("bincode serialize: {e}"))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

fn dec_record<T: for<'de> Deserialize<'de>>(tag: u8, data: &[u8]) -> Result<T, String> {
    if data.len() < 2 {
        return Err("nft_data_too_short".to_string());
    }
    if data[0] != NFT_DATA_VERSION_V1 {
        return Err(format!("unsupported_nft_data_version: {}", data[0]));
    }
    if data[1] != tag {
        return Err(format!(
            "nft_data_tag_mismatch: expected={} got={}",
            tag, data[1]
        ));
    }
    bincode_fixed_le()
        .deserialize(&data[2..])
        .map_err(|e| format!("bincode deserialize: {e}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NftOwnerV1 {
    owner_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NftApprovalV1 {
    approved_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NftBoolV1 {
    value: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftTokenRefV1 {
    pub collection_id: u64,
    pub serial: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftCollectionRefV1 {
    pub collection_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftTokenIndexRefV1 {
    pub owner_b64: String,
    pub owner_index: u64,
    pub collection_index: u64,
}

fn validate_nft_token_ref_state_v1(r: &NftTokenRefV1) -> Result<(), String> {
    if r.collection_id == 0 {
        return Err("nft_index_collection_id_zero".to_string());
    }
    if r.serial == 0 {
        return Err("nft_index_serial_zero".to_string());
    }
    Ok(())
}

fn validate_nft_collection_ref_state_v1(r: &NftCollectionRefV1) -> Result<(), String> {
    if r.collection_id == 0 {
        return Err("nft_index_collection_id_zero".to_string());
    }
    Ok(())
}

fn validate_nft_token_index_ref_state_v1(r: &NftTokenIndexRefV1) -> Result<(), String> {
    validate_nft_address_b64_v1("token_index.owner_b64", &r.owner_b64)?;
    Ok(())
}

fn validate_collection_meta_state_v1(meta: &NftCollectionMetaV1) -> Result<(), String> {
    if meta.id == 0 {
        return Err("nft_collection_id_zero".to_string());
    }
    validate_nft_address_b64_v1("collection.owner_b64", &meta.owner_b64)?;
    validate_nft_address_b64_v1("collection.issuer_b64", &meta.issuer_b64)?;
    validate_asset_type_transfer_policy_matrix_v1(&meta.asset_type, &meta.transfer_policy)
        .map_err(|e| format!("nft_collection_{e}"))?;
    if !is_symbol_ok(&meta.symbol) {
        return Err("nft_collection_symbol_invalid".to_string());
    }
    if !is_name_ok(&meta.name) {
        return Err("nft_collection_name_invalid".to_string());
    }
    if let Some(max_supply) = meta.max_supply {
        if max_supply == 0 {
            return Err("nft_collection_max_supply_zero".to_string());
        }
        if max_supply < meta.total_minted {
            return Err("nft_collection_max_supply_below_total_minted".to_string());
        }
    }
    if meta.live_supply > meta.total_minted {
        return Err("nft_collection_live_supply_exceeds_total_minted".to_string());
    }
    ensure_hash32_nonzero("collection.metadata_hash", &meta.metadata_hash)?;
    if !is_uri_ok(&meta.base_uri) {
        return Err("nft_collection_base_uri_invalid".to_string());
    }
    Ok(())
}

fn validate_token_meta_state_v1(meta: &NftTokenMetaV1) -> Result<(), String> {
    if meta.collection_id == 0 {
        return Err("nft_token_collection_id_zero".to_string());
    }
    if meta.serial == 0 {
        return Err("nft_token_serial_zero".to_string());
    }
    ensure_hash32_nonzero("token.metadata_hash", &meta.metadata_hash)?;
    validate_nft_expiry_v1(meta.expires_at_height)?;
    if matches!(meta.status, NftTokenStatusV1::Expired) && meta.expires_at_height.is_none() {
        return Err("nft_token_expired_status_requires_expiry".to_string());
    }
    if !is_uri_ok(&meta.token_uri) {
        return Err("nft_token_uri_invalid".to_string());
    }
    Ok(())
}

pub fn encode_collection_meta_state_v1(meta: &NftCollectionMetaV1) -> Result<AccountState, String> {
    validate_collection_meta_state_v1(meta)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_COLLECTION_META, meta)?,
    })
}

pub fn decode_collection_meta_state_v1(st: &AccountState) -> Result<NftCollectionMetaV1, String> {
    let meta: NftCollectionMetaV1 = dec_record(TAG_COLLECTION_META, &st.data)?;
    validate_collection_meta_state_v1(&meta)?;
    Ok(meta)
}

pub fn encode_collection_cfg_state_v1(cfg: &NftCollectionCfgV1) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_COLLECTION_CFG, cfg)?,
    })
}

pub fn decode_collection_cfg_state_v1(st: &AccountState) -> Result<NftCollectionCfgV1, String> {
    if st.data.is_empty() {
        return Ok(NftCollectionCfgV1::default());
    }
    dec_record(TAG_COLLECTION_CFG, &st.data)
}

pub fn encode_token_meta_state_v1(meta: &NftTokenMetaV1) -> Result<AccountState, String> {
    validate_token_meta_state_v1(meta)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_TOKEN_META, meta)?,
    })
}

pub fn decode_token_meta_state_v1(st: &AccountState) -> Result<NftTokenMetaV1, String> {
    let meta: NftTokenMetaV1 = dec_record(TAG_TOKEN_META, &st.data)?;
    validate_token_meta_state_v1(&meta)?;
    Ok(meta)
}

pub fn encode_token_owner_state_v1(owner_b64: &str) -> Result<AccountState, String> {
    let owner_b64 = validate_nft_address_b64_v1("owner_b64", owner_b64)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_TOKEN_OWNER, &NftOwnerV1 { owner_b64 })?,
    })
}

pub fn decode_token_owner_b64_v1(st: &AccountState) -> Result<String, String> {
    let v: NftOwnerV1 = dec_record(TAG_TOKEN_OWNER, &st.data)?;
    validate_nft_address_b64_v1("owner_b64", &v.owner_b64)
}

pub fn encode_token_approval_state_v1(approved_b64: &str) -> Result<AccountState, String> {
    let approved_b64 = validate_nft_address_b64_v1("approved_b64", approved_b64)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_TOKEN_APPROVAL, &NftApprovalV1 { approved_b64 })?,
    })
}

pub fn decode_token_approval_b64_v1(st: &AccountState) -> Result<String, String> {
    let v: NftApprovalV1 = dec_record(TAG_TOKEN_APPROVAL, &st.data)?;
    validate_nft_address_b64_v1("approved_b64", &v.approved_b64)
}

pub fn encode_bool_state_v1(value: bool) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_BOOL, &NftBoolV1 { value })?,
    })
}

pub fn decode_bool_state_v1(st: &AccountState) -> Result<bool, String> {
    if st.data.is_empty() {
        return Ok(false);
    }
    let v: NftBoolV1 = dec_record(TAG_BOOL, &st.data)?;
    Ok(v.value)
}

pub fn encode_token_ref_state_v1(r: &NftTokenRefV1) -> Result<AccountState, String> {
    validate_nft_token_ref_state_v1(r)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_TOKEN_REF, r)?,
    })
}

pub fn decode_token_ref_state_v1(st: &AccountState) -> Result<NftTokenRefV1, String> {
    let r: NftTokenRefV1 = dec_record(TAG_TOKEN_REF, &st.data)?;
    validate_nft_token_ref_state_v1(&r)?;
    Ok(r)
}

pub fn encode_collection_ref_state_v1(r: &NftCollectionRefV1) -> Result<AccountState, String> {
    validate_nft_collection_ref_state_v1(r)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_COLLECTION_REF, r)?,
    })
}

pub fn decode_collection_ref_state_v1(st: &AccountState) -> Result<NftCollectionRefV1, String> {
    let r: NftCollectionRefV1 = dec_record(TAG_COLLECTION_REF, &st.data)?;
    validate_nft_collection_ref_state_v1(&r)?;
    Ok(r)
}

pub fn encode_token_index_ref_state_v1(r: &NftTokenIndexRefV1) -> Result<AccountState, String> {
    validate_nft_token_index_ref_state_v1(r)?;
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_TOKEN_INDEX_REF, r)?,
    })
}

pub fn decode_token_index_ref_state_v1(st: &AccountState) -> Result<NftTokenIndexRefV1, String> {
    let r: NftTokenIndexRefV1 = dec_record(TAG_TOKEN_INDEX_REF, &st.data)?;
    validate_nft_token_index_ref_state_v1(&r)?;
    Ok(r)
}

pub fn nft_op_name_v1(op: &NftOpV1) -> &'static str {
    match op {
        NftOpV1::CreateCollection { .. } => "create_collection",
        NftOpV1::Mint { .. } => "mint",
        NftOpV1::Transfer { .. } => "transfer",
        NftOpV1::Approve { .. } => "approve",
        NftOpV1::SetApprovalForAll { .. } => "set_approval_for_all",
        NftOpV1::Burn { .. } => "burn",
        NftOpV1::Revoke { .. } => "revoke",
        NftOpV1::SetTokenUri { .. } => "set_token_uri",
        NftOpV1::SetCollectionUri { .. } => "set_collection_uri",
        NftOpV1::FreezeToken { .. } => "freeze_token",
        NftOpV1::SetCollectionPolicy { .. } => "set_collection_policy",
        NftOpV1::SetIssuer { .. } => "set_issuer",
        NftOpV1::SetPaused { .. } => "pause",
    }
}

pub fn nft_event_kind_v1(op: &NftOpV1) -> &'static str {
    match op {
        NftOpV1::CreateCollection { .. } => "nft_create_collection",
        NftOpV1::Mint { .. } => "nft_mint",
        NftOpV1::Transfer { .. } => "nft_transfer",
        NftOpV1::Approve { .. } => "nft_approve",
        NftOpV1::SetApprovalForAll { .. } => "nft_approve_all",
        NftOpV1::Burn { .. } => "nft_burn",
        NftOpV1::Revoke { .. } => "nft_revoke",
        NftOpV1::SetTokenUri { .. } => "nft_set_token_uri",
        NftOpV1::SetCollectionUri { .. } => "nft_set_collection_uri",
        NftOpV1::FreezeToken { .. } => "nft_freeze_token",
        NftOpV1::SetCollectionPolicy { .. } => "nft_set_collection_policy",
        NftOpV1::SetIssuer { .. } => "nft_set_issuer",
        NftOpV1::SetPaused { .. } => "nft_pause",
    }
}

/// Legacy memo-derived NFT receipt preview.
///
/// Do not use this as a source of truth for applied blocks. Mainnet-grade NFT receipts/events
/// must come from `Block::nft_events`, which validators recompute from the state transition.
#[deprecated(
    note = "memo-derived legacy preview only; use Block::nft_events / nft_event_json_v1 for applied receipts"
)]
pub fn nft_receipt_json_v1(tx: &Transaction) -> Result<Option<Value>, String> {
    if !is_nft_tx(tx) {
        return Ok(None);
    }

    let sender = validate_nft_address_b64_v1("sender", &tx.sender)?;
    let op = parse_nft_memo_v1(tx)?;
    let kind = nft_event_kind_v1(&op);
    let op_name = nft_op_name_v1(&op);

    let value = match op {
        NftOpV1::CreateCollection {
            symbol,
            name,
            max_supply,
            base_uri,
            metadata_hash,
            mintable,
            burnable,
            asset_type,
            transfer_policy,
            revocable,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "owner_b64": sender,
            "issuer_b64": sender,
            "asset_type": asset_type.as_str(),
            "transfer_policy": transfer_policy.as_str(),
            "revocable": revocable,
            "symbol": symbol,
            "name": name,
            "max_supply": max_supply.map(|v| v.to_string()),
            "base_uri": base_uri,
            "metadata_hash": hex::encode(metadata_hash),
            "mintable": mintable,
            "burnable": burnable
        }),
        NftOpV1::Mint {
            collection_id,
            to_b64,
            token_uri,
            metadata_hash,
            expires_at_height,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "issuer_b64": sender,
            "to_b64": to_b64,
            "token_uri": token_uri,
            "metadata_hash": hex::encode(metadata_hash),
            "status": NftTokenStatusV1::Active.as_str(),
            "expires_at_height": expires_at_height
        }),
        NftOpV1::Transfer {
            collection_id,
            serial,
            to_b64,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "sender_b64": sender,
            "to_b64": to_b64
        }),
        NftOpV1::Approve {
            collection_id,
            serial,
            approved_b64,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "sender_b64": sender,
            "approved_b64": approved_b64
        }),
        NftOpV1::SetApprovalForAll {
            collection_id,
            operator_b64,
            approved,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "owner_b64": sender,
            "operator_b64": operator_b64,
            "approved": approved
        }),
        NftOpV1::Burn {
            collection_id,
            serial,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "sender_b64": sender,
            "status": NftTokenStatusV1::Burned.as_str()
        }),
        NftOpV1::Revoke {
            collection_id,
            serial,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "issuer_b64": sender,
            "status": NftTokenStatusV1::Revoked.as_str()
        }),
        NftOpV1::SetTokenUri {
            collection_id,
            serial,
            token_uri,
            metadata_hash,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "issuer_b64": sender,
            "token_uri": token_uri,
            "metadata_hash": hex::encode(metadata_hash)
        }),
        NftOpV1::SetCollectionUri {
            collection_id,
            base_uri,
            metadata_hash,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "owner_b64": sender,
            "base_uri": base_uri,
            "metadata_hash": hex::encode(metadata_hash)
        }),
        NftOpV1::FreezeToken {
            collection_id,
            serial,
            frozen,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "serial": serial,
            "issuer_b64": sender,
            "frozen": frozen,
            "status": if frozen { NftTokenStatusV1::Frozen.as_str() } else { NftTokenStatusV1::Active.as_str() }
        }),
        NftOpV1::SetCollectionPolicy {
            collection_id,
            mintable,
            burnable,
            transfer_policy,
            revocable,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "owner_b64": sender,
            "mintable": mintable,
            "burnable": burnable,
            "transfer_policy": transfer_policy.as_str(),
            "revocable": revocable
        }),
        NftOpV1::SetIssuer {
            collection_id,
            issuer_b64,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "owner_b64": sender,
            "issuer_b64": issuer_b64
        }),
        NftOpV1::SetPaused {
            collection_id,
            paused,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "collection_id": collection_id,
            "owner_b64": sender,
            "paused": paused
        }),
    };

    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn addr(byte: u8) -> String {
        crate::keyfmt::pk_b64_from_bytes(&[byte; 32])
    }

    fn hash_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn mk_tx_from_memo_str(memo: String) -> Transaction {
        Transaction {
            sender: addr(1),
            receiver: NFT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 1,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(memo),
        }
    }

    fn mk_tx_from_op(op: &NftOpV1) -> Transaction {
        mk_tx_from_memo_str(nft_memo_json_v1(op).unwrap())
    }

    fn mk_tx(memo: serde_json::Value) -> Transaction {
        mk_tx_from_memo_str(serde_json::to_string(&memo).unwrap())
    }

    #[test]
    fn nft_parse_accepts_canonical_create_collection() {
        let op = NftOpV1::CreateCollection {
            symbol: "GAME_ITEMS".to_string(),
            name: "Game Items".to_string(),
            max_supply: Some(1000),
            base_uri: "ipfs://cid/".to_string(),
            metadata_hash: [0xabu8; 32],
            mintable: true,
            burnable: false,
            asset_type: NftAssetTypeV1::Collectible,
            transfer_policy: NftTransferPolicyV1::Transferable,
            revocable: false,
        };
        let tx = mk_tx_from_op(&op);
        assert_eq!(parse_nft_memo_v1(&tx).unwrap(), op);
    }

    #[test]
    fn nft_parse_rejects_trimmed_or_noncanonical_fields() {
        for memo in [
            json!({
                "base_uri":"ipfs://cid/",
                "burnable":false,
                "asset_type":"collectible",
                "transfer_policy":"transferable",
                "revocable":false,
                "ctx":CTX_NFT_CREATE_COLLECTION,
                "max_supply":1000,
                "metadata_hash_hex":hash_hex(0xab),
                "mintable":true,
                "name":" Game Items",
                "op":"create_collection",
                "symbol":"GAME_ITEMS",
                "v":1
            }),
            json!({
                "base_uri":" ipfs://cid/",
                "burnable":false,
                "asset_type":"collectible",
                "transfer_policy":"transferable",
                "revocable":false,
                "ctx":CTX_NFT_CREATE_COLLECTION,
                "max_supply":1000,
                "metadata_hash_hex":hash_hex(0xab),
                "mintable":true,
                "name":"Game Items",
                "op":"create_collection",
                "symbol":"GAME_ITEMS",
                "v":1
            }),
            json!({
                "base_uri":"ipfs://cid/",
                "burnable":false,
                "ctx":format!(" {}", CTX_NFT_CREATE_COLLECTION),
                "max_supply":1000,
                "metadata_hash_hex":hash_hex(0xab),
                "mintable":true,
                "name":"Game Items",
                "op":"create_collection",
                "symbol":"GAME_ITEMS",
                "v":1
            }),
            json!({
                "base_uri":"ipfs://cid/",
                "burnable":false,
                "asset_type":"collectible",
                "transfer_policy":"transferable",
                "revocable":false,
                "ctx":CTX_NFT_CREATE_COLLECTION,
                "max_supply":1000,
                "metadata_hash_hex":hash_hex(0xab).to_ascii_uppercase(),
                "mintable":true,
                "name":"Game Items",
                "op":"create_collection",
                "symbol":"GAME_ITEMS",
                "v":1
            }),
        ] {
            assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
        }
    }

    #[test]
    fn nft_parse_rejects_unknown_fields_and_string_numbers() {
        let mut memo = json!({
            "base_uri":"ipfs://cid/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":1000,
            "metadata_hash_hex":hash_hex(0xab),
            "mintable":true,
            "name":"Game Items",
            "op":"create_collection",
            "symbol":"GAME_ITEMS",
            "v":1
        });
        memo.as_object_mut()
            .unwrap()
            .insert("extra".to_string(), json!(true));
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());

        let memo = json!({
            "base_uri":"ipfs://cid/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":"1000",
            "metadata_hash_hex":hash_hex(0xab),
            "mintable":true,
            "name":"Game Items",
            "op":"create_collection",
            "symbol":"GAME_ITEMS",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
    }

    #[test]
    fn nft_parse_rejects_missing_metadata_hash() {
        let memo = json!({
            "base_uri":"ipfs://cid/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":1000,
            "mintable":true,
            "name":"Game Items",
            "op":"create_collection",
            "symbol":"GAME_ITEMS",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
    }

    #[test]
    fn nft_parse_rejects_zero_metadata_hash() {
        let memo = json!({
            "base_uri":"ipfs://cid/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":1000,
            "metadata_hash_hex":"00".repeat(32),
            "mintable":true,
            "name":"Game Items",
            "op":"create_collection",
            "symbol":"GAME_ITEMS",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
    }

    #[test]
    fn nft_syntax_rejects_bad_sender_address() {
        let mut tx = mk_tx_from_op(&NftOpV1::Transfer {
            collection_id: 1,
            serial: 1,
            to_b64: addr(2),
        });
        tx.sender = "not-a-canonical-key".to_string();
        tx.hash = tx.calculate_hash();
        assert!(validate_nft_tx_syntax(&tx).is_err());
    }

    #[test]
    fn nft_parse_rejects_bad_addresses() {
        for memo in [
            json!({
                "collection_id":1,
                "ctx":CTX_NFT_MINT,
                "metadata_hash_hex":hash_hex(0xcd),
                "expires_at_height":null,
                "op":"mint",
                "to":"not-a-canonical-key",
                "token_uri":"ipfs://token/1",
                "v":1
            }),
            json!({
                "collection_id":1,
                "ctx":CTX_NFT_TRANSFER,
                "op":"transfer",
                "serial":1,
                "to":format!(" {}", addr(2)),
                "v":1
            }),
            json!({
                "approved":format!("{} ", addr(3)),
                "collection_id":1,
                "ctx":CTX_NFT_APPROVE,
                "op":"approve",
                "serial":1,
                "v":1
            }),
            json!({
                "approved":true,
                "collection_id":1,
                "ctx":CTX_NFT_APPROVE_ALL,
                "op":"set_approval_for_all",
                "operator":"0x1111111111111111111111111111111111111111111111111111111111111111",
                "v":1
            }),
        ] {
            assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
        }
    }

    #[test]
    fn nft_parse_accepts_asset_type_transfer_policy_and_expiry() {
        let op = NftOpV1::CreateCollection {
            symbol: "BADGE".to_string(),
            name: "Badge Collection".to_string(),
            max_supply: Some(10),
            base_uri: "newgen://badges/".to_string(),
            metadata_hash: [0x44; 32],
            mintable: true,
            burnable: false,
            asset_type: NftAssetTypeV1::Badge,
            transfer_policy: NftTransferPolicyV1::Soulbound,
            revocable: true,
        };
        let tx = mk_tx_from_op(&op);
        assert_eq!(parse_nft_memo_v1(&tx).unwrap(), op);

        let mint = NftOpV1::Mint {
            collection_id: 1,
            to_b64: addr(2),
            token_uri: "newgen://badges/1".to_string(),
            metadata_hash: [0x45; 32],
            expires_at_height: Some(100),
        };
        let tx = mk_tx_from_op(&mint);
        assert_eq!(parse_nft_memo_v1(&tx).unwrap(), mint);
    }

    #[test]
    fn nft_asset_type_transfer_policy_matrix_is_explicit() {
        use NftAssetTypeV1::*;
        use NftTransferPolicyV1::*;
        assert!(validate_asset_type_transfer_policy_matrix_v1(&Collectible, &Transferable).is_ok());
        assert!(validate_asset_type_transfer_policy_matrix_v1(&Collectible, &Soulbound).is_ok());
        assert!(validate_asset_type_transfer_policy_matrix_v1(&Badge, &Transferable).is_err());
        assert!(
            validate_asset_type_transfer_policy_matrix_v1(&Certificate, &Transferable).is_err()
        );
        assert!(validate_asset_type_transfer_policy_matrix_v1(&Receipt, &Transferable).is_err());
        assert!(validate_asset_type_transfer_policy_matrix_v1(
            &ComputeProofCertificate,
            &Transferable
        )
        .is_err());
        for asset in [AccessPass, Membership, AIAccessPass] {
            assert!(validate_asset_type_transfer_policy_matrix_v1(&asset, &Transferable).is_ok());
            assert!(
                validate_asset_type_transfer_policy_matrix_v1(&asset, &IssuerOnlyTransfer).is_ok()
            );
            assert!(validate_asset_type_transfer_policy_matrix_v1(&asset, &Soulbound).is_ok());
            assert!(validate_asset_type_transfer_policy_matrix_v1(&asset, &Frozen).is_ok());
        }
    }

    #[test]
    fn nft_parse_rejects_transferable_badge_and_bad_policy_fields() {
        let bad = NftOpV1::CreateCollection {
            symbol: "BADGE".to_string(),
            name: "Badge Collection".to_string(),
            max_supply: Some(10),
            base_uri: "newgen://badges/".to_string(),
            metadata_hash: [0x46; 32],
            mintable: true,
            burnable: false,
            asset_type: NftAssetTypeV1::Badge,
            transfer_policy: NftTransferPolicyV1::Transferable,
            revocable: true,
        };
        assert!(nft_memo_json_v1(&bad).is_err());

        let memo = json!({
            "asset_type":"badge ",
            "base_uri":"newgen://badges/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":10,
            "metadata_hash_hex":hash_hex(0x47),
            "mintable":true,
            "name":"Badge Collection",
            "op":"create_collection",
            "revocable":true,
            "symbol":"BADGE",
            "transfer_policy":"soulbound",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());

        let mint = json!({
            "collection_id":1,
            "ctx":CTX_NFT_MINT,
            "expires_at_height":0,
            "metadata_hash_hex":hash_hex(0x48),
            "op":"mint",
            "to":addr(2),
            "token_uri":"newgen://badges/1",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(mint)).is_err());
    }

    #[test]
    fn nft_parse_rejects_bad_uri_scheme() {
        let memo = json!({
            "base_uri":"ftp://cid/",
            "burnable":false,
            "ctx":CTX_NFT_CREATE_COLLECTION,
            "max_supply":1000,
            "metadata_hash_hex":hash_hex(0xab),
            "mintable":true,
            "name":"Game Items",
            "op":"create_collection",
            "symbol":"GAME_ITEMS",
            "v":1
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
    }

    #[test]
    fn nft_parse_rejects_zero_ids_and_empty_addresses() {
        for memo in [
            json!({"collection_id":0,"ctx":CTX_NFT_MINT,"metadata_hash_hex":hash_hex(0xcd),"op":"mint","to":addr(2),"token_uri":"ipfs://t/1","v":1}),
            json!({"collection_id":1,"ctx":CTX_NFT_TRANSFER,"op":"transfer","serial":0,"to":addr(2),"v":1}),
            json!({"collection_id":1,"ctx":CTX_NFT_TRANSFER,"op":"transfer","serial":1,"to":"","v":1}),
            json!({"approved":true,"collection_id":1,"ctx":CTX_NFT_APPROVE_ALL,"op":"set_approval_for_all","operator":"","v":1}),
        ] {
            assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
        }
    }

    #[test]
    fn nft_state_rejects_noncanonical_owner_and_approval() {
        assert!(encode_token_owner_state_v1("not-a-canonical-key").is_err());
        assert!(encode_token_approval_state_v1("not-a-canonical-key").is_err());

        let bad_owner_state = AccountState {
            nonce: 0,
            balance: 0,
            data: enc_record(
                TAG_TOKEN_OWNER,
                &NftOwnerV1 {
                    owner_b64: "not-a-canonical-key".to_string(),
                },
            )
            .unwrap(),
        };
        assert!(decode_token_owner_b64_v1(&bad_owner_state).is_err());

        let bad_approval_state = AccountState {
            nonce: 0,
            balance: 0,
            data: enc_record(
                TAG_TOKEN_APPROVAL,
                &NftApprovalV1 {
                    approved_b64: format!(" {}", addr(3)),
                },
            )
            .unwrap(),
        };
        assert!(decode_token_approval_b64_v1(&bad_approval_state).is_err());
    }

    #[test]
    fn nft_state_rejects_bad_collection_meta() {
        let good = NftCollectionMetaV1 {
            id: 1,
            owner_b64: addr(1),
            symbol: "GAME_ITEMS".to_string(),
            name: "Game Items".to_string(),
            max_supply: Some(10),
            total_minted: 2,
            live_supply: 2,
            created_height: 7,
            metadata_hash: [0x11; 32],
            base_uri: "ipfs://cid/".to_string(),

            issuer_b64: addr(1),
            asset_type: crate::nft::NftAssetTypeV1::Collectible,
            transfer_policy: crate::nft::NftTransferPolicyV1::Transferable,
            revocable: false,
        };
        assert!(encode_collection_meta_state_v1(&good).is_ok());

        let mut bad_owner = good.clone();
        bad_owner.owner_b64 = "not-a-canonical-key".to_string();
        assert!(encode_collection_meta_state_v1(&bad_owner).is_err());

        let mut bad_hash = good.clone();
        bad_hash.metadata_hash = [0; 32];
        assert!(encode_collection_meta_state_v1(&bad_hash).is_err());

        let mut bad_uri = good.clone();
        bad_uri.base_uri = "ftp://cid/".to_string();
        assert!(encode_collection_meta_state_v1(&bad_uri).is_err());

        let mut bad_supply = good.clone();
        bad_supply.live_supply = 3;
        bad_supply.total_minted = 2;
        assert!(encode_collection_meta_state_v1(&bad_supply).is_err());

        let bad_state = AccountState {
            nonce: 0,
            balance: 0,
            data: enc_record(TAG_COLLECTION_META, &bad_hash).unwrap(),
        };
        assert!(decode_collection_meta_state_v1(&bad_state).is_err());
    }

    #[test]
    fn nft_state_rejects_bad_token_meta() {
        let good = NftTokenMetaV1 {
            collection_id: 1,
            serial: 1,
            minted_height: 9,
            metadata_hash: [0x22; 32],
            token_uri: "newgen://token/1".to_string(),

            status: crate::nft::NftTokenStatusV1::Active,
            expires_at_height: None,
        };
        assert!(encode_token_meta_state_v1(&good).is_ok());

        let mut bad_id = good.clone();
        bad_id.collection_id = 0;
        assert!(encode_token_meta_state_v1(&bad_id).is_err());

        let mut bad_hash = good.clone();
        bad_hash.metadata_hash = [0; 32];
        assert!(encode_token_meta_state_v1(&bad_hash).is_err());

        let mut bad_uri = good.clone();
        bad_uri.token_uri = "ftp://token/1".to_string();
        assert!(encode_token_meta_state_v1(&bad_uri).is_err());

        let bad_state = AccountState {
            nonce: 0,
            balance: 0,
            data: enc_record(TAG_TOKEN_META, &bad_hash).unwrap(),
        };
        assert!(decode_token_meta_state_v1(&bad_state).is_err());
    }
    #[test]
    fn nft_state_index_refs_roundtrip_and_reject_invalid_values() {
        let token_ref = NftTokenRefV1 {
            collection_id: 7,
            serial: 3,
        };
        let st = encode_token_ref_state_v1(&token_ref).unwrap();
        assert_eq!(decode_token_ref_state_v1(&st).unwrap(), token_ref);

        let collection_ref = NftCollectionRefV1 { collection_id: 7 };
        let st = encode_collection_ref_state_v1(&collection_ref).unwrap();
        assert_eq!(decode_collection_ref_state_v1(&st).unwrap(), collection_ref);

        let index_ref = NftTokenIndexRefV1 {
            owner_b64: addr(4),
            owner_index: 2,
            collection_index: 9,
        };
        let st = encode_token_index_ref_state_v1(&index_ref).unwrap();
        assert_eq!(decode_token_index_ref_state_v1(&st).unwrap(), index_ref);

        assert!(encode_token_ref_state_v1(&NftTokenRefV1 {
            collection_id: 0,
            serial: 1
        })
        .is_err());
        assert!(encode_token_ref_state_v1(&NftTokenRefV1 {
            collection_id: 1,
            serial: 0
        })
        .is_err());
        assert!(encode_collection_ref_state_v1(&NftCollectionRefV1 { collection_id: 0 }).is_err());
        assert!(encode_token_index_ref_state_v1(&NftTokenIndexRefV1 {
            owner_b64: "not-a-canonical-key".to_string(),
            owner_index: 0,
            collection_index: 0,
        })
        .is_err());
    }

    #[test]
    fn nft_create_rejects_unknown_fields() {
        let memo = serde_json::json!({
            "v": 1,
            "ctx": CTX_NFT_CREATE_COLLECTION,
            "op": "create_collection",
            "symbol": "UNKN",
            "name": "Unknown Field",
            "max_supply": 10,
            "base_uri": "newgen://unknown/",
            "metadata_hash_hex": hash_hex(0x91),
            "mintable": true,
            "burnable": true,
            "asset_type": "collectible",
            "transfer_policy": "transferable",
            "revocable": false,
            "unexpected": true
        });
        assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
    }

    #[test]
    fn nft_create_rejects_noncanonical_symbol_name_uri_hash() {
        let cases = [
            serde_json::json!({
                "v": 1,
                "ctx": CTX_NFT_CREATE_COLLECTION,
                "op": "create_collection",
                "symbol": "bad",
                "name": "Bad Symbol",
                "max_supply": 10,
                "base_uri": "newgen://bad-symbol/",
                "metadata_hash_hex": hash_hex(0x92),
                "mintable": true,
                "burnable": true,
                "asset_type": "collectible",
                "transfer_policy": "transferable",
                "revocable": false
            }),
            serde_json::json!({
                "v": 1,
                "ctx": CTX_NFT_CREATE_COLLECTION,
                "op": "create_collection",
                "symbol": "BADNAME",
                "name": " Bad Name ",
                "max_supply": 10,
                "base_uri": "newgen://bad-name/",
                "metadata_hash_hex": hash_hex(0x93),
                "mintable": true,
                "burnable": true,
                "asset_type": "collectible",
                "transfer_policy": "transferable",
                "revocable": false
            }),
            serde_json::json!({
                "v": 1,
                "ctx": CTX_NFT_CREATE_COLLECTION,
                "op": "create_collection",
                "symbol": "BADURI",
                "name": "Bad Uri",
                "max_supply": 10,
                "base_uri": "ftp://bad-uri/",
                "metadata_hash_hex": hash_hex(0x94),
                "mintable": true,
                "burnable": true,
                "asset_type": "collectible",
                "transfer_policy": "transferable",
                "revocable": false
            }),
            serde_json::json!({
                "v": 1,
                "ctx": CTX_NFT_CREATE_COLLECTION,
                "op": "create_collection",
                "symbol": "BADHASH",
                "name": "Bad Hash",
                "max_supply": 10,
                "base_uri": "newgen://bad-hash/",
                "metadata_hash_hex": "00".repeat(32),
                "mintable": true,
                "burnable": true,
                "asset_type": "collectible",
                "transfer_policy": "transferable",
                "revocable": false
            }),
        ];
        for memo in cases {
            assert!(parse_nft_memo_v1(&mk_tx(memo)).is_err());
        }
    }

    #[test]
    #[allow(deprecated)]
    fn nft_receipt_json_transfer_has_expected_shape() {
        let tx = mk_tx_from_op(&NftOpV1::Transfer {
            collection_id: 7,
            serial: 3,
            to_b64: addr(2),
        });

        let v = nft_receipt_json_v1(&tx).unwrap().unwrap();
        assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("nft_transfer"));
        assert_eq!(v.get("collection_id").and_then(|x| x.as_u64()), Some(7));
        assert_eq!(v.get("serial").and_then(|x| x.as_u64()), Some(3));
        let expected_to = addr(2);
        assert_eq!(
            v.get("to_b64").and_then(|x| x.as_str()),
            Some(expected_to.as_str())
        );
    }
}
