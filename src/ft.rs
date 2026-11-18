// src/ft.rs
//
// Phase 4 (Gate 4.0) — Native Fungible Tokens (FT v1)
//
// Design goals:
// - NO protocol break of legacy user tx format (Transaction remains unchanged)
// - FT ops are encoded as consensus-critical "system ops" via receiver sentinel + memo JSON
// - Deterministic, bounded, mainnet-grade validation
// - Activation gated (height-based) via governance params/env
//
// IMPORTANT:
// - This module only defines syntax + state keys + deterministic encoding helpers.
// - The actual state transitions are applied in blockchain.rs (SMT path), gated by activation height.

use crate::account::AccountState;
use crate::state_smt::sys_key;
use crate::transaction::Transaction;
use bincode::Options;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Receiver sentinel for FT operations.
/// Consensus-critical: any tx with receiver=FT must have a valid FT memo, otherwise reject.
pub const FT_RECEIVER: &str = "FT";

pub const FTV1_MEMO_MAX_BYTES: usize = 16 * 1024;

// Domain separation tags (signed inside memo string).
pub const CTX_FT_CREATE: &str = "NEWGEN:FTV1:CREATE";
pub const CTX_FT_TRANSFER: &str = "NEWGEN:FTV1:TRANSFER";
pub const CTX_FT_MINT: &str = "NEWGEN:FTV1:MINT";
pub const CTX_FT_BURN: &str = "NEWGEN:FTV1:BURN";

// Optional ops (Part 3)
pub const CTX_FT_APPROVE: &str = "NEWGEN:FTV1:APPROVE";
pub const CTX_FT_TRANSFER_FROM: &str = "NEWGEN:FTV1:TRANSFER_FROM";
pub const CTX_FT_PAUSE: &str = "NEWGEN:FTV1:PAUSE";
pub const CTX_FT_FREEZE: &str = "NEWGEN:FTV1:FREEZE";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtTokenMetaV1 {
    pub id: u64,
    pub owner_b64: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: Option<u128>,
    pub supply: u128,
    pub created_height: u64,
    pub metadata_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FtOpV1 {
    CreateToken {
        symbol: String,
        decimals: u8,
        max_supply: Option<u128>,
        metadata_hash: [u8; 32],
        /// If false, additional mint is forbidden after create.
        mintable: bool,
        /// If false, burn is forbidden.
        burnable: bool,
        /// If true, owner may freeze accounts.
        freeze_enabled: bool,
        /// Optional initial mint to owner at creation.
        initial_supply: u128,
    },
    Transfer {
        token_id: u64,
        to_b64: String,
        amount: u128,
    },
    Mint {
        token_id: u64,
        to_b64: String,
        amount: u128,
    },
    Burn {
        token_id: u64,
        amount: u128,
    },
    Approve {
        token_id: u64,
        spender_b64: String,
        amount: u128,
    },
    TransferFrom {
        token_id: u64,
        from_b64: String,
        to_b64: String,
        amount: u128,
    },
    SetPaused {
        token_id: u64,
        paused: bool,
    },
    SetFrozen {
        token_id: u64,
        addr_b64: String,
        frozen: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtTokenCfgV1 {
    pub mintable: bool,
    pub burnable: bool,
    pub paused: bool,
    pub freeze_enabled: bool,
}

impl Default for FtTokenCfgV1 {
    fn default() -> Self {
        Self {
            mintable: true,
            burnable: true,
            paused: false,
            freeze_enabled: false,
        }
    }
}

fn get_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

fn get_nonempty_trimmed_str(v: &Value, key: &str) -> Result<String, String> {
    let s = get_str(v, key)?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(format!("missing_or_invalid_field: {}", key));
    }
    Ok(trimmed.to_string())
}

fn get_token_id_nonzero(v: &Value, key: &str) -> Result<u64, String> {
    let token_id = get_u64(v, key)?;
    if token_id == 0 {
        return Err(format!("missing_or_invalid_field: {}", key));
    }
    Ok(token_id)
}

fn get_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

fn get_u8(v: &Value, key: &str) -> Result<u8, String> {
    let n = get_u64(v, key)?;
    if n > 255 {
        return Err(format!("field_out_of_range_u8: {}", key));
    }
    Ok(n as u8)
}

fn get_u128_any(v: &Value, key: &str) -> Result<u128, String> {
    match v.get(key) {
        Some(x) if x.is_u64() => Ok(x.as_u64().unwrap() as u128),
        Some(x) if x.is_string() => {
            let s = x.as_str().unwrap();
            s.parse::<u128>()
                .map_err(|_| format!("invalid_u128_decimal: {}", key))
        }
        _ => Err(format!("missing_or_invalid_field: {}", key)),
    }
}

fn get_u128_any_opt(v: &Value, key: &str) -> Result<Option<u128>, String> {
    match v.get(key) {
        None => Ok(None),
        Some(x) if x.is_null() => Ok(None),
        Some(_) => Ok(Some(get_u128_any(v, key)?)),
    }
}

// --------------------------
// Amount helpers (FT decimals)
// --------------------------
//
// FT amounts are stored in atomic units (u128). The token's `decimals` field
// defines the human-readable scale (10^decimals). These helpers are deterministic
// (no floats) and accept both '.' and ',' as decimal separators.

pub fn ft_scale_u128(decimals: u8) -> Result<u128, String> {
    // Keep a conservative upper bound to avoid overflow and to match typical token conventions.
    if decimals > 18 {
        return Err("decimals_too_large".to_string());
    }
    let mut s: u128 = 1;
    for _ in 0..decimals {
        s = s
            .checked_mul(10)
            .ok_or_else(|| "scale_overflow".to_string())?;
    }
    Ok(s)
}

pub fn parse_ft_amount_decimal_to_atomic(input: &str, decimals: u8) -> Result<u128, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty_amount".to_string());
    }
    if s.starts_with('-') {
        return Err("negative_amount".to_string());
    }
    if s.contains('e') || s.contains('E') {
        return Err("scientific_not_allowed".to_string());
    }

    let scale = ft_scale_u128(decimals)?;
    let s = s.replace(',', ".");
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err("invalid_decimal_format".to_string());
    }

    let whole_str = parts[0];
    if whole_str.is_empty() {
        return Err("invalid_decimal_format".to_string());
    }
    let whole: u128 = whole_str
        .parse::<u128>()
        .map_err(|_| "invalid_whole_digits".to_string())?;

    let frac: u128 = if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.len() > decimals as usize {
            return Err("too_many_decimals".to_string());
        }
        // pad right with zeros to `decimals`
        let mut frac_digits = frac_str.to_string();
        while frac_digits.len() < decimals as usize {
            frac_digits.push('0');
        }
        if frac_digits.is_empty() {
            0
        } else {
            frac_digits
                .parse::<u128>()
                .map_err(|_| "invalid_fraction_digits".to_string())?
        }
    } else {
        0
    };

    let atomic = whole
        .checked_mul(scale)
        .ok_or_else(|| "amount_overflow".to_string())?
        .checked_add(frac)
        .ok_or_else(|| "amount_overflow".to_string())?;
    Ok(atomic)
}

pub fn format_ft_amount_atomic_to_decimal(amount_atomic: u128, decimals: u8) -> String {
    let scale = match ft_scale_u128(decimals) {
        Ok(s) => s,
        Err(_) => return amount_atomic.to_string(), // fail-open display
    };
    if decimals == 0 {
        return amount_atomic.to_string();
    }
    let whole = amount_atomic / scale;
    let frac = amount_atomic % scale;
    // zero-pad fractional part to `decimals`
    format!("{}.{:0width$}", whole, frac, width = decimals as usize)
}

fn get_bool_default(v: &Value, key: &str, default: bool) -> Result<bool, String> {
    match v.get(key) {
        None => Ok(default),
        Some(x) if x.is_null() => Ok(default),
        Some(x) if x.is_boolean() => Ok(x.as_bool().unwrap()),
        _ => Err(format!("missing_or_invalid_field: {}", key)),
    }
}

fn parse_hash32_hex_opt(v: &Value, key: &str) -> Result<[u8; 32], String> {
    let s_opt = v.get(key).and_then(|x| x.as_str());
    if s_opt.is_none() {
        return Ok([0u8; 32]);
    }
    let s = s_opt.unwrap().trim();
    if s.is_empty() {
        return Ok([0u8; 32]);
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid_hex32: {} ({})", key, e))?;
    if bytes.len() != 32 {
        return Err(format!("invalid_hex32_len: {}", key));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn is_symbol_ok(sym: &str) -> bool {
    let s = sym.trim();
    let n = s.len();
    if !(3..=10).contains(&n) {
        return false;
    }
    s.bytes()
        .all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

/// True if tx uses FT receiver sentinel.
pub fn is_ft_tx(tx: &Transaction) -> bool {
    tx.receiver.trim() == FT_RECEIVER
}

/// Parse FT memo JSON into FtOpV1.
/// Memo format:
/// {"v":1,"ctx":"NEWGEN:FTV1:CREATE","op":"create_token",...}
/// {"v":1,"ctx":"NEWGEN:FTV1:TRANSFER","op":"transfer",...}
pub fn parse_ft_memo_v1(tx: &Transaction) -> Result<FtOpV1, String> {
    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "ft_tx_missing_memo".to_string())?;

    if memo.len() > FTV1_MEMO_MAX_BYTES {
        return Err("ft_tx_memo_too_large".to_string());
    }

    let v: Value = serde_json::from_str(memo).map_err(|e| format!("ft_tx_memo_not_json: {}", e))?;
    let ver = get_u64(&v, "v")?;
    if ver != 1 {
        return Err(format!("unsupported_ft_memo_version: {}", ver));
    }

    let op = get_str(&v, "op")?;
    let ctx = get_str(&v, "ctx")?;

    match op.as_str() {
        "create_token" => {
            if ctx != CTX_FT_CREATE {
                return Err("ft_ctx_mismatch".to_string());
            }
            let symbol = get_nonempty_trimmed_str(&v, "symbol")?;
            let decimals = get_u8(&v, "decimals")?;
            if decimals > 18 {
                return Err("ft_decimals_out_of_range".to_string());
            }
            if !is_symbol_ok(&symbol) {
                return Err("ft_symbol_invalid".to_string());
            }

            let max_supply = get_u128_any_opt(&v, "max_supply")?;
            if let Some(m) = max_supply {
                if m == 0 {
                    return Err("ft_max_supply_must_be_positive".to_string());
                }
            }

            let metadata_hash = parse_hash32_hex_opt(&v, "metadata_hash_hex")?;

            let mintable = get_bool_default(&v, "mintable", true)?;
            let burnable = get_bool_default(&v, "burnable", true)?;
            let freeze_enabled = get_bool_default(&v, "freeze_enabled", false)?;

            let initial_supply: u128 =
                (get_u128_any_opt(&v, "initial_supply")?).unwrap_or_default();
            if initial_supply > 0 {
                if let Some(m) = max_supply {
                    if initial_supply > m {
                        return Err("ft_initial_supply_exceeds_max_supply".to_string());
                    }
                }
            }
            // If minting is disabled, enforce fixed supply at create.
            if !mintable {
                let m = max_supply
                    .ok_or_else(|| "ft_mintable_false_requires_max_supply".to_string())?;
                if initial_supply != m {
                    return Err("ft_fixed_supply_requires_initial_equals_max".to_string());
                }
            }

            Ok(FtOpV1::CreateToken {
                symbol,
                decimals,
                max_supply,
                metadata_hash,
                mintable,
                burnable,
                freeze_enabled,
                initial_supply,
            })
        }

        "transfer" => {
            if ctx != CTX_FT_TRANSFER {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let to_b64 = get_nonempty_trimmed_str(&v, "to")?;
            let amount = get_u128_any(&v, "amount")?;
            if amount == 0 {
                return Err("ft_amount_must_be_positive".to_string());
            }

            Ok(FtOpV1::Transfer {
                token_id,
                to_b64,
                amount,
            })
        }

        "mint" => {
            if ctx != CTX_FT_MINT {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let to_b64 = get_nonempty_trimmed_str(&v, "to")?;
            let amount = get_u128_any(&v, "amount")?;
            if amount == 0 {
                return Err("ft_amount_must_be_positive".to_string());
            }
            Ok(FtOpV1::Mint {
                token_id,
                to_b64,
                amount,
            })
        }

        "burn" => {
            if ctx != CTX_FT_BURN {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let amount = get_u128_any(&v, "amount")?;
            if amount == 0 {
                return Err("ft_amount_must_be_positive".to_string());
            }
            Ok(FtOpV1::Burn { token_id, amount })
        }

        "approve" => {
            if ctx != CTX_FT_APPROVE {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let spender_b64 = get_nonempty_trimmed_str(&v, "spender")?;
            let amount: u128 = (get_u128_any_opt(&v, "amount")?).unwrap_or_default();
            Ok(FtOpV1::Approve {
                token_id,
                spender_b64,
                amount,
            })
        }

        "transfer_from" => {
            if ctx != CTX_FT_TRANSFER_FROM {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let from_b64 = get_nonempty_trimmed_str(&v, "from")?;
            let to_b64 = get_nonempty_trimmed_str(&v, "to")?;
            let amount = get_u128_any(&v, "amount")?;
            if amount == 0 {
                return Err("ft_amount_must_be_positive".to_string());
            }
            Ok(FtOpV1::TransferFrom {
                token_id,
                from_b64,
                to_b64,
                amount,
            })
        }

        "pause" => {
            if ctx != CTX_FT_PAUSE {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let paused = get_bool_default(&v, "paused", true)?;
            Ok(FtOpV1::SetPaused { token_id, paused })
        }

        "freeze" => {
            if ctx != CTX_FT_FREEZE {
                return Err("ft_ctx_mismatch".to_string());
            }
            let token_id = get_token_id_nonzero(&v, "token_id")?;
            let addr_b64 = get_nonempty_trimmed_str(&v, "addr")?;
            let frozen = get_bool_default(&v, "frozen", true)?;
            Ok(FtOpV1::SetFrozen {
                token_id,
                addr_b64,
                frozen,
            })
        }

        _ => Err("unsupported_ft_op".to_string()),
    }
}

/// Syntax validation for receiver=FT txs.
/// Does not touch state. Consensus-critical.
pub fn validate_ft_tx_syntax(tx: &Transaction) -> Result<(), String> {
    if !is_ft_tx(tx) {
        return Ok(());
    }

    if tx.is_coinbase {
        return Err("ft_tx_cannot_be_coinbase".to_string());
    }

    // FT ops must not move native coins (only pay fees)
    if tx.amount != 0 {
        return Err("ft_tx_amount_must_be_0".to_string());
    }

    // Must parse as v1 FT memo
    let _op = parse_ft_memo_v1(tx)?;
    Ok(())
}

// ----------------------------
// SMT keys (reserved sys space)
// ----------------------------

pub fn k_ft_next_token_id() -> [u8; 32] {
    sys_key("ft/next_token_id")
}

pub fn k_ft_meta(token_id: u64) -> [u8; 32] {
    sys_key(&format!("ft/{}/meta", token_id))
}

pub fn k_ft_cfg(token_id: u64) -> [u8; 32] {
    sys_key(&format!("ft/{}/cfg", token_id))
}

pub fn k_ft_balance(token_id: u64, addr_b64: &str) -> [u8; 32] {
    sys_key(&format!("ft/{}/bal/{}", token_id, addr_b64.trim()))
}

pub fn k_ft_owner_count(owner_b64: &str) -> [u8; 32] {
    sys_key(&format!("ft/owner/{}/count", owner_b64.trim()))
}

pub fn k_ft_owner_last_create(owner_b64: &str) -> [u8; 32] {
    sys_key(&format!("ft/owner/{}/last_create", owner_b64.trim()))
}

pub fn k_ft_allowance(token_id: u64, owner_b64: &str, spender_b64: &str) -> [u8; 32] {
    sys_key(&format!(
        "ft/{}/allow/{}/{}",
        token_id,
        owner_b64.trim(),
        spender_b64.trim()
    ))
}

pub fn k_ft_frozen(token_id: u64, addr_b64: &str) -> [u8; 32] {
    sys_key(&format!("ft/{}/freeze/{}", token_id, addr_b64.trim()))
}

// ----------------------------
// Deterministic state codec (bincode fixed LE)
// ----------------------------

pub const FT_DATA_VERSION_V1: u8 = 1;
const TAG_META: u8 = 1;
const TAG_BAL: u8 = 2;
const TAG_CFG: u8 = 3;
const TAG_ALLOW: u8 = 4;
const TAG_FREEZE: u8 = 5;

fn bincode_fixed_le() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

fn enc_record<T: Serialize>(tag: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.push(FT_DATA_VERSION_V1);
    out.push(tag);
    let payload = bincode_fixed_le()
        .serialize(v)
        .map_err(|e| format!("bincode serialize: {e}"))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

fn dec_record<T: for<'de> Deserialize<'de>>(tag: u8, data: &[u8]) -> Result<T, String> {
    if data.len() < 2 {
        return Err("ft_data_too_short".to_string());
    }
    if data[0] != FT_DATA_VERSION_V1 {
        return Err(format!("unsupported_ft_data_version: {}", data[0]));
    }
    if data[1] != tag {
        return Err(format!(
            "ft_data_tag_mismatch: expected={} got={}",
            tag, data[1]
        ));
    }
    bincode_fixed_le()
        .deserialize(&data[2..])
        .map_err(|e| format!("bincode deserialize: {e}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FtBalanceV1 {
    amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FtFreezeV1 {
    frozen: bool,
}

pub fn encode_meta_state_v1(meta: &FtTokenMetaV1) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_META, meta)?,
    })
}

pub fn decode_meta_state_v1(st: &AccountState) -> Result<FtTokenMetaV1, String> {
    dec_record(TAG_META, &st.data)
}

pub fn encode_balance_state_v1(amount: u128) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_BAL, &FtBalanceV1 { amount })?,
    })
}

pub fn decode_balance_amount_v1(st: &AccountState) -> Result<u128, String> {
    if st.data.is_empty() {
        return Ok(0);
    }
    let bal: FtBalanceV1 = dec_record(TAG_BAL, &st.data)?;
    Ok(bal.amount)
}

pub fn encode_cfg_state_v1(cfg: &FtTokenCfgV1) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_CFG, cfg)?,
    })
}

pub fn decode_cfg_state_v1(st: &AccountState) -> Result<FtTokenCfgV1, String> {
    if st.data.is_empty() {
        return Ok(FtTokenCfgV1::default());
    }
    dec_record(TAG_CFG, &st.data)
}

pub fn encode_allowance_state_v1(amount: u128) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_ALLOW, &FtBalanceV1 { amount })?,
    })
}

pub fn decode_allowance_amount_v1(st: &AccountState) -> Result<u128, String> {
    if st.data.is_empty() {
        return Ok(0);
    }
    let bal: FtBalanceV1 = dec_record(TAG_ALLOW, &st.data)?;
    Ok(bal.amount)
}

pub fn encode_freeze_state_v1(frozen: bool) -> Result<AccountState, String> {
    Ok(AccountState {
        nonce: 0,
        balance: 0,
        data: enc_record(TAG_FREEZE, &FtFreezeV1 { frozen })?,
    })
}

pub fn decode_frozen_bool_v1(st: &AccountState) -> Result<bool, String> {
    if st.data.is_empty() {
        return Ok(false);
    }
    let f: FtFreezeV1 = dec_record(TAG_FREEZE, &st.data)?;
    Ok(f.frozen)
}

pub fn ft_op_name_v1(op: &FtOpV1) -> &'static str {
    match op {
        FtOpV1::CreateToken { .. } => "create_token",
        FtOpV1::Transfer { .. } => "transfer",
        FtOpV1::Mint { .. } => "mint",
        FtOpV1::Burn { .. } => "burn",
        FtOpV1::Approve { .. } => "approve",
        FtOpV1::TransferFrom { .. } => "transfer_from",
        FtOpV1::SetPaused { .. } => "pause",
        FtOpV1::SetFrozen { .. } => "freeze",
    }
}

pub fn ft_event_kind_v1(op: &FtOpV1) -> &'static str {
    match op {
        FtOpV1::CreateToken { .. } => "ft_create",
        FtOpV1::Transfer { .. } => "ft_transfer",
        FtOpV1::Mint { .. } => "ft_mint",
        FtOpV1::Burn { .. } => "ft_burn",
        FtOpV1::Approve { .. } => "ft_approve",
        FtOpV1::TransferFrom { .. } => "ft_transfer_from",
        FtOpV1::SetPaused { .. } => "ft_pause",
        FtOpV1::SetFrozen { .. } => "ft_freeze",
    }
}

/// Best-effort receipt-like JSON derived from the consensus FT memo.
/// This is stable enough for explorer/indexer consumption, but it is not a canonical execution
/// receipt because Block/Transaction currently do not persist post-state deltas.
///
/// Important limitation: `create_token` cannot know the assigned `token_id` from the tx alone,
/// so `token_id` is omitted for that operation.
pub fn ft_receipt_json_v1(tx: &Transaction) -> Result<Option<Value>, String> {
    if !is_ft_tx(tx) {
        return Ok(None);
    }

    let sender = tx.sender.trim().to_string();
    let op = parse_ft_memo_v1(tx)?;
    let kind = ft_event_kind_v1(&op);
    let op_name = ft_op_name_v1(&op);

    let value = match op {
        FtOpV1::CreateToken {
            symbol,
            decimals,
            max_supply,
            metadata_hash,
            mintable,
            burnable,
            freeze_enabled,
            initial_supply,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "owner_b64": sender,
            "symbol": symbol,
            "decimals": decimals,
            "max_supply": max_supply.map(|v| v.to_string()),
            "initial_supply": initial_supply.to_string(),
            "metadata_hash": hex::encode(metadata_hash),
            "mintable": mintable,
            "burnable": burnable,
            "freeze_enabled": freeze_enabled
        }),
        FtOpV1::Transfer {
            token_id,
            to_b64,
            amount,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "from_b64": sender,
            "to_b64": to_b64,
            "amount": amount.to_string()
        }),
        FtOpV1::Mint {
            token_id,
            to_b64,
            amount,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "owner_b64": sender,
            "to_b64": to_b64,
            "amount": amount.to_string()
        }),
        FtOpV1::Burn { token_id, amount } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "from_b64": sender,
            "amount": amount.to_string()
        }),
        FtOpV1::Approve {
            token_id,
            spender_b64,
            amount,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "owner_b64": sender,
            "spender_b64": spender_b64,
            "amount": amount.to_string()
        }),
        FtOpV1::TransferFrom {
            token_id,
            from_b64,
            to_b64,
            amount,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "spender_b64": sender,
            "from_b64": from_b64,
            "to_b64": to_b64,
            "amount": amount.to_string()
        }),
        FtOpV1::SetPaused { token_id, paused } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "owner_b64": sender,
            "paused": paused
        }),
        FtOpV1::SetFrozen {
            token_id,
            addr_b64,
            frozen,
        } => serde_json::json!({
            "v": 1,
            "kind": kind,
            "op": op_name,
            "token_id": token_id,
            "owner_b64": sender,
            "addr_b64": addr_b64,
            "frozen": frozen
        }),
    };

    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ft_parse_rejects_empty_address_like_fields() {
        let mk_tx = |memo: serde_json::Value| Transaction {
            sender: "SENDER".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 1,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(serde_json::to_string(&memo).unwrap()),
        };

        let tx_transfer = mk_tx(json!({
            "v": 1,
            "ctx": CTX_FT_TRANSFER,
            "op": "transfer",
            "token_id": 1,
            "to": "   ",
            "amount": "1"
        }));
        assert!(parse_ft_memo_v1(&tx_transfer).is_err());

        let tx_approve = mk_tx(json!({
            "v": 1,
            "ctx": CTX_FT_APPROVE,
            "op": "approve",
            "token_id": 1,
            "spender": "",
            "amount": "1"
        }));
        assert!(parse_ft_memo_v1(&tx_approve).is_err());

        let tx_transfer_from = mk_tx(json!({
            "v": 1,
            "ctx": CTX_FT_TRANSFER_FROM,
            "op": "transfer_from",
            "token_id": 1,
            "from": "",
            "to": "DEST",
            "amount": "1"
        }));
        assert!(parse_ft_memo_v1(&tx_transfer_from).is_err());

        let tx_freeze = mk_tx(json!({
            "v": 1,
            "ctx": CTX_FT_FREEZE,
            "op": "freeze",
            "token_id": 1,
            "addr": " ",
            "frozen": true
        }));
        assert!(parse_ft_memo_v1(&tx_freeze).is_err());
    }

    #[test]
    fn ft_parse_trims_symbol_and_addresses() {
        let tx = Transaction {
            sender: "SENDER".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 1,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(
                serde_json::to_string(&json!({
                    "v": 1,
                    "ctx": CTX_FT_CREATE,
                    "op": "create_token",
                    "symbol": "  GEMS  ",
                    "decimals": 0,
                    "max_supply": "10",
                    "initial_supply": "10",
                    "mintable": false
                }))
                .unwrap(),
            ),
        };

        match parse_ft_memo_v1(&tx).unwrap() {
            FtOpV1::CreateToken { symbol, .. } => assert_eq!(symbol, "GEMS"),
            _ => panic!("unexpected op"),
        }

        let tx_transfer = Transaction {
            sender: "SENDER".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 2,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(
                serde_json::to_string(&json!({
                    "v": 1,
                    "ctx": CTX_FT_TRANSFER,
                    "op": "transfer",
                    "token_id": 1,
                    "to": "  DEST  ",
                    "amount": "1"
                }))
                .unwrap(),
            ),
        };

        match parse_ft_memo_v1(&tx_transfer).unwrap() {
            FtOpV1::Transfer { to_b64, .. } => assert_eq!(to_b64, "DEST"),
            _ => panic!("unexpected op"),
        }
    }

    #[test]
    fn ft_parse_rejects_zero_token_id_for_existing_token_ops() {
        let mk_tx = |memo: serde_json::Value| Transaction {
            sender: "SENDER".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 1,
            signature: String::new(),
            hash: String::new(),
            is_coinbase: false,
            memo: Some(serde_json::to_string(&memo).unwrap()),
        };

        for memo in [
            json!({"v":1,"ctx":CTX_FT_TRANSFER,"op":"transfer","token_id":0,"to":"DEST","amount":"1"}),
            json!({"v":1,"ctx":CTX_FT_MINT,"op":"mint","token_id":0,"to":"DEST","amount":"1"}),
            json!({"v":1,"ctx":CTX_FT_BURN,"op":"burn","token_id":0,"amount":"1"}),
            json!({"v":1,"ctx":CTX_FT_APPROVE,"op":"approve","token_id":0,"spender":"DEST","amount":"1"}),
            json!({"v":1,"ctx":CTX_FT_TRANSFER_FROM,"op":"transfer_from","token_id":0,"from":"A","to":"B","amount":"1"}),
            json!({"v":1,"ctx":CTX_FT_PAUSE,"op":"pause","token_id":0,"paused":true}),
            json!({"v":1,"ctx":CTX_FT_FREEZE,"op":"freeze","token_id":0,"addr":"A","frozen":true}),
        ] {
            assert!(parse_ft_memo_v1(&mk_tx(memo)).is_err());
        }
    }

    #[test]
    fn ft_receipt_json_transfer_has_expected_shape() {
        let tx = Transaction {
            sender: "ALICE".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 7,
            signature: String::new(),
            hash: "abcd".to_string(),
            is_coinbase: false,
            memo: Some(
                serde_json::to_string(&json!({
                    "v": 1,
                    "ctx": CTX_FT_TRANSFER,
                    "op": "transfer",
                    "token_id": 42,
                    "to": "BOB",
                    "amount": "25"
                }))
                .unwrap(),
            ),
        };

        let v = ft_receipt_json_v1(&tx).unwrap().unwrap();
        assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("ft_transfer"));
        assert_eq!(v.get("token_id").and_then(|x| x.as_u64()), Some(42));
        assert_eq!(v.get("from_b64").and_then(|x| x.as_str()), Some("ALICE"));
        assert_eq!(v.get("to_b64").and_then(|x| x.as_str()), Some("BOB"));
        assert_eq!(v.get("amount").and_then(|x| x.as_str()), Some("25"));
    }

    #[test]
    fn ft_receipt_json_create_omits_token_id_and_keeps_limits() {
        let tx = Transaction {
            sender: "OWNER".to_string(),
            receiver: FT_RECEIVER.to_string(),
            amount: 0,
            max_fee_per_tx: 0,
            nonce: 1,
            signature: String::new(),
            hash: "h1".to_string(),
            is_coinbase: false,
            memo: Some(
                serde_json::to_string(&json!({
                    "v": 1,
                    "ctx": CTX_FT_CREATE,
                    "op": "create_token",
                    "symbol": "GEMS",
                    "decimals": 0,
                    "max_supply": "1000",
                    "initial_supply": "100",
                    "mintable": true,
                    "burnable": true,
                    "freeze_enabled": true
                }))
                .unwrap(),
            ),
        };

        let v = ft_receipt_json_v1(&tx).unwrap().unwrap();
        assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("ft_create"));
        assert_eq!(v.get("owner_b64").and_then(|x| x.as_str()), Some("OWNER"));
        assert!(v.get("token_id").is_none());
        assert_eq!(v.get("max_supply").and_then(|x| x.as_str()), Some("1000"));
        assert_eq!(
            v.get("initial_supply").and_then(|x| x.as_str()),
            Some("100")
        );
    }
    #[test]
    fn ft_amount_decimal_parsing_and_formatting() {
        // 6 decimals (native-style scale)
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("5", 6).unwrap(),
            5_000_000u128
        );
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("5.50", 6).unwrap(),
            5_500_000u128
        );
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("5,50", 6).unwrap(),
            5_500_000u128
        );
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("0.000001", 6).unwrap(),
            1u128
        );
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("1.234567", 6).unwrap(),
            1_234_567u128
        );
        assert!(parse_ft_amount_decimal_to_atomic("1.2345678", 6).is_err());

        // 2 decimals (cents-style)
        assert_eq!(
            parse_ft_amount_decimal_to_atomic("5.50", 2).unwrap(),
            550u128
        );
        assert_eq!(format_ft_amount_atomic_to_decimal(550u128, 2), "5.50");
        assert_eq!(format_ft_amount_atomic_to_decimal(25u128, 0), "25");
    }
}
