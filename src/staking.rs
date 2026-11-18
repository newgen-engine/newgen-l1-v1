use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Receiver sentinella per le “system ops” di staking/validator registry.
///
/// ⚠️ Consensus-critical: qualsiasi TX con receiver=STAKE e memo non valido
/// deve essere rifiutata, altrimenti rischi burn/lock involontari.
pub const STAKE_RECEIVER: &str = "STAKE";

/// Parametri PoS (fase 1: ground truth on-chain, senza cambiare consenso).
///
/// Nota: in questa patch li esponiamo per parsing da genesis.json,
/// ma NON li applichiamo ancora alla produzione blocchi.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PosParamsV1 {
    pub min_stake: u64,
    pub unbonding_epochs: u64,
    pub epoch_len: u64,
    pub committee_size: u64,
}

impl Default for PosParamsV1 {
    fn default() -> Self {
        Self {
            min_stake: 1,
            unbonding_epochs: 7,
            epoch_len: 1000,
            committee_size: 64,
        }
    }
}

fn get_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

fn get_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("missing_or_invalid_field: {}", key))
}

/// Ritorna true se la TX usa il receiver sentinella.
pub fn is_stake_tx(tx: &Transaction) -> bool {
    tx.receiver == STAKE_RECEIVER
}

/// Validazione sintattica (non-stateful) delle TX receiver=STAKE.
///
/// Requisiti minimi:
/// - memo deve essere JSON valido
/// - { v:1, op:"..." } obbligatorio
/// - campi obbligatori per op
/// - vincoli minimi su amount (bond/unbond >0, register/update/rotate/withdraw =0)
pub fn validate_stake_tx_syntax(tx: &Transaction) -> Result<(), String> {
    if !is_stake_tx(tx) {
        return Ok(());
    }

    if tx.is_coinbase {
        return Err("stake_tx_cannot_be_coinbase".to_string());
    }

    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "stake_tx_missing_memo".to_string())?;

    // difesa soft anti-DoS (consensus-friendly): memo troppo grande
    if memo.len() > 16 * 1024 {
        return Err("stake_tx_memo_too_large".to_string());
    }

    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("stake_tx_memo_not_json: {}", e))?;

    let ver = get_u64(&v, "v")?;
    if ver != 1 {
        return Err(format!("unsupported_stake_memo_version: {}", ver));
    }

    let op = get_str(&v, "op")?;

    match op.as_str() {
        "register_validator" => {
            // required fields
            let _cons_pk = get_str(&v, "consensus_pubkey_b64")?;
            let _net = get_str(&v, "net_addr")?;
            let commission = get_u64(&v, "commission_bps")?;
            if commission > 10_000 {
                return Err("commission_bps_out_of_range".to_string());
            }
            // metadata è opzionale
            // amount = 0 (register non sposta fondi)
            if tx.amount != 0 {
                return Err("register_validator_amount_must_be_0".to_string());
            }
        }

        "update_validator" => {
            // almeno un campo deve essere presente
            let has_net = v.get("net_addr").and_then(|x| x.as_str()).is_some();
            let has_comm = v.get("commission_bps").and_then(|x| x.as_u64()).is_some();
            let has_meta = v.get("metadata").and_then(|x| x.as_str()).is_some();

            if !(has_net || has_comm || has_meta) {
                return Err("update_validator_requires_at_least_one_field".to_string());
            }

            if let Some(c) = v.get("commission_bps").and_then(|x| x.as_u64()) {
                if c > 10_000 {
                    return Err("commission_bps_out_of_range".to_string());
                }
            }

            if tx.amount != 0 {
                return Err("update_validator_amount_must_be_0".to_string());
            }
        }

        "rotate_key" => {
            let _new_pk = get_str(&v, "new_pubkey_b64")?;
            let _proof = get_str(&v, "proof_signed_by_old")?;
            if tx.amount != 0 {
                return Err("rotate_key_amount_must_be_0".to_string());
            }
        }

        "bond" => {
            let _val_pk = get_str(&v, "validator_pk_b64")?;
            if tx.amount == 0 {
                return Err("bond_amount_must_be_gt_0".to_string());
            }
        }

        "unbond" => {
            let _val_pk = get_str(&v, "validator_pk_b64")?;
            if tx.amount == 0 {
                return Err("unbond_amount_must_be_gt_0".to_string());
            }
        }

        "withdraw" => {
            let _val_pk = get_str(&v, "validator_pk_b64")?;
            if tx.amount != 0 {
                return Err("withdraw_amount_must_be_0".to_string());
            }
        }

        "randao_commit" => {
            let _epoch = get_u64(&v, "epoch")?;
            let c = get_str(&v, "commit_b64")?;
            crate::keyfmt::decode_pk_any(&c)
                .map_err(|e| format!("randao_commit_invalid_32b: {e}"))?;
            if tx.amount != 0 {
                return Err("randao_commit_amount_must_be_0".to_string());
            }
        }

        "randao_reveal" => {
            let _epoch = get_u64(&v, "epoch")?;
            let s = get_str(&v, "secret_b64")?;
            crate::keyfmt::decode_pk_any(&s)
                .map_err(|e| format!("randao_reveal_invalid_32b: {e}"))?;
            if tx.amount != 0 {
                return Err("randao_reveal_amount_must_be_0".to_string());
            }
        }

        "evidence_double_vote" => {
            let _epoch = get_u64(&v, "epoch")?;
            let _height = get_u64(&v, "height")?;
            let _round = get_u64(&v, "round")?;
            let voter = get_str(&v, "voter_pk")?;
            let bh_a = get_str(&v, "block_hash_a")?;
            let bh_b = get_str(&v, "block_hash_b")?;
            let sig_a = get_str(&v, "sig_a_b64")?;
            let sig_b = get_str(&v, "sig_b_b64")?;

            // Cheap structural checks (consensus-critical guardrail)
            if bh_a == bh_b {
                return Err("evidence_double_vote_same_hash".to_string());
            }
            crate::state_smt::bytes32_from_hex(&bh_a)
                .map_err(|e| format!("evidence_block_hash_a_invalid: {e}"))?;
            crate::state_smt::bytes32_from_hex(&bh_b)
                .map_err(|e| format!("evidence_block_hash_b_invalid: {e}"))?;

            crate::keyfmt::decode_pk_any(&voter)
                .map_err(|e| format!("evidence_voter_pk_invalid: {e}"))?;
            crate::keyfmt::decode_sig64_b64(&sig_a)
                .map_err(|e| format!("evidence_sig_a_invalid: {e}"))?;
            crate::keyfmt::decode_sig64_b64(&sig_b)
                .map_err(|e| format!("evidence_sig_b_invalid: {e}"))?;

            if tx.amount != 0 {
                return Err("evidence_double_vote_amount_must_be_0".to_string());
            }
        }

        _ => return Err(format!("unknown_stake_op: {}", op)),
    }

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Phase 1 groundwork (Modalità B): typed parsing + deterministic on-chain records (SMT via AccountState.data)
//
// Nota: in questo step i record e i codec sono pronti, ma l'integrazione nel compute_state_root
// (stato SMT) viene completata nella patch successiva.
// -------------------------------------------------------------------------------------------------

use crate::account::AccountState;
use crate::chain_identity;
use crate::keyfmt;
use crate::state_smt::{sys_key, StateSmt};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bincode::Options;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Versione del payload in `AccountState.data` per staking/registry.
pub const STAKE_DATA_VERSION_V1: u8 = 1;

/// Tag (record type) in `AccountState.data`.
const TAG_PARAMS: u8 = 1;
const TAG_OWNER_LINK: u8 = 2;
const TAG_VALIDATOR: u8 = 3;
const TAG_UNBOND_LIST: u8 = 4;
const TAG_TOTAL_BONDED: u8 = 5;
const TAG_VALIDATOR_INDEX: u8 = 6;
const TAG_SLASH_PARAMS: u8 = 7;
const TAG_EVIDENCE_MARKER: u8 = 8;

fn bincode_fixed_le() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

fn enc_record<T: Serialize>(tag: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.push(STAKE_DATA_VERSION_V1);
    out.push(tag);
    let payload = bincode_fixed_le()
        .serialize(v)
        .map_err(|e| format!("bincode serialize: {e}"))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

fn dec_record<T: for<'de> Deserialize<'de>>(tag: u8, data: &[u8]) -> Result<T, String> {
    if data.len() < 2 {
        return Err("stake_data_too_short".to_string());
    }
    if data[0] != STAKE_DATA_VERSION_V1 {
        return Err(format!("unsupported_stake_data_version: {}", data[0]));
    }
    if data[1] != tag {
        return Err(format!(
            "stake_data_tag_mismatch: expected={}, got={}",
            tag, data[1]
        ));
    }
    bincode_fixed_le()
        .deserialize(&data[2..])
        .map_err(|e| format!("bincode deserialize: {e}"))
}

/// Stato validator (fase 1: è solo ground truth; non impatta ancora consenso).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ValidatorStatusV1 {
    Active,
    Inactive,
    Jailed,
    Tombstoned,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecordV1 {
    /// Owner (tx.sender) che controlla update/rotate.
    pub owner: String,
    /// Chiave consenso (ed25519) canonica in base64 (32 bytes).
    pub consensus_pubkey_b64: String,
    /// Indirizzo rete (multiaddr/stringa) dichiarato.
    pub net_addr: String,
    /// Commissione in bps (0..=10_000).
    pub commission_bps: u64,
    pub status: ValidatorStatusV1,
    pub bonded: u64,
    pub jailed_until_epoch: u64,
    pub metadata: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OwnerLinkV1 {
    pub owner: String,
    /// Pubkey validator in hex canonico (32 bytes).
    pub validator_pk_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UnbondEntryV1 {
    pub amount: u64,
    pub unlock_epoch: u64,
}

pub type UnbondListV1 = Vec<UnbondEntryV1>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TotalBondedV1 {
    pub total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidatorIndexV1 {
    /// Lista deterministica di validator pk in hex (lowercase, 32 bytes).
    /// Mantieni l'ordine di inserimento per avere replay identico.
    pub pk_hex: Vec<String>,
}

// -------------------------------
// Phase 4 groundwork: Slashing params + evidence markers (consensus-critical)
// -------------------------------

/// Parametri slashing (on-chain, deterministic, versioned).
///
/// Nota: questi parametri NON cambiano il fork-choice, ma determinano la severità delle penalità.
/// Devono essere conservati nello state SMT (sys key) per evitare divergenze dopo restart.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PosSlashParamsV1 {
    /// Penalità in basis points (bps) sul bonded corrente per double-vote.
    pub double_vote_slash_bps: u64,
    /// Numero di epoch di jail per double-vote (0 = no jail).
    pub double_vote_jail_epochs: u64,
    /// Se true, double-vote porta a tombstone (irreversibile).
    pub double_vote_tombstone: bool,
}

impl Default for PosSlashParamsV1 {
    fn default() -> Self {
        Self {
            double_vote_slash_bps: 500,   // 5%
            double_vote_jail_epochs: 2,   // 2 epoch
            double_vote_tombstone: false, // jail, non tombstone
        }
    }
}

/// Marker idempotente: impedisce di applicare due volte la stessa evidence.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EvidenceMarkerV1 {
    /// Altezza del blocco in cui l'evidence è stata applicata.
    pub applied_at_height: u64,
}

// -------------------------------
// SMT key derivation (deterministic)
// -------------------------------

pub fn k_stake_params() -> [u8; 32] {
    sys_key("stake/params")
}

pub fn k_total_bonded() -> [u8; 32] {
    sys_key("stake/total_bonded")
}

pub fn k_validator_index() -> [u8; 32] {
    sys_key("stake/val_index")
}

pub fn k_slash_params() -> [u8; 32] {
    sys_key("stake/slash_params")
}

/// Evidence marker per double-vote (epoch,height,round,voter).
pub fn k_evidence_double_vote(epoch: u64, height: u64, round: u32, voter_pk_hex: &str) -> [u8; 32] {
    let pk = voter_pk_hex.trim().to_ascii_lowercase();
    sys_key(&format!(
        "stake/evidence/double_vote/{}/{}/{}/{}",
        epoch, height, round, pk
    ))
}

pub fn k_owner_link(owner: &str) -> [u8; 32] {
    sys_key(&format!("stake/owner/{}", owner.trim()))
}

pub fn k_validator(pk_hex: &str) -> [u8; 32] {
    sys_key(&format!("stake/val/{}", pk_hex.trim()))
}

pub fn k_unbond(pk_hex: &str) -> [u8; 32] {
    sys_key(&format!("stake/unbond/{}", pk_hex.trim()))
}

// -------------------------------
// AccountState codec helpers
// -------------------------------

pub fn as_state_from_data(data: Vec<u8>) -> AccountState {
    AccountState {
        nonce: 0,
        balance: 0,
        data,
    }
}

pub fn encode_params_state(params: &PosParamsV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_PARAMS, params)?))
}

pub fn decode_params_state(st: &AccountState) -> Result<PosParamsV1, String> {
    dec_record(TAG_PARAMS, &st.data)
}

pub fn encode_owner_link_state(link: &OwnerLinkV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_OWNER_LINK, link)?))
}

pub fn decode_owner_link_state(st: &AccountState) -> Result<OwnerLinkV1, String> {
    dec_record(TAG_OWNER_LINK, &st.data)
}

pub fn encode_validator_state(v: &ValidatorRecordV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_VALIDATOR, v)?))
}

pub fn decode_validator_state(st: &AccountState) -> Result<ValidatorRecordV1, String> {
    dec_record(TAG_VALIDATOR, &st.data)
}

pub fn encode_unbond_list_state(xs: &UnbondListV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_UNBOND_LIST, xs)?))
}

pub fn decode_unbond_list_state(st: &AccountState) -> Result<UnbondListV1, String> {
    dec_record(TAG_UNBOND_LIST, &st.data)
}

pub fn encode_total_bonded_state(x: &TotalBondedV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_TOTAL_BONDED, x)?))
}

pub fn decode_total_bonded_state(st: &AccountState) -> Result<TotalBondedV1, String> {
    dec_record(TAG_TOTAL_BONDED, &st.data)
}

pub fn encode_validator_index_state(x: &ValidatorIndexV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_VALIDATOR_INDEX, x)?))
}

pub fn decode_validator_index_state(st: &AccountState) -> Result<ValidatorIndexV1, String> {
    dec_record(TAG_VALIDATOR_INDEX, &st.data)
}

pub fn encode_slash_params_state(p: &PosSlashParamsV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_SLASH_PARAMS, p)?))
}

pub fn decode_slash_params_state(st: &AccountState) -> Result<PosSlashParamsV1, String> {
    dec_record(TAG_SLASH_PARAMS, &st.data)
}

pub fn encode_evidence_marker_state(m: &EvidenceMarkerV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_EVIDENCE_MARKER, m)?))
}

pub fn decode_evidence_marker_state(st: &AccountState) -> Result<EvidenceMarkerV1, String> {
    dec_record(TAG_EVIDENCE_MARKER, &st.data)
}

// -------------------------------
// Typed stake calls
// -------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeCallV1 {
    Register {
        consensus_pubkey_b64: String,
        net_addr: String,
        commission_bps: u64,
        metadata: String,
    },
    Update {
        net_addr: Option<String>,
        commission_bps: Option<u64>,
        metadata: Option<String>,
    },
    RotateKey {
        new_pubkey_b64: String,
        proof_signed_by_old_b64: String,
    },
    Bond {
        validator_pk_b64: String,
        amount: u64,
    },
    Unbond {
        validator_pk_b64: String,
        amount: u64,
    },
    Withdraw {
        validator_pk_b64: String,
    },
    RandaoCommit {
        epoch: u64,
        commit_b64: String,
    },
    RandaoReveal {
        epoch: u64,
        secret_b64: String,
    },
    /// Evidence di double-vote per (epoch,height,round) con hash diversi.
    ///
    /// La TX è receiver=STAKE, amount=0, memo JSON v=1.
    EvidenceDoubleVote {
        epoch: u64,
        height: u64,
        round: u32,
        voter_pk_any: String,
        block_hash_a: String,
        sig_a_b64: String,
        block_hash_b: String,
        sig_b_b64: String,
    },
}
/// Parse memo JSON v=1 in una rappresentazione typed.
/// Ritorna Ok(None) se non è una stake tx.
pub fn parse_stake_call_v1(tx: &Transaction) -> Result<Option<StakeCallV1>, String> {
    if !is_stake_tx(tx) {
        return Ok(None);
    }
    // riusa il firewall sintattico esistente
    validate_stake_tx_syntax(tx)?;

    let memo = tx
        .memo
        .as_ref()
        .ok_or_else(|| "stake_tx_missing_memo".to_string())?;
    let v: Value =
        serde_json::from_str(memo).map_err(|e| format!("stake_tx_memo_not_json: {e}"))?;

    let op = get_str(&v, "op")?;
    let call = match op.as_str() {
        "register_validator" => {
            let cons = get_str(&v, "consensus_pubkey_b64")?;
            let net = get_str(&v, "net_addr")?;
            let comm = get_u64(&v, "commission_bps")?;
            let meta = v
                .get("metadata")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            StakeCallV1::Register {
                consensus_pubkey_b64: cons,
                net_addr: net,
                commission_bps: comm,
                metadata: meta,
            }
        }
        "update_validator" => {
            let net = v
                .get("net_addr")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let comm = v.get("commission_bps").and_then(|x| x.as_u64());
            let meta = v
                .get("metadata")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            StakeCallV1::Update {
                net_addr: net,
                commission_bps: comm,
                metadata: meta,
            }
        }
        "rotate_key" => {
            let new_pk = get_str(&v, "new_pubkey_b64")?;
            let proof = get_str(&v, "proof_signed_by_old")?;
            StakeCallV1::RotateKey {
                new_pubkey_b64: new_pk,
                proof_signed_by_old_b64: proof,
            }
        }
        "bond" => {
            let vp = get_str(&v, "validator_pk_b64")?;
            StakeCallV1::Bond {
                validator_pk_b64: vp,
                amount: tx.amount,
            }
        }
        "unbond" => {
            let vp = get_str(&v, "validator_pk_b64")?;
            StakeCallV1::Unbond {
                validator_pk_b64: vp,
                amount: tx.amount,
            }
        }
        "withdraw" => {
            let vp = get_str(&v, "validator_pk_b64")?;
            StakeCallV1::Withdraw {
                validator_pk_b64: vp,
            }
        }
        "randao_commit" => {
            let epoch = get_u64(&v, "epoch")?;
            let commit = get_str(&v, "commit_b64")?;
            StakeCallV1::RandaoCommit {
                epoch,
                commit_b64: commit,
            }
        }
        "randao_reveal" => {
            let epoch = get_u64(&v, "epoch")?;
            let secret = get_str(&v, "secret_b64")?;
            StakeCallV1::RandaoReveal {
                epoch,
                secret_b64: secret,
            }
        }
        "evidence_double_vote" => {
            let epoch = get_u64(&v, "epoch")?;
            let height = get_u64(&v, "height")?;
            let round_u64 = get_u64(&v, "round")?;
            let voter = get_str(&v, "voter_pk")?;
            let bh_a = get_str(&v, "block_hash_a")?;
            let bh_b = get_str(&v, "block_hash_b")?;
            let sig_a = get_str(&v, "sig_a_b64")?;
            let sig_b = get_str(&v, "sig_b_b64")?;
            if round_u64 > (u32::MAX as u64) {
                return Err("evidence_round_out_of_range".to_string());
            }
            StakeCallV1::EvidenceDoubleVote {
                epoch,
                height,
                round: round_u64 as u32,
                voter_pk_any: voter,
                block_hash_a: bh_a,
                sig_a_b64: sig_a,
                block_hash_b: bh_b,
                sig_b_b64: sig_b,
            }
        }

        _ => return Err(format!("unknown_stake_op: {op}")),
    };

    Ok(Some(call))
}

// -------------------------------
// Rotate proof verification
// -------------------------------

fn rotate_signing_bytes_v1(owner: &str, old_pk: &[u8; 32], new_pk: &[u8; 32]) -> Vec<u8> {
    // Domain separation + network_id (anti replay cross-chain) + owner binding.
    let mut msg = Vec::with_capacity(128);
    msg.extend_from_slice(b"NEWGEN_STAKE_ROTATE_V1|");
    msg.extend_from_slice(chain_identity::network_id().as_bytes());
    msg.extend_from_slice(b"|");
    msg.extend_from_slice(owner.trim().as_bytes());
    msg.extend_from_slice(b"|");
    msg.extend_from_slice(old_pk);
    msg.extend_from_slice(b"|");
    msg.extend_from_slice(new_pk);
    msg
}

/// Costruisce il messaggio canonico da firmare per `rotate_key` v1.
/// Utile per wallet/CLI e test. Il payload è consensus-critical.
pub fn rotate_message_v1(
    owner: &str,
    old_pk_any: &str,
    new_pk_any: &str,
) -> Result<Vec<u8>, String> {
    let old_pk = keyfmt::decode_pk_any(old_pk_any).map_err(|e| format!("old pk: {e}"))?;
    let new_pk = keyfmt::decode_pk_any(new_pk_any).map_err(|e| format!("new pk: {e}"))?;
    Ok(rotate_signing_bytes_v1(owner, &old_pk, &new_pk))
}

/// Verifica proof ed25519 (base64(64)) firmata dalla vecchia pubkey.
pub fn verify_rotate_proof_v1(
    owner: &str,
    old_pk_any: &str,
    new_pk_any: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let old_pk = keyfmt::decode_pk_any(old_pk_any).map_err(|e| format!("old pk: {e}"))?;
    let new_pk = keyfmt::decode_pk_any(new_pk_any).map_err(|e| format!("new pk: {e}"))?;
    let sig64 = keyfmt::decode_sig64_b64(signature_b64).map_err(|e| format!("sig: {e}"))?;

    let vk = VerifyingKey::from_bytes(&old_pk).map_err(|e| format!("invalid ed25519 pk: {e}"))?;
    let sig = Signature::from_bytes(&sig64);
    let msg = rotate_signing_bytes_v1(owner, &old_pk, &new_pk);

    vk.verify(&msg, &sig)
        .map_err(|_| "rotate_proof_invalid".to_string())
}

/// Canonical base64 (padded) per pks in memo.
pub fn canonical_pk_b64(pk_any: &str) -> Result<String, String> {
    let pk = keyfmt::decode_pk_any(pk_any).map_err(|e| format!("pk: {e}"))?;
    Ok(STANDARD.encode(pk))
}

// -------------------------------
// Phase 4 groundwork: slashing helper (consensus-critical state transition)
// -------------------------------

/// Applica slashing (riduzione bonded) e jail/tombstone su un validator record.
/// Ritorna (new_root, applied_slash_amount).
///
/// Nota: questa funzione modifica SOLO lo stato PoS (ValidatorRecordV1).
/// L'eventuale accounting economico (es. credit a treasury) è gestito altrove.
pub fn apply_slash_v1(
    smt: &StateSmt,
    root: [u8; 32],
    validator_pk_hex: &str,
    slash_amount: u64,
    jail_epochs: u64,
    current_epoch: u64,
    tombstone: bool,
) -> Result<([u8; 32], u64), String> {
    let pk_hex = validator_pk_hex.trim().to_ascii_lowercase();
    let key = k_validator(&pk_hex);

    let st = smt
        .get_account(root, key)
        .map_err(|e| format!("SMT get_account validator failed: {e}"))?
        .ok_or_else(|| "slash_validator_not_found".to_string())?;

    let mut rec = decode_validator_state(&st)?;

    // idempotent: se tombstoned non facciamo nulla
    if matches!(rec.status, ValidatorStatusV1::Tombstoned) {
        return Ok((root, 0));
    }

    let applied: u64 = slash_amount.min(rec.bonded);
    rec.bonded = rec.bonded.saturating_sub(applied);

    if tombstone {
        rec.status = ValidatorStatusV1::Tombstoned;
        rec.jailed_until_epoch = u64::MAX;
    } else if jail_epochs > 0 {
        rec.status = ValidatorStatusV1::Jailed;
        rec.jailed_until_epoch = current_epoch.saturating_add(jail_epochs);
    }

    let new_root = smt.update_account(root, key, encode_validator_state(&rec)?)?;
    Ok((new_root, applied))
}
