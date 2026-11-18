// src/pos.rs
//
// Phase 2 — Randomness + committee selection (anti-manipolazione)
// - RANDAO commit/reveal per epoca
// - seed(E) derivato da seed(E-1) + XOR(reveals(E)) + entropy_root
// - committee(E) selezionato stake-weighted dal registry usando seed(E)
//
// Consensus-critical: codec + key derivation + hashing devono rimanere invariati.

use crate::account::AccountState;
use crate::keyfmt;
use crate::state_smt::sys_key;
use bincode::Options;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub const POS_DATA_VERSION_V1: u8 = 1;

const TAG_SEED: u8 = 1;
const TAG_RANDAO_AGG: u8 = 2;
const TAG_RANDAO_COMMITTERS: u8 = 3;
const TAG_RANDAO_COMMIT: u8 = 4;
const TAG_RANDAO_REVEAL: u8 = 5;
const TAG_COMMITTEE: u8 = 6;
const TAG_COMMITTEE_V2: u8 = 7;

fn bincode_fixed_le() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

fn enc_record<T: Serialize>(tag: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.push(POS_DATA_VERSION_V1);
    out.push(tag);
    let payload = bincode_fixed_le()
        .serialize(v)
        .map_err(|e| format!("bincode serialize: {e}"))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

fn dec_record<T: for<'de> Deserialize<'de>>(tag: u8, data: &[u8]) -> Result<T, String> {
    if data.len() < 2 {
        return Err("pos_data_too_short".to_string());
    }
    if data[0] != POS_DATA_VERSION_V1 {
        return Err(format!("unsupported_pos_data_version: {}", data[0]));
    }
    if data[1] != tag {
        return Err(format!(
            "pos_data_tag_mismatch: expected={}, got={}",
            tag, data[1]
        ));
    }
    bincode_fixed_le()
        .deserialize(&data[2..])
        .map_err(|e| format!("bincode deserialize: {e}"))
}

fn as_state_from_data(data: Vec<u8>) -> AccountState {
    AccountState {
        nonce: 0,
        balance: 0,
        data,
    }
}

// -------------------------------
// On-chain records
// -------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SeedV1 {
    pub seed: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct RandaoAggV1 {
    pub xor: [u8; 32],
    pub reveals: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct CommittersV1 {
    pub pk_hex: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitV1 {
    pub commit: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevealV1 {
    pub secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeV1 {
    pub members_pk_hex: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeMemberV2 {
    pub pk_hex: String,
    pub stake: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeV2 {
    /// Deterministic order (consensus-critical).
    pub members: Vec<CommitteeMemberV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeAny {
    V1(CommitteeV1),
    V2(CommitteeV2),
}

impl CommitteeAny {
    /// Return committee members pubkeys as hex list, regardless of version.
    /// Non-consensus helper: used in tests and diagnostics.
    pub fn pk_hex_list(&self) -> Vec<String> {
        match self {
            CommitteeAny::V1(c) => c.members_pk_hex.clone(),
            CommitteeAny::V2(c) => c.members.iter().map(|m| m.pk_hex.clone()).collect(),
        }
    }
}
// -------------------------------
// SMT key derivation
// -------------------------------

pub fn k_seed(epoch: u64) -> [u8; 32] {
    sys_key(&format!("pos/seed/{}", epoch))
}

pub fn k_randao_agg(epoch: u64) -> [u8; 32] {
    sys_key(&format!("pos/randao/agg/{}", epoch))
}

pub fn k_randao_committers(epoch: u64) -> [u8; 32] {
    sys_key(&format!("pos/randao/committers/{}", epoch))
}

pub fn k_randao_commit(epoch: u64, validator_pk_hex: &str) -> [u8; 32] {
    sys_key(&format!(
        "pos/randao/commit/{}/{}",
        epoch,
        validator_pk_hex.trim()
    ))
}

pub fn k_randao_reveal(epoch: u64, validator_pk_hex: &str) -> [u8; 32] {
    sys_key(&format!(
        "pos/randao/reveal/{}/{}",
        epoch,
        validator_pk_hex.trim()
    ))
}

pub fn k_committee(epoch: u64) -> [u8; 32] {
    sys_key(&format!("pos/committee/{}", epoch))
}

// -------------------------------
// AccountState codecs
// -------------------------------

pub fn encode_seed_state(seed: &[u8; 32]) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(
        TAG_SEED,
        &SeedV1 { seed: *seed },
    )?))
}

pub fn decode_seed_state(st: &AccountState) -> Result<SeedV1, String> {
    dec_record(TAG_SEED, &st.data)
}

pub fn encode_randao_agg_state(x: &RandaoAggV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_RANDAO_AGG, x)?))
}

pub fn decode_randao_agg_state(st: &AccountState) -> Result<RandaoAggV1, String> {
    dec_record(TAG_RANDAO_AGG, &st.data)
}

pub fn encode_committers_state(x: &CommittersV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_RANDAO_COMMITTERS, x)?))
}

pub fn decode_committers_state(st: &AccountState) -> Result<CommittersV1, String> {
    dec_record(TAG_RANDAO_COMMITTERS, &st.data)
}

pub fn encode_commit_state(x: &CommitV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_RANDAO_COMMIT, x)?))
}

pub fn decode_commit_state(st: &AccountState) -> Result<CommitV1, String> {
    dec_record(TAG_RANDAO_COMMIT, &st.data)
}

pub fn encode_reveal_state(x: &RevealV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_RANDAO_REVEAL, x)?))
}

pub fn decode_reveal_state(st: &AccountState) -> Result<RevealV1, String> {
    dec_record(TAG_RANDAO_REVEAL, &st.data)
}

pub fn encode_committee_state(x: &CommitteeV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_COMMITTEE, x)?))
}

pub fn decode_committee_state(st: &AccountState) -> Result<CommitteeV1, String> {
    dec_record(TAG_COMMITTEE, &st.data)
}

/// Explicit V1 wrappers (used by Phase 3 activation gate code).
pub fn encode_committee_state_v1(x: &CommitteeV1) -> Result<AccountState, String> {
    encode_committee_state(x)
}

pub fn decode_committee_state_v1(st: &AccountState) -> Result<CommitteeV1, String> {
    decode_committee_state(st)
}

/// V2: committee stores stake snapshot (consensus-critical post-fork).
pub fn encode_committee_state_v2(x: &CommitteeV2) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(TAG_COMMITTEE_V2, x)?))
}

pub fn decode_committee_state_v2(st: &AccountState) -> Result<CommitteeV2, String> {
    dec_record(TAG_COMMITTEE_V2, &st.data)
}

/// Decode committee state supporting both V1 and V2 (tag-based).
pub fn decode_committee_state_any(st: &AccountState) -> Result<CommitteeAny, String> {
    if st.data.len() < 2 {
        return Err("pos_data_too_short".to_string());
    }
    if st.data[0] != POS_DATA_VERSION_V1 {
        return Err(format!("unsupported_pos_data_version: {}", st.data[0]));
    }
    match st.data[1] {
        TAG_COMMITTEE => Ok(CommitteeAny::V1(dec_record(TAG_COMMITTEE, &st.data)?)),
        TAG_COMMITTEE_V2 => Ok(CommitteeAny::V2(dec_record(TAG_COMMITTEE_V2, &st.data)?)),
        t => Err(format!("pos_data_tag_unknown: {}", t)),
    }
}

// -------------------------------
// Deterministic randomness helpers
// -------------------------------

pub fn seed0_from_network_id(network_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NEWGEN_POS_SEED0_V1|");
    h.update(network_id.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

pub fn commit_hash_v1(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

pub fn next_seed_v1(
    prev_seed: &[u8; 32],
    epoch: u64,
    xor_reveals: &[u8; 32],
    entropy_root: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NEWGEN_POS_SEED_V1|");
    h.update(epoch.to_le_bytes());
    h.update(prev_seed);
    h.update(xor_reveals);
    h.update(entropy_root);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

// -------------------------------
// Leader selection (Phase 2 completion)
// -------------------------------

fn u64_from_tag(seed: &[u8; 32], tag: &[u8], x: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(seed);
    h.update(x.to_le_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

/// Deterministic leader for a given slot, derived from (seed(epoch), slot, committee).
///
/// We use a seed-derived rotation offset + round-robin over committee:
///   offset = H("LEADER_OFF" || seed) mod N
///   leader = committee[(offset + (slot mod N)) mod N]
///
/// - stable across nodes
/// - avoids bias from per-slot re-sampling
/// - does NOT change consensus yet (Phase 3 will wire it into block production)
pub fn leader_for_slot_v1(
    seed_epoch: &[u8; 32],
    slot: u64,
    committee: &[String],
) -> Option<String> {
    if committee.is_empty() {
        return None;
    }
    let n = committee.len() as u64;

    // seed-derived rotation start (domain-separated)
    let off = u64_from_tag(seed_epoch, b"NEWGEN_POS_LEADER_OFF_V1|", 0) % n;

    // round-robin step (slot can be absolute; modulo is deterministic)
    let idx = (off + (slot % n)) % n;
    Some(committee[idx as usize].clone())
}

/// Phase 3A — Leader selection per (slot, round).
/// Round permette view-change deterministico senza cambiare il committee.
pub fn leader_for_slot_round_v1(
    seed_epoch: &[u8; 32],
    slot: u64,
    round: u32,
    committee: &[String],
) -> Option<String> {
    if committee.is_empty() {
        return None;
    }
    let n = committee.len() as u64;

    // seed-derived rotation start (domain-separated, MUST be stable consensus-wise)
    let off = u64_from_tag(seed_epoch, b"NEWGEN_POS_LEADER_OFF_V1|", 0) % n;

    // deterministic view-change: advance one position per round
    // Use modular arithmetic to avoid u64 overflow (debug != release otherwise).
    let idx = (off + (slot % n) + ((round as u64) % n)) % n;
    committee.get(idx as usize).cloned()
}

/// Phase 3A — Stake-weighted deterministic leader selection per (slot, round).
///
/// r = H("NEWGEN_POS_LEADER_WEIGHTED_V1|" || seed_epoch || slot || round)
/// x = r mod total_stake
/// pick first member where cumulative_stake > x
///
/// NOTE: uses u128 accumulation to avoid overflow and remain deterministic in debug/release.
pub fn leader_for_slot_round_weighted_v1(
    seed_epoch: &[u8; 32],
    slot: u64,
    round: u32,
    committee: &[CommitteeMemberV2],
) -> Option<String> {
    if committee.is_empty() {
        return None;
    }

    let mut total: u128 = 0;
    for m in committee.iter() {
        total = total.saturating_add(m.stake as u128);
    }
    if total == 0 {
        return None;
    }

    let mut h = Sha256::new();
    h.update(b"NEWGEN_POS_LEADER_WEIGHTED_V1|");
    h.update(seed_epoch);
    h.update(slot.to_le_bytes());
    h.update(round.to_le_bytes());
    let d = h.finalize();

    // Take first 16 bytes as little-endian u128 (deterministic).
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    let r = u128::from_le_bytes(b);

    let x = r % total;

    let mut cum: u128 = 0;
    for m in committee.iter() {
        cum = cum.saturating_add(m.stake as u128);
        if cum > x {
            return Some(m.pk_hex.clone());
        }
    }

    // Should not happen, but keep deterministic fallback.
    committee.last().map(|m| m.pk_hex.clone())
}

/// ----------------------------------------------------------
/// Phase 3A — Proposer proof (Ed25519) domain-separated
/// ----------------------------------------------------------
pub const DOMAIN_POS_PROOF_V1: &[u8] = b"newgen:pos_proof:v1\0";
pub const DOMAIN_POS_PROOF_V2: &[u8] = b"newgen:pos_proof:v2\0";

fn parse_hash32_hex_strict(s: &str) -> Result<[u8; 32], String> {
    let st = s.trim();
    if st.is_empty() || st == "0" {
        return Ok([0u8; 32]);
    }
    if st.len() != 64 {
        return Err("hash_not_32b_hex".to_string());
    }
    let v = hex::decode(st).map_err(|_| "hash_invalid_hex".to_string())?;
    if v.len() != 32 {
        return Err("hash_not_32b".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Message hash (32 bytes) firmato dal proposer per provare la sua elezione.
/// Include seed dell'epoch + (epoch, slot, round, height) + prev_hash + block_hash.
#[allow(clippy::too_many_arguments)]
pub fn proposer_proof_msg_hash_v1(
    chain_id: &str,
    seed_epoch: &[u8; 32],
    epoch: u64,
    slot: u64,
    round: u32,
    height: u64,
    prev_hash_hex: &str,
    block_hash_hex: &str,
) -> Result<[u8; 32], String> {
    let prev32 = parse_hash32_hex_strict(prev_hash_hex)?;
    let bh32 = parse_hash32_hex_strict(block_hash_hex)?;

    let mut h = Sha256::new();
    h.update(DOMAIN_POS_PROOF_V1);

    // chain_id length-prefixed
    let cid = chain_id.as_bytes();
    h.update((cid.len() as u32).to_le_bytes());
    h.update(cid);

    // seed + fields
    h.update(seed_epoch);
    h.update(epoch.to_le_bytes());
    h.update(slot.to_le_bytes());
    h.update(round.to_le_bytes());
    h.update(height.to_le_bytes());

    h.update(prev32);
    h.update(bh32);

    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    Ok(a)
}

/// Variante v2: include anche il digest del QC del parent (32 bytes), per impedire
/// "QC stripping / QC rewriting" senza cambiare l'hash del blocco.
///
/// msg32 = SHA256(DOMAIN_V2 || chain_id || seed_epoch || epoch || slot || round || height
///                || prev_hash32 || block_hash32 || qc_parent_digest32)
#[allow(clippy::too_many_arguments)]
pub fn proposer_proof_msg_hash_v2(
    chain_id: &str,
    seed_epoch: &[u8; 32],
    epoch: u64,
    slot: u64,
    round: u32,
    height: u64,
    prev_hash_hex: &str,
    block_hash_hex: &str,
    qc_parent_digest32: &[u8; 32],
) -> Result<[u8; 32], String> {
    let prev32 = parse_hash32_hex_strict(prev_hash_hex)?;
    let bh32 = parse_hash32_hex_strict(block_hash_hex)?;

    let mut h = Sha256::new();
    h.update(DOMAIN_POS_PROOF_V2);

    // chain_id length-prefixed
    let cid = chain_id.as_bytes();
    h.update((cid.len() as u32).to_le_bytes());
    h.update(cid);

    // seed + fields
    h.update(seed_epoch);
    h.update(epoch.to_le_bytes());
    h.update(slot.to_le_bytes());
    h.update(round.to_le_bytes());
    h.update(height.to_le_bytes());

    h.update(prev32);
    h.update(bh32);
    h.update(qc_parent_digest32);

    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    Ok(a)
}

/// Firma (64 bytes) del proposer sul message-hash.
/// Ritorna bytes raw (consensus-critical, compat con Block.signature).
pub fn sign_proposer_proof_v1(sk: &SigningKey, msg32: &[u8; 32]) -> [u8; 64] {
    let sig = sk.sign(msg32);
    sig.to_bytes()
}

/// Verifica proof (signature over msg32).
pub fn verify_proposer_proof_v1(
    miner_pub_key_any: &str,
    msg32: &[u8; 32],
    sig_bytes: &[u8],
) -> bool {
    if sig_bytes.len() != 64 {
        return false;
    }
    let pk = match keyfmt::decode_pk_any(miner_pub_key_any) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(msg32, &sig).is_ok()
}

// -------------------------------
// Committee selection (stake-weighted, without replacement)
// -------------------------------

fn u64_from_seed(seed: &[u8; 32], counter: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(b"NEWGEN_POS_RNG_V1|");
    h.update(seed);
    h.update(counter.to_le_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

/// Deterministic stake-weighted sampling without replacement.
/// Input candidates: (pk_hex, weight). Weight=0 candidates ignored.
///
/// Nota: complessità O(k*N) ma sufficiente per gate (N~1000, k~64..256).
pub fn select_committee_v1(
    seed: &[u8; 32],
    candidates: &[(String, u64)],
    committee_size: usize,
) -> Vec<String> {
    if committee_size == 0 {
        return vec![];
    }

    let mut pool: Vec<(String, u64)> = candidates.iter().filter(|(_, w)| *w > 0).cloned().collect();

    if pool.is_empty() {
        return vec![];
    }

    if committee_size >= pool.len() {
        return pool.into_iter().map(|(pk, _)| pk).collect();
    }

    let mut out: Vec<String> = Vec::with_capacity(committee_size);

    let mut total_weight: u128 = pool.iter().map(|(_, w)| *w as u128).sum();

    for i in 0..committee_size {
        if total_weight == 0 || pool.is_empty() {
            break;
        }

        let r = (u64_from_seed(seed, i as u64) as u128) % total_weight;

        let mut acc: u128 = 0;
        let mut chosen_idx: usize = 0;

        for (idx, (_, w)) in pool.iter().enumerate() {
            acc = acc.saturating_add(*w as u128);
            if r < acc {
                chosen_idx = idx;
                break;
            }
        }

        let (pk, w) = pool.remove(chosen_idx);
        out.push(pk);
        total_weight = total_weight.saturating_sub(w as u128);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_is_deterministic_and_unique() {
        let seed = [7u8; 32];
        let cands: Vec<(String, u64)> = vec![
            ("aa".to_string(), 10),
            ("bb".to_string(), 20),
            ("cc".to_string(), 30),
            ("dd".to_string(), 40),
        ];

        let a = select_committee_v1(&seed, &cands, 3);
        let b = select_committee_v1(&seed, &cands, 3);

        assert_eq!(a, b);

        let mut s = std::collections::BTreeSet::new();
        for x in &a {
            assert!(s.insert(x.clone()), "duplicate member");
        }
    }
    #[test]
    fn leader_is_deterministic_and_rotates() {
        let seed = [9u8; 32];
        let committee: Vec<String> = vec![
            "aa".to_string(),
            "bb".to_string(),
            "cc".to_string(),
            "dd".to_string(),
            "ee".to_string(),
        ];

        let l1 = leader_for_slot_v1(&seed, 12345, &committee).unwrap();
        let l2 = leader_for_slot_v1(&seed, 12345, &committee).unwrap();
        assert_eq!(l1, l2, "leader must be deterministic");

        // first N slots should produce a permutation (round-robin w/ offset)
        let n = committee.len() as u64;
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..n {
            let l = leader_for_slot_v1(&seed, s, &committee).unwrap();
            assert!(seen.insert(l), "duplicate leader within first N slots");
        }
        assert_eq!(seen.len(), committee.len());
        // round=0 must match the legacy leader_for_slot_v1 (compat requirement)
        let lr0 = leader_for_slot_round_v1(&seed, 12345, 0, &committee).unwrap();
        assert_eq!(lr0, l1, "round=0 must match leader_for_slot_v1");

        // for a fixed slot, varying round should rotate deterministically through committee
        let mut seen_r = std::collections::BTreeSet::new();
        for r in 0..(committee.len() as u32) {
            let l = leader_for_slot_round_v1(&seed, 42, r, &committee).unwrap();
            assert!(seen_r.insert(l), "duplicate leader within first N rounds");
        }
        assert_eq!(seen_r.len(), committee.len());
    }

    #[test]
    fn proposer_proof_signs_and_verifies() {
        let seed = [2u8; 32];
        let chain_id = "test-chain";
        let epoch = 3u64;
        let slot = 42u64;
        let round = 1u32;
        let height = 123u64;

        let prev_hash = "0";
        let block_hash = "11".repeat(32);

        let msg32 = proposer_proof_msg_hash_v1(
            chain_id,
            &seed,
            epoch,
            slot,
            round,
            height,
            prev_hash,
            &block_hash,
        )
        .expect("msg32");

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());

        let sig64 = sign_proposer_proof_v1(&sk, &msg32);
        assert!(verify_proposer_proof_v1(&pk_hex, &msg32, &sig64));
    }

    #[test]
    fn leader_changes_with_round() {
        let seed = [9u8; 32];
        let committee: Vec<String> = vec![
            "aa".to_string(),
            "bb".to_string(),
            "cc".to_string(),
            "dd".to_string(),
        ];

        let l0 = leader_for_slot_round_v1(&seed, 10, 0, &committee).unwrap();
        let l1 = leader_for_slot_round_v1(&seed, 10, 1, &committee).unwrap();
        assert_ne!(l0, l1, "round should change leader deterministically");
    }
}
