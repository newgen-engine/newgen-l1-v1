// src/finality_bft.rs
//
// Phase 3B — Finality Gadget (BFT su committee) con certificati compatti (no BLS).
//
// Questo modulo è consensus-critical per:
// - Domain separation
// - Hashing deterministico dei vote
// - Formato QC compatto: bitset + firme Ed25519 in ordine deterministico
//
// In questa consegna "intermedia" forniamo:
// - tipi Vote / Cert
// - funzioni sign/verify per vote
// - builder/verify per QC (certificato)
// L'integrazione runtime (P2P gossip, pool persistente, inclusione nel blocco
// successivo, validazione chain) verrà aggiunta nel completamento dello Step 3B.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keyfmt;

pub const DOMAIN_FINALITY_VOTE_V1: &[u8] = b"newgen:finality_vote:v1\0";

pub const DOMAIN_FINALITY_QC_DIGEST_V1: &[u8] = b"newgen:finality_qc_digest:v1\0";

/// Digest canonico (32 bytes) di un QC.
/// Usato per "bindare" il QC dentro la proposer proof (Phase 3B) senza cambiare l'hash del blocco.
///
/// digest = SHA256( DOMAIN || len(chain_id) || chain_id || epoch || height || round || block_hash32
///                  || len(bitset) || bitset_bytes || sig_count || sig64* )
pub fn qc_digest32_v1(chain_id: &str, cert: &FinalityBftCertV1) -> Result<[u8; 32], String> {
    let bh32 = parse_hash32_hex_strict(&cert.block_hash)?;
    let mut h = Sha256::new();
    h.update(DOMAIN_FINALITY_QC_DIGEST_V1);

    let cid = chain_id.as_bytes();
    h.update((cid.len() as u32).to_le_bytes());
    h.update(cid);

    h.update(cert.epoch.to_le_bytes());
    h.update(cert.height.to_le_bytes());
    h.update(cert.round.to_le_bytes());
    h.update(bh32);

    h.update((cert.voter_bitset.len() as u32).to_le_bytes());
    h.update(&cert.voter_bitset);

    h.update((cert.sigs_b64.len() as u32).to_le_bytes());
    for s in &cert.sigs_b64 {
        let sig64 = keyfmt::decode_sig64_b64(s).map_err(|e| format!("sig decode: {e}"))?;
        h.update(sig64);
    }

    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

/// QC digest helper: None => [0;32] (deterministico).
pub fn qc_digest32_opt_v1(
    chain_id: &str,
    cert_opt: Option<&FinalityBftCertV1>,
) -> Result<[u8; 32], String> {
    match cert_opt {
        Some(c) => qc_digest32_v1(chain_id, c),
        None => Ok([0u8; 32]),
    }
}

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

/// Hash (32 bytes) del messaggio di voto.
///
/// msg = SHA256( DOMAIN || len(chain_id) || chain_id || epoch || height || round || block_hash_32 )
pub fn vote_msg_hash_v1(
    chain_id: &str,
    epoch: u64,
    height: u64,
    round: u32,
    block_hash_hex: &str,
) -> Result<[u8; 32], String> {
    let bh32 = parse_hash32_hex_strict(block_hash_hex)?;

    let mut h = Sha256::new();
    h.update(DOMAIN_FINALITY_VOTE_V1);

    let cid = chain_id.as_bytes();
    h.update((cid.len() as u32).to_le_bytes());
    h.update(cid);

    h.update(epoch.to_le_bytes());
    h.update(height.to_le_bytes());
    h.update(round.to_le_bytes());
    h.update(bh32);

    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FinalityBftVoteV1 {
    pub epoch: u64,
    pub height: u64,
    pub round: u32,
    pub block_hash: String,
    /// Pubkey del voter (ed25519) in HEX (64 chars, lowercase preferred).
    pub voter_pk_hex: String,
    /// Signature Ed25519 su vote_msg_hash_v1(...) codificata base64(64 bytes).
    pub sig_b64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FinalityBftCertV1 {
    pub epoch: u64,
    pub height: u64,
    pub round: u32,
    pub block_hash: String,
    /// Bitset in ordine committee-index (LSB-first).
    pub voter_bitset: Vec<u8>,
    /// Array firme base64, in ordine crescente degli indici settati nel bitset.
    pub sigs_b64: Vec<String>,
}

/// Helper: bitset len (bytes) per committee size n.
pub fn bitset_len_for_committee(n: usize) -> usize {
    n.div_ceil(8)
}

pub fn bitset_test(bitset: &[u8], idx: usize) -> bool {
    let byte = idx / 8;
    let bit = idx % 8;
    if byte >= bitset.len() {
        return false;
    }
    (bitset[byte] & (1u8 << bit)) != 0
}

pub fn bitset_set(bitset: &mut [u8], idx: usize) {
    let byte = idx / 8;
    let bit = idx % 8;
    if byte < bitset.len() {
        bitset[byte] |= 1u8 << bit;
    }
}

pub fn bitset_popcount(bitset: &[u8]) -> usize {
    bitset.iter().map(|b| b.count_ones() as usize).sum()
}

pub fn bitset_indices(bitset: &[u8], n: usize) -> Vec<usize> {
    let mut out = Vec::new();
    for i in 0..n {
        if bitset_test(bitset, i) {
            out.push(i);
        }
    }
    out
}

fn verifying_key_from_pk_any(pk: &str) -> Result<VerifyingKey, String> {
    let pk_bytes = keyfmt::decode_pk_any(pk).map_err(|e| format!("pk decode: {e}"))?;
    VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("verifying_key: {e}"))
}

/// Sign a vote with an already-decoded ed25519 secret key.
/// The returned vote includes voter_pk_hex derived from the signing key.
pub fn sign_vote_v1(
    sk: &SigningKey,
    chain_id: &str,
    epoch: u64,
    height: u64,
    round: u32,
    block_hash_hex: &str,
) -> Result<FinalityBftVoteV1, String> {
    let msg = vote_msg_hash_v1(chain_id, epoch, height, round, block_hash_hex)?;
    let sig = sk.sign(&msg);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    Ok(FinalityBftVoteV1 {
        epoch,
        height,
        round,
        block_hash: block_hash_hex.trim().to_string(),
        voter_pk_hex: pk_hex,
        sig_b64: STANDARD.encode(sig.to_bytes()),
    })
}

pub fn verify_vote_sig_v1(vote: &FinalityBftVoteV1, chain_id: &str) -> Result<(), String> {
    let vk = verifying_key_from_pk_any(&vote.voter_pk_hex)?;
    let sig_arr =
        keyfmt::decode_sig64_b64(&vote.sig_b64).map_err(|e| format!("sig decode: {e}"))?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = vote_msg_hash_v1(
        chain_id,
        vote.epoch,
        vote.height,
        vote.round,
        &vote.block_hash,
    )?;
    vk.verify_strict(&msg, &sig)
        .map_err(|_| "vote_sig_invalid".to_string())
}

/// Build a compact QC (certificate) from a list of votes.
/// Votes MUST refer to the same (epoch,height,round,block_hash).
///
/// Ordering:
/// - committee_pk_hex defines deterministic committee order
/// - bitset uses committee indices
/// - sigs_b64 is ordered by increasing index of set bits
pub fn build_cert_v1(
    chain_id: &str,
    epoch: u64,
    height: u64,
    round: u32,
    block_hash_hex: &str,
    committee_pk_hex: &[String],
    votes: &[FinalityBftVoteV1],
) -> Result<FinalityBftCertV1, String> {
    if committee_pk_hex.is_empty() {
        return Err("empty_committee".to_string());
    }

    use std::collections::HashMap;
    let mut sig_map: HashMap<String, String> = HashMap::new();

    for v in votes {
        if v.epoch != epoch
            || v.height != height
            || v.round != round
            || v.block_hash.trim() != block_hash_hex.trim()
        {
            continue;
        }
        if verify_vote_sig_v1(v, chain_id).is_err() {
            continue;
        }
        sig_map
            .entry(v.voter_pk_hex.trim().to_string())
            .or_insert_with(|| v.sig_b64.trim().to_string());
    }

    let n = committee_pk_hex.len();
    let mut bitset = vec![0u8; bitset_len_for_committee(n)];
    let mut sigs: Vec<String> = Vec::new();

    for (i, pk) in committee_pk_hex.iter().enumerate() {
        if let Some(sig_b64) = sig_map.get(pk.trim()) {
            bitset_set(&mut bitset, i);
            sigs.push(sig_b64.clone());
        }
    }

    Ok(FinalityBftCertV1 {
        epoch,
        height,
        round,
        block_hash: block_hash_hex.trim().to_string(),
        voter_bitset: bitset,
        sigs_b64: sigs,
    })
}

/// Verify a compact QC and return (signed_stake, total_stake).
///
/// Requirements checked:
/// - voter_bitset length is correct for committee
/// - sigs_b64.len() == popcount(bitset)
/// - every signature verifies against its corresponding committee pubkey
pub fn verify_cert_v1(
    cert: &FinalityBftCertV1,
    chain_id: &str,
    committee_pk_hex: &[String],
    committee_stakes: &[u64],
) -> Result<(u64, u64), String> {
    let n = committee_pk_hex.len();
    if n == 0 {
        return Err("empty_committee".to_string());
    }
    if committee_stakes.len() != n {
        return Err("committee_stakes_len_mismatch".to_string());
    }
    if cert.voter_bitset.len() != bitset_len_for_committee(n) {
        return Err("bitset_len_mismatch".to_string());
    }
    let want = bitset_popcount(&cert.voter_bitset);
    if cert.sigs_b64.len() != want {
        return Err("sigs_len_mismatch".to_string());
    }

    let msg = vote_msg_hash_v1(
        chain_id,
        cert.epoch,
        cert.height,
        cert.round,
        &cert.block_hash,
    )?;

    let mut signed_stake: u64 = 0;
    let mut total_stake: u64 = 0;
    for st in committee_stakes {
        total_stake = total_stake.saturating_add(*st);
    }

    for (sig_i, idx) in bitset_indices(&cert.voter_bitset, n)
        .into_iter()
        .enumerate()
    {
        let pk = &committee_pk_hex[idx];
        let vk = verifying_key_from_pk_any(pk)?;

        let sig_arr = keyfmt::decode_sig64_b64(&cert.sigs_b64[sig_i])
            .map_err(|e| format!("sig decode: {e}"))?;
        let sig = Signature::from_bytes(&sig_arr);

        vk.verify_strict(&msg, &sig)
            .map_err(|_| format!("qc_sig_invalid_at_idx={}", idx))?;

        signed_stake = signed_stake.saturating_add(committee_stakes[idx]);
    }

    Ok((signed_stake, total_stake))
}

/// Check stake-quorum >= 2/3.
pub fn meets_quorum_2of3(signed_stake: u64, total_stake: u64) -> bool {
    signed_stake.saturating_mul(3) >= total_stake.saturating_mul(2)
}

/// ceil(2/3 * total_stake)
pub fn quorum_2of3_ceil(total_stake: u64) -> u64 {
    // ceil(2*total/3) = (2*total + 2)/3
    (total_stake.saturating_mul(2).saturating_add(2)) / 3
}

/// Alias: quorum stake = ceil(2/3 * total_stake)
pub fn stake_quorum_2f3(total_stake: u64) -> u64 {
    quorum_2of3_ceil(total_stake)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sk_from_u8(v: u8) -> SigningKey {
        let mut a = [0u8; 32];
        a.fill(v);
        SigningKey::from_bytes(&a)
    }

    #[test]
    fn vote_sign_and_verify_roundtrip() {
        let sk = sk_from_u8(7);
        let chain_id = "newgen-test";
        let bh = "11".repeat(32);
        let vote = sign_vote_v1(&sk, chain_id, 1, 100, 0, &bh).unwrap();
        verify_vote_sig_v1(&vote, chain_id).unwrap();
    }

    #[test]
    fn cert_build_and_verify_simple() {
        let chain_id = "newgen-test";
        let bh = "22".repeat(32);

        let sk1 = sk_from_u8(1);
        let sk2 = sk_from_u8(2);
        let pk1 = hex::encode(sk1.verifying_key().to_bytes());
        let pk2 = hex::encode(sk2.verifying_key().to_bytes());

        let committee = vec![pk1.clone(), pk2.clone()];
        let stakes = vec![100u64, 100u64];

        let v1 = sign_vote_v1(&sk1, chain_id, 1, 10, 0, &bh).unwrap();
        let v2 = sign_vote_v1(&sk2, chain_id, 1, 10, 0, &bh).unwrap();

        let cert = build_cert_v1(chain_id, 1, 10, 0, &bh, &committee, &[v1, v2]).unwrap();
        let (signed, total) = verify_cert_v1(&cert, chain_id, &committee, &stakes).unwrap();

        assert_eq!(signed, 200);
        assert_eq!(total, 200);
        assert!(meets_quorum_2of3(signed, total));
    }

    #[test]
    fn quorum_edge_cases() {
        // Exactly 2/3 should pass.
        assert!(meets_quorum_2of3(200, 300));
        // Just below 2/3 should fail.
        assert!(!meets_quorum_2of3(199, 300));

        // Small totals.
        assert!(meets_quorum_2of3(2, 3));
        assert!(!meets_quorum_2of3(1, 3));

        // Saturation safety: total=0 => treat as quorum by formula.
        // total_stake=0 should never occur for an active committee.
        assert!(meets_quorum_2of3(0, 0));
    }

    #[test]
    fn cert_sig_order_is_committee_index_order() {
        let chain_id = "newgen-test";
        let bh = "33".repeat(32);

        // Committee of 4 validators.
        let sk0 = sk_from_u8(10);
        let sk1 = sk_from_u8(11);
        let sk2 = sk_from_u8(12);
        let sk3 = sk_from_u8(13);

        let pk0 = hex::encode(sk0.verifying_key().to_bytes());
        let pk1 = hex::encode(sk1.verifying_key().to_bytes());
        let pk2 = hex::encode(sk2.verifying_key().to_bytes());
        let pk3 = hex::encode(sk3.verifying_key().to_bytes());

        let committee = vec![pk0.clone(), pk1.clone(), pk2.clone(), pk3.clone()];
        let stakes = vec![1u64, 1u64, 1u64, 1u64];

        // Provide votes intentionally out-of-order and with duplicates.
        let v2 = sign_vote_v1(&sk2, chain_id, 7, 77, 0, &bh).unwrap();
        let v0 = sign_vote_v1(&sk0, chain_id, 7, 77, 0, &bh).unwrap();
        let v2_dup = sign_vote_v1(&sk2, chain_id, 7, 77, 0, &bh).unwrap();

        let cert = build_cert_v1(
            chain_id,
            7,
            77,
            0,
            &bh,
            &committee,
            &[v2.clone(), v0.clone(), v2_dup],
        )
        .unwrap();

        // Expect bitset indices {0,2} and signatures ordered by idx => sig(pk0) then sig(pk2).
        assert_eq!(bitset_popcount(&cert.voter_bitset), 2);
        assert!(bitset_test(&cert.voter_bitset, 0));
        assert!(!bitset_test(&cert.voter_bitset, 1));
        assert!(bitset_test(&cert.voter_bitset, 2));
        assert!(!bitset_test(&cert.voter_bitset, 3));

        // Verify also validates and computes signed stake = 2.
        let (signed, total) = verify_cert_v1(&cert, chain_id, &committee, &stakes).unwrap();
        assert_eq!(signed, 2);
        assert_eq!(total, 4);

        // Signature order invariant (by committee idx): sig[0] must be v0 signature, sig[1] must be v2 signature.
        assert_eq!(cert.sigs_b64.len(), 2);
        assert_eq!(cert.sigs_b64[0], v0.sig_b64);
        assert_eq!(cert.sigs_b64[1], v2.sig_b64);
    }

    #[test]
    fn netmsg_encode_decode_preserves_qc_exactly() {
        use crate::netmsg::{decode, encode, NetMsg};

        let chain_id = "newgen-test";
        let bh = "44".repeat(32);

        let sk0 = sk_from_u8(20);
        let sk2 = sk_from_u8(22);

        let pk0 = hex::encode(sk0.verifying_key().to_bytes());
        let pk1 = "00".repeat(32); // dummy (not used)
        let pk2 = hex::encode(sk2.verifying_key().to_bytes());
        let pk3 = "ff".repeat(32); // dummy (not used)

        let committee = vec![pk0.clone(), pk1, pk2.clone(), pk3];
        let stakes = vec![1u64, 1u64, 1u64, 1u64];

        let v0 = sign_vote_v1(&sk0, chain_id, 9, 99, 0, &bh).unwrap();
        let v2 = sign_vote_v1(&sk2, chain_id, 9, 99, 0, &bh).unwrap();

        let cert = build_cert_v1(chain_id, 9, 99, 0, &bh, &committee, &[v2, v0]).unwrap();
        // sanity verify
        let (signed, total) = verify_cert_v1(&cert, chain_id, &committee, &stakes).unwrap();
        assert!(
            !meets_quorum_2of3(signed, total),
            "2/4 stake should not meet 2/3"
        );

        let msg = NetMsg::FinalityBftCert(cert.clone());
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("decode must succeed");

        match decoded {
            NetMsg::FinalityBftCert(c2) => assert_eq!(c2, cert),
            _ => panic!("expected FinalityBftCert"),
        }
    }

    #[test]
    fn partition_sim_2_of_4_no_quorum_3_of_4_quorum() {
        let chain_id = "newgen-test";
        let bh = "55".repeat(32);

        let sk0 = sk_from_u8(30);
        let sk1 = sk_from_u8(31);
        let sk2 = sk_from_u8(32);
        let sk3 = sk_from_u8(33);

        let pk0 = hex::encode(sk0.verifying_key().to_bytes());
        let pk1 = hex::encode(sk1.verifying_key().to_bytes());
        let pk2 = hex::encode(sk2.verifying_key().to_bytes());
        let pk3 = hex::encode(sk3.verifying_key().to_bytes());

        let committee = vec![pk0.clone(), pk1.clone(), pk2.clone(), pk3.clone()];
        let stakes = vec![1u64, 1u64, 1u64, 1u64];

        // Partition 2-of-4: should fail quorum.
        let v0 = sign_vote_v1(&sk0, chain_id, 1, 10, 0, &bh).unwrap();
        let v1 = sign_vote_v1(&sk1, chain_id, 1, 10, 0, &bh).unwrap();
        let cert2 = build_cert_v1(chain_id, 1, 10, 0, &bh, &committee, &[v0, v1]).unwrap();
        let (signed2, total2) = verify_cert_v1(&cert2, chain_id, &committee, &stakes).unwrap();
        assert_eq!(signed2, 2);
        assert_eq!(total2, 4);
        assert!(!meets_quorum_2of3(signed2, total2));

        // Partition 3-of-4: should meet quorum.
        let v0 = sign_vote_v1(&sk0, chain_id, 1, 11, 0, &bh).unwrap();
        let v1 = sign_vote_v1(&sk1, chain_id, 1, 11, 0, &bh).unwrap();
        let v2 = sign_vote_v1(&sk2, chain_id, 1, 11, 0, &bh).unwrap();
        let cert3 = build_cert_v1(chain_id, 1, 11, 0, &bh, &committee, &[v2, v1, v0]).unwrap();
        let (signed3, total3) = verify_cert_v1(&cert3, chain_id, &committee, &stakes).unwrap();
        assert_eq!(signed3, 3);
        assert_eq!(total3, 4);
        assert!(meets_quorum_2of3(signed3, total3));
    }
}
