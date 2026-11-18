use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::cognitive_chain::{
    validate_non_empty_no_separator, validate_sha256_hex_field, CognitiveAttestationCertV1,
    CognitiveAttestationEnvelopeV1, CognitiveAttestationSigV1, CognitiveTxAnchorV1,
    CognitiveTxDisputeV1, CognitiveTxKindV1, CognitiveTxRevokeV1, CognitiveTxSupersedeV1,
    CognitiveTxV1,
};
use crate::governance::{GovProposalKind, GovernanceTx};
use crate::transaction::Transaction;

pub const DOMAIN_HEADER_V1: &[u8] = b"newgen:header:v1\0";
pub const DOMAIN_GOVTX_V1: &[u8] = b"newgen:govtx:v1\0";
pub const DOMAIN_COGTX_V1: &[u8] = b"newgen:cogtx:v1\0";
pub const DOMAIN_TX_V1: &[u8] = b"newgen:txleaf:v1\0";

#[inline]
fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

#[inline]
fn put_gov_kind(out: &mut Vec<u8>, kind: &GovProposalKind) {
    // Tag stabili (mainnet-grade): NON dipendono da `Debug`.
    // Importante: i valori attuali sono identici ai nomi delle varianti, quindi
    // questa modifica NON cambia l'encoding rispetto al passato, ma elimina il rischio
    // di rottura accidentale se in futuro cambia la rappresentazione `Debug`.
    let tag = match kind {
        GovProposalKind::UpdateValidators => "UpdateValidators",
        GovProposalKind::UpdateEconomyPolicy => "UpdateEconomyPolicy",
        GovProposalKind::UpdateSecurityPolicy => "UpdateSecurityPolicy",
        GovProposalKind::BumpProtocolVersion => "BumpProtocolVersion",
        GovProposalKind::EmergencySafeModeOn => "EmergencySafeModeOn",
        GovProposalKind::EmergencySafeModeOff => "EmergencySafeModeOff",
        GovProposalKind::UpdateGovernanceParams => "UpdateGovernanceParams",
        GovProposalKind::UpdateReputationPolicy => "UpdateReputationPolicy",
        GovProposalKind::UpdateMempoolPolicy => "UpdateMempoolPolicy",
        GovProposalKind::RotateValidatorKey => "RotateValidatorKey",
        GovProposalKind::RevokeValidator => "RevokeValidator",
        GovProposalKind::UnrevokeValidator => "UnrevokeValidator",
        GovProposalKind::RequestValidatorComputeTransition => "RequestValidatorComputeTransition",
        GovProposalKind::CancelValidatorComputeTransition => "CancelValidatorComputeTransition",
        GovProposalKind::IngestWalletReputationEvidence => "IngestWalletReputationEvidence",
        GovProposalKind::IngestE2WorkerReputationEvidence => "IngestE2WorkerReputationEvidence",
        GovProposalKind::BindE2WorkerOperatorWallet => "BindE2WorkerOperatorWallet",
        GovProposalKind::GrantE2WorkerCloudUnit => "GrantE2WorkerCloudUnit",
        GovProposalKind::RevokeE2WorkerCloudUnit => "RevokeE2WorkerCloudUnit",
        GovProposalKind::GrantE2WorkerGpuCapability => "GrantE2WorkerGpuCapability",
        GovProposalKind::RevokeE2WorkerGpuCapability => "RevokeE2WorkerGpuCapability",
        GovProposalKind::GrantE2WorkerCriticalWorkload => "GrantE2WorkerCriticalWorkload",
        GovProposalKind::RevokeE2WorkerCriticalWorkload => "RevokeE2WorkerCriticalWorkload",
        GovProposalKind::IngestComputeFiatSettlementProof => "IngestComputeFiatSettlementProof",
    };
    put_str(out, tag);
}

#[inline]
fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

#[inline]
fn put_hex32_required(out: &mut Vec<u8>, field_name: &str, s: &str) {
    validate_sha256_hex_field(field_name, s).unwrap_or_else(|e| panic!("{}", e));
    let raw = hex::decode(s).unwrap_or_else(|e| panic!("{} decode failed: {}", field_name, e));
    debug_assert_eq!(raw.len(), 32);
    out.extend_from_slice(&raw);
}

#[inline]
fn put_b64_fixed_required(out: &mut Vec<u8>, field_name: &str, s: &str, expected_len: usize) {
    let raw = B64
        .decode(s)
        .unwrap_or_else(|e| panic!("{} base64 decode failed: {}", field_name, e));
    if raw.len() != expected_len {
        panic!(
            "{} invalid length: got {} expected {}",
            field_name,
            raw.len(),
            expected_len
        );
    }
    out.extend_from_slice(&raw);
}

#[inline]
fn put_cog_kind(out: &mut Vec<u8>, kind: CognitiveTxKindV1) {
    let tag = match kind {
        CognitiveTxKindV1::Anchor => 1u8,
        CognitiveTxKindV1::Dispute => 2u8,
        CognitiveTxKindV1::Revoke => 3u8,
        CognitiveTxKindV1::Supersede => 4u8,
    };
    put_u8(out, tag);
}

fn encode_cognitive_envelope_v1(out: &mut Vec<u8>, env: &CognitiveAttestationEnvelopeV1) {
    env.validate()
        .unwrap_or_else(|e| panic!("invalid cognitive envelope: {}", e));
    put_str(out, &env.chain_id);
    put_hex32_required(out, "genesis_hash", &env.genesis_hash);
    put_hex32_required(out, "object_hash_hex", &env.object_hash_hex);
    put_hex32_required(out, "claim_hash_hex", &env.claim_hash_hex);
    put_hex32_required(out, "evidence_root_hex", &env.evidence_root_hex);
    put_hex32_required(out, "context_hash_hex", &env.context_hash_hex);
    put_str(out, &env.policy_id);
    put_hex32_required(out, "model_manifest_hash_hex", &env.model_manifest_hash_hex);
    put_u64(out, env.created_at_height);
    put_u64(out, env.created_at_ts);
}

fn encode_cognitive_cert_v1(out: &mut Vec<u8>, cert: &CognitiveAttestationCertV1) {
    if cert.sigs.is_empty() {
        panic!("cognitive attestation cert must contain at least one signature");
    }
    encode_cognitive_envelope_v1(out, &cert.envelope);
    put_u32(out, cert.sigs.len() as u32);

    let mut prev_signer: Option<&str> = None;
    let mut seen = std::collections::HashSet::new();
    for sig in &cert.sigs {
        encode_cognitive_sig_v1(out, sig);
        if let Some(prev) = prev_signer {
            if sig.signer_public_key_b64.as_str() < prev {
                panic!("cognitive attestation cert signatures are not sorted canonically");
            }
        }
        prev_signer = Some(sig.signer_public_key_b64.as_str());
        if !seen.insert(sig.signer_public_key_b64.as_str()) {
            panic!("duplicate signer in cognitive attestation cert");
        }
    }
}

fn encode_cognitive_sig_v1(out: &mut Vec<u8>, sig: &CognitiveAttestationSigV1) {
    sig.validate_format()
        .unwrap_or_else(|e| panic!("invalid cognitive attestation signature: {}", e));
    put_b64_fixed_required(out, "signer_public_key_b64", &sig.signer_public_key_b64, 32);
    put_b64_fixed_required(out, "signature_b64", &sig.signature_b64, 64);
}

fn encode_cognitive_anchor_v1(out: &mut Vec<u8>, v: &CognitiveTxAnchorV1) {
    encode_cognitive_cert_v1(out, &v.attestation_cert);
}

fn encode_cognitive_dispute_v1(out: &mut Vec<u8>, v: &CognitiveTxDisputeV1) {
    validate_sha256_hex_field("target_object_hash_hex", &v.target_object_hash_hex)
        .unwrap_or_else(|e| panic!("{}", e));
    validate_non_empty_no_separator("reason_code", &v.reason_code)
        .unwrap_or_else(|e| panic!("{}", e));
    validate_sha256_hex_field("dispute_evidence_root_hex", &v.dispute_evidence_root_hex)
        .unwrap_or_else(|e| panic!("{}", e));
    put_hex32_required(out, "target_object_hash_hex", &v.target_object_hash_hex);
    put_str(out, &v.reason_code);
    put_hex32_required(
        out,
        "dispute_evidence_root_hex",
        &v.dispute_evidence_root_hex,
    );
    put_b64_fixed_required(
        out,
        "submitter_public_key_b64",
        &v.submitter_public_key_b64,
        32,
    );
    put_b64_fixed_required(out, "signature_b64", &v.signature_b64, 64);
}

fn encode_cognitive_revoke_v1(out: &mut Vec<u8>, v: &CognitiveTxRevokeV1) {
    validate_sha256_hex_field("target_object_hash_hex", &v.target_object_hash_hex)
        .unwrap_or_else(|e| panic!("{}", e));
    validate_non_empty_no_separator("reason_code", &v.reason_code)
        .unwrap_or_else(|e| panic!("{}", e));
    put_hex32_required(out, "target_object_hash_hex", &v.target_object_hash_hex);
    put_str(out, &v.reason_code);
    put_b64_fixed_required(
        out,
        "authority_public_key_b64",
        &v.authority_public_key_b64,
        32,
    );
    put_b64_fixed_required(out, "signature_b64", &v.signature_b64, 64);
}

fn encode_cognitive_supersede_v1(out: &mut Vec<u8>, v: &CognitiveTxSupersedeV1) {
    validate_sha256_hex_field("old_object_hash_hex", &v.old_object_hash_hex)
        .unwrap_or_else(|e| panic!("{}", e));
    validate_sha256_hex_field("new_object_hash_hex", &v.new_object_hash_hex)
        .unwrap_or_else(|e| panic!("{}", e));
    if v.old_object_hash_hex == v.new_object_hash_hex {
        panic!("supersede old_object_hash_hex must differ from new_object_hash_hex");
    }
    validate_non_empty_no_separator("reason_code", &v.reason_code)
        .unwrap_or_else(|e| panic!("{}", e));
    put_hex32_required(out, "old_object_hash_hex", &v.old_object_hash_hex);
    put_hex32_required(out, "new_object_hash_hex", &v.new_object_hash_hex);
    put_str(out, &v.reason_code);
    put_b64_fixed_required(
        out,
        "authority_public_key_b64",
        &v.authority_public_key_b64,
        32,
    );
    put_b64_fixed_required(out, "signature_b64", &v.signature_b64, 64);
}

#[inline]
fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Decodifica hex in 32 bytes.
/// - In dev_mode: se invalido ritorna 32 zeri (deterministico) ma logga un warning throttled.
/// - In public_mode: fail-closed (panic) se il valore non è un hex32 valido.
#[inline]
fn hex32_or_zero(s: &str) -> [u8; 32] {
    let st = s.trim();
    if st.is_empty() || st == "0" {
        return [0u8; 32];
    }
    match hex::decode(st) {
        Ok(v) if v.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            out
        }
        Ok(v) => {
            let public_mode = crate::runtime_mode::public_mode_enabled();
            if public_mode {
                panic!("hex32 invalid length={} for '{}'", v.len(), st);
            }
            ng_warn_throttle!(
                key: "ngbin.hex32.len",
                every_ms: 5000,
                target: "ngbin",
                "hex32 invalid length={} for '{}'",
                v.len(),
                st
            );
            [0u8; 32]
        }
        Err(e) => {
            let public_mode = crate::runtime_mode::public_mode_enabled();
            if public_mode {
                panic!("hex32 decode failed for '{}': {}", st, e);
            }
            ng_warn_throttle!(
                key: "ngbin.hex32.decode",
                every_ms: 5000,
                target: "ngbin",
                "hex32 decode failed for '{}': {}",
                st,
                e
            );
            [0u8; 32]
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

pub fn try_encode_govtx_v1(gtx: &GovernanceTx) -> Result<Vec<u8>, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| encode_govtx_v1(gtx)))
        .map_err(panic_payload_to_string)
}

pub fn try_encode_cognitive_tx_v1(ctx: &CognitiveTxV1) -> Result<Vec<u8>, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| encode_cognitive_tx_v1(ctx)))
        .map_err(panic_payload_to_string)
}

pub fn try_header_hash_hex_v1(
    index: u64,
    timestamp: u64,
    previous_hash_hex: &str,
    tx_root_hex: &str,
    state_root_hex: &str,
    governance_txs: &[GovernanceTx],
    cognitive_txs: &[CognitiveTxV1],
    miner_pub_key: &str,
) -> Result<String, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        header_hash_hex_v1(
            index,
            timestamp,
            previous_hash_hex,
            tx_root_hex,
            state_root_hex,
            governance_txs,
            cognitive_txs,
            miner_pub_key,
        )
    }))
    .map_err(panic_payload_to_string)
}

pub fn encode_govtx_v1(gtx: &GovernanceTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(DOMAIN_GOVTX_V1);

    match gtx {
        GovernanceTx::Proposal(p) => {
            put_u8(&mut out, 1);
            put_str(&mut out, &p.id);
            put_gov_kind(&mut out, &p.kind);
            put_bytes(&mut out, &p.payload);
            put_u64(&mut out, p.created_at_height);
            put_u64(&mut out, p.effective_height);
            put_str(&mut out, &p.proposer);
            // Consensus-critical governance signature/domain fields. These fields are
            // validated by governance.rs and must be part of the canonical block/header
            // encoding; otherwise two blocks with different accepted governance domains
            // could hash identically.
            put_str(&mut out, &p.signature_domain);
            put_str(&mut out, &p.chain_id);
            put_str(&mut out, &p.genesis_hash);
            put_str(&mut out, &p.signature);
        }
        GovernanceTx::Vote(v) => {
            put_u8(&mut out, 2);
            put_str(&mut out, &v.proposal_id);
            // The explicit voted proposal hash is consensus-critical. It prevents a
            // vote for one proposal incarnation from being silently reused after a
            // reorg/reinclusion that changes the proposal hash.
            put_str(&mut out, &v.proposal_hash_hex);
            put_str(&mut out, &v.voter);
            put_str(&mut out, &v.signature_domain);
            put_str(&mut out, &v.chain_id);
            put_str(&mut out, &v.genesis_hash);
            put_str(&mut out, &v.signature);
        }
        GovernanceTx::FinalityVote(fv) => {
            // Tag 3: deterministic finality vote (checkpoint + ed25519 signature)
            put_u8(&mut out, 3);
            put_u64(&mut out, fv.checkpoint.height);
            put_str(&mut out, &fv.checkpoint.block_hash);
            put_str(&mut out, &fv.checkpoint.chain_id);
            put_str(&mut out, &fv.checkpoint.genesis_hash);
            put_str(&mut out, &fv.checkpoint.validator_set_hash);
            put_u64(&mut out, fv.checkpoint.ts);
            put_str(&mut out, &fv.sig.signer_pk_b64);
            put_str(&mut out, &fv.sig.sig_b64);
        }
    }
    out
}

pub fn govtx_size_bytes_v1(gtx: &GovernanceTx) -> usize {
    // dominio + tag + campi (length-prefixed per string/bytes)
    let b = encode_govtx_v1(gtx);
    b.len()
}

pub fn encode_cognitive_tx_v1(ctx: &CognitiveTxV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(384);
    out.extend_from_slice(DOMAIN_COGTX_V1);

    put_cog_kind(&mut out, ctx.kind());
    match ctx {
        CognitiveTxV1::Anchor(v) => encode_cognitive_anchor_v1(&mut out, v),
        CognitiveTxV1::Dispute(v) => encode_cognitive_dispute_v1(&mut out, v),
        CognitiveTxV1::Revoke(v) => encode_cognitive_revoke_v1(&mut out, v),
        CognitiveTxV1::Supersede(v) => encode_cognitive_supersede_v1(&mut out, v),
    }
    out
}

pub fn cognitive_tx_size_bytes_v1(ctx: &CognitiveTxV1) -> usize {
    encode_cognitive_tx_v1(ctx).len()
}

pub fn encode_tx_v1(tx: &Transaction) -> Vec<u8> {
    // Nota: qui NON includo tx.hash (derivato). L’hash si ricalcola sempre.
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(DOMAIN_TX_V1);

    put_u8(&mut out, if tx.is_coinbase { 1 } else { 0 });
    put_str(&mut out, tx.sender.trim());
    put_str(&mut out, tx.receiver.trim());
    put_u64(&mut out, tx.amount);
    put_u64(&mut out, tx.nonce);
    put_u64(&mut out, tx.max_fee_per_tx);
    put_str(&mut out, tx.signature.trim());

    match &tx.memo {
        Some(m) => {
            put_u8(&mut out, 1);
            put_str(&mut out, m);
        }
        None => {
            put_u8(&mut out, 0);
        }
    }

    out
}

pub fn tx_hash_hex_v1(tx: &Transaction) -> String {
    let b = encode_tx_v1(tx);
    hex::encode(sha256_32(&b))
}

pub fn tx_size_bytes_v1(tx: &Transaction) -> usize {
    encode_tx_v1(tx).len()
}

pub fn header_hash_hex_v1(
    index: u64,
    timestamp: u64,
    previous_hash_hex: &str,
    tx_root_hex: &str,
    state_root_hex: &str,
    governance_txs: &[GovernanceTx],
    cognitive_txs: &[CognitiveTxV1],
    miner_pub_key: &str, // lasciato string perché nel tuo codice è stringa (non 32 bytes raw)
) -> String {
    let mut out = Vec::with_capacity(256 + governance_txs.len() * 128 + cognitive_txs.len() * 256);
    out.extend_from_slice(DOMAIN_HEADER_V1);

    put_u64(&mut out, index);
    put_u64(&mut out, timestamp);
    out.extend_from_slice(&hex32_or_zero(previous_hash_hex));
    out.extend_from_slice(&hex32_or_zero(tx_root_hex));
    out.extend_from_slice(&hex32_or_zero(state_root_hex));

    put_u32(&mut out, governance_txs.len() as u32);
    for gtx in governance_txs {
        let gb = encode_govtx_v1(gtx);
        put_bytes(&mut out, &gb);
    }

    put_u32(&mut out, cognitive_txs.len() as u32);
    for ctx in cognitive_txs {
        let cb = encode_cognitive_tx_v1(ctx);
        put_bytes(&mut out, &cb);
    }

    put_str(&mut out, miner_pub_key.trim());

    hex::encode(sha256_32(&out))
}

/// Dimensione canonica “wire” v1 (deterministica) usata per max_block_size e fill-ratio.
pub fn try_block_size_bytes_v1(block: &crate::block::Block) -> Result<usize, String> {
    // Header v1:
    // domain + index(u64) + ts(u64)
    // + prev_hash(32) + tx_root(32) + state_root(32)
    // + gov_count(u32) + [ (len(u32) + gov_bytes)*N ]
    // + cognitive_count(u32) + [ (len(u32) + cognitive_bytes)*N ]
    // + miner_pk_len(u32) + miner_pk_bytes
    let miner_pk = block.miner_pub_key.trim().as_bytes();

    let mut total: usize = 0;

    total += DOMAIN_HEADER_V1.len();
    total += 8; // index
    total += 8; // timestamp
    total += 32; // previous_hash (fixed 32)
    total += 32; // tx_root (fixed 32)
    total += 32; // state_root (fixed 32)

    total += 4; // governance_txs count (u32)
    for gtx in &block.governance_txs {
        let gb = match try_encode_govtx_v1(gtx) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("invalid governance tx: {}", e));
            }
        }; // se vuoi evitare alloc qui, serve una govtx_size_v1()
        total += 4; // len prefix
        total += gb.len(); // payload
    }

    total += 4; // cognitive_txs count (u32)
    for ctx in &block.cognitive_txs {
        let cb = match try_encode_cognitive_tx_v1(ctx) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("invalid cognitive tx: {}", e));
            }
        };
        total += 4; // len prefix
        total += cb.len();
    }

    total += 4; // miner_pub_key len (u32)
    total += miner_pk.len();

    // signature
    total += 1; // present flag
    if let Some(sig) = &block.signature {
        total += 4; // len
        total += sig.len();
    }

    // txs
    total += 4; // tx count (u32)
    for tx in &block.transactions {
        total += tx_size_bytes_v1(tx);
    }

    Ok(total)
}

/// Helper legacy fail-fast per path interni trusted.
/// I path runtime/validation devono preferire `try_block_size_bytes_v1`.
#[cfg(test)]
#[allow(dead_code)]
fn block_size_bytes_v1(block: &crate::block::Block) -> usize {
    try_block_size_bytes_v1(block).unwrap_or_else(|e| panic!("block_size_bytes_v1 failed: {}", e))
}

/// Dimensione canonica “wire” v2 (deterministica).
///
/// V2 estende V1 aggiungendo i campi Phase 3A (PoS proposer proof):
/// - pos_epoch(u64) + pos_slot(u64) + pos_round(u32)
/// - pos_proof: present(u8) + len(u32) + bytes
///
/// Nota: NON cambia il block hash (header_hash_hex_v1 resta invariato).
pub fn try_block_size_bytes_v2(block: &crate::block::Block) -> Result<usize, String> {
    let mut total = try_block_size_bytes_v1(block)?;

    // PoS metadata
    total += 8; // pos_epoch
    total += 8; // pos_slot
    total += 4; // pos_round

    // pos_proof (ed25519)
    total += 1; // present flag
    if let Some(p) = &block.pos_proof {
        total += 4; // len
        total += p.len();
    }

    Ok(total)
}

/// Helper legacy fail-fast per path interni trusted.
/// I path runtime/validation devono preferire `try_block_size_bytes_v2`.
#[cfg(test)]
#[allow(dead_code)]
fn block_size_bytes_v2(block: &crate::block::Block) -> usize {
    try_block_size_bytes_v2(block).unwrap_or_else(|e| panic!("block_size_bytes_v2 failed: {}", e))
}

/// Dimensione canonica "wire" v3 (deterministica).
///
/// V3 estende V2 aggiungendo (Phase 3B):
/// - finality_qc: present(u8) + fields + bitset + sigs
///
/// Nota: come per V2, NON cambia l'header_hash_hex_v1.
pub fn try_block_size_bytes_v3(block: &crate::block::Block) -> Result<usize, String> {
    let mut total = try_block_size_bytes_v2(block)?;

    // QC present flag
    total += 1;
    if let Some(qc) = &block.finality_qc {
        total += 8; // epoch
        total += 8; // height
        total += 4; // round
        total += 32; // block_hash (fixed 32 bytes)

        total += 4; // bitset len prefix (u32)
        total += qc.voter_bitset.len();

        total += 4; // sig count (u32)
                    // Signatures are base64 in struct (for JSON), but on-wire canonical encoding would be 64 bytes each.
                    // For size policy, count 64 bytes each (upper bound is handled elsewhere by max_block_size).
        for _ in &qc.sigs_b64 {
            total += 64;
        }
    }

    // NFT events are deterministic state-transition receipts. They are not included in the
    // block header hash, but they are part of the propagated/persisted block object and must
    // count against anti-spam block-size policy.
    total += 4; // nft_events count
    for ev in &block.nft_events {
        let bytes =
            serde_json::to_vec(ev).map_err(|e| format!("invalid nft event encoding: {e}"))?;
        total += 4;
        total += bytes.len();
    }

    Ok(total)
}

/// Helper legacy fail-fast per path interni trusted.
/// I path runtime/validation devono preferire `try_block_size_bytes_v3`.
#[cfg(test)]
#[allow(dead_code)]
fn block_size_bytes_v3(block: &crate::block::Block) -> usize {
    try_block_size_bytes_v3(block).unwrap_or_else(|e| panic!("block_size_bytes_v3 failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cognitive_chain::{
        CognitiveAttestationCertV1, CognitiveAttestationEnvelopeV1, CognitiveAttestationSigV1,
        CognitiveTxAnchorV1, CognitiveTxDisputeV1, CognitiveTxV1,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_hash(ch: char) -> String {
        std::iter::repeat(ch).take(64).collect()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_anchor_tx() -> CognitiveTxV1 {
        let sk = signing_key(9);
        let env = CognitiveAttestationEnvelopeV1 {
            chain_id: "newgen-devnet".to_string(),
            genesis_hash: sample_hash('a'),
            object_hash_hex: sample_hash('b'),
            claim_hash_hex: sample_hash('c'),
            evidence_root_hex: sample_hash('d'),
            context_hash_hex: sample_hash('e'),
            policy_id: "verified-response-v1".to_string(),
            model_manifest_hash_hex: sample_hash('f'),
            created_at_height: 11,
            created_at_ts: 22,
        };
        let sig = sk.sign(&env.canonical_bytes().unwrap());
        CognitiveTxV1::Anchor(CognitiveTxAnchorV1 {
            attestation_cert: CognitiveAttestationCertV1 {
                envelope: env,
                sigs: vec![CognitiveAttestationSigV1 {
                    signer_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
                    signature_b64: B64.encode(sig.to_bytes()),
                }],
            },
        })
    }

    #[test]
    fn encode_cognitive_tx_is_deterministic() {
        let tx = sample_anchor_tx();
        let a = encode_cognitive_tx_v1(&tx);
        let b = encode_cognitive_tx_v1(&tx);
        assert_eq!(a, b);
        assert!(a.starts_with(DOMAIN_COGTX_V1));
    }

    #[test]
    fn encode_cognitive_anchor_rejects_unsorted_duplicate_signers() {
        let mut tx = sample_anchor_tx();
        let sig = match &mut tx {
            CognitiveTxV1::Anchor(v) => {
                let first = v.attestation_cert.sigs[0].clone();
                v.attestation_cert.sigs.push(first.clone());
                v.attestation_cert.sigs.swap(0, 1);
                first
            }
            _ => unreachable!(),
        };
        let err = std::panic::catch_unwind(|| encode_cognitive_tx_v1(&tx)).expect_err("must panic");
        let msg = if let Some(s) = err.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = err.downcast_ref::<&str>() {
            s.to_string()
        } else {
            String::new()
        };
        assert!(msg.contains("duplicate signer") || msg.contains("not sorted canonically"));
        let _ = sig;
    }

    #[test]
    fn header_hash_changes_when_cognitive_txs_change() {
        let base = header_hash_hex_v1(
            1,
            2,
            &sample_hash('1'),
            &sample_hash('2'),
            &sample_hash('3'),
            &[],
            &[],
            "miner",
        );
        let changed = header_hash_hex_v1(
            1,
            2,
            &sample_hash('1'),
            &sample_hash('2'),
            &sample_hash('3'),
            &[],
            &[sample_anchor_tx()],
            "miner",
        );
        assert_ne!(base, changed);
    }

    #[test]
    fn block_size_counts_cognitive_txs() {
        let mut block = crate::block::Block::default();
        let size_empty = block_size_bytes_v3(&block);
        block.cognitive_txs.push(sample_anchor_tx());
        let size_with = block_size_bytes_v3(&block);
        assert!(size_with > size_empty);
    }

    #[test]
    fn block_size_counts_nft_events() {
        let mut block = crate::block::Block::default();
        let size_empty = block_size_bytes_v3(&block);
        block.nft_events.push(crate::nft::NftEventV1::base(
            "nft_token_minted",
            "mint",
            1,
            &sample_hash('a'),
            0,
        ));
        let size_with = block_size_bytes_v3(&block);
        assert!(size_with > size_empty);
    }

    #[test]
    fn encode_cognitive_dispute_is_stable() {
        let sk = signing_key(7);
        let payload = CognitiveTxDisputeV1 {
            target_object_hash_hex: sample_hash('0'),
            reason_code: "conflicting_evidence".to_string(),
            dispute_evidence_root_hex: sample_hash('9'),
            submitter_public_key_b64: B64.encode(sk.verifying_key().to_bytes()),
            signature_b64: String::new(),
        };
        let sig = sk.sign(&payload.canonical_bytes().unwrap());
        let tx = CognitiveTxV1::Dispute(CognitiveTxDisputeV1 {
            signature_b64: B64.encode(sig.to_bytes()),
            ..payload
        });
        let a = encode_cognitive_tx_v1(&tx);
        let b = encode_cognitive_tx_v1(&tx);
        assert_eq!(a, b);
    }

    #[test]
    fn encode_gov_proposal_includes_domain_fields() {
        let base = GovernanceTx::Proposal(crate::governance::TxGovernanceProposal {
            id: "ngbin-domain-govp-00000000000000000000000000000001".to_string(),
            kind: crate::governance::GovProposalKind::UpdateGovernanceParams,
            payload: b"{}".to_vec(),
            created_at_height: 10,
            effective_height: 20,
            proposer: "proposer".to_string(),
            signature_domain: "nggov-signature-domain-v2".to_string(),
            chain_id: "chain-a".to_string(),
            genesis_hash: sample_hash('a'),
            signature: "sig".to_string(),
        });
        let mut changed_domain = base.clone();
        if let GovernanceTx::Proposal(p) = &mut changed_domain {
            p.signature_domain = "other-domain".to_string();
        }
        let mut changed_chain = base.clone();
        if let GovernanceTx::Proposal(p) = &mut changed_chain {
            p.chain_id = "chain-b".to_string();
        }
        let mut changed_genesis = base.clone();
        if let GovernanceTx::Proposal(p) = &mut changed_genesis {
            p.genesis_hash = sample_hash('b');
        }
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_domain));
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_chain));
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_genesis));
    }

    #[test]
    fn encode_gov_vote_includes_proposal_hash_and_domain_fields() {
        let base = GovernanceTx::Vote(crate::governance::TxGovernanceVote {
            proposal_id: "ngbin-vote-domain-govp-00000000000000000000000000000002".to_string(),
            proposal_hash_hex: sample_hash('1'),
            voter: "voter".to_string(),
            signature_domain: "nggov-signature-domain-v2".to_string(),
            chain_id: "chain-a".to_string(),
            genesis_hash: sample_hash('a'),
            signature: "sig".to_string(),
        });
        let mut changed_hash = base.clone();
        if let GovernanceTx::Vote(v) = &mut changed_hash {
            v.proposal_hash_hex = sample_hash('2');
        }
        let mut changed_domain = base.clone();
        if let GovernanceTx::Vote(v) = &mut changed_domain {
            v.signature_domain = "other-domain".to_string();
        }
        let mut changed_chain = base.clone();
        if let GovernanceTx::Vote(v) = &mut changed_chain {
            v.chain_id = "chain-b".to_string();
        }
        let mut changed_genesis = base.clone();
        if let GovernanceTx::Vote(v) = &mut changed_genesis {
            v.genesis_hash = sample_hash('b');
        }
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_hash));
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_domain));
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_chain));
        assert_ne!(encode_govtx_v1(&base), encode_govtx_v1(&changed_genesis));
    }
}
