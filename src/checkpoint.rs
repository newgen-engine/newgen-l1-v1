use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

/// Checkpoint deterministico: ancora la chain a (height, block_hash) + ancore anti-divergenza.
///
/// Nota: `ts` DEVE essere deterministico. In Alpha usiamo `block.timestamp`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: String,

    // Anti-divergenza: vincolano a una specifica "world"
    pub chain_id: String,
    pub genesis_hash: String,
    pub validator_set_hash: String,

    /// Timestamp deterministico del blocco (non "now")
    pub ts: u64,
}

impl Checkpoint {
    /// Canonical string (stable across nodes). Uses '|' as separator.
    ///
    /// IMPORTANT: The fields used here MUST NOT contain '|'.
    pub fn signing_string(&self) -> Result<String, String> {
        for (name, v) in [
            ("block_hash", &self.block_hash),
            ("chain_id", &self.chain_id),
            ("genesis_hash", &self.genesis_hash),
            ("validator_set_hash", &self.validator_set_hash),
        ] {
            if v.contains('|') {
                return Err(format!(
                    "Checkpoint field contains invalid separator '|': {name}"
                ));
            }
        }
        Ok(format!(
            "ckpt|{}|{}|{}|{}|{}|{}",
            self.height,
            self.block_hash,
            self.chain_id,
            self.genesis_hash,
            self.validator_set_hash,
            self.ts
        ))
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.signing_string()?.into_bytes())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSig {
    /// Signer pubkey (ed25519) encoded as base64(32 bytes)
    pub signer_pk_b64: String,
    /// Signature encoded as base64(64 bytes)
    pub sig_b64: String,
}

impl CheckpointSig {
    /// Decode signer pubkey and return hex string (lowercase) for membership checks.
    pub fn signer_pk_hex(&self) -> Result<String, String> {
        let pk = STANDARD
            .decode(&self.signer_pk_b64)
            .map_err(|e| format!("checkpoint signer_pk_b64 decode failed: {e}"))?;
        if pk.len() != 32 {
            return Err(format!(
                "checkpoint signer_pk_b64 len={} (expected 32)",
                pk.len()
            ));
        }
        Ok(hex::encode(pk))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSigMsg {
    pub checkpoint: Checkpoint,
    pub sig: CheckpointSig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointCert {
    pub checkpoint: Checkpoint,
    /// Sorted by signer_pk_b64 for canonicality.
    pub sigs: Vec<CheckpointSig>,
}

/// Sign a checkpoint using a base64-encoded 32-byte ed25519 secret key.
pub fn sign_checkpoint_b64(miner_sk_b64: &str, ckpt: &Checkpoint) -> Result<CheckpointSig, String> {
    let sk_bytes = STANDARD
        .decode(miner_sk_b64)
        .map_err(|e| format!("miner_sk_b64 decode failed: {e}"))?;
    let sk_arr: [u8; 32] = sk_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "miner_sk_b64 must decode to 32 bytes (got {})",
            sk_bytes.len()
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_arr);
    let vk = sk.verifying_key();

    let msg = ckpt.signing_bytes()?;
    let sig = sk.sign(&msg);

    Ok(CheckpointSig {
        signer_pk_b64: STANDARD.encode(vk.to_bytes()),
        sig_b64: STANDARD.encode(sig.to_bytes()),
    })
}

/// Sign a checkpoint using a `SigningKey` (ed25519). Returns a base64-encoded signature payload.
pub fn sign_checkpoint(sk: &SigningKey, ckpt: &Checkpoint) -> Result<CheckpointSig, String> {
    let vk = sk.verifying_key();
    let msg = ckpt.signing_bytes()?;
    let sig = sk.sign(&msg);

    Ok(CheckpointSig {
        signer_pk_b64: STANDARD.encode(vk.to_bytes()),
        sig_b64: STANDARD.encode(sig.to_bytes()),
    })
}

/// Verify ONLY cryptography (ed25519). Does not check membership/quorum.
pub fn verify_checkpoint_sig(ckpt: &Checkpoint, sig: &CheckpointSig) -> Result<(), String> {
    let pk_bytes = STANDARD
        .decode(&sig.signer_pk_b64)
        .map_err(|e| format!("signer_pk_b64 decode failed: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(format!(
            "signer_pk_b64 len={} (expected 32)",
            pk_bytes.len()
        ));
    }

    let sig_bytes = STANDARD
        .decode(&sig.sig_b64)
        .map_err(|e| format!("sig_b64 decode failed: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!("sig_b64 len={} (expected 64)", sig_bytes.len()));
    }

    let vk = VerifyingKey::from_bytes(
        &pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signer_pk_b64 is not 32 bytes".to_string())?,
    )
    .map_err(|e| format!("VerifyingKey parse failed: {e}"))?;

    let sig = Signature::from_bytes(
        &sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "sig_b64 is not 64 bytes".to_string())?,
    );

    let msg = ckpt.signing_bytes()?;
    vk.verify_strict(&msg, &sig)
        .map_err(|e| format!("checkpoint signature verify failed: {e}"))?;

    Ok(())
}

/// Verify checkpoint certificate:
/// - each signature is cryptographically valid for cert.checkpoint
/// - each signer is in `allowed_signers_hex`
/// - at least `quorum_k` unique signers
pub fn verify_checkpoint_cert(
    cert: &CheckpointCert,
    quorum_k: usize,
    allowed_signers_hex: &HashSet<String>,
) -> Result<(), String> {
    if quorum_k == 0 {
        return Err("quorum_k must be >= 1".to_string());
    }
    if allowed_signers_hex.is_empty() {
        return Err("allowed_signers_hex is empty (checkpoint signing disabled)".to_string());
    }

    let mut seen: HashSet<String> = HashSet::new();
    for s in &cert.sigs {
        verify_checkpoint_sig(&cert.checkpoint, s)?;
        let signer_hex = s.signer_pk_hex()?;
        if !allowed_signers_hex.contains(&signer_hex) {
            return Err("checkpoint signer not in validator set".to_string());
        }
        if !seen.insert(signer_hex) {
            return Err("duplicate signer in checkpoint cert".to_string());
        }
    }

    if seen.len() < quorum_k {
        return Err(format!(
            "checkpoint quorum not reached: got {} need {}",
            seen.len(),
            quorum_k
        ));
    }

    Ok(())
}

/// Build a canonical cert from a map of signer_pk_b64 -> sig.
///
/// Notes:
/// - sorts signatures by signer_pk_b64 for deterministic serialization.
/// - re-validates signatures and membership.
pub fn build_checkpoint_cert(
    ckpt: Checkpoint,
    sigs_by_pk_b64: &HashMap<String, CheckpointSig>,
    quorum_k: usize,
    allowed_signers_hex: &HashSet<String>,
) -> Result<CheckpointCert, String> {
    let mut sigs: Vec<CheckpointSig> = sigs_by_pk_b64.values().cloned().collect();
    sigs.sort_by(|a, b| a.signer_pk_b64.cmp(&b.signer_pk_b64));

    let cert = CheckpointCert {
        checkpoint: ckpt,
        sigs,
    };

    verify_checkpoint_cert(&cert, quorum_k, allowed_signers_hex)?;
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn sample_checkpoint() -> Checkpoint {
        Checkpoint {
            height: 42,
            block_hash: "abcd".to_string(),
            chain_id: "newgen-mainnet".to_string(),
            genesis_hash: "genesis-hash".to_string(),
            validator_set_hash: "validators-hash".to_string(),
            ts: 1_700_000_000,
        }
    }

    #[test]
    fn signing_string_rejects_separator_in_fields() {
        let mut ckpt = sample_checkpoint();
        ckpt.block_hash = "bad|hash".to_string();
        assert!(ckpt.signing_string().is_err());
    }

    #[test]
    fn sign_and_verify_checkpoint_roundtrip() {
        let ckpt = sample_checkpoint();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sign_checkpoint(&sk, &ckpt).unwrap();
        verify_checkpoint_sig(&ckpt, &sig).unwrap();
        assert_eq!(
            sig.signer_pk_hex().unwrap(),
            hex::encode(sk.verifying_key().to_bytes())
        );
    }

    #[test]
    fn build_cert_sorts_signatures_and_enforces_quorum() {
        let ckpt = sample_checkpoint();
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let sig_a = sign_checkpoint(&sk_a, &ckpt).unwrap();
        let sig_b = sign_checkpoint(&sk_b, &ckpt).unwrap();
        let mut map = HashMap::new();
        map.insert(sig_b.signer_pk_b64.clone(), sig_b.clone());
        map.insert(sig_a.signer_pk_b64.clone(), sig_a.clone());
        let allowed: HashSet<String> = [
            hex::encode(sk_a.verifying_key().to_bytes()),
            hex::encode(sk_b.verifying_key().to_bytes()),
        ]
        .into_iter()
        .collect();

        let cert = build_checkpoint_cert(ckpt.clone(), &map, 2, &allowed).unwrap();
        assert_eq!(cert.sigs.len(), 2);
        assert!(cert.sigs[0].signer_pk_b64 <= cert.sigs[1].signer_pk_b64);
        verify_checkpoint_cert(&cert, 2, &allowed).unwrap();
        assert!(build_checkpoint_cert(ckpt, &map, 3, &allowed).is_err());
    }
}
