// src/crypto.rs
//
// Mainnet-grade minimal ed25519 helpers.
//
// Goals:
// - Domain separation by default (prevents cross-protocol signature replay)
// - Stable byte-oriented API at module boundary
// - Detailed errors (Result) + small bool wrappers when convenient
// - Integrates with existing key formatting utilities (keyfmt.rs)
//
// NOTE:
// This module is intentionally small and does NOT replace higher-level signing
// already implemented in wallet/checkpoint/finality_bft. It's a generic helper.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::keyfmt;

/// Global domain prefix for all domain-separated signatures in NewGen.
///
/// Keep this stable.
pub const DOMAIN_PREFIX: &[u8] = b"NEWGEN:";

/// Default context for the legacy wrappers in this module.
///
/// If you use this module for specific protocol messages, pass an explicit
/// context (e.g. b"HELLO_V1", b"CHECKPOINT_CERT_V1", b"TX_PAYLOAD_V1").
pub const DEFAULT_CTX: &[u8] = b"CRYPTO_GENERIC_V1";

#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidPublicKey(String),
    InvalidSignature(String),
    VerifyFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidPublicKey(e) => write!(f, "invalid public key: {e}"),
            CryptoError::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            CryptoError::VerifyFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn ds_message(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    // Format: NEWGEN:<CTX>:<MSG>
    // Use ':' separator so contexts cannot overlap ambiguously.
    let mut out = Vec::with_capacity(DOMAIN_PREFIX.len() + ctx.len() + 1 + msg.len());
    out.extend_from_slice(DOMAIN_PREFIX);
    out.extend_from_slice(ctx);
    out.push(b':');
    out.extend_from_slice(msg);
    out
}

/// Generate a new ed25519 signing key using OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Convenience: derive verifying key from signing key.
pub fn verifying_key(sk: &SigningKey) -> VerifyingKey {
    sk.verifying_key()
}

/// Domain-separated sign. Returns raw 64-byte signature.
pub fn sign_ds_bytes(sk: &SigningKey, ctx: &[u8], msg: &[u8]) -> [u8; 64] {
    let m = ds_message(ctx, msg);
    let sig: Signature = sk.sign(&m);
    sig.to_bytes()
}

/// Domain-separated verify. Strict ed25519 verification.
pub fn verify_ds_bytes(
    vk: &VerifyingKey,
    ctx: &[u8],
    msg: &[u8],
    sig64: &[u8; 64],
) -> Result<(), CryptoError> {
    let sig = Signature::from_bytes(sig64);
    let m = ds_message(ctx, msg);
    vk.verify_strict(&m, &sig)
        .map_err(|_| CryptoError::VerifyFailed)
}

/// Domain-separated sign -> base64(64 bytes).
pub fn sign_ds_b64(sk: &SigningKey, ctx: &[u8], msg: &[u8]) -> String {
    let sig64 = sign_ds_bytes(sk, ctx, msg);
    general_purpose::STANDARD.encode(sig64)
}

/// Domain-separated verify with pk_any (hex/base64) + sig_b64.
pub fn verify_ds_b64(
    pk_any: &str,
    sig_b64: &str,
    ctx: &[u8],
    msg: &[u8],
) -> Result<(), CryptoError> {
    let pk32 =
        keyfmt::decode_pk_any(pk_any).map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
    let sig64 = keyfmt::decode_sig64_b64(sig_b64)
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

    let vk = VerifyingKey::from_bytes(&pk32)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    verify_ds_bytes(&vk, ctx, msg, &sig64)
}

// -----------------------------------------------------------------------------
// Legacy-compatible wrappers (minimal behavior change):
// - keep function names similar to your previous file
// - improve internals: SigningKey/VerifyingKey + domain separation + Result API
// -----------------------------------------------------------------------------

/// Backward-compatible wrapper name.
///
/// Returns a SigningKey (v2-style) instead of dalek v1 Keypair.
pub fn generate_keypair() -> SigningKey {
    generate_signing_key()
}

/// Backward-compatible wrapper name.
///
/// Signs with DEFAULT_CTX and returns a dalek Signature.
pub fn sign_message(message: &[u8], keypair: &SigningKey) -> Signature {
    let sig64 = sign_ds_bytes(keypair, DEFAULT_CTX, message);
    Signature::from_bytes(&sig64)
}

/// Backward-compatible wrapper name.
///
/// Verifies with DEFAULT_CTX. Returns bool for call-sites that want a quick check.
pub fn verify_signature(message: &[u8], signature: &Signature, public_key: &VerifyingKey) -> bool {
    let sig64 = signature.to_bytes();
    verify_ds_bytes(public_key, DEFAULT_CTX, message, &sig64).is_ok()
}

/// Preferred API: detailed error.
pub fn verify_signature_result(
    message: &[u8],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let sig64 = signature.to_bytes();
    verify_ds_bytes(public_key, DEFAULT_CTX, message, &sig64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t01_sign_verify_ok() {
        let sk = generate_signing_key();
        let vk = verifying_key(&sk);
        let msg = b"hello";
        let sig = sign_ds_bytes(&sk, b"TEST_V1", msg);
        assert!(verify_ds_bytes(&vk, b"TEST_V1", msg, &sig).is_ok());
    }

    #[test]
    fn t02_domain_separation_blocks_replay() {
        let sk = generate_signing_key();
        let vk = verifying_key(&sk);
        let msg = b"same-bytes";
        let sig = sign_ds_bytes(&sk, b"CTX_A", msg);
        assert!(verify_ds_bytes(&vk, b"CTX_A", msg, &sig).is_ok());
        assert!(verify_ds_bytes(&vk, b"CTX_B", msg, &sig).is_err());
    }
}
