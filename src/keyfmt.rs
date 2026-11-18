// src/keyfmt.rs
//
// Deterministic key format utilities for validator / governance operations.
// Supports public keys provided as:
//   - Base64 (standard or URL-safe, with or without padding)
//   - Hex (64 chars, optionally 0x-prefixed)
// Canonical outputs:
//   - Base64 (standard alphabet, padded)
//   - Hex (lowercase)

use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone)]
pub enum KeyFmtError {
    Empty,
    InvalidHex,
    InvalidBase64,
    WrongLength { expected: usize, got: usize },
}

impl std::fmt::Display for KeyFmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFmtError::Empty => write!(f, "empty input"),
            KeyFmtError::InvalidHex => write!(f, "invalid hex"),
            KeyFmtError::InvalidBase64 => write!(f, "invalid base64"),
            KeyFmtError::WrongLength { expected, got } => {
                write!(f, "wrong length: expected {}, got {}", expected, got)
            }
        }
    }
}

impl std::error::Error for KeyFmtError {}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn strip_0x(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("0x") {
        rest
    } else if let Some(rest) = s.strip_prefix("0X") {
        rest
    } else {
        s
    }
}

fn looks_like_hex64(s: &str) -> bool {
    let s = strip_0x(s);
    s.len() == 64 && s.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

/// Canonicalize a base64-like string so STANDARD decoding has a good chance:
/// - strip whitespace
/// - translate URL-safe alphabet (-, _) to standard (+, /)
/// - add padding '=' up to multiple-of-4 length
fn canon_b64_for_decode(s: &str) -> String {
    let mut t = strip_ws(s);
    t = t.replace('-', "+").replace('_', "/");
    let rem = t.len() % 4;
    if rem != 0 {
        let pad = 4 - rem;
        t.extend(std::iter::repeat_n('=', pad));
    }
    t
}

fn decode_b64_any(s: &str) -> Result<Vec<u8>, KeyFmtError> {
    // Try: canonicalized STANDARD
    let c = canon_b64_for_decode(s);
    if let Ok(v) = general_purpose::STANDARD.decode(c.as_bytes()) {
        return Ok(v);
    }

    // Fallbacks: URL-safe engines, with and without padding.
    let raw = strip_ws(s);
    if let Ok(v) = general_purpose::URL_SAFE.decode(raw.as_bytes()) {
        return Ok(v);
    }
    if let Ok(v) = general_purpose::URL_SAFE_NO_PAD.decode(raw.as_bytes()) {
        return Ok(v);
    }

    Err(KeyFmtError::InvalidBase64)
}

/// Decode a 32-byte public key from either hex(64) or base64.
pub fn decode_pk_any(s: &str) -> Result<[u8; 32], KeyFmtError> {
    let s = strip_ws(s);
    if s.is_empty() {
        return Err(KeyFmtError::Empty);
    }

    if looks_like_hex64(&s) {
        let hs = strip_0x(&s);
        let bytes = hex::decode(hs).map_err(|_| KeyFmtError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(KeyFmtError::WrongLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let bytes = decode_b64_any(&s)?;
    if bytes.len() != 32 {
        return Err(KeyFmtError::WrongLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a 64-byte Ed25519 signature from base64 (standard or url-safe).
pub fn decode_sig64_b64(s: &str) -> Result<[u8; 64], KeyFmtError> {
    let s = strip_ws(s);
    if s.is_empty() {
        return Err(KeyFmtError::Empty);
    }
    let bytes = decode_b64_any(&s)?;
    if bytes.len() != 64 {
        return Err(KeyFmtError::WrongLength {
            expected: 64,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Canonical hex (lowercase) for a pubkey input (base64 or hex).
pub fn pk_hex_from_any(s: &str) -> Result<String, KeyFmtError> {
    let pk = decode_pk_any(s)?;
    Ok(hex::encode(pk))
}

/// Canonical base64 (STANDARD alphabet, padded) for a pubkey input (base64 or hex).
pub fn pk_b64_from_any(s: &str) -> Result<String, KeyFmtError> {
    let pk = decode_pk_any(s)?;
    Ok(general_purpose::STANDARD.encode(pk))
}

/// Compare two pubkeys given in any supported format (base64/hex) by value.
pub fn eq_pk_any(a: &str, b: &str) -> bool {
    match (decode_pk_any(a), decode_pk_any(b)) {
        (Ok(aa), Ok(bb)) => aa == bb,
        _ => false,
    }
}

/// Utility: canonical base64 for already-decoded 32-byte keys.
pub fn pk_b64_from_bytes(pk: &[u8; 32]) -> String {
    general_purpose::STANDARD.encode(pk)
}

/// Utility: canonical hex for already-decoded 32-byte keys.
pub fn pk_hex_from_bytes(pk: &[u8; 32]) -> String {
    hex::encode(pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn decode_pk_supports_hex_and_base64_variants() {
        let pk = [0x11u8; 32];
        let hex_in = format!("0x{}", hex::encode(pk));
        let b64 = general_purpose::STANDARD.encode(pk);
        let b64_url = general_purpose::URL_SAFE_NO_PAD.encode(pk);

        assert_eq!(decode_pk_any(&hex_in).unwrap(), pk);
        assert_eq!(decode_pk_any(&b64).unwrap(), pk);
        assert_eq!(decode_pk_any(&b64_url).unwrap(), pk);
        assert!(eq_pk_any(&hex_in, &b64));
    }

    #[test]
    fn decode_signature_rejects_wrong_length() {
        let short = general_purpose::STANDARD.encode([0u8; 32]);
        let err = decode_sig64_b64(&short).unwrap_err();
        assert!(matches!(
            err,
            KeyFmtError::WrongLength {
                expected: 64,
                got: 32
            }
        ));
    }

    #[test]
    fn canonical_outputs_are_stable() {
        let pk = [0x22u8; 32];
        let hex_in = hex::encode(pk);
        let b64 = pk_b64_from_any(&hex_in).unwrap();
        let back_hex = pk_hex_from_any(&b64).unwrap();
        assert_eq!(back_hex, hex::encode(pk));
        assert_eq!(pk_hex_from_bytes(&pk), hex::encode(pk));
        assert_eq!(pk_b64_from_bytes(&pk), b64);
    }
}
