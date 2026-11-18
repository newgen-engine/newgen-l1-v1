use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transaction::Transaction;

/// NETWORK_ID canonico usato dal wallet v2 e dal core.
#[inline]
pub fn network_id() -> &'static str {
    crate::chain_identity::network_id()
}

/// Payload "canonico" di una transazione da firmare lato wallet.
///
/// Nota: questo è indipendente da `crate::transaction::Transaction`.
/// È il formato pensato per i client (wallet, explorer, CLI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPayload {
    pub network_id: String, // es: "newgen-devnet"
    pub from: String,       // address (in futuro "NG1...")
    pub to: String,         // address
    pub amount: u64,
    pub max_fee_per_tx: u64, // fee massima che l'utente è disposto a pagare
    pub nonce: u64,
    pub memo: Option<String>,
}

/// Transazione firmata lato client.
///
/// - `payload`        → dati logici della TX
/// - `public_key_b64` → chiave pubblica ed25519 in base64 (32 byte)
/// - `signature_b64`  → firma ed25519 in base64 (64 byte)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub payload: TransactionPayload,
    pub public_key_b64: String,
    pub signature_b64: String,
}

/// Costruisce la stringa **deterministica** da firmare.
///
/// Schema:
/// `<network_id>|<from>|<to>|<amount>|<max_fee_per_tx>|<nonce>|<memo_or_empty>`
/// `<network_id>|<from>|<to>|<amount>|<max_fee_per_tx>|<nonce>|<memo_or_empty>`
pub fn canonical_signing_string(payload: &TransactionPayload) -> String {
    let memo_str = match &payload.memo {
        Some(m) => m.as_str(),
        None => "",
    };

    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        payload.network_id,
        payload.from,
        payload.to,
        payload.amount,
        payload.max_fee_per_tx,
        payload.nonce,
        memo_str
    )
}

/// Firma un `TransactionPayload` con una secret key in base64 (ed25519).
///
/// Ritorna `Ok(signature_b64)` oppure `Err` con una descrizione.
pub fn sign_payload_ed25519(
    secret_key_b64: &str,
    payload: &TransactionPayload,
) -> Result<String, String> {
    let sk_bytes = STANDARD
        .decode(secret_key_b64)
        .map_err(|e| format!("invalid base64 secret key: {e}"))?;

    if sk_bytes.len() != 32 {
        return Err(format!(
            "secret key must be 32 bytes, got {}",
            sk_bytes.len()
        ));
    }

    let sk_arr: [u8; 32] = sk_bytes[..32]
        .try_into()
        .map_err(|_| "cannot convert to [u8; 32]")?;
    let signing_key = SigningKey::from_bytes(&sk_arr);

    let msg = canonical_signing_string(payload);
    let sig = signing_key.sign(msg.as_bytes());
    Ok(STANDARD.encode(sig.to_bytes()))
}

/// Verifica una `SignedTransaction` usando la public key in base64.
///
/// NON controlla saldo, fee o nonce a livello economico:
/// si limita a dire se la firma crittografica è corretta.
pub fn verify_signed_transaction(signed: &SignedTransaction) -> Result<(), String> {
    let pk_bytes = STANDARD
        .decode(&signed.public_key_b64)
        .map_err(|e| format!("invalid base64 public key: {e}"))?;

    if pk_bytes.len() != 32 {
        return Err(format!(
            "public key must be 32 bytes, got {}",
            pk_bytes.len()
        ));
    }

    let pk_arr: [u8; 32] = pk_bytes[..32]
        .try_into()
        .map_err(|_| "cannot convert public key to [u8; 32]")?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("invalid public key bytes: {e}"))?;

    let sig_bytes = STANDARD
        .decode(&signed.signature_b64)
        .map_err(|e| format!("invalid base64 signature: {e}"))?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let sig = Signature::from_bytes(
        &sig_bytes[..64]
            .try_into()
            .map_err(|_| "cannot convert signature to [u8; 64]")?,
    );

    let msg = canonical_signing_string(&signed.payload);

    // 1️⃣ Verifica crittografica della firma
    verifying_key
        .verify(msg.as_bytes(), &sig)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    // 2️⃣ Verifica di coerenza: `from` deve corrispondere alla public key
    //
    // Al livello attuale del protocollo, trattiamo `from` come "identità grezza"
    // del mittente, quindi deve essere uguale alla public key in base64.
    let recomputed_pk_b64 = STANDARD.encode(pk_bytes);
    if signed.payload.from != recomputed_pk_b64 {
        return Err("from_mismatch_public_key".to_string());
    }

    Ok(())
}

/// ⚠️ LEGACY: vecchio schema di firma (receiver+amount+hash).
/// NON usato nel wallet v2 canonico. Tenuto solo per compatibilità dev.
/// Firma una transazione con la chiave privata del wallet
pub fn sign_transaction(private_key_b64: &str, receiver: &str, amount: u64, hash: &str) -> String {
    let private_key_bytes = match STANDARD.decode(private_key_b64) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let sk_arr: [u8; 32] = match private_key_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    let signing_key = SigningKey::from_bytes(&sk_arr);
    let message = format!("{}{}{}", receiver, amount, hash);
    let signature = signing_key.sign(message.as_bytes());
    STANDARD.encode(signature.to_bytes())
}

// ========================================================
// LEGACY HEX WALLET API (solo per dev / test interni)
// ========================================================
//
// Nota: queste funzioni usano chiavi e firme in formato hex
// e NON seguono lo schema canonico v2 (base64 + TransactionPayload).
// Non vanno usate per il wallet v2 "ufficiale" in produzione.

/// Rappresenta una coppia di chiavi in hex (pubblica/privata)
#[derive(Debug, Clone)]
pub struct WalletKeypair {
    pub public_hex: String,
    pub secret_hex: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("hex decode error: {e}"))
}

/// Genera una coppia di chiavi ed25519.
pub fn generate_keypair() -> WalletKeypair {
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pk = sk.verifying_key();

    WalletKeypair {
        public_hex: hex_encode(pk.to_bytes().as_ref()),
        secret_hex: hex_encode(sk.to_bytes().as_ref()),
    }
}

/// Firma dei bytes con sk hex → firma hex.
pub fn sign_bytes_hex(secret_hex: &str, msg: &[u8]) -> Result<String, String> {
    let sk_bytes = hex_decode(secret_hex)?;
    if sk_bytes.len() != 32 {
        return Err("secret key must be 32 bytes".into());
    }
    let sk_arr: [u8; 32] = sk_bytes[..32]
        .try_into()
        .map_err(|_| "secret key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&sk_arr);

    let sig: Signature = sk.sign(msg);
    Ok(hex_encode(sig.to_bytes().as_ref()))
}

/// Verifica firma (pubkey hex, firma hex) sui bytes.
pub fn verify_bytes_hex(public_hex: &str, sig_hex: &str, msg: &[u8]) -> Result<bool, String> {
    let pk_bytes = hex_decode(public_hex)?;
    let sig_bytes = hex_decode(sig_hex)?;
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Ok(false);
    }
    let pk_arr: [u8; 32] = pk_bytes[..32]
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("verifying key error: {e}"))?;

    let sig_arr: [u8; 64] = sig_bytes[..64]
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);

    Ok(vk.verify(msg, &sig).is_ok())
}

/// Messaggio canonico per la firma TX: SHA256("sender|receiver|amount")
fn tx_signing_message(sender_hex: &str, receiver_hex: &str, amount: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sender_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(receiver_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(amount.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Crea una Transaction firmata con la chiave privata del mittente.
/// - `sender_secret_hex`: chiave privata ed25519 (32 byte hex)
/// - `receiver_public_hex`: chiave pubblica destinatario (32 byte hex)
/// - `amount`: importo
pub fn create_signed_tx(
    sender_secret_hex: &str,
    receiver_public_hex: &str,
    amount: u64,
) -> Result<Transaction, String> {
    // Deriva la chiave pubblica dal segreto mittente
    let sk_bytes = hex_decode(sender_secret_hex)?;
    if sk_bytes.len() != 32 {
        return Err("secret key must be 32 bytes".into());
    }
    let sk_arr: [u8; 32] = sk_bytes[..32]
        .try_into()
        .map_err(|_| "secret key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&sk_arr);

    let sender_public_hex = hex_encode(sk.verifying_key().to_bytes().as_ref());

    // Messaggio canonico
    let msg = tx_signing_message(&sender_public_hex, receiver_public_hex, amount);

    // Firma
    let signature_hex = sign_bytes_hex(sender_secret_hex, &msg)?;

    // Crea Transaction (non-coinbase)
    let tx = Transaction::new(
        sender_public_hex,
        receiver_public_hex.to_string(),
        amount,
        0, // nonce placeholder
        0, // max_fee_per_tx placeholder (wallet HEX legacy, non usato)
        signature_hex,
        false, // is_coinbase
        None,  // memo
    );

    Ok(tx)
}

/// Wrapper per compatibilità API: genera una coppia chiavi (address + private)
pub fn generate_wallet() -> (String, String) {
    let kp = generate_keypair();
    (kp.public_hex, kp.secret_hex)
}

// --- CERTIFICAZIONE WALLET (firma ED25519 del nodo master) ---

/// Firma la chiave pubblica del wallet con la chiave privata master (base64)
/// `wallet_pub_b64` è la pubkey del wallet in base64 (spesso coincide con "address")
pub fn try_sign_wallet_pubkey(master_sk_b64: &str, wallet_pub_b64: &str) -> Result<String, String> {
    let master_sk_bytes = STANDARD
        .decode(master_sk_b64)
        .map_err(|e| format!("invalid_master_sk_b64: {e}"))?;
    let sk_arr: [u8; 32] = master_sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid_master_sk_len".to_string())?;
    let signing_key = SigningKey::from_bytes(&sk_arr);

    let wallet_pub_bytes = STANDARD
        .decode(wallet_pub_b64)
        .map_err(|e| format!("invalid_wallet_pub_b64: {e}"))?;

    let mut message = b"WALLET_CERT_v1|".to_vec();
    message.extend_from_slice(&wallet_pub_bytes);

    let sig = signing_key.sign(&message);
    Ok(STANDARD.encode(sig.to_bytes()))
}

/// Compat legacy: ritorna stringa vuota in caso di errore (no panic).
pub fn sign_wallet_pubkey(master_sk_b64: &str, wallet_pub_b64: &str) -> String {
    try_sign_wallet_pubkey(master_sk_b64, wallet_pub_b64).unwrap_or_default()
}

/// Verifica il certificato del wallet dato la chiave pubblica master
pub fn verify_wallet_cert(master_pk_b64: &str, wallet_pub_b64: &str, cert_b64: &str) -> bool {
    // Decodifica base64
    let master_pk_bytes = match STANDARD.decode(master_pk_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let wallet_pub_bytes = match STANDARD.decode(wallet_pub_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match STANDARD.decode(cert_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // ✅ HARD CHECKS (non usare unwrap_or con zeri: è insicuro)
    if master_pk_bytes.len() != 32 || wallet_pub_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    // Converti in array a lunghezza fissa
    let master_arr: [u8; 32] = match master_pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Crea la verifying key del master
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&master_arr) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // ✅ FIX CLIPPY: niente match inutile
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Prepara il messaggio da verificare
    let mut message = b"WALLET_CERT_v1|".to_vec();
    message.extend_from_slice(&wallet_pub_bytes);

    verifying_key.verify(&message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn keygen_sign_verify_roundtrip_hex_legacy() {
        // Testa ancora le primitive HEX legacy
        let kp = generate_keypair();
        let data = b"hello world";
        let sig = sign_bytes_hex(&kp.secret_hex, data).unwrap();
        let ok = verify_bytes_hex(&kp.public_hex, &sig, data).unwrap();
        assert!(ok);
    }

    #[test]
    fn create_tx_legacy_builds_struct() {
        // Non usiamo più verify_signature() qui, perché il sender è in HEX
        // e il core ora si aspetta base64.
        let a = generate_keypair();
        let b = generate_keypair();
        let tx = create_signed_tx(&a.secret_hex, &b.public_hex, 42).unwrap();

        assert_eq!(tx.amount, 42);
        assert!(!tx.is_coinbase);
        // Verifichiamo solo che i campi siano stati popolati
        assert!(!tx.signature.is_empty());
        assert!(!tx.sender.is_empty());
        assert!(!tx.receiver.is_empty());
    }

    #[test]
    fn signed_transaction_and_core_transaction_agree_v2() {
        // ✅ Test importante per il wallet v2:
        // verifica che:
        // - sign_payload_ed25519
        // - verify_signed_transaction
        // - Transaction::verify_signature
        // siano tutti allineati.

        // 1) Genera una keypair ed25519
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key();

        let sk_b64 = STANDARD.encode(sk.to_bytes());
        let pk_b64 = STANDARD.encode(pk.to_bytes());

        // 2) Costruisci un payload canonico come usato nel wallet v2
        let payload = TransactionPayload {
            network_id: crate::chain_identity::network_id().to_string(),
            from: pk_b64.clone(),
            to: "receiver-test".to_string(),
            amount: 123,
            max_fee_per_tx: 0,
            nonce: 42,
            memo: None,
        };

        // 3) Firma il payload con la SK in base64
        let sig_b64 = sign_payload_ed25519(&sk_b64, &payload).expect("sign_payload_ed25519 failed");

        let signed = SignedTransaction {
            payload: payload.clone(),
            public_key_b64: pk_b64.clone(),
            signature_b64: sig_b64.clone(),
        };

        // 4) Verifica lato wallet v2
        verify_signed_transaction(&signed).expect("verify_signed_transaction failed");

        // 5) Costruisci una Transaction core come fa l'API
        let tx = Transaction {
            sender: payload.from, // = pk_b64
            receiver: payload.to,
            amount: payload.amount,
            max_fee_per_tx: payload.max_fee_per_tx,
            nonce: payload.nonce,
            signature: sig_b64,
            hash: String::new(),
            is_coinbase: false,
            memo: payload.memo,
        };

        // 6) Verifica lato core (Transaction::verify_signature)
        assert!(
            tx.verify_signature(),
            "core Transaction::verify_signature failed per lo schema v2"
        );
    }
}
