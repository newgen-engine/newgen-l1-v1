#![allow(deprecated)]
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM a 256 bit
use argon2::password_hash::SaltString;
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// SecureWallet rappresenta un keystore cifrato v2.
///
/// - `address`       → address pubblico del wallet (derivato dalla public key)
/// - `public_key`    → chiave pubblica in base64 (utile per integrazioni / debug)
/// - `encrypted_key` → private key cifrata con AES-256-GCM
/// - `salt` / `nonce`→ parametri per Argon2 e AES-GCM
/// - `balance`       → valore informativo (cache lato client)
/// - `certificate`   → firma opzionale del master (WALLET_CERT_v1, ecc.)
/// - `created_at`    → timestamp UNIX (secondi)
/// - `note`          → campo libero (es. "wallet nodo A", "wallet utente X")
/// - `reputation`    → punteggio locale di fiducia (0 = neutro)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureWallet {
    #[serde(default)]
    pub version: u32,
    pub address: String,
    pub encrypted_key: String,
    pub salt: String,
    pub nonce: String,
    pub balance: u64,
    pub certificate: Option<String>,

    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub reputation: i32,
}

fn argon2_config() -> Argon2<'static> {
    // Mainnet-grade baseline (tarabile):
    // - memory: 64 MiB
    // - iterations: 2
    // - parallelism: 1
    // Output: 32 bytes
    let params = argon2::Params::new(64 * 1024, 2, 1, Some(32))
        .unwrap_or_else(|_| argon2::Params::default());
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn salt_bytes_for_kdf(salt_str: &str) -> Result<Vec<u8>, String> {
    // Prefer SaltString (PHC compatible). Fallback to legacy behavior for older wallets.
    if let Ok(salt) = SaltString::from_b64(salt_str) {
        Ok(salt.as_salt().as_ref().as_bytes().to_vec())
    } else {
        // legacy: treat as raw UTF-8 bytes
        Ok(salt_str.as_bytes().to_vec())
    }
}

impl SecureWallet {
    /// Crea un nuovo keystore cifrato a partire da una private key raw ed una password.
    ///
    /// `priv_key` deve contenere una chiave ed25519 (32 byte).
    /// Se è più lunga, vengono usati solo i primi 32 byte.
    pub fn encrypt(priv_key: &[u8], password: &str) -> Result<Self, String> {
        // Normalizza la private key a 32 byte
        let sk_bytes: [u8; 32] = if priv_key.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&priv_key[0..32]);
            arr
        } else {
            return Err("priv_key_too_short".to_string());
        };

        // Deriva la public key dalla secret ed25519
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pk_bytes = verifying_key.to_bytes();
        let public_key_b64 = general_purpose::STANDARD.encode(pk_bytes);

        // Address derivato da HASH(pubkey) → primi 20 byte, codificati in base64 con prefisso "NG1"
        let mut hasher = Sha256::new();
        hasher.update(pk_bytes);
        let digest = hasher.finalize();
        let payload = &digest[0..20];
        let address = format!("NG1{}", general_purpose::STANDARD.encode(payload));

        // 1️⃣ Genera salt casuale per Argon2
        let mut rng = OsRng;
        let salt = SaltString::generate(&mut rng);

        // 2️⃣ Deriva chiave simmetrica da password + salt
        let argon2 = argon2_config();
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(
                password.as_bytes(),
                salt.as_salt().as_ref().as_bytes(),
                &mut key_bytes,
            )
            .map_err(|e| format!("argon2_derivation_failed: {e}"))?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // 3️⃣ Genera nonce casuale per AES-GCM
        use rand_core::RngCore;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 4️⃣ Cifra la private key
        let ciphertext = cipher
            .encrypt(nonce, sk_bytes.as_ref())
            .map_err(|e| format!("encryption_failed: {e}"))?;

        // 5️⃣ Timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(SecureWallet {
            version: 2,
            address,
            encrypted_key: general_purpose::STANDARD.encode(ciphertext),
            salt: salt.to_string(),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            balance: 0,
            certificate: None,
            public_key: public_key_b64,
            created_at,
            note: None,
            reputation: 0,
        })
    }

    /// Decifra la private key a partire dal keystore e dalla password.
    ///
    /// Ritorna `Some(Vec<u8>)` con i 32 byte di secret key ed25519,
    /// oppure `None` se la password è sbagliata o i dati sono corrotti.
    pub fn decrypt_result(&self, password: &str) -> Result<Vec<u8>, String> {
        // 1️⃣ Ricostruisci la chiave simmetrica da password + salt
        let mut key_bytes = [0u8; 32];

        let argon2 = argon2_config();
        let salt_bytes = salt_bytes_for_kdf(&self.salt)?;
        argon2
            .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
            .map_err(|e| format!("argon2_derivation_failed: {e}"))?;

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // 2️⃣ Decodifica nonce e ciphertext
        let nonce_bytes = general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|_| "nonce_b64_invalid".to_string())?;
        if nonce_bytes.len() != 12 {
            return Err("nonce_len_invalid".to_string());
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = general_purpose::STANDARD
            .decode(&self.encrypted_key)
            .map_err(|_| "ciphertext_b64_invalid".to_string())?;

        // 3️⃣ Decifra
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "decrypt_failed".to_string())
    }

    /// Compat/UX: ritorna None su qualsiasi errore.
    pub fn decrypt(&self, password: &str) -> Option<Vec<u8>> {
        self.decrypt_result(password).ok()
    }
}
