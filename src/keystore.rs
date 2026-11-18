use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub enum KeyRole {
    P2PIdentity,      // libp2p Keypair protobuf bytes
    ValidatorSigning, // ed25519 secret key bytes (32)
    WalletCA,         // ed25519 secret key bytes (32) - opzionale/offline
}

impl KeyRole {
    fn as_str(&self) -> &'static str {
        match self {
            KeyRole::P2PIdentity => "p2p_identity",
            KeyRole::ValidatorSigning => "validator_signing",
            KeyRole::WalletCA => "wallet_ca",
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct KdfParamsJson {
    // Stored as MiB for readability; converted to KiB for Argon2 Params.
    #[serde(rename = "m_cost_kib", alias = "m_cost_kib")]
    m_cost_mib: u32,
    t_cost: u32,
    p_cost: u32,
    salt_b64: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SealedEntry {
    role: String,
    public_key_b64: Option<String>, // utile per audit (no segreto)
    kdf: KdfParamsJson,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct KeystoreFile {
    version: u32,
    entries: HashMap<String, SealedEntry>,
}

#[derive(Debug)]
pub enum KeystoreError {
    Io(String),
    Json(String),
    MissingPassphrase,
    MissingEntry(String),
    Crypto(String),
    Policy(String),
}

fn keystore_default_path() -> PathBuf {
    // per i tuoi RUN_A/RUN_B ecc: CWD è già la cartella del nodo
    // usa secrets/keystore.json se esiste la dir, altrimenti keystore.json
    let p1 = PathBuf::from("secrets/keystore.json");
    if p1.parent().map(|d| d.exists()).unwrap_or(false) {
        p1
    } else {
        PathBuf::from("keystore.json")
    }
}

fn passphrase_from_env() -> Result<Zeroizing<String>, KeystoreError> {
    if let Ok(pass) = std::env::var("NEWGEN_KEYSTORE_PASSPHRASE") {
        let pass = pass.trim().to_string();
        if !pass.is_empty() {
            return Ok(Zeroizing::new(pass));
        }
    }

    if let Ok(path_s) = std::env::var("NEWGEN_KEYSTORE_PASSPHRASE_FILE") {
        let path = PathBuf::from(path_s);
        let txt = fs::read_to_string(&path).map_err(|e| {
            KeystoreError::Io(format!("read passphrase file {}: {e}", path.display()))
        })?;
        let pass = txt.trim().to_string();
        if !pass.is_empty() {
            return Ok(Zeroizing::new(pass));
        }
        return Err(KeystoreError::Policy(format!(
            "empty passphrase file: {}",
            path.display()
        )));
    }

    Err(KeystoreError::MissingPassphrase)
}

fn argon2_from_params(kdf: &KdfParamsJson) -> Result<Argon2<'static>, KeystoreError> {
    let params = Params::new(
        kdf.m_cost_mib.saturating_mul(1024),
        kdf.t_cost,
        kdf.p_cost,
        Some(32),
    )
    .map_err(|e| KeystoreError::Crypto(format!("argon2 params: {e}")))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn derive_key(pass: &str, kdf: &KdfParamsJson) -> Result<[u8; 32], KeystoreError> {
    let salt = STANDARD
        .decode(&kdf.salt_b64)
        .map_err(|e| KeystoreError::Crypto(format!("salt b64 decode: {e}")))?;
    let a2 = argon2_from_params(kdf)?;
    let mut out = [0u8; 32];
    a2.hash_password_into(pass.as_bytes(), &salt, &mut out)
        .map_err(|e| KeystoreError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(out)
}

fn seal(
    pass: &str,
    plaintext: &[u8],
    public_key_b64: Option<String>,
) -> Result<SealedEntry, KeystoreError> {
    // Parametri KDF “ragionevoli” per baseline (tarabili)
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let kdf = KdfParamsJson {
        m_cost_mib: 64, // 64 MiB
        t_cost: 2,
        p_cost: 1,
        salt_b64: STANDARD.encode(salt),
    };

    let key = derive_key(pass, &kdf)?;
    let aead = XChaCha20Poly1305::new((&key).into());

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    #[allow(deprecated)]
    let xnonce = XNonce::clone_from_slice(&nonce);
    let ct = aead
        .encrypt(&xnonce, plaintext)
        .map_err(|e| KeystoreError::Crypto(format!("encrypt: {e}")))?;

    Ok(SealedEntry {
        role: "unset".to_string(), // sovrascritto dal caller
        public_key_b64,
        kdf,
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ct),
    })
}

fn open(pass: &str, entry: &SealedEntry) -> Result<Vec<u8>, KeystoreError> {
    let key = derive_key(pass, &entry.kdf)?;
    let aead = XChaCha20Poly1305::new((&key).into());

    let nonce = STANDARD
        .decode(&entry.nonce_b64)
        .map_err(|e| KeystoreError::Crypto(format!("nonce b64 decode: {e}")))?;
    let ct = STANDARD
        .decode(&entry.ciphertext_b64)
        .map_err(|e| KeystoreError::Crypto(format!("ct b64 decode: {e}")))?;

    if nonce.len() != 24 {
        return Err(KeystoreError::Crypto(format!(
            "nonce length invalid: {} (expected 24)",
            nonce.len()
        )));
    }

    #[allow(deprecated)]
    let xnonce = XNonce::clone_from_slice(&nonce);
    aead.decrypt(&xnonce, ct.as_ref())
        .map_err(|e| KeystoreError::Crypto(format!("decrypt: {e}")))
}

fn load_file(path: &Path) -> Result<KeystoreFile, KeystoreError> {
    if !path.exists() {
        return Ok(KeystoreFile {
            version: 1,
            entries: HashMap::new(),
        });
    }
    let txt = fs::read_to_string(path).map_err(|e| KeystoreError::Io(format!("{e}")))?;
    serde_json::from_str(&txt).map_err(|e| KeystoreError::Json(format!("{e}")))
}

fn save_file(path: &Path, ks: &KeystoreFile) -> Result<(), KeystoreError> {
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| KeystoreError::Io(format!("{e}")))?;
        }
    }

    let txt = serde_json::to_string_pretty(ks).map_err(|e| KeystoreError::Json(format!("{e}")))?;

    // Atomic write: temp + rename (best effort on Windows as well).
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, txt).map_err(|e| KeystoreError::Io(format!("{e}")))?;

    crate::utils::atomic_replace_file_v1(&tmp, path)
        .map_err(|e| KeystoreError::Io(format!("{e}")))?;
    Ok(())
}

/// API pubblica: path risolto da env o default
pub fn keystore_path() -> PathBuf {
    std::env::var("NEWGEN_KEYSTORE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| keystore_default_path())
}

/// Carica entry (no init). In public_mode deve esistere.
pub fn load_secret_bytes(role: KeyRole, public_mode: bool) -> Result<Vec<u8>, KeystoreError> {
    let path = keystore_path();
    let pass = passphrase_from_env()?;

    let ks = load_file(&path)?;
    let k = role.as_str().to_string();
    let entry = ks
        .entries
        .get(&k)
        .ok_or_else(|| KeystoreError::MissingEntry(k.clone()))?;

    if public_mode && entry.ciphertext_b64.is_empty() {
        return Err(KeystoreError::Policy("empty entry in public_mode".into()));
    }

    open(&pass, entry)
}

/// Inizializza una entry in modo esplicito (da tool/CLI), non chiamare in public_mode runtime.
pub fn init_entry(
    role: KeyRole,
    plaintext: &[u8],
    public_key_b64: Option<String>,
) -> Result<(), KeystoreError> {
    let path = keystore_path();
    let pass = passphrase_from_env()?;

    let mut ks = load_file(&path)?;
    let mut entry = seal(&pass, plaintext, public_key_b64)?;
    entry.role = role.as_str().to_string();
    ks.entries.insert(role.as_str().to_string(), entry);
    save_file(&path, &ks)?;
    Ok(())
}
