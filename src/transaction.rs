// in src/transaction.rs

use crate::chain_identity;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wallet::{canonical_signing_string, TransactionPayload};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    /// Fee massima che il sender è disposto a pagare per la TX
    pub max_fee_per_tx: u64,
    /// Nonce anti–replay
    pub nonce: u64,
    /// Firma ed25519 in base64 (64 byte)
    pub signature: String,
    /// Hash logico della TX (SHA-256 dei campi core)
    pub hash: String,
    /// true = coinbase / reward, esentata da verifica firma
    pub is_coinbase: bool,
    /// Memo opzionale lato utente (ancora poco usato)
    pub memo: Option<String>,
}

impl Transaction {
    /// Costruttore “ufficiale” v2.
    ///
    /// NOTA: molti path interni per ora passano `max_fee_per_tx = 0` e `memo = None`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: String,
        receiver: String,
        amount: u64,
        nonce: u64,
        max_fee_per_tx: u64,
        signature: String,
        is_coinbase: bool,
        memo: Option<String>,
    ) -> Self {
        let mut tx = Self {
            sender,
            receiver,
            amount,
            max_fee_per_tx,
            nonce,
            signature,
            hash: String::new(),
            is_coinbase,
            memo,
        };
        tx.hash = tx.calculate_hash();
        tx
    }

    /// Calcola l'hash SHA-256 **canonico** della TX.
    ///
    /// Questo hash è il vero "txid" logico e deve:
    /// - essere deterministico,
    /// - includere tutti i campi di consenso (amount/nonce/fee/memo...),
    /// - essere stabile tra nodi.
    ///
    /// Nota: NON includiamo `signature` nell'hash: la firma prova autenticità,
    /// mentre l’identità della TX resta legata al payload.
    pub fn calculate_hash(&self) -> String {
        let memo_str = match &self.memo {
            Some(m) => m.as_str(),
            None => "",
        };

        // Domain separation + network id (anti-replay cross-chain)
        // Per una mainnet “vera” il network_id ideale è un parametro di chain o un campo TX;
        // intanto usiamo il NETWORK_ID canonico del core.
        let mut hasher = Sha256::new();
        hasher.update(b"NEWGEN_TX_V2|");
        hasher.update(chain_identity::network_id().as_bytes());
        hasher.update(b"|");

        hasher.update(self.sender.as_bytes());
        hasher.update(b"|");
        hasher.update(self.receiver.as_bytes());
        hasher.update(b"|");
        hasher.update(self.amount.to_be_bytes());
        hasher.update(b"|");
        hasher.update(self.max_fee_per_tx.to_be_bytes());
        hasher.update(b"|");
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(b"|");
        hasher.update(if self.is_coinbase { b"1" } else { b"0" });
        hasher.update(b"|");
        hasher.update(memo_str.as_bytes());

        format!("{:x}", hasher.finalize())
    }

    /// Verifica la firma con lo **schema canonico** TransactionPayload v2.
    ///
    /// - per le TX coinbase ritorna sempre true (non sono firmate)
    /// - per le altre:
    ///   ricostruisce il payload → canonical_signing_string → verifica con ed25519.
    pub fn verify_signature(&self) -> bool {
        if self.is_coinbase {
            return true;
        }

        // 1) Decodifica la chiave pubblica (sender) da base64
        let pk_bytes = match STANDARD.decode(&self.sender) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let pk_array: &[u8; 32] = match pk_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false, // lunghezza chiave non valida
        };

        let pubkey = match VerifyingKey::from_bytes(pk_array) {
            Ok(pk) => pk,
            Err(_) => return false, // byte chiave non validi
        };

        // 2) Decodifica la firma da base64
        let sig_bytes = match STANDARD.decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig_array: &[u8; 64] = match sig_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false, // lunghezza firma non valida
        };

        let signature = Signature::from_bytes(sig_array);

        // 3) Ricostruisci il payload canonico.
        //
        // NOTA: qui usiamo:
        // - network_id fisso (NETWORK_ID)
        // - from = self.sender
        // - to   = self.receiver
        // - amount, nonce, memo, max_fee_per_tx
        //
        // Deve essere coerente con quello che fanno il wallet v2 e l'API /submit_signed.
        let payload = TransactionPayload {
            network_id: chain_identity::network_id().to_string(),
            from: self.sender.clone(),
            to: self.receiver.clone(),
            amount: self.amount,
            max_fee_per_tx: self.max_fee_per_tx,
            nonce: self.nonce,
            memo: self.memo.clone(),
        };

        let msg = canonical_signing_string(&payload);

        // 4) Verifica crittografica
        pubkey.verify_strict(msg.as_bytes(), &signature).is_ok()
    }
}
