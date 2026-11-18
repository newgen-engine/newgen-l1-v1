use crate::cognitive_chain::CognitiveTxV1;
use crate::finality_bft::FinalityBftCertV1;
use crate::governance::GovernanceTx;
use crate::nft::NftEventV1;
use crate::ngbin;
use crate::transaction::Transaction;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum BlockEvidenceV1 {
    /// Proposer equivocation evidence: same (epoch,slot,round,height,prev_hash) but two different
    /// block hashes, both signed (pos_proof) by the same proposer key.
    DoublePropose {
        epoch: u64,
        height: u64,
        slot: u64,
        round: u32,
        proposer_pk_any: String,
        prev_hash: String,
        block_hash_a: String,
        proof_a_b64: String,
        block_hash_b: String,
        proof_b_b64: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,

    /// Merkle root delle TX utente (leaf=SHA256(0x00||txid), node=SHA256(0x01||L||R), odd=promote last)
    /// Usata per light client (proof di inclusione TX).
    #[serde(default)]
    pub tx_root: String,
    #[serde(default)]
    pub state_root: String,

    pub miner_pub_key: String,
    pub signature: Option<Vec<u8>>,

    /// TX di governance associate a questo blocco (proposte / voti)
    #[serde(default)]
    pub governance_txs: Vec<GovernanceTx>,

    /// TX cognitive associate a questo blocco (anchor / dispute / revoke / supersede).
    #[serde(default)]
    pub cognitive_txs: Vec<CognitiveTxV1>,

    // ----------------------------------------------------------
    // Phase 3A — PoS proposer proof (seed-based leader election)
    // ----------------------------------------------------------
    /// Epoch (height / epoch_len) usata per l'elezione del proposer.
    #[serde(default)]
    pub pos_epoch: u64,
    /// Slot (derivato da timestamp/genesis_time/slot_secs) usato per l'elezione.
    #[serde(default)]
    pub pos_slot: u64,
    /// Round/view del consenso per lo slot (0=default, incrementa su timeout).
    #[serde(default)]
    pub pos_round: u32,
    /// Firma Ed25519 del proposer su un messaggio domain-separated che include
    /// seed, epoch, slot, round e hash del blocco (proof of election).
    #[serde(default)]
    pub pos_proof: Option<Vec<u8>>,

    // ----------------------------------------------------------
    // Phase 3B — Finality Gadget (QC per il parent, opzionale)
    // ----------------------------------------------------------
    /// Certificato compatto (bitset + firme) che finalizza il blocco precedente.
    /// Opzionale: se assente, la finality può laggare.
    #[serde(default)]
    pub finality_qc: Option<FinalityBftCertV1>,

    // ----------------------------------------------------------
    // Phase 4 — Evidence (consensus-critical slashing)
    // ----------------------------------------------------------
    #[serde(default)]
    pub evidence: Vec<BlockEvidenceV1>,

    /// NFT events emitted by successful state transitions in this block.
    /// These are not parsed from tx memo; validators recompute them from the same state transition
    /// that produces `state_root` and reject mismatches on incoming blocks.
    #[serde(default)]
    pub nft_events: Vec<NftEventV1>,
}

#[derive(Debug, Clone)]
pub enum BlockBuildError {
    TxHashMismatch { index: usize },
    Internal(String),
}

// -----------------------------
// TX Merkle root (Step 58 light client)
// leaf = SHA256(0x00 || txid)
// node = SHA256(0x01 || left || right)
// odd handling: promote last (RFC6962-style)
// -----------------------------
fn sha256_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn merkle_leaf(txid: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[&[0x00], txid])
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[&[0x01], left, right])
}

fn empty_tx_root_v1() -> [u8; 32] {
    // Root deterministica per blocchi senza TX utente
    sha256_concat(&[b"NG_TX_ROOT_EMPTY_V1"])
}

fn txid_bytes_from_tx(tx: &Transaction) -> Result<[u8; 32], BlockBuildError> {
    // Non fidarti di tx.hash: ricalcola sempre dal payload canonico
    let txid_hex = tx.calculate_hash();

    let raw = hex::decode(&txid_hex).map_err(|e| {
        BlockBuildError::Internal(format!("txid hex decode failed: {e} (txid={})", txid_hex))
    })?;

    if raw.len() != 32 {
        return Err(BlockBuildError::Internal(format!(
            "txid hash len != 32: got {} (txid={})",
            raw.len(),
            txid_hex
        )));
    }

    let mut a = [0u8; 32];
    a.copy_from_slice(&raw[..32]);
    Ok(a)
}

fn tx_root_hex_from_transactions(txs: &[Transaction]) -> Result<String, BlockBuildError> {
    if txs.is_empty() {
        return Ok(hex::encode(empty_tx_root_v1()));
    }

    // leaves = SHA256(0x00 || txid_bytes)
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    for t in txs {
        let txid = txid_bytes_from_tx(t)?; // <-- QUI il ? professionale
        level.push(merkle_leaf(&txid));
    }

    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;

        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
            } else {
                // odd: promote last
                next.push(level[i]);
            }
            i += 2;
        }

        level = next;
    }

    Ok(hex::encode(level[0]))
}

impl Block {
    /// Costruzione STRICT (world-grade) per input non fidato:
    /// - Se `tx.hash` è vuoto -> lo calcola (campo derivato mancante)
    /// - Se `tx.hash` è presente ma diverso dal calcolato -> ERRORE (tampering/bug)
    pub fn try_new(
        index: u64,
        timestamp: u64,
        previous_hash: String,
        mut transactions: Vec<Transaction>,
    ) -> Result<Self, BlockBuildError> {
        for (i, tx) in transactions.iter_mut().enumerate() {
            let expected = tx.calculate_hash();

            if tx.hash.is_empty() {
                tx.hash = expected;
            } else if tx.hash != expected {
                return Err(BlockBuildError::TxHashMismatch { index: i });
            }
        }

        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: String::new(),
            signature: None,
            governance_txs: Vec::new(),
            cognitive_txs: Vec::new(),
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: Vec::new(),
            nft_events: Vec::new(),
        };

        block.tx_root = tx_root_hex_from_transactions(&block.transactions)?;
        block.hash = block.calculate_hash();
        Ok(block)
    }

    /// Costruttore compatibile (usato internamente dal nodo).
    /// In mondo reale: se qui fallisce, è un bug interno e deve esplodere subito.
    pub fn build_local(
        index: u64,
        timestamp: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
    ) -> Result<Self, BlockBuildError> {
        // Path usato dal miner: input "interno", ma vogliamo comunque essere resilienti a tx.hash stale.
        // 1) prova strict
        match Self::try_new(
            index,
            timestamp,
            previous_hash.clone(),
            transactions.clone(),
        ) {
            Ok(b) => Ok(b),
            Err(BlockBuildError::TxHashMismatch { .. }) => {
                // 2) normalizza: svuota tx.hash e riprova (ricalcolo deterministico)
                let mut txs = transactions;
                for tx in txs.iter_mut() {
                    tx.hash.clear();
                }
                Self::try_new(index, timestamp, previous_hash, txs)
            }
            Err(e) => Err(e),
        }
    }

    /// Costruttore compatibile (legacy).
    ///
    /// ⚠️ Nessun fallback a blocco vuoto: se fallisce è un bug interno/consenso e deve essere visibile.
    pub fn new(
        index: u64,
        timestamp: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
    ) -> Self {
        Self::build_local(index, timestamp, previous_hash, transactions).unwrap_or_else(|e| {
            panic!("BLOCK BUILD FAILED (no fallback): {:?}", e);
        })
    }

    /// Hash deterministico del blocco (commit reale del contenuto).
    ///
    /// Nota: per robustezza world-grade usiamo `tx.calculate_hash()` e non `tx.hash`.
    /// Questo evita che un tx.hash “mentito” possa influenzare l’hash del blocco.
    pub fn try_calculate_hash(&self) -> Result<String, String> {
        let tx_root = if !self.tx_root.is_empty() {
            self.tx_root.clone()
        } else {
            tx_root_hex_from_transactions(&self.transactions)
                .map_err(|e| format!("tx_root recompute failed: {:?}", e))?
        };

        let state_root = if self.state_root.is_empty() {
            "0"
        } else {
            self.state_root.as_str()
        };

        ngbin::try_header_hash_hex_v1(
            self.index,
            self.timestamp,
            &self.previous_hash,
            &tx_root,
            state_root,
            &self.governance_txs,
            &self.cognitive_txs,
            &self.miner_pub_key,
        )
    }

    /// Helper fail-fast per path interni trusted.
    /// I path runtime/validation devono preferire `try_calculate_hash()`.
    pub(crate) fn calculate_hash(&self) -> String {
        self.try_calculate_hash()
            .unwrap_or_else(|e| panic!("BLOCK HASH CALCULATION FAILED: {}", e))
    }

    /// Firma il blocco con la chiave del validator.
    pub fn sign(&mut self, keypair: &SigningKey) {
        self.miner_pub_key = hex::encode(keypair.verifying_key().to_bytes());
        self.hash = self.calculate_hash();
        let sig = keypair.sign(self.hash.as_bytes());
        self.signature = Some(sig.to_bytes().to_vec());
    }

    /// Verifica la firma del blocco (sul suo `self.hash` corrente).
    pub fn verify_signature(&self) -> bool {
        let sig_bytes = match &self.signature {
            Some(s) => s,
            None => return false,
        };
        if sig_bytes.len() != 64 {
            return false;
        }

        let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_array);

        let pub_bytes_vec = match hex::decode(&self.miner_pub_key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if pub_bytes_vec.len() != 32 {
            return false;
        }

        let pub_array: [u8; 32] = match pub_bytes_vec.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let vk = match VerifyingKey::from_bytes(&pub_array) {
            Ok(v) => v,
            Err(_) => return false,
        };

        vk.verify_strict(self.hash.as_bytes(), &signature).is_ok()
    }

    /// Verifica integrità + firma:
    /// - ricalcola hash e confronta con `self.hash`
    /// - verifica firma sullo hash corrente
    pub fn verify_integrity_and_signature(&self) -> bool {
        match self.try_calculate_hash() {
            Ok(h) if h == self.hash => self.verify_signature(),
            _ => false,
        }
    }

    pub fn try_size_bytes(&self) -> Result<usize, String> {
        crate::ngbin::try_block_size_bytes_v3(self).map(|v| v.max(1))
    }

    /// Size bytes (utile per limiti anti-spam / block size policy)
    /// Helper fail-fast per path interni trusted.
    /// I path runtime/validation devono preferire `try_size_bytes()`.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn size_bytes(&self) -> usize {
        self.try_size_bytes()
            .unwrap_or_else(|e| panic!("BLOCK SIZE CALCULATION FAILED: {}", e))
    }
}

impl Default for Block {
    fn default() -> Self {
        Self {
            index: 0,
            timestamp: 0,
            transactions: Vec::new(),
            previous_hash: String::from("0"),
            hash: String::from("0"),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: String::from("miner_dummy"),
            signature: None,
            governance_txs: Vec::new(),
            cognitive_txs: Vec::new(),
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: Vec::new(),
            nft_events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod block7_nft_event_compat_tests {
    use super::*;

    #[test]
    fn legacy_block_json_without_nft_events_defaults_empty_vec() {
        let raw = serde_json::json!({
            "index": 42,
            "timestamp": 123456,
            "transactions": [],
            "previous_hash": "prev",
            "hash": "hash",
            "tx_root": "",
            "state_root": "",
            "miner_pub_key": "MINER",
            "signature": null,
            "governance_txs": [],
            "cognitive_txs": [],
            "pos_epoch": 0,
            "pos_slot": 0,
            "pos_round": 0,
            "pos_proof": null,
            "finality_qc": null,
            "evidence": []
        });
        let block: Block = serde_json::from_value(raw).expect("legacy block must deserialize");
        assert!(block.nft_events.is_empty());
    }
}
