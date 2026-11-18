use sha2::{Digest, Sha256};

use crate::transaction::Transaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

fn sha256_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

// RFC6962-style: leaf = SHA256(0x00 || txid), node = SHA256(0x01 || left || right)
fn hash_leaf(txid: &[u8; 32]) -> [u8; 32] {
    sha256_chunks(&[&[0x00], txid])
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_chunks(&[&[0x01], left, right])
}

fn empty_root() -> [u8; 32] {
    // Deterministico e “versionato” per evitare ambiguità future
    sha256_chunks(&[b"NG_TX_ROOT_EMPTY_V1"])
}

pub fn txid_bytes_from_tx(tx: &Transaction) -> [u8; 32] {
    let hex = if !tx.hash.is_empty() {
        tx.hash.clone()
    } else {
        tx.calculate_hash()
    };

    let raw = match hex::decode(&hex) {
        Ok(r) if r.len() == 32 => r,
        _ => {
            // Se tx.hash è malformato (attacco / input sporco), ignora e ricalcola
            let expected = tx.calculate_hash();
            match hex::decode(&expected) {
                Ok(r) if r.len() == 32 => r,
                _ => {
                    let public_mode = crate::runtime_mode::public_mode_enabled();
                    if public_mode {
                        panic!(
                            "txid_bytes_from_tx: cannot decode recalculated tx hash (unexpected)"
                        );
                    }
                    ng_error_throttle!(
                        key: "merkle.txid.fallback",
                        every_ms: 5000,
                        target: "merkle",
                        "txid_bytes_from_tx: fallback to zeros (unexpected)"
                    );
                    return [0u8; 32];
                } // fallback estremo
            }
        }
    };

    let mut a = [0u8; 32];
    a.copy_from_slice(&raw[..32]);
    a
}

pub fn txids_from_transactions(txs: &[Transaction]) -> Vec<[u8; 32]> {
    txs.iter().map(txid_bytes_from_tx).collect()
}

pub fn merkle_root_from_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return empty_root();
    }

    let mut level: Vec<[u8; 32]> = txids.iter().map(hash_leaf).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;

        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_node(&level[i], &level[i + 1]));
            } else {
                // RFC6962: se dispari, l’ultimo “sale” invariato
                next.push(level[i]);
            }
            i += 2;
        }

        level = next;
    }

    level[0]
}

pub fn merkle_proof_from_txids(txids: &[[u8; 32]], mut index: usize) -> Vec<(Side, [u8; 32])> {
    if txids.is_empty() {
        return vec![];
    }

    let mut proof: Vec<(Side, [u8; 32])> = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.iter().map(hash_leaf).collect();

    while level.len() > 1 {
        if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                proof.push((Side::Right, level[index + 1]));
            }
        } else {
            proof.push((Side::Left, level[index - 1]));
        }

        // next level
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_node(&level[i], &level[i + 1]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }

        level = next;
        index /= 2;
    }

    proof
}

pub fn tx_root_hex_from_transactions(txs: &[Transaction]) -> String {
    let txids = txids_from_transactions(txs);
    hex::encode(merkle_root_from_txids(&txids))
}
