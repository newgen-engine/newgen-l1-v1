use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,

    #[serde(default)]
    pub tx_root: String,

    #[serde(default)]
    pub state_root: String,
}

impl BlockHeader {
    pub fn verify_chain(headers: &[BlockHeader]) -> bool {
        for w in headers.windows(2) {
            let a = &w[0];
            let b = &w[1];
            if b.height != a.height + 1 {
                return false;
            }
            if b.prev_hash != a.hash {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u64, hash: &str, prev_hash: &str) -> BlockHeader {
        BlockHeader {
            height,
            hash: hash.to_string(),
            prev_hash: prev_hash.to_string(),
            timestamp: 1_700_000_000 + height,
            tx_root: format!("tx-{height}"),
            state_root: format!("state-{height}"),
        }
    }

    #[test]
    fn verify_chain_accepts_linear_headers() {
        let hs = vec![
            header(0, "h0", "0"),
            header(1, "h1", "h0"),
            header(2, "h2", "h1"),
        ];
        assert!(BlockHeader::verify_chain(&hs));
    }

    #[test]
    fn verify_chain_rejects_gap_or_prev_hash_mismatch() {
        let gap = vec![header(0, "h0", "0"), header(2, "h2", "h0")];
        assert!(!BlockHeader::verify_chain(&gap));

        let mismatch = vec![header(0, "h0", "0"), header(1, "h1", "wrong")];
        assert!(!BlockHeader::verify_chain(&mismatch));
    }
}
