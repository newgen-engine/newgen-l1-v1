// ===================================
// FILE: src/indexer_stream.rs
// NewGen Engine™ — Data Bridge (Indexer SQL)
// -----------------------------------
// TCP JSONL stream (newline-delimited JSON) for external indexers.
//
// Mainnet-grade hardening included:
// - Optional shared-secret token (required if configured).
// - Bounded catch-up replay on connect (last N blocks).
// - If a client lags (drops messages), the connection is closed (prevents SQL corruption).
//
// Wire schema is STABLE and decoupled from internal Block/Tx structs.
// Messages:
//   Client -> server:
//     {"type":"hello","last_height":123,"token":"..."}
//   Server -> client:
//     {"type":"hello","chain_id":"...","protocol_version":3,"tip_height":200,"oldest_height":50,"ts_ms":...}
//     {"type":"commit","block":{...}}
//     {"type":"rollback","to_height":198}
//     {"type":"need_snapshot","oldest_height":50}
//     {"type":"error","message":"..."}
// -----------------------------------

use crate::{block::Block, chain_identity, ft, nft, version};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

const BROADCAST_CAP: usize = 4096;
const HANDSHAKE_TIMEOUT_SECS: u64 = 3;
const MAX_HANDSHAKE_LINE_BYTES: usize = 8 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IndexerMsg {
    Hello {
        #[serde(skip_serializing_if = "Option::is_none")]
        chain_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol_version: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tip_height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        oldest_height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        ts_ms: u64,
    },
    Commit {
        block: WireBlock,
    },
    Rollback {
        to_height: u64,
    },
    NeedSnapshot {
        oldest_height: u64,
    },
    Error {
        message: String,
    },
}

/// Stable wire block schema (expected by external SQL indexers).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireBlock {
    height: u64,
    hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_hash: Option<String>,
    timestamp_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer: Option<String>,
    #[serde(default)]
    txs: Vec<WireTx>,
    #[serde(default)]
    events: Vec<WireEvent>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireTx {
    hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>, // numeric string
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<String>, // numeric string
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ft: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nft: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nft_events: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug)]
struct Backlog {
    base_height: u64,
    tip_height: u64,
    commits: VecDeque<(u64, String)>,
    max_blocks: usize,
}

impl Backlog {
    fn new(max_blocks: usize) -> Self {
        Self {
            base_height: 0,
            tip_height: 0,
            commits: VecDeque::new(),
            max_blocks: max_blocks.max(100),
        }
    }

    fn oldest_height(&self) -> u64 {
        if self.commits.is_empty() {
            0
        } else {
            self.base_height
        }
    }

    fn tip_height(&self) -> u64 {
        if self.commits.is_empty() {
            0
        } else {
            self.tip_height
        }
    }

    fn reset_to_single(&mut self, height: u64, line: String) {
        self.commits.clear();
        self.base_height = height;
        self.tip_height = height;
        self.commits.push_back((height, line));
    }

    fn push_commit(&mut self, height: u64, line: String) {
        if self.commits.is_empty() {
            self.reset_to_single(height, line);
            return;
        }

        let expected_next = self.tip_height.saturating_add(1);
        if height == expected_next {
            self.tip_height = height;
            self.commits.push_back((height, line));
        } else if height <= self.tip_height {
            // duplicate/replay, ignore in backlog
        } else {
            // discontinuity: reset backlog to avoid gaps
            self.reset_to_single(height, line);
        }

        while self.commits.len() > self.max_blocks {
            self.commits.pop_front();
            self.base_height = self.base_height.saturating_add(1);
        }
    }

    fn apply_rollback(&mut self, to_height: u64) {
        if self.commits.is_empty() {
            self.base_height = to_height.saturating_add(1);
            self.tip_height = to_height;
            return;
        }

        // rollback before our window: clear
        if to_height + 1 < self.base_height {
            self.commits.clear();
            self.base_height = to_height.saturating_add(1);
            self.tip_height = to_height;
            return;
        }

        while let Some((h, _)) = self.commits.back() {
            if *h > to_height {
                self.commits.pop_back();
            } else {
                break;
            }
        }

        if let Some((h, _)) = self.commits.back() {
            self.tip_height = *h;
        } else {
            self.base_height = to_height.saturating_add(1);
            self.tip_height = to_height;
        }
    }

    fn replay_from(&self, from_height: u64) -> Vec<String> {
        if self.commits.is_empty() {
            return vec![];
        }
        let start = from_height.max(self.base_height);
        self.commits
            .iter()
            .filter(|(h, _)| *h >= start)
            .map(|(_, line)| line.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct IndexerPublisher {
    tx: broadcast::Sender<String>,
    backlog: Arc<Mutex<Backlog>>,
    token: Option<String>,
}

impl IndexerPublisher {
    pub fn seed_from_chain(&self, chain: &[Block]) {
        let mut bl = self.backlog.lock().unwrap_or_else(|e| e.into_inner());
        bl.commits.clear();
        bl.base_height = 0;
        bl.tip_height = 0;

        if chain.is_empty() {
            return;
        }

        let max = bl.max_blocks;
        let start = chain.len().saturating_sub(max);
        for b in &chain[start..] {
            let msg = IndexerMsg::Commit {
                block: to_wire_block(b),
            };
            match serde_json::to_string(&msg) {
                Ok(line) => bl.push_commit(b.index, line),
                Err(e) => {
                    ng_error!(target:"indexer_stream", "serialize commit seed failed at height {}: {}", b.index, e)
                }
            }
        }
    }

    pub fn emit_commit(&self, block: &Block) {
        let msg = IndexerMsg::Commit {
            block: to_wire_block(block),
        };
        match serde_json::to_string(&msg) {
            Ok(line) => {
                {
                    let mut bl = self.backlog.lock().unwrap_or_else(|e| e.into_inner());
                    bl.push_commit(block.index, line.clone());
                }
                let _ = self.tx.send(line);
            }
            Err(e) => {
                ng_error!(target:"indexer_stream", "serialize commit failed at height {}: {}", block.index, e)
            }
        }
    }

    pub fn emit_rollback(&self, to_height: u64) {
        {
            let mut bl = self.backlog.lock().unwrap_or_else(|e| e.into_inner());
            bl.apply_rollback(to_height);
        }
        let msg = IndexerMsg::Rollback { to_height };
        match serde_json::to_string(&msg) {
            Ok(line) => {
                let _ = self.tx.send(line);
            }
            Err(e) => {
                ng_error!(target:"indexer_stream", "serialize rollback failed to_height {}: {}", to_height, e)
            }
        }
    }

    pub fn emit_error(&self, message: impl Into<String>) {
        let msg = IndexerMsg::Error {
            message: message.into(),
        };
        match serde_json::to_string(&msg) {
            Ok(line) => {
                let _ = self.tx.send(line);
            }
            Err(e) => ng_error!(target:"indexer_stream", "serialize error msg failed: {}", e),
        }
    }
}

/// Spawn TCP JSONL server. Returns a publisher handle that can be called from consensus code.
pub async fn spawn_indexer_stream(
    bind: &str,
    token: Option<String>,
    max_backlog_blocks: usize,
) -> std::io::Result<IndexerPublisher> {
    // Mainnet hardening: in public_mode, if binding to a non-loopback address,
    // require an explicit shared-secret token to avoid accidental exposure.
    let public_mode = crate::runtime_mode::public_mode_enabled();

    if public_mode && token.is_none() {
        if let Ok(sa) = bind.parse::<std::net::SocketAddr>() {
            if !sa.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "indexer token required in public mode for non-loopback bind",
                ));
            }
        }
    }

    let listener = TcpListener::bind(bind).await?;

    let (tx, _rx) = broadcast::channel::<String>(BROADCAST_CAP);
    let publisher = IndexerPublisher {
        tx: tx.clone(),
        backlog: Arc::new(Mutex::new(Backlog::new(max_backlog_blocks))),
        token,
    };

    let publisher_for_accept = publisher.clone();

    // accept loop
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let pub_for_client = publisher_for_accept.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_client(stream, addr.to_string(), pub_for_client).await
                        {
                            ng_warn!(target:"indexer_stream", "client {} closed: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    ng_error!(target:"indexer_stream", "accept error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(publisher)
}

async fn handle_client(
    stream: TcpStream,
    _addr: String,
    publisher: IndexerPublisher,
) -> std::io::Result<()> {
    let (r, w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut writer = BufWriter::new(w);

    // --- Handshake (optional unless token is configured) ---
    let mut line = String::new();
    let mut last_height: u64 = 0;
    let mut saw_hello = false;

    let read_res = timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        reader.read_line(&mut line),
    )
    .await;
    match read_res {
        Ok(Ok(n)) if n > 0 => {
            if line.len() <= MAX_HANDSHAKE_LINE_BYTES {
                if let Ok(IndexerMsg::Hello {
                    last_height: lh,
                    token,
                    ..
                }) = serde_json::from_str::<IndexerMsg>(line.trim())
                {
                    saw_hello = true;
                    last_height = lh.unwrap_or(0);
                    if let Some(required) = publisher.token.as_ref() {
                        if token.as_deref() != Some(required.as_str()) {
                            let err = IndexerMsg::Error {
                                message: "forbidden".to_string(),
                            };
                            let _ = write_line(&mut writer, &err).await;
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            // timeout
        }
    }

    if publisher.token.is_some() && !saw_hello {
        let err = IndexerMsg::Error {
            message: "handshake_required".to_string(),
        };
        let _ = write_line(&mut writer, &err).await;
        return Ok(());
    }

    let (tip_height, oldest_height, replay_lines) = {
        let bl = publisher.backlog.lock().unwrap_or_else(|e| e.into_inner());
        let tip = bl.tip_height();
        let oldest = bl.oldest_height();
        let replay = bl.replay_from(last_height.saturating_add(1));
        (tip, oldest, replay)
    };

    // Per-connection server hello
    let hello = IndexerMsg::Hello {
        chain_id: Some(chain_identity::chain_id().to_string()),
        protocol_version: Some(version::PROTOCOL_VERSION as i32),
        tip_height: Some(tip_height),
        oldest_height: Some(oldest_height),
        last_height: None,
        token: None,
        ts_ms: now_ms(),
    };
    write_line(&mut writer, &hello).await?;

    if oldest_height > 0 && last_height.saturating_add(1) < oldest_height {
        let need = IndexerMsg::NeedSnapshot { oldest_height };
        let _ = write_line(&mut writer, &need).await;
    }

    for l in replay_lines {
        writer.write_all(l.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;

    let mut rx = publisher.tx.subscribe();

    loop {
        match rx.recv().await {
            Ok(out) => {
                writer.write_all(out.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
            Err(broadcast::error::RecvError::Lagged(dropped)) => {
                // Missing commits would corrupt SQL state; force reconnect.
                let err = IndexerMsg::Error {
                    message: format!("lagged: dropped {} messages; reconnect required", dropped),
                };
                let _ = write_line(&mut writer, &err).await;
                return Ok(());
            }
        }
    }
}

async fn write_line(
    writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    msg: &IndexerMsg,
) -> std::io::Result<()> {
    if let Ok(line) = serde_json::to_string(msg) {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

fn to_wire_block(block: &Block) -> WireBlock {
    let parent_hash = if block.previous_hash.is_empty() {
        None
    } else {
        Some(block.previous_hash.clone())
    };

    let producer = if block.miner_pub_key.is_empty() {
        None
    } else {
        Some(block.miner_pub_key.clone())
    };

    let mut events = Vec::new();
    let txs = block
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let fee_u64 = if tx.is_coinbase { 0 } else { tx.max_fee_per_tx };
            let ft_receipt = match ft::ft_receipt_json_v1(tx) {
                Ok(v) => v,
                Err(e) => {
                    ng_warn!(target:"indexer_stream", "ft receipt decode failed for tx {}: {}", tx.hash, e);
                    None
                }
            };
            let nft_events_for_tx = nft::nft_events_for_tx_v1(&block.nft_events, &tx.hash, i as u32);
            let mut nft_event_values: Vec<Value> = Vec::with_capacity(nft_events_for_tx.len());
            for ev in nft_events_for_tx {
                match nft::nft_event_json_v1(ev) {
                    Ok(v) => nft_event_values.push(v),
                    Err(e) => ng_warn!(target:"indexer_stream", "nft event encode failed for tx {}: {}", tx.hash, e),
                }
            }
            let nft_receipt = nft_event_values.first().cloned();

            if let Some(data) = ft_receipt.clone() {
                let kind = data
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("ft_unknown".to_string()));
                events.push(WireEvent {
                    kind,
                    tx_hash: Some(tx.hash.clone()),
                    data: Some(data.clone()),
                });
            }
            for data in nft_event_values.iter().cloned() {
                let kind = data
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("nft_unknown".to_string()));
                events.push(WireEvent {
                    kind,
                    tx_hash: Some(tx.hash.clone()),
                    data: Some(data),
                });
            }

            WireTx {
                hash: tx.hash.clone(),
                index: Some(i as u32),
                from_addr: Some(tx.sender.clone()),
                to_addr: Some(tx.receiver.clone()),
                amount: Some(tx.amount.to_string()),
                fee: Some(fee_u64.to_string()),
                nonce: Some(tx.nonce),
                memo: tx.memo.clone(),
                status: Some(if tx.is_coinbase { "coinbase" } else { "ok" }.to_string()),
                raw: serde_json::to_value(tx).ok(),
                ft: ft_receipt,
                nft: nft_receipt,
                nft_events: nft_event_values,
            }
        })
        .collect::<Vec<_>>();

    WireBlock {
        height: block.index,
        hash: block.hash.clone(),
        parent_hash,
        timestamp_ms: block.timestamp.saturating_mul(1000),
        producer,
        txs,
        events,
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn to_wire_block_includes_ft_receipt_and_event() {
        let memo = serde_json::to_string(&serde_json::json!({
            "v": 1,
            "ctx": crate::ft::CTX_FT_TRANSFER,
            "op": "transfer",
            "token_id": 7,
            "to": "BOB",
            "amount": "55"
        }))
        .unwrap();

        let tx = Transaction::new(
            "ALICE".to_string(),
            crate::ft::FT_RECEIVER.to_string(),
            0,
            1,
            3,
            String::new(),
            false,
            Some(memo),
        );

        let block = Block {
            index: 9,
            timestamp: 123,
            transactions: vec![tx.clone()],
            previous_hash: "prev".to_string(),
            hash: "hash".to_string(),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: "MINER".to_string(),
            signature: None,
            governance_txs: vec![],
            cognitive_txs: vec![],
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: vec![],
            nft_events: vec![],
        };

        let wb = to_wire_block(&block);
        assert_eq!(wb.txs.len(), 1);
        let ft = wb.txs[0].ft.as_ref().expect("ft receipt must exist");
        assert_eq!(ft.get("kind").and_then(|v| v.as_str()), Some("ft_transfer"));
        assert_eq!(ft.get("token_id").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(wb.events.len(), 1);
        assert_eq!(wb.events[0].kind.as_deref(), Some("ft_transfer"));
        assert_eq!(wb.events[0].tx_hash.as_deref(), Some(tx.hash.as_str()));
    }

    #[test]
    fn to_wire_block_does_not_synthesize_nft_events_from_memo() {
        let to_b64 = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let memo = crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Transfer {
            collection_id: 4,
            serial: 2,
            to_b64: to_b64.clone(),
        })
        .unwrap();

        let tx = Transaction::new(
            crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            3,
            String::new(),
            false,
            Some(memo),
        );

        let block = Block {
            index: 10,
            timestamp: 124,
            transactions: vec![tx],
            previous_hash: "prev".to_string(),
            hash: "hash-no-nft-events".to_string(),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: "MINER".to_string(),
            signature: None,
            governance_txs: vec![],
            cognitive_txs: vec![],
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: vec![],
            nft_events: vec![],
        };

        let wb = to_wire_block(&block);
        assert_eq!(wb.txs.len(), 1);
        assert!(wb.txs[0].nft.is_none());
        assert!(wb.txs[0].nft_events.is_empty());
        assert!(wb.events.iter().all(|ev| {
            ev.kind
                .as_deref()
                .map(|kind| !kind.starts_with("nft_"))
                .unwrap_or(true)
        }));
    }

    #[test]
    fn nft_indexer_emits_exact_events() {
        let owner = crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]);
        let to_b64 = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let mint_memo = crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Mint {
            collection_id: 1,
            to_b64: to_b64.clone(),
            token_uri: "newgen://indexer/1".to_string(),
            metadata_hash: [0x9au8; 32],
            expires_at_height: None,
        })
        .unwrap();
        let tx = Transaction::new(
            owner.clone(),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            7,
            String::new(),
            false,
            Some(mint_memo),
        );
        let mut ev = crate::nft::NftEventV1::base("nft_token_minted", "mint", 77, &tx.hash, 0);
        ev.collection_id = Some(1);
        ev.serial = Some(1);
        ev.asset_id = Some(crate::nft::nft_asset_id_v1(1, 1));
        ev.owner_b64 = Some(to_b64.clone());
        ev.issuer_b64 = Some(owner.clone());
        ev.token_uri = Some("newgen://indexer/1".to_string());
        ev.metadata_hash = Some("9a".repeat(32));

        let block = Block {
            index: 77,
            timestamp: 177,
            transactions: vec![tx.clone()],
            previous_hash: "prev-indexer".to_string(),
            hash: "hash-indexer".to_string(),
            tx_root: String::new(),
            state_root: "root-indexer".to_string(),
            miner_pub_key: "MINER".to_string(),
            signature: None,
            governance_txs: vec![],
            cognitive_txs: vec![],
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: vec![],
            nft_events: vec![ev.clone()],
        };

        let wb = to_wire_block(&block);
        assert_eq!(wb.events.len(), 1);
        assert_eq!(wb.events[0].kind.as_deref(), Some("nft_token_minted"));
        assert_eq!(wb.events[0].tx_hash.as_deref(), Some(tx.hash.as_str()));
        assert_eq!(wb.txs.len(), 1);
        assert_eq!(wb.txs[0].nft_events.len(), 1);
        assert_eq!(
            wb.txs[0]
                .nft
                .as_ref()
                .unwrap()
                .get("asset_id")
                .and_then(|v| v.as_str()),
            Some("nft:1:1")
        );
        assert_eq!(
            wb.txs[0]
                .nft
                .as_ref()
                .unwrap()
                .get("owner_b64")
                .and_then(|v| v.as_str()),
            Some(to_b64.as_str())
        );
        let expected_hash = "9a".repeat(32);
        assert_eq!(
            wb.txs[0].nft_events[0]
                .get("metadata_hash")
                .and_then(|v| v.as_str()),
            Some(expected_hash.as_str())
        );
    }

    #[test]
    fn to_wire_block_includes_nft_receipt_and_event() {
        let to_b64 = crate::keyfmt::pk_b64_from_bytes(&[2u8; 32]);
        let memo = crate::nft::nft_memo_json_v1(&crate::nft::NftOpV1::Transfer {
            collection_id: 4,
            serial: 2,
            to_b64: to_b64.clone(),
        })
        .unwrap();

        let tx = Transaction::new(
            crate::keyfmt::pk_b64_from_bytes(&[1u8; 32]),
            crate::nft::NFT_RECEIVER.to_string(),
            0,
            1,
            3,
            String::new(),
            false,
            Some(memo),
        );

        let mut ev =
            crate::nft::NftEventV1::base("nft_token_transferred", "transfer", 10, &tx.hash, 0);
        ev.collection_id = Some(4);
        ev.serial = Some(2);
        ev.asset_id = Some(crate::nft::nft_asset_id_v1(4, 2));
        ev.from_b64 = Some(tx.sender.clone());
        ev.to_b64 = Some(to_b64.clone());
        ev.owner_b64 = Some(to_b64.clone());

        let block = Block {
            index: 10,
            timestamp: 124,
            transactions: vec![tx.clone()],
            previous_hash: "prev".to_string(),
            hash: "hash2".to_string(),
            tx_root: String::new(),
            state_root: String::new(),
            miner_pub_key: "MINER".to_string(),
            signature: None,
            governance_txs: vec![],
            cognitive_txs: vec![],
            pos_epoch: 0,
            pos_slot: 0,
            pos_round: 0,
            pos_proof: None,
            finality_qc: None,
            evidence: vec![],
            nft_events: vec![ev],
        };

        let wb = to_wire_block(&block);
        assert_eq!(wb.txs.len(), 1);
        let nft = wb.txs[0].nft.as_ref().expect("nft receipt must exist");
        assert_eq!(
            nft.get("kind").and_then(|v| v.as_str()),
            Some("nft_token_transferred")
        );
        assert_eq!(nft.get("collection_id").and_then(|v| v.as_u64()), Some(4));
        assert_eq!(wb.events.len(), 1);
        assert_eq!(wb.txs[0].nft_events.len(), 1);
        assert_eq!(wb.events[0].kind.as_deref(), Some("nft_token_transferred"));
        assert_eq!(wb.events[0].tx_hash.as_deref(), Some(tx.hash.as_str()));
    }
}
