use crate::block::Block;
use crate::checkpoint::{CheckpointCert, CheckpointSigMsg};
use crate::finality_bft::{FinalityBftCertV1, FinalityBftVoteV1};
use serde::{Deserialize, Serialize};

/// Tutti i messaggi scambiati tra peer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetMsg {
    /// Ping periodico o diagnostico
    Ping(String),

    /// Annunci generici (già usato in passato; lo teniamo)
    Announce(String),

    /// 🔹 Handshake iniziale tra peer (Step 41 - v2)
    /// Usato per scambiarsi:
    /// - identificativo del peer
    /// - indirizzo in ascolto
    /// - height corrente
    /// - versione software / protocollo
    /// - ancoraggi anti-divergenza (chain_id / genesis_hash / validator_set_hash)
    Hello {
        peer_id: String,
        listen_addr: Option<String>,
        height: u64,
        software_version: String,
        protocol_version: u32,
        min_supported_protocol_version: u32,

        // ✅ Anti-divergenza (world-grade)
        // Option = compatibilità con peer vecchi, ma tu puoi comunque rifiutarli.
        chain_id: Option<String>,
        genesis_hash: Option<String>,
        validator_set_hash: Option<String>,
        tip_hash: Option<String>,
        finalized_height: Option<u64>,
        finalized_hash: Option<String>,

        // ✅ Phase 5 — Snapshot v2 advertise (optional, backward compatible)
        snapshot_v2_latest_height: Option<u64>,
        snapshot_v2_meta_sha256_hex: Option<String>,
        snapshot_v2_chunks: Option<u32>,
        snapshot_v2_chunk_size: Option<u32>,

        // Runtime readiness telemetry (optional, backward compatible).
        // Signed runtime telemetry is chain-bound and peer-bound.
        validator_pubkey: Option<String>,
        runtime_sync_caught_up: Option<bool>,
        runtime_bootstrap_complete: Option<bool>,
        p2p_ready_for_mining: Option<bool>,
        runtime_telemetry_ts: Option<u64>,
        runtime_telemetry_sig_b64: Option<String>,
    },

    /// Nuova transazione
    NewTx(crate::transaction::Transaction),

    /// Nuovo blocco (push diretto)
    NewBlock(Block),

    /// 🔹 Checkpoint signature gossip (Alpha)
    /// In Alpha, il receiver accetta solo se il blocco esiste già localmente.
    CheckpointSig(CheckpointSigMsg),

    /// 🔹 Checkpoint certificate gossip (Alpha)
    /// Certificato = checkpoint + firme >= quorum.
    CheckpointCert(CheckpointCert),

    /// 🔹 Phase 3B — Finality BFT vote gossip (ed25519)
    FinalityBftVote(FinalityBftVoteV1),

    /// 🔹 Phase 3B — Finality BFT certificate gossip (opzionale, acceleratore)
    FinalityBftCert(FinalityBftCertV1),

    /// 🔹 Pulse leggero e frequente: liveness / tip awareness / fork hint.
    /// Nessuna telemetria firmata qui: il path deve restare cheap in steady-state.
    PulseLight {
        height: u64,
        ts: u64,
        tip_hash: Option<String>,
    },

    /// 🔹 Pulse firmato meno frequente (full telemetry).
    /// Manteniamo il nome `Pulse` per compatibilità wire con i peer già aggiornati.
    Pulse {
        height: u64,
        ts: u64,
        tip_hash: Option<String>,
        finalized_height: Option<u64>,
        finalized_hash: Option<String>,
        peer_id: Option<String>,
        chain_id: Option<String>,
        genesis_hash: Option<String>,
        validator_set_hash: Option<String>,

        // Runtime readiness telemetry (optional, backward compatible).
        // Signed runtime telemetry is chain-bound and peer-bound.
        validator_pubkey: Option<String>,
        runtime_sync_caught_up: Option<bool>,
        runtime_bootstrap_complete: Option<bool>,
        p2p_ready_for_mining: Option<bool>,
        runtime_telemetry_sig_b64: Option<String>,
    },

    /// 🔹 Richiesta di sincronizzazione chunked (Step 32B)
    SyncRequest { from: u64, limit: u32 },

    /// 🔹 Risposta chunked con blocchi serializzati (Step 32B)
    SyncResponse { blocks: Vec<Block> },

    // 20-C — mini-protocollo di catch-up
    /// Inventario header (index, hash) — in questa fase mandiamo anche solo il tip
    Inv(Vec<(u64, String)>),

    /// Richiesta di un blocco specifico per indice
    GetBlock(u64),

    /// Risposta contenente un blocco specifico
    Block(Block),
}

/// Serializza un messaggio P2P in bytes (Result).
pub fn encode_result(msg: &NetMsg) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}

/// Serializza un messaggio P2P in bytes (legacy).
/// In caso di errore: logga e ritorna Vec vuoto (il caller dovrebbe droppare l’invio).
pub fn encode(msg: &NetMsg) -> Vec<u8> {
    match encode_result(msg) {
        Ok(v) => v,
        Err(e) => {
            ng_error!(target: "p2p.netmsg", "encode failed: {e}");
            Vec::new()
        }
    }
}

/// Deserializza un messaggio P2P da bytes
pub fn decode(data: &[u8]) -> Option<NetMsg> {
    serde_json::from_slice(data).ok()
}
