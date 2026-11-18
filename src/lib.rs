// src/lib.rs

#[macro_use]
pub mod logging;
pub mod chain_identity;
pub mod cognitive_chain;

pub mod indexer_stream;

pub mod error;

pub mod perf_metrics;

pub mod maintenance_params;
pub mod runtime_mode;

pub mod api;
pub mod block;
pub mod blockchain;
pub mod explorer;
pub mod finality_bft;
pub mod ft;
pub mod mempool;
pub mod netmsg;
pub mod nft;
pub mod p2p;
pub mod p2p_peerbook;
pub mod persistence;
pub mod pos;
pub mod staking;
pub mod transaction;
pub mod utils;
pub mod wallet;
pub mod wallet_secure;
pub use crate::persistence::save_blockchain;
pub mod account;
pub mod anchor_store;
pub mod checkpoint;
pub mod compute_contract;
pub mod e2_worker_evidence;
// mod db_singleton;
pub mod crypto;
pub mod governance;
pub mod governance_provider;
pub mod headers;
pub mod keyfmt;
pub mod keystore;
pub mod merkle;
pub mod ngbin;
pub mod node_paths;
pub mod peer_reputation;
pub mod protocol_ids;
pub mod reputation_score;
pub mod rr_v3_msg;
pub mod rr_v3_transport;
pub mod security_metrics;
pub mod security_policy;
pub mod snapshot;
pub mod state;
pub mod state_smt;
pub mod state_sync;
pub mod state_sync_supervisor;
pub mod storage;
mod storage_migrations;
pub mod sync_policy;
pub mod tx_policy;
pub mod version;

use std::sync::{Arc, Mutex};

// Rilancia tipi utili al bin
pub use blockchain::Blockchain;
pub use mempool::Mempool;
pub type SharedChain = Arc<Mutex<Blockchain>>;
pub type SharedMempool = Arc<Mutex<Mempool>>;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod operator_role_model_l1_tests;
