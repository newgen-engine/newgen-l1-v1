//! Phase 5 — State sync (snapshot v2) client.
//!
//! This module provides a **runtime-integrated** bootstrap path:
//! - connect to one or more peers (seed multiaddrs)
//! - discover the latest snapshot-v2 bundle (meta + chunks)
//! - download chunks with multi-peer retry/fallback (+ retry rounds/backoff, optional resume)
//! - verify chunk SHA256 against meta
//!
//! It intentionally mirrors `src/bin/fetch_snapshot_v2.rs`, but adds:
//! multi-peer selection + chunk fallback, and an optional trust anchor.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use libp2p::futures::StreamExt;
use libp2p::identity;
use libp2p::request_response;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp::Config as TcpConfig, yamux, Multiaddr, PeerId, Swarm};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::anchor_store;
use crate::p2p::{P2pBootPhase, P2pControl, SnapshotMetaRuntimeReply};
use crate::protocol_ids::RR_V3;
use crate::rr_v3_msg::{decode_v3, encode_v3, RrV3Msg};
use crate::rr_v3_transport::{NewgenHeadersCodec, RRv3Request, RRv3Response};
use crate::security_policy::SecurityPolicy;
use crate::snapshot::{
    rrv3_safe_snapshot_chunk_bytes, snapshot_meta_is_validator_bootstrap_capable, SnapshotMeta,
};
use crate::storage::DbStore;
use crate::{checkpoint, keyfmt};
use crate::{Blockchain, Mempool};
use checkpoint::{verify_checkpoint_cert, CheckpointCert};

#[doc(hidden)]
pub fn apply_imported_snapshot_to_live_runtime(
    storage: Arc<DbStore>,
    chain: &Arc<Mutex<Blockchain>>,
    mempool: &Arc<Mutex<Mempool>>,
    security_policy: &Arc<SecurityPolicy>,
) -> Result<(), String> {
    let blocks = storage
        .load_chain()
        .map_err(|e| format!("reload post-import snapshot failed: {:?}", e))?;
    if blocks.is_empty() {
        return Err("import snapshot riuscito ma DB resta vuoto".to_string());
    }

    let (
        prior_governance,
        prior_governance_bootstrap,
        prior_miner_sk_b64,
        prior_reputation,
        prior_indexer_stream,
    ) = {
        let g = chain.lock().unwrap_or_else(|e| e.into_inner());
        (
            g.governance.clone(),
            g.governance_bootstrap.clone(),
            g.policy.miner_sk_b64.clone(),
            g.reputation.clone(),
            g.cloned_indexer_stream(),
        )
    };

    let mut rebuilt = Blockchain::from_blocks_with_storage(blocks, storage.clone());
    let rebuilt_governance_empty = rebuilt
        .governance
        .as_ref()
        .map(|g| g.validator_set.entries.is_empty())
        .unwrap_or(true);
    if rebuilt_governance_empty {
        if let Some(prev_gov) = prior_governance.clone() {
            rebuilt.governance = Some(prev_gov);
        }
    }
    let rebuilt_bootstrap_empty = rebuilt
        .governance_bootstrap
        .as_ref()
        .map(|g| g.validator_set.entries.is_empty())
        .unwrap_or(true);
    if rebuilt_bootstrap_empty {
        rebuilt.governance_bootstrap =
            prior_governance_bootstrap.or_else(|| prior_governance.clone());
    }
    rebuilt.apply_governance_economy_overrides();
    rebuilt.reputation = prior_reputation;
    if let Some(indexer_stream) = prior_indexer_stream {
        rebuilt.attach_indexer_stream(indexer_stream);
    }
    rebuilt.set_miner_sk_b64(prior_miner_sk_b64.clone());
    let local_miner_authorized = if prior_miner_sk_b64.trim().is_empty() {
        rebuilt.is_authorized_miner = false;
        false
    } else {
        rebuilt.refresh_local_miner_authorization().map_err(|e| {
            format!("reapply local miner authorization after snapshot import failed: {e}")
        })?
    };
    if let Some(rep_arc) = rebuilt.reputation.as_ref() {
        let mut rep = rep_arc.lock().unwrap_or_else(|e| e.into_inner());
        if local_miner_authorized {
            let sk_bytes = STANDARD
                .decode(prior_miner_sk_b64.trim())
                .map_err(|e| format!("miner_sk_b64_invalid_base64_after_snapshot_import:{e}"))?;
            let seed: [u8; 32] = sk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "miner_sk_b64_not_32_bytes_after_snapshot_import".to_string())?;
            let (pubkey_hex, _, _) = rebuilt.local_miner_authorization_status()?;
            rep.set_local_source_attester_identity(Some(pubkey_hex), Some(seed));
        } else {
            rep.set_local_source_attester_identity(None, None);
        }
    }
    rebuilt.set_proposal_gate_open(false);
    rebuilt.set_p2p_ready_for_mining(false);
    rebuilt.set_runtime_sync_caught_up(false);
    rebuilt.set_runtime_bootstrap_complete(false);
    let base_fee = rebuilt.base_fee_per_tx();

    {
        let mut g = chain.lock().unwrap_or_else(|e| e.into_inner());
        *g = rebuilt;
    }

    {
        let mut mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
        *mp = Mempool::from_security_policy(security_policy.as_ref());
        mp.set_base_fee_per_tx_hint(base_fee);
    }

    Ok(())
}

#[doc(hidden)]
pub async fn notify_state_sync_applied_and_rearm_p2p(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
) -> Result<(), String> {
    let (ack_tx, ack_rx) = oneshot::channel::<()>();
    ctrl.send(P2pControl::StateSyncApplied { ack: ack_tx })
        .map_err(|_| "p2p ctrl channel closed before StateSyncApplied".to_string())?;
    tokio::time::timeout(Duration::from_secs(2), ack_rx)
        .await
        .map_err(|_| "timeout waiting StateSyncApplied ack".to_string())
        .and_then(|res| res.map_err(|_| "StateSyncApplied ack dropped".to_string()))?;

    let (phase_tx, phase_rx) = oneshot::channel::<()>();
    ctrl.send(P2pControl::SetBootPhase {
        phase: P2pBootPhase::RestartCatchup,
        ack: phase_tx,
    })
    .map_err(|_| "p2p ctrl channel closed before RestartCatchup arm".to_string())?;
    tokio::time::timeout(Duration::from_secs(2), phase_rx)
        .await
        .map_err(|_| "timeout waiting RestartCatchup arm ack".to_string())
        .and_then(|res| res.map_err(|_| "RestartCatchup arm ack dropped".to_string()))?;

    Ok(())
}

#[doc(hidden)]
pub async fn import_snapshot_v2_bundle_into_live_runtime_and_rearm(
    storage: Arc<DbStore>,
    bundle_dir: &Path,
    chain: &Arc<Mutex<Blockchain>>,
    mempool: &Arc<Mutex<Mempool>>,
    security_policy: &Arc<SecurityPolicy>,
    ctrl: &mpsc::UnboundedSender<P2pControl>,
) -> Result<(), String> {
    storage
        .import_snapshot_v2_bundle(bundle_dir, true)
        .map_err(|e| format!("import snapshot v2 failed: {:?}", e))?;
    apply_imported_snapshot_to_live_runtime(storage, chain, mempool, security_policy)?;
    notify_state_sync_applied_and_rearm_p2p(ctrl).await
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn runtime_snapshot_verified_existing_chunk_v276(
    fpath: &Path,
    expected_sha256_hex: &str,
    height: u64,
    chunk_index: u32,
    total_chunks: u32,
    context: &str,
) -> Result<bool, String> {
    if !fpath.exists() {
        return Ok(false);
    }

    match std::fs::read(fpath) {
        Ok(existing) => {
            let got = sha256_hex(&existing);
            if got == expected_sha256_hex {
                ng_info!(
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_existing_chunk_verified_reuse_v276 height={} chunk={}/{} context={} bytes={} action=skip_network_fetch",
                    height,
                    chunk_index.saturating_add(1),
                    total_chunks,
                    context,
                    existing.len()
                );
                Ok(true)
            } else {
                let _ = std::fs::remove_file(fpath);
                ng_warn!(
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_existing_chunk_hash_mismatch_removed_v276 height={} chunk={}/{} context={} got={} expected={} action=redownload",
                    height,
                    chunk_index.saturating_add(1),
                    total_chunks,
                    context,
                    got,
                    expected_sha256_hex
                );
                Ok(false)
            }
        }
        Err(err) => {
            let _ = std::fs::remove_file(fpath);
            ng_warn!(
                target: "state_sync.bootstrap",
                "event=runtime_snapshot_existing_chunk_unreadable_removed_v276 height={} chunk={}/{} context={} err={} action=redownload",
                height,
                chunk_index.saturating_add(1),
                total_chunks,
                context,
                err
            );
            Ok(false)
        }
    }
}

fn meta_key(meta: &SnapshotMeta, meta_sha256_opt: Option<&String>) -> String {
    if let Some(s) = meta_sha256_opt {
        let t = s.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    // Stable key: sha256 of canonical JSON representation.
    let bytes = serde_json::to_vec(meta).expect("SnapshotMeta serializable");
    sha256_hex(&bytes)
}

fn snapshot_meta_same_download_manifest_v251(a: &SnapshotMeta, b: &SnapshotMeta) -> bool {
    a.height == b.height
        && a.bytes_len == b.bytes_len
        && a.chunk_size == b.chunk_size
        && a.chunks == b.chunks
        && a.chunk_hashes_hex == b.chunk_hashes_hex
        && a.checkpoint_block_hash == b.checkpoint_block_hash
        && a.genesis_hash == b.genesis_hash
        && a.state_root == b.state_root
}

fn snapshot_meta_same_download_manifest_key_v286(
    plan_key: &str,
    plan_meta: &SnapshotMeta,
    candidate_key: &str,
    candidate_meta: &SnapshotMeta,
) -> bool {
    // V286 makes the V285 "identical manifest only" rule explicit at the plan
    // key/meta_sha layer too. Chunk failover is allowed only when both peers
    // advertise the same canonical manifest key and the byte/chunk download
    // manifest matches. This prevents grouping snapshots that share chunk layout
    // but differ in version, window, finalized/QC, governance/economy sidecar,
    // state coverage, or any other canonical manifest field captured by meta_key.
    plan_key == candidate_key
        && snapshot_meta_same_download_manifest_v251(plan_meta, candidate_meta)
}

fn snapshot_meta_same_transfer_bundle_v281_historical_test_only(
    a: &SnapshotMeta,
    b: &SnapshotMeta,
) -> bool {
    // Historical V281 equivalence helper kept for regression tests only.
    // V285/V286 deliberately no longer use this helper for transfer-plan grouping:
    // GetSnapshotV2Chunk(height, index) has no manifest/bundle id, so failover
    // must be limited to byte-identical manifests until the wire protocol can
    // bind chunk requests to a manifest hash.
    a.height == b.height
        && a.bytes_len == b.bytes_len
        && a.chunk_size == b.chunk_size
        && a.chunks == b.chunks
        && a.checkpoint_block_hash == b.checkpoint_block_hash
        && a.genesis_hash == b.genesis_hash
        && a.state_root == b.state_root
        && a.snapshot_bootstrap_role == b.snapshot_bootstrap_role
        && a.state_coverage_mode == b.state_coverage_mode
        && a.validator_bootstrap_capable == b.validator_bootstrap_capable
        && a.include_state_nodes == b.include_state_nodes
        && a.reachable_state_nodes == b.reachable_state_nodes
}

fn snapshot_meta_same_trust_family_v251(a: &SnapshotMeta, b: &SnapshotMeta) -> bool {
    a.height == b.height
        && a.checkpoint_block_hash == b.checkpoint_block_hash
        && a.genesis_hash == b.genesis_hash
        && a.state_root == b.state_root
        && a.snapshot_bootstrap_role == b.snapshot_bootstrap_role
        && a.state_coverage_mode == b.state_coverage_mode
}

#[derive(Clone, Debug)]
pub struct StateSyncConfig {
    /// Chain id used to reject foreign snapshots.
    pub chain_id: String,

    /// If non-empty, the discovered snapshot meta must match this genesis hash.
    pub expected_genesis_hash: String,

    /// Optional lower bound used by RestartCatchup/large-gap recovery.  When set,
    /// a snapshot must advance beyond the local tip before we download/import it.
    /// This prevents stale bootstrap_latest bundles from being re-imported at the
    /// same height and then triggering a useless restart loop.
    pub min_acceptable_snapshot_height: Option<u64>,

    /// Optional peer/cluster height hint for diagnostics and stale-meta rejection.
    pub reference_peer_height: Option<u64>,

    /// Maximum tolerated distance between the best known peer height and a latest
    /// snapshot response.  Applied only when reference_peer_height is set.
    pub max_snapshot_staleness_blocks: u64,

    /// Public mode (permissionless): require a cryptographic trust anchor for snapshot acceptance.
    ///
    /// In public mode we do **not** accept a raw hash-only anchor.
    pub public_mode: bool,

    /// Optional trust anchor (mainnet-grade): a checkpoint certificate file path.
    ///
    /// If set, the discovered snapshot meta must match the cert's checkpoint (height + block_hash),
    /// and the cert must verify against the bootstrap validator set.
    pub trusted_checkpoint_cert_path: Option<String>,

    /// Legacy (dev/test): if set, require meta.checkpoint_block_hash == this value.
    /// Not accepted in public mode.
    pub trusted_checkpoint_hash: Option<String>,

    /// Optional anchor cache file path.
    /// If present, the node can bootstrap without a manual cert file.
    pub anchor_cache_path: Option<PathBuf>,

    /// If true (default), in public mode the node may fetch the latest cert from peers and cache it.
    pub auto_fetch_anchor: bool,
    /// RRv3 max frame size (must be >= server side).
    pub rr_v3_max_frame_bytes: usize,
    /// RR request timeout.
    pub rr_timeout_ms: u64,
    /// Connection timeout to gather peers.
    pub connect_timeout_ms: u64,
    /// Strong bootstrap-readiness timeout for the live runtime actor. This is intentionally
    /// longer than a raw dial timeout because a seed must become semantically usable
    /// (Hello OK / snapshot advert / prior RR success), not just TCP-connected.
    pub bootstrap_ready_timeout_ms: u64,
    /// Snapshot-meta bootstrap discovery rounds before falling back.
    pub bootstrap_meta_retry_rounds: usize,
    /// Base backoff (milliseconds) between snapshot-meta bootstrap rounds.
    pub bootstrap_meta_retry_backoff_ms: u64,
    /// Per-chunk retry rounds (each round iterates all available peers).
    pub chunk_retry_rounds: usize,
    /// Backoff (milliseconds) between failed chunk rounds.
    pub chunk_retry_backoff_ms: u64,
    /// If true, keep already downloaded+verified chunks and resume partial downloads.
    pub resume_partial_download: bool,
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            chain_id: crate::chain_identity::chain_id().to_string(),
            expected_genesis_hash: String::new(),
            min_acceptable_snapshot_height: None,
            reference_peer_height: None,
            max_snapshot_staleness_blocks: env_u64(
                "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_STALENESS_BLOCKS",
                1024,
            )
            .max(1),
            public_mode: false,
            trusted_checkpoint_cert_path: std::env::var("NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH")
                .ok()
                .and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                }),
            trusted_checkpoint_hash: std::env::var("NEWGEN_TRUSTED_CHECKPOINT_HASH")
                .ok()
                .and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                }),
            anchor_cache_path: std::env::var("NEWGEN_ANCHOR_CACHE_PATH")
                .ok()
                .and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(t))
                    }
                }),
            auto_fetch_anchor: std::env::var("NEWGEN_AUTO_FETCH_ANCHOR")
                .ok()
                .map(|s| s.trim() != "0")
                .unwrap_or(true),
            rr_v3_max_frame_bytes: env_usize(
                "NEWGEN_SNAPSHOT_RR_V3_MAX_FRAME_BYTES",
                env_usize("NEWGEN_RR_V3_MAX_FRAME_BYTES", 16 * 1024 * 1024),
            )
            .clamp(1024 * 1024, 256 * 1024 * 1024),
            rr_timeout_ms: env_u64("NEWGEN_STATE_SYNC_TIMEOUT_MS", 30_000).max(300),
            connect_timeout_ms: env_u64("NEWGEN_STATE_SYNC_CONNECT_TIMEOUT_MS", 12_000).max(300),
            bootstrap_ready_timeout_ms: env_u64(
                "NEWGEN_STATE_SYNC_BOOTSTRAP_READY_TIMEOUT_MS",
                10_000,
            )
            .max(1_000),
            bootstrap_meta_retry_rounds: env_usize(
                "NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_ROUNDS",
                4,
            )
            .max(1),
            bootstrap_meta_retry_backoff_ms: env_u64(
                "NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_BACKOFF_MS",
                500,
            )
            .max(50),
            chunk_retry_rounds: env_usize("NEWGEN_STATE_SYNC_CHUNK_RETRY_ROUNDS", 3).max(1),
            chunk_retry_backoff_ms: env_u64("NEWGEN_STATE_SYNC_CHUNK_RETRY_BACKOFF_MS", 400)
                .max(10),
            resume_partial_download: std::env::var("NEWGEN_STATE_SYNC_RESUME_PARTIAL")
                .ok()
                .map(|v| {
                    let t = v.trim().to_ascii_lowercase();
                    !(t == "0" || t == "false" || t == "no" || t == "off")
                })
                .unwrap_or(true),
        }
    }
}

// --- Behaviour (reqres only)
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StateSyncEvent")]
struct StateSyncBehaviour {
    reqres_v3: request_response::Behaviour<NewgenHeadersCodec>,
}

#[derive(Debug)]
enum StateSyncEvent {
    ReqResV3(request_response::Event<RRv3Request, RRv3Response>),
}

impl From<request_response::Event<RRv3Request, RRv3Response>> for StateSyncEvent {
    fn from(e: request_response::Event<RRv3Request, RRv3Response>) -> Self {
        Self::ReqResV3(e)
    }
}

async fn rr_call(
    swarm: &mut Swarm<StateSyncBehaviour>,
    peer: PeerId,
    msg: RrV3Msg,
    timeout_ms: u64,
) -> Result<RrV3Msg, String> {
    let req_id = swarm
        .behaviour_mut()
        .reqres_v3
        .send_request(&peer, RRv3Request(encode_v3(&msg)));

    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let next = tokio::time::timeout_at(deadline, swarm.next())
            .await
            .map_err(|_| "timeout".to_string())?;
        let ev = match next {
            Some(e) => e,
            None => return Err("swarm ended".to_string()),
        };

        if let SwarmEvent::Behaviour(StateSyncEvent::ReqResV3(e)) = ev {
            match e {
                request_response::Event::Message { peer: p, message } if p == peer => match message
                {
                    request_response::Message::Response {
                        request_id,
                        response,
                    } if request_id == req_id => {
                        let bytes = response.0;
                        let msg =
                            decode_v3(&bytes).ok_or_else(|| "invalid RRv3 JSON".to_string())?;
                        return Ok(msg);
                    }
                    _ => {}
                },
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                } if request_id == req_id => {
                    return Err(format!("outbound failure: {error:?}"));
                }
                _ => {}
            }
        }
    }
}

async fn connect_peers(
    swarm: &mut Swarm<StateSyncBehaviour>,
    seeds: &[Multiaddr],
    connect_timeout_ms: u64,
) -> Result<Vec<PeerId>, String> {
    let mut pending: usize = 0;
    for a in seeds {
        if swarm.dial(a.clone()).is_ok() {
            pending = pending.saturating_add(1);
        }
    }
    if pending == 0 {
        return Err("no dialable seed peers".to_string());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_millis(connect_timeout_ms);
    let mut peers: Vec<PeerId> = Vec::new();
    let mut seen: HashSet<PeerId> = HashSet::new();

    while tokio::time::Instant::now() < deadline {
        let next = match tokio::time::timeout_at(deadline, swarm.next()).await {
            Ok(v) => v,
            Err(_) => {
                // Best-effort discovery: if at least one peer connected, do not fail on timeout.
                if peers.is_empty() {
                    return Err("connect timeout".to_string());
                }
                break;
            }
        };

        let ev = match next {
            Some(e) => e,
            None => break,
        };

        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
            if seen.insert(peer_id) {
                peers.push(peer_id);
                // We don't need a huge fanout to be robust.
                if peers.len() >= 8 {
                    break;
                }
            }
        }
        // Ignore failures: we can still proceed if at least one peer connects.
    }

    if peers.is_empty() {
        return Err("no peer connected".to_string());
    }
    Ok(peers)
}

fn out_paths(out_dir: &Path) -> (PathBuf, PathBuf) {
    let meta = out_dir.join("meta.json");
    let chunks = out_dir.join("chunks");
    (meta, chunks)
}

fn verify_snapshot_chunk_bytes_len(meta: &SnapshotMeta, chunks_dir: &Path) -> Result<u64, String> {
    let mut total: u64 = 0;
    for i in 0..meta.chunks {
        let p = chunks_dir.join(format!("{:06}.bin", i));
        let len = std::fs::metadata(&p)
            .map_err(|e| {
                format!(
                    "snapshot bytes_len verification failed: missing chunk {} at {}: {e}",
                    i,
                    p.display()
                )
            })?
            .len();
        total = total.saturating_add(len);
    }

    if total != meta.bytes_len {
        return Err(format!(
            "snapshot bytes_len mismatch: meta_bytes_len={} actual_bytes={} action=fail_closed",
            meta.bytes_len, total
        ));
    }

    Ok(total)
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create parent dir {}: {e}", parent.display()))?;
    }

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp_path = path.with_file_name(format!(".{}.tmp", file_name));

    {
        use std::io::Write;
        let mut tmp_file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("cannot create temp file {}: {e}", tmp_path.display()))?;
        tmp_file
            .write_all(bytes)
            .map_err(|e| format!("cannot write temp file {}: {e}", tmp_path.display()))?;
        tmp_file
            .sync_all()
            .map_err(|e| format!("cannot sync temp file {}: {e}", tmp_path.display()))?;
    }

    crate::utils::atomic_replace_file_v1(&tmp_path, path).map_err(|e| {
        format!(
            "cannot replace temp file {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })
}

fn quorum_k_2of3(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    // ceil((2/3) * n)
    (2 * n).div_ceil(3)
}

fn validator_set_hash_hex(validators_hex: &HashSet<String>) -> String {
    // Must match `Blockchain::validator_set_hash_hex` logic (Phase-1/Finality). Keep consensus-stable.
    let mut v: Vec<String> = validators_hex.iter().cloned().collect();
    v.sort();
    v.dedup();

    let mut preimage = String::new();
    preimage.push_str("newgen.validator_set.v1\n");
    for pk in v {
        preimage.push_str(&pk);
        preimage.push('\n');
    }
    sha256_hex(preimage.as_bytes())
}

fn load_bootstrap_validators_hex() -> Result<HashSet<String>, String> {
    // In public mode the node already requires governance bootstrap.
    // Use it as the canonical validator set for anchor verification.
    let gov = crate::governance_provider::load_governance_bootstrap_required_quiet(
        "config/governance.json",
    )
    .map_err(|e| {
        format!(
            "governance bootstrap required for anchor verification: {}",
            e
        )
    })?;

    let mut set: HashSet<String> = HashSet::new();
    for e in gov.validator_set.entries {
        let h = keyfmt::pk_hex_from_any(&e.pub_key)
            .map_err(|_| "invalid validator pub_key in governance.json".to_string())?;
        set.insert(h);
    }
    if set.is_empty() {
        return Err("governance validator_set is empty (cannot verify anchor)".to_string());
    }
    Ok(set)
}

fn read_checkpoint_cert_from_path(path: &str) -> Result<CheckpointCert, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read checkpoint cert file '{}': {e}", path))?;
    serde_json::from_slice::<CheckpointCert>(&bytes)
        .map_err(|e| format!("invalid checkpoint cert JSON '{}': {e}", path))
}

fn verify_snapshot_meta_against_checkpoint_cert(
    meta: &SnapshotMeta,
    cfg: &StateSyncConfig,
    cert: &CheckpointCert,
    allowed_signers_hex: &HashSet<String>,
) -> Result<(), String> {
    // Chain binding
    if cert.checkpoint.chain_id != cfg.chain_id {
        return Err("anchor chain_id mismatch".to_string());
    }
    if !cfg.expected_genesis_hash.trim().is_empty()
        && cert.checkpoint.genesis_hash != cfg.expected_genesis_hash
    {
        return Err("anchor genesis_hash mismatch".to_string());
    }

    // Snapshot binding (height + checkpoint hash)
    if cert.checkpoint.height != meta.height {
        return Err("anchor height mismatch vs snapshot meta".to_string());
    }
    if cert.checkpoint.block_hash != meta.checkpoint_block_hash {
        return Err("anchor checkpoint hash mismatch vs snapshot meta".to_string());
    }

    // Snapshot meta should also carry genesis_hash in public mode.
    if cfg.public_mode {
        if meta.genesis_hash.trim().is_empty() {
            return Err("snapshot meta missing genesis_hash (public mode)".to_string());
        }
        if !cfg.expected_genesis_hash.trim().is_empty()
            && meta.genesis_hash != cfg.expected_genesis_hash
        {
            return Err("snapshot meta genesis_hash mismatch".to_string());
        }
        if meta.genesis_hash != cert.checkpoint.genesis_hash {
            return Err("snapshot meta genesis_hash != anchor genesis_hash".to_string());
        }
    }

    // Validator set binding
    let vset_hash = validator_set_hash_hex(allowed_signers_hex);
    if cert.checkpoint.validator_set_hash != vset_hash {
        return Err("anchor validator_set_hash mismatch".to_string());
    }

    let quorum_k = quorum_k_2of3(allowed_signers_hex.len());
    verify_checkpoint_cert(cert, quorum_k, allowed_signers_hex)
        .map_err(|e| format!("anchor checkpoint cert invalid: {e}"))?;

    Ok(())
}

async fn fetch_best_checkpoint_cert_from_peers(
    swarm: &mut Swarm<StateSyncBehaviour>,
    peers: &[PeerId],
    cfg: &StateSyncConfig,
    allowed_signers_hex: &HashSet<String>,
) -> Result<Option<CheckpointCert>, String> {
    if allowed_signers_hex.is_empty() {
        return Ok(None);
    }

    let vset_hash = validator_set_hash_hex(allowed_signers_hex);
    let quorum_k = quorum_k_2of3(allowed_signers_hex.len());

    let mut best: Option<CheckpointCert> = None;

    for peer in peers.iter().copied() {
        let resp = match rr_call(
            swarm,
            peer,
            RrV3Msg::GetCheckpointCertLatest,
            cfg.rr_timeout_ms,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let cert = match resp {
            RrV3Msg::CheckpointCertLatest { cert: Some(c), .. } => c,
            _ => continue,
        };

        // Chain binding
        if cert.checkpoint.chain_id != cfg.chain_id {
            continue;
        }
        if !cfg.expected_genesis_hash.trim().is_empty()
            && cert.checkpoint.genesis_hash != cfg.expected_genesis_hash
        {
            continue;
        }
        if cert.checkpoint.validator_set_hash != vset_hash {
            continue;
        }

        if verify_checkpoint_cert(&cert, quorum_k, allowed_signers_hex).is_err() {
            continue;
        }

        best = match best {
            None => Some(cert),
            Some(b) => {
                if anchor_store::is_better_checkpoint_cert(&cert, &b) {
                    Some(cert)
                } else {
                    Some(b)
                }
            }
        };
    }

    Ok(best)
}

fn snapshot_meta_usable_for_validator_bootstrap(meta: &SnapshotMeta) -> Result<(), String> {
    meta.validate_basic()
        .map_err(|e| format!("snapshot_meta_invalid:{e}"))?;
    if snapshot_meta_is_validator_bootstrap_capable(meta) {
        return Ok(());
    }
    let reason = if meta.reachable_state_nodes && meta.consensus_bootstrap_context.is_none() {
        "missing_consensus_bootstrap_context"
    } else {
        "not_validator_bootstrap_capable"
    };
    Err(format!(
        "snapshot_not_validator_bootstrap_capable:{} height={} role={:?} coverage={:?}",
        reason, meta.height, meta.snapshot_bootstrap_role, meta.state_coverage_mode
    ))
}

fn snapshot_meta_satisfies_progress_gate(
    meta: &SnapshotMeta,
    cfg: &StateSyncConfig,
) -> Result<(), String> {
    if let Some(min_height) = cfg.min_acceptable_snapshot_height {
        if meta.height < min_height {
            let local_height_hint = min_height.saturating_sub(1);
            return Err(format!(
                "snapshot_not_progressive snapshot_height={} min_acceptable_snapshot_height={} local_height_hint={} peer_height_hint={}",
                meta.height,
                min_height,
                local_height_hint,
                cfg.reference_peer_height
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
    }

    if let Some(peer_height) = cfg.reference_peer_height {
        if peer_height > meta.height {
            let staleness = peer_height.saturating_sub(meta.height);
            if staleness > cfg.max_snapshot_staleness_blocks {
                return Err(format!(
                    "snapshot_too_stale snapshot_height={} peer_height_hint={} staleness_blocks={} max_snapshot_staleness_blocks={}",
                    meta.height,
                    peer_height,
                    staleness,
                    cfg.max_snapshot_staleness_blocks
                ));
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
struct SnapshotMetaCandidate {
    peer: PeerId,
    meta: SnapshotMeta,
    key: String,
}

const LARGE_GAP_WITHOUT_SNAPSHOT_BOOTSTRAP_THRESHOLD: u64 = 1024;

fn rr_v3_snapshot_response_kind(msg: &RrV3Msg) -> &'static str {
    match msg {
        RrV3Msg::SnapshotV2Meta { .. } => "SnapshotV2Meta",
        RrV3Msg::Error { .. } => "Error",
        RrV3Msg::SnapshotV2Chunk { .. } => "SnapshotV2Chunk",
        RrV3Msg::Headers { .. } => "Headers",
        RrV3Msg::CheckpointCertLatest { .. } => "CheckpointCertLatest",
        RrV3Msg::GetHeaders { .. } => "GetHeaders",
        RrV3Msg::GetSnapshotV2Latest => "GetSnapshotV2Latest",
        RrV3Msg::GetSnapshotV2Meta { .. } => "GetSnapshotV2Meta",
        RrV3Msg::GetSnapshotV2Chunk { .. } => "GetSnapshotV2Chunk",
        RrV3Msg::GetCheckpointCertLatest => "GetCheckpointCertLatest",
    }
}

fn snapshot_meta_response_error_reason(code: u32, message: &str) -> &'static str {
    let msg = message.to_ascii_lowercase();
    if code == 413
        || msg.contains("too_large")
        || msg.contains("too large")
        || msg.contains("oversize")
        || msg.contains("max_frame")
        || msg.contains("frame") && msg.contains("large")
    {
        "snapshot_meta_oversize"
    } else if code == 404 || msg.contains("not_found") || msg.contains("missing") {
        "snapshot_meta_missing"
    } else if code == 429 || msg.contains("busy") || msg.contains("inflight") {
        "snapshot_peer_busy"
    } else if code >= 500 {
        "snapshot_peer_internal_error"
    } else {
        "snapshot_meta_peer_error"
    }
}

fn extract_u64_field_from_message(message: &str, field: &str) -> Option<u64> {
    let bytes = message.as_bytes();
    let field_bytes = field.as_bytes();
    let mut i = 0usize;
    while i + field_bytes.len() <= bytes.len() {
        if &bytes[i..i + field_bytes.len()] == field_bytes {
            let mut j = i + field_bytes.len();
            while j < bytes.len() && matches!(bytes[j], b' ' | b':' | b'=') {
                j += 1;
            }
            let start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > start {
                if let Ok(v) = message[start..j].parse::<u64>() {
                    return Some(v);
                }
            }
        }
        i += 1;
    }
    None
}

fn infer_snapshot_error_heights(message: &str) -> (Option<u64>, Option<u64>) {
    let local_height = extract_u64_field_from_message(message, "local_height")
        .or_else(|| extract_u64_field_from_message(message, "local"));
    let peer_height = extract_u64_field_from_message(message, "peer_height")
        .or_else(|| extract_u64_field_from_message(message, "snapshot_height"))
        .or_else(|| extract_u64_field_from_message(message, "height"));
    (local_height, peer_height)
}

fn parse_runtime_snapshot_meta_error(err: &str) -> Option<(u32, String)> {
    let code = extract_u64_field_from_message(err, "code").map(|v| v as u32)?;
    let message = err
        .split("msg=")
        .nth(1)
        .or_else(|| err.split("message=").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| err.to_string());
    Some((code, message))
}

fn large_gap_without_snapshot_bootstrap_gap(
    local_height: Option<u64>,
    peer_height: Option<u64>,
) -> Option<u64> {
    let (Some(local_height), Some(peer_height)) = (local_height, peer_height) else {
        return None;
    };
    if peer_height <= local_height {
        return None;
    }
    let gap = peer_height.saturating_sub(local_height);
    if gap >= LARGE_GAP_WITHOUT_SNAPSHOT_BOOTSTRAP_THRESHOLD {
        Some(gap)
    } else {
        None
    }
}

fn log_large_gap_without_snapshot_bootstrap_if_known(
    peer: PeerId,
    local_height: Option<u64>,
    peer_height: Option<u64>,
    reason: &str,
) {
    let (Some(local_height), Some(peer_height)) = (local_height, peer_height) else {
        return;
    };
    let Some(gap) = large_gap_without_snapshot_bootstrap_gap(Some(local_height), Some(peer_height))
    else {
        return;
    };
    ng_warn!(
        target: "state_sync.bootstrap",
        "event=large_gap_without_snapshot_bootstrap peer={} local_height={} peer_height={} gap={} reason={} action=block_sync_fallback",
        peer,
        local_height,
        peer_height,
        gap,
        reason
    );
}

fn log_snapshot_meta_response_error(
    peer: PeerId,
    code: u32,
    message: &str,
    local_height_hint: Option<u64>,
    peer_height_hint: Option<u64>,
) -> &'static str {
    let reason = snapshot_meta_response_error_reason(code, message);
    let cache_message = format!(
        "snapshot_meta_response_error peer={} code={} message={} reason={}",
        peer, code, message, reason
    );
    crate::api::record_runtime_snapshot_error_v1(cache_message.clone());
    crate::api::record_runtime_state_sync_error_v1(cache_message);
    ng_warn!(
        target: "state_sync.bootstrap",
        "event=snapshot_meta_response_error peer={} code={} message={} reason={} action=fallback_or_retry",
        peer,
        code,
        message,
        reason
    );
    let (msg_local, msg_peer) = infer_snapshot_error_heights(message);
    log_large_gap_without_snapshot_bootstrap_if_known(
        peer,
        local_height_hint
            .or(msg_local)
            .or_else(crate::api::runtime_status_cache_height_v1),
        peer_height_hint.or(msg_peer),
        reason,
    );
    reason
}

async fn discover_snapshot_v2_candidates_with_retry(
    swarm: &mut Swarm<StateSyncBehaviour>,
    peers: &[PeerId],
    effective_height_opt: Option<u64>,
    cfg: &StateSyncConfig,
    trusted_cert: Option<&CheckpointCert>,
    allowed_signers_hex: &HashSet<String>,
    max_snapshot_bytes: u64,
    max_snapshot_chunks: u64,
) -> Result<Vec<SnapshotMetaCandidate>, String> {
    let rounds = cfg.bootstrap_meta_retry_rounds.max(1);
    let base_backoff_ms = cfg.bootstrap_meta_retry_backoff_ms.max(50);

    let mut saw_rr_response = false;
    let mut saw_snapshot_meta = false;
    let mut last_rr_successes: usize = 0;
    let mut last_meta_responses: usize = 0;
    let mut last_rejected: usize = 0;

    for round in 0..rounds {
        if round > 0 {
            let sleep_ms = base_backoff_ms.saturating_mul(round as u64);
            ng_info!(
                target: "state_sync.bootstrap",
                "event=meta_retry_backoff round={} rounds={} sleep_ms={}",
                round + 1,
                rounds,
                sleep_ms
            );
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }

        let mut rr_successes: usize = 0;
        let mut meta_responses: usize = 0;
        let mut rejected: usize = 0;
        let mut candidates: Vec<SnapshotMetaCandidate> = Vec::new();

        for peer in peers.iter().copied() {
            let req = if let Some(h) = effective_height_opt {
                RrV3Msg::GetSnapshotV2Meta { height: h }
            } else {
                RrV3Msg::GetSnapshotV2Latest
            };

            let req_kind = rr_v3_snapshot_response_kind(&req);
            let resp = match rr_call(swarm, peer, req, cfg.rr_timeout_ms).await {
                Ok(r) => {
                    rr_successes = rr_successes.saturating_add(1);
                    r
                }
                Err(err) => {
                    crate::api::record_runtime_state_sync_error_v1(format!(
                        "direct_seed_snapshot_meta_request_failed peer={} request_kind={} error={}",
                        peer, req_kind, err
                    ));
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=direct_seed_snapshot_meta_request_failed peer={} request_kind={} error={} action=retry_next_peer",
                        peer,
                        req_kind,
                        err
                    );
                    continue;
                }
            };

            let (meta, sha_opt) = match resp {
                RrV3Msg::SnapshotV2Meta {
                    meta: Some(m),
                    meta_sha256_hex,
                } => {
                    meta_responses = meta_responses.saturating_add(1);
                    (m, meta_sha256_hex)
                }
                RrV3Msg::SnapshotV2Meta { meta: None, .. } => {
                    meta_responses = meta_responses.saturating_add(1);
                    crate::api::record_runtime_snapshot_error_v1(format!(
                        "snapshot_meta_response_empty peer={} reason=snapshot_meta_missing",
                        peer
                    ));
                    log_large_gap_without_snapshot_bootstrap_if_known(
                        peer,
                        crate::api::runtime_status_cache_height_v1(),
                        effective_height_opt,
                        "snapshot_meta_missing",
                    );
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=snapshot_meta_response_empty peer={} reason=snapshot_meta_missing action=fallback_or_retry",
                        peer
                    );
                    continue;
                }
                RrV3Msg::Error { code, message } => {
                    rr_successes = rr_successes.saturating_add(0);
                    let _reason = log_snapshot_meta_response_error(
                        peer,
                        code,
                        &message,
                        None,
                        effective_height_opt,
                    );
                    continue;
                }
                other => {
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=snapshot_meta_response_unexpected_kind peer={} kind={} action=fallback_or_retry",
                        peer,
                        rr_v3_snapshot_response_kind(&other)
                    );
                    continue;
                }
            };

            let mut usable = true;

            if let Err(err) = snapshot_meta_usable_for_validator_bootstrap(&meta) {
                ng_warn_throttle!(
                    key: format!("snapshot_meta_rejected_validator_bootstrap_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=snapshot_meta_rejected peer={} reason={}",
                    peer,
                    err
                );
                usable = false;
            }

            if usable && (meta.chunks == 0 || meta.chunk_hashes_hex.len() != meta.chunks as usize) {
                ng_warn_throttle!(
                    key: format!("snapshot_meta_rejected_chunk_layout_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=snapshot_meta_rejected peer={} reason=invalid_chunk_layout chunks={} chunk_hashes={}",
                    peer,
                    meta.chunks,
                    meta.chunk_hashes_hex.len()
                );
                usable = false;
            }

            if usable
                && (meta.bytes_len > max_snapshot_bytes
                    || (meta.chunks as u64) > max_snapshot_chunks)
            {
                ng_warn_throttle!(
                    key: format!("snapshot_meta_rejected_limits_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=snapshot_meta_rejected peer={} reason=snapshot_limits_exceeded bytes_len={} max_bytes={} chunks={} max_chunks={}",
                    peer,
                    meta.bytes_len,
                    max_snapshot_bytes,
                    meta.chunks,
                    max_snapshot_chunks
                );
                usable = false;
            }

            if usable {
                if let Err(err) = runtime_snapshot_meta_transport_safe_v280(&meta, cfg) {
                    ng_warn_throttle!(
                        key: format!("snapshot_meta_rejected_transport_budget_{}", peer),
                        every_ms: 30_000,
                        target: "state_sync.bootstrap",
                        "event=snapshot_meta_rejected peer={} reason={}",
                        peer,
                        err
                    );
                    usable = false;
                }
            }

            if usable
                && !cfg.expected_genesis_hash.trim().is_empty()
                && !meta.genesis_hash.trim().is_empty()
                && meta.genesis_hash != cfg.expected_genesis_hash
            {
                ng_warn_throttle!(
                    key: format!("snapshot_meta_rejected_genesis_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=snapshot_meta_rejected peer={} reason=genesis_mismatch meta_genesis={} expected_genesis={}",
                    peer,
                    meta.genesis_hash,
                    cfg.expected_genesis_hash
                );
                usable = false;
            }

            if usable {
                if let Err(err) = snapshot_meta_satisfies_progress_gate(&meta, cfg) {
                    ng_warn_throttle!(
                        key: format!("snapshot_meta_rejected_progress_{}_{}", peer, meta.height),
                        every_ms: 30_000,
                        target: "state_sync.bootstrap",
                        "event=snapshot_meta_rejected peer={} reason={}",
                        peer,
                        err
                    );
                    usable = false;
                }
            }

            if usable {
                if let Some(cert) = trusted_cert {
                    if let Err(err) = verify_snapshot_meta_against_checkpoint_cert(
                        &meta,
                        cfg,
                        cert,
                        allowed_signers_hex,
                    ) {
                        ng_warn_throttle!(
                            key: format!("snapshot_meta_rejected_anchor_{}", peer),
                            every_ms: 30_000,
                            target: "state_sync.bootstrap",
                            "event=snapshot_meta_rejected peer={} reason=anchor_verification_failed err={}",
                            peer,
                            err
                        );
                        usable = false;
                    }
                } else if let Some(anchor) = cfg.trusted_checkpoint_hash.as_ref() {
                    if !anchor.trim().is_empty() && meta.checkpoint_block_hash != *anchor {
                        ng_warn_throttle!(
                            key: format!("snapshot_meta_rejected_anchor_hash_{}", peer),
                            every_ms: 30_000,
                            target: "state_sync.bootstrap",
                            "event=snapshot_meta_rejected peer={} reason=checkpoint_anchor_hash_mismatch meta_checkpoint={} expected_anchor={}",
                            peer,
                            meta.checkpoint_block_hash,
                            anchor
                        );
                        usable = false;
                    }
                }
            }

            if !usable {
                rejected = rejected.saturating_add(1);
                continue;
            }

            let key = meta_key(&meta, sha_opt.as_ref());
            candidates.push(SnapshotMetaCandidate { peer, meta, key });
        }

        saw_rr_response |= rr_successes > 0;
        saw_snapshot_meta |= meta_responses > 0;
        last_rr_successes = rr_successes;
        last_meta_responses = meta_responses;
        last_rejected = rejected;

        if !candidates.is_empty() {
            if round > 0 {
                ng_info!(
                    target: "state_sync.bootstrap",
                    "event=meta_retry_succeeded round={} rounds={} rr_successes={} meta_responses={} rejected={}",
                    round + 1,
                    rounds,
                    rr_successes,
                    meta_responses,
                    rejected
                );
            }
            return Ok(candidates);
        }

        if round + 1 < rounds {
            ng_warn!(
                target: "state_sync.bootstrap",
                "event=meta_retry_no_usable round={} rounds={} rr_successes={} meta_responses={} rejected={}",
                round + 1,
                rounds,
                rr_successes,
                meta_responses,
                rejected
            );
        }
    }

    if !saw_rr_response {
        return Err(format!(
            "no peer responded to snapshot-v2 meta requests after {} rounds",
            rounds
        ));
    }
    if !saw_snapshot_meta {
        return Err(format!(
            "peers responded but none returned snapshot-v2 meta after {} rounds (last_rr_successes={})",
            rounds, last_rr_successes
        ));
    }

    Err(format!(
        "no peer provided a usable snapshot-v2 meta after {} rounds (last_rr_successes={}, last_meta_responses={}, last_rejected={})",
        rounds, last_rr_successes, last_meta_responses, last_rejected
    ))
}

async fn await_runtime_bootstrap_ready(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    height_opt: Option<u64>,
    timeout_ms: u64,
) -> Result<(), String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::AwaitBootstrapReady {
        height_opt,
        timeout_ms,
        response: tx,
    })
    .map_err(|_| "p2p ctrl channel closed while waiting bootstrap readiness".to_string())?;
    rx.await
        .map_err(|_| "p2p bootstrap readiness response channel closed".to_string())?
}

async fn list_runtime_snapshot_peers(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    height_opt: Option<u64>,
) -> Result<Vec<PeerId>, String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::ListBootstrapSnapshotPeers {
        height_opt,
        response: tx,
    })
    .map_err(|_| "p2p ctrl channel closed while listing snapshot peers".to_string())?;
    rx.await
        .map_err(|_| "p2p snapshot peer list response channel closed".to_string())
}

async fn list_runtime_snapshot_peers_resilient(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    height_opt: Option<u64>,
) -> Result<Vec<PeerId>, String> {
    let peers = list_runtime_snapshot_peers(ctrl, height_opt).await?;
    if !peers.is_empty() || height_opt.is_none() {
        return Ok(peers);
    }
    list_runtime_snapshot_peers(ctrl, None).await
}

async fn nudge_runtime_bootstrap_connectivity(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
) -> Result<(), String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::NudgeBootstrapConnectivity { response: tx })
        .map_err(|_| "p2p ctrl channel closed while nudging bootstrap connectivity".to_string())?;
    rx.await
        .map_err(|_| "p2p bootstrap connectivity nudge response channel closed".to_string())
}

async fn discover_runtime_snapshot_peers_with_backoff(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    height_opt: Option<u64>,
    ready_timeout_ms: u64,
    connect_timeout_ms: u64,
    attempts: usize,
) -> Result<Vec<PeerId>, String> {
    let attempts = attempts.max(1);
    let mut last_err = String::new();
    for attempt in 0..attempts {
        let _ = nudge_runtime_bootstrap_connectivity(ctrl).await;
        let readiness_err = await_runtime_bootstrap_ready(ctrl, height_opt, ready_timeout_ms)
            .await
            .err()
            .map(|e| {
                format!(
                    "runtime bootstrap network not ready before snapshot peer discovery attempt {}/{}: {}",
                    attempt + 1,
                    attempts,
                    e
                )
            });
        match list_runtime_snapshot_peers_resilient(ctrl, height_opt).await {
            Ok(v) if !v.is_empty() => return Ok(v),
            Ok(_) => {
                last_err = readiness_err.unwrap_or_else(|| {
                    format!(
                        "runtime bootstrap found no reachable peers for snapshot meta after connectivity nudge (attempt {}/{})",
                        attempt + 1,
                        attempts
                    )
                });
            }
            Err(e) => last_err = e,
        }
        if attempt + 1 < attempts {
            let sleep_ms = connect_timeout_ms.min(1_500).max(200);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }
    Err(last_err)
}

async fn fetch_runtime_snapshot_meta_from_peer(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    peer: PeerId,
    height_opt: Option<u64>,
    timeout_ms: u64,
) -> Result<SnapshotMetaRuntimeReply, String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::FetchSnapshotV2MetaFromPeer {
        peer,
        height_opt,
        timeout_ms,
        response: tx,
    })
    .map_err(|_| "p2p ctrl channel closed while requesting snapshot meta from peer".to_string())?;
    match rx
        .await
        .map_err(|_| "p2p snapshot meta-from-peer response channel closed".to_string())?
    {
        Ok(reply) => Ok(reply),
        Err(err) => {
            if let Some((code, message)) = parse_runtime_snapshot_meta_error(&err) {
                let _reason =
                    log_snapshot_meta_response_error(peer, code, &message, None, height_opt);
            } else {
                crate::api::record_runtime_state_sync_error_v1(format!(
                    "snapshot_meta_request_failed peer={} error={}",
                    peer, err
                ));
                ng_warn!(
                    target: "state_sync.bootstrap",
                    "event=snapshot_meta_request_failed peer={} error={} action=fallback_or_retry",
                    peer,
                    err
                );
            }
            Err(err)
        }
    }
}

async fn fetch_runtime_checkpoint_cert_from_peer(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    peer: PeerId,
    timeout_ms: u64,
) -> Result<Option<CheckpointCert>, String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::FetchCheckpointCertLatestFromPeer {
        peer,
        timeout_ms,
        response: tx,
    })
    .map_err(|_| {
        "p2p ctrl channel closed while requesting checkpoint cert from peer".to_string()
    })?;
    rx.await
        .map_err(|_| "p2p checkpoint cert response channel closed".to_string())?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeSnapshotChunkFailureClassV251 {
    /// Server explicitly asks the client to refetch meta / reopen a serve session.
    MetaRefetchRequired,
    /// Network/transport/correlation failure. Retry different peers first.
    Transport,
    /// Peer returned bytes that do not match the selected snapshot manifest.
    SnapshotData,
    /// Peer returned the wrong RRv3 message or malformed payload.
    Protocol,
    /// Peer is temporarily busy/rate-limited.
    PeerBusy,
    /// Local/client-side non-retryable failure.
    Permanent,
}

fn runtime_snapshot_chunk_failure_class_v251(err: &str) -> RuntimeSnapshotChunkFailureClassV251 {
    let e = err.to_ascii_lowercase();
    if e.contains("snapshot_session_expired_refetch_meta")
        || e.contains("snapshot_session_stalled_refetch_meta")
        || e.contains("snapshot_session_stalled_refetch_meta_v250")
        || e.contains("snapshot_chunk_transport_retry_exhausted_refetch_meta")
        || e.contains("snapshot_chunk_session_refetched_rotate_peer_v251")
        || (e.contains("connectionclosed")
            && (e.contains("refetch_meta")
                || e.contains("rotate_peer")
                || e.contains("session_turn")
                || e.contains("session turn")
                || e.contains("not_current_session")
                || e.contains("not current session")
                || e.contains("not_active_session")
                || e.contains("not active session")
                || e.contains("not_peer_turn")
                || e.contains("not peer turn")
                || e.contains("turn changed")
                || e.contains("turn_changed")))
        || e.contains("runtime snapshot meta response was none")
        || e.contains("snapshot_meta_response_none_v264")
        || e.contains("snapshot meta response was none")
    {
        RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
    } else if e.contains("connectionclosed")
        || e.contains("dialfailure")
        || e.contains("timeout")
        || e.contains("response channel closed")
        || e.contains("ctrl channel closed")
        || e.contains("transport")
    {
        RuntimeSnapshotChunkFailureClassV251::Transport
    } else if e.contains("sha mismatch")
        || e.contains("hash mismatch")
        || e.contains("cannot write chunk")
        || e.contains("invalid base64")
        || e.contains("base64")
    {
        RuntimeSnapshotChunkFailureClassV251::SnapshotData
    } else if e.contains("rrv3_busy")
        || e.contains("busy")
        || e.contains("inflight")
        || e.contains("rate")
        || e.contains("429")
        || e.contains("temporary")
        || e.contains("code=500")
        || e.contains("code=503")
    {
        RuntimeSnapshotChunkFailureClassV251::PeerBusy
    } else if e.contains("response kind mismatch")
        || e.contains("correlation mismatch")
        || e.contains("wrong kind")
        || e.contains("wrong_kind")
        || e.contains("unexpected")
        || e.contains("received=")
    {
        RuntimeSnapshotChunkFailureClassV251::Protocol
    } else {
        RuntimeSnapshotChunkFailureClassV251::Permanent
    }
}

fn runtime_snapshot_chunk_failure_penalty_v251(class: RuntimeSnapshotChunkFailureClassV251) -> u32 {
    match class {
        // V268: refetch/turn-rotation is normal snapshot control flow, not a peer fault.
        RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired => 0,
        RuntimeSnapshotChunkFailureClassV251::Transport => 1,
        RuntimeSnapshotChunkFailureClassV251::PeerBusy => 1,
        RuntimeSnapshotChunkFailureClassV251::Protocol => 3,
        RuntimeSnapshotChunkFailureClassV251::SnapshotData => 4,
        RuntimeSnapshotChunkFailureClassV251::Permanent => 8,
    }
}

fn runtime_snapshot_apply_chunk_peer_failure_penalty_v268(
    peer_failures: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    penalty: u32,
) -> u32 {
    let current = peer_failures.get(&peer).copied().unwrap_or(0);
    if penalty == 0 {
        // V268: a refetch/rotation marker is not a peer failure. Do not create
        // a zero-valued suppression entry and do not erase a prior real score.
        return current;
    }
    let updated = current.saturating_add(penalty);
    peer_failures.insert(peer, updated);
    updated
}

fn runtime_snapshot_chunk_error_requires_meta_refetch_v223(err: &str) -> bool {
    runtime_snapshot_chunk_failure_class_v251(err)
        == RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
}

fn runtime_snapshot_retry_floor_v277() -> usize {
    // V281: state-sync owns provider failover across the grouped peer set and
    // across compatible bundle plans. Keep the outer retry floor small so a
    // connection-flaky provider does not hold D on the same chunk for many
    // rounds before B/C or the next bundle plan can be tried. Every accepted
    // chunk remains manifest-hash verified, so safety comes from verification,
    // not from long retry loops.
    env_usize("NEWGEN_RUNTIME_SNAPSHOT_CHUNK_RETRY_FLOOR", 3).clamp(1, 12)
}

fn runtime_snapshot_prefer_larger_chunk_size_order_v278(a: u32, b: u32) -> std::cmp::Ordering {
    // V278: after V277 raised the transport-safe raw chunk cap to 2MiB, prefer
    // the larger compatible bundle first so D uses fewer round trips. If that
    // faster plan fails, the surrounding compatible-plan downshift can still
    // fall back to smaller chunks.
    b.cmp(&a)
}

fn runtime_snapshot_candidate_selection_order_v279(
    a_meta: &SnapshotMeta,
    a_key: &str,
    a_rank_index: Option<usize>,
    b_meta: &SnapshotMeta,
    b_key: &str,
    b_rank_index: Option<usize>,
) -> std::cmp::Ordering {
    // V279: choose the fastest compatible manifest before freezing the primary
    // bundle. V278 only preferred larger chunks inside the plan sort, after
    // `chosen/selected` had already been fixed. That could keep a 1MiB bundle
    // primary even when an equivalent 2MiB bundle existed. Put chunk_size desc
    // in the initial candidate ordering, before key/rank tie-breakers.
    b_meta
        .height
        .cmp(&a_meta.height)
        .then_with(|| {
            b_meta
                .validator_bootstrap_capable
                .cmp(&a_meta.validator_bootstrap_capable)
        })
        .then_with(|| b_meta.include_state_nodes.cmp(&a_meta.include_state_nodes))
        .then_with(|| {
            b_meta
                .reachable_state_nodes
                .cmp(&a_meta.reachable_state_nodes)
        })
        .then_with(|| {
            runtime_snapshot_prefer_larger_chunk_size_order_v278(
                a_meta.chunk_size,
                b_meta.chunk_size,
            )
        })
        .then_with(|| a_key.cmp(b_key))
        .then_with(|| match (a_rank_index, b_rank_index) {
            (Some(a_rank), Some(b_rank)) => a_rank.cmp(&b_rank),
            _ => std::cmp::Ordering::Equal,
        })
}

fn runtime_snapshot_allow_cross_family_fallback_v280(
    effective_height_opt: Option<u64>,
    trusted_cert_present: bool,
    trusted_checkpoint_hash: Option<&str>,
) -> bool {
    // V280: only allow downshifting to an older compatible snapshot family when
    // the node did not request/derive a specific trusted checkpoint height. If
    // an explicit cert/height/hash anchor is present, fail closed on that family.
    effective_height_opt.is_none()
        && !trusted_cert_present
        && trusted_checkpoint_hash
            .map(|h| h.trim().is_empty())
            .unwrap_or(true)
}

fn runtime_snapshot_candidate_allowed_for_plan_v280(
    candidate_meta: &SnapshotMeta,
    primary_meta: &SnapshotMeta,
    allow_cross_family_fallback: bool,
) -> bool {
    allow_cross_family_fallback
        || snapshot_meta_same_trust_family_v251(candidate_meta, primary_meta)
}

fn runtime_snapshot_meta_transport_safe_v280(
    meta: &SnapshotMeta,
    cfg: &StateSyncConfig,
) -> Result<(), String> {
    let safe_chunk_size = rrv3_safe_snapshot_chunk_bytes(cfg.rr_v3_max_frame_bytes);
    if (meta.chunk_size as usize) > safe_chunk_size {
        return Err(format!(
            "snapshot_chunk_size_exceeds_rrv3_transport_budget chunk_size={} max_safe_chunk_size={} rr_v3_max_frame_bytes={}",
            meta.chunk_size, safe_chunk_size, cfg.rr_v3_max_frame_bytes
        ));
    }
    Ok(())
}

fn runtime_snapshot_effective_chunk_retry_rounds_v264(configured: usize) -> Result<u32, String> {
    u32::try_from(configured.max(runtime_snapshot_retry_floor_v277()))
        .map_err(|_| "chunk_retry_rounds too large for runtime snapshot fallback".to_string())
}

fn runtime_snapshot_effective_direct_chunk_retry_rounds_v264(configured: usize) -> usize {
    configured.max(runtime_snapshot_retry_floor_v277())
}

fn runtime_snapshot_effective_chunk_timeout_ms_v277(cfg: &StateSyncConfig) -> u64 {
    // V277: chunk transfers are the longest RRv3 state-sync request. Give them
    // a dedicated timeout so a healthy but busy snapshot seed is not treated as
    // a connection drop, without slowing meta/hello paths.
    env_u64(
        "NEWGEN_RUNTIME_SNAPSHOT_CHUNK_TIMEOUT_MS",
        cfg.rr_timeout_ms.max(30_000),
    )
    .max(cfg.rr_timeout_ms)
    .max(1_000)
}

fn runtime_snapshot_dedup_peers_preserve_order_v274(peers: &mut Vec<PeerId>) {
    let mut seen: HashSet<PeerId> = HashSet::new();
    peers.retain(|peer| seen.insert(*peer));
}

fn runtime_snapshot_primary_chunk_start_offset_v274(
    peers_for_bundle: &[PeerId],
    preferred_peer: Option<PeerId>,
) -> usize {
    // V274: keep snapshot transfer single-primary, but do not pin to a fixed
    // alphabetic/validator-name peer such as A. Start each chunk from the last
    // peer that actually served a valid chunk; if that peer disappears from the
    // current compatible bundle, fall back to the first qualified meta provider.
    if peers_for_bundle.is_empty() {
        return 0;
    }
    preferred_peer
        .and_then(|preferred| peers_for_bundle.iter().position(|peer| *peer == preferred))
        .unwrap_or(0)
}

fn runtime_snapshot_promote_preferred_peer_v274(
    preferred_peer: &mut Option<PeerId>,
    successful_peer: PeerId,
) -> bool {
    let changed = preferred_peer
        .map(|current| current != successful_peer)
        .unwrap_or(true);
    *preferred_peer = Some(successful_peer);
    changed
}

fn runtime_snapshot_transfer_mode_v276() -> &'static str {
    // V280: keep the transfer single-primary/sequential to avoid validator-wide
    // fan-out while D bootstraps. Acceleration/stability now comes from fewer
    // RRv3 chunk round trips, preflight 0/last, sticky success, local cooldown,
    // fast inner P2P retry handoff, transport-safe meta filtering, and
    // cross-family fallback when the latest unpinned snapshot is not servable.
    "single_primary_sequential_identical_manifest_key_snapshot_simple_recovery_v286"
}

fn runtime_snapshot_transfer_local_cooldown_penalty_v275(
    class: RuntimeSnapshotChunkFailureClassV251,
) -> u32 {
    match class {
        // V275: meta-refetch/session-turn is not a global reputation fault, but
        // during this transfer it is still a bad provider signal. Cool it down
        // locally so D does not waste every chunk retry on the same stale peer.
        RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired => 1,
        RuntimeSnapshotChunkFailureClassV251::Transport => 1,
        RuntimeSnapshotChunkFailureClassV251::PeerBusy => 2,
        RuntimeSnapshotChunkFailureClassV251::Protocol => 3,
        RuntimeSnapshotChunkFailureClassV251::SnapshotData => 8,
        RuntimeSnapshotChunkFailureClassV251::Permanent => 8,
    }
}

fn runtime_snapshot_preflight_chunk_indices_v275(total_chunks: u32) -> Vec<u32> {
    if total_chunks == 0 {
        return Vec::new();
    }
    let last = total_chunks.saturating_sub(1);
    let mut order = Vec::with_capacity(if last == 0 { 1 } else { 2 });
    order.push(0);
    if last != 0 {
        order.push(last);
    }
    order
}

fn runtime_snapshot_chunk_download_order_v275(total_chunks: u32) -> Vec<u32> {
    if total_chunks == 0 {
        return Vec::new();
    }
    let last = total_chunks.saturating_sub(1);
    let mut order = Vec::with_capacity(total_chunks as usize);
    order.push(0);
    if last != 0 {
        order.push(last);
        for i in 1..last {
            order.push(i);
        }
    }
    order
}

fn runtime_snapshot_chunk_refetch_rotate_error_v251(
    peer: PeerId,
    height: u64,
    chunk_index: u32,
    err: &str,
) -> String {
    format!(
        "snapshot_chunk_session_refetched_rotate_peer_v251 peer={} height={} chunk_index={} err={}",
        peer, height, chunk_index, err
    )
}

fn runtime_snapshot_record_chunk_peer_failure_v251(
    peer_failures: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    chunk_index: u32,
    err: &str,
    context: &str,
) -> RuntimeSnapshotChunkFailureClassV251 {
    let class = runtime_snapshot_chunk_failure_class_v251(err);
    let class_label = match class {
        RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired => "meta_refetch_required",
        RuntimeSnapshotChunkFailureClassV251::Transport => "transport",
        RuntimeSnapshotChunkFailureClassV251::SnapshotData => "snapshot_data",
        RuntimeSnapshotChunkFailureClassV251::Protocol => "protocol",
        RuntimeSnapshotChunkFailureClassV251::PeerBusy => "peer_busy",
        RuntimeSnapshotChunkFailureClassV251::Permanent => "permanent",
    };
    let penalty = runtime_snapshot_chunk_failure_penalty_v251(class);
    let fail_count =
        runtime_snapshot_apply_chunk_peer_failure_penalty_v268(peer_failures, peer, penalty);
    ng_warn!(
        target: "state_sync.bootstrap",
        "event=runtime_snapshot_chunk_peer_failed_v251 context={} chunk_index={} peer={} class={} penalty={} peer_failures={} action=rotate_peer",
        context,
        chunk_index,
        peer,
        class_label,
        penalty,
        fail_count
    );
    class
}

fn runtime_snapshot_record_chunk_peer_failure_v276(
    peer_failures: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    chunk_index: u32,
    err: &str,
    context: &str,
) -> RuntimeSnapshotChunkFailureClassV251 {
    let class = runtime_snapshot_chunk_failure_class_v251(err);
    let class_label = match class {
        RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired => "meta_refetch_required",
        RuntimeSnapshotChunkFailureClassV251::Transport => "transport",
        RuntimeSnapshotChunkFailureClassV251::SnapshotData => "snapshot_data",
        RuntimeSnapshotChunkFailureClassV251::Protocol => "protocol",
        RuntimeSnapshotChunkFailureClassV251::PeerBusy => "peer_busy",
        RuntimeSnapshotChunkFailureClassV251::Permanent => "permanent",
    };
    let reputation_penalty = runtime_snapshot_chunk_failure_penalty_v251(class);
    let transfer_cooldown = runtime_snapshot_transfer_local_cooldown_penalty_v275(class);
    let fail_count = runtime_snapshot_apply_chunk_peer_failure_penalty_v268(
        peer_failures,
        peer,
        transfer_cooldown,
    );
    ng_warn!(
        target: "state_sync.bootstrap",
        "event=runtime_snapshot_chunk_peer_failed_v276 context={} chunk_index={} peer={} class={} reputation_penalty={} transfer_cooldown={} peer_failures={} action=rotate_peer_or_cooldown",
        context,
        chunk_index,
        peer,
        class_label,
        reputation_penalty,
        transfer_cooldown,
        fail_count
    );
    class
}

async fn fetch_runtime_snapshot_chunk(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    peer: PeerId,
    height: u64,
    chunk_index: u32,
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let (tx, rx) = oneshot::channel();
    ctrl.send(P2pControl::FetchSnapshotV2Chunk {
        peer,
        height,
        chunk_index,
        timeout_ms,
        response: tx,
    })
    .map_err(|_| "p2p ctrl channel closed while requesting snapshot chunk".to_string())?;
    rx.await
        .map_err(|_| "p2p snapshot chunk response channel closed".to_string())?
}

async fn fetch_runtime_snapshot_chunk_with_peer_fallback<F, Fut, V>(
    peers_for_bundle: &[PeerId],
    start: usize,
    rounds: u32,
    chunk_index: u32,
    peer_failures: &mut HashMap<PeerId, u32>,
    peer_fail_skip_threshold: u32,
    chunk_retry_backoff_ms: u64,
    mut fetch: F,
    mut validate: V,
) -> Result<(PeerId, Vec<u8>), String>
where
    F: FnMut(PeerId) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
    V: FnMut(PeerId, &[u8]) -> Result<(), String>,
{
    if peers_for_bundle.is_empty() {
        return Err(format!(
            "snapshot_chunk_no_peers_for_bundle_v251 chunk_index={}",
            chunk_index
        ));
    }

    let rounds = rounds.max(1);
    let mut last_chunk_err = String::new();
    let mut class_counts: HashMap<&'static str, u32> = HashMap::new();
    // V253: a suppression-window reset must get one immediate retry pass. V252 cleared
    // peer_failures after all peers were temporarily suppressed, but if that happened on
    // the final configured round the chunk could fail without ever using the reset window.
    let mut round: u32 = 0;
    let mut reset_retry_budget_v253: u32 = 1;

    while round < rounds {
        if round > 0 {
            let backoff = chunk_retry_backoff_ms.saturating_mul(round as u64).max(50);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }

        let mut attempted_this_round: HashSet<PeerId> = HashSet::new();
        let mut round_had_eligible_peer = false;

        for off in 0..peers_for_bundle.len() {
            let peer = peers_for_bundle[(start + off + round as usize) % peers_for_bundle.len()];
            if !attempted_this_round.insert(peer) {
                continue;
            }
            if peer_failures.get(&peer).copied().unwrap_or(0) >= peer_fail_skip_threshold {
                continue;
            }
            round_had_eligible_peer = true;

            let result: Result<Vec<u8>, String> = match fetch(peer).await {
                Ok(bytes) => match validate(peer, &bytes) {
                    Ok(()) => {
                        peer_failures.remove(&peer);
                        return Ok((peer, bytes));
                    }
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            };

            let Err(err) = result else {
                unreachable!("successful chunk fetch returned above");
            };
            let class = runtime_snapshot_chunk_failure_class_v251(&err);
            let class_label = match class {
                RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired => {
                    "meta_refetch_required"
                }
                RuntimeSnapshotChunkFailureClassV251::Transport => "transport",
                RuntimeSnapshotChunkFailureClassV251::SnapshotData => "snapshot_data",
                RuntimeSnapshotChunkFailureClassV251::Protocol => "protocol",
                RuntimeSnapshotChunkFailureClassV251::PeerBusy => "peer_busy",
                RuntimeSnapshotChunkFailureClassV251::Permanent => "permanent",
            };
            *class_counts.entry(class_label).or_insert(0) += 1;
            let reputation_penalty = runtime_snapshot_chunk_failure_penalty_v251(class);
            let transfer_cooldown = runtime_snapshot_transfer_local_cooldown_penalty_v275(class);
            let fail_count = runtime_snapshot_apply_chunk_peer_failure_penalty_v268(
                peer_failures,
                peer,
                transfer_cooldown,
            );
            last_chunk_err = format!(
                "chunk={} peer={} class={} reputation_penalty={} transfer_cooldown={} peer_failures={} err={}",
                chunk_index,
                peer,
                class_label,
                reputation_penalty,
                transfer_cooldown,
                fail_count,
                err
            );
            ng_warn!(
                target: "state_sync.bootstrap",
                "event=runtime_snapshot_chunk_peer_failed_v275 chunk_index={} peer={} round={} class={} reputation_penalty={} transfer_cooldown={} peer_failures={} action=rotate_peer_or_cooldown",
                chunk_index,
                peer,
                round + 1,
                class_label,
                reputation_penalty,
                transfer_cooldown,
                fail_count
            );
        }

        if !round_had_eligible_peer {
            peer_failures.clear();
            ng_warn!(
                target: "state_sync.bootstrap",
                "event=runtime_snapshot_chunk_peer_failure_window_reset_v253 chunk_index={} round={} reason=all_candidate_peers_suppressed action=retry_after_reset",
                chunk_index,
                round + 1
            );
            if reset_retry_budget_v253 > 0 {
                reset_retry_budget_v253 = reset_retry_budget_v253.saturating_sub(1);
                continue;
            }
        }

        round = round.saturating_add(1);
    }

    Err(format!(
        "snapshot_chunk_fetch_exhausted_v251 chunk_index={} peers={} classes={:?} last_error={}",
        chunk_index,
        peers_for_bundle.len(),
        class_counts,
        last_chunk_err
    ))
}

async fn runtime_snapshot_fetch_verify_write_chunk_v275(
    ctrl: &mpsc::UnboundedSender<P2pControl>,
    meta: &SnapshotMeta,
    chunks_dir: &Path,
    peers_for_bundle: &[PeerId],
    chunk_index: u32,
    cfg: &StateSyncConfig,
    peer_failures: &mut HashMap<PeerId, u32>,
    peer_fail_skip_threshold: u32,
    preferred_snapshot_peer_v274: &mut Option<PeerId>,
    context: &str,
) -> Result<Option<(PeerId, usize)>, String> {
    if chunk_index >= meta.chunks {
        return Err(format!(
            "runtime_snapshot_chunk_index_out_of_range_v275 chunk_index={} chunks={}",
            chunk_index, meta.chunks
        ));
    }
    let exp = meta
        .chunk_hashes_hex
        .get(chunk_index as usize)
        .map(|s| s.trim().to_string())
        .ok_or_else(|| {
            format!(
                "runtime_snapshot_missing_chunk_hash_v275 chunk_index={} chunks={}",
                chunk_index, meta.chunks
            )
        })?;
    let fname = format!("{:06}.bin", chunk_index);
    let fpath = chunks_dir.join(&fname);

    // V276: verified reuse is always safe because the chunk is accepted only
    // when its SHA256 matches the active manifest. This avoids downloading the
    // preflight chunks (0/last) twice when resume_partial_download is false,
    // while still removing stale/corrupt chunks from older manifests.
    if runtime_snapshot_verified_existing_chunk_v276(
        &fpath,
        &exp,
        meta.height,
        chunk_index,
        meta.chunks,
        context,
    )? {
        return Ok(None);
    }

    let start = runtime_snapshot_primary_chunk_start_offset_v274(
        peers_for_bundle,
        *preferred_snapshot_peer_v274,
    );
    let chunk_retry_rounds =
        runtime_snapshot_effective_chunk_retry_rounds_v264(cfg.chunk_retry_rounds)?;
    let meta_height = meta.height;
    let meta_chunks = meta.chunks;
    let timeout_ms = runtime_snapshot_effective_chunk_timeout_ms_v277(cfg);

    let (peer, bytes) = fetch_runtime_snapshot_chunk_with_peer_fallback(
        peers_for_bundle,
        start,
        chunk_retry_rounds,
        chunk_index,
        peer_failures,
        peer_fail_skip_threshold,
        cfg.chunk_retry_backoff_ms,
        |peer| {
            let ctrl2 = ctrl.clone();
            async move {
                match fetch_runtime_snapshot_chunk(&ctrl2, peer, meta_height, chunk_index, timeout_ms).await {
                    Err(err) if runtime_snapshot_chunk_error_requires_meta_refetch_v223(&err) => {
                        ng_info!(
                            target: "state_sync.bootstrap",
                            "event=runtime_snapshot_chunk_session_refetch_meta_v251 peer={} height={} chunk_index={} reason=server_requested_meta_refetch action=refetch_meta_then_rotate_peer",
                            peer,
                            meta_height,
                            chunk_index
                        );
                        if let Err(meta_err) = fetch_runtime_snapshot_meta_from_peer(
                            &ctrl2,
                            peer,
                            Some(meta_height),
                            timeout_ms,
                        )
                        .await
                        {
                            ng_warn!(
                                target: "state_sync.bootstrap",
                                "event=runtime_snapshot_meta_refetch_transient_v264 peer={} height={} chunk_index={} err={} action=retry_chunk_without_permanent_suppression",
                                peer,
                                meta_height,
                                chunk_index,
                                meta_err
                            );
                        }
                        Err(runtime_snapshot_chunk_refetch_rotate_error_v251(
                            peer,
                            meta_height,
                            chunk_index,
                            &err,
                        ))
                    }
                    other => other,
                }
            }
        },
        |peer, chunk_bytes| {
            let got = sha256_hex(chunk_bytes);
            if got != exp {
                return Err(format!(
                    "chunk {} sha mismatch from {}: got {} expected {}",
                    chunk_index, peer, got, exp
                ));
            }
            write_file_atomic(&fpath, chunk_bytes)
                .map_err(|e| format!("cannot write chunk {}: {}", chunk_index, e))
        },
    )
    .await?;

    if runtime_snapshot_promote_preferred_peer_v274(preferred_snapshot_peer_v274, peer) {
        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_snapshot_primary_provider_switched_v274 height={} chunk={} peer={} reason=valid_chunk_served",
            meta_height,
            chunk_index,
            peer
        );
    }

    if context == "runtime_snapshot_preflight_v275" {
        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_snapshot_provider_preflight_chunk_verified_v275 height={} chunk={}/{} peer={} bytes={} action=provider_qualified",
            meta_height,
            chunk_index.saturating_add(1),
            meta_chunks,
            peer,
            bytes.len()
        );
    } else if chunk_index == 0
        || chunk_index.saturating_add(1) == meta_chunks
        || chunk_index.saturating_add(1) % 50 == 0
    {
        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_snapshot_download_progress_v222 height={} chunk={}/{} peer={} bytes={}",
            meta_height,
            chunk_index.saturating_add(1),
            meta_chunks,
            peer,
            bytes.len()
        );
    }

    Ok(Some((peer, bytes.len())))
}

pub async fn fetch_snapshot_v2_bundle_via_runtime_ctrl(
    ctrl: mpsc::UnboundedSender<P2pControl>,
    out_dir: &Path,
    height_opt: Option<u64>,
    cfg: StateSyncConfig,
) -> Result<SnapshotMeta, String> {
    let max_snapshot_bytes = env_u64(
        "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_BYTES",
        4 * 1024 * 1024 * 1024,
    )
    .max(1024 * 1024);
    let max_snapshot_chunks = env_u64("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_CHUNKS", 1_000_000).max(1);

    let mut trusted_cert: Option<CheckpointCert> = None;
    let mut allowed_signers_hex: HashSet<String> = HashSet::new();
    let need_vset = cfg.public_mode || cfg.trusted_checkpoint_cert_path.is_some();
    if need_vset {
        allowed_signers_hex = load_bootstrap_validators_hex()?;
    }

    if let Some(path) = cfg.trusted_checkpoint_cert_path.as_ref() {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read trusted checkpoint cert {}: {e}", path))?;
        let cert = serde_json::from_slice::<CheckpointCert>(&bytes)
            .map_err(|e| format!("invalid trusted checkpoint cert JSON {}: {e}", path))?;
        trusted_cert = Some(cert);
    }

    if trusted_cert.is_none() {
        if let Some(cache_path) = cfg.anchor_cache_path.as_ref() {
            trusted_cert = anchor_store::load_checkpoint_cert(cache_path.as_path());
        }
    }

    // V219 minimal-safe: runtime P2P SnapshotV2 bootstrap can hit transient
    // RRv3 dial/connection-close races while the seed is otherwise healthy. Keep
    // direct seed discovery unchanged, but give the live runtime actor enough
    // bounded rounds to complete meta/chunk fetch before failing closed.
    let rounds = cfg.bootstrap_meta_retry_rounds.max(8);
    let base_backoff_ms = cfg.bootstrap_meta_retry_backoff_ms.max(50);
    let ready_timeout_ms = cfg
        .bootstrap_ready_timeout_ms
        .max(cfg.connect_timeout_ms)
        .max(cfg.rr_timeout_ms)
        .max(1_000);
    let runtime_peer_discovery_attempts =
        env_usize("NEWGEN_RUNTIME_SNAPSHOT_PEER_DISCOVERY_ATTEMPTS", 8).max(3);
    let runtime_ready_timeout_ms =
        env_u64("NEWGEN_RUNTIME_SNAPSHOT_READY_TIMEOUT_MS", ready_timeout_ms)
            .max(ready_timeout_ms)
            .max(10_000);
    ng_info!(
        target: "state_sync.bootstrap",
        "event=runtime_snapshot_discovery_policy attempts={} ready_timeout_ms={} base_ready_timeout_ms={} connect_timeout_ms={} rr_timeout_ms={}",
        runtime_peer_discovery_attempts,
        runtime_ready_timeout_ms,
        ready_timeout_ms,
        cfg.connect_timeout_ms,
        cfg.rr_timeout_ms,
    );

    if trusted_cert.is_none() && cfg.public_mode && cfg.auto_fetch_anchor {
        if allowed_signers_hex.is_empty() {
            allowed_signers_hex = load_bootstrap_validators_hex()?;
        }
        let mut best: Option<CheckpointCert> = None;
        for round in 0..rounds {
            if round > 0 {
                let sleep_ms = base_backoff_ms.saturating_mul(round as u64);
                ng_info!(
                    target: "state_sync.anchor",
                    "event=anchor_retry_backoff round={} rounds={} sleep_ms={}",
                    round + 1,
                    rounds,
                    sleep_ms
                );
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
            let peers = match discover_runtime_snapshot_peers_with_backoff(
                &ctrl,
                None,
                runtime_ready_timeout_ms,
                cfg.connect_timeout_ms,
                runtime_peer_discovery_attempts,
            )
            .await
            {
                Ok(v) if !v.is_empty() => v,
                Ok(_) => continue,
                Err(e) => {
                    ng_warn!(
                        target: "state_sync.anchor",
                        "event=anchor_peer_discovery_failed round={} rounds={} err={}",
                        round + 1,
                        rounds,
                        e
                    );
                    continue;
                }
            };
            for peer in peers {
                let cert = match fetch_runtime_checkpoint_cert_from_peer(
                    &ctrl,
                    peer,
                    cfg.rr_timeout_ms.max(500),
                )
                .await
                {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(_) => continue,
                };
                let quorum_k = quorum_k_2of3(allowed_signers_hex.len());
                if let Err(_e) = verify_checkpoint_cert(&cert, quorum_k, &allowed_signers_hex) {
                    continue;
                }
                let replace = match best.as_ref() {
                    None => true,
                    Some(prev) => {
                        cert.checkpoint.height > prev.checkpoint.height
                            || (cert.checkpoint.height == prev.checkpoint.height
                                && cert.checkpoint.ts > prev.checkpoint.ts)
                    }
                };
                if replace {
                    best = Some(cert);
                }
            }
            if best.is_some() {
                break;
            }
        }
        if let Some(cert) = best {
            if let Some(cp) = cfg.anchor_cache_path.as_ref() {
                let _ = anchor_store::save_checkpoint_cert(cp.as_path(), &cert);
            }
            trusted_cert = Some(cert);
        }
    }

    if cfg.public_mode && trusted_cert.is_none() {
        return Err("public mode requires a signed checkpoint cert (provide NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH, cache path, or enable auto-fetch).".to_string());
    }

    let effective_height_opt: Option<u64> = if let Some(cert) = trusted_cert.as_ref() {
        if let Some(h) = height_opt {
            if h != cert.checkpoint.height {
                return Err(
                    "requested snapshot height does not match trusted checkpoint cert height"
                        .to_string(),
                );
            }
        }
        Some(cert.checkpoint.height)
    } else {
        height_opt
    };

    #[derive(Clone)]
    struct RuntimeSnapshotCandidate {
        peer: PeerId,
        key: String,
        meta: SnapshotMeta,
        rank_index: usize,
    }

    #[derive(Clone)]
    struct RuntimeSnapshotBundlePlanV251 {
        key: String,
        meta: SnapshotMeta,
        peers: Vec<PeerId>,
    }

    let mut selected_plans_v251: Vec<RuntimeSnapshotBundlePlanV251> = Vec::new();
    let mut last_err = String::new();

    for round in 0..rounds {
        if round > 0 {
            let sleep_ms = base_backoff_ms.saturating_mul(round as u64);
            ng_info!(
                target: "state_sync.bootstrap",
                "event=runtime_bootstrap_retry_backoff round={} rounds={} sleep_ms={}",
                round + 1,
                rounds,
                sleep_ms
            );
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }

        let peers = match discover_runtime_snapshot_peers_with_backoff(
            &ctrl,
            effective_height_opt,
            runtime_ready_timeout_ms,
            cfg.connect_timeout_ms,
            runtime_peer_discovery_attempts,
        )
        .await
        {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                last_err = format!(
                    "runtime bootstrap found no reachable peers for snapshot meta after discovery backoff (round {}/{})",
                    round + 1,
                    rounds
                );
                continue;
            }
            Err(e) => {
                last_err = e;
                continue;
            }
        };

        let mut rr_successes = 0usize;
        let mut meta_responses = 0usize;
        let mut rejected = 0usize;
        let mut candidates: Vec<RuntimeSnapshotCandidate> = Vec::new();

        for (peer_rank, peer) in peers.iter().copied().enumerate() {
            let candidate = match fetch_runtime_snapshot_meta_from_peer(
                &ctrl,
                peer,
                effective_height_opt,
                cfg.rr_timeout_ms.max(500),
            )
            .await
            {
                Ok(c) => {
                    rr_successes += 1;
                    c
                }
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };

            meta_responses += 1;
            let meta = &candidate.meta;
            let mut usable = true;

            if let Err(err) = snapshot_meta_usable_for_validator_bootstrap(meta) {
                ng_warn_throttle!(
                    key: format!("runtime_snapshot_meta_rejected_validator_bootstrap_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_meta_rejected peer={} reason={}",
                    peer,
                    err
                );
                usable = false;
            }

            if usable && (meta.chunks == 0 || meta.chunk_hashes_hex.len() != meta.chunks as usize) {
                ng_warn_throttle!(
                    key: format!("runtime_snapshot_meta_rejected_chunk_layout_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_meta_rejected peer={} reason=invalid_chunk_layout chunks={} chunk_hashes={}",
                    peer,
                    meta.chunks,
                    meta.chunk_hashes_hex.len()
                );
                usable = false;
            }
            if usable
                && (meta.bytes_len > max_snapshot_bytes
                    || (meta.chunks as u64) > max_snapshot_chunks)
            {
                ng_warn_throttle!(
                    key: format!("runtime_snapshot_meta_rejected_limits_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_meta_rejected peer={} reason=snapshot_limits_exceeded bytes_len={} max_bytes={} chunks={} max_chunks={}",
                    peer,
                    meta.bytes_len,
                    max_snapshot_bytes,
                    meta.chunks,
                    max_snapshot_chunks
                );
                usable = false;
            }
            if usable {
                if let Err(err) = runtime_snapshot_meta_transport_safe_v280(meta, &cfg) {
                    ng_warn_throttle!(
                        key: format!("runtime_snapshot_meta_rejected_transport_budget_{}", peer),
                        every_ms: 30_000,
                        target: "state_sync.bootstrap",
                        "event=runtime_snapshot_meta_rejected peer={} reason={}",
                        peer,
                        err
                    );
                    usable = false;
                }
            }
            if usable
                && !cfg.expected_genesis_hash.trim().is_empty()
                && !meta.genesis_hash.trim().is_empty()
                && meta.genesis_hash != cfg.expected_genesis_hash
            {
                ng_warn_throttle!(
                    key: format!("runtime_snapshot_meta_rejected_genesis_{}", peer),
                    every_ms: 30_000,
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_meta_rejected peer={} reason=genesis_mismatch meta_genesis={} expected_genesis={}",
                    peer,
                    meta.genesis_hash,
                    cfg.expected_genesis_hash
                );
                usable = false;
            }
            if usable {
                if let Err(err) = snapshot_meta_satisfies_progress_gate(meta, &cfg) {
                    ng_warn_throttle!(
                        key: format!("runtime_snapshot_meta_rejected_progress_{}_{}", peer, meta.height),
                        every_ms: 30_000,
                        target: "state_sync.bootstrap",
                        "event=runtime_snapshot_meta_rejected peer={} reason={}",
                        peer,
                        err
                    );
                    usable = false;
                }
            }
            if usable {
                if let Some(cert) = trusted_cert.as_ref() {
                    if let Err(err) = verify_snapshot_meta_against_checkpoint_cert(
                        meta,
                        &cfg,
                        cert,
                        &allowed_signers_hex,
                    ) {
                        ng_warn_throttle!(
                            key: format!("runtime_snapshot_meta_rejected_anchor_{}", peer),
                            every_ms: 30_000,
                            target: "state_sync.bootstrap",
                            "event=runtime_snapshot_meta_rejected peer={} reason=anchor_verification_failed err={}",
                            peer,
                            err
                        );
                        usable = false;
                    }
                } else if let Some(anchor) = cfg.trusted_checkpoint_hash.as_ref() {
                    if !anchor.trim().is_empty() && meta.checkpoint_block_hash != *anchor {
                        ng_warn_throttle!(
                            key: format!("runtime_snapshot_meta_rejected_anchor_hash_{}", peer),
                            every_ms: 30_000,
                            target: "state_sync.bootstrap",
                            "event=runtime_snapshot_meta_rejected peer={} reason=checkpoint_anchor_hash_mismatch meta_checkpoint={} expected_anchor={}",
                            peer,
                            meta.checkpoint_block_hash,
                            anchor
                        );
                        usable = false;
                    }
                }
            }

            if !usable {
                rejected += 1;
                continue;
            }

            candidates.push(RuntimeSnapshotCandidate {
                peer: candidate.peer,
                key: meta_key(meta, candidate.meta_sha256_hex.as_ref()),
                meta: candidate.meta.clone(),
                rank_index: peer_rank,
            });
        }

        if candidates.is_empty() {
            last_err = if rr_successes == 0 {
                format!(
                    "no peer responded to snapshot-v2 meta requests after {} rounds",
                    round + 1
                )
            } else if meta_responses == 0 {
                format!(
                    "snapshot-v2 requests reached peers but no meta responses were returned (round {}/{})",
                    round + 1,
                    rounds
                )
            } else {
                format!(
                    "snapshot-v2 meta responses were all rejected (round {}/{}, rejected={})",
                    round + 1,
                    rounds,
                    rejected
                )
            };
            ng_warn!(
                target: "state_sync.bootstrap",
                "event=runtime_bootstrap_no_usable_meta round={} rounds={} rr_successes={} meta_responses={} rejected={}",
                round + 1,
                rounds,
                rr_successes,
                meta_responses,
                rejected
            );
            continue;
        }

        candidates.sort_by(|a, b| {
            runtime_snapshot_candidate_selection_order_v279(
                &a.meta,
                &a.key,
                Some(a.rank_index),
                &b.meta,
                &b.key,
                Some(b.rank_index),
            )
        });
        let chosen = candidates[0].clone();
        let allow_cross_family_fallback_v280 = runtime_snapshot_allow_cross_family_fallback_v280(
            effective_height_opt,
            trusted_cert.is_some(),
            cfg.trusted_checkpoint_hash.as_deref(),
        );
        let mut plans: Vec<RuntimeSnapshotBundlePlanV251> = Vec::new();
        for candidate in candidates.iter() {
            if !runtime_snapshot_candidate_allowed_for_plan_v280(
                &candidate.meta,
                &chosen.meta,
                allow_cross_family_fallback_v280,
            ) {
                continue;
            }
            if let Some(plan) = plans.iter_mut().find(|plan| {
                snapshot_meta_same_download_manifest_key_v286(
                    &plan.key,
                    &plan.meta,
                    &candidate.key,
                    &candidate.meta,
                )
            }) {
                plan.peers.push(candidate.peer);
            } else {
                plans.push(RuntimeSnapshotBundlePlanV251 {
                    key: candidate.key.clone(),
                    meta: candidate.meta.clone(),
                    peers: vec![candidate.peer],
                });
            }
        }
        for plan in plans.iter_mut() {
            runtime_snapshot_dedup_peers_preserve_order_v274(&mut plan.peers);
        }
        plans.sort_by(|a, b| {
            let a_primary_family = snapshot_meta_same_trust_family_v251(&a.meta, &chosen.meta);
            let b_primary_family = snapshot_meta_same_trust_family_v251(&b.meta, &chosen.meta);
            b_primary_family
                .cmp(&a_primary_family)
                .then_with(|| {
                    runtime_snapshot_candidate_selection_order_v279(
                        &a.meta, &a.key, None, &b.meta, &b.key, None,
                    )
                })
                .then_with(|| b.peers.len().cmp(&a.peers.len()))
        });
        selected_plans_v251 = plans;

        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_bootstrap_meta_selected_v251 round={} rounds={} rr_successes={} meta_responses={} rejected={} bundle_plans={} primary_peers={} primary_chunk_size={}",
            round + 1,
            rounds,
            rr_successes,
            meta_responses,
            rejected,
            selected_plans_v251.len(),
            selected_plans_v251.first().map(|p| p.peers.len()).unwrap_or(0),
            selected_plans_v251.first().map(|p| p.meta.chunk_size).unwrap_or(0)
        );
        break;
    }

    if selected_plans_v251.is_empty() {
        return Err(if last_err.is_empty() {
            format!(
                "runtime actor did not provide a usable snapshot-v2 meta after {} rounds",
                rounds
            )
        } else {
            last_err.clone()
        });
    }

    let peer_fail_skip_threshold: u32 = 8;
    let mut last_plan_err_v251 = String::new();

    'plan_v251: for (plan_index_v251, plan_v251) in selected_plans_v251.iter().enumerate() {
        let meta = plan_v251.meta.clone();
        let peers_for_bundle = plan_v251.peers.clone();
        let (meta_path, chunks_dir) = out_paths(out_dir);
        std::fs::create_dir_all(&chunks_dir)
            .map_err(|e| format!("cannot create out dir {}: {e}", out_dir.display()))?;

        let meta_bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| format!("cannot serialize meta.json: {e}"))?;
        write_file_atomic(&meta_path, &meta_bytes)
            .map_err(|e| format!("cannot write meta.json atomically: {e}"))?;

        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_snapshot_bundle_plan_start_v251 plan={}/{} height={} chunk_size={} chunks={} peers={} reason={}",
            plan_index_v251 + 1,
            selected_plans_v251.len(),
            meta.height,
            meta.chunk_size,
            meta.chunks,
            peers_for_bundle.len(),
            if plan_index_v251 == 0 { "primary" } else { "fallback_or_downshift" }
        );

        let mut peer_failures: HashMap<PeerId, u32> = HashMap::new();
        let mut preferred_snapshot_peer_v274: Option<PeerId> = peers_for_bundle.first().copied();
        let transfer_mode_v276 = runtime_snapshot_transfer_mode_v276();
        if let Some(peer) = preferred_snapshot_peer_v274 {
            ng_info!(
                target: "state_sync.bootstrap",
                "event=runtime_snapshot_primary_provider_selected_v274 plan={}/{} height={} peer={} reason=first_qualified_meta_provider transfer_mode_v276={}",
                plan_index_v251 + 1,
                selected_plans_v251.len(),
                meta.height,
                peer,
                transfer_mode_v276
            );
        }

        // V275 bootstrap accelerator: qualify the provider before committing to a
        // long transfer. Chunk 0 proves the beginning of the bundle; last chunk
        // proves the selected provider can actually serve the end of the latest
        // finalized bundle. Both use sticky single-primary failover, so a stale A
        // is cooled down and the first peer serving valid bytes becomes primary.
        for preflight_chunk_v275 in runtime_snapshot_preflight_chunk_indices_v275(meta.chunks) {
            match runtime_snapshot_fetch_verify_write_chunk_v275(
                &ctrl,
                &meta,
                &chunks_dir,
                &peers_for_bundle,
                preflight_chunk_v275,
                &cfg,
                &mut peer_failures,
                peer_fail_skip_threshold,
                &mut preferred_snapshot_peer_v274,
                "runtime_snapshot_preflight_v275",
            )
            .await
            {
                Ok(_) => {}
                Err(err) => {
                    last_plan_err_v251 = format!(
                        "runtime actor failed snapshot provider preflight chunk {} from peers [{}]: {}",
                        preflight_chunk_v275,
                        peers_for_bundle
                            .iter()
                            .map(|p| p.to_base58())
                            .collect::<Vec<_>>()
                            .join(","),
                        err
                    );
                    if plan_index_v251 + 1 < selected_plans_v251.len() {
                        ng_warn!(
                            target: "state_sync.bootstrap",
                            "event=runtime_snapshot_provider_preflight_failed_v275 plan={}/{} height={} chunk={} peers={} err={} action=try_next_snapshot_bundle_plan_v280",
                            plan_index_v251 + 1,
                            selected_plans_v251.len(),
                            meta.height,
                            preflight_chunk_v275,
                            peers_for_bundle.len(),
                            last_plan_err_v251
                        );
                        continue 'plan_v251;
                    }
                    return Err(last_plan_err_v251);
                }
            }
        }

        let download_order_v275 = runtime_snapshot_chunk_download_order_v275(meta.chunks);
        ng_info!(
            target: "state_sync.bootstrap",
            "event=runtime_snapshot_download_order_selected_v275 height={} chunks={} order=preflight_0_last_then_linear transfer_mode_v276={}",
            meta.height,
            meta.chunks,
            transfer_mode_v276
        );

        for i in download_order_v275 {
            if let Err(err) = runtime_snapshot_fetch_verify_write_chunk_v275(
                &ctrl,
                &meta,
                &chunks_dir,
                &peers_for_bundle,
                i,
                &cfg,
                &mut peer_failures,
                peer_fail_skip_threshold,
                &mut preferred_snapshot_peer_v274,
                "runtime_snapshot_download_v275",
            )
            .await
            {
                last_plan_err_v251 = format!(
                    "runtime actor failed to download snapshot chunk {} from peers [{}]: {}",
                    i,
                    peers_for_bundle
                        .iter()
                        .map(|p| p.to_base58())
                        .collect::<Vec<_>>()
                        .join(","),
                    err
                );
                if plan_index_v251 + 1 < selected_plans_v251.len() {
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=runtime_snapshot_bundle_plan_failed_downshift_v276 plan={}/{} height={} chunk={} peers={} err={} action=try_next_snapshot_bundle_plan_v280",
                        plan_index_v251 + 1,
                        selected_plans_v251.len(),
                        meta.height,
                        i,
                        peers_for_bundle.len(),
                        last_plan_err_v251
                    );
                    continue 'plan_v251;
                }
                return Err(last_plan_err_v251);
            }
        }
        verify_snapshot_chunk_bytes_len(&meta, &chunks_dir)?;
        return Ok(meta);
    }

    Err(if last_plan_err_v251.is_empty() {
        "runtime actor failed to download snapshot bundle from all V251 plans".to_string()
    } else {
        last_plan_err_v251
    })
}

/// Downloads a snapshot v2 bundle from seed peers into `out_dir`.
///
/// Returns the selected `SnapshotMeta` on success.
pub async fn fetch_snapshot_v2_bundle_from_seeds(
    seed_multiaddrs: Vec<String>,
    out_dir: &Path,
    height_opt: Option<u64>,
    cfg: StateSyncConfig,
) -> Result<SnapshotMeta, String> {
    if seed_multiaddrs.is_empty() {
        return Err("no seed peers provided".to_string());
    }

    // --- Trust anchor resolution
    //
    // In public mode, we require a *signed* checkpoint cert, but it can come from:
    // 1) explicit file path (NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH)
    // 2) cached cert on disk (NEWGEN_ANCHOR_CACHE_PATH)
    // 3) fetched from peers (RRv3) and cached (if auto_fetch_anchor=true)
    //
    // Hash-only anchors are never accepted in public mode.
    if cfg.public_mode && cfg.trusted_checkpoint_hash.is_some() {
        return Err(
            "public mode does not accept NEWGEN_TRUSTED_CHECKPOINT_HASH (hash-only). Use a signed cert or enable auto-fetch."
                .to_string(),
        );
    }

    let mut trusted_cert: Option<CheckpointCert> = None;
    let mut allowed_signers_hex: HashSet<String> = HashSet::new();

    // We only need the validator set when verifying a cert.
    let need_vset = cfg.public_mode || cfg.trusted_checkpoint_cert_path.is_some();

    if need_vset {
        allowed_signers_hex = load_bootstrap_validators_hex()?;
    }

    // 1) explicit cert path
    if let Some(p) = cfg.trusted_checkpoint_cert_path.as_ref() {
        trusted_cert = Some(read_checkpoint_cert_from_path(p)?);
    }

    // 2) cache path
    if trusted_cert.is_none() {
        if let Some(cp) = cfg.anchor_cache_path.as_ref() {
            trusted_cert = anchor_store::load_checkpoint_cert(cp.as_path());
            if trusted_cert.is_some() && allowed_signers_hex.is_empty() {
                allowed_signers_hex = load_bootstrap_validators_hex()?;
            }
        }
    }

    // Parse + dedup
    let mut seeds: Vec<Multiaddr> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for s in seed_multiaddrs {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if !seen.insert(t.to_string()) {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(a) => seeds.push(a),
            Err(_) => {
                // keep going
                continue;
            }
        }
    }
    if seeds.is_empty() {
        return Err("no valid seed multiaddrs".to_string());
    }

    // Build swarm (req-res only)
    let local_keys = identity::Keypair::generate_ed25519();
    let rr_cfg = request_response::Config::default()
        .with_request_timeout(Duration::from_millis(cfg.rr_timeout_ms));
    let protocols = std::iter::once((RR_V3.to_string(), request_response::ProtocolSupport::Full));
    let reqres_v3 = request_response::Behaviour::with_codec(
        NewgenHeadersCodec {
            max_frame_bytes: cfg.rr_v3_max_frame_bytes,
        },
        protocols,
        rr_cfg,
    );

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_keys)
        .with_tokio()
        .with_tcp(
            TcpConfig::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("swarm builder (tcp/noise/yamux) failed: {e}"))?
        .with_behaviour(move |_| Ok(StateSyncBehaviour { reqres_v3 }))
        .map_err(|e| format!("swarm builder behaviour failed: {e}"))?
        .build();

    // Listen on ephemeral local port
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .map_err(|e| format!("listen failed: {e}"))?;

    // Connect to as many seed peers as available (best-effort)
    let peers = connect_peers(&mut swarm, &seeds, cfg.connect_timeout_ms).await?;

    let max_snapshot_bytes = env_u64(
        "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_BYTES",
        10_u64 * 1024 * 1024 * 1024,
    )
    .max(1024 * 1024);
    let max_snapshot_chunks = env_u64("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_CHUNKS", 100_000).max(1);

    // 3) auto-fetch cert from peers (public mode)
    if trusted_cert.is_none() && cfg.public_mode && cfg.auto_fetch_anchor {
        if allowed_signers_hex.is_empty() {
            allowed_signers_hex = load_bootstrap_validators_hex()?;
        }
        let fetched =
            fetch_best_checkpoint_cert_from_peers(&mut swarm, &peers, &cfg, &allowed_signers_hex)
                .await?;
        if let Some(cert) = fetched {
            // Persist best-effort
            if let Some(cp) = cfg.anchor_cache_path.as_ref() {
                let _ = anchor_store::save_checkpoint_cert(cp.as_path(), &cert);
            }
            trusted_cert = Some(cert);
        }
    }

    // In public mode, anchor is mandatory (fail-closed).
    if cfg.public_mode && trusted_cert.is_none() {
        return Err("public mode requires a signed checkpoint cert (provide NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH, cache path, or enable auto-fetch).".to_string());
    }

    // --- Discover meta (query peers, select best)
    // If we have a trusted cert, force snapshot height to cert height (mainnet-grade).
    let effective_height_opt: Option<u64> = if let Some(cert) = trusted_cert.as_ref() {
        if let Some(h) = height_opt {
            if h != cert.checkpoint.height {
                return Err(
                    "requested snapshot height does not match trusted checkpoint cert height"
                        .to_string(),
                );
            }
        }
        Some(cert.checkpoint.height)
    } else {
        height_opt
    };

    let mut candidates = discover_snapshot_v2_candidates_with_retry(
        &mut swarm,
        &peers,
        effective_height_opt,
        &cfg,
        trusted_cert.as_ref(),
        &allowed_signers_hex,
        max_snapshot_bytes,
        max_snapshot_chunks,
    )
    .await?;

    // Select best: highest height; prefer including state nodes and larger
    // transport-safe chunks. V280 keeps lower-height/progressive families as
    // fallback plans when no explicit trusted height/hash/cert pins the request.
    candidates.sort_by(|a, b| {
        runtime_snapshot_candidate_selection_order_v279(
            &a.meta, &a.key, None, &b.meta, &b.key, None,
        )
    });
    let selected = candidates[0].clone();
    let allow_cross_family_fallback_v280 = runtime_snapshot_allow_cross_family_fallback_v280(
        effective_height_opt,
        trusted_cert.is_some(),
        cfg.trusted_checkpoint_hash.as_deref(),
    );

    #[derive(Clone)]
    struct DirectSnapshotBundlePlanV252 {
        key: String,
        meta: SnapshotMeta,
        peers: Vec<PeerId>,
    }

    let mut selected_plans_v252: Vec<DirectSnapshotBundlePlanV252> = Vec::new();
    for candidate in candidates.iter() {
        if !runtime_snapshot_candidate_allowed_for_plan_v280(
            &candidate.meta,
            &selected.meta,
            allow_cross_family_fallback_v280,
        ) {
            continue;
        }
        if let Some(plan) = selected_plans_v252.iter_mut().find(|plan| {
            snapshot_meta_same_download_manifest_key_v286(
                &plan.key,
                &plan.meta,
                &candidate.key,
                &candidate.meta,
            )
        }) {
            plan.peers.push(candidate.peer);
        } else {
            selected_plans_v252.push(DirectSnapshotBundlePlanV252 {
                key: candidate.key.clone(),
                meta: candidate.meta.clone(),
                peers: vec![candidate.peer],
            });
        }
    }
    for plan in selected_plans_v252.iter_mut() {
        runtime_snapshot_dedup_peers_preserve_order_v274(&mut plan.peers);
    }
    selected_plans_v252.sort_by(|a, b| {
        let a_primary_family = snapshot_meta_same_trust_family_v251(&a.meta, &selected.meta);
        let b_primary_family = snapshot_meta_same_trust_family_v251(&b.meta, &selected.meta);
        b_primary_family
            .cmp(&a_primary_family)
            .then_with(|| {
                runtime_snapshot_candidate_selection_order_v279(
                    &a.meta, &a.key, None, &b.meta, &b.key, None,
                )
            })
            .then_with(|| b.peers.len().cmp(&a.peers.len()))
    });

    if selected_plans_v252.is_empty() {
        return Err("no verified direct seed snapshot bundle plan available".to_string());
    }

    let peer_fail_skip_threshold: u32 = 8;
    let mut last_plan_err_v252 = String::new();

    'direct_plan_v252: for (plan_index_v252, plan_v252) in selected_plans_v252.iter().enumerate() {
        let meta = plan_v252.meta.clone();
        let peers_for_bundle = plan_v252.peers.clone();
        if peers_for_bundle.is_empty() {
            last_plan_err_v252 = format!(
                "direct seed snapshot plan {} has no peers height={} chunk_size={} chunks={}",
                plan_index_v252 + 1,
                meta.height,
                meta.chunk_size,
                meta.chunks
            );
            continue;
        }

        ng_info!(
            target: "state_sync.bootstrap",
            "event=direct_snapshot_bundle_plan_start_v252 plan={}/{} height={} chunk_size={} chunks={} peers={} reason={}",
            plan_index_v252 + 1,
            selected_plans_v252.len(),
            meta.height,
            meta.chunk_size,
            meta.chunks,
            peers_for_bundle.len(),
            if plan_index_v252 == 0 { "primary" } else { "fallback_or_downshift" }
        );

        // --- Persist meta for the active plan only. If chunk 0 forces a downshift plan,
        // this overwrites meta.json before any successful chunk from the previous plan is trusted.
        let (meta_path, chunks_dir) = out_paths(out_dir);
        std::fs::create_dir_all(&chunks_dir)
            .map_err(|e| format!("cannot create out dir {}: {e}", out_dir.display()))?;

        let meta_bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| format!("cannot serialize meta.json: {e}"))?;
        write_file_atomic(&meta_path, &meta_bytes)
            .map_err(|e| format!("cannot write meta.json atomically: {e}"))?;

        // --- Fetch chunks with multi-peer fallback + retry/backoff + optional resume.
        // V252 keeps direct seed behavior aligned with the runtime-ctrl path:
        // classify errors, rotate peers, refetch meta without immediate same-session retry,
        // reset suppression windows, and downshift to a compatible bundle plan when chunk 0 fails.
        let mut peer_failures: HashMap<PeerId, u32> = HashMap::new();
        let mut preferred_snapshot_peer_v274: Option<PeerId> = peers_for_bundle.first().copied();
        if let Some(peer) = preferred_snapshot_peer_v274 {
            ng_info!(
                target: "state_sync.bootstrap",
                "event=direct_snapshot_primary_provider_selected_v274 plan={}/{} height={} peer={} reason=first_qualified_meta_provider",
                plan_index_v252 + 1,
                selected_plans_v252.len(),
                meta.height,
                peer
            );
        }

        let download_order_v275 = runtime_snapshot_chunk_download_order_v275(meta.chunks);
        let preflight_chunks_v275 = runtime_snapshot_preflight_chunk_indices_v275(meta.chunks);
        ng_info!(
            target: "state_sync.bootstrap",
            "event=direct_snapshot_download_order_selected_v275 height={} chunks={} order=preflight_0_last_then_linear",
            meta.height,
            meta.chunks
        );

        for i in download_order_v275 {
            let exp = meta.chunk_hashes_hex[i as usize].trim().to_string();
            let fname = format!("{:06}.bin", i);
            let fpath = chunks_dir.join(&fname);
            let mut ok = false;

            // V276: verified reuse is safe even when resume_partial_download is
            // false, because acceptance is tied to the active manifest hash. This
            // prevents preflight chunk 0/last from being fetched twice and removes
            // stale chunks from older bundle plans before redownloading.
            if runtime_snapshot_verified_existing_chunk_v276(
                &fpath,
                &exp,
                meta.height,
                i,
                meta.chunks,
                "direct_snapshot_download_v276",
            )? {
                continue;
            }

            // V274: sticky single-primary provider for direct seeds as well.
            // If the initial provider is stale/non-validator/unable to serve chunks,
            // the peer that successfully serves a valid chunk is promoted for the
            // remaining chunks instead of trying the bad provider first every time.
            let start = runtime_snapshot_primary_chunk_start_offset_v274(
                &peers_for_bundle,
                preferred_snapshot_peer_v274,
            );

            let rounds =
                runtime_snapshot_effective_direct_chunk_retry_rounds_v264(cfg.chunk_retry_rounds);
            let chunk_timeout_ms_v277 = runtime_snapshot_effective_chunk_timeout_ms_v277(&cfg);
            let mut round: usize = 0;
            let mut reset_retry_budget_v253: usize = 1;
            while round < rounds {
                let mut attempted_this_round: HashSet<PeerId> = HashSet::new();
                let mut round_had_eligible_peer = false;

                for off in 0..peers_for_bundle.len() {
                    let peer = peers_for_bundle[(start + off + round) % peers_for_bundle.len()];
                    if !attempted_this_round.insert(peer) {
                        continue;
                    }

                    if peer_failures.get(&peer).copied().unwrap_or(0) >= peer_fail_skip_threshold {
                        continue;
                    }
                    round_had_eligible_peer = true;

                    let resp = match rr_call(
                        &mut swarm,
                        peer,
                        RrV3Msg::GetSnapshotV2Chunk {
                            height: meta.height,
                            chunk_index: i,
                        },
                        chunk_timeout_ms_v277,
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(err) => {
                            runtime_snapshot_record_chunk_peer_failure_v276(
                                &mut peer_failures,
                                peer,
                                i,
                                &err,
                                "direct_seed_rr_call_v252",
                            );
                            continue;
                        }
                    };

                    if let RrV3Msg::Error { code, message } = &resp {
                        if runtime_snapshot_chunk_error_requires_meta_refetch_v223(message) {
                            ng_info!(
                                target: "state_sync.bootstrap",
                                "event=direct_snapshot_chunk_session_refetch_meta_v252 peer={} height={} chunk_index={} code={} reason=server_requested_meta_refetch action=refetch_meta_then_rotate_peer",
                                peer,
                                meta.height,
                                i,
                                code
                            );
                            let _ = rr_call(
                                &mut swarm,
                                peer,
                                RrV3Msg::GetSnapshotV2Meta {
                                    height: meta.height,
                                },
                                cfg.rr_timeout_ms,
                            )
                            .await;
                            let err = runtime_snapshot_chunk_refetch_rotate_error_v251(
                                peer,
                                meta.height,
                                i,
                                message,
                            );
                            runtime_snapshot_record_chunk_peer_failure_v276(
                                &mut peer_failures,
                                peer,
                                i,
                                &err,
                                "direct_seed_refetch_meta_v252",
                            );
                            continue;
                        }

                        let err = format!(
                            "runtime snapshot chunk peer error code={} msg={} height={} chunk_index={}",
                            code, message, meta.height, i
                        );
                        runtime_snapshot_record_chunk_peer_failure_v276(
                            &mut peer_failures,
                            peer,
                            i,
                            &err,
                            "direct_seed_peer_error_v252",
                        );
                        continue;
                    }

                    let (height, idx, data_b64) = match resp {
                        RrV3Msg::SnapshotV2Chunk {
                            height,
                            chunk_index,
                            data_b64,
                        } => (height, chunk_index, data_b64),
                        other => {
                            let err = format!(
                                "runtime snapshot chunk response kind mismatch expected=SnapshotV2Chunk received={} height={} chunk_index={}",
                                rr_v3_snapshot_response_kind(&other),
                                meta.height,
                                i
                            );
                            runtime_snapshot_record_chunk_peer_failure_v276(
                                &mut peer_failures,
                                peer,
                                i,
                                &err,
                                "direct_seed_kind_mismatch_v252",
                            );
                            continue;
                        }
                    };

                    if height != meta.height || idx != i {
                        let err = format!(
                            "runtime snapshot chunk correlation mismatch expected_height={} expected_chunk_index={} received_height={} received_chunk_index={}",
                            meta.height, i, height, idx
                        );
                        runtime_snapshot_record_chunk_peer_failure_v276(
                            &mut peer_failures,
                            peer,
                            i,
                            &err,
                            "direct_seed_correlation_mismatch_v252",
                        );
                        continue;
                    }

                    let bytes = match STANDARD.decode(data_b64.as_bytes()) {
                        Ok(b) => b,
                        Err(err) => {
                            runtime_snapshot_record_chunk_peer_failure_v276(
                                &mut peer_failures,
                                peer,
                                i,
                                &format!("invalid base64 snapshot chunk: {}", err),
                                "direct_seed_base64_v252",
                            );
                            continue;
                        }
                    };

                    let got = sha256_hex(&bytes);
                    if got != exp {
                        let err = format!(
                            "chunk {} sha mismatch from {}: got {} expected {}",
                            i, peer, got, exp
                        );
                        runtime_snapshot_record_chunk_peer_failure_v276(
                            &mut peer_failures,
                            peer,
                            i,
                            &err,
                            "direct_seed_sha_mismatch_v252",
                        );
                        continue;
                    }

                    write_file_atomic(&fpath, &bytes)
                        .map_err(|e| format!("cannot write chunk file atomically: {e}"))?;

                    peer_failures.remove(&peer);

                    ok = true;
                    if runtime_snapshot_promote_preferred_peer_v274(
                        &mut preferred_snapshot_peer_v274,
                        peer,
                    ) {
                        ng_info!(
                            target: "state_sync.bootstrap",
                            "event=direct_snapshot_primary_provider_switched_v274 height={} chunk={} peer={} reason=valid_chunk_served",
                            meta.height,
                            i,
                            peer
                        );
                    }
                    if i == 0 || i.saturating_add(1) == meta.chunks || i.saturating_add(1) % 50 == 0
                    {
                        ng_info!(
                            target: "state_sync.bootstrap",
                            "event=direct_snapshot_download_progress_v252 height={} chunk={}/{} peer={} bytes={}",
                            meta.height,
                            i.saturating_add(1),
                            meta.chunks,
                            peer,
                            bytes.len()
                        );
                    }
                    break;
                }

                if ok {
                    break;
                }

                if !round_had_eligible_peer {
                    peer_failures.clear();
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=direct_snapshot_chunk_peer_failure_window_reset_v253 height={} chunk_index={} round={} reason=all_candidate_peers_suppressed action=retry_after_reset",
                        meta.height,
                        i,
                        round + 1
                    );
                    if reset_retry_budget_v253 > 0 {
                        reset_retry_budget_v253 = reset_retry_budget_v253.saturating_sub(1);
                        continue;
                    }
                }

                // Progressive backoff between rounds (except after the last round).
                if round + 1 < rounds {
                    let ms = cfg
                        .chunk_retry_backoff_ms
                        .saturating_mul((round as u64).saturating_add(1));
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
                round = round.saturating_add(1);
            }

            if !ok {
                last_plan_err_v252 = format!(
                    "failed to download verified chunk {} after {} rounds from direct seed peers [{}] plan={}/{} height={} chunk_size={}",
                    i,
                    rounds,
                    peers_for_bundle
                        .iter()
                        .map(|p| p.to_base58())
                        .collect::<Vec<_>>()
                        .join(","),
                    plan_index_v252 + 1,
                    selected_plans_v252.len(),
                    meta.height,
                    meta.chunk_size
                );
                if plan_index_v252 + 1 < selected_plans_v252.len() {
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=direct_snapshot_bundle_plan_failed_downshift_v276 plan={}/{} height={} chunk={} chunk_size={} peers={} preflight={} err={} action=try_next_snapshot_bundle_plan_v280",
                        plan_index_v252 + 1,
                        selected_plans_v252.len(),
                        meta.height,
                        i,
                        meta.chunk_size,
                        peers_for_bundle.len(),
                        preflight_chunks_v275.contains(&i),
                        last_plan_err_v252
                    );
                    continue 'direct_plan_v252;
                }
                return Err(last_plan_err_v252);
            }
        }
        verify_snapshot_chunk_bytes_len(&meta, &chunks_dir)?;
        return Ok(meta);
    }

    Err(if last_plan_err_v252.is_empty() {
        "direct seed failed to download snapshot bundle from all V252 plans".to_string()
    } else {
        last_plan_err_v252
    })
}

/// Fetch the best/latest checkpoint cert from seed peers (RRv3).
///
/// This is used to make the anchor **self-updating**: a node can join without a manual cert file,
/// by fetching a quorum-signed cert from peers and caching it.
///
/// Returns `Ok(None)` if no seed returned a valid cert.
pub async fn fetch_checkpoint_cert_latest_from_seeds(
    seed_multiaddrs: Vec<String>,
    cfg: StateSyncConfig,
) -> Result<Option<CheckpointCert>, String> {
    if seed_multiaddrs.is_empty() {
        return Ok(None);
    }

    if cfg.public_mode && cfg.trusted_checkpoint_hash.is_some() {
        return Err("public mode does not accept hash-only anchors".to_string());
    }

    // Parse + dedup
    let mut seeds: Vec<Multiaddr> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for s in seed_multiaddrs {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if !seen.insert(t.to_string()) {
            continue;
        }
        if let Ok(a) = t.parse::<Multiaddr>() {
            seeds.push(a);
        }
    }
    if seeds.is_empty() {
        return Ok(None);
    }

    let allowed_signers_hex = load_bootstrap_validators_hex()?;
    let vset_hash = validator_set_hash_hex(&allowed_signers_hex);
    let quorum_k = quorum_k_2of3(allowed_signers_hex.len());

    // Build swarm (req-res only)
    let local_keys = identity::Keypair::generate_ed25519();
    let rr_cfg = request_response::Config::default()
        .with_request_timeout(Duration::from_millis(cfg.rr_timeout_ms));
    let protocols = std::iter::once((RR_V3.to_string(), request_response::ProtocolSupport::Full));
    let reqres_v3 = request_response::Behaviour::with_codec(
        NewgenHeadersCodec {
            max_frame_bytes: cfg.rr_v3_max_frame_bytes,
        },
        protocols,
        rr_cfg,
    );

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_keys)
        .with_tokio()
        .with_tcp(
            TcpConfig::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("swarm builder (tcp/noise/yamux) failed: {e}"))?
        .with_behaviour(move |_| Ok(StateSyncBehaviour { reqres_v3 }))
        .map_err(|e| format!("swarm builder behaviour failed: {e}"))?
        .build();

    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .map_err(|e| format!("listen failed: {e}"))?;

    let peers = match connect_peers(&mut swarm, &seeds, cfg.connect_timeout_ms).await {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    let mut best: Option<CheckpointCert> = None;

    for peer in peers.iter().copied() {
        let resp = match rr_call(
            &mut swarm,
            peer,
            RrV3Msg::GetCheckpointCertLatest,
            cfg.rr_timeout_ms,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let cert = match resp {
            RrV3Msg::CheckpointCertLatest { cert: Some(c), .. } => c,
            _ => continue,
        };

        // Basic binding checks
        if cert.checkpoint.chain_id != cfg.chain_id {
            continue;
        }
        if !cfg.expected_genesis_hash.trim().is_empty()
            && cert.checkpoint.genesis_hash != cfg.expected_genesis_hash
        {
            continue;
        }
        if cert.checkpoint.validator_set_hash != vset_hash {
            continue;
        }

        if verify_checkpoint_cert(&cert, quorum_k, &allowed_signers_hex).is_err() {
            continue;
        }

        best = match best {
            None => Some(cert),
            Some(b) => {
                if anchor_store::is_better_checkpoint_cert(&cert, &b) {
                    Some(cert)
                } else {
                    Some(b)
                }
            }
        };
    }

    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{
        Council, GovernanceParams, GovernanceState, ValidatorEntry, ValidatorSet,
    };
    use crate::peer_reputation::{PeerReputationManager, ReputationConfig};
    use crate::snapshot::{SnapshotMeta, SnapshotStateCoverageMode};
    use crate::storage::{mirror_blockchain_to_storage, open_clean_test_dbstore};
    use crate::tests::test_process_lock;
    use ed25519_dalek::SigningKey;

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            let saved = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn sample_meta() -> SnapshotMeta {
        SnapshotMeta {
            version: 2,
            height: 42,
            base_height: 0,
            bytes_len: 1,
            chunk_size: 1,
            chunks: 1,
            chunk_hashes_hex: vec!["dd".repeat(32)],
            state_root: "11".repeat(32),
            checkpoint_block_hash: "22".repeat(32),
            genesis_hash: "33".repeat(32),
            created_at_ts: 0,
            window_from_height: 0,
            window_to_height: 42,
            include_state_nodes: true,
            reachable_state_nodes: true,
            state_coverage_mode: SnapshotStateCoverageMode::TipReachableOnly,
            historical_state_roots_queryable: false,
            validator_bootstrap_capable: false,
            snapshot_bootstrap_role: crate::snapshot::SnapshotBootstrapRole::ReadOnlyTipState,
            governance_snapshot_height: None,
            governance_snapshot_hash_hex: None,
            governance_snapshot_json: None,
            economy_snapshot_height: Some(42),
            economy_snapshot_hash_hex: Some("44".repeat(32)),
            finalized_height: None,
            finalized_hash: None,
            highest_qc_height: None,
            highest_qc_round: None,
            highest_qc_block_hash: None,
            finality_source: None,
            finality_binding_version: None,
            compute_order_state_store_hash_hex: None,
            compute_order_state_store_json: None,
            consensus_bootstrap_context: None,
            consensus_bootstrap_context_omission_reason: None,
        }
    }

    #[test]
    fn snapshot_bytes_len_verification_rejects_mismatch_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let chunks_dir = tmp.path().join("chunks");
        std::fs::create_dir_all(&chunks_dir).unwrap();
        std::fs::write(chunks_dir.join("000000.bin"), [1u8, 2u8]).unwrap();

        let mut meta = sample_meta();
        meta.chunks = 1;
        meta.bytes_len = 1;

        let err = verify_snapshot_chunk_bytes_len(&meta, &chunks_dir).unwrap_err();
        assert!(err.contains("snapshot bytes_len mismatch"));
        assert!(err.contains("action=fail_closed"));
    }

    #[test]
    fn snapshot_bytes_len_verification_rejects_missing_chunk_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let chunks_dir = tmp.path().join("chunks");
        std::fs::create_dir_all(&chunks_dir).unwrap();

        let mut meta = sample_meta();
        meta.chunks = 1;
        meta.bytes_len = 1;

        let err = verify_snapshot_chunk_bytes_len(&meta, &chunks_dir).unwrap_err();
        assert!(err.contains("snapshot bytes_len verification failed"));
        assert!(err.contains("missing chunk 0"));
    }

    fn validator_bootstrap_meta(mut meta: SnapshotMeta) -> SnapshotMeta {
        meta.window_to_height = meta.height;
        meta.economy_snapshot_height = Some(meta.height);
        let next_height = meta.height.saturating_add(1);
        let epoch_len = 10;
        let epoch = next_height / epoch_len;
        let epoch_start = epoch.saturating_mul(epoch_len);
        let epoch_end = epoch_start.saturating_add(epoch_len.saturating_sub(1));
        let ctx = crate::snapshot::SnapshotConsensusBootstrapContext::from_epoch_contexts(
            meta.height,
            meta.state_root.clone(),
            vec![crate::snapshot::SnapshotConsensusEpochBootstrapContext {
                epoch,
                coverage_start_height: epoch_start,
                coverage_end_height: epoch_end,
                pos_params: crate::staking::PosParamsV1 {
                    min_stake: 1,
                    unbonding_epochs: 1,
                    epoch_len,
                    committee_size: 1,
                },
                params_source: None,
                seed_source: None,
                committee_source: None,
                legacy_params_source_height: None,
                legacy_params_source_state_root: None,
                seed_epoch: epoch,
                seed_hex: "aa".repeat(32),
                committee: crate::snapshot::SnapshotConsensusCommitteeContext::V1 {
                    members_pk_hex: vec!["validator-a".to_string()],
                },
            }],
        );
        meta.consensus_bootstrap_context = Some(ctx);
        let finalized_height = meta.height.saturating_sub(1);
        meta.finalized_height = Some(finalized_height);
        meta.finalized_hash = Some("55".repeat(32));
        meta.highest_qc_height = Some(meta.height);
        meta.highest_qc_round = Some(1);
        meta.highest_qc_block_hash = Some(meta.checkpoint_block_hash.clone());
        meta.finality_source = Some("test_finality_meta".to_string());
        meta.finality_binding_version = Some(1);
        meta.validator_bootstrap_capable = true;
        meta.snapshot_bootstrap_role = crate::snapshot::SnapshotBootstrapRole::ValidatorBootstrap;
        meta
    }

    #[test]
    fn runtime_state_sync_rejects_non_validator_capable_snapshot_meta() {
        let meta = sample_meta();
        let err = snapshot_meta_usable_for_validator_bootstrap(&meta).unwrap_err();
        assert!(
            err.contains(
                "snapshot_not_validator_bootstrap_capable:missing_consensus_bootstrap_context"
            ),
            "err={err}"
        );
    }

    #[test]
    fn runtime_state_sync_accepts_validator_capable_snapshot_meta() {
        let meta = validator_bootstrap_meta(sample_meta());
        snapshot_meta_usable_for_validator_bootstrap(&meta)
            .expect("validator-capable snapshot meta must be accepted");
    }

    #[test]
    fn restart_catchup_rejects_non_progressive_snapshot_meta() {
        let meta = validator_bootstrap_meta(sample_meta());
        let cfg = StateSyncConfig {
            min_acceptable_snapshot_height: Some(meta.height.saturating_add(1)),
            reference_peer_height: Some(meta.height.saturating_add(8_000)),
            ..StateSyncConfig::default()
        };
        let err = snapshot_meta_satisfies_progress_gate(&meta, &cfg).unwrap_err();
        assert!(err.contains("snapshot_not_progressive"), "err={err}");
    }

    #[test]
    fn restart_catchup_rejects_stale_snapshot_meta_against_peer_height() {
        let meta = validator_bootstrap_meta(sample_meta());
        let cfg = StateSyncConfig {
            min_acceptable_snapshot_height: Some(meta.height),
            reference_peer_height: Some(meta.height.saturating_add(8_000)),
            max_snapshot_staleness_blocks: 1024,
            ..StateSyncConfig::default()
        };
        let err = snapshot_meta_satisfies_progress_gate(&meta, &cfg).unwrap_err();
        assert!(err.contains("snapshot_too_stale"), "err={err}");
    }

    #[test]
    fn restart_catchup_accepts_progressive_fresh_snapshot_meta() {
        let meta = validator_bootstrap_meta(sample_meta());
        let cfg = StateSyncConfig {
            min_acceptable_snapshot_height: Some(meta.height.saturating_sub(1)),
            reference_peer_height: Some(meta.height.saturating_add(16)),
            max_snapshot_staleness_blocks: 1024,
            ..StateSyncConfig::default()
        };
        snapshot_meta_satisfies_progress_gate(&meta, &cfg)
            .expect("progressive fresh snapshot meta must pass");
    }

    #[test]
    fn meta_key_prefers_explicit_sha_override() {
        let meta = sample_meta();
        let override_sha = "  explicit-sha  ".to_string();
        assert_eq!(meta_key(&meta, Some(&override_sha)), "explicit-sha");
    }

    #[test]
    fn meta_key_falls_back_to_canonical_hash_when_override_missing_or_blank() {
        let meta = sample_meta();
        let expected = sha256_hex(&serde_json::to_vec(&meta).unwrap());
        assert_eq!(meta_key(&meta, None), expected);
        assert_eq!(meta_key(&meta, Some(&"   ".to_string())), expected);
    }

    #[test]
    fn default_config_parses_env_and_clamps() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&[
            "NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH",
            "NEWGEN_TRUSTED_CHECKPOINT_HASH",
            "NEWGEN_ANCHOR_CACHE_PATH",
            "NEWGEN_AUTO_FETCH_ANCHOR",
            "NEWGEN_RR_V3_MAX_FRAME_BYTES",
            "NEWGEN_STATE_SYNC_TIMEOUT_MS",
            "NEWGEN_STATE_SYNC_CONNECT_TIMEOUT_MS",
            "NEWGEN_STATE_SYNC_BOOTSTRAP_READY_TIMEOUT_MS",
            "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_STALENESS_BLOCKS",
            "NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_ROUNDS",
            "NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_BACKOFF_MS",
            "NEWGEN_STATE_SYNC_CHUNK_RETRY_ROUNDS",
            "NEWGEN_STATE_SYNC_CHUNK_RETRY_BACKOFF_MS",
            "NEWGEN_STATE_SYNC_RESUME_PARTIAL",
            "NEWGEN_PUBLIC",
            "NEWGEN_PUBLIC_MODE",
            "NEWGEN_NETWORK_MODE",
        ]);

        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");
        std::env::set_var("NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH", "   ");
        std::env::set_var("NEWGEN_TRUSTED_CHECKPOINT_HASH", "   ");
        std::env::set_var("NEWGEN_ANCHOR_CACHE_PATH", "   ");
        std::env::set_var("NEWGEN_AUTO_FETCH_ANCHOR", "0");
        std::env::set_var("NEWGEN_RR_V3_MAX_FRAME_BYTES", "42");
        std::env::set_var("NEWGEN_STATE_SYNC_TIMEOUT_MS", "1");
        std::env::set_var("NEWGEN_STATE_SYNC_CONNECT_TIMEOUT_MS", "2");
        std::env::set_var("NEWGEN_STATE_SYNC_BOOTSTRAP_READY_TIMEOUT_MS", "5");
        std::env::set_var("NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_ROUNDS", "0");
        std::env::set_var("NEWGEN_STATE_SYNC_BOOTSTRAP_META_RETRY_BACKOFF_MS", "5");
        std::env::set_var("NEWGEN_STATE_SYNC_CHUNK_RETRY_ROUNDS", "0");
        std::env::set_var("NEWGEN_STATE_SYNC_CHUNK_RETRY_BACKOFF_MS", "3");
        std::env::set_var("NEWGEN_STATE_SYNC_RESUME_PARTIAL", "off");
        std::env::set_var("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_STALENESS_BLOCKS", "0");

        let cfg = StateSyncConfig::default();
        assert_eq!(cfg.chain_id, crate::chain_identity::chain_id());
        assert_eq!(cfg.trusted_checkpoint_cert_path, None);
        assert_eq!(cfg.trusted_checkpoint_hash, None);
        assert_eq!(cfg.anchor_cache_path, None);
        assert!(!cfg.auto_fetch_anchor);
        assert_eq!(cfg.rr_v3_max_frame_bytes, 1024 * 1024);
        assert_eq!(cfg.rr_timeout_ms, 300);
        assert_eq!(cfg.connect_timeout_ms, 300);
        assert_eq!(cfg.bootstrap_ready_timeout_ms, 1_000);
        assert_eq!(cfg.bootstrap_meta_retry_rounds, 1);
        assert_eq!(cfg.bootstrap_meta_retry_backoff_ms, 50);
        assert_eq!(cfg.chunk_retry_rounds, 1);
        assert_eq!(cfg.chunk_retry_backoff_ms, 10);
        assert_eq!(cfg.max_snapshot_staleness_blocks, 1);
        assert!(!cfg.resume_partial_download);
    }

    fn test_governance_with_validator(pubkey_hex: &str) -> GovernanceState {
        GovernanceState::new(
            Council {
                members: vec!["PROTO_MEMBER".to_string()],
                threshold: 1,
            },
            Council {
                members: vec!["ECON_MEMBER".to_string()],
                threshold: 1,
            },
            Council {
                members: vec!["EMERGENCY_MEMBER".to_string()],
                threshold: 1,
            },
            GovernanceParams {
                min_timelock_blocks: 1,
                max_proposal_lifetime_blocks: 100_000,
                max_emergency_duration_blocks: 10,
                wallet_reputation_promotion_quorum: 2,
                e2_worker_admission_activation_height: 0,
                validator_compute_transition_min_active_validators: 2,
                validator_compute_transition_min_finality_quorum: 2,
                validator_compute_transition_validator_quality_floor: 600,
                validator_compute_transition_exit_cooldown_blocks: 10,
                validator_compute_transition_max_finality_lag_blocks: 2,
                validator_compute_transition_max_recent_missed_slots: 3,
                ft_activation_height: u64::MAX,
                ft_max_tokens_per_owner: 0,
                ft_create_cooldown_blocks: 0,
                ft_create_fee_native: 0,
                nft_activation_height: u64::MAX,
                nft_max_collections_per_owner: 0,
                nft_create_cooldown_blocks: 0,
                nft_create_fee_native: 0,
                nft_enabled: false,
                nft_public_create_enabled: false,
                nft_public_mint_enabled: false,
                nft_public_transfer_enabled: false,
                nft_public_approval_enabled: false,
                nft_public_burn_enabled: false,
                nft_public_revoke_enabled: false,
                nft_public_metadata_update_enabled: false,
                nft_public_freeze_enabled: false,
                nft_public_policy_update_enabled: false,
                nft_public_issuer_update_enabled: false,
                nft_public_pause_enabled: false,
                nft_metadata_hash_required: true,
                nft_max_memo_bytes: crate::nft::NFTV1_MEMO_MAX_BYTES as u32,
                nft_max_uri_bytes: crate::nft::NFTV1_URI_MAX_BYTES as u32,
                nft_max_name_bytes: crate::nft::NFTV1_NAME_MAX_BYTES as u32,
                nft_max_symbol_bytes: crate::nft::NFTV1_SYMBOL_MAX_BYTES as u32,
                nft_max_tokens_per_collection: 0,
                nft_max_tokens_per_owner: 0,
                nft_mint_fee_native: 0,
                nft_transfer_fee_native: 0,
                nft_approval_fee_native: 0,
                nft_burn_fee_native: 0,
                nft_revoke_fee_native: 0,
                nft_metadata_update_fee_native: 0,
                nft_freeze_fee_native: 0,
                nft_policy_update_fee_native: 0,
                nft_issuer_update_fee_native: 0,
                nft_pause_fee_native: 0,
            },
            ValidatorSet {
                entries: vec![ValidatorEntry {
                    pub_key: pubkey_hex.to_string(),
                    alias: Some("LocalValidator".to_string()),
                    weight: 1,
                }],
                version: 1,
            },
        )
    }

    #[test]
    fn apply_imported_snapshot_preserves_local_miner_authorization_context() {
        let seed = [0xA1u8; 32];
        let miner_sk_b64 = STANDARD.encode(seed);
        let miner_pub_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());

        let mut original = Blockchain::new();
        original.governance = Some(test_governance_with_validator(&miner_pub_hex));
        original.governance_bootstrap = original.governance.clone();
        original.set_miner_sk_b64(miner_sk_b64.clone());
        let rep_cfg = ReputationConfig {
            local_source_node_id: Some("TEST_D".to_string()),
            persist_path: tempfile::tempdir()
                .unwrap()
                .path()
                .join("rep.json")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        };
        let rep = Arc::new(Mutex::new(PeerReputationManager::new(rep_cfg)));
        original.reputation = Some(rep.clone());
        assert!(original.refresh_local_miner_authorization().unwrap());
        {
            let mut guard = rep.lock().unwrap_or_else(|e| e.into_inner());
            guard.set_local_source_attester_identity(Some(miner_pub_hex.clone()), Some(seed));
        }

        let storage = Arc::new(open_clean_test_dbstore("state_sync_preserve_auth").unwrap());
        mirror_blockchain_to_storage(storage.as_ref(), &original).unwrap();

        let chain = Arc::new(Mutex::new(original));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let security_policy = Arc::new(SecurityPolicy::default());

        apply_imported_snapshot_to_live_runtime(storage, &chain, &mempool, &security_policy)
            .unwrap();

        let guard = chain.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.policy.miner_sk_b64, miner_sk_b64);
        assert!(guard.is_authorized_miner);
        assert_eq!(
            guard
                .local_consensus_runtime_view_for_next_block()
                .validator_pubkey,
            Some(miner_pub_hex)
        );
        assert!(guard.reputation.is_some());
    }

    #[test]
    fn apply_imported_snapshot_does_not_grant_local_miner_authorization_when_absent() {
        let mut original = Blockchain::new();
        original.governance = Some(test_governance_with_validator(
            "74c2d9e9984be2214c6cb12c79b50052b72b11e9050a9154403312eb314f43b8",
        ));
        original.governance_bootstrap = original.governance.clone();
        let rep_cfg = ReputationConfig {
            local_source_node_id: Some("TEST_D".to_string()),
            persist_path: tempfile::tempdir()
                .unwrap()
                .path()
                .join("rep.json")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        };
        let rep = Arc::new(Mutex::new(PeerReputationManager::new(rep_cfg)));
        original.reputation = Some(rep);
        original.is_authorized_miner = false;

        let storage = Arc::new(open_clean_test_dbstore("state_sync_preserve_unauth").unwrap());
        mirror_blockchain_to_storage(storage.as_ref(), &original).unwrap();

        let chain = Arc::new(Mutex::new(original));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let security_policy = Arc::new(SecurityPolicy::default());

        apply_imported_snapshot_to_live_runtime(storage, &chain, &mempool, &security_policy)
            .unwrap();

        let guard = chain.lock().unwrap_or_else(|e| e.into_inner());
        assert!(guard.policy.miner_sk_b64.is_empty());
        assert!(!guard.is_authorized_miner);
        assert!(guard.reputation.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_snapshot_chunk_headers_response_marks_peer_failure_and_falls_back() {
        use std::collections::VecDeque;
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let peers = vec![p1, p2];
        let scripted: Arc<Mutex<HashMap<PeerId, VecDeque<Result<Vec<u8>, String>>>>> = Arc::new(Mutex::new(HashMap::from([
            (p1, VecDeque::from([Err("runtime snapshot chunk response kind mismatch expected=SnapshotV2Chunk received=Headers".to_string())])),
            (p2, VecDeque::from([Ok(vec![1u8, 2u8, 3u8])])),
        ])));
        let mut peer_failures = HashMap::new();
        let result = fetch_runtime_snapshot_chunk_with_peer_fallback(
            &peers,
            0,
            2,
            36,
            &mut peer_failures,
            8,
            10,
            |peer| {
                let scripted = scripted.clone();
                std::future::ready({
                    let mut guard = scripted.lock().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get_mut(&peer)
                        .and_then(|q| q.pop_front())
                        .unwrap_or_else(|| Err("no scripted response".to_string()))
                })
            },
            |_peer, _bytes| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(result.0, p2);
        assert_eq!(peer_failures.get(&p1).copied(), Some(3));
        assert_eq!(peer_failures.get(&p2).copied(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_snapshot_chunk_error_response_retries_next_peer() {
        use std::collections::VecDeque;
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let peers = vec![p1, p2];
        let scripted: Arc<Mutex<HashMap<PeerId, VecDeque<Result<Vec<u8>, String>>>>> = Arc::new(Mutex::new(HashMap::from([
            (p1, VecDeque::from([Err("runtime snapshot chunk peer error peer=p1 request_id=OutboundRequestId(1) height=42 chunk_index=7 code=409 msg=wrong_kind".to_string())])),
            (p2, VecDeque::from([Ok(vec![9u8, 9u8])])),
        ])));
        let mut peer_failures = HashMap::new();
        let result = fetch_runtime_snapshot_chunk_with_peer_fallback(
            &peers,
            0,
            2,
            7,
            &mut peer_failures,
            8,
            10,
            |peer| {
                let scripted = scripted.clone();
                std::future::ready({
                    let mut guard = scripted.lock().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get_mut(&peer)
                        .and_then(|q| q.pop_front())
                        .unwrap_or_else(|| Err("no scripted response".to_string()))
                })
            },
            |_peer, _bytes| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(result.0, p2);
        assert_eq!(peer_failures.get(&p1).copied(), Some(3));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_snapshot_chunk_state_sync_continues_when_one_peer_is_correct() {
        use std::collections::VecDeque;
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        let peers = vec![p1, p2, p3];
        let expected = vec![4u8, 5u8, 6u8];
        let scripted: Arc<Mutex<HashMap<PeerId, VecDeque<Result<Vec<u8>, String>>>>> = Arc::new(Mutex::new(HashMap::from([
            (p1, VecDeque::from([Err("runtime snapshot chunk response kind mismatch expected=SnapshotV2Chunk received=Headers".to_string())])),
            (p2, VecDeque::from([Err("runtime snapshot chunk peer error peer=p2 request_id=OutboundRequestId(2) height=42 chunk_index=9 code=500 msg=temporary".to_string())])),
            (p3, VecDeque::from([Ok(expected.clone())])),
        ])));
        let mut peer_failures = HashMap::new();
        let result = fetch_runtime_snapshot_chunk_with_peer_fallback(
            &peers,
            0,
            3,
            9,
            &mut peer_failures,
            8,
            10,
            |peer| {
                let scripted = scripted.clone();
                std::future::ready({
                    let mut guard = scripted.lock().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get_mut(&peer)
                        .and_then(|q| q.pop_front())
                        .unwrap_or_else(|| Err("no scripted response".to_string()))
                })
            },
            |_peer, bytes| {
                if bytes == expected.as_slice() {
                    Ok(())
                } else {
                    Err("unexpected chunk bytes".to_string())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, p3);
        assert_eq!(result.1, expected);
        assert_eq!(peer_failures.get(&p1).copied(), Some(3));
        assert_eq!(peer_failures.get(&p2).copied(), Some(1));
    }
    #[test]
    fn runtime_snapshot_chunk_refetch_meta_marker_v223_is_detected() {
        assert!(runtime_snapshot_chunk_error_requires_meta_refetch_v223(
            "runtime snapshot chunk peer error code=409 msg=snapshot_session_expired_refetch_meta"
        ));
        assert!(runtime_snapshot_chunk_error_requires_meta_refetch_v223(
            "snapshot_chunk_transport_retry_exhausted_refetch_meta peer=abc height=10 chunk_index=0 err=ConnectionClosed"
        ));
        assert!(runtime_snapshot_chunk_error_requires_meta_refetch_v223(
            "snapshot_session_stalled_refetch_meta_v250"
        ));
        assert!(!runtime_snapshot_chunk_error_requires_meta_refetch_v223(
            "runtime snapshot chunk peer error code=500 msg=temporary"
        ));
    }

    #[test]
    fn runtime_snapshot_chunk_failure_class_v251_distinguishes_transport_protocol_and_data() {
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251("ConnectionClosed while waiting for chunk"),
            RuntimeSnapshotChunkFailureClassV251::Transport
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251(
                "snapshot_chunk_session_refetched_rotate_peer_v251 peer=p1 height=42 chunk_index=0 err=ConnectionClosed"
            ),
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251(
                "ConnectionClosed during snapshot session_turn changed before chunk response"
            ),
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251("runtime snapshot chunk response kind mismatch expected=SnapshotV2Chunk received=Headers"),
            RuntimeSnapshotChunkFailureClassV251::Protocol
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251("chunk 0 sha mismatch from peer"),
            RuntimeSnapshotChunkFailureClassV251::SnapshotData
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251("snapshot_session_stalled_refetch_meta_v250"),
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251(
                "runtime snapshot chunk peer error code=500 msg=temporary"
            ),
            RuntimeSnapshotChunkFailureClassV251::PeerBusy
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_snapshot_chunk_refetch_meta_rotates_peer_before_retrying_same_session_v251() {
        use std::collections::VecDeque;
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let peers = vec![p1, p2];
        let scripted: Arc<Mutex<HashMap<PeerId, VecDeque<Result<Vec<u8>, String>>>>> = Arc::new(Mutex::new(HashMap::from([
            (p1, VecDeque::from([Err("snapshot_chunk_session_refetched_rotate_peer_v251 peer=p1 height=42 chunk_index=0 err=snapshot_session_stalled_refetch_meta_v250".to_string())])),
            (p2, VecDeque::from([Ok(vec![7u8, 7u8])])),
        ])));
        let mut peer_failures = HashMap::new();
        let result = fetch_runtime_snapshot_chunk_with_peer_fallback(
            &peers,
            0,
            2,
            0,
            &mut peer_failures,
            8,
            10,
            |peer| {
                let scripted = scripted.clone();
                std::future::ready({
                    let mut guard = scripted.lock().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get_mut(&peer)
                        .and_then(|q| q.pop_front())
                        .unwrap_or_else(|| Err("no scripted response".to_string()))
                })
            },
            |_peer, _bytes| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(result.0, p2);
        // V275: MetaRefetchRequired is still not a global reputation fault,
        // but it does create a local transfer cooldown so the next chunk does
        // not waste the first attempt on the same stale/session-turn peer.
        assert_eq!(peer_failures.get(&p1).copied(), Some(1));
        assert_eq!(peer_failures.get(&p2).copied(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_snapshot_chunk_window_reset_v253_retries_after_all_peers_suppressed() {
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let peers = vec![p1, p2];
        let expected = vec![8u8, 8u8];
        let scripted: Arc<Mutex<HashMap<PeerId, Vec<Result<Vec<u8>, String>>>>> =
            Arc::new(Mutex::new(HashMap::from([
                (p1, vec![Ok(expected.clone())]),
                (
                    p2,
                    vec![Err("should not be required after reset".to_string())],
                ),
            ])));
        let mut peer_failures = HashMap::from([(p1, 8_u32), (p2, 8_u32)]);

        let result = fetch_runtime_snapshot_chunk_with_peer_fallback(
            &peers,
            0,
            1,
            0,
            &mut peer_failures,
            8,
            1,
            |peer| {
                let scripted = scripted.clone();
                std::future::ready({
                    let mut guard = scripted.lock().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get_mut(&peer)
                        .and_then(|q| {
                            if q.is_empty() {
                                None
                            } else {
                                Some(q.remove(0))
                            }
                        })
                        .unwrap_or_else(|| Err("no scripted response after reset".to_string()))
                })
            },
            |_peer, bytes| {
                if bytes == expected.as_slice() {
                    Ok(())
                } else {
                    Err("unexpected chunk bytes after reset".to_string())
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result.0, p1);
        assert_eq!(result.1, expected);
        assert_eq!(peer_failures.get(&p1).copied(), None);
    }

    #[test]
    fn runtime_snapshot_primary_chunk_start_offset_v274_uses_sticky_success_peer() {
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let peers = vec![a, b, c];
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&peers, None),
            0
        );
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&peers, Some(a)),
            0
        );
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&peers, Some(b)),
            1
        );
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&peers, Some(c)),
            2
        );
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&peers, Some(PeerId::random())),
            0
        );
        assert_eq!(
            runtime_snapshot_primary_chunk_start_offset_v274(&[], Some(a)),
            0
        );
    }

    #[test]
    fn runtime_snapshot_dedup_peers_preserve_order_v274_keeps_ranked_primary_first() {
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let mut peers = vec![b, a, b, c, a];
        runtime_snapshot_dedup_peers_preserve_order_v274(&mut peers);
        assert_eq!(peers, vec![b, a, c]);
    }

    #[test]
    fn runtime_snapshot_promote_preferred_peer_v274_switches_after_valid_chunk() {
        let a = PeerId::random();
        let b = PeerId::random();
        let mut preferred = Some(a);
        assert!(runtime_snapshot_promote_preferred_peer_v274(
            &mut preferred,
            b
        ));
        assert_eq!(preferred, Some(b));
        assert!(!runtime_snapshot_promote_preferred_peer_v274(
            &mut preferred,
            b
        ));
        assert_eq!(preferred, Some(b));
    }

    #[test]
    fn runtime_snapshot_chunk_download_order_v275_prefetches_edges_then_linear() {
        assert_eq!(
            runtime_snapshot_chunk_download_order_v275(0),
            Vec::<u32>::new()
        );
        assert_eq!(runtime_snapshot_chunk_download_order_v275(1), vec![0]);
        assert_eq!(runtime_snapshot_chunk_download_order_v275(2), vec![0, 1]);
        assert_eq!(
            runtime_snapshot_chunk_download_order_v275(5),
            vec![0, 4, 1, 2, 3]
        );
        assert_eq!(runtime_snapshot_preflight_chunk_indices_v275(5), vec![0, 4]);
    }

    #[test]
    fn runtime_snapshot_transfer_mode_v276_is_explicitly_sequential() {
        assert_eq!(
            runtime_snapshot_transfer_mode_v276(),
            "single_primary_sequential_identical_manifest_key_snapshot_simple_recovery_v286"
        );
    }

    #[test]
    fn runtime_snapshot_effective_chunk_timeout_v277_has_stable_floor() {
        let mut cfg = StateSyncConfig::default();
        cfg.rr_timeout_ms = 15_000;
        assert_eq!(
            runtime_snapshot_effective_chunk_timeout_ms_v277(&cfg),
            30_000
        );
        cfg.rr_timeout_ms = 45_000;
        assert_eq!(
            runtime_snapshot_effective_chunk_timeout_ms_v277(&cfg),
            45_000
        );
    }

    #[test]
    fn runtime_snapshot_transfer_cooldown_v275_does_not_change_reputation_penalty() {
        assert_eq!(
            runtime_snapshot_chunk_failure_penalty_v251(
                RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
            ),
            0
        );
        assert_eq!(
            runtime_snapshot_transfer_local_cooldown_penalty_v275(
                RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
            ),
            1
        );
        assert_eq!(
            runtime_snapshot_transfer_local_cooldown_penalty_v275(
                RuntimeSnapshotChunkFailureClassV251::SnapshotData
            ),
            8
        );
    }

    #[test]
    fn runtime_snapshot_verified_existing_chunk_v276_reuses_matching_chunk_without_resume_flag() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "newgen_state_sync_v276_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fpath = dir.join("000000.bin");
        let bytes = b"verified-preflight-chunk";
        std::fs::write(&fpath, bytes).unwrap();
        let expected = sha256_hex(bytes);
        assert!(runtime_snapshot_verified_existing_chunk_v276(
            &fpath,
            &expected,
            42,
            0,
            2,
            "test_v276",
        )
        .unwrap());
        assert!(fpath.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn runtime_snapshot_verified_existing_chunk_v276_removes_stale_chunk() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "newgen_state_sync_v276_stale_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fpath = dir.join("000001.bin");
        std::fs::write(&fpath, b"old-stale-chunk").unwrap();
        let expected = sha256_hex(b"new-active-manifest-chunk");
        assert!(!runtime_snapshot_verified_existing_chunk_v276(
            &fpath,
            &expected,
            42,
            1,
            2,
            "test_v276",
        )
        .unwrap());
        assert!(!fpath.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn runtime_snapshot_record_chunk_peer_failure_v276_applies_local_cooldown_for_meta_refetch() {
        let peer = PeerId::random();
        let mut peer_failures = HashMap::new();
        let class = runtime_snapshot_record_chunk_peer_failure_v276(
            &mut peer_failures,
            peer,
            0,
            "snapshot_chunk_session_refetched_rotate_peer_v251 peer=p1 height=42 chunk_index=0 err=snapshot_session_stalled_refetch_meta_v250",
            "direct_seed_refetch_meta_v276_test",
        );
        assert_eq!(
            class,
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(peer_failures.get(&peer).copied(), Some(1));
        assert_eq!(
            runtime_snapshot_chunk_failure_penalty_v251(class),
            0,
            "global reputation penalty must remain unchanged for session-turn/meta-refetch"
        );
    }

    #[test]
    fn snapshot_meta_response_error_reason_classifies_transport_failures_v184() {
        assert_eq!(
            snapshot_meta_response_error_reason(413, "rr_v3_resp_too_large"),
            "snapshot_meta_oversize"
        );
        assert_eq!(
            snapshot_meta_response_error_reason(413, "encoded frame too large for max_frame"),
            "snapshot_meta_oversize"
        );
        assert_eq!(
            snapshot_meta_response_error_reason(404, "snapshot_not_found"),
            "snapshot_meta_missing"
        );
        assert_eq!(
            snapshot_meta_response_error_reason(429, "rrv3_busy"),
            "snapshot_peer_busy"
        );
        assert_eq!(
            snapshot_meta_response_error_reason(500, "internal"),
            "snapshot_peer_internal_error"
        );
    }

    #[test]
    fn snapshot_meta_error_height_parser_detects_large_gap_v184() {
        let msg = "rr_v3_resp_too_large local_height=48 peer_height=39435 height=39435";
        let (local, peer) = infer_snapshot_error_heights(msg);
        assert_eq!(local, Some(48));
        assert_eq!(peer, Some(39435));
        assert_eq!(
            large_gap_without_snapshot_bootstrap_gap(local, peer),
            Some(39387)
        );
        assert_eq!(
            large_gap_without_snapshot_bootstrap_gap(Some(39400), Some(39435)),
            None
        );
    }

    #[test]
    fn runtime_snapshot_meta_error_parser_preserves_code_and_message_v184() {
        let err = "runtime snapshot meta error code=413 msg=rr_v3_resp_too_large local_height=48 peer_height=39435";
        let (code, message) = parse_runtime_snapshot_meta_error(err).unwrap();
        assert_eq!(code, 413);
        assert!(message.contains("rr_v3_resp_too_large"));
        assert!(message.contains("peer_height=39435"));
        assert_eq!(
            snapshot_meta_response_error_reason(code, &message),
            "snapshot_meta_oversize"
        );
    }

    #[test]
    fn snapshot_chunk_meta_none_after_refetch_is_zero_penalty_v268() {
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251(
                "runtime snapshot meta response was None from 12D3KooWexample",
            ),
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_penalty_v251(
                RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired,
            ),
            0
        );
    }

    #[test]
    fn snapshot_connection_closed_during_session_turn_is_zero_penalty_v268() {
        let err = "snapshot_chunk_session_refetched_rotate_peer_v251 peer=p1 height=42 chunk_index=7 err=ConnectionClosed";
        assert_eq!(
            runtime_snapshot_chunk_failure_class_v251(err),
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(
            runtime_snapshot_chunk_failure_penalty_v251(
                RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired,
            ),
            0
        );

        let p = PeerId::random();
        let mut peer_failures = HashMap::new();
        let class = runtime_snapshot_record_chunk_peer_failure_v251(
            &mut peer_failures,
            p,
            7,
            err,
            "v268_session_turn",
        );
        assert_eq!(
            class,
            RuntimeSnapshotChunkFailureClassV251::MetaRefetchRequired
        );
        assert_eq!(peer_failures.get(&p).copied(), None);
    }

    #[test]
    fn snapshot_chunk_retry_rounds_v264_have_safe_floor_for_large_snapshot() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&["NEWGEN_RUNTIME_SNAPSHOT_CHUNK_RETRY_FLOOR"]);
        std::env::remove_var("NEWGEN_RUNTIME_SNAPSHOT_CHUNK_RETRY_FLOOR");

        assert_eq!(runtime_snapshot_retry_floor_v277(), 3);
        assert_eq!(
            runtime_snapshot_effective_chunk_retry_rounds_v264(1).unwrap(),
            3
        );
        assert_eq!(
            runtime_snapshot_effective_chunk_retry_rounds_v264(3).unwrap(),
            3
        );
        assert_eq!(
            runtime_snapshot_effective_chunk_retry_rounds_v264(16).unwrap(),
            16
        );
        assert_eq!(
            runtime_snapshot_effective_direct_chunk_retry_rounds_v264(3),
            3
        );

        std::env::set_var("NEWGEN_RUNTIME_SNAPSHOT_CHUNK_RETRY_FLOOR", "4");
        assert_eq!(runtime_snapshot_retry_floor_v277(), 4);
        assert_eq!(
            runtime_snapshot_effective_chunk_retry_rounds_v264(1).unwrap(),
            4
        );
    }

    #[test]
    fn runtime_snapshot_bundle_sort_prefers_larger_chunk_size_v278() {
        assert_eq!(
            runtime_snapshot_prefer_larger_chunk_size_order_v278(2 * 1024 * 1024, 1024 * 1024),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            runtime_snapshot_prefer_larger_chunk_size_order_v278(1024 * 1024, 2 * 1024 * 1024),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            runtime_snapshot_prefer_larger_chunk_size_order_v278(2 * 1024 * 1024, 2 * 1024 * 1024),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn runtime_snapshot_candidates_same_height_prefers_larger_chunk_before_primary_selection_v279()
    {
        #[derive(Clone)]
        struct CandidateForSort {
            meta: SnapshotMeta,
            key: String,
            rank_index: usize,
        }

        let mut small = validator_bootstrap_meta(sample_meta());
        small.height = 52_000;
        small.window_to_height = 52_000;
        small.finalized_height = Some(52_000);
        small.chunk_size = 1024 * 1024;
        small.chunks = 100;
        small.chunk_hashes_hex = vec!["aa".repeat(32); small.chunks as usize];
        small.bytes_len = small.chunk_size as u64 * small.chunks as u64;

        let mut large = small.clone();
        large.chunk_size = 2 * 1024 * 1024;
        large.chunks = 50;
        large.chunk_hashes_hex = vec!["bb".repeat(32); large.chunks as usize];
        large.bytes_len = large.chunk_size as u64 * large.chunks as u64;

        let mut candidates = vec![
            CandidateForSort {
                meta: small.clone(),
                key: "000-small-would-have-won-before-v279".to_string(),
                rank_index: 0,
            },
            CandidateForSort {
                meta: large.clone(),
                key: "999-large".to_string(),
                rank_index: 1,
            },
        ];

        candidates.sort_by(|a, b| {
            runtime_snapshot_candidate_selection_order_v279(
                &a.meta,
                &a.key,
                Some(a.rank_index),
                &b.meta,
                &b.key,
                Some(b.rank_index),
            )
        });

        assert_eq!(candidates[0].meta.chunk_size, 2 * 1024 * 1024);
        assert_eq!(candidates[0].key, "999-large");
        assert!(snapshot_meta_same_trust_family_v251(
            &candidates[0].meta,
            &small
        ));
        assert!(snapshot_meta_same_trust_family_v251(
            &candidates[0].meta,
            &large
        ));
        assert!(snapshot_meta_same_download_manifest_v251(
            &candidates[0].meta,
            &large
        ));
        assert!(!snapshot_meta_same_download_manifest_v251(
            &candidates[0].meta,
            &small
        ));
    }

    #[test]
    fn runtime_snapshot_v285_rejects_non_identical_manifest_for_peer_failover() {
        let mut a = validator_bootstrap_meta(sample_meta());
        a.height = 51712;
        a.window_to_height = 51712;
        a.bytes_len = 106_000_000;
        a.chunk_size = 2 * 1024 * 1024;
        a.chunks = 51;
        a.chunk_hashes_hex = (0..51).map(|i| format!("{:064x}", i + 1)).collect();
        a.checkpoint_block_hash = "aa".repeat(32);
        a.state_root = "bb".repeat(32);

        let mut b = a.clone();
        // Same canonical state/height but different byte/chunk manifest. V285
        // must not use this peer as fallback for the same transfer plan because
        // GetSnapshotV2Chunk carries only (height, index), not a manifest id.
        b.chunk_hashes_hex = (0..51).map(|i| format!("{:064x}", i + 10_000)).collect();
        assert!(snapshot_meta_same_transfer_bundle_v281_historical_test_only(&a, &b));
        assert!(!snapshot_meta_same_download_manifest_v251(&a, &b));

        let mut peers = vec![a.clone()];
        if peers
            .iter()
            .any(|m| snapshot_meta_same_download_manifest_v251(m, &b))
        {
            peers.push(b.clone());
        }
        assert_eq!(
            peers.len(),
            1,
            "non-identical manifests must not be grouped for chunk failover"
        );
    }

    #[test]
    fn runtime_snapshot_v286_requires_same_meta_key_for_peer_failover() {
        let mut a = validator_bootstrap_meta(sample_meta());
        a.height = 51712;
        a.window_to_height = 51712;
        a.bytes_len = 106_000_000;
        a.chunk_size = 2 * 1024 * 1024;
        a.chunks = 51;
        a.chunk_hashes_hex = (0..51).map(|i| format!("{:064x}", i + 1)).collect();
        a.checkpoint_block_hash = "aa".repeat(32);
        a.state_root = "bb".repeat(32);
        a.finalized_height = Some(51710);
        a.finalized_hash = Some("cc".repeat(32));

        let mut b = a.clone();
        // Same byte/chunk download layout, but a different canonical meta field.
        // V286 must not group it unless the key/meta_sha matches too.
        b.finalized_height = Some(51711);
        b.finalized_hash = Some("dd".repeat(32));

        assert!(snapshot_meta_same_download_manifest_v251(&a, &b));
        assert!(!snapshot_meta_same_download_manifest_key_v286(
            "meta-a", &a, "meta-b", &b
        ));
        assert!(snapshot_meta_same_download_manifest_key_v286(
            "meta-a", &a, "meta-a", &a
        ));
    }

    #[test]
    fn runtime_snapshot_cross_family_fallback_v280_allows_lower_progressive_family_when_unpinned() {
        let mut latest = validator_bootstrap_meta(sample_meta());
        latest.height = 52_000;
        latest.window_to_height = 52_000;
        latest.finalized_height = Some(52_000);
        latest.chunk_size = 2 * 1024 * 1024;
        latest.chunks = 50;
        latest.chunk_hashes_hex = vec!["aa".repeat(32); latest.chunks as usize];
        latest.bytes_len = latest.chunk_size as u64 * latest.chunks as u64;

        let mut older = latest.clone();
        older.height = 51_900;
        older.window_to_height = 51_900;
        older.finalized_height = Some(51_900);
        older.state_root = "66".repeat(32);
        older.checkpoint_block_hash = "77".repeat(32);
        older.highest_qc_height = Some(51_900);
        older.highest_qc_block_hash = Some(older.checkpoint_block_hash.clone());

        assert!(!snapshot_meta_same_trust_family_v251(&older, &latest));
        assert!(runtime_snapshot_allow_cross_family_fallback_v280(
            None, false, None
        ));
        assert!(runtime_snapshot_candidate_allowed_for_plan_v280(
            &older, &latest, true,
        ));
        assert!(!runtime_snapshot_candidate_allowed_for_plan_v280(
            &older, &latest, false,
        ));
        assert!(!runtime_snapshot_allow_cross_family_fallback_v280(
            Some(latest.height),
            false,
            None,
        ));
        assert!(!runtime_snapshot_allow_cross_family_fallback_v280(
            None, true, None
        ));
        assert!(!runtime_snapshot_allow_cross_family_fallback_v280(
            None,
            false,
            Some("22"),
        ));
    }

    #[test]
    fn runtime_snapshot_transport_safe_meta_v280_rejects_oversized_chunk_size() {
        let cfg = StateSyncConfig {
            rr_v3_max_frame_bytes: 16 * 1024 * 1024,
            ..StateSyncConfig::default()
        };
        let safe = rrv3_safe_snapshot_chunk_bytes(cfg.rr_v3_max_frame_bytes);

        let mut ok = validator_bootstrap_meta(sample_meta());
        ok.chunk_size = safe as u32;
        ok.chunks = 1;
        ok.chunk_hashes_hex = vec!["aa".repeat(32)];
        ok.bytes_len = ok.chunk_size as u64;
        runtime_snapshot_meta_transport_safe_v280(&ok, &cfg)
            .expect("transport-safe chunk size should pass");

        let mut too_large = ok.clone();
        too_large.chunk_size = safe.saturating_add(1) as u32;
        let err = runtime_snapshot_meta_transport_safe_v280(&too_large, &cfg).unwrap_err();
        assert!(
            err.contains("snapshot_chunk_size_exceeds_rrv3_transport_budget"),
            "err={err}"
        );
    }
}
