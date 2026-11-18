use crate::rr_v3_msg::{encode_v3 as encode_rr_v3, RrV3Msg};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

pub const SNAPSHOT_V2_CHUNK_MIN_BYTES: usize = 16 * 1024;
pub const SNAPSHOT_V2_CHUNK_MAX_BYTES: usize = 16 * 1024 * 1024;

// V277: keep each RRv3 snapshot chunk response comfortably below the
// transport timeout/connection stability envelope used during external
// Windows -> server cold-start bootstrap, while reducing the number of
// per-chunk RRv3 round trips. A 4MiB raw chunk becomes ~5.6MiB after base64
// plus JSON/envelope and was observed to close the stream on chunk 0. A 2MiB
// raw cap keeps the encoded response small enough for the default 16MiB frame
// budget but roughly halves request count versus the earlier 1MiB cap.
// Until snapshot chunks are moved to a true streaming/subchunked protocol,
// do not raise this cap aggressively.
pub const SNAPSHOT_V2_RRV3_SINGLE_RESPONSE_RAW_CAP_BYTES: usize = 2 * 1024 * 1024;
const SNAPSHOT_V2_RRV3_B64_RESERVE_BYTES: usize = 2048;

/// Conservative RRv3-safe payload budget for snapshot chunk *raw bytes*.
///
/// RRv3 snapshot chunks are encoded as JSON plus base64. This helper computes
/// a transport-safe upper bound for the raw chunk bytes so that the final
/// RRv3 response remains under `max_frame_bytes` with margin.
pub fn rrv3_safe_snapshot_chunk_bytes(max_frame_bytes: usize) -> usize {
    let reserved = SNAPSHOT_V2_RRV3_B64_RESERVE_BYTES.min(max_frame_bytes.saturating_sub(1));
    let usable = max_frame_bytes.saturating_sub(reserved);
    let raw_payload = usable.saturating_mul(3) / 4;
    raw_payload
        .min(SNAPSHOT_V2_RRV3_SINGLE_RESPONSE_RAW_CAP_BYTES)
        .clamp(SNAPSHOT_V2_CHUNK_MIN_BYTES, SNAPSHOT_V2_CHUNK_MAX_BYTES)
}

/// Clamp a requested snapshot chunk size to both the local storage policy and
/// the RRv3 transport budget.
pub fn clamp_snapshot_chunk_bytes_for_rrv3(
    requested_chunk_bytes: usize,
    max_frame_bytes: usize,
) -> usize {
    requested_chunk_bytes
        .clamp(SNAPSHOT_V2_CHUNK_MIN_BYTES, SNAPSHOT_V2_CHUNK_MAX_BYTES)
        .min(rrv3_safe_snapshot_chunk_bytes(max_frame_bytes))
}

/// Build the small metadata view advertised over RRv3.
///
/// `meta.json` on disk can legitimately carry private/testnet sidecars for
/// offline import and diagnostics. Those sidecars must not be part of RRv3
/// discovery because the frame budget is intentionally small. The full compute
/// order and governance payloads are already carried inside the hashed snapshot
/// payload header; the transport manifest therefore advertises only their
/// hashes. This keeps both full-history and pruned snapshot discovery bounded
/// and RRv3-frame-safe.
pub fn snapshot_meta_for_rrv3_transport(meta: &SnapshotMeta) -> SnapshotMeta {
    let mut transport = meta.clone();

    // Backward compatibility hardening: legacy/testnet pruned bundles may carry
    // the sidecar JSON in meta.json but not yet carry the corresponding hash
    // field. RRv3 transport must strip the JSON, so derive the hash first;
    // otherwise a valid legacy bundle would become invalid only because it was
    // advertised over the slim transport manifest.
    if transport.compute_order_state_store_hash_hex.is_none() {
        if let Some(js) = transport.compute_order_state_store_json.as_ref() {
            transport.compute_order_state_store_hash_hex =
                Some(format!("{:x}", Sha256::digest(js.as_bytes())));
        }
    }
    if transport.governance_snapshot_hash_hex.is_none() {
        if let Some(js) = transport.governance_snapshot_json.as_ref() {
            transport.governance_snapshot_hash_hex =
                Some(format!("{:x}", Sha256::digest(js.as_bytes())));
        }
    }

    transport.compute_order_state_store_json = None;
    transport.governance_snapshot_json = None;

    transport
}

/// Encode snapshot metadata exactly as it would be sent over RRv3.
///
/// This is the authoritative transport gate: callers must not rely only on
/// chunk-size checks because a valid on-disk `meta.json` can be much larger than
/// `rr_v3_max_frame_bytes` when it contains sidecar JSON. The returned SHA is
/// computed over the slim transport metadata representation, not over the full
/// on-disk manifest.
pub fn encode_snapshot_meta_for_rrv3(
    meta: &SnapshotMeta,
    max_frame_bytes: usize,
) -> Option<(SnapshotMeta, String, Vec<u8>)> {
    let transport_meta = snapshot_meta_for_rrv3_transport(meta);

    if transport_meta.validate_basic().is_err() {
        return None;
    }

    if (transport_meta.chunk_size as usize) > rrv3_safe_snapshot_chunk_bytes(max_frame_bytes) {
        return None;
    }

    let meta_bytes = serde_json::to_vec_pretty(&transport_meta).ok()?;
    let sha = format!("{:x}", Sha256::digest(&meta_bytes));

    let msg = RrV3Msg::SnapshotV2Meta {
        meta: Some(transport_meta.clone()),
        meta_sha256_hex: Some(sha.clone()),
    };
    let encoded = encode_rr_v3(&msg);

    if encoded.is_empty() || encoded.len() > max_frame_bytes {
        return None;
    }

    Some((transport_meta, sha, encoded))
}

/// Returns true only if the snapshot metadata is sane *and* the declared chunk
/// size plus encoded transport metadata fit inside RRv3's frame budget.
pub fn snapshot_meta_is_rrv3_transport_servable(
    meta: &SnapshotMeta,
    max_frame_bytes: usize,
) -> bool {
    encode_snapshot_meta_for_rrv3(meta, max_frame_bytes).is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotLatestBundleRefreshReason {
    MissingMeta,
    UnreadableMeta,
    InvalidMeta,
    NotTransportServable,
    MissingChunkFiles,
    CorruptChunkFiles,
    StaleHeight,
    StaleWindow,
    StaleCheckpointBlock,
    NonCanonicalTimestamp,
}

impl SnapshotLatestBundleRefreshReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingMeta => "missing meta.json",
            Self::UnreadableMeta => "unreadable meta.json",
            Self::InvalidMeta => "invalid meta.json",
            Self::NotTransportServable => "meta.json not RRv3-transport-servable",
            Self::MissingChunkFiles => "meta.json references missing chunk files",
            Self::CorruptChunkFiles => "meta.json references corrupt chunk files",
            Self::StaleHeight => "meta.json height is stale for current snapshot cadence",
            Self::StaleWindow => {
                "meta.json window/base height is stale for current snapshot cadence"
            }
            Self::StaleCheckpointBlock => {
                "meta.json checkpoint block hash does not match current canonical anchor"
            }
            Self::NonCanonicalTimestamp => {
                "meta.json created_at_ts is not canonical for the current anchor"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotConsensusBootstrapContextOmissionReason {
    HistoricalStateCoverageUnavailable,
    ConsensusContextIncomplete,
}

impl SnapshotConsensusBootstrapContextOmissionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HistoricalStateCoverageUnavailable => {
                "historical state coverage unavailable for consensus bootstrap context"
            }
            Self::ConsensusContextIncomplete => {
                "consensus bootstrap context incomplete for exported snapshot"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotBundleFileStamp {
    len: u64,
    modified_unix_nanos: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotBundleIntegrityStamp {
    meta: SnapshotBundleFileStamp,
    chunks: Vec<SnapshotBundleFileStamp>,
}

#[derive(Debug, Clone)]
struct SnapshotBundleIntegrityCacheEntry {
    stamp: SnapshotBundleIntegrityStamp,
    intact: bool,
}

static SNAPSHOT_BUNDLE_INTEGRITY_CACHE: OnceLock<
    Mutex<HashMap<PathBuf, SnapshotBundleIntegrityCacheEntry>>,
> = OnceLock::new();

fn snapshot_bundle_integrity_cache(
) -> &'static Mutex<HashMap<PathBuf, SnapshotBundleIntegrityCacheEntry>> {
    SNAPSHOT_BUNDLE_INTEGRITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn snapshot_bundle_file_stamp(path: &Path) -> Option<SnapshotBundleFileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified_unix_nanos = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(SnapshotBundleFileStamp {
        len: meta.len(),
        modified_unix_nanos,
    })
}

fn snapshot_bundle_integrity_stamp(
    bundle_dir: &Path,
    bundle_meta: &SnapshotMeta,
) -> Option<SnapshotBundleIntegrityStamp> {
    let meta_stamp = snapshot_bundle_file_stamp(&bundle_dir.join("meta.json"))?;
    let chunks_dir = bundle_dir.join("chunks");
    let mut chunks = Vec::with_capacity(bundle_meta.chunks as usize);
    for idx in 0..bundle_meta.chunks {
        let chunk_path = chunks_dir.join(format!("{:06}.bin", idx));
        chunks.push(snapshot_bundle_file_stamp(&chunk_path)?);
    }
    Some(SnapshotBundleIntegrityStamp {
        meta: meta_stamp,
        chunks,
    })
}

fn snapshot_bundle_chunks_are_complete_and_intact_uncached(
    bundle_dir: &Path,
    meta: &SnapshotMeta,
) -> bool {
    let chunks_dir = bundle_dir.join("chunks");
    let mut total_len: u64 = 0;
    for idx in 0..meta.chunks {
        let chunk_path = chunks_dir.join(format!("{:06}.bin", idx));
        let bytes = match std::fs::read(&chunk_path) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        total_len = total_len.saturating_add(bytes.len() as u64);
        let got_hash = format!("{:x}", Sha256::digest(&bytes));
        let expected_hash = match meta.chunk_hashes_hex.get(idx as usize) {
            Some(h) => h,
            None => return false,
        };
        if got_hash != *expected_hash {
            return false;
        }
    }
    total_len == meta.bytes_len
}

fn snapshot_bundle_chunks_are_complete_and_intact(bundle_dir: &Path, meta: &SnapshotMeta) -> bool {
    let cache_key = bundle_dir.to_path_buf();
    if let Some(stamp) = snapshot_bundle_integrity_stamp(bundle_dir, meta) {
        if let Ok(cache) = snapshot_bundle_integrity_cache().lock() {
            if let Some(entry) = cache.get(&cache_key) {
                if entry.stamp == stamp {
                    return entry.intact;
                }
            }
        }
        let intact = snapshot_bundle_chunks_are_complete_and_intact_uncached(bundle_dir, meta);
        if let Ok(mut cache) = snapshot_bundle_integrity_cache().lock() {
            cache.insert(
                cache_key,
                SnapshotBundleIntegrityCacheEntry { stamp, intact },
            );
        }
        return intact;
    }

    snapshot_bundle_chunks_are_complete_and_intact_uncached(bundle_dir, meta)
}

pub fn preferred_checkpoint_snapshot_export_height(tip_height: u64, snapshot_every_n: u64) -> u64 {
    let snapshot_every_n = snapshot_every_n.max(1);
    if tip_height < snapshot_every_n {
        tip_height
    } else {
        (tip_height / snapshot_every_n) * snapshot_every_n
    }
}

pub fn preferred_bootstrap_snapshot_export_height(tip_height: u64) -> u64 {
    // GetSnapshotV2Latest must track the freshest bootstrap-servable snapshot, not the
    // cadenced checkpoint floor used for pruning/retention.
    tip_height
}

#[allow(dead_code)]
pub fn preferred_latest_snapshot_export_height(tip_height: u64, snapshot_every_n: u64) -> u64 {
    preferred_checkpoint_snapshot_export_height(tip_height, snapshot_every_n)
}

pub fn snapshot_latest_bundle_refresh_reason(
    bundle_dir: &Path,
    max_frame_bytes: usize,
    expected_height: Option<u64>,
    expected_window_from_height: Option<u64>,
    expected_checkpoint_block_hash: Option<&str>,
    expected_created_at_ts: Option<u64>,
) -> Option<SnapshotLatestBundleRefreshReason> {
    let meta_path = bundle_dir.join("meta.json");
    if !meta_path.exists() {
        return Some(SnapshotLatestBundleRefreshReason::MissingMeta);
    }

    let bytes = match std::fs::read(&meta_path) {
        Ok(bytes) => bytes,
        Err(_) => return Some(SnapshotLatestBundleRefreshReason::UnreadableMeta),
    };
    let meta = match serde_json::from_slice::<SnapshotMeta>(&bytes) {
        Ok(meta) => meta,
        Err(_) => return Some(SnapshotLatestBundleRefreshReason::InvalidMeta),
    };

    if meta.validate_basic().is_err() {
        return Some(SnapshotLatestBundleRefreshReason::InvalidMeta);
    }

    if !snapshot_meta_is_rrv3_transport_servable(&meta, max_frame_bytes) {
        return Some(SnapshotLatestBundleRefreshReason::NotTransportServable);
    }

    let chunks_dir = bundle_dir.join("chunks");
    for idx in 0..meta.chunks {
        let chunk_path = chunks_dir.join(format!("{:06}.bin", idx));
        if !chunk_path.exists() {
            return Some(SnapshotLatestBundleRefreshReason::MissingChunkFiles);
        }
    }
    if !snapshot_bundle_chunks_are_complete_and_intact(bundle_dir, &meta) {
        return Some(SnapshotLatestBundleRefreshReason::CorruptChunkFiles);
    }

    if let Some(expected_height) = expected_height {
        if meta.height != expected_height {
            return Some(SnapshotLatestBundleRefreshReason::StaleHeight);
        }
    }
    if let Some(expected_window_from_height) = expected_window_from_height {
        if meta.window_from_height != expected_window_from_height
            || meta.base_height != expected_window_from_height
        {
            return Some(SnapshotLatestBundleRefreshReason::StaleWindow);
        }
    }
    if let Some(expected_checkpoint_block_hash) = expected_checkpoint_block_hash {
        if meta.checkpoint_block_hash.trim() != expected_checkpoint_block_hash.trim() {
            return Some(SnapshotLatestBundleRefreshReason::StaleCheckpointBlock);
        }
    }
    if let Some(expected_created_at_ts) = expected_created_at_ts {
        if meta.created_at_ts != expected_created_at_ts {
            return Some(SnapshotLatestBundleRefreshReason::NonCanonicalTimestamp);
        }
    }

    None
}

fn default_snapshot_version() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "version", rename_all = "snake_case")]
pub enum SnapshotConsensusCommitteeContext {
    V1 {
        members_pk_hex: Vec<String>,
    },
    V2 {
        members: Vec<crate::pos::CommitteeMemberV2>,
    },
}

impl SnapshotConsensusCommitteeContext {
    pub fn validate_basic(&self) -> Result<(), String> {
        match self {
            Self::V1 { members_pk_hex } => {
                if members_pk_hex.is_empty() {
                    return Err(
                        "snapshot consensus bootstrap committee v1 must not be empty".to_string(),
                    );
                }
            }
            Self::V2 { members } => {
                if members.is_empty() {
                    return Err(
                        "snapshot consensus bootstrap committee v2 must not be empty".to_string(),
                    );
                }
                if members
                    .iter()
                    .any(|m| m.pk_hex.trim().is_empty() || m.stake == 0)
                {
                    return Err(
                        "snapshot consensus bootstrap committee v2 contains invalid member"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }

    pub fn to_committee_any(&self) -> crate::pos::CommitteeAny {
        match self {
            Self::V1 { members_pk_hex } => crate::pos::CommitteeAny::V1(crate::pos::CommitteeV1 {
                members_pk_hex: members_pk_hex.clone(),
            }),
            Self::V2 { members } => crate::pos::CommitteeAny::V2(crate::pos::CommitteeV2 {
                members: members.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotConsensusContextSourceKind {
    HistoricalBlockStateRoot,
    SnapshotStateRoot,
    // Retained for backward compatibility with older sidecars/tests. New snapshot
    // exports should not synthesize future-epoch params via snapshot-tip carry-forward.
    SnapshotStateRootCarryForward,
    DerivedGenesisNetworkSeed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotConsensusContextSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    pub state_root: String,
    pub kind: SnapshotConsensusContextSourceKind,
}

impl SnapshotConsensusContextSource {
    pub fn validate_basic(&self) -> Result<(), String> {
        if self.state_root.trim().is_empty()
            && !matches!(
                self.kind,
                SnapshotConsensusContextSourceKind::DerivedGenesisNetworkSeed
            )
        {
            return Err(
                "snapshot consensus bootstrap source state_root cannot be empty".to_string(),
            );
        }
        Ok(())
    }

    pub fn from_legacy_params_source(
        block_height: Option<u64>,
        state_root: Option<String>,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> Result<Option<Self>, String> {
        match (block_height, state_root) {
            (Some(height), Some(state_root)) => {
                let kind = if height == snapshot_height && state_root.trim() == snapshot_state_root.trim() {
                    SnapshotConsensusContextSourceKind::SnapshotStateRoot
                } else {
                    SnapshotConsensusContextSourceKind::HistoricalBlockStateRoot
                };
                Ok(Some(Self {
                    block_height: Some(height),
                    state_root,
                    kind,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(
                "snapshot consensus bootstrap legacy params source height/state_root must be set together"
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotConsensusEpochBootstrapContext {
    pub epoch: u64,
    #[serde(alias = "next_height_start")]
    pub coverage_start_height: u64,
    #[serde(alias = "next_height_end")]
    pub coverage_end_height: u64,
    pub pos_params: crate::staking::PosParamsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_source: Option<SnapshotConsensusContextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_source: Option<SnapshotConsensusContextSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committee_source: Option<SnapshotConsensusContextSource>,
    #[serde(default, rename = "params_source_height", skip_serializing)]
    pub(crate) legacy_params_source_height: Option<u64>,
    #[serde(default, rename = "params_source_state_root", skip_serializing)]
    pub(crate) legacy_params_source_state_root: Option<String>,
    pub seed_epoch: u64,
    pub seed_hex: String,
    pub committee: SnapshotConsensusCommitteeContext,
}

impl SnapshotConsensusEpochBootstrapContext {
    pub fn normalized_params_source(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> Result<Option<SnapshotConsensusContextSource>, String> {
        let legacy = SnapshotConsensusContextSource::from_legacy_params_source(
            self.legacy_params_source_height,
            self.legacy_params_source_state_root.clone(),
            snapshot_height,
            snapshot_state_root,
        )?;
        match (&self.params_source, legacy) {
            (Some(source), Some(legacy_source)) if *source != legacy_source => Err(
                "snapshot consensus bootstrap epoch context params_source/legacy params source mismatch"
                    .to_string(),
            ),
            (Some(source), _) => Ok(Some(source.clone())),
            (None, Some(legacy_source)) => Ok(Some(legacy_source)),
            (None, None) => Ok(None),
        }
    }

    pub fn validate_basic_with_snapshot(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> Result<(), String> {
        if self.coverage_start_height > self.coverage_end_height {
            return Err(format!(
                "snapshot consensus bootstrap epoch context invalid height window: {} > {}",
                self.coverage_start_height, self.coverage_end_height
            ));
        }
        if self.pos_params.epoch_len == 0 {
            return Err(
                "snapshot consensus bootstrap epoch context pos_params.epoch_len must be > 0"
                    .to_string(),
            );
        }
        if self.seed_epoch != self.epoch {
            return Err(format!(
                "snapshot consensus bootstrap epoch context seed_epoch/epoch mismatch: {} vs {}",
                self.seed_epoch, self.epoch
            ));
        }
        let expected_start = self.epoch.saturating_mul(self.pos_params.epoch_len);
        let expected_end =
            expected_start.saturating_add(self.pos_params.epoch_len.saturating_sub(1));
        if self.coverage_start_height != expected_start || self.coverage_end_height != expected_end
        {
            return Err(format!(
                "snapshot consensus bootstrap epoch context height window mismatch for epoch {}: [{}..={}] vs [{}..={}]",
                self.epoch,
                self.coverage_start_height,
                self.coverage_end_height,
                expected_start,
                expected_end
            ));
        }
        if let Some(source) = self.normalized_params_source(snapshot_height, snapshot_state_root)? {
            source.validate_basic()?;
        }
        if let Some(source) = self.seed_source.as_ref() {
            source.validate_basic()?;
        }
        if let Some(source) = self.committee_source.as_ref() {
            source.validate_basic()?;
        }
        if self.seed_hex.len() != 64 || !self.seed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(
                "snapshot consensus bootstrap epoch context seed_hex must be 32-byte hex"
                    .to_string(),
            );
        }
        self.committee.validate_basic()?;
        Ok(())
    }

    pub fn validate_basic(&self) -> Result<(), String> {
        self.validate_basic_with_snapshot(0, "")
    }

    pub fn contains_next_height(&self, next_height: u64) -> bool {
        self.coverage_start_height <= next_height && next_height <= self.coverage_end_height
    }

    pub fn decode_seed(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(self.seed_hex.trim()).map_err(|e| {
            format!(
                "snapshot consensus bootstrap epoch context seed_hex decode failed: {}",
                e
            )
        })?;
        if bytes.len() != 32 {
            return Err(format!(
                "snapshot consensus bootstrap epoch context seed_hex length invalid: {}",
                bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotConsensusBootstrapContext {
    pub snapshot_height: u64,
    pub prev_state_root: String,
    /// Inclusive height range for the minimal historical consensus sidecar.
    /// This is consensus-only coverage: it does not imply historical SMT roots are queryable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_consensus_window_from_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_consensus_window_to_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_start_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_end_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_epochs: Vec<u64>,
    #[serde(default)]
    pub epoch_contexts: Vec<SnapshotConsensusEpochBootstrapContext>,
    #[serde(
        default,
        rename = "next_height",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_next_height: Option<u64>,
    #[serde(default, rename = "epoch", skip_serializing_if = "Option::is_none")]
    legacy_epoch: Option<u64>,
    #[serde(
        default,
        rename = "pos_params",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_pos_params: Option<crate::staking::PosParamsV1>,
    #[serde(
        default,
        rename = "seed_epoch",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_seed_epoch: Option<u64>,
    #[serde(default, rename = "seed_hex", skip_serializing_if = "Option::is_none")]
    legacy_seed_hex: Option<String>,
    #[serde(default, rename = "committee", skip_serializing_if = "Option::is_none")]
    legacy_committee: Option<SnapshotConsensusCommitteeContext>,
}

impl SnapshotConsensusBootstrapContext {
    pub fn from_epoch_contexts(
        snapshot_height: u64,
        prev_state_root: String,
        epoch_contexts: Vec<SnapshotConsensusEpochBootstrapContext>,
    ) -> Self {
        let coverage_start_height = epoch_contexts
            .iter()
            .map(|ctx| ctx.coverage_start_height)
            .min();
        let coverage_end_height = epoch_contexts
            .iter()
            .map(|ctx| ctx.coverage_end_height)
            .max();
        let covered_epochs = epoch_contexts.iter().map(|ctx| ctx.epoch).collect();
        Self {
            snapshot_height,
            prev_state_root,
            historical_consensus_window_from_height: None,
            historical_consensus_window_to_height: None,
            coverage_start_height,
            coverage_end_height,
            covered_epochs,
            epoch_contexts,
            legacy_next_height: None,
            legacy_epoch: None,
            legacy_pos_params: None,
            legacy_seed_epoch: None,
            legacy_seed_hex: None,
            legacy_committee: None,
        }
    }

    pub fn with_historical_consensus_window(mut self, from_height: u64, to_height: u64) -> Self {
        self.historical_consensus_window_from_height = Some(from_height);
        self.historical_consensus_window_to_height = Some(to_height);
        self
    }

    pub fn historical_consensus_window(&self) -> Option<(u64, u64)> {
        match (
            self.historical_consensus_window_from_height,
            self.historical_consensus_window_to_height,
        ) {
            (Some(from), Some(to)) => Some((from, to)),
            _ => None,
        }
    }

    pub fn covers_consensus_height(&self, height: u64) -> bool {
        let Some((from, to)) = self.historical_consensus_window() else {
            return self.epoch_context_for_next_height(height).is_some();
        };
        if height < from || height > to {
            return false;
        }
        self.epoch_context_for_next_height(height).is_some()
    }

    fn epoch_contexts_cover_height_range(
        contexts: &[SnapshotConsensusEpochBootstrapContext],
        from_height: u64,
        to_height: u64,
    ) -> bool {
        if from_height > to_height {
            return false;
        }
        let mut ranges = contexts
            .iter()
            .map(|ctx| (ctx.coverage_start_height, ctx.coverage_end_height))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        let mut cursor = from_height;
        for (start, end) in ranges {
            if end < cursor {
                continue;
            }
            if start > cursor {
                return false;
            }
            if end >= to_height {
                return true;
            }
            cursor = end.saturating_add(1);
        }
        false
    }

    pub fn normalized_epoch_contexts(
        &self,
    ) -> Result<Vec<SnapshotConsensusEpochBootstrapContext>, String> {
        if !self.epoch_contexts.is_empty() {
            return Ok(self.epoch_contexts.clone());
        }
        match (
            self.legacy_next_height,
            self.legacy_epoch,
            self.legacy_pos_params.clone(),
            self.legacy_seed_epoch,
            self.legacy_seed_hex.clone(),
            self.legacy_committee.clone(),
        ) {
            (
                Some(next_height),
                Some(epoch),
                Some(pos_params),
                Some(seed_epoch),
                Some(seed_hex),
                Some(committee),
            ) => {
                if pos_params.epoch_len == 0 {
                    return Err(
                        "snapshot consensus bootstrap legacy context pos_params.epoch_len must be > 0"
                            .to_string(),
                    );
                }
                let next_height_start = epoch.saturating_mul(pos_params.epoch_len);
                let next_height_end = next_height_start
                    .saturating_add(pos_params.epoch_len.saturating_sub(1));
                if next_height < next_height_start || next_height > next_height_end {
                    return Err(format!(
                        "snapshot consensus bootstrap legacy context next_height {} outside epoch {} range [{}..={}]",
                        next_height,
                        epoch,
                        next_height_start,
                        next_height_end
                    ));
                }
                Ok(vec![SnapshotConsensusEpochBootstrapContext {
                    epoch,
                    coverage_start_height: next_height_start,
                    coverage_end_height: next_height_end,
                    pos_params,
                    params_source: None,
                    seed_source: None,
                    committee_source: None,
                    legacy_params_source_height: None,
                    legacy_params_source_state_root: None,
                    seed_epoch,
                    seed_hex,
                    committee,
                }])
            },
            _ => Err(
                "snapshot consensus bootstrap context missing epoch_contexts and legacy current context"
                    .to_string(),
            ),
        }
    }

    pub fn epoch_context(&self, epoch: u64) -> Option<SnapshotConsensusEpochBootstrapContext> {
        self.normalized_epoch_contexts()
            .ok()?
            .into_iter()
            .find(|ctx| ctx.epoch == epoch)
    }

    pub fn epoch_context_for_next_height(
        &self,
        next_height: u64,
    ) -> Option<SnapshotConsensusEpochBootstrapContext> {
        self.normalized_epoch_contexts()
            .ok()?
            .into_iter()
            .find(|ctx| ctx.contains_next_height(next_height))
    }

    pub fn validate_basic(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> Result<(), String> {
        if self.snapshot_height != snapshot_height {
            return Err(format!(
                "snapshot consensus bootstrap context height mismatch: {} vs {}",
                self.snapshot_height, snapshot_height
            ));
        }
        if self.prev_state_root.trim() != snapshot_state_root.trim() {
            return Err(
                "snapshot consensus bootstrap context prev_state_root mismatch".to_string(),
            );
        }
        let contexts = self.normalized_epoch_contexts()?;
        if contexts.is_empty() {
            return Err("snapshot consensus bootstrap context has no epoch contexts".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        for ctx in contexts.iter() {
            ctx.validate_basic_with_snapshot(snapshot_height, snapshot_state_root)?;
            if !seen.insert(ctx.epoch) {
                return Err(format!(
                    "snapshot consensus bootstrap context duplicate epoch context: {}",
                    ctx.epoch
                ));
            }
        }
        let expected_next_height = snapshot_height.saturating_add(1);
        if !contexts
            .iter()
            .any(|ctx| ctx.contains_next_height(expected_next_height))
        {
            return Err(format!(
                "snapshot consensus bootstrap context missing coverage for next_height {}",
                expected_next_height
            ));
        }
        let derived_coverage_start = contexts.iter().map(|ctx| ctx.coverage_start_height).min();
        let derived_coverage_end = contexts.iter().map(|ctx| ctx.coverage_end_height).max();
        let derived_epochs = contexts.iter().map(|ctx| ctx.epoch).collect::<Vec<_>>();
        if let Some(start) = self.coverage_start_height {
            if Some(start) != derived_coverage_start {
                return Err(format!(
                    "snapshot consensus bootstrap context coverage_start_height mismatch: {:?} vs {:?}",
                    self.coverage_start_height, derived_coverage_start
                ));
            }
        }
        if let Some(end) = self.coverage_end_height {
            if Some(end) != derived_coverage_end {
                return Err(format!(
                    "snapshot consensus bootstrap context coverage_end_height mismatch: {:?} vs {:?}",
                    self.coverage_end_height, derived_coverage_end
                ));
            }
        }
        if !self.covered_epochs.is_empty() && self.covered_epochs != derived_epochs {
            return Err(format!(
                "snapshot consensus bootstrap context covered_epochs mismatch: {:?} vs {:?}",
                self.covered_epochs, derived_epochs
            ));
        }
        match (
            self.historical_consensus_window_from_height,
            self.historical_consensus_window_to_height,
        ) {
            (Some(from), Some(to)) => {
                if from > to {
                    return Err(format!(
                        "snapshot consensus bootstrap historical window invalid: {} > {}",
                        from, to
                    ));
                }
                if !Self::epoch_contexts_cover_height_range(&contexts, from, to) {
                    return Err(format!(
                        "snapshot consensus bootstrap context does not cover historical consensus window [{}..={}]",
                        from, to
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(
                    "snapshot consensus bootstrap historical window endpoints must be set together"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStateCoverageMode {
    /// No SMT state-node payload is included. Blocks may be replayed from genesis or another source.
    NoStateNodes,
    /// SMT nodes cover every state root required to query the exported block window.
    FullHistoricalState,
    /// SMT nodes contain only the closure reachable from `state_root` at `height`.
    /// Intermediate state roots inside the exported block window are not guaranteed queryable.
    TipReachableOnly,
}

pub fn default_snapshot_state_coverage_mode() -> SnapshotStateCoverageMode {
    SnapshotStateCoverageMode::TipReachableOnly
}

fn default_snapshot_historical_state_roots_queryable() -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotBootstrapRole {
    /// Snapshot is safe for validator/runtime bootstrap. For reachable-only tip snapshots this
    /// requires a valid consensus bootstrap sidecar.
    ValidatorBootstrap,
    /// Snapshot contains only tip state and is suitable for read-only/explorer/diagnostic use.
    ReadOnlyTipState,
    /// Snapshot declares full historical SMT state coverage for its exported window.
    HistoricalStateArchive,
}

pub fn default_snapshot_validator_bootstrap_capable() -> bool {
    false
}

pub fn default_snapshot_bootstrap_role() -> SnapshotBootstrapRole {
    SnapshotBootstrapRole::ReadOnlyTipState
}

pub fn snapshot_meta_is_validator_bootstrap_capable(meta: &SnapshotMeta) -> bool {
    meta.validate_basic().is_ok() && meta.validator_bootstrap_capable
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Snapshot format version.
    /// v1 = legacy single-file (NGSNAP01)
    /// v2 = chunked bundle (meta.json + chunks/) (NGSNAP02)
    #[serde(default = "default_snapshot_version")]
    pub version: u32,

    /// Snapshot tip height.
    pub height: u64,

    /// Base height contained in the snapshot.
    /// For non-pruned DBs this is 0.
    #[serde(default)]
    pub base_height: u64,

    /// Total bytes in all chunks (payload only).
    pub bytes_len: u64,

    /// Chunk size used to split the snapshot payload.
    pub chunk_size: u32,

    /// Number of chunks.
    pub chunks: u32,

    /// SHA256 hash (hex) for each chunk, same ordering as chunk index.
    #[serde(default)]
    pub chunk_hashes_hex: Vec<String>,

    /// State root (hex) at `height`.
    pub state_root: String,

    /// Block hash at `height` (anchor).
    pub checkpoint_block_hash: String,

    /// Block hash at genesis height 0 (chain identity).
    #[serde(default)]
    pub genesis_hash: String,

    /// Canonical snapshot timestamp (unix seconds), derived deterministically from
    /// the checkpoint block timestamp rather than wall-clock export time so that
    /// honest peers exporting the same canonical window produce byte-identical
    /// snapshot bundles.
    #[serde(default)]
    pub created_at_ts: u64,

    /// Blocks window exported: [window_from_height, window_to_height].
    /// For v2 this allows future pruning-safe snapshots.
    #[serde(default)]
    pub window_from_height: u64,
    #[serde(default)]
    pub window_to_height: u64,

    /// Whether state nodes are included.
    #[serde(default)]
    pub include_state_nodes: bool,

    /// Whether the snapshot includes only nodes reachable from `state_root`.
    #[serde(default)]
    pub reachable_state_nodes: bool,

    /// Explicit state coverage contract. `tip_reachable_only` guarantees only `state_root`
    /// at `height`; it does not make intermediate block state roots queryable.
    #[serde(default = "default_snapshot_state_coverage_mode")]
    pub state_coverage_mode: SnapshotStateCoverageMode,

    /// Whether every state root in [window_from_height, window_to_height] can be queried
    /// locally from the imported state-node payload. Reachable-only tip snapshots must set
    /// this to false.
    #[serde(default = "default_snapshot_historical_state_roots_queryable")]
    pub historical_state_roots_queryable: bool,

    /// Explicit provider contract: true only when this snapshot can safely bootstrap
    /// a validator/runtime node. Reachable-only tip snapshots require a valid consensus
    /// bootstrap sidecar; read-only snapshots must set this to false.
    #[serde(default = "default_snapshot_validator_bootstrap_capable")]
    pub validator_bootstrap_capable: bool,

    /// Human-readable role for snapshot discovery and operator diagnostics.
    #[serde(default = "default_snapshot_bootstrap_role")]
    pub snapshot_bootstrap_role: SnapshotBootstrapRole,

    /// Optional governance snapshot anchor required for pruned snapshots.
    /// When `base_height > 0`, imports/boots need a governance state snapshot
    /// at or above `base_height` to avoid fail-open replay from missing history.
    ///
    /// `meta.json` remains a bounded manifest: new bundles advertise only the
    /// governance height/hash here, while the full JSON sidecar is carried inside
    /// the hashed snapshot payload header. Legacy bundles may still contain
    /// `governance_snapshot_json` in meta and are accepted for compatibility.
    #[serde(default)]
    pub governance_snapshot_height: Option<u64>,
    #[serde(default)]
    pub governance_snapshot_hash_hex: Option<String>,
    #[serde(default)]
    pub governance_snapshot_json: Option<String>,

    /// Optional economy/controller snapshot anchor for post-tip runtime recovery.
    /// The full economy JSON is carried inside the hashed snapshot payload header;
    /// meta.json only advertises the bound height/hash so discovery remains bounded.
    #[serde(default)]
    pub economy_snapshot_height: Option<u64>,
    #[serde(default)]
    pub economy_snapshot_hash_hex: Option<String>,

    /// Explicit finalized head bound to the snapshot window.
    ///
    /// This is intentionally distinct from `base_height`: base_height is only the
    /// first retained block in the pruned payload, while finalized_height is the
    /// latest consensus-finalized block. Validator/bootstrap snapshots must carry
    /// this explicitly so import never falls back to base_height as finality.
    #[serde(default)]
    pub finalized_height: Option<u64>,
    #[serde(default)]
    pub finalized_hash: Option<String>,
    #[serde(default)]
    pub highest_qc_height: Option<u64>,
    #[serde(default)]
    pub highest_qc_round: Option<u32>,
    #[serde(default)]
    pub highest_qc_block_hash: Option<String>,
    #[serde(default)]
    pub finality_source: Option<String>,
    #[serde(default)]
    pub finality_binding_version: Option<u32>,

    /// Optional compute order state sidecar. Required for pruned snapshots so E2
    /// order surfaces and claim admission can remain operational without replaying
    /// pruned historical blocks.
    #[serde(default)]
    pub compute_order_state_store_hash_hex: Option<String>,

    /// Optional full JSON sidecar used by private/testnet bundles. Public discovery
    /// may rely only on the hash, but import requires the payload in the bundle header.
    #[serde(default)]
    pub compute_order_state_store_json: Option<String>,

    /// Optional consensus bootstrap sidecar derived from the exported snapshot tip state.
    /// This carries a minimal multi-epoch consensus context (previous/current when available,
    /// always covering `snapshot_height + 1`) so a cold-start validator can recover
    /// proposer/committee/finality paths immediately after import even when historical
    /// SMT roots prior to the snapshot tip are intentionally absent. Future epochs are
    /// intentionally omitted unless they can be anchored to a real epoch-specific source.
    #[serde(default)]
    pub consensus_bootstrap_context: Option<SnapshotConsensusBootstrapContext>,

    /// Optional structured reason explaining why a reachable-only snapshot omitted
    /// the consensus bootstrap sidecar even though the rest of the bundle is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_bootstrap_context_omission_reason:
        Option<SnapshotConsensusBootstrapContextOmissionReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub height: u64,
    pub index: u32,
    pub bytes: Vec<u8>,
}

impl SnapshotMeta {
    pub fn validate_basic(&self) -> Result<(), String> {
        if self.version < 2 {
            return Err("snapshot meta version must be >= 2".to_string());
        }
        if self.chunk_size == 0 {
            return Err("snapshot meta chunk_size must be > 0".to_string());
        }
        if self.chunks == 0 {
            return Err("snapshot meta chunks must be > 0".to_string());
        }
        if self.chunk_hashes_hex.len() != self.chunks as usize {
            return Err(format!(
                "snapshot meta chunk hash list mismatch: hashes={} chunks={}",
                self.chunk_hashes_hex.len(),
                self.chunks
            ));
        }
        if self.window_from_height > self.window_to_height {
            return Err(format!(
                "snapshot meta invalid window: {} > {}",
                self.window_from_height, self.window_to_height
            ));
        }
        if self.height != self.window_to_height {
            return Err(format!(
                "snapshot meta height/window_to mismatch: height={} window_to={}",
                self.height, self.window_to_height
            ));
        }
        // Pruning-safe invariant: snapshot base height is the first block included in the bundle.
        if self.base_height != self.window_from_height {
            return Err(format!(
                "snapshot meta base_height/window_from mismatch: base_height={} window_from={}",
                self.base_height, self.window_from_height
            ));
        }
        // A pruned snapshot is a bootstrap/state-sync artifact, not a block-only archive.
        // Without state nodes the importer cannot verify or restore the tip SMT/economy
        // state for the retained window. Enforce this at metadata/discovery level, not
        // only later during payload import, so peers do not advertise/select bundles that
        // are known to be non-bootstrappable.
        if self.base_height > 0 && !self.include_state_nodes {
            return Err(format!(
                "snapshot meta pruned snapshot requires state nodes: base_height={} include_state_nodes=false",
                self.base_height
            ));
        }
        if self.bytes_len == 0 {
            return Err("snapshot meta bytes_len must be > 0".to_string());
        }
        let is_hex32 = |value: &str| -> bool {
            let value = value.trim();
            value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        };
        if self.state_root.trim() != "0" && !is_hex32(&self.state_root) {
            return Err("snapshot meta state_root must be 32-byte hex or 0".to_string());
        }
        if !is_hex32(&self.checkpoint_block_hash) {
            return Err("snapshot meta checkpoint_block_hash must be 32-byte hex".to_string());
        }
        if !is_hex32(&self.genesis_hash) {
            return Err("snapshot meta genesis_hash must be 32-byte hex".to_string());
        }
        for hash in &self.chunk_hashes_hex {
            if !is_hex32(hash) {
                return Err(
                    "snapshot meta chunk_hashes_hex entries must be 32-byte hex".to_string()
                );
            }
        }
        let expected_coverage_mode = if !self.include_state_nodes {
            SnapshotStateCoverageMode::NoStateNodes
        } else if self.reachable_state_nodes {
            SnapshotStateCoverageMode::TipReachableOnly
        } else {
            SnapshotStateCoverageMode::FullHistoricalState
        };
        if self.state_coverage_mode != expected_coverage_mode {
            return Err(format!(
                "snapshot meta state_coverage_mode mismatch: mode={:?} expected={:?} include_state_nodes={} reachable_state_nodes={}",
                self.state_coverage_mode,
                expected_coverage_mode,
                self.include_state_nodes,
                self.reachable_state_nodes
            ));
        }
        if self.reachable_state_nodes && self.historical_state_roots_queryable {
            return Err(
                "snapshot meta reachable_state_nodes=true requires historical_state_roots_queryable=false"
                    .to_string(),
            );
        }
        if self.historical_state_roots_queryable
            && self.state_coverage_mode != SnapshotStateCoverageMode::FullHistoricalState
        {
            return Err(
                "snapshot meta historical_state_roots_queryable=true requires full_historical_state coverage"
                    .to_string(),
            );
        }
        if self.state_coverage_mode == SnapshotStateCoverageMode::FullHistoricalState
            && !self.historical_state_roots_queryable
        {
            return Err(
                "snapshot meta full_historical_state coverage requires historical_state_roots_queryable=true"
                    .to_string(),
            );
        }
        match (
            self.economy_snapshot_height,
            self.economy_snapshot_hash_hex.as_ref(),
        ) {
            (Some(h), Some(hash)) => {
                if h != self.height {
                    return Err(format!(
                        "snapshot meta economy_snapshot_height/height mismatch: {} vs {}",
                        h, self.height
                    ));
                }
                let hash = hash.trim();
                if hash.len() != 64 || !hash.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
                    return Err(
                        "snapshot meta economy_snapshot_hash_hex must be 32-byte hex".to_string(),
                    );
                }
            }
            (None, None) => {
                return Err(
                    "snapshot meta missing economy snapshot height/hash for snapshot v2"
                        .to_string(),
                );
            }
            _ => {
                return Err(
                    "snapshot meta economy snapshot height/hash must be set together".to_string(),
                );
            }
        }

        match (
            self.finalized_height,
            self.finalized_hash.as_deref(),
            self.highest_qc_height,
            self.highest_qc_round,
            self.highest_qc_block_hash.as_deref(),
            self.finality_binding_version,
        ) {
            (
                Some(finalized_height),
                Some(finalized_hash),
                Some(highest_qc_height),
                Some(_highest_qc_round),
                Some(highest_qc_block_hash),
                Some(binding_version),
            ) => {
                if binding_version != 1 {
                    return Err(format!(
                        "snapshot meta unsupported finality_binding_version: {}",
                        binding_version
                    ));
                }
                if finalized_height > self.height {
                    return Err(format!(
                        "snapshot meta finalized_height {} exceeds height {}",
                        finalized_height, self.height
                    ));
                }
                if highest_qc_height > self.height {
                    return Err(format!(
                        "snapshot meta highest_qc_height {} exceeds height {}",
                        highest_qc_height, self.height
                    ));
                }
                if finalized_height > highest_qc_height {
                    return Err(format!(
                        "snapshot meta finalized_height {} exceeds highest_qc_height {}",
                        finalized_height, highest_qc_height
                    ));
                }
                if finalized_height > 0 && !is_hex32(finalized_hash) {
                    return Err(
                        "snapshot meta finalized_hash must be 32-byte hex for non-zero finality"
                            .to_string(),
                    );
                }
                if highest_qc_height > 0 && !is_hex32(highest_qc_block_hash) {
                    return Err(
                        "snapshot meta highest_qc_block_hash must be 32-byte hex for non-zero QC"
                            .to_string(),
                    );
                }
                if self.base_height > 0 {
                    if finalized_height < self.base_height {
                        return Err(format!(
                            "snapshot meta finalized_height {} below base_height {}",
                            finalized_height, self.base_height
                        ));
                    }
                    if self.height > self.base_height.saturating_add(1)
                        && finalized_height == self.base_height
                    {
                        return Err(format!(
                            "snapshot meta finalized_height equals base_height for non-trivial pruned window: finalized_height={} height={}",
                            finalized_height, self.height
                        ));
                    }
                }
            }
            (None, None, None, None, None, None) => {
                if self.base_height > 0 || self.validator_bootstrap_capable {
                    return Err(format!(
                        "snapshot meta pruned/validator bootstrap snapshot requires explicit finalized head: base_height={} validator_bootstrap_capable={}",
                        self.base_height, self.validator_bootstrap_capable
                    ));
                }
            }
            _ => {
                return Err("snapshot meta finality fields must be set together".to_string());
            }
        }

        match (
            self.compute_order_state_store_hash_hex.as_ref(),
            self.compute_order_state_store_json.as_ref(),
        ) {
            (Some(hash), payload) => {
                let hash = hash.trim();
                if hash.len() != 64 || !hash.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
                    return Err(
                        "snapshot meta compute_order_state_store_hash_hex must be 32-byte hex"
                            .to_string(),
                    );
                }
                if let Some(js) = payload {
                    let actual = format!("{:x}", Sha256::digest(js.as_bytes()));
                    if actual != hash {
                        return Err("snapshot meta compute_order_state_store_json/hash mismatch"
                            .to_string());
                    }
                }
            }
            (None, Some(_)) => {
                return Err("snapshot meta compute_order_state_store_json without hash".to_string());
            }
            (None, None) => {
                if self.base_height > 0 || crate::runtime_mode::public_mode_enabled() {
                    return Err(format!(
                        "snapshot meta public/pruned snapshot requires compute order state store sidecar: base_height={} public_mode={}",
                        self.base_height,
                        crate::runtime_mode::public_mode_enabled()
                    ));
                }
            }
        }

        if let Some(ctx) = self.consensus_bootstrap_context.as_ref() {
            ctx.validate_basic(self.height, &self.state_root)?;
        }
        if self.consensus_bootstrap_context.is_some()
            && self.consensus_bootstrap_context_omission_reason.is_some()
        {
            return Err(
                "snapshot meta cannot contain both consensus bootstrap context and omission reason"
                    .to_string(),
            );
        }
        if self.consensus_bootstrap_context_omission_reason.is_some()
            && !(self.include_state_nodes && self.reachable_state_nodes)
        {
            return Err(
                "snapshot meta consensus bootstrap omission reason requires reachable state nodes"
                    .to_string(),
            );
        }

        let expected_validator_bootstrap_capable = match self.state_coverage_mode {
            SnapshotStateCoverageMode::NoStateNodes => false,
            SnapshotStateCoverageMode::TipReachableOnly => {
                self.consensus_bootstrap_context.is_some()
            }
            SnapshotStateCoverageMode::FullHistoricalState => self.historical_state_roots_queryable,
        };
        if self.validator_bootstrap_capable != expected_validator_bootstrap_capable {
            return Err(format!(
                "snapshot meta validator_bootstrap_capable mismatch: value={} expected={} coverage={:?} has_consensus_bootstrap={}",
                self.validator_bootstrap_capable,
                expected_validator_bootstrap_capable,
                self.state_coverage_mode,
                self.consensus_bootstrap_context.is_some()
            ));
        }
        let expected_bootstrap_role = match self.state_coverage_mode {
            SnapshotStateCoverageMode::FullHistoricalState => {
                SnapshotBootstrapRole::HistoricalStateArchive
            }
            SnapshotStateCoverageMode::TipReachableOnly if expected_validator_bootstrap_capable => {
                SnapshotBootstrapRole::ValidatorBootstrap
            }
            _ => SnapshotBootstrapRole::ReadOnlyTipState,
        };
        if self.snapshot_bootstrap_role != expected_bootstrap_role {
            return Err(format!(
                "snapshot meta snapshot_bootstrap_role mismatch: role={:?} expected={:?} coverage={:?} validator_bootstrap_capable={}",
                self.snapshot_bootstrap_role,
                expected_bootstrap_role,
                self.state_coverage_mode,
                self.validator_bootstrap_capable
            ));
        }

        if self.base_height > 0 {
            let Some(gov_h) = self.governance_snapshot_height else {
                return Err(
                    "snapshot meta missing governance_snapshot_height for pruned snapshot"
                        .to_string(),
                );
            };
            if gov_h < self.base_height || gov_h > self.height {
                return Err(format!(
                    "snapshot meta governance snapshot height {} outside [{},{}]",
                    gov_h, self.base_height, self.height
                ));
            }

            let has_hash = self
                .governance_snapshot_hash_hex
                .as_deref()
                .map(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false);
            let has_legacy_json = self.governance_snapshot_json.is_some();
            if !has_hash && !has_legacy_json {
                return Err(
                    "snapshot meta missing governance_snapshot_hash_hex for pruned snapshot"
                        .to_string(),
                );
            }

            if let Some(gov_json) = self.governance_snapshot_json.as_ref() {
                serde_json::from_str::<crate::governance::GovernanceState>(gov_json).map_err(
                    |e| {
                        format!(
                            "snapshot meta governance snapshot JSON decode failed: {}",
                            e
                        )
                    },
                )?;
                if let Some(expected_hash) = self.governance_snapshot_hash_hex.as_deref() {
                    let actual_hash = format!("{:x}", Sha256::digest(gov_json.as_bytes()));
                    if actual_hash != expected_hash {
                        return Err(format!(
                            "snapshot meta governance snapshot hash mismatch: expected={} actual={}",
                            expected_hash, actual_hash
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn state_root_is_empty(&self) -> bool {
        let s = self.state_root.trim();
        s.is_empty() || s == "0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{Council, GovernanceParams, GovernanceState, ValidatorSet};

    fn sample_governance_json() -> String {
        serde_json::to_string(&GovernanceState::new(
            Council {
                members: vec!["protocol_member".to_string()],
                threshold: 1,
            },
            Council {
                members: vec!["economy_member".to_string()],
                threshold: 1,
            },
            Council {
                members: vec!["emergency_member".to_string()],
                threshold: 1,
            },
            GovernanceParams {
                min_timelock_blocks: 0,
                max_proposal_lifetime_blocks: 100_000,
                max_emergency_duration_blocks: 0,
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
                entries: Vec::new(),
                version: 0,
            },
        ))
        .unwrap()
    }

    fn sample_epoch_context(
        epoch: u64,
        coverage_start_height: u64,
        coverage_end_height: u64,
    ) -> SnapshotConsensusEpochBootstrapContext {
        SnapshotConsensusEpochBootstrapContext {
            epoch,
            coverage_start_height,
            coverage_end_height,
            pos_params: crate::staking::PosParamsV1 {
                min_stake: 1,
                unbonding_epochs: 7,
                epoch_len: 10,
                committee_size: 1,
            },
            params_source: Some(SnapshotConsensusContextSource {
                block_height: Some(coverage_end_height),
                state_root: "11".repeat(32),
                kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
            }),
            seed_source: Some(SnapshotConsensusContextSource {
                block_height: Some(coverage_end_height),
                state_root: "11".repeat(32),
                kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
            }),
            committee_source: Some(SnapshotConsensusContextSource {
                block_height: Some(coverage_end_height),
                state_root: "11".repeat(32),
                kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
            }),
            legacy_params_source_height: None,
            legacy_params_source_state_root: None,
            seed_epoch: epoch,
            seed_hex: "aa".repeat(32),
            committee: SnapshotConsensusCommitteeContext::V1 {
                members_pk_hex: vec!["validator-a".to_string()],
            },
        }
    }

    fn valid_meta() -> SnapshotMeta {
        let chunk0 = b"chunk-0";
        let chunk1 = b"chunk-1";
        SnapshotMeta {
            version: 2,
            height: 10,
            base_height: 8,
            bytes_len: (chunk0.len() + chunk1.len()) as u64,
            chunk_size: 16,
            chunks: 2,
            chunk_hashes_hex: vec![
                format!("{:x}", Sha256::digest(chunk0)),
                format!("{:x}", Sha256::digest(chunk1)),
            ],
            state_root: "11".repeat(32),
            checkpoint_block_hash: "22".repeat(32),
            genesis_hash: "33".repeat(32),
            created_at_ts: 1,
            window_from_height: 8,
            window_to_height: 10,
            include_state_nodes: true,
            reachable_state_nodes: true,
            state_coverage_mode: SnapshotStateCoverageMode::TipReachableOnly,
            historical_state_roots_queryable: false,
            validator_bootstrap_capable: false,
            snapshot_bootstrap_role: crate::snapshot::SnapshotBootstrapRole::ReadOnlyTipState,
            governance_snapshot_height: Some(10),
            governance_snapshot_hash_hex: Some(format!(
                "{:x}",
                Sha256::digest(sample_governance_json().as_bytes())
            )),
            governance_snapshot_json: Some(sample_governance_json()),
            economy_snapshot_height: Some(10),
            economy_snapshot_hash_hex: Some("44".repeat(32)),
            finalized_height: Some(9),
            finalized_hash: Some("55".repeat(32)),
            highest_qc_height: Some(10),
            highest_qc_round: Some(1),
            highest_qc_block_hash: Some("22".repeat(32)),
            finality_source: Some("test_finality_meta".to_string()),
            finality_binding_version: Some(1),
            compute_order_state_store_hash_hex: Some(
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_string(),
            ),
            compute_order_state_store_json: Some("{}".to_string()),
            consensus_bootstrap_context: None,
            consensus_bootstrap_context_omission_reason: None,
        }
    }

    fn write_valid_bundle(dir: &std::path::Path, meta: &SnapshotMeta) {
        std::fs::create_dir_all(dir.join("chunks")).unwrap();
        for idx in 0..meta.chunks {
            std::fs::write(
                dir.join("chunks").join(format!("{:06}.bin", idx)),
                format!("chunk-{idx}"),
            )
            .unwrap();
        }
        std::fs::write(
            dir.join("meta.json"),
            serde_json::to_vec_pretty(meta).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn validate_basic_accepts_consistent_meta() {
        assert!(valid_meta().validate_basic().is_ok());
    }

    #[test]
    fn validate_basic_accepts_pruned_governance_hash_without_meta_json() {
        let mut meta = valid_meta();
        meta.governance_snapshot_hash_hex = Some(format!(
            "{:x}",
            Sha256::digest(sample_governance_json().as_bytes())
        ));
        meta.governance_snapshot_json = None;

        assert!(meta.validate_basic().is_ok());
    }

    #[test]
    fn validate_basic_rejects_pruned_governance_without_hash_or_legacy_json() {
        let mut meta = valid_meta();
        meta.governance_snapshot_hash_hex = None;
        meta.governance_snapshot_json = None;

        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("governance_snapshot_hash_hex"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_basic_rejects_hash_count_and_window_mismatch() {
        let mut meta = valid_meta();
        meta.chunk_hashes_hex.pop();
        assert!(meta.validate_basic().is_err());

        let mut meta = valid_meta();
        meta.window_from_height = 11;
        assert!(meta.validate_basic().is_err());
    }

    #[test]
    fn state_root_empty_recognizes_blank_and_zero() {
        let mut meta = valid_meta();
        meta.state_root = "   ".to_string();
        assert!(meta.state_root_is_empty());
        meta.state_root = "0".to_string();
        assert!(meta.state_root_is_empty());
        meta.state_root = "abcd".to_string();
        assert!(!meta.state_root_is_empty());
    }

    #[test]
    fn rrv3_safe_snapshot_chunk_budget_stays_below_frame_cap() {
        let budget = rrv3_safe_snapshot_chunk_bytes(262_144);
        assert!(budget < 262_144);
        assert!(budget >= SNAPSHOT_V2_CHUNK_MIN_BYTES);
    }

    #[test]
    fn rrv3_safe_snapshot_chunk_budget_v230_caps_large_frames_to_single_response_payload() {
        let budget = rrv3_safe_snapshot_chunk_bytes(8 * 1024 * 1024);
        assert_eq!(budget, SNAPSHOT_V2_RRV3_SINGLE_RESPONSE_RAW_CAP_BYTES);
        assert!(budget < 4 * 1024 * 1024);
    }

    #[test]
    fn clamp_snapshot_chunk_bytes_v230_downshifts_four_mib_chunks_for_rrv3() {
        let clamped = clamp_snapshot_chunk_bytes_for_rrv3(4 * 1024 * 1024, 8 * 1024 * 1024);
        assert_eq!(clamped, SNAPSHOT_V2_RRV3_SINGLE_RESPONSE_RAW_CAP_BYTES);
    }

    #[test]
    fn transport_servable_rejects_oversize_chunk_metadata() {
        let mut meta = valid_meta();
        meta.chunk_size = 1_345_130;
        assert!(!snapshot_meta_is_rrv3_transport_servable(&meta, 262_144));

        meta.chunk_size = clamp_snapshot_chunk_bytes_for_rrv3(1_345_130, 262_144) as u32;
        assert!(snapshot_meta_is_rrv3_transport_servable(&meta, 262_144));
    }

    #[test]
    fn rrv3_transport_meta_derives_hashes_before_stripping_legacy_sidecars_v186() {
        let mut meta = valid_meta();
        meta.governance_snapshot_hash_hex = None;
        meta.compute_order_state_store_hash_hex = None;

        assert!(
            meta.validate_basic().is_err(),
            "precondition: legacy meta without compute-order hash should not validate directly"
        );

        let transport = snapshot_meta_for_rrv3_transport(&meta);

        assert!(transport.governance_snapshot_json.is_none());
        assert!(transport.compute_order_state_store_json.is_none());
        assert!(transport.governance_snapshot_hash_hex.is_some());
        assert!(transport.compute_order_state_store_hash_hex.is_some());
        assert!(transport.validate_basic().is_ok());

        let expected_gov = format!(
            "{:x}",
            Sha256::digest(meta.governance_snapshot_json.as_ref().unwrap().as_bytes())
        );
        let expected_compute = format!(
            "{:x}",
            Sha256::digest(
                meta.compute_order_state_store_json
                    .as_ref()
                    .unwrap()
                    .as_bytes()
            )
        );
        assert_eq!(
            transport.governance_snapshot_hash_hex.as_deref(),
            Some(expected_gov.as_str())
        );
        assert_eq!(
            transport.compute_order_state_store_hash_hex.as_deref(),
            Some(expected_compute.as_str())
        );

        let (_transport, sha, encoded) = encode_snapshot_meta_for_rrv3(&meta, 262_144)
            .expect("legacy sidecars should be hash-derived and stripped for RRv3");
        assert_eq!(sha.len(), 64);
        assert!(encoded.len() <= 262_144);
    }

    #[test]
    fn rrv3_transport_meta_strips_large_full_history_sidecars() {
        let mut meta = valid_meta();
        meta.base_height = 0;
        meta.window_from_height = 0;
        meta.governance_snapshot_height = Some(meta.height);
        meta.governance_snapshot_json = Some(format!(
            r#"{{"large_governance_sidecar":"{}"}}"#,
            "g".repeat(300_000)
        ));

        let compute_json = format!(r#"{{"orders":"{}"}}"#, "c".repeat(300_000));
        meta.compute_order_state_store_hash_hex =
            Some(format!("{:x}", Sha256::digest(compute_json.as_bytes())));
        meta.compute_order_state_store_json = Some(compute_json);

        assert!(serde_json::to_vec_pretty(&meta).unwrap().len() > 262_144);

        let (transport, sha, encoded) = encode_snapshot_meta_for_rrv3(&meta, 262_144)
            .expect("large on-disk sidecars must be stripped for RRv3 transport");

        assert_eq!(transport.base_height, 0);
        assert!(transport.governance_snapshot_json.is_none());
        assert!(transport.compute_order_state_store_json.is_none());
        assert!(transport.compute_order_state_store_hash_hex.is_some());
        assert_eq!(sha.len(), 64);
        assert!(encoded.len() <= 262_144);
        assert!(transport.validate_basic().is_ok());
        assert!(snapshot_meta_is_rrv3_transport_servable(&meta, 262_144));
    }

    #[test]
    fn snapshot_meta_contract_declares_tip_reachable_only_not_historical_queryable() {
        let meta = valid_meta();
        assert_eq!(
            meta.state_coverage_mode,
            SnapshotStateCoverageMode::TipReachableOnly
        );
        assert!(!meta.historical_state_roots_queryable);
        assert!(meta.validate_basic().is_ok());
    }

    #[test]
    fn snapshot_meta_tip_reachable_without_sidecar_is_not_validator_bootstrap_capable() {
        let meta = valid_meta();
        assert!(!meta.validator_bootstrap_capable);
        assert_eq!(
            meta.snapshot_bootstrap_role,
            SnapshotBootstrapRole::ReadOnlyTipState
        );
        assert!(!snapshot_meta_is_validator_bootstrap_capable(&meta));
        meta.validate_basic()
            .expect("read-only tip-state snapshot meta must validate");
    }

    #[test]
    fn snapshot_meta_tip_reachable_with_sidecar_is_validator_bootstrap_capable() {
        let mut meta = valid_meta();
        meta.consensus_bootstrap_context =
            Some(SnapshotConsensusBootstrapContext::from_epoch_contexts(
                meta.height,
                meta.state_root.clone(),
                vec![sample_epoch_context(1, 10, 19)],
            ));
        meta.validator_bootstrap_capable = true;
        meta.snapshot_bootstrap_role = SnapshotBootstrapRole::ValidatorBootstrap;
        meta.validate_basic()
            .expect("tip reachable snapshot with consensus sidecar must validate");
        assert!(snapshot_meta_is_validator_bootstrap_capable(&meta));
    }

    #[test]
    fn snapshot_meta_full_historical_archive_is_validator_capable_without_tip_sidecar() {
        let mut meta = valid_meta();
        meta.reachable_state_nodes = false;
        meta.state_coverage_mode = SnapshotStateCoverageMode::FullHistoricalState;
        meta.historical_state_roots_queryable = true;
        meta.validator_bootstrap_capable = true;
        meta.snapshot_bootstrap_role = SnapshotBootstrapRole::HistoricalStateArchive;
        meta.validate_basic()
            .expect("full historical archive with queryable roots must validate");
        assert!(snapshot_meta_is_validator_bootstrap_capable(&meta));
    }

    #[test]
    fn snapshot_meta_contract_rejects_reachable_only_historical_query_claim() {
        let mut meta = valid_meta();
        meta.historical_state_roots_queryable = true;
        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains(
                "reachable_state_nodes=true requires historical_state_roots_queryable=false"
            ),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn snapshot_meta_contract_rejects_state_coverage_mode_drift() {
        let mut meta = valid_meta();
        meta.state_coverage_mode = SnapshotStateCoverageMode::FullHistoricalState;
        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("state_coverage_mode mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn snapshot_meta_validate_accepts_consensus_bootstrap_omission_reason_for_reachable_only_bundle(
    ) {
        let mut meta = valid_meta();
        meta.consensus_bootstrap_context_omission_reason = Some(
            SnapshotConsensusBootstrapContextOmissionReason::HistoricalStateCoverageUnavailable,
        );
        meta.validate_basic()
            .expect("reachable-only omission reason must validate");
    }

    #[test]
    fn snapshot_meta_validate_rejects_pruned_bundle_without_state_nodes() {
        let mut meta = valid_meta();
        meta.include_state_nodes = false;
        meta.reachable_state_nodes = false;
        meta.state_coverage_mode = SnapshotStateCoverageMode::NoStateNodes;
        meta.historical_state_roots_queryable = false;
        meta.validator_bootstrap_capable = false;
        meta.snapshot_bootstrap_role = SnapshotBootstrapRole::ReadOnlyTipState;
        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("pruned snapshot requires state nodes"),
            "err={err}"
        );
    }

    #[test]
    fn snapshot_meta_validate_rejects_pruned_bundle_without_explicit_finality_v209() {
        let mut meta = valid_meta();
        meta.finalized_height = None;
        meta.finalized_hash = None;
        meta.highest_qc_height = None;
        meta.highest_qc_round = None;
        meta.highest_qc_block_hash = None;
        meta.finality_source = None;
        meta.finality_binding_version = None;

        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("requires explicit finalized head"),
            "err={err}"
        );
    }

    #[test]
    fn snapshot_meta_validate_rejects_base_height_as_finality_v209() {
        let mut meta = valid_meta();
        meta.finalized_height = Some(meta.base_height);
        meta.finalized_hash = Some("55".repeat(32));
        meta.highest_qc_height = Some(meta.base_height);
        meta.highest_qc_round = Some(1);
        meta.highest_qc_block_hash = Some("55".repeat(32));

        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("finalized_height equals base_height"),
            "err={err}"
        );
    }

    #[test]
    fn snapshot_meta_validate_rejects_consensus_bootstrap_omission_reason_without_reachable_state_nodes(
    ) {
        let mut meta = valid_meta();
        // This test targets the omission-reason contract, not the pruned-window contract.
        // Keep it full/base-height zero so the new pruned-snapshot state-node guard
        // does not mask the intended error.
        meta.base_height = 0;
        meta.window_from_height = 0;
        meta.governance_snapshot_height = None;
        meta.governance_snapshot_hash_hex = None;
        meta.governance_snapshot_json = None;
        meta.include_state_nodes = false;
        meta.reachable_state_nodes = false;
        meta.state_coverage_mode = SnapshotStateCoverageMode::NoStateNodes;
        meta.historical_state_roots_queryable = false;
        meta.validator_bootstrap_capable = false;
        meta.snapshot_bootstrap_role = SnapshotBootstrapRole::ReadOnlyTipState;
        meta.consensus_bootstrap_context_omission_reason =
            Some(SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete);
        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("consensus bootstrap omission reason requires reachable state nodes"),
            "err={err}"
        );
    }

    #[test]
    fn snapshot_meta_validate_rejects_context_and_omission_reason_together() {
        let mut meta = valid_meta();
        meta.consensus_bootstrap_context =
            Some(SnapshotConsensusBootstrapContext::from_epoch_contexts(
                meta.height,
                meta.state_root.clone(),
                vec![sample_epoch_context(1, 10, 19)],
            ));
        meta.consensus_bootstrap_context_omission_reason =
            Some(SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete);
        let err = meta.validate_basic().unwrap_err();
        assert!(
            err.contains("cannot contain both consensus bootstrap context and omission reason"),
            "err={err}"
        );
    }

    #[test]
    fn preferred_checkpoint_snapshot_export_height_uses_cadence_floor() {
        assert_eq!(preferred_checkpoint_snapshot_export_height(1459, 512), 1024);
        assert_eq!(preferred_checkpoint_snapshot_export_height(511, 512), 511);
        assert_eq!(preferred_checkpoint_snapshot_export_height(512, 512), 512);
    }

    #[test]
    fn preferred_bootstrap_snapshot_export_height_uses_tip() {
        assert_eq!(preferred_bootstrap_snapshot_export_height(1459), 1459);
        assert_eq!(preferred_bootstrap_snapshot_export_height(0), 0);
    }

    #[test]
    fn consensus_bootstrap_context_validate_accepts_consistent_multi_epoch_context() {
        let params = crate::staking::PosParamsV1 {
            min_stake: 1,
            unbonding_epochs: 7,
            epoch_len: 5,
            committee_size: 4,
        };
        let ctx = SnapshotConsensusBootstrapContext {
            snapshot_height: 10,
            prev_state_root: "11".repeat(32),
            historical_consensus_window_from_height: None,
            historical_consensus_window_to_height: None,
            coverage_start_height: Some(5),
            coverage_end_height: Some(14),
            covered_epochs: vec![1, 2],
            epoch_contexts: vec![
                SnapshotConsensusEpochBootstrapContext {
                    epoch: 1,
                    coverage_start_height: 5,
                    coverage_end_height: 9,
                    pos_params: params.clone(),
                    params_source: Some(SnapshotConsensusContextSource {
                        block_height: Some(10),
                        state_root: "11".repeat(32),
                        kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
                    }),
                    seed_source: None,
                    committee_source: None,
                    legacy_params_source_height: None,
                    legacy_params_source_state_root: None,
                    seed_epoch: 1,
                    seed_hex: "aa".repeat(32),
                    committee: SnapshotConsensusCommitteeContext::V1 {
                        members_pk_hex: vec!["bb".repeat(32)],
                    },
                },
                SnapshotConsensusEpochBootstrapContext {
                    epoch: 2,
                    coverage_start_height: 10,
                    coverage_end_height: 14,
                    pos_params: params.clone(),
                    params_source: Some(SnapshotConsensusContextSource {
                        block_height: Some(10),
                        state_root: "11".repeat(32),
                        kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
                    }),
                    seed_source: None,
                    committee_source: None,
                    legacy_params_source_height: None,
                    legacy_params_source_state_root: None,
                    seed_epoch: 2,
                    seed_hex: "cc".repeat(32),
                    committee: SnapshotConsensusCommitteeContext::V1 {
                        members_pk_hex: vec!["dd".repeat(32)],
                    },
                },
            ],
            legacy_next_height: None,
            legacy_epoch: None,
            legacy_pos_params: None,
            legacy_seed_epoch: None,
            legacy_seed_hex: None,
            legacy_committee: None,
        };
        assert!(ctx.validate_basic(10, &"11".repeat(32)).is_ok());
        let epoch_ctx = ctx.epoch_context(2).unwrap();
        assert_eq!(epoch_ctx.decode_seed().unwrap(), [0xcc; 32]);
        assert!(ctx.epoch_context_for_next_height(11).is_some());
    }

    #[test]
    fn consensus_bootstrap_context_validate_accepts_legacy_single_context() {
        let ctx = SnapshotConsensusBootstrapContext {
            snapshot_height: 10,
            prev_state_root: "11".repeat(32),
            historical_consensus_window_from_height: None,
            historical_consensus_window_to_height: None,
            coverage_start_height: None,
            coverage_end_height: None,
            covered_epochs: vec![],
            epoch_contexts: vec![],
            legacy_next_height: Some(11),
            legacy_epoch: Some(2),
            legacy_pos_params: Some(crate::staking::PosParamsV1 {
                min_stake: 1,
                unbonding_epochs: 7,
                epoch_len: 5,
                committee_size: 4,
            }),
            legacy_seed_epoch: Some(2),
            legacy_seed_hex: Some("aa".repeat(32)),
            legacy_committee: Some(SnapshotConsensusCommitteeContext::V1 {
                members_pk_hex: vec!["bb".repeat(32)],
            }),
        };
        assert!(ctx.validate_basic(10, &"11".repeat(32)).is_ok());
        assert!(ctx.epoch_context(2).is_some());
    }

    #[test]
    fn consensus_bootstrap_context_validate_rejects_missing_next_height_coverage() {
        let params = crate::staking::PosParamsV1 {
            min_stake: 1,
            unbonding_epochs: 7,
            epoch_len: 5,
            committee_size: 4,
        };
        let ctx = SnapshotConsensusBootstrapContext {
            snapshot_height: 10,
            prev_state_root: "11".repeat(32),
            historical_consensus_window_from_height: None,
            historical_consensus_window_to_height: None,
            coverage_start_height: Some(5),
            coverage_end_height: Some(9),
            covered_epochs: vec![1],
            epoch_contexts: vec![SnapshotConsensusEpochBootstrapContext {
                epoch: 1,
                coverage_start_height: 5,
                coverage_end_height: 9,
                pos_params: params,
                params_source: Some(SnapshotConsensusContextSource {
                    block_height: Some(10),
                    state_root: "11".repeat(32),
                    kind: SnapshotConsensusContextSourceKind::SnapshotStateRoot,
                }),
                seed_source: None,
                committee_source: None,
                legacy_params_source_height: None,
                legacy_params_source_state_root: None,
                seed_epoch: 1,
                seed_hex: "aa".repeat(32),
                committee: SnapshotConsensusCommitteeContext::V1 {
                    members_pk_hex: vec!["bb".repeat(32)],
                },
            }],
            legacy_next_height: None,
            legacy_epoch: None,
            legacy_pos_params: None,
            legacy_seed_epoch: None,
            legacy_seed_hex: None,
            legacy_committee: None,
        };
        assert!(ctx.validate_basic(10, &"11".repeat(32)).is_err());
    }

    #[test]
    fn consensus_bootstrap_context_rejects_incomplete_historical_consensus_window() {
        // The epoch context itself must be internally valid; this test is specifically
        // about the declared historical consensus sidecar window being larger than
        // the consensus heights covered by the sidecar. For epoch_len=10, epoch 1
        // covers [10..=19], so declaring [10..=20] must fail on coverage, not on
        // epoch-context shape.
        let ctx = SnapshotConsensusBootstrapContext::from_epoch_contexts(
            10,
            "11".repeat(32),
            vec![sample_epoch_context(1, 10, 19)],
        )
        .with_historical_consensus_window(10, 20);
        let err = ctx.validate_basic(10, &"11".repeat(32)).unwrap_err();
        assert!(
            err.contains("does not cover historical consensus window"),
            "err={err}"
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_missing_meta() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::MissingMeta)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_invalid_meta() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("meta.json"), b"not-json").unwrap();
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::InvalidMeta)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_not_transport_servable_meta() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size = 1_345_130;
        write_valid_bundle(dir.path(), &meta);
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::NotTransportServable)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_accepts_valid_transport_servable_meta() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        write_valid_bundle(dir.path(), &meta);
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            None
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_missing_chunk_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        std::fs::create_dir_all(dir.path().join("chunks")).unwrap();
        std::fs::write(
            dir.path().join("meta.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::MissingChunkFiles)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_corrupt_chunk_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        write_valid_bundle(dir.path(), &meta);
        std::fs::write(
            dir.path().join("chunks").join("000001.bin"),
            b"corrupt-chunk",
        )
        .unwrap();
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::CorruptChunkFiles)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_stale_height() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        write_valid_bundle(dir.path(), &meta);
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(
                dir.path(),
                262_144,
                Some(meta.height + 1),
                Some(meta.window_from_height),
                Some(&meta.checkpoint_block_hash),
                Some(meta.created_at_ts),
            ),
            Some(SnapshotLatestBundleRefreshReason::StaleHeight)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_reports_noncanonical_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        write_valid_bundle(dir.path(), &meta);
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(
                dir.path(),
                262_144,
                Some(meta.height),
                Some(meta.window_from_height),
                Some(&meta.checkpoint_block_hash),
                Some(meta.created_at_ts + 1),
            ),
            Some(SnapshotLatestBundleRefreshReason::NonCanonicalTimestamp)
        );
    }

    #[test]
    fn latest_bundle_refresh_reason_cache_invalidates_when_chunk_stamp_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = valid_meta();
        meta.chunk_size =
            clamp_snapshot_chunk_bytes_for_rrv3(meta.chunk_size as usize, 262_144) as u32;
        write_valid_bundle(dir.path(), &meta);
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            None
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::write(
            dir.path().join("chunks").join("000001.bin"),
            b"corrupt-chunk",
        )
        .unwrap();
        assert_eq!(
            snapshot_latest_bundle_refresh_reason(dir.path(), 262_144, None, None, None, None),
            Some(SnapshotLatestBundleRefreshReason::CorruptChunkFiles)
        );
    }
}
