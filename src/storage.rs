// NOTE (Mainnet-grade storage hardening):
// - Fjall è il backend canonico e durabile del runtime.
// - Gli update sono resi crash-safe tramite journaling (WAL marker) e recovery deterministico.
// - Sono definiti invarianti di storage (height ↔ tip hash ↔ state_root, contiguità, integrità hash).
// - È incluso un framework di migrazioni deterministiche (db_version in metadata).
// - Le entrypoint legacy restano solo come compatibilità di firma, non come backend alternativo.
//
// src/storage.rs
//
// Step 42 — Interfaccia astratta + implementazione canonica Fjall
//           + funzione di mirror dalla Blockchain esistente.

use crate::block::Block;
use crate::blockchain::{Blockchain, SnapshotEconomyStateV1};
use crate::cognitive_chain::{
    cognitive_registry_claim_index_storage_key, cognitive_registry_entry_storage_key,
    cognitive_registry_event_storage_key, cognitive_registry_meta_last_applied_height_key,
    cognitive_registry_meta_last_event_seq_key, validate_sha256_hex_field,
    CognitiveRegistryEntryV1, CognitiveRegistryEventV1, COGNITIVE_REGISTRY_CLAIM_INDEX_KEY_PREFIX,
    COGNITIVE_REGISTRY_ENTRY_KEY_PREFIX, COGNITIVE_REGISTRY_EVENT_KEY_PREFIX,
};
use crate::finality_bft::{self, FinalityBftCertV1, FinalityBftVoteV1};
use crate::governance::GovernanceState;
use crate::snapshot::{
    SnapshotBootstrapRole, SnapshotConsensusBootstrapContext,
    SnapshotConsensusBootstrapContextOmissionReason, SnapshotConsensusCommitteeContext,
    SnapshotConsensusEpochBootstrapContext, SnapshotMeta, SnapshotStateCoverageMode,
    SNAPSHOT_V2_CHUNK_MAX_BYTES, SNAPSHOT_V2_CHUNK_MIN_BYTES,
};
use crate::state_smt::{is_virtual_empty_hash, SmtNode, SmtWriteBatch};
use fjall::{
    Database as FjallDatabase, Keyspace as FjallKeyspace, KeyspaceCreateOptions,
    OwnedWriteBatch as FjallOwnedWriteBatch, PersistMode as FjallPersistMode,
};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-faults")]
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// -------------------------
// Flush tuning (dev/test)
// -------------------------
//
// Il flush del backend embedded Fjall può essere costoso su Windows (fsync) e causare spike CPU/Disk.
// In soak test, questi spike possono generare ritardi nella propagazione dei blocchi
// abbastanza lunghi da creare fork temporanei.
//
// Default (mainnet-safe): flush ad ogni blocco.
// Per dev/soak: esporta `NEWGEN_DB_FLUSH_EVERY_N_BLOCKS=10` (o 20, ecc.).
static DB_FLUSH_EVERY_N_BLOCKS: OnceLock<u64> = OnceLock::new();

fn db_flush_every_n_blocks() -> u64 {
    *DB_FLUSH_EVERY_N_BLOCKS.get_or_init(|| {
        std::env::var("NEWGEN_DB_FLUSH_EVERY_N_BLOCKS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| (1..=10_000).contains(&n))
            .unwrap_or(1)
    })
}

/// Canonical path for the active storage backend.
/// Tutto il nodo deve usare questo, non stringhe hardcodate in giro.
pub const DB_PATH: &str = "db";

/// Public storage-boundary wrapper for runtime schema coordination.
/// External call sites should not depend on `storage_migrations` directly.
pub fn ensure_runtime_storage_schema_current() -> Result<(), String> {
    crate::storage_migrations::ensure_runtime_schema_current()
}

/// Human-readable note for operators about the active runtime storage bootstrap strategy.
pub fn runtime_storage_bootstrap_strategy_note() -> &'static str {
    crate::storage_migrations::runtime_bootstrap_strategy_note()
}

pub(crate) fn current_runtime_storage_schema_version() -> u32 {
    crate::storage_migrations::CURRENT_RUNTIME_STORAGE_SCHEMA_VERSION
}

const FJALL_DIR_LOCK_FILE_NAME: &str = ".newgen_fjall_process.lock";
const FJALL_DIR_LOCK_INFO_FILE_NAME: &str = ".newgen_fjall_process.lockinfo.json";

const VERIFY_AUX_SCAN_LIMIT_QUICK: usize = 128;
const VERIFY_AUX_SCAN_LIMIT_FULL: usize = usize::MAX;
const FINALITY_BFT_META_DB_KEY: &str = "finality_bft_meta_v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedFinalityBftMetaV1 {
    finalized_height: u64,
    finalized_hash: String,
    highest_qc_height: u64,
    highest_qc_round: u32,
    highest_qc_block_hash: String,
}

#[derive(Clone)]
struct CanonicalFjallHandle {
    db: FjallDatabase,
    dir_lock: Arc<DbDirInterprocessLock>,
}

/// Process-local registry for the canonical Fjall database handle.
///
/// Mainnet-grade invariant: within a single process we do not reopen the same physical
/// database directory with multiple independent handles. All call sites must reuse the
/// canonical handle for the normalized path.
static FJALL_DB_REGISTRY: OnceLock<Mutex<HashMap<PathBuf, CanonicalFjallHandle>>> = OnceLock::new();

fn fjall_db_registry() -> &'static Mutex<HashMap<PathBuf, CanonicalFjallHandle>> {
    FJALL_DB_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Serialize)]
struct DbDirLockInfo {
    pid: u32,
    acquired_at_unix_ms: u64,
    executable: String,
}

struct DbDirInterprocessLock {
    lock_info_path: PathBuf,
    #[allow(dead_code)]
    file: File,
}

impl DbDirInterprocessLock {
    fn acquire(normalized_db_dir: &Path) -> StorageResult<Self> {
        let lock_file_path = normalized_db_dir.join(FJALL_DIR_LOCK_FILE_NAME);
        let lock_info_path = normalized_db_dir.join(FJALL_DIR_LOCK_INFO_FILE_NAME);
        let file = open_interprocess_lock_file(&lock_file_path)
            .map_err(|e| storage_error_from_lock_io(normalized_db_dir, &lock_info_path, e))?;
        let lock = Self {
            lock_info_path,
            file,
        };
        lock.write_lock_info_best_effort();
        Ok(lock)
    }

    fn write_lock_info_best_effort(&self) {
        let info = DbDirLockInfo {
            pid: std::process::id(),
            acquired_at_unix_ms: unix_time_millis_now(),
            executable: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&info) {
            atomic_write_file_best_effort(&self.lock_info_path, &bytes);
        }
    }
}

impl Drop for DbDirInterprocessLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_info_path);
    }
}

fn unix_time_millis_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn atomic_write_file_best_effort(path: &Path, bytes: &[u8]) {
    let parent = match path.parent() {
        Some(parent) => parent,
        None => return,
    };
    let stem = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("lock-info");
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        stem,
        std::process::id(),
        unix_time_millis_now()
    ));
    let mut tmp_file = match OpenOptions::new().create_new(true).write(true).open(&tmp) {
        Ok(file) => file,
        Err(_) => return,
    };
    if tmp_file.write_all(bytes).is_err() || tmp_file.sync_all().is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    drop(tmp_file);
    if crate::utils::atomic_replace_file_v1(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
    }
}

fn normalize_db_registry_path<P: AsRef<Path>>(path: P) -> StorageResult<PathBuf> {
    let raw = path.as_ref();
    std::fs::create_dir_all(raw).map_err(|e| {
        StorageError::BackendError(format!("cannot create db dir {}: {e}", raw.display()))
    })?;
    std::fs::canonicalize(raw).map_err(|e| {
        StorageError::BackendError(format!("cannot canonicalize db dir {}: {e}", raw.display()))
    })
}

#[cfg(unix)]
fn open_lock_file_rw(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

#[cfg(unix)]
fn acquire_unix_nonblocking_exclusive_lock(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;

    unsafe extern "C" {
        fn flock(fd: c_int, operation: c_int) -> c_int;
    }

    const LOCK_EX: c_int = 2;
    const LOCK_NB: c_int = 4;
    const EINTR: i32 = 4;

    loop {
        // SAFETY: `file.as_raw_fd()` is a live descriptor owned by `file`; `flock`
        // is invoked with constant flags and does not outlive the file object.
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(EINTR)) {
            continue;
        }
        return Err(err);
    }
}

#[cfg(unix)]
fn open_interprocess_lock_file(path: &Path) -> std::io::Result<File> {
    let file = open_lock_file_rw(path)?;
    acquire_unix_nonblocking_exclusive_lock(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_interprocess_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_interprocess_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
}

fn format_existing_lock_holder_details(lock_info_path: &Path) -> Option<String> {
    let bytes = fs::read(lock_info_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let pid = value.get("pid").and_then(|v| v.as_u64());
    let exe = value.get("executable").and_then(|v| v.as_str());
    let acquired = value.get("acquired_at_unix_ms").and_then(|v| v.as_u64());
    let mut parts = Vec::new();
    if let Some(pid) = pid {
        parts.push(format!("pid={pid}"));
    }
    if let Some(exe) = exe {
        parts.push(format!("exe={exe}"));
    }
    if let Some(acquired) = acquired {
        parts.push(format!("acquired_at_unix_ms={acquired}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn is_interprocess_lock_conflict_io(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(11) => true,
        #[cfg(windows)]
        Some(32 | 33) => true,
        _ => matches!(err.kind(), std::io::ErrorKind::WouldBlock),
    }
}

fn storage_error_from_lock_io(
    normalized_db_dir: &Path,
    lock_info_path: &Path,
    err: std::io::Error,
) -> StorageError {
    if is_interprocess_lock_conflict_io(&err) {
        let details = format_existing_lock_holder_details(lock_info_path)
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        StorageError::InterprocessOpenConflict {
            path: normalized_db_dir.display().to_string(),
            message: format!(
                "runtime db dir is already locked by another process{}",
                details
            ),
        }
    } else {
        StorageError::BackendError(format!(
            "cannot acquire runtime db dir lock {}: {err}",
            normalized_db_dir.display()
        ))
    }
}

fn open_canonical_fjall_db<P: AsRef<Path>>(
    path: P,
) -> StorageResult<(PathBuf, FjallDatabase, Arc<DbDirInterprocessLock>)> {
    let normalized = normalize_db_registry_path(path)?;
    let registry = fjall_db_registry();
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = guard.get(&normalized) {
        return Ok((normalized, entry.db.clone(), entry.dir_lock.clone()));
    }
    let dir_lock = Arc::new(DbDirInterprocessLock::acquire(&normalized)?);
    let db = FjallDatabase::builder(&normalized)
        .open()
        .map_err(|e| StorageError::BackendError(e.to_string()))?;
    guard.insert(
        normalized.clone(),
        CanonicalFjallHandle {
            db: db.clone(),
            dir_lock: dir_lock.clone(),
        },
    );
    Ok((normalized, db, dir_lock))
}

fn evict_canonical_fjall_db_by_normalized_path(path: &Path) {
    let registry = fjall_db_registry();
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.remove(path);
}

/// Evicts the canonical runtime DB handle for a path from the in-process registry.
///
/// This is the backend-agnostic boundary API used by runtime/bootstrap code.
pub fn evict_canonical_db_for_path<P: AsRef<Path>>(path: P) {
    let raw = path.as_ref();
    if !raw.exists() {
        return;
    }
    if let Ok(normalized) = std::fs::canonicalize(raw) {
        evict_canonical_fjall_db_by_normalized_path(&normalized);
    }
}

/// Errori di storage possibili.
/// Per ora è minimale, estendibile in futuro.
#[derive(Debug)]
pub enum StorageError {
    /// Errore generico del backend (DB, IO, ecc.)
    BackendError(String),

    /// Runtime DB dir already opened by another process.
    InterprocessOpenConflict { path: String, message: String },

    /// Richiesta di blocco non trovato (es. index fuori range)
    BlockNotFound(u64),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::BackendError(msg) => write!(f, "{msg}"),
            StorageError::InterprocessOpenConflict { path, message } => {
                write!(f, "db_dir_locked:{}:{}", path, message)
            }
            StorageError::BlockNotFound(height) => write!(f, "block_not_found:{height}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl StorageError {
    pub fn is_interprocess_open_conflict(&self) -> bool {
        matches!(self, StorageError::InterprocessOpenConflict { .. })
    }
}

/// Alias comodo per i risultati dello storage.
pub type StorageResult<T> = Result<T, StorageError>;

// -------------------------
// KVStore abstraction (compile-time, zero-cost in hot path)
// -------------------------
//
// NOTE:
// - This layer is intentionally minimal and backend-oriented (Fjall is the runtime default backend).
// - We keep the on-disk layout stable for existing runtime instances. A dedicated `meta` tree is additive
//   and migrated deterministically; legacy meta keys remain readable.
// - Batch commit is replay-safe under the current backend OCC retry semantics: ops are accumulated in memory
//   and applied inside a single transaction closure with no external side-effects.

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum ColumnFamily {
    Blocks,
    TxIndex,
    StateNodes,
    Meta,
    FinalityBftLastVote,
    FinalityBftMeta,
    FinalityBftQcArchive,
    CognitiveRegistryEntries,
    CognitiveRegistryByClaim,
    CognitiveRegistryEvents,
    CognitiveRegistryMeta,
}

impl ColumnFamily {
    pub const ALL: [ColumnFamily; 11] = [
        ColumnFamily::Blocks,
        ColumnFamily::TxIndex,
        ColumnFamily::StateNodes,
        ColumnFamily::Meta,
        ColumnFamily::FinalityBftLastVote,
        ColumnFamily::FinalityBftMeta,
        ColumnFamily::FinalityBftQcArchive,
        ColumnFamily::CognitiveRegistryEntries,
        ColumnFamily::CognitiveRegistryByClaim,
        ColumnFamily::CognitiveRegistryEvents,
        ColumnFamily::CognitiveRegistryMeta,
    ];

    pub fn keyspace_name(self) -> &'static str {
        match self {
            ColumnFamily::Blocks => "blocks",
            ColumnFamily::TxIndex => "tx_index",
            ColumnFamily::StateNodes => "state_nodes",
            ColumnFamily::Meta => "meta",
            ColumnFamily::FinalityBftLastVote => "finality_bft_last_vote",
            ColumnFamily::FinalityBftMeta => "finality_bft_meta",
            ColumnFamily::FinalityBftQcArchive => "finality_bft_qc_archive",
            ColumnFamily::CognitiveRegistryEntries => "cognitive_registry_entries",
            ColumnFamily::CognitiveRegistryByClaim => "cognitive_registry_by_claim",
            ColumnFamily::CognitiveRegistryEvents => "cognitive_registry_events",
            ColumnFamily::CognitiveRegistryMeta => "cognitive_registry_meta",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum StorageDurability {
    Buffered,
    SyncAll,
}

#[derive(Clone, Debug)]
enum DbOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        val: Vec<u8>,
    },
    Del {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
}

pub(crate) type StorageKvPair = (Vec<u8>, Vec<u8>);
pub(crate) type StorageKvIter<'a> = Box<dyn Iterator<Item = StorageResult<StorageKvPair>> + 'a>;

pub(crate) trait KVBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]);
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]);
}

pub(crate) trait KVStore: Send + Sync {
    type Batch: KVBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> StorageResult<Option<Vec<u8>>>;
    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> StorageResult<()>;
    fn delete(&self, cf: ColumnFamily, key: &[u8]) -> StorageResult<()>;

    fn batch(&self) -> Self::Batch;
    fn write_batch(&self, batch: Self::Batch) -> StorageResult<()>;
    fn write_batch_with_durability(
        &self,
        batch: Self::Batch,
        _durability: StorageDurability,
    ) -> StorageResult<()> {
        self.write_batch(batch)
    }

    /// Durability barrier for snapshot/pruning gates.
    fn flush_sync(&self) -> StorageResult<()>;

    /// Prefix scan iterator (used by pruning / SMT rebuild). Not a hot path.
    fn scan_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: Vec<u8>,
    ) -> StorageResult<StorageKvIter<'a>>;

    /// Range scan iterator (used by pruning / index maintenance). Not a hot path.
    fn iter_range<'a>(
        &'a self,
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    ) -> StorageResult<StorageKvIter<'a>>;
}

/// Runtime batch accumulator for the canonical Fjall backend.
///
/// Ops are accumulated in memory and committed atomically across the fixed keyspaces.
// -------------------------
// Test fault injection (feature-gated)
// -------------------------
//
// Used by Step 8 industrial testing.
// Enable with: `--features test-faults` and set `NG_TEST_DISK_FULL_AFTER_BYTES`.
// NOTE: This must NEVER be enabled for production builds.
#[cfg(feature = "test-faults")]
static TEST_DISK_FULL_BUDGET: OnceLock<AtomicI64> = OnceLock::new();

#[cfg(feature = "test-faults")]
fn test_disk_full_consume(bytes: usize) -> StorageResult<()> {
    let Ok(s) = std::env::var("NG_TEST_DISK_FULL_AFTER_BYTES") else {
        return Ok(());
    };

    let limit: i64 = s.trim().parse().map_err(|_| {
        StorageError::BackendError("NG_TEST_DISK_FULL_AFTER_BYTES must be an integer".to_string())
    })?;

    if limit <= 0 {
        return Err(StorageError::BackendError(
            "simulated disk full (budget <= 0)".to_string(),
        ));
    }

    let budget = TEST_DISK_FULL_BUDGET.get_or_init(|| AtomicI64::new(limit));

    let delta = bytes as i64;
    let prev = budget.fetch_sub(delta, Ordering::Relaxed);
    let newv = prev - delta;

    if newv < 0 {
        return Err(StorageError::BackendError(format!(
            "simulated disk full (remaining={})",
            newv
        )));
    }

    Ok(())
}

#[cfg(not(feature = "test-faults"))]
#[inline]
fn test_disk_full_consume(_bytes: usize) -> StorageResult<()> {
    Ok(())
}

/// Interfaccia astratta per lo storage della blockchain.
///
/// Il codice "alto" (blockchain, sync, API) dovrebbe parlare con questo trait,
/// mentre le implementazioni concrete (file JSON legacy, backend embedded, ecc.) restano
/// incapsulate qui sotto.
pub trait ChainStorage: Send + Sync {
    /// Ritorna l'altezza corrente della chain (numero di blocchi - 1),
    /// oppure 0 se esiste solo il genesis o la chain è vuota.
    fn get_height(&self) -> StorageResult<u64>;

    /// Restituisce il blocco all'indice dato, se esiste.
    fn get_block(&self, index: u64) -> StorageResult<Option<Block>>;

    /// Restituisce una sequenza di blocchi a partire da `from`,
    /// fino ad un massimo di `limit`. Se non ci sono blocchi, restituisce vec vuoto.
    fn get_blocks_range(&self, from: u64, limit: u32) -> StorageResult<Vec<Block>>;

    /// Aggiunge un nuovo blocco in coda alla chain.
    fn append_block(&self, block: &Block) -> StorageResult<()>;
}

// -------------------------
// Implementazione con il backend canonico Fjall
// -------------------------

/// Schema metadata keys (root DB keys; stable).
///
/// Nota: teniamo le chiavi nel DB root per compatibilità con DB legacy.
/// Le migrazioni deterministiche (storage_migrations) inizializzano e aggiornano queste chiavi.
pub const META_HEIGHT_KEY: &str = "meta:height";
pub const META_BASE_HEIGHT_KEY: &str = "meta:base_height";
pub const META_TIP_HASH_KEY: &str = "meta:tip_hash";
pub const META_TIP_STATE_ROOT_KEY: &str = "meta:tip_state_root";
pub const META_DB_VERSION_KEY: &str = "meta:db_version";
pub const META_JOURNAL_PENDING_KEY: &str = "meta:journal_pending";

// Governance cache (acceleratore di boot; non consenso)
pub const META_GOV_BOOTSTRAP_JSON_KEY: &str = "meta:gov_bootstrap_json";
pub const META_GOV_SNAPSHOT_HEIGHT_KEY: &str = "meta:gov_snapshot_height";
pub const META_GOV_SNAPSHOT_JSON_KEY: &str = "meta:gov_snapshot_json";
pub const META_ECONOMY_SNAPSHOT_HEIGHT_KEY: &str = "meta:economy_snapshot_height";
pub const META_ECONOMY_SNAPSHOT_JSON_KEY: &str = "meta:economy_snapshot_json";
/// Historical economy snapshot sidecar index.  The latest keys above remain the
/// compatibility/read-fast path; this height-index lets checkpoint/window exports
/// bind to an older snapshot height instead of depending on the current latest.
pub const META_ECONOMY_SNAPSHOT_BY_HEIGHT_PREFIX: &str = "meta:economy_snapshot:height:";
pub const META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY: &str =
    "meta:snapshot_consensus_bootstrap_json";
pub const META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY: &str =
    "meta:snapshot_reachable_state_import_json";
pub const META_COMPUTE_ORDER_STATE_STORE_JSON_KEY: &str = "meta:compute_order_state_store_v1_json";
pub const META_COMPUTE_ORDER_STATE_STORE_HEIGHT_KEY: &str =
    "meta:compute_order_state_store_v1_height";
pub const META_COMPUTE_ORDER_STATE_STORE_HASH_KEY: &str = "meta:compute_order_state_store_v1_hash";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotReachableStateImportMarker {
    pub height: u64,
    pub state_root: String,
    /// Imported snapshot block window. Historical SMT state roots in this window are not
    /// queryable for tip-reachable snapshots, but consensus may be served by the minimal
    /// consensus sidecar if the height is covered there.
    #[serde(default)]
    pub window_from_height: u64,
    #[serde(default)]
    pub window_to_height: u64,
    #[serde(default = "crate::snapshot::default_snapshot_state_coverage_mode")]
    pub state_coverage_mode: SnapshotStateCoverageMode,
    #[serde(default)]
    pub historical_state_roots_queryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalMarker {
    op: String,
    ts: u64,
    note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub height: Option<u64>,
    pub issues: Vec<String>,
    pub needs_recovery: bool,
}

#[derive(Debug, Clone)]
pub struct PruneReport {
    pub old_base_height: u64,
    pub new_base_height: u64,
    pub pruned_blocks: u64,
    pub pruned_tx_index: u64,
}

/// Report per GC/compaction di `state_nodes`.
///
/// Mainnet-grade note:
/// - Il GC **non** deve mai rimuovere nodi raggiungibili dal `state_root` scelto.
/// - Un crash a metà GC è safe: il risultato è un superset (rimangono più nodi del necessario).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcStateNodesReport {
    /// Nodi raggiungibili dal root (target set).
    pub reachable: u64,
    /// Chiavi scansionate nel tree.
    pub scanned: u64,
    /// Nodi rimossi (unreachable).
    pub removed: u64,
    /// Nodi mantenuti.
    pub kept: u64,
    /// Durata totale in millisecondi.
    pub duration_ms: u64,
}

fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn encode_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn decode_u64(bytes: &[u8]) -> StorageResult<u64> {
    if bytes.len() != 8 {
        return Err(StorageError::BackendError(
            "valore meta:height con lunghezza non valida".to_string(),
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(arr))
}

fn decode_u32(bytes: &[u8]) -> StorageResult<u32> {
    if bytes.len() != 4 {
        return Err(StorageError::BackendError(
            "valore meta:db_version con lunghezza non valida".to_string(),
        ));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(arr))
}

fn block_key(index: u64) -> String {
    // chiave lexicographically-ordinabile
    // b:00000000000000000000, b:00000000000000000001, ...
    format!("b:{:020}", index)
}

/// Handle runtime basato sul backend canonico Fjall.
#[derive(Clone)]
#[doc(hidden)]
pub struct RuntimeKeyspaceHandle {
    db: FjallDatabase,
    inner: FjallKeyspace,
}

#[derive(Clone)]
pub(crate) struct StorageStateNodeStore {
    db: FjallDatabase,
    inner: FjallKeyspace,
}

impl fmt::Debug for RuntimeKeyspaceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeKeyspaceHandle")
            .field("backend", &"fjall")
            .finish()
    }
}

impl fmt::Debug for StorageStateNodeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageStateNodeStore")
            .field("backend", &"fjall")
            .finish()
    }
}

impl fmt::Debug for DbStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbStore").finish_non_exhaustive()
    }
}

impl StorageStateNodeStore {
    pub(crate) fn get_node_decoded(&self, key: &[u8]) -> Result<Option<SmtNode>, String> {
        self.inner
            .get(key)
            .map_err(|e| format!("fjall get: {e}"))
            .and_then(|opt| {
                opt.map(|v| {
                    bincode::deserialize(v.as_ref()).map_err(|e| format!("bincode node: {e}"))
                })
                .transpose()
            })
    }

    pub(crate) fn put_node(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner
            .insert(key, value)
            .map_err(|e| format!("fjall insert: {e}"))?;
        Ok(())
    }

    pub(crate) fn write_batch(&self, batch: SmtWriteBatch) -> Result<(), String> {
        let mut wb = FjallOwnedWriteBatch::with_capacity(
            self.db.clone(),
            batch.puts.len() + batch.deletes.len(),
        );
        for (k, v) in batch.puts {
            wb.insert(&self.inner, k, v);
        }
        for k in batch.deletes {
            wb.remove(&self.inner, k);
        }
        wb.commit().map_err(|e| format!("fjall batch commit: {e}"))
    }
}

#[derive(Clone, Debug)]
enum RuntimeKeyspaceOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

#[derive(Clone, Debug, Default)]
#[doc(hidden)]
pub struct RuntimeKeyspaceBatch {
    ops: Vec<RuntimeKeyspaceOp>,
}

impl RuntimeKeyspaceBatch {
    pub fn put<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.ops.push(RuntimeKeyspaceOp::Put {
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        });
    }

    pub fn delete<K>(&mut self, key: K)
    where
        K: AsRef<[u8]>,
    {
        self.ops.push(RuntimeKeyspaceOp::Delete {
            key: key.as_ref().to_vec(),
        });
    }
}

impl RuntimeKeyspaceHandle {
    pub fn from_fjall(db: FjallDatabase, inner: FjallKeyspace) -> Self {
        Self { db, inner }
    }

    pub fn get<K>(&self, key: K) -> StorageResult<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        self.inner
            .get(key.as_ref())
            .map(|opt| opt.map(|v| v.as_ref().to_vec()))
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    pub fn batch(&self) -> RuntimeKeyspaceBatch {
        RuntimeKeyspaceBatch::default()
    }

    fn write_batch_with_durability(
        &self,
        batch: RuntimeKeyspaceBatch,
        durability: StorageDurability,
    ) -> StorageResult<()> {
        if batch.ops.is_empty() {
            return Ok(());
        }
        let mut wb = FjallOwnedWriteBatch::with_capacity(self.db.clone(), batch.ops.len());
        for op in batch.ops {
            match op {
                RuntimeKeyspaceOp::Put { key, value } => wb.insert(&self.inner, key, value),
                RuntimeKeyspaceOp::Delete { key } => wb.remove(&self.inner, key),
            }
        }
        let wb = match durability {
            StorageDurability::Buffered => wb,
            StorageDurability::SyncAll => wb.durability(Some(FjallPersistMode::SyncAll)),
        };
        wb.commit()
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    /// Buffered write into the keyspace. Visible locally, but not a crash-durability barrier.
    pub fn insert<K, V>(&self, key: K, value: V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.inner
            .insert(key.as_ref(), value.as_ref())
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    /// Single-key durable write bound to a SyncAll batch commit.
    pub fn insert_sync<K, V>(&self, key: K, value: V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut batch = self.batch();
        batch.put(key, value);
        self.write_batch_sync(batch)
    }

    pub fn remove<K>(&self, key: K) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
    {
        self.inner
            .remove(key.as_ref())
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    /// Single-key durable delete bound to a SyncAll batch commit.
    pub fn remove_sync<K>(&self, key: K) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
    {
        let mut batch = self.batch();
        batch.delete(key);
        self.write_batch_sync(batch)
    }

    pub fn write_batch(&self, batch: RuntimeKeyspaceBatch) -> StorageResult<()> {
        self.write_batch_with_durability(batch, StorageDurability::Buffered)
    }

    pub fn write_batch_sync(&self, batch: RuntimeKeyspaceBatch) -> StorageResult<()> {
        self.write_batch_with_durability(batch, StorageDurability::SyncAll)
    }

    /// Process-wide durability barrier for the canonical Fjall DB handle.
    pub fn flush(&self) -> StorageResult<()> {
        self.db
            .persist(FjallPersistMode::SyncAll)
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    pub fn iter<'a>(&'a self) -> StorageKvIter<'a> {
        Box::new(self.inner.iter().map(|guard| {
            let (k, v) = guard
                .into_inner()
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            Ok((k.as_ref().to_vec(), v.as_ref().to_vec()))
        }))
    }

    pub fn range_from<'a>(&'a self, start: Vec<u8>) -> StorageKvIter<'a> {
        Box::new(self.inner.range(start..).map(|guard| {
            let (k, v) = guard
                .into_inner()
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            Ok((k.as_ref().to_vec(), v.as_ref().to_vec()))
        }))
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FjallBatch {
    ops: Vec<DbOp>,
}

impl FjallBatch {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }
}

impl KVBatch for FjallBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push(DbOp::Put {
            cf,
            key: key.to_vec(),
            val: value.to_vec(),
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(DbOp::Del {
            cf,
            key: key.to_vec(),
        });
    }
}

#[derive(Clone)]
pub struct DbStore {
    db: FjallDatabase,
    #[allow(dead_code)]
    dir_lock: Arc<DbDirInterprocessLock>,
    blocks_keyspace: FjallKeyspace,
    tx_index_keyspace: FjallKeyspace,
    state_nodes_keyspace: FjallKeyspace,
    meta_keyspace: FjallKeyspace,
    finality_bft_last_vote_keyspace: FjallKeyspace,
    finality_bft_meta_keyspace: FjallKeyspace,
    finality_bft_qc_keyspace: FjallKeyspace,
    cognitive_registry_entries_keyspace: FjallKeyspace,
    cognitive_registry_by_claim_keyspace: FjallKeyspace,
    cognitive_registry_events_keyspace: FjallKeyspace,
    cognitive_registry_meta_keyspace: FjallKeyspace,
}

impl DbStore {
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let (normalized_path, db, dir_lock) = open_canonical_fjall_db(path)?;
        let open_result: StorageResult<Self> = (|| {
            let blocks_keyspace = db
                .keyspace(
                    ColumnFamily::Blocks.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let tx_index_keyspace = db
                .keyspace(
                    ColumnFamily::TxIndex.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let state_nodes_keyspace = db
                .keyspace(
                    ColumnFamily::StateNodes.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let meta_keyspace = db
                .keyspace(
                    ColumnFamily::Meta.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let finality_bft_last_vote_keyspace = db
                .keyspace(
                    ColumnFamily::FinalityBftLastVote.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let finality_bft_meta_keyspace = db
                .keyspace(
                    ColumnFamily::FinalityBftMeta.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let finality_bft_qc_keyspace = db
                .keyspace(
                    ColumnFamily::FinalityBftQcArchive.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let cognitive_registry_entries_keyspace = db
                .keyspace(
                    ColumnFamily::CognitiveRegistryEntries.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let cognitive_registry_by_claim_keyspace = db
                .keyspace(
                    ColumnFamily::CognitiveRegistryByClaim.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let cognitive_registry_events_keyspace = db
                .keyspace(
                    ColumnFamily::CognitiveRegistryEvents.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let cognitive_registry_meta_keyspace = db
                .keyspace(
                    ColumnFamily::CognitiveRegistryMeta.keyspace_name(),
                    KeyspaceCreateOptions::default,
                )
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            crate::storage::ensure_runtime_storage_schema_current()
                .map_err(StorageError::BackendError)?;
            let storage = Self {
                db,
                dir_lock,
                blocks_keyspace,
                tx_index_keyspace,
                state_nodes_keyspace,
                meta_keyspace,
                finality_bft_last_vote_keyspace,
                finality_bft_meta_keyspace,
                finality_bft_qc_keyspace,
                cognitive_registry_entries_keyspace,
                cognitive_registry_by_claim_keyspace,
                cognitive_registry_events_keyspace,
                cognitive_registry_meta_keyspace,
            };
            storage.ensure_runtime_db_version_marker()?;
            Ok(storage)
        })();
        if open_result.is_err() {
            evict_canonical_fjall_db_by_normalized_path(&normalized_path);
        }
        open_result
    }

    fn canonical_keyspace(&self, cf: ColumnFamily) -> &FjallKeyspace {
        match cf {
            ColumnFamily::Blocks => &self.blocks_keyspace,
            ColumnFamily::TxIndex => &self.tx_index_keyspace,
            ColumnFamily::StateNodes => &self.state_nodes_keyspace,
            ColumnFamily::Meta => &self.meta_keyspace,
            ColumnFamily::FinalityBftLastVote => &self.finality_bft_last_vote_keyspace,
            ColumnFamily::FinalityBftMeta => &self.finality_bft_meta_keyspace,
            ColumnFamily::FinalityBftQcArchive => &self.finality_bft_qc_keyspace,
            ColumnFamily::CognitiveRegistryEntries => &self.cognitive_registry_entries_keyspace,
            ColumnFamily::CognitiveRegistryByClaim => &self.cognitive_registry_by_claim_keyspace,
            ColumnFamily::CognitiveRegistryEvents => &self.cognitive_registry_events_keyspace,
            ColumnFamily::CognitiveRegistryMeta => &self.cognitive_registry_meta_keyspace,
        }
    }

    pub fn cognitive_registry_get_entry(
        &self,
        object_hash_hex: &str,
    ) -> StorageResult<Option<CognitiveRegistryEntryV1>> {
        let key = cognitive_registry_entry_storage_key(object_hash_hex)
            .map_err(StorageError::BackendError)?;
        match self.get(ColumnFamily::CognitiveRegistryEntries, &key)? {
            Some(v) => {
                let entry: CognitiveRegistryEntryV1 = serde_json::from_slice(&v)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                entry.validate().map_err(StorageError::BackendError)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    pub fn cognitive_registry_put_entry(
        &self,
        entry: &CognitiveRegistryEntryV1,
    ) -> StorageResult<()> {
        entry.validate().map_err(StorageError::BackendError)?;
        let key = cognitive_registry_entry_storage_key(&entry.object_hash_hex)
            .map_err(StorageError::BackendError)?;
        let data =
            serde_json::to_vec(entry).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.put(ColumnFamily::CognitiveRegistryEntries, &key, &data)
    }
    pub(crate) fn cognitive_registry_put_entry_in_batch(
        &self,
        batch: &mut FjallBatch,
        entry: &CognitiveRegistryEntryV1,
    ) -> StorageResult<()> {
        entry.validate().map_err(StorageError::BackendError)?;
        let key = cognitive_registry_entry_storage_key(&entry.object_hash_hex)
            .map_err(StorageError::BackendError)?;
        let data =
            serde_json::to_vec(entry).map_err(|e| StorageError::BackendError(e.to_string()))?;
        batch.put(ColumnFamily::CognitiveRegistryEntries, &key, &data);
        Ok(())
    }

    pub fn cognitive_registry_get_claim_index(
        &self,
        claim_hash_hex: &str,
    ) -> StorageResult<Vec<String>> {
        let key = cognitive_registry_claim_index_storage_key(claim_hash_hex)
            .map_err(StorageError::BackendError)?;
        match self.get(ColumnFamily::CognitiveRegistryByClaim, &key)? {
            Some(v) => {
                let mut rows: Vec<String> = serde_json::from_slice(&v)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                for object_hash in &rows {
                    validate_sha256_hex_field("object_hash_hex", object_hash)
                        .map_err(StorageError::BackendError)?;
                }
                rows.sort();
                rows.dedup();
                Ok(rows)
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn cognitive_registry_put_claim_index(
        &self,
        claim_hash_hex: &str,
        object_hashes: &[String],
    ) -> StorageResult<()> {
        let key = cognitive_registry_claim_index_storage_key(claim_hash_hex)
            .map_err(StorageError::BackendError)?;
        let mut normalized = object_hashes.to_vec();
        for object_hash in &normalized {
            validate_sha256_hex_field("object_hash_hex", object_hash)
                .map_err(StorageError::BackendError)?;
        }
        normalized.sort();
        normalized.dedup();
        let data = serde_json::to_vec(&normalized)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.put(ColumnFamily::CognitiveRegistryByClaim, &key, &data)
    }
    pub(crate) fn cognitive_registry_put_claim_index_in_batch(
        &self,
        batch: &mut FjallBatch,
        claim_hash_hex: &str,
        object_hashes: &[String],
    ) -> StorageResult<()> {
        let key = cognitive_registry_claim_index_storage_key(claim_hash_hex)
            .map_err(StorageError::BackendError)?;
        let mut normalized = object_hashes.to_vec();
        for object_hash in &normalized {
            validate_sha256_hex_field("object_hash_hex", object_hash)
                .map_err(StorageError::BackendError)?;
        }
        normalized.sort();
        normalized.dedup();
        let data = serde_json::to_vec(&normalized)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        batch.put(ColumnFamily::CognitiveRegistryByClaim, &key, &data);
        Ok(())
    }

    pub fn cognitive_registry_append_event(
        &self,
        event: &CognitiveRegistryEventV1,
    ) -> StorageResult<()> {
        event.validate().map_err(StorageError::BackendError)?;
        let key = cognitive_registry_event_storage_key(event.block_height, event.event_seq);
        let data =
            serde_json::to_vec(event).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.put(ColumnFamily::CognitiveRegistryEvents, &key, &data)
    }
    pub(crate) fn cognitive_registry_append_event_in_batch(
        &self,
        batch: &mut FjallBatch,
        event: &CognitiveRegistryEventV1,
    ) -> StorageResult<()> {
        event.validate().map_err(StorageError::BackendError)?;
        let key = cognitive_registry_event_storage_key(event.block_height, event.event_seq);
        let data =
            serde_json::to_vec(event).map_err(|e| StorageError::BackendError(e.to_string()))?;
        batch.put(ColumnFamily::CognitiveRegistryEvents, &key, &data);
        Ok(())
    }

    pub fn cognitive_registry_get_events_since(
        &self,
        from_height: u64,
        limit: usize,
    ) -> StorageResult<Vec<CognitiveRegistryEventV1>> {
        let start = cognitive_registry_event_storage_key(from_height, 0);
        let end = b"event;".to_vec();
        let mut out = Vec::new();
        for item in self.iter_range(ColumnFamily::CognitiveRegistryEvents, start, end)? {
            let (_k, v) = item?;
            let event: CognitiveRegistryEventV1 = serde_json::from_slice(&v)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            event.validate().map_err(StorageError::BackendError)?;
            if event.block_height < from_height {
                continue;
            }
            out.push(event);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn cognitive_registry_get_last_applied_height(&self) -> StorageResult<Option<u64>> {
        match self.get(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_applied_height_key(),
        )? {
            Some(v) => Ok(Some(decode_u64(&v)?)),
            None => Ok(None),
        }
    }

    pub fn cognitive_registry_set_last_applied_height(&self, height: u64) -> StorageResult<()> {
        self.put(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_applied_height_key(),
            &encode_u64(height),
        )
    }
    pub(crate) fn cognitive_registry_set_last_applied_height_in_batch(
        &self,
        batch: &mut FjallBatch,
        height: u64,
    ) -> StorageResult<()> {
        batch.put(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_applied_height_key(),
            &encode_u64(height),
        );
        Ok(())
    }

    pub fn cognitive_registry_get_last_event_seq(&self) -> StorageResult<Option<u64>> {
        match self.get(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_event_seq_key(),
        )? {
            Some(v) => Ok(Some(decode_u64(&v)?)),
            None => Ok(None),
        }
    }

    pub fn cognitive_registry_set_last_event_seq(&self, seq: u64) -> StorageResult<()> {
        self.put(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_event_seq_key(),
            &encode_u64(seq),
        )
    }
    pub(crate) fn cognitive_registry_set_last_event_seq_in_batch(
        &self,
        batch: &mut FjallBatch,
        seq: u64,
    ) -> StorageResult<()> {
        batch.put(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_event_seq_key(),
            &encode_u64(seq),
        );
        Ok(())
    }

    pub(crate) fn state_node_store(&self) -> StorageStateNodeStore {
        StorageStateNodeStore {
            db: self.db.clone(),
            inner: self.state_nodes_keyspace.clone(),
        }
    }

    #[doc(hidden)]
    pub fn meta_store(&self) -> RuntimeKeyspaceHandle {
        RuntimeKeyspaceHandle::from_fjall(self.db.clone(), self.meta_keyspace.clone())
    }

    #[doc(hidden)]
    pub fn finality_bft_last_vote_store(&self) -> RuntimeKeyspaceHandle {
        RuntimeKeyspaceHandle::from_fjall(
            self.db.clone(),
            self.finality_bft_last_vote_keyspace.clone(),
        )
    }

    #[doc(hidden)]
    pub fn finality_bft_meta_store(&self) -> RuntimeKeyspaceHandle {
        RuntimeKeyspaceHandle::from_fjall(self.db.clone(), self.finality_bft_meta_keyspace.clone())
    }

    #[doc(hidden)]
    pub fn finality_bft_qc_archive_store(&self) -> RuntimeKeyspaceHandle {
        RuntimeKeyspaceHandle::from_fjall(self.db.clone(), self.finality_bft_qc_keyspace.clone())
    }

    pub(crate) fn clear_state_nodes(&self) -> StorageResult<()> {
        let mut wb = FjallOwnedWriteBatch::with_capacity(self.db.clone(), 0);
        for guard in self.state_nodes_keyspace.iter() {
            let (k, _) = guard
                .into_inner()
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            wb.remove(&self.state_nodes_keyspace, k.as_ref());
        }
        wb.commit()
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        crate::state_smt::clear_global_node_cache();
        Ok(())
    }

    pub(crate) fn state_nodes_is_empty(&self) -> StorageResult<bool> {
        Ok(self.state_nodes_keyspace.iter().next().is_none())
    }

    fn clear_keyspace(&self, cf: ColumnFamily) -> StorageResult<()> {
        let keyspace = self.canonical_keyspace(cf);
        let mut batch = FjallOwnedWriteBatch::with_capacity(self.db.clone(), 0);
        for guard in keyspace.iter() {
            let (k, _) = guard
                .into_inner()
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            batch.remove(keyspace, k.as_ref());
        }
        batch
            .commit()
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        if matches!(cf, ColumnFamily::StateNodes) {
            crate::state_smt::clear_global_node_cache();
        }
        Ok(())
    }

    fn iter_all_cf<'a>(&'a self, cf: ColumnFamily) -> StorageResult<StorageKvIter<'a>> {
        self.scan_prefix(cf, Vec::new())
    }

    fn meta_get_u64_opt(&self, key: &str) -> StorageResult<Option<u64>> {
        match self.get(ColumnFamily::Meta, key.as_bytes())? {
            Some(v) => Ok(Some(decode_u64(&v)?)),
            None => Ok(None),
        }
    }

    fn meta_get_u32_opt(&self, key: &str) -> StorageResult<Option<u32>> {
        match self.get(ColumnFamily::Meta, key.as_bytes())? {
            Some(v) => Ok(Some(decode_u32(&v)?)),
            None => Ok(None),
        }
    }

    fn meta_get_string_opt(&self, key: &str) -> StorageResult<Option<String>> {
        match self.get(ColumnFamily::Meta, key.as_bytes())? {
            Some(v) => String::from_utf8(v)
                .map(Some)
                .map_err(|e| StorageError::BackendError(e.to_string())),
            None => Ok(None),
        }
    }

    fn meta_put_u64(&self, key: &str, v: u64) -> StorageResult<()> {
        self.put(ColumnFamily::Meta, key.as_bytes(), &encode_u64(v))
    }

    fn meta_put_u32(&self, key: &str, v: u32) -> StorageResult<()> {
        self.put(ColumnFamily::Meta, key.as_bytes(), &encode_u32(v))
    }

    fn meta_put_string(&self, key: &str, v: &str) -> StorageResult<()> {
        self.put(ColumnFamily::Meta, key.as_bytes(), v.as_bytes())
    }

    fn meta_remove(&self, key: &str) -> StorageResult<()> {
        self.delete(ColumnFamily::Meta, key.as_bytes())
    }

    fn runtime_schema_has_any_user_data(&self) -> StorageResult<bool> {
        for cf in ColumnFamily::ALL {
            if self.iter_all_cf(cf)?.next().transpose()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_runtime_schema_admission(&self) -> StorageResult<bool> {
        let current = crate::storage::current_runtime_storage_schema_version();
        match self.meta_get_u32_opt(META_DB_VERSION_KEY)? {
            Some(found) if found == current => Ok(false),
            Some(found) => Err(StorageError::BackendError(format!(
                "unsupported runtime db_version: found={} expected={}",
                found, current
            ))),
            None => {
                if self.runtime_schema_has_any_user_data()? {
                    Err(StorageError::BackendError(
                        "runtime db_version missing on non-empty Fjall backend; refusing fail-open admission"
                            .to_string(),
                    ))
                } else {
                    Ok(true)
                }
            }
        }
    }

    fn initialize_runtime_db_version_marker(&self) -> StorageResult<()> {
        let mut batch = self.batch();
        batch.put(
            ColumnFamily::Meta,
            META_DB_VERSION_KEY.as_bytes(),
            &encode_u32(crate::storage::current_runtime_storage_schema_version()),
        );
        self.write_batch_with_durability(batch, StorageDurability::SyncAll)
    }

    fn ensure_runtime_db_version_marker(&self) -> StorageResult<()> {
        let needs_init = self.validate_runtime_schema_admission()?;
        if needs_init {
            self.initialize_runtime_db_version_marker()?;
        }
        Ok(())
    }
}

impl KVStore for DbStore {
    type Batch = FjallBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        self.canonical_keyspace(cf)
            .get(key)
            .map(|opt| opt.map(|v| v.as_ref().to_vec()))
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> StorageResult<()> {
        self.canonical_keyspace(cf)
            .insert(key, value)
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    fn delete(&self, cf: ColumnFamily, key: &[u8]) -> StorageResult<()> {
        self.canonical_keyspace(cf)
            .remove(key)
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    fn batch(&self) -> Self::Batch {
        FjallBatch::new()
    }

    fn write_batch(&self, batch: Self::Batch) -> StorageResult<()> {
        self.write_batch_with_durability(batch, StorageDurability::Buffered)
    }

    fn write_batch_with_durability(
        &self,
        batch: Self::Batch,
        durability: StorageDurability,
    ) -> StorageResult<()> {
        let mut wb = FjallOwnedWriteBatch::with_capacity(self.db.clone(), batch.ops.len());
        for op in batch.ops {
            match op {
                DbOp::Put { cf, key, val } => wb.insert(self.canonical_keyspace(cf), key, val),
                DbOp::Del { cf, key } => wb.remove(self.canonical_keyspace(cf), key),
            }
        }
        // Single atomic commit across every touched keyspace.
        // Mainnet-grade durability: when SyncAll is requested, bind the durability mode
        // to the batch commit itself instead of doing a split-phase `commit` + `persist`.
        let wb = match durability {
            StorageDurability::Buffered => wb,
            StorageDurability::SyncAll => wb.durability(Some(FjallPersistMode::SyncAll)),
        };
        wb.commit()
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    fn flush_sync(&self) -> StorageResult<()> {
        self.db
            .persist(FjallPersistMode::SyncAll)
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    fn scan_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: Vec<u8>,
    ) -> StorageResult<StorageKvIter<'a>> {
        let it = self.canonical_keyspace(cf).prefix(prefix).map(|guard| {
            guard
                .into_inner()
                .map(|(k, v)| (k.as_ref().to_vec(), v.as_ref().to_vec()))
                .map_err(|e| StorageError::BackendError(e.to_string()))
        });
        Ok(Box::new(it))
    }

    fn iter_range<'a>(
        &'a self,
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    ) -> StorageResult<StorageKvIter<'a>> {
        let it = self.canonical_keyspace(cf).range(start..end).map(|guard| {
            guard
                .into_inner()
                .map(|(k, v)| (k.as_ref().to_vec(), v.as_ref().to_vec()))
                .map_err(|e| StorageError::BackendError(e.to_string()))
        });
        Ok(Box::new(it))
    }
}

impl ChainStorage for DbStore {
    fn get_height(&self) -> StorageResult<u64> {
        Ok(self
            .get(ColumnFamily::Meta, META_HEIGHT_KEY.as_bytes())?
            .map(|v| decode_u64(&v))
            .transpose()?
            .unwrap_or(0))
    }

    fn get_block(&self, index: u64) -> StorageResult<Option<Block>> {
        let key = block_key(index);
        match self.get(ColumnFamily::Blocks, key.as_bytes())? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| StorageError::BackendError(e.to_string())),
            None => Ok(None),
        }
    }

    fn get_blocks_range(&self, from: u64, limit: u32) -> StorageResult<Vec<Block>> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let max = from.saturating_add(limit as u64);
        let mut idx = from;
        while idx < max {
            match self.get_block(idx)? {
                Some(b) => out.push(b),
                None => break,
            }
            idx = idx.saturating_add(1);
        }
        Ok(out)
    }

    fn append_block(&self, block: &Block) -> StorageResult<()> {
        let n = db_flush_every_n_blocks();
        let do_flush = if n <= 1 {
            true
        } else {
            block.index.is_multiple_of(n)
        };
        self.append_block_inner(block, do_flush)
    }
}

impl DbStore {
    pub fn is_initialized(&self) -> StorageResult<bool> {
        Ok(self.meta_get_u64_opt(META_HEIGHT_KEY)?.is_some())
    }

    pub fn has_state_root_node(&self, state_root_hex: &str) -> StorageResult<bool> {
        let root = state_root_hex.trim();
        if root.is_empty() || root == "0" {
            return Ok(true);
        }
        let hash = crate::state_smt::bytes32_from_hex(root).map_err(StorageError::BackendError)?;
        if crate::state_smt::is_virtual_empty_hash(&hash) {
            return Ok(true);
        }
        Ok(self.get(ColumnFamily::StateNodes, &hash)?.is_some())
    }

    pub fn load_chain(&self) -> StorageResult<Vec<Block>> {
        let height = match self.meta_get_u64_opt(META_HEIGHT_KEY)? {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };
        let base_height = self.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
        if base_height > height {
            return Err(StorageError::BackendError(format!(
                "invalid meta: base_height={} > height={}",
                base_height, height
            )));
        }
        let mut out = Vec::new();
        for index in base_height..=height {
            let key = block_key(index);
            let bytes = self
                .get(ColumnFamily::Blocks, key.as_bytes())?
                .ok_or_else(|| {
                    StorageError::BackendError(format!("db corrupted: missing block idx={}", index))
                })?;
            let block: Block = serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            out.push(block);
        }
        Ok(out)
    }

    pub fn get_tx_by_hash(
        &self,
        hash: &str,
    ) -> StorageResult<Option<(u64, crate::transaction::Transaction)>> {
        let opt = self.get(ColumnFamily::TxIndex, hash.as_bytes())?;
        if let Some(bytes) = opt {
            let height = decode_u64(&bytes)?;
            if let Some(block) = self.get_block(height)? {
                if let Some(tx) = block.transactions.into_iter().find(|t| t.hash == hash) {
                    return Ok(Some((height, tx)));
                }
            }
        }
        Ok(None)
    }

    fn append_block_inner(&self, block: &Block, do_flush: bool) -> StorageResult<()> {
        let index = block.index;
        let key = block_key(index);
        let data =
            serde_json::to_vec(block).map_err(|e| StorageError::BackendError(e.to_string()))?;
        let mut batch = <Self as KVStore>::batch(self);
        let mut budget: usize = data.len().saturating_add(key.len());
        batch.put(ColumnFamily::Blocks, key.as_bytes(), &data);
        for tx in &block.transactions {
            if tx.is_coinbase || tx.hash.is_empty() {
                continue;
            }
            let k = tx.hash.as_bytes();
            let exists = self.get(ColumnFamily::TxIndex, k)?;
            if exists.is_none() {
                budget = budget.saturating_add(8).saturating_add(k.len());
                batch.put(ColumnFamily::TxIndex, k, &encode_u64(index));
            }
        }
        batch.put(
            ColumnFamily::Meta,
            META_HEIGHT_KEY.as_bytes(),
            &encode_u64(index),
        );
        batch.put(
            ColumnFamily::Meta,
            META_TIP_HASH_KEY.as_bytes(),
            block.hash.as_bytes(),
        );
        let tip_state_root = if block.state_root.is_empty() {
            "0"
        } else {
            block.state_root.as_str()
        };
        batch.put(
            ColumnFamily::Meta,
            META_TIP_STATE_ROOT_KEY.as_bytes(),
            tip_state_root.as_bytes(),
        );
        test_disk_full_consume(budget)?;
        let durability = if do_flush {
            StorageDurability::SyncAll
        } else {
            StorageDurability::Buffered
        };
        <Self as KVStore>::write_batch_with_durability(self, batch, durability)
    }

    pub fn flush_db(&self) -> StorageResult<()> {
        self.flush_sync()
    }

    pub fn append_blocks_batch(&self, blocks: &[Block], do_flush: bool) -> StorageResult<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        for b in blocks {
            self.append_block_inner(b, false)?;
        }
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn append_blocks_delta_checked_with_flush(
        &self,
        expected_db_tip: u64,
        blocks: &[Block],
        do_flush: bool,
    ) -> StorageResult<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let db_tip = self.get_height()?;
        let db_has_tip = self.get_block(db_tip)?.is_some();
        if !db_has_tip {
            return Err(StorageError::BackendError(
                "DB non inizializzato: richiede mirror completo".to_string(),
            ));
        }
        if db_tip != expected_db_tip {
            return Err(StorageError::BackendError(format!(
                "DB tip mismatch: db_tip={} expected={}",
                db_tip, expected_db_tip
            )));
        }
        let mut start = 0usize;
        while start < blocks.len() && blocks[start].index <= db_tip {
            let idx = blocks[start].index;
            let db_block = self.get_block(idx)?.ok_or_else(|| {
                StorageError::BackendError(format!("DB corrotto: manca block idx={}", idx))
            })?;
            if db_block.hash != blocks[start].hash {
                return Err(StorageError::BackendError(format!(
                    "DB divergenza su idx={}: db_hash={} incoming_hash={}",
                    idx, db_block.hash, blocks[start].hash
                )));
            }
            start += 1;
        }
        if start >= blocks.len() {
            return Ok(());
        }
        let tip_block = self
            .get_block(db_tip)?
            .ok_or_else(|| StorageError::BackendError("DB tip block missing".to_string()))?;
        let mut prev_index = db_tip;
        let mut prev_hash = tip_block.hash.clone();
        for (i, b) in blocks[start..].iter().enumerate() {
            let expected_index = prev_index.saturating_add(1);
            if b.index != expected_index {
                return Err(StorageError::BackendError(format!(
                    "Append delta non contiguo: blocks[{}].index={} atteso={}",
                    i + start,
                    b.index,
                    expected_index
                )));
            }
            if b.previous_hash != prev_hash {
                return Err(StorageError::BackendError(format!(
                    "Append delta previous_hash mismatch: idx={} prev_hash(atteso)={} prev_hash(blocco)={}",
                    b.index, &prev_hash, &b.previous_hash
                )));
            }
            self.append_block_inner(b, false)?;
            prev_index = b.index;
            prev_hash = b.hash.clone();
        }
        let last_idx = blocks.last().map(|b| b.index).unwrap_or(db_tip);
        let new_height = self.get_height()?;
        if new_height != last_idx {
            return Err(StorageError::BackendError(format!(
                "append delta post-check failed: meta height={} expected={}",
                new_height, last_idx
            )));
        }
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn append_blocks_delta_checked_with_state_nodes_atomic(
        &self,
        expected_db_tip: u64,
        blocks: &[Block],
        state_nodes: &[([u8; 32], Vec<u8>)],
        do_flush: bool,
    ) -> StorageResult<()> {
        self.append_blocks_delta_checked_with_state_nodes_and_economy_snapshot_atomic(
            expected_db_tip,
            blocks,
            state_nodes,
            None,
            do_flush,
        )
    }

    pub fn append_blocks_delta_checked_with_state_nodes_and_economy_snapshot_atomic(
        &self,
        expected_db_tip: u64,
        blocks: &[Block],
        state_nodes: &[([u8; 32], Vec<u8>)],
        economy_snapshot: Option<(u64, &str)>,
        do_flush: bool,
    ) -> StorageResult<()> {
        if blocks.is_empty() {
            if economy_snapshot.is_some() {
                return Err(StorageError::BackendError(
                    "economy snapshot atomic append requires a non-empty block batch".to_string(),
                ));
            }
            if !state_nodes.is_empty() {
                self.apply_state_nodes_batch(state_nodes, do_flush)?;
            }
            return Ok(());
        }
        let db_tip = self.get_height()?;
        let db_has_tip = self.get_block(db_tip)?.is_some();
        if !db_has_tip {
            return Err(StorageError::BackendError(
                "DB non inizializzato: richiede mirror completo".to_string(),
            ));
        }
        if db_tip != expected_db_tip {
            return Err(StorageError::BackendError(format!(
                "DB tip mismatch: db_tip={} expected={}",
                db_tip, expected_db_tip
            )));
        }
        let mut start = 0usize;
        while start < blocks.len() && blocks[start].index <= db_tip {
            let idx = blocks[start].index;
            let db_block = self.get_block(idx)?.ok_or_else(|| {
                StorageError::BackendError(format!("DB corrotto: manca block idx={}", idx))
            })?;
            if db_block.hash != blocks[start].hash {
                return Err(StorageError::BackendError(format!(
                    "DB divergenza su idx={}: db_hash={} incoming_hash={}",
                    idx, db_block.hash, blocks[start].hash
                )));
            }
            start += 1;
        }
        if start >= blocks.len() {
            if !state_nodes.is_empty() {
                self.apply_state_nodes_batch(state_nodes, do_flush)?;
            }
            if let Some((snap_height, snap_json)) = economy_snapshot {
                let last = blocks.last().ok_or_else(|| {
                    StorageError::BackendError(
                        "economy snapshot idempotent append requires a block batch".to_string(),
                    )
                })?;
                if snap_height != last.index {
                    return Err(StorageError::BackendError(format!(
                        "economy snapshot idempotent append height mismatch: snap={} last_block={}",
                        snap_height, last.index
                    )));
                }
                let db_tip_now = self.get_height()?;
                if db_tip_now != snap_height {
                    return Err(StorageError::BackendError(format!(
                        "economy snapshot idempotent append DB tip mismatch: db_tip={} snap={}",
                        db_tip_now, snap_height
                    )));
                }
                self.put_economy_snapshot(snap_height, snap_json, do_flush)?;
            }
            return Ok(());
        }
        let tip_block = self
            .get_block(db_tip)?
            .ok_or_else(|| StorageError::BackendError("DB tip block missing".to_string()))?;
        let mut prev_index = db_tip;
        let mut prev_hash = tip_block.hash.clone();
        let mut batch = <Self as KVStore>::batch(self);
        let mut budget = 0usize;
        let mut seen_tx: HashSet<Vec<u8>> = HashSet::new();
        for (i, b) in blocks[start..].iter().enumerate() {
            let expected_index = prev_index.saturating_add(1);
            if b.index != expected_index {
                return Err(StorageError::BackendError(format!(
                    "Append delta non contiguo: blocks[{}].index={} atteso={}",
                    i + start,
                    b.index,
                    expected_index
                )));
            }
            if b.previous_hash != prev_hash {
                return Err(StorageError::BackendError(format!(
                    "Append delta previous_hash mismatch: idx={} prev_hash(atteso)={} prev_hash(blocco)={}",
                    b.index, &prev_hash, &b.previous_hash
                )));
            }
            let key = block_key(b.index);
            let data =
                serde_json::to_vec(b).map_err(|e| StorageError::BackendError(e.to_string()))?;
            budget = budget.saturating_add(data.len()).saturating_add(key.len());
            batch.put(ColumnFamily::Blocks, key.as_bytes(), &data);
            for tx in &b.transactions {
                if tx.is_coinbase || tx.hash.is_empty() {
                    continue;
                }
                let k = tx.hash.as_bytes();
                if !seen_tx.insert(k.to_vec()) {
                    continue;
                }
                let exists = self.get(ColumnFamily::TxIndex, k)?;
                if exists.is_none() {
                    budget = budget.saturating_add(8).saturating_add(k.len());
                    batch.put(ColumnFamily::TxIndex, k, &encode_u64(b.index));
                }
            }
            prev_index = b.index;
            prev_hash = b.hash.clone();
        }
        for (k, v) in state_nodes {
            budget = budget.saturating_add(32).saturating_add(v.len());
            batch.put(ColumnFamily::StateNodes, &k[..], v.as_slice());
        }
        let last_new = blocks
            .last()
            .ok_or_else(|| StorageError::BackendError("empty blocks".to_string()))?;
        budget = budget
            .saturating_add(8)
            .saturating_add(META_HEIGHT_KEY.len());
        batch.put(
            ColumnFamily::Meta,
            META_HEIGHT_KEY.as_bytes(),
            &encode_u64(last_new.index),
        );
        budget = budget
            .saturating_add(last_new.hash.len())
            .saturating_add(META_TIP_HASH_KEY.len());
        batch.put(
            ColumnFamily::Meta,
            META_TIP_HASH_KEY.as_bytes(),
            last_new.hash.as_bytes(),
        );
        let tip_state_root = if last_new.state_root.is_empty() {
            "0"
        } else {
            last_new.state_root.as_str()
        };
        budget = budget
            .saturating_add(tip_state_root.len())
            .saturating_add(META_TIP_STATE_ROOT_KEY.len());
        batch.put(
            ColumnFamily::Meta,
            META_TIP_STATE_ROOT_KEY.as_bytes(),
            tip_state_root.as_bytes(),
        );
        if let Some((snap_height, snap_json)) = economy_snapshot {
            let snap: SnapshotEconomyStateV1 = serde_json::from_str(snap_json).map_err(|e| {
                StorageError::BackendError(format!(
                    "atomic append economy snapshot JSON invalid: {e}"
                ))
            })?;
            snap.validate_basic().map_err(|e| {
                StorageError::BackendError(format!("atomic append economy snapshot invalid: {e}"))
            })?;
            if snap_height != last_new.index || snap.height != last_new.index {
                return Err(StorageError::BackendError(format!(
                    "atomic append economy snapshot height mismatch: arg={} json={} tip={}",
                    snap_height, snap.height, last_new.index
                )));
            }
            let last_root = if last_new.state_root.trim().is_empty() {
                "0"
            } else {
                last_new.state_root.as_str()
            };
            if snap.block_hash != last_new.hash || snap.state_root != last_root {
                return Err(StorageError::BackendError(format!(
                    "atomic append economy snapshot tip binding mismatch block_match={} state_root_match={}",
                    snap.block_hash == last_new.hash,
                    snap.state_root == last_root
                )));
            }
            let historical_key = Self::economy_snapshot_by_height_key(snap_height);
            budget = budget
                .saturating_add(8)
                .saturating_add(META_ECONOMY_SNAPSHOT_HEIGHT_KEY.len())
                .saturating_add(snap_json.len())
                .saturating_add(META_ECONOMY_SNAPSHOT_JSON_KEY.len())
                .saturating_add(snap_json.len())
                .saturating_add(historical_key.len());
            batch.put(
                ColumnFamily::Meta,
                META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
                &encode_u64(snap_height),
            );
            batch.put(
                ColumnFamily::Meta,
                META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
                snap_json.as_bytes(),
            );
            batch.put(
                ColumnFamily::Meta,
                historical_key.as_bytes(),
                snap_json.as_bytes(),
            );
        }
        test_disk_full_consume(budget)?;
        let durability = if do_flush {
            StorageDurability::SyncAll
        } else {
            StorageDurability::Buffered
        };
        self.write_batch_with_durability(batch, durability)
    }

    pub fn append_blocks_delta_checked(
        &self,
        expected_db_tip: u64,
        blocks: &[Block],
    ) -> StorageResult<()> {
        self.append_blocks_delta_checked_with_flush(expected_db_tip, blocks, true)
    }

    pub fn insert_state_node(&self, hash: [u8; 32], data: &[u8]) -> StorageResult<()> {
        self.put(ColumnFamily::StateNodes, &hash[..], data)
    }

    pub fn apply_state_nodes_batch(
        &self,
        updates: &[([u8; 32], Vec<u8>)],
        do_flush: bool,
    ) -> StorageResult<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut batch = <Self as KVStore>::batch(self);
        let mut budget = 0usize;
        for (k, v) in updates {
            budget = budget.saturating_add(k.len()).saturating_add(v.len());
            batch.put(ColumnFamily::StateNodes, &k[..], v.as_slice());
        }
        test_disk_full_consume(budget)?;
        let durability = if do_flush {
            StorageDurability::SyncAll
        } else {
            StorageDurability::Buffered
        };
        self.write_batch_with_durability(batch, durability)
    }

    pub fn get_governance_bootstrap_json(&self) -> StorageResult<Option<String>> {
        self.meta_get_string_opt(META_GOV_BOOTSTRAP_JSON_KEY)
    }

    pub fn put_governance_bootstrap_json(&self, json: &str, do_flush: bool) -> StorageResult<()> {
        self.meta_put_string(META_GOV_BOOTSTRAP_JSON_KEY, json)?;
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn get_governance_snapshot(&self) -> StorageResult<Option<(u64, String)>> {
        let h = self.meta_get_u64_opt(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
        let js = self.meta_get_string_opt(META_GOV_SNAPSHOT_JSON_KEY)?;
        match (h, js) {
            (Some(h), Some(js)) => Ok(Some((h, js))),
            _ => Ok(None),
        }
    }

    pub fn put_governance_snapshot(
        &self,
        height: u64,
        json: &str,
        do_flush: bool,
    ) -> StorageResult<()> {
        let mut batch = self.batch();
        batch.put(
            ColumnFamily::Meta,
            META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes(),
            &encode_u64(height),
        );
        batch.put(
            ColumnFamily::Meta,
            META_GOV_SNAPSHOT_JSON_KEY.as_bytes(),
            json.as_bytes(),
        );
        self.write_batch_with_durability(
            batch,
            if do_flush {
                StorageDurability::SyncAll
            } else {
                StorageDurability::Buffered
            },
        )
    }

    fn economy_snapshot_by_height_key(height: u64) -> String {
        // Fixed-width decimal keeps lexicographic order stable for diagnostics and
        // avoids ambiguous key suffixes.  The value stores the canonical JSON sidecar.
        format!("{}{:020}", META_ECONOMY_SNAPSHOT_BY_HEIGHT_PREFIX, height)
    }

    pub fn get_economy_snapshot(&self) -> StorageResult<Option<(u64, String)>> {
        let h = self.meta_get_u64_opt(META_ECONOMY_SNAPSHOT_HEIGHT_KEY)?;
        let js = self.meta_get_string_opt(META_ECONOMY_SNAPSHOT_JSON_KEY)?;
        match (h, js) {
            (Some(h), Some(js)) => Ok(Some((h, js))),
            _ => Ok(None),
        }
    }

    fn get_economy_snapshot_at_height(&self, height: u64) -> StorageResult<Option<(u64, String)>> {
        let key = Self::economy_snapshot_by_height_key(height);
        let Some(js) = self.meta_get_string_opt(&key)? else {
            return Ok(None);
        };
        let snap: SnapshotEconomyStateV1 = serde_json::from_str(&js).map_err(|e| {
            StorageError::BackendError(format!(
                "indexed economy snapshot JSON invalid at height {height}: {e}"
            ))
        })?;
        snap.validate_basic().map_err(|e| {
            StorageError::BackendError(format!(
                "indexed economy snapshot invalid at height {height}: {e}"
            ))
        })?;
        if snap.height != height {
            return Err(StorageError::BackendError(format!(
                "indexed economy snapshot height mismatch key={} json={}",
                height, snap.height
            )));
        }
        Ok(Some((height, js)))
    }

    pub fn put_economy_snapshot(
        &self,
        height: u64,
        json: &str,
        do_flush: bool,
    ) -> StorageResult<()> {
        let snap: SnapshotEconomyStateV1 = serde_json::from_str(json).map_err(|e| {
            StorageError::BackendError(format!("economy snapshot JSON invalid: {e}"))
        })?;
        snap.validate_basic()
            .map_err(|e| StorageError::BackendError(format!("economy snapshot invalid: {e}")))?;
        if snap.height != height {
            return Err(StorageError::BackendError(format!(
                "economy snapshot height mismatch: arg={} json={}",
                height, snap.height
            )));
        }
        let mut batch = self.batch();
        batch.put(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
            &encode_u64(height),
        );
        batch.put(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
            json.as_bytes(),
        );
        let historical_key = Self::economy_snapshot_by_height_key(height);
        batch.put(
            ColumnFamily::Meta,
            historical_key.as_bytes(),
            json.as_bytes(),
        );
        self.write_batch_with_durability(
            batch,
            if do_flush {
                StorageDurability::SyncAll
            } else {
                StorageDurability::Buffered
            },
        )
    }

    pub fn clear_economy_snapshot(&self, do_flush: bool) -> StorageResult<()> {
        let historical_keys: Vec<Vec<u8>> = self
            .scan_prefix(
                ColumnFamily::Meta,
                META_ECONOMY_SNAPSHOT_BY_HEIGHT_PREFIX.as_bytes().to_vec(),
            )?
            .map(|entry| entry.map(|(k, _)| k))
            .collect::<StorageResult<Vec<_>>>()?;

        let mut batch = self.batch();
        batch.delete(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
        );
        batch.delete(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
        );
        for key in historical_keys {
            batch.delete(ColumnFamily::Meta, key.as_slice());
        }
        self.write_batch_with_durability(
            batch,
            if do_flush {
                StorageDurability::SyncAll
            } else {
                StorageDurability::Buffered
            },
        )
    }

    pub fn get_compute_order_state_store_v1(
        &self,
    ) -> StorageResult<Option<crate::compute_contract::ComputeOrderStateStoreV1>> {
        let h = self.meta_get_u64_opt(META_COMPUTE_ORDER_STATE_STORE_HEIGHT_KEY)?;
        let hash = self.meta_get_string_opt(META_COMPUTE_ORDER_STATE_STORE_HASH_KEY)?;
        let js = self.meta_get_string_opt(META_COMPUTE_ORDER_STATE_STORE_JSON_KEY)?;
        match (h, hash, js) {
            (None, None, None) => Ok(None),
            (Some(h), Some(hash), Some(js)) => {
                let store: crate::compute_contract::ComputeOrderStateStoreV1 =
                    serde_json::from_str(&js).map_err(|e| {
                        StorageError::BackendError(format!(
                            "compute order state store JSON invalid: {e}"
                        ))
                    })?;
                if store.last_applied_height != h {
                    return Err(StorageError::BackendError(format!(
                        "compute order state store height binding mismatch: meta={} json={}",
                        h, store.last_applied_height
                    )));
                }
                if store.last_applied_hash != hash {
                    return Err(StorageError::BackendError(format!(
                        "compute order state store hash binding mismatch: meta={} json={}",
                        hash, store.last_applied_hash
                    )));
                }
                Ok(Some(store))
            }
            _ => Err(StorageError::BackendError(
                "compute order state store metadata incomplete (height/hash/json must all be present)"
                    .to_string(),
            )),
        }
    }

    pub fn put_compute_order_state_store_v1(
        &self,
        store: &crate::compute_contract::ComputeOrderStateStoreV1,
        do_flush: bool,
    ) -> StorageResult<()> {
        if store.last_applied_hash.trim().is_empty() && store.last_applied_height > 0 {
            return Err(StorageError::BackendError(
                "compute order state store invalid: non-zero height with empty hash".to_string(),
            ));
        }
        let js = serde_json::to_string(store).map_err(|e| {
            StorageError::BackendError(format!("compute order state store JSON encode failed: {e}"))
        })?;
        let mut batch = self.batch();
        batch.put(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_HEIGHT_KEY.as_bytes(),
            &encode_u64(store.last_applied_height),
        );
        batch.put(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_HASH_KEY.as_bytes(),
            store.last_applied_hash.as_bytes(),
        );
        batch.put(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_JSON_KEY.as_bytes(),
            js.as_bytes(),
        );
        self.write_batch_with_durability(
            batch,
            if do_flush {
                StorageDurability::SyncAll
            } else {
                StorageDurability::Buffered
            },
        )
    }

    pub fn clear_compute_order_state_store_v1(&self, do_flush: bool) -> StorageResult<()> {
        let mut batch = self.batch();
        batch.delete(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_HEIGHT_KEY.as_bytes(),
        );
        batch.delete(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_HASH_KEY.as_bytes(),
        );
        batch.delete(
            ColumnFamily::Meta,
            META_COMPUTE_ORDER_STATE_STORE_JSON_KEY.as_bytes(),
        );
        self.write_batch_with_durability(
            batch,
            if do_flush {
                StorageDurability::SyncAll
            } else {
                StorageDurability::Buffered
            },
        )
    }

    pub fn advance_compute_order_state_store_with_blocks_v1(
        &self,
        blocks: &[Block],
        required_job_kind_activation_height: u64,
        do_flush: bool,
    ) -> StorageResult<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let mut store = match self.get_compute_order_state_store_v1()? {
            Some(store) => store,
            None => {
                if blocks.first().map(|b| b.index).unwrap_or(0) != 0 {
                    return Err(StorageError::BackendError(format!(
                        "compute order state store missing before non-genesis append:first_block={}",
                        blocks.first().map(|b| b.index).unwrap_or(0)
                    )));
                }
                crate::compute_contract::ComputeOrderStateStoreV1::default()
            }
        };
        for block in blocks {
            crate::compute_contract::compute_order_state_store_apply_block_v1(
                &mut store,
                block,
                required_job_kind_activation_height,
            )
            .map_err(StorageError::BackendError)?;
        }
        self.put_compute_order_state_store_v1(&store, do_flush)
    }

    pub fn get_snapshot_consensus_bootstrap_context(
        &self,
    ) -> StorageResult<Option<SnapshotConsensusBootstrapContext>> {
        let Some(js) = self.meta_get_string_opt(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)? else {
            return Ok(None);
        };
        let ctx = serde_json::from_str::<SnapshotConsensusBootstrapContext>(&js)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(Some(ctx))
    }

    pub fn put_snapshot_consensus_bootstrap_context(
        &self,
        ctx: &SnapshotConsensusBootstrapContext,
        do_flush: bool,
    ) -> StorageResult<()> {
        let js =
            serde_json::to_string(ctx).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.meta_put_string(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY, &js)?;
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn clear_snapshot_consensus_bootstrap_context(&self, do_flush: bool) -> StorageResult<()> {
        self.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn get_snapshot_reachable_state_import_marker(
        &self,
    ) -> StorageResult<Option<SnapshotReachableStateImportMarker>> {
        let Some(js) = self.meta_get_string_opt(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?
        else {
            return Ok(None);
        };
        let marker = serde_json::from_str::<SnapshotReachableStateImportMarker>(&js)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(Some(marker))
    }

    pub fn put_snapshot_reachable_state_import_marker(
        &self,
        marker: &SnapshotReachableStateImportMarker,
        do_flush: bool,
    ) -> StorageResult<()> {
        let js =
            serde_json::to_string(marker).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.meta_put_string(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY, &js)?;
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn clear_snapshot_reachable_state_import_marker(
        &self,
        do_flush: bool,
    ) -> StorageResult<()> {
        self.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
        if do_flush {
            self.flush_db()?;
        }
        Ok(())
    }

    pub fn validate_reachable_state_root_closure(
        &self,
        state_root_hex: &str,
        max_nodes: u64,
    ) -> StorageResult<u64> {
        let reachable = self.collect_reachable_state_nodes(state_root_hex, max_nodes)?;
        Ok(reachable.len() as u64)
    }

    #[doc(hidden)]
    pub fn overwrite_tip_metadata_for_repair_testing(
        &self,
        height: u64,
        tip_hash: &str,
        tip_state_root: &str,
    ) -> StorageResult<()> {
        self.meta_put_u64(META_HEIGHT_KEY, height)?;
        self.meta_put_string(META_TIP_HASH_KEY, tip_hash)?;
        self.meta_put_string(META_TIP_STATE_ROOT_KEY, tip_state_root)?;
        Ok(())
    }

    fn invalidate_governance_snapshot_if_outside_window(
        &self,
        base_height: u64,
        tip_height: Option<u64>,
    ) -> StorageResult<()> {
        let Some(tip_height) = tip_height else {
            self.meta_remove(META_GOV_SNAPSHOT_JSON_KEY)?;
            self.meta_remove(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
            return Ok(());
        };

        let raw_h = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes())?;
        let raw_js = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_JSON_KEY.as_bytes())?;
        let keep = match (raw_h, raw_js) {
            (Some(hb), Some(jsb)) => match (decode_u64(&hb), String::from_utf8(jsb.to_vec())) {
                (Ok(snap_h), Ok(js)) => {
                    serde_json::from_str::<GovernanceState>(&js).is_ok()
                        && (base_height == 0 || snap_h >= base_height)
                        && snap_h <= tip_height
                }
                _ => false,
            },
            _ => false,
        };
        if !keep {
            self.meta_remove(META_GOV_SNAPSHOT_JSON_KEY)?;
            self.meta_remove(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
        }
        Ok(())
    }

    fn journal_begin(&self, op: &str, note: &str) -> StorageResult<()> {
        let marker = JournalMarker {
            op: op.to_string(),
            ts: Self::now_unix_ts(),
            note: note.to_string(),
        };
        let bytes =
            serde_json::to_vec(&marker).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.put(
            ColumnFamily::Meta,
            META_JOURNAL_PENDING_KEY.as_bytes(),
            &bytes,
        )?;
        self.flush_db()?;
        Ok(())
    }

    fn journal_clear(&self) -> StorageResult<()> {
        self.meta_remove(META_JOURNAL_PENDING_KEY)?;
        self.flush_db()?;
        Ok(())
    }

    fn journal_marker(&self) -> StorageResult<Option<JournalMarker>> {
        let Some(bytes) = self.get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())? else {
            return Ok(None);
        };
        let marker = serde_json::from_slice::<JournalMarker>(&bytes)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(Some(marker))
    }

    fn now_unix_ts() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn verify_governance_cache_best_effort(
        &self,
        height: u64,
        base_height: u64,
        issues: &mut Vec<String>,
    ) -> StorageResult<()> {
        if let Some(raw) = self.get(ColumnFamily::Meta, META_GOV_BOOTSTRAP_JSON_KEY.as_bytes())? {
            match String::from_utf8(raw.to_vec()) {
                Ok(js) => {
                    if let Err(e) = serde_json::from_str::<GovernanceState>(&js) {
                        issues.push(format!("governance bootstrap JSON decode failed: {}", e));
                    }
                }
                Err(e) => issues.push(format!("governance bootstrap meta invalid UTF-8: {}", e)),
            }
        }

        let snap_h_raw = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes())?;
        let snap_js_raw = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_JSON_KEY.as_bytes())?;
        match (snap_h_raw, snap_js_raw) {
            (None, None) => {
                if base_height > 0 {
                    issues.push(format!(
                        "governance snapshot missing for pruned db (base_height={})",
                        base_height
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => issues.push(
                "governance snapshot metadata incomplete (height/json must both be present)"
                    .to_string(),
            ),
            (Some(hb), Some(jsb)) => match decode_u64(&hb) {
                Ok(snap_h) => {
                    if snap_h > height {
                        issues.push(format!(
                            "governance snapshot height {} > tip {}",
                            snap_h, height
                        ));
                    }
                    if snap_h < base_height {
                        issues.push(format!(
                            "governance snapshot height {} < base_height {}",
                            snap_h, base_height
                        ));
                    }
                    match String::from_utf8(jsb.to_vec()) {
                        Ok(js) => {
                            if let Err(e) = serde_json::from_str::<GovernanceState>(&js) {
                                issues
                                    .push(format!("governance snapshot JSON decode failed: {}", e));
                            }
                        }
                        Err(e) => {
                            issues.push(format!("governance snapshot JSON invalid UTF-8: {}", e))
                        }
                    }
                }
                Err(e) => issues.push(format!("governance snapshot height decode failed: {}", e)),
            },
        }
        Ok(())
    }

    fn verify_economy_cache_best_effort(
        &self,
        height: u64,
        base_height: u64,
        issues: &mut Vec<String>,
    ) -> StorageResult<()> {
        let snap_h_raw = self.get(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
        )?;
        let snap_js_raw = self.get(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
        )?;
        let economy_sidecar_required =
            base_height > 0 || crate::runtime_mode::public_mode_enabled();
        let require_economy_state_accounts = crate::runtime_mode::public_mode_enabled();
        match (snap_h_raw, snap_js_raw) {
            (None, None) => {
                if economy_sidecar_required {
                    issues.push(format!(
                        "economy snapshot missing for strict db boot (base_height={} public_mode={})",
                        base_height,
                        crate::runtime_mode::public_mode_enabled()
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => issues.push(
                "economy snapshot metadata incomplete (height/json must both be present)"
                    .to_string(),
            ),
            (Some(hb), Some(jsb)) => match decode_u64(&hb) {
                Ok(snap_h) => {
                    if snap_h != height {
                        issues.push(format!(
                            "economy snapshot height {} != tip {}",
                            snap_h, height
                        ));
                    }
                    match String::from_utf8(jsb.to_vec()) {
                        Ok(js) => match serde_json::from_str::<SnapshotEconomyStateV1>(&js) {
                            Ok(snap) => {
                                if let Err(e) = snap.validate_basic() {
                                    issues.push(format!("economy snapshot invalid: {}", e));
                                }
                                if snap.height != snap_h {
                                    issues.push(format!(
                                        "economy snapshot JSON height {} != meta height {}",
                                        snap.height, snap_h
                                    ));
                                }
                                if snap.base_height != base_height {
                                    issues.push(format!(
                                        "economy snapshot base_height {} != db base_height {}",
                                        snap.base_height, base_height
                                    ));
                                }
                                if let Some(tip) = self.get_block(height)? {
                                    let tip_root = if tip.state_root.trim().is_empty() {
                                        "0"
                                    } else {
                                        tip.state_root.as_str()
                                    };
                                    if snap.block_hash != tip.hash {
                                        issues.push(
                                            "economy snapshot block_hash is not bound to tip"
                                                .to_string(),
                                        );
                                    }
                                    if snap.state_root != tip_root {
                                        issues.push(
                                            "economy snapshot state_root is not bound to tip"
                                                .to_string(),
                                        );
                                    }
                                }
                                if let Err(e) = self
                                    .verify_snapshot_economy_state_against_tip_state_v1(
                                        &snap,
                                        require_economy_state_accounts,
                                    )
                                {
                                    issues.push(format!(
                                        "economy snapshot SMT binding invalid: {}",
                                        e
                                    ));
                                }
                            }
                            Err(e) => {
                                issues.push(format!("economy snapshot JSON decode failed: {}", e))
                            }
                        },
                        Err(e) => {
                            issues.push(format!("economy snapshot JSON invalid UTF-8: {}", e))
                        }
                    }
                }
                Err(e) => issues.push(format!("economy snapshot height decode failed: {}", e)),
            },
        }
        Ok(())
    }

    fn verify_finality_last_vote_store_best_effort(
        &self,
        full: bool,
        issues: &mut Vec<String>,
    ) -> StorageResult<bool> {
        let mut had_issue = false;
        let limit = if full {
            VERIFY_AUX_SCAN_LIMIT_FULL
        } else {
            VERIFY_AUX_SCAN_LIMIT_QUICK
        };
        let chain_id = crate::chain_identity::chain_id();
        for item in self
            .iter_all_cf(ColumnFamily::FinalityBftLastVote)?
            .take(limit)
        {
            let (key, value) = item?;
            let key_str = match std::str::from_utf8(key.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    issues.push(format!("finality_last_vote key invalid UTF-8: {}", e));
                    had_issue = true;
                    continue;
                }
            };
            let mut parts = key_str.split(':');
            let (Some(prefix), Some(height_s), Some(round_s), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                issues.push(format!("finality_last_vote key malformed: {}", key_str));
                had_issue = true;
                continue;
            };
            if prefix != "fv" {
                issues.push(format!(
                    "finality_last_vote key prefix invalid: {}",
                    key_str
                ));
                had_issue = true;
                continue;
            }
            let key_height = match height_s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "finality_last_vote key height decode failed for {}: {}",
                        key_str, e
                    ));
                    had_issue = true;
                    continue;
                }
            };
            let key_round = match round_s.parse::<u32>() {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "finality_last_vote key round decode failed for {}: {}",
                        key_str, e
                    ));
                    had_issue = true;
                    continue;
                }
            };
            let vote: FinalityBftVoteV1 = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "finality_last_vote value decode failed for {}: {}",
                        key_str, e
                    ));
                    had_issue = true;
                    continue;
                }
            };
            if vote.height != key_height || vote.round != key_round {
                issues.push(format!(
                    "finality_last_vote key/value mismatch key={} vote_height={} vote_round={}",
                    key_str, vote.height, vote.round
                ));
                had_issue = true;
            }
            if let Err(e) = finality_bft::verify_vote_sig_v1(&vote, chain_id) {
                issues.push(format!(
                    "finality_last_vote signature invalid for {}: {}",
                    key_str, e
                ));
                had_issue = true;
            }
        }
        Ok(had_issue)
    }

    fn verify_finality_meta_and_qc_archive_best_effort(
        &self,
        height: u64,
        base_height: u64,
        full: bool,
        issues: &mut Vec<String>,
    ) -> StorageResult<()> {
        if let Some(v) = self.get(
            ColumnFamily::FinalityBftMeta,
            FINALITY_BFT_META_DB_KEY.as_bytes(),
        )? {
            match serde_json::from_slice::<PersistedFinalityBftMetaV1>(&v) {
                Ok(meta) => {
                    if meta.finalized_height > height {
                        issues.push(format!(
                            "finality_meta finalized_height={} exceeds tip={}",
                            meta.finalized_height, height
                        ));
                    }
                    if meta.highest_qc_height > height {
                        issues.push(format!(
                            "finality_meta highest_qc_height={} exceeds tip={}",
                            meta.highest_qc_height, height
                        ));
                    }
                    if meta.finalized_height > meta.highest_qc_height {
                        issues.push(format!(
                            "finality_meta finalized_height={} exceeds highest_qc_height={}",
                            meta.finalized_height, meta.highest_qc_height
                        ));
                    }
                    if meta.finalized_height > 0 {
                        if meta.finalized_hash.is_empty() {
                            issues.push(format!(
                                "finality_meta finalized_hash missing at height {}",
                                meta.finalized_height
                            ));
                        } else if let Some(block) = self.get_block(meta.finalized_height)? {
                            if block.hash != meta.finalized_hash {
                                issues.push(format!(
                                    "finality_meta finalized_hash mismatch at height {}",
                                    meta.finalized_height
                                ));
                            }
                        } else if meta.finalized_height >= base_height {
                            issues.push(format!(
                                "finality_meta finalized_height {} missing from retained chain window",
                                meta.finalized_height
                            ));
                        }
                    }
                    if meta.highest_qc_height > 0 {
                        if meta.highest_qc_block_hash.is_empty() {
                            issues.push(format!(
                                "finality_meta highest_qc_block_hash missing at height {}",
                                meta.highest_qc_height
                            ));
                        } else if let Some(block) = self.get_block(meta.highest_qc_height)? {
                            if block.hash != meta.highest_qc_block_hash {
                                issues.push(format!(
                                    "finality_meta highest_qc_block_hash mismatch at height {}",
                                    meta.highest_qc_height
                                ));
                            }
                        } else if meta.highest_qc_height >= base_height {
                            issues.push(format!(
                                "finality_meta highest_qc_height {} missing from retained chain window",
                                meta.highest_qc_height
                            ));
                        }
                    }
                }
                Err(e) => issues.push(format!("finality_meta decode failed: {}", e)),
            }
        }

        let limit = if full {
            VERIFY_AUX_SCAN_LIMIT_FULL
        } else {
            VERIFY_AUX_SCAN_LIMIT_QUICK
        };
        let chain_id = crate::chain_identity::chain_id();
        for item in self
            .iter_all_cf(ColumnFamily::FinalityBftQcArchive)?
            .take(limit)
        {
            let (key, value) = item?;
            let key_str = match std::str::from_utf8(key.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    issues.push(format!("finality_qc_archive key invalid UTF-8: {}", e));
                    continue;
                }
            };
            let Some(rest) = key_str.strip_prefix("qc:") else {
                issues.push(format!("finality_qc_archive key malformed: {}", key_str));
                continue;
            };
            let Some((height_hex, key_hash)) = rest.split_once(':') else {
                issues.push(format!("finality_qc_archive key malformed: {}", key_str));
                continue;
            };
            let key_height = match u64::from_str_radix(height_hex, 16) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "finality_qc_archive key height decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            if let Err(e) = validate_sha256_hex_field("finality_qc_archive.key_hash", key_hash) {
                issues.push(format!(
                    "finality_qc_archive key hash invalid for {}: {}",
                    key_str, e
                ));
                continue;
            }
            let qc: FinalityBftCertV1 = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "finality_qc_archive value decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            if let Err(e) = finality_bft::qc_digest32_v1(chain_id, &qc) {
                issues.push(format!(
                    "finality_qc_archive structural validation failed for {}: {}",
                    key_str, e
                ));
            }
            if qc.height != key_height {
                issues.push(format!(
                    "finality_qc_archive key/value height mismatch key={} qc_height={}",
                    key_str, qc.height
                ));
            }
            if qc.block_hash != key_hash {
                issues.push(format!(
                    "finality_qc_archive key/value hash mismatch key={} qc_hash={}",
                    key_str, qc.block_hash
                ));
            }
            if qc.height > height {
                issues.push(format!(
                    "finality_qc_archive qc_height={} exceeds tip={}",
                    qc.height, height
                ));
            } else if qc.height >= base_height {
                match self.get_block(qc.height)? {
                    Some(block) => {
                        if block.hash != qc.block_hash {
                            issues.push(format!(
                                "finality_qc_archive block hash mismatch at height {}",
                                qc.height
                            ));
                        }
                    }
                    None => issues.push(format!(
                        "finality_qc_archive references missing retained block at height {}",
                        qc.height
                    )),
                }
            }
        }
        Ok(())
    }

    fn verify_cognitive_registry_best_effort(
        &self,
        height: u64,
        base_height: u64,
        full: bool,
        issues: &mut Vec<String>,
    ) -> StorageResult<()> {
        let limit = if full {
            VERIFY_AUX_SCAN_LIMIT_FULL
        } else {
            VERIFY_AUX_SCAN_LIMIT_QUICK
        };
        let mut entry_claims: HashMap<String, String> = HashMap::new();
        let mut entry_links: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
        let mut claim_index_rows: HashMap<String, Vec<String>> = HashMap::new();
        let mut max_event_seq: Option<u64> = None;
        let mut max_event_height: Option<u64> = None;

        for item in self
            .iter_all_cf(ColumnFamily::CognitiveRegistryEntries)?
            .take(limit)
        {
            let (key, value) = item?;
            let key_str = match std::str::from_utf8(key.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    issues.push(format!("cognitive_registry entry key invalid UTF-8: {}", e));
                    continue;
                }
            };
            let Some(object_hash) = key_str.strip_prefix(COGNITIVE_REGISTRY_ENTRY_KEY_PREFIX)
            else {
                issues.push(format!(
                    "cognitive_registry entry key malformed: {}",
                    key_str
                ));
                continue;
            };
            if let Err(e) = validate_sha256_hex_field("object_hash_hex", object_hash) {
                issues.push(format!(
                    "cognitive_registry entry key invalid {}: {}",
                    key_str, e
                ));
                continue;
            }
            let entry: CognitiveRegistryEntryV1 = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry entry decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            if let Err(e) = entry.validate() {
                issues.push(format!(
                    "cognitive_registry entry validation failed for {}: {}",
                    key_str, e
                ));
                continue;
            }
            if entry.object_hash_hex != object_hash {
                issues.push(format!(
                    "cognitive_registry entry key/value mismatch key={} entry_object={}",
                    key_str, entry.object_hash_hex
                ));
            }
            if entry.anchor_height > height {
                issues.push(format!(
                    "cognitive_registry entry anchor_height={} exceeds tip={}",
                    entry.anchor_height, height
                ));
            }
            if entry.updated_at_height > height {
                issues.push(format!(
                    "cognitive_registry entry updated_at_height={} exceeds tip={}",
                    entry.updated_at_height, height
                ));
            }
            if entry.updated_at_height < entry.anchor_height {
                issues.push(format!(
                    "cognitive_registry entry updated_at_height {} < anchor_height {} for {}",
                    entry.updated_at_height, entry.anchor_height, entry.object_hash_hex
                ));
            }
            if entry.anchor_height >= base_height {
                match self.get_block(entry.anchor_height)? {
                    Some(block) => {
                        if block.hash != entry.anchor_block_hash {
                            issues.push(format!(
                                "cognitive_registry entry anchor block hash mismatch at height {} for {}",
                                entry.anchor_height, entry.object_hash_hex
                            ));
                        }
                    }
                    None => issues.push(format!(
                        "cognitive_registry entry anchor block missing at retained height {} for {}",
                        entry.anchor_height, entry.object_hash_hex
                    )),
                }
            }
            if full {
                entry_links.insert(
                    entry.object_hash_hex.clone(),
                    (entry.supersedes.clone(), entry.superseded_by.clone()),
                );
                entry_claims.insert(entry.object_hash_hex.clone(), entry.claim_hash_hex.clone());
            }
        }

        for item in self
            .iter_all_cf(ColumnFamily::CognitiveRegistryByClaim)?
            .take(limit)
        {
            let (key, value) = item?;
            let key_str = match std::str::from_utf8(key.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    issues.push(format!("cognitive_registry claim key invalid UTF-8: {}", e));
                    continue;
                }
            };
            let Some(claim_hash) = key_str.strip_prefix(COGNITIVE_REGISTRY_CLAIM_INDEX_KEY_PREFIX)
            else {
                issues.push(format!(
                    "cognitive_registry claim key malformed: {}",
                    key_str
                ));
                continue;
            };
            if let Err(e) = validate_sha256_hex_field("claim_hash_hex", claim_hash) {
                issues.push(format!(
                    "cognitive_registry claim key invalid {}: {}",
                    key_str, e
                ));
                continue;
            }
            let rows: Vec<String> = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry claim index decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            let mut normalized = rows.clone();
            let mut valid_rows = true;
            for object_hash in &normalized {
                if let Err(e) = validate_sha256_hex_field("object_hash_hex", object_hash) {
                    issues.push(format!(
                        "cognitive_registry claim index invalid object hash in {}: {}",
                        key_str, e
                    ));
                    valid_rows = false;
                    break;
                }
            }
            if !valid_rows {
                continue;
            }
            normalized.sort();
            normalized.dedup();
            if rows != normalized {
                issues.push(format!(
                    "cognitive_registry claim index {} is not normalized/deduplicated",
                    key_str
                ));
            }
            if full {
                for object_hash in &normalized {
                    match entry_claims.get(object_hash) {
                        Some(entry_claim) if entry_claim == claim_hash => {}
                        Some(entry_claim) => issues.push(format!(
                            "cognitive_registry claim index {} points to {} with mismatched claim {}",
                            key_str, object_hash, entry_claim
                        )),
                        None => issues.push(format!(
                            "cognitive_registry claim index {} points to missing entry {}",
                            key_str, object_hash
                        )),
                    }
                }
                claim_index_rows.insert(claim_hash.to_string(), normalized);
            }
        }

        for item in self
            .iter_all_cf(ColumnFamily::CognitiveRegistryEvents)?
            .take(limit)
        {
            let (key, value) = item?;
            let key_str = match std::str::from_utf8(key.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    issues.push(format!("cognitive_registry event key invalid UTF-8: {}", e));
                    continue;
                }
            };
            let Some(rest) = key_str.strip_prefix(COGNITIVE_REGISTRY_EVENT_KEY_PREFIX) else {
                issues.push(format!(
                    "cognitive_registry event key malformed: {}",
                    key_str
                ));
                continue;
            };
            let Some((height_s, seq_s)) = rest.split_once(':') else {
                issues.push(format!(
                    "cognitive_registry event key malformed: {}",
                    key_str
                ));
                continue;
            };
            let key_height = match height_s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry event height decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            let key_seq = match seq_s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry event seq decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            let event: CognitiveRegistryEventV1 = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry event decode failed for {}: {}",
                        key_str, e
                    ));
                    continue;
                }
            };
            if let Err(e) = event.validate() {
                issues.push(format!(
                    "cognitive_registry event validation failed for {}: {}",
                    key_str, e
                ));
                continue;
            }
            if event.block_height != key_height || event.event_seq != key_seq {
                issues.push(format!(
                    "cognitive_registry event key/value mismatch key={} event_height={} event_seq={}",
                    key_str, event.block_height, event.event_seq
                ));
            }
            if event.block_height > height {
                issues.push(format!(
                    "cognitive_registry event height {} exceeds tip {}",
                    event.block_height, height
                ));
            } else if event.block_height >= base_height {
                match self.get_block(event.block_height)? {
                    Some(block) => {
                        if block.hash != event.block_hash {
                            issues.push(format!(
                                "cognitive_registry event block hash mismatch at height {} seq {}",
                                event.block_height, event.event_seq
                            ));
                        }
                    }
                    None => issues.push(format!(
                        "cognitive_registry event references missing retained block at height {} seq {}",
                        event.block_height, event.event_seq
                    )),
                }
            }
            if full {
                match entry_claims.get(&event.object_hash_hex) {
                    Some(entry_claim) => {
                        if entry_claim != &event.claim_hash_hex {
                            issues.push(format!(
                                "cognitive_registry event claim mismatch for object {} seq {}",
                                event.object_hash_hex, event.event_seq
                            ));
                        }
                    }
                    None => issues.push(format!(
                        "cognitive_registry event references missing entry for object {} seq {}",
                        event.object_hash_hex, event.event_seq
                    )),
                }
                if let Some(related_object_hash) = event.related_object_hash_hex.as_ref() {
                    if !entry_claims.contains_key(related_object_hash) {
                        issues.push(format!(
                            "cognitive_registry event references missing related entry {} at seq {}",
                            related_object_hash, event.event_seq
                        ));
                    }
                }
            }
            max_event_seq =
                Some(max_event_seq.map_or(event.event_seq, |cur| cur.max(event.event_seq)));
            max_event_height = Some(
                max_event_height.map_or(event.block_height, |cur| cur.max(event.block_height)),
            );
        }

        let last_applied_raw = self.get(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_applied_height_key(),
        )?;
        let last_applied = match last_applied_raw {
            Some(v) => match decode_u64(&v) {
                Ok(h) => Some(h),
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry meta last_applied_height decode failed: {}",
                        e
                    ));
                    None
                }
            },
            None => None,
        };
        let last_event_seq_raw = self.get(
            ColumnFamily::CognitiveRegistryMeta,
            cognitive_registry_meta_last_event_seq_key(),
        )?;
        let last_event_seq = match last_event_seq_raw {
            Some(v) => match decode_u64(&v) {
                Ok(seq) => Some(seq),
                Err(e) => {
                    issues.push(format!(
                        "cognitive_registry meta last_event_seq decode failed: {}",
                        e
                    ));
                    None
                }
            },
            None => None,
        };

        if let Some(last_applied_h) = last_applied {
            if last_applied_h > height {
                issues.push(format!(
                    "cognitive_registry last_applied_height={} exceeds tip={}",
                    last_applied_h, height
                ));
            }
        }
        if full {
            match (max_event_seq, last_event_seq) {
                (Some(max_seq), Some(meta_seq)) if meta_seq != max_seq => issues.push(format!(
                    "cognitive_registry meta last_event_seq={} mismatches max event seq {}",
                    meta_seq, max_seq
                )),
                (Some(max_seq), None) => issues.push(format!(
                    "cognitive_registry meta last_event_seq missing (max event seq {})",
                    max_seq
                )),
                (None, Some(meta_seq)) => issues.push(format!(
                    "cognitive_registry meta last_event_seq={} present but no events exist",
                    meta_seq
                )),
                _ => {}
            }
            match (max_event_height, last_applied) {
                (Some(max_h), Some(applied)) if applied != max_h => issues.push(format!(
                    "cognitive_registry meta last_applied_height={} mismatches max event height {}",
                    applied, max_h
                )),
                (Some(max_h), None) => issues.push(format!(
                    "cognitive_registry meta last_applied_height missing (max event height {})",
                    max_h
                )),
                (None, Some(applied)) => issues.push(format!(
                    "cognitive_registry meta last_applied_height={} present but no events exist",
                    applied
                )),
                _ => {}
            }
            for (object_hash, claim_hash) in &entry_claims {
                match claim_index_rows.get(claim_hash) {
                    Some(rows) if rows.contains(object_hash) => {}
                    Some(_) => issues.push(format!(
                        "cognitive_registry entry {} missing from claim index {}",
                        object_hash, claim_hash
                    )),
                    None => issues.push(format!(
                        "cognitive_registry entry {} references missing claim index {}",
                        object_hash, claim_hash
                    )),
                }
            }
            for (object_hash, (supersedes, superseded_by)) in &entry_links {
                if let Some(old_object) = supersedes {
                    match entry_links.get(old_object) {
                        Some((_, old_superseded_by)) => {
                            if old_superseded_by.as_deref() != Some(object_hash.as_str()) {
                                issues.push(format!(
                                    "cognitive_registry supersedes backlink mismatch: {} -> {}",
                                    object_hash, old_object
                                ));
                            }
                        }
                        None => issues.push(format!(
                            "cognitive_registry entry {} supersedes missing object {}",
                            object_hash, old_object
                        )),
                    }
                }
                if let Some(new_object) = superseded_by {
                    match entry_links.get(new_object) {
                        Some((new_supersedes, _)) => {
                            if new_supersedes.as_deref() != Some(object_hash.as_str()) {
                                issues.push(format!(
                                    "cognitive_registry superseded_by backlink mismatch: {} <- {}",
                                    object_hash, new_object
                                ));
                            }
                        }
                        None => issues.push(format!(
                            "cognitive_registry entry {} superseded_by missing object {}",
                            object_hash, new_object
                        )),
                    }
                }
            }
        }

        Ok(())
    }

    fn governance_snapshot_anchor_valid_for_window(
        &self,
        base_height: u64,
        tip_height: u64,
    ) -> StorageResult<bool> {
        if base_height == 0 {
            return Ok(true);
        }
        let raw_h = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes())?;
        let raw_js = self.get(ColumnFamily::Meta, META_GOV_SNAPSHOT_JSON_KEY.as_bytes())?;
        let (Some(hb), Some(jsb)) = (raw_h, raw_js) else {
            return Ok(false);
        };
        let snap_h = match decode_u64(&hb) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let js = match String::from_utf8(jsb.to_vec()) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if serde_json::from_str::<GovernanceState>(&js).is_err() {
            return Ok(false);
        }
        Ok(snap_h >= base_height && snap_h <= tip_height)
    }

    fn economy_snapshot_anchor_valid_for_window(
        &self,
        base_height: u64,
        tip_height: u64,
    ) -> StorageResult<bool> {
        if base_height == 0 && !crate::runtime_mode::public_mode_enabled() {
            return Ok(true);
        }
        let raw_h = self.get(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
        )?;
        let raw_js = self.get(
            ColumnFamily::Meta,
            META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
        )?;
        let (Some(hb), Some(jsb)) = (raw_h, raw_js) else {
            return Ok(false);
        };
        let snap_h = match decode_u64(&hb) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if snap_h != tip_height {
            return Ok(false);
        }
        let js = match String::from_utf8(jsb.to_vec()) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let snap = match serde_json::from_str::<SnapshotEconomyStateV1>(&js) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if snap.validate_basic().is_err() {
            return Ok(false);
        }
        if snap.height != tip_height || snap.base_height != base_height {
            return Ok(false);
        }
        let Some(tip) = self.get_block(tip_height)? else {
            return Ok(false);
        };
        let tip_root = if tip.state_root.trim().is_empty() {
            "0"
        } else {
            tip.state_root.as_str()
        };
        if snap.block_hash != tip.hash || snap.state_root != tip_root {
            return Ok(false);
        }
        let require_state_accounts = crate::runtime_mode::public_mode_enabled();
        match self.verify_snapshot_economy_state_against_tip_state_v1(&snap, require_state_accounts)
        {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn invalidate_governance_bootstrap_if_corrupt(&self) -> StorageResult<()> {
        if let Some(raw) = self.get(ColumnFamily::Meta, META_GOV_BOOTSTRAP_JSON_KEY.as_bytes())? {
            let valid = String::from_utf8(raw.to_vec())
                .ok()
                .and_then(|js| serde_json::from_str::<GovernanceState>(&js).ok())
                .is_some();
            if !valid {
                self.meta_remove(META_GOV_BOOTSTRAP_JSON_KEY)?;
            }
        }
        Ok(())
    }

    pub fn verify_db(&self, full: bool) -> StorageResult<VerifyReport> {
        let mut issues = Vec::new();
        let journal_pending = self
            .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())?
            .is_some();
        if journal_pending {
            issues.push("journal_pending: previous operation did not complete cleanly".to_string());
        }
        let height_opt = self.meta_get_u64_opt(META_HEIGHT_KEY)?;
        if height_opt.is_none() {
            let has_any = self
                .iter_all_cf(ColumnFamily::Blocks)?
                .next()
                .transpose()?
                .is_some();
            if has_any {
                issues.push("blocks exist but meta height missing".to_string());
            }
            self.verify_governance_cache_best_effort(0, 0, &mut issues)?;
            self.verify_economy_cache_best_effort(0, 0, &mut issues)?;
            self.verify_finality_last_vote_store_best_effort(full, &mut issues)?;
            self.verify_finality_meta_and_qc_archive_best_effort(0, 0, full, &mut issues)?;
            self.verify_cognitive_registry_best_effort(0, 0, full, &mut issues)?;
            let needs_recovery = journal_pending || !issues.is_empty();
            return Ok(VerifyReport {
                ok: issues.is_empty() && !needs_recovery,
                height: None,
                issues,
                needs_recovery,
            });
        }
        let height = height_opt.unwrap();
        let base_height = self.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
        if base_height > height {
            issues.push(format!(
                "invalid meta: base_height={} > height={}",
                base_height, height
            ));
        }
        let window: u64 = 2048;
        let quick_window_span = window.saturating_sub(1);
        let start = if full {
            base_height
        } else {
            base_height.max(height.saturating_sub(quick_window_span))
        };

        let mut prev_hash: Option<String> = None;
        if start > base_height {
            match self.get_block(start - 1)? {
                Some(prev) => prev_hash = Some(prev.hash),
                None => issues.push(format!(
                    "missing block {} needed for quick-verify boundary",
                    start - 1
                )),
            }
        }

        for idx in start..=height {
            let Some(b) = self.get_block(idx)? else {
                issues.push(format!("missing block {}", idx));
                break;
            };
            if b.index != idx {
                issues.push(format!("block index mismatch at {} -> {}", idx, b.index));
            }
            if b.try_calculate_hash().map_or(true, |h| b.hash != h) {
                issues.push(format!("block hash mismatch at {}", idx));
            }
            if let Some(ph) = prev_hash.as_ref() {
                if &b.previous_hash != ph {
                    issues.push(format!("previous_hash mismatch at {}", idx));
                }
            }
            prev_hash = Some(b.hash.clone());
            if full {
                for tx in &b.transactions {
                    if tx.is_coinbase || tx.hash.is_empty() {
                        continue;
                    }
                    match self.get(ColumnFamily::TxIndex, tx.hash.as_bytes())? {
                        Some(v) => {
                            let stored_h = decode_u64(&v)?;
                            if stored_h != idx {
                                issues.push(format!(
                                    "tx_index mismatch {} -> {} expected {}",
                                    tx.hash, stored_h, idx
                                ));
                            }
                        }
                        None => issues.push(format!("missing tx_index for {}", tx.hash)),
                    }
                }
            }
        }
        if let Some(tip) = self.get_block(height)? {
            if let Some(meta_tip_hash) = self.meta_get_string_opt(META_TIP_HASH_KEY)? {
                if meta_tip_hash != tip.hash {
                    issues.push(format!(
                        "tip_hash mismatch: meta={} db={}",
                        meta_tip_hash, tip.hash
                    ));
                }
            } else {
                issues.push("meta tip_hash missing".to_string());
            }
            let expected_sr = if tip.state_root.is_empty() {
                "0".to_string()
            } else {
                tip.state_root.clone()
            };
            if let Some(meta_sr) = self.meta_get_string_opt(META_TIP_STATE_ROOT_KEY)? {
                if meta_sr != expected_sr {
                    issues.push(format!(
                        "tip_state_root mismatch: meta={} db={}",
                        meta_sr, expected_sr
                    ));
                }
            } else {
                issues.push("meta tip_state_root missing".to_string());
            }
        }
        if self.meta_get_u32_opt(META_DB_VERSION_KEY)?.is_none() {
            issues.push("db_version missing".to_string());
        }
        self.verify_governance_cache_best_effort(height, base_height, &mut issues)?;
        self.verify_economy_cache_best_effort(height, base_height, &mut issues)?;
        self.verify_finality_last_vote_store_best_effort(full, &mut issues)?;
        self.verify_finality_meta_and_qc_archive_best_effort(
            height,
            base_height,
            full,
            &mut issues,
        )?;
        self.verify_cognitive_registry_best_effort(height, base_height, full, &mut issues)?;
        let needs_recovery = journal_pending || !issues.is_empty();
        Ok(VerifyReport {
            ok: issues.is_empty() && !needs_recovery,
            height: Some(height),
            issues,
            needs_recovery,
        })
    }

    fn collect_full_rebuildable_auxiliary_issues(
        &self,
        height: u64,
        base_height: u64,
    ) -> StorageResult<Vec<String>> {
        let mut issues = Vec::new();
        self.verify_governance_cache_best_effort(height, base_height, &mut issues)?;
        self.verify_economy_cache_best_effort(height, base_height, &mut issues)?;
        self.verify_finality_meta_and_qc_archive_best_effort(
            height,
            base_height,
            true,
            &mut issues,
        )?;
        self.verify_cognitive_registry_best_effort(height, base_height, true, &mut issues)?;
        Ok(issues)
    }

    pub fn repair_db(&self, full_verify_after: bool) -> StorageResult<VerifyReport> {
        let mut unrecoverable_last_vote_issues = Vec::new();
        if self.verify_finality_last_vote_store_best_effort(
            true,
            &mut unrecoverable_last_vote_issues,
        )? {
            return Err(StorageError::BackendError(format!(
                "repair refused: finality last-vote store is corrupted and cannot be deterministically rebuilt without weakening anti-equivocation safety: {}",
                unrecoverable_last_vote_issues.join("; ")
            )));
        }

        let mut preflight = self.verify_db(false)?;
        if preflight.ok && !preflight.needs_recovery {
            let aux_height = self.meta_get_u64_opt(META_HEIGHT_KEY)?.unwrap_or(0);
            let aux_base_height = self
                .meta_get_u64_opt(META_BASE_HEIGHT_KEY)?
                .unwrap_or(0)
                .min(aux_height);
            let full_aux_issues =
                self.collect_full_rebuildable_auxiliary_issues(aux_height, aux_base_height)?;
            if !full_aux_issues.is_empty() {
                preflight.ok = false;
                preflight.needs_recovery = true;
                preflight.issues.extend(full_aux_issues);
            } else if full_verify_after {
                let full_preflight = self.verify_db(true)?;
                if full_preflight.ok && !full_preflight.needs_recovery {
                    return Ok(full_preflight);
                }
                // Important: if the quick window looked clean but the full verify finds
                // corruption outside that window, this call must continue into the actual
                // repair path instead of returning a non-ok report without attempting
                // recovery.
                preflight = full_preflight;
            } else {
                return Ok(preflight);
            }
        }

        let pending_marker = self.journal_marker()?;
        let pending_op = pending_marker.as_ref().map(|m| m.op.as_str());
        let journal_only_recovery = pending_marker.is_some()
            && preflight
                .issues
                .iter()
                .all(|issue| issue.starts_with("journal_pending:"));
        let force_chain_replace_aux_clear = matches!(
            pending_op,
            Some("mirror-chain")
                | Some("mirror-chain-with-state")
                | Some("import-snapshot")
                | Some("import-snapshot-v2")
                | Some("repair-db")
        );
        let must_clear_state_nodes = matches!(
            pending_op,
            Some("mirror-chain-with-state") | Some("import-snapshot") | Some("import-snapshot-v2")
        );

        let height_opt = self.meta_get_u64_opt(META_HEIGHT_KEY)?;
        let current_height = height_opt.unwrap_or(0);
        let base_height = self
            .meta_get_u64_opt(META_BASE_HEIGHT_KEY)?
            .unwrap_or(0)
            .min(current_height);

        let mut finality_runtime_issues = Vec::new();
        self.verify_finality_meta_and_qc_archive_best_effort(
            current_height,
            base_height,
            true,
            &mut finality_runtime_issues,
        )?;
        let mut cognitive_runtime_issues = Vec::new();
        self.verify_cognitive_registry_best_effort(
            current_height,
            base_height,
            true,
            &mut cognitive_runtime_issues,
        )?;
        let effective_journal_only_recovery = journal_only_recovery
            && finality_runtime_issues.is_empty()
            && cognitive_runtime_issues.is_empty();

        let has_any_blocks = self
            .iter_all_cf(ColumnFamily::Blocks)?
            .next()
            .transpose()?
            .is_some();

        let mut last_good: Option<(u64, Block)> = None;
        let mut prev_hash: Option<String> = None;
        for idx in base_height..=current_height {
            let Some(b) = self.get_block(idx)? else {
                break;
            };
            if b.index != idx || b.try_calculate_hash().map_or(true, |h| b.hash != h) {
                break;
            }
            if idx > 0 {
                if let Some(ph) = prev_hash.as_ref() {
                    if b.previous_hash != *ph {
                        break;
                    }
                }
            }
            prev_hash = Some(b.hash.clone());
            last_good = Some((idx, b));
        }

        let chain_window_changed = height_opt.is_none() && has_any_blocks
            || last_good
                .as_ref()
                .map_or(false, |(target_height, _)| *target_height < current_height);

        let repaired_base_height = match (height_opt, last_good.as_ref()) {
            (Some(_), Some((target_height, _))) => base_height.min(*target_height),
            _ => 0,
        };
        let repaired_tip_height = last_good.as_ref().map(|(target_height, _)| *target_height);
        if let Some(target_height) = repaired_tip_height {
            if repaired_base_height > 0
                && !self.governance_snapshot_anchor_valid_for_window(
                    repaired_base_height,
                    target_height,
                )?
            {
                return Err(StorageError::BackendError(format!(
                    "repair refused: pruned db governance snapshot anchor is missing/corrupted or would fall outside the repaired window [{}..{}]; persist a fresh governance snapshot from canonical runtime before retrying",
                    repaired_base_height, target_height
                )));
            }
            if (repaired_base_height > 0 || crate::runtime_mode::public_mode_enabled())
                && !self
                    .economy_snapshot_anchor_valid_for_window(repaired_base_height, target_height)?
            {
                return Err(StorageError::BackendError(format!(
                    "repair refused: strict economy snapshot anchor is missing/corrupted or not bound to the repaired tip [{}..{}]; persist a fresh economy snapshot from canonical runtime before retrying",
                    repaired_base_height, target_height
                )));
            }
        }

        self.journal_begin("repair-db", "deterministic repair")?;
        if force_chain_replace_aux_clear
            || (!effective_journal_only_recovery && chain_window_changed)
        {
            self.invalidate_auxiliary_runtime_state_for_chain_replace()?;
        } else {
            if !finality_runtime_issues.is_empty() {
                self.clear_rebuildable_finality_runtime_state()?;
            }
            if !cognitive_runtime_issues.is_empty() {
                self.clear_rebuildable_cognitive_runtime_state()?;
            }
        }
        if must_clear_state_nodes {
            self.clear_keyspace(ColumnFamily::StateNodes)?;
        }

        if height_opt.is_none() {
            if has_any_blocks {
                self.clear_keyspace(ColumnFamily::Blocks)?;
                self.clear_keyspace(ColumnFamily::TxIndex)?;
                self.meta_remove(META_HEIGHT_KEY)?;
                self.meta_remove(META_BASE_HEIGHT_KEY)?;
                self.meta_remove(META_TIP_HASH_KEY)?;
                self.meta_remove(META_TIP_STATE_ROOT_KEY)?;
                self.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
                self.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
            } else {
                self.clear_keyspace(ColumnFamily::TxIndex)?;
                self.meta_remove(META_HEIGHT_KEY)?;
                self.meta_remove(META_BASE_HEIGHT_KEY)?;
                self.meta_remove(META_TIP_HASH_KEY)?;
                self.meta_remove(META_TIP_STATE_ROOT_KEY)?;
                self.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
                self.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
            }
            self.invalidate_governance_snapshot_if_outside_window(0, None)?;
            self.invalidate_governance_bootstrap_if_corrupt()?;
            self.meta_put_u32(
                META_DB_VERSION_KEY,
                crate::storage::current_runtime_storage_schema_version(),
            )?;
            self.flush_db()?;
            self.journal_clear()?;
            return self.verify_db(full_verify_after);
        }

        let Some((target_height, tip)) = last_good else {
            self.clear_keyspace(ColumnFamily::Blocks)?;
            self.clear_keyspace(ColumnFamily::TxIndex)?;
            self.meta_remove(META_HEIGHT_KEY)?;
            self.meta_remove(META_BASE_HEIGHT_KEY)?;
            self.meta_remove(META_TIP_HASH_KEY)?;
            self.meta_remove(META_TIP_STATE_ROOT_KEY)?;
            self.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
            self.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
            self.invalidate_governance_snapshot_if_outside_window(0, None)?;
            self.invalidate_governance_bootstrap_if_corrupt()?;
            self.meta_put_u32(
                META_DB_VERSION_KEY,
                crate::storage::current_runtime_storage_schema_version(),
            )?;
            self.flush_db()?;
            self.journal_clear()?;
            return self.verify_db(full_verify_after);
        };

        if target_height < current_height {
            for idx in (target_height + 1)..=current_height {
                let key = block_key(idx);
                self.delete(ColumnFamily::Blocks, key.as_bytes())?;
            }
        }

        self.clear_keyspace(ColumnFamily::TxIndex)?;
        for idx in base_height..=target_height {
            let b = self.get_block(idx)?.ok_or_else(|| {
                StorageError::BackendError(format!("repair missing block {}", idx))
            })?;
            for tx in &b.transactions {
                if tx.is_coinbase || tx.hash.is_empty() {
                    continue;
                }
                let key = tx.hash.as_bytes();
                if self.get(ColumnFamily::TxIndex, key)?.is_none() {
                    self.put(ColumnFamily::TxIndex, key, &encode_u64(idx))?;
                }
            }
        }

        self.meta_put_u64(META_HEIGHT_KEY, target_height)?;
        self.meta_put_u64(META_BASE_HEIGHT_KEY, repaired_base_height)?;
        self.meta_put_string(META_TIP_HASH_KEY, &tip.hash)?;
        let sr = if tip.state_root.is_empty() {
            "0"
        } else {
            tip.state_root.as_str()
        };
        self.meta_put_string(META_TIP_STATE_ROOT_KEY, sr)?;
        self.invalidate_governance_snapshot_if_outside_window(
            repaired_base_height,
            Some(target_height),
        )?;
        self.invalidate_governance_bootstrap_if_corrupt()?;
        self.meta_put_u32(
            META_DB_VERSION_KEY,
            crate::storage::current_runtime_storage_schema_version(),
        )?;
        self.flush_db()?;
        self.journal_clear()?;
        self.verify_db(full_verify_after)
    }

    /// Phase 5 — Pruning (blocks + tx_index).
    ///
    /// Elimina i blocchi con height < `target_base_height` e rimuove le entry di `tx_index`
    /// associate a quei blocchi. Aggiorna `meta:base_height`.
    ///
    /// - `target_base_height`: nuova base_height desiderata (clampata a tip_height per non svuotare la chain).
    /// - `max_blocks`: limite massimo di blocchi rimossi in questa chiamata (per evitare pause lunghe).
    ///
    /// Nota: NON esegue GC di `state_nodes` (compaction separata).
    pub fn prune_blocks_below(
        &self,
        target_base_height: u64,
        max_blocks: usize,
    ) -> StorageResult<PruneReport> {
        let tip_opt = self.meta_get_u64_opt(META_HEIGHT_KEY)?;
        let tip_height = match tip_opt {
            Some(h) => h,
            None => {
                return Ok(PruneReport {
                    old_base_height: 0,
                    new_base_height: 0,
                    pruned_blocks: 0,
                    pruned_tx_index: 0,
                });
            }
        };

        let old_base_height = self.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
        let target_base_height = target_base_height.min(tip_height);

        if max_blocks == 0 || target_base_height <= old_base_height {
            return Ok(PruneReport {
                old_base_height,
                new_base_height: old_base_height,
                pruned_blocks: 0,
                pruned_tx_index: 0,
            });
        }

        // Pruning changes the retained canonical window. For pruned DBs we must preserve
        // governance and economy/controller snapshots. Governance may be anchored anywhere
        // inside the retained window. Economy is stricter: it is tip-bound because it carries
        // the post-tip prospective fee/emission controller state.
        let mut economy_snapshot_after_prune: Option<String> = None;
        if target_base_height > 0 {
            match self.get_governance_snapshot()? {
                Some((snap_h, _)) if snap_h >= target_base_height && snap_h <= tip_height => {}
                Some((snap_h, _)) => {
                    return Err(StorageError::BackendError(format!(
                        "refusing prune: governance snapshot height {} is invalid for target base_height {} (persist a fresh governance snapshot first)",
                        snap_h, target_base_height
                    )));
                }
                None => {
                    return Err(StorageError::BackendError(format!(
                        "refusing prune: pruned db would lack governance snapshot for target base_height {} (persist a fresh governance snapshot first)",
                        target_base_height
                    )));
                }
            }

            let (_econ_h, econ_json) = match self.get_economy_snapshot()? {
                Some((econ_h, econ_json)) if econ_h == tip_height => (econ_h, econ_json),
                Some((econ_h, _)) => match self
                    .synthesize_tip_economy_snapshot_for_prune_from_full_blocks_v1(
                        tip_height,
                        old_base_height,
                    )? {
                    Some(fresh) => fresh,
                    None => {
                        return Err(StorageError::BackendError(format!(
                            "refusing prune: economy snapshot height {} is not tip {} (persist a fresh economy snapshot first)",
                            econ_h, tip_height
                        )));
                    }
                },
                None => match self.synthesize_tip_economy_snapshot_for_prune_from_full_blocks_v1(
                    tip_height,
                    old_base_height,
                )? {
                    Some(fresh) => fresh,
                    None => {
                        return Err(StorageError::BackendError(format!(
                            "refusing prune: pruned db would lack economy snapshot for target base_height {} (persist a fresh economy snapshot first)",
                            target_base_height
                        )));
                    }
                },
            };
            let mut econ: SnapshotEconomyStateV1 = match serde_json::from_str(&econ_json) {
                Ok(econ) => econ,
                Err(e) => match self
                    .synthesize_tip_economy_snapshot_for_prune_from_full_blocks_v1(
                        tip_height,
                        old_base_height,
                    )? {
                    Some((_, fresh_json)) => serde_json::from_str(&fresh_json).map_err(|fresh_err| {
                        StorageError::BackendError(format!(
                            "refusing prune: economy snapshot JSON invalid: {e}; synthesized replacement invalid: {fresh_err}"
                        ))
                    })?,
                    None => {
                        return Err(StorageError::BackendError(format!(
                            "refusing prune: economy snapshot JSON invalid: {e}"
                        )));
                    }
                },
            };
            econ.validate_basic().map_err(|e| {
                StorageError::BackendError(format!("refusing prune: economy snapshot invalid: {e}"))
            })?;
            let tip = self.get_block(tip_height)?.ok_or_else(|| {
                StorageError::BackendError(format!(
                    "refusing prune: tip block {} missing while validating economy snapshot",
                    tip_height
                ))
            })?;
            let tip_root = if tip.state_root.trim().is_empty() {
                "0"
            } else {
                tip.state_root.as_str()
            };
            if econ.height != tip_height
                || econ.block_hash != tip.hash
                || econ.state_root != tip_root
            {
                return Err(StorageError::BackendError(format!(
                    "refusing prune: economy snapshot is not bound to current tip height={} tip={} block_match={} state_root_match={}",
                    econ.height,
                    tip_height,
                    econ.block_hash == tip.hash,
                    econ.state_root == tip_root
                )));
            }
            self.verify_snapshot_economy_state_against_tip_state_v1(
                &econ,
                crate::runtime_mode::public_mode_enabled(),
            )
            .map_err(|e| {
                StorageError::BackendError(format!(
                    "refusing prune: economy snapshot is not semantically bound to tip state: {e}"
                ))
            })?;
            econ.base_height = target_base_height;
            econ.policy_hash_hex =
                SnapshotEconomyStateV1::policy_hash_for(&econ.policy).map_err(|e| {
                    StorageError::BackendError(format!(
                        "refusing prune: economy snapshot policy hash failed: {e}"
                    ))
                })?;
            econ.validate_basic().map_err(|e| {
                StorageError::BackendError(format!(
                    "refusing prune: rewritten economy snapshot invalid: {e}"
                ))
            })?;
            economy_snapshot_after_prune = Some(serde_json::to_string(&econ).map_err(|e| {
                StorageError::BackendError(format!(
                    "refusing prune: rewritten economy snapshot serialize failed: {e}"
                ))
            })?);
        }

        self.journal_begin("prune-blocks", "prune blocks below base_height")?;

        let mut batch = <Self as KVStore>::batch(self);
        let mut pruned_blocks: u64 = 0;
        let mut pruned_tx_index: u64 = 0;
        let limit = max_blocks as u64;
        let mut h = old_base_height;

        while h < target_base_height && pruned_blocks < limit {
            let b = self.get_block(h)?.ok_or_else(|| {
                StorageError::BackendError(format!("prune missing block idx={}", h))
            })?;

            for tx in &b.transactions {
                if tx.is_coinbase || tx.hash.is_empty() {
                    continue;
                }
                let key = tx.hash.as_bytes();
                if let Some(v) = self.get(ColumnFamily::TxIndex, key)? {
                    let stored_h = decode_u64(&v)?;
                    if stored_h == h {
                        batch.delete(ColumnFamily::TxIndex, key);
                        pruned_tx_index += 1;
                    }
                }
            }

            let key = block_key(h);
            batch.delete(ColumnFamily::Blocks, key.as_bytes());

            pruned_blocks += 1;
            h += 1;
        }

        let new_base_height = old_base_height.saturating_add(pruned_blocks);
        batch.put(
            ColumnFamily::Meta,
            META_BASE_HEIGHT_KEY.as_bytes(),
            &encode_u64(new_base_height),
        );
        // Economy sidecar base_height is part of the pruning commit. Writing it in
        // a later buffered operation can leave a crash window where blocks/base_height
        // are pruned but the tip-bound economy sidecar still advertises the old
        // base_height. That is fail-closed on next boot, but not mainnet-grade
        // atomicity. Keep the retained-window mutation and economy anchor rewrite in
        // the same durable batch.
        if let Some(econ_json) = economy_snapshot_after_prune.as_ref() {
            batch.put(
                ColumnFamily::Meta,
                META_ECONOMY_SNAPSHOT_HEIGHT_KEY.as_bytes(),
                &encode_u64(tip_height),
            );
            batch.put(
                ColumnFamily::Meta,
                META_ECONOMY_SNAPSHOT_JSON_KEY.as_bytes(),
                econ_json.as_bytes(),
            );
            let historical_key = Self::economy_snapshot_by_height_key(tip_height);
            batch.put(
                ColumnFamily::Meta,
                historical_key.as_bytes(),
                econ_json.as_bytes(),
            );
        }
        self.write_batch_with_durability(batch, StorageDurability::SyncAll)?;
        self.journal_clear()?;

        Ok(PruneReport {
            old_base_height,
            new_base_height,
            pruned_blocks,
            pruned_tx_index,
        })
    }

    /// Export snapshot (blocks + optional state_nodes).
    /// Formato: magic + header_json_len + header_json + blocks + state_nodes.
    pub fn export_snapshot<P: AsRef<Path>>(
        &self,
        path: P,
        include_state_nodes: bool,
    ) -> StorageResult<()> {
        #[derive(Serialize, Deserialize)]
        struct Header {
            version: u32,
            height: Option<u64>,
            tip_hash: Option<String>,
            tip_state_root: Option<String>,
            include_state_nodes: bool,
        }

        let height = self.meta_get_u64_opt(META_HEIGHT_KEY)?;
        let tip_hash = self.meta_get_string_opt(META_TIP_HASH_KEY)?;
        let tip_state_root = self.meta_get_string_opt(META_TIP_STATE_ROOT_KEY)?;

        let hdr = Header {
            version: 1,
            height,
            tip_hash,
            tip_state_root,
            include_state_nodes,
        };

        let hdr_bytes =
            serde_json::to_vec(&hdr).map_err(|e| StorageError::BackendError(e.to_string()))?;

        let mut w = BufWriter::new(
            File::create(path).map_err(|e| StorageError::BackendError(e.to_string()))?,
        );
        w.write_all(b"NGSNAP01")
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        w.write_all(&(hdr_bytes.len() as u32).to_be_bytes())
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        w.write_all(&hdr_bytes)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;

        if let Some(h) = height {
            for idx in 0..=h {
                let b = self.get_block(idx)?.ok_or_else(|| {
                    StorageError::BackendError(format!("snapshot missing block {}", idx))
                })?;
                let bytes = serde_json::to_vec(&b)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                w.write_all(&(bytes.len() as u32).to_be_bytes())
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                w.write_all(&bytes)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
            }
        }

        if include_state_nodes {
            let mut count: u64 = 0;
            for item in self.iter_all_cf(ColumnFamily::StateNodes)? {
                let (_k, _v) = item?;
                count = count.saturating_add(1);
            }
            w.write_all(&count.to_be_bytes())
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            for item in self.iter_all_cf(ColumnFamily::StateNodes)? {
                let (k, v) = item?;
                if k.len() != 32 {
                    continue;
                }
                w.write_all(&k)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                w.write_all(&(v.len() as u32).to_be_bytes())
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                w.write_all(&v)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
            }
        } else {
            w.write_all(&0u64.to_be_bytes())
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
        }

        w.flush()
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    /// Import snapshot (blocks + state_nodes), crash-safe via journal.
    pub fn import_snapshot<P: AsRef<Path>>(
        &self,
        path: P,
        wipe_state_nodes: bool,
    ) -> StorageResult<()> {
        let mut r = BufReader::new(
            File::open(path).map_err(|e| StorageError::BackendError(e.to_string()))?,
        );

        fn env_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(default)
        }

        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(default)
        }

        let max_hdr = env_usize("NG_SNAPSHOT_MAX_HEADER_BYTES", 4 * 1024 * 1024);
        let max_block = env_usize("NG_SNAPSHOT_MAX_BLOCK_BYTES", 64 * 1024 * 1024);
        let max_state_nodes = env_u64("NG_SNAPSHOT_MAX_STATE_NODES", 50_000_000);
        let max_state_node_bytes = env_usize("NG_SNAPSHOT_MAX_STATE_NODE_BYTES", 256 * 1024);
        let max_height = env_u64("NG_SNAPSHOT_MAX_HEIGHT", 5_000_000);

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        if &magic != b"NGSNAP01" {
            return Err(StorageError::BackendError("snapshot bad magic".to_string()));
        }

        let mut lenb = [0u8; 4];
        r.read_exact(&mut lenb)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let hdr_len = u32::from_be_bytes(lenb) as usize;
        if hdr_len == 0 || hdr_len > max_hdr {
            return Err(StorageError::BackendError(format!(
                "snapshot header too large: {} (max={})",
                hdr_len, max_hdr
            )));
        }
        let mut hdr_buf = vec![0u8; hdr_len];
        r.read_exact(&mut hdr_buf)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;

        #[derive(Serialize, Deserialize)]
        struct Header {
            version: u32,
            height: Option<u64>,
            tip_hash: Option<String>,
            tip_state_root: Option<String>,
            include_state_nodes: bool,
        }

        let hdr: Header = serde_json::from_slice(&hdr_buf)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        if hdr.version != 1 {
            return Err(StorageError::BackendError(format!(
                "snapshot version unsupported: {}",
                hdr.version
            )));
        }

        if let Some(h) = hdr.height {
            if h > max_height {
                return Err(StorageError::BackendError(format!(
                    "snapshot height too large: {} (max={})",
                    h, max_height
                )));
            }
        }

        // Open the recovery journal only once structural validation has passed and
        // we are about to mutate the DB. Validation-only failures must not leave a
        // spurious pending journal marker behind.
        self.journal_begin("import-snapshot", "snapshot restore")?;

        self.clear_chain_runtime_for_mirror()?;
        self.invalidate_auxiliary_runtime_state_for_chain_replace()?;
        if wipe_state_nodes {
            self.clear_keyspace(ColumnFamily::StateNodes)?;
        }

        if let Some(h) = hdr.height {
            for idx in 0..=h {
                let mut blen = [0u8; 4];
                r.read_exact(&mut blen)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                let n = u32::from_be_bytes(blen) as usize;
                if n == 0 || n > max_block {
                    return Err(StorageError::BackendError(format!(
                        "snapshot block blob too large: {} (max={})",
                        n, max_block
                    )));
                }
                let mut buf = vec![0u8; n];
                r.read_exact(&mut buf)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                let b: Block = serde_json::from_slice(&buf)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                if b.index != idx {
                    return Err(StorageError::BackendError(format!(
                        "snapshot block index mismatch: expected {} got {}",
                        idx, b.index
                    )));
                }
                self.append_block_inner(&b, false)?;
            }
        }

        let mut cntb = [0u8; 8];
        r.read_exact(&mut cntb)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let count = u64::from_be_bytes(cntb);
        if count > max_state_nodes {
            return Err(StorageError::BackendError(format!(
                "snapshot state_nodes count too large: {} (max={})",
                count, max_state_nodes
            )));
        }
        let mut state_batch = <Self as KVStore>::batch(self);
        let mut pending = 0usize;
        for _ in 0..count {
            let mut key = [0u8; 32];
            r.read_exact(&mut key)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let mut vlenb = [0u8; 4];
            r.read_exact(&mut vlenb)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let vlen = u32::from_be_bytes(vlenb) as usize;
            if vlen == 0 || vlen > max_state_node_bytes {
                return Err(StorageError::BackendError(format!(
                    "snapshot state_node blob too large: {} (max={})",
                    vlen, max_state_node_bytes
                )));
            }
            let mut val = vec![0u8; vlen];
            r.read_exact(&mut val)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            test_disk_full_consume(32 + vlen)?;
            state_batch.put(ColumnFamily::StateNodes, &key[..], &val);
            pending += 1;
            if pending >= 2048 {
                self.write_batch(state_batch)?;
                state_batch = <Self as KVStore>::batch(self);
                pending = 0;
            }
        }
        if pending > 0 {
            self.write_batch(state_batch)?;
        }

        let mut trailing = [0u8; 1];
        match r.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => {
                return Err(StorageError::BackendError(
                    "snapshot v1 has trailing bytes after payload".to_string(),
                ));
            }
            Err(e) => return Err(StorageError::BackendError(e.to_string())),
        }

        self.flush_db()?;
        self.journal_clear()?;
        Ok(())
    }

    fn snapshot_smt_get_account_at_state_root(
        &self,
        state_root_hex: &str,
        key: [u8; 32],
    ) -> StorageResult<Option<crate::account::AccountState>> {
        let root = crate::keyfmt::decode_pk_any(state_root_hex)
            .map_err(|_| StorageError::BackendError("invalid snapshot state_root".to_string()))?;
        let smt = crate::state_smt::StateSmt::new(self.state_node_store());
        smt.get_account(root, key)
            .map_err(StorageError::BackendError)
    }

    fn snapshot_system_account_key(name: &str) -> [u8; 32] {
        // Must stay byte-for-byte aligned with Blockchain::sys_key().  The helper is
        // duplicated locally instead of exposing Blockchain internals so storage can
        // validate imported sidecars without constructing a runtime chain.
        let mut k = crate::state_smt::addr_key(&format!("\0sys/{}", name));
        k[0] = 0x00;
        k
    }

    fn get_persisted_finality_bft_meta_v209(
        &self,
    ) -> StorageResult<Option<PersistedFinalityBftMetaV1>> {
        match self.get(
            ColumnFamily::FinalityBftMeta,
            FINALITY_BFT_META_DB_KEY.as_bytes(),
        )? {
            Some(bytes) => serde_json::from_slice::<PersistedFinalityBftMetaV1>(&bytes)
                .map(Some)
                .map_err(|e| {
                    StorageError::BackendError(format!(
                        "finality_meta decode failed for snapshot binding: {e}"
                    ))
                }),
            None => Ok(None),
        }
    }

    fn validate_finality_bft_meta_for_snapshot_v209(
        &self,
        meta: &PersistedFinalityBftMetaV1,
        base_height: u64,
        snapshot_height: u64,
        context: &str,
    ) -> StorageResult<()> {
        let is_hex32 = |value: &str| -> bool {
            let value = value.trim();
            value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        };

        if meta.finalized_height > snapshot_height {
            return Err(StorageError::BackendError(format!(
                "{context}: finalized_height {} exceeds snapshot_height {}",
                meta.finalized_height, snapshot_height
            )));
        }
        if meta.highest_qc_height > snapshot_height {
            return Err(StorageError::BackendError(format!(
                "{context}: highest_qc_height {} exceeds snapshot_height {}",
                meta.highest_qc_height, snapshot_height
            )));
        }
        if meta.finalized_height > meta.highest_qc_height {
            return Err(StorageError::BackendError(format!(
                "{context}: finalized_height {} exceeds highest_qc_height {}",
                meta.finalized_height, meta.highest_qc_height
            )));
        }
        if base_height > 0 {
            if meta.finalized_height < base_height {
                return Err(StorageError::BackendError(format!(
                    "{context}: finalized_height {} below snapshot base_height {}",
                    meta.finalized_height, base_height
                )));
            }
            if snapshot_height > base_height.saturating_add(1)
                && meta.finalized_height == base_height
            {
                return Err(StorageError::BackendError(format!(
                    "{context}: refusing base_height-as-finality fallback finalized_height={} snapshot_height={}",
                    meta.finalized_height, snapshot_height
                )));
            }
        }
        if meta.finalized_height > 0 {
            if !is_hex32(&meta.finalized_hash) {
                return Err(StorageError::BackendError(format!(
                    "{context}: finalized_hash missing/invalid at height {}",
                    meta.finalized_height
                )));
            }
            if let Some(block) = self.get_block(meta.finalized_height)? {
                if block.hash != meta.finalized_hash {
                    return Err(StorageError::BackendError(format!(
                        "{context}: finalized_hash mismatch at height {} expected={} actual={}",
                        meta.finalized_height, meta.finalized_hash, block.hash
                    )));
                }
            } else if meta.finalized_height >= base_height {
                return Err(StorageError::BackendError(format!(
                    "{context}: finalized_height {} missing from retained snapshot window",
                    meta.finalized_height
                )));
            }
        }
        if meta.highest_qc_height > 0 {
            if !is_hex32(&meta.highest_qc_block_hash) {
                return Err(StorageError::BackendError(format!(
                    "{context}: highest_qc_block_hash missing/invalid at height {}",
                    meta.highest_qc_height
                )));
            }
            if let Some(block) = self.get_block(meta.highest_qc_height)? {
                if block.hash != meta.highest_qc_block_hash {
                    return Err(StorageError::BackendError(format!(
                        "{context}: highest_qc_block_hash mismatch at height {} expected={} actual={}",
                        meta.highest_qc_height, meta.highest_qc_block_hash, block.hash
                    )));
                }
            } else if meta.highest_qc_height >= base_height {
                return Err(StorageError::BackendError(format!(
                    "{context}: highest_qc_height {} missing from retained snapshot window",
                    meta.highest_qc_height
                )));
            }
        }

        Ok(())
    }

    fn finality_bft_meta_for_snapshot_export_v209(
        &self,
        base_height: u64,
        snapshot_height: u64,
    ) -> StorageResult<Option<PersistedFinalityBftMetaV1>> {
        let meta = self.get_persisted_finality_bft_meta_v209()?;
        match meta {
            Some(meta) => {
                self.validate_finality_bft_meta_for_snapshot_v209(
                    &meta,
                    base_height,
                    snapshot_height,
                    "snapshot export finality binding v209",
                )?;
                Ok(Some(meta))
            }
            None if base_height == 0 => Ok(None),
            None => Err(StorageError::BackendError(format!(
                "snapshot export missing finalized head for pruned snapshot: base_height={} height={}",
                base_height, snapshot_height
            ))),
        }
    }

    fn persist_finality_bft_meta_from_snapshot_v209(
        &self,
        meta: &PersistedFinalityBftMetaV1,
    ) -> StorageResult<()> {
        let bytes = serde_json::to_vec(meta).map_err(|e| {
            StorageError::BackendError(format!(
                "snapshot import finality meta serialize failed: {e}"
            ))
        })?;
        self.put(
            ColumnFamily::FinalityBftMeta,
            FINALITY_BFT_META_DB_KEY.as_bytes(),
            &bytes,
        )
    }

    fn synthesize_economy_snapshot_from_full_blocks_v1(
        &self,
        target_height: u64,
        db_base_height: u64,
        context: &str,
    ) -> StorageResult<Option<(u64, String)>> {
        // A full-history DB can deterministically rebuild economy state for any retained
        // historical export target by replaying canonical blocks [0..target_height].
        // A pruned DB cannot do this safely; it must provide an indexed historical
        // sidecar for the requested height.
        if db_base_height != 0 {
            return Ok(None);
        }

        let mut blocks = Vec::with_capacity(target_height.saturating_add(1).min(1024) as usize);
        for idx in 0..=target_height {
            let Some(block) = self.get_block(idx)? else {
                return Ok(None);
            };
            if block.index != idx {
                return Err(StorageError::BackendError(format!(
                    "cannot synthesize economy snapshot for {context}: block index mismatch expected={} actual={}",
                    idx, block.index
                )));
            }
            blocks.push(block);
        }

        let mut chain = Blockchain::from_blocks(blocks);
        chain.base_height = db_base_height;
        let Some(tip) = chain.chain.last() else {
            return Ok(None);
        };
        if tip.index != target_height {
            return Err(StorageError::BackendError(format!(
                "cannot synthesize economy snapshot for {context}: rebuilt tip {} != target {}",
                tip.index, target_height
            )));
        }
        let snap = chain.build_snapshot_economy_state_v1(tip).map_err(|e| {
            StorageError::BackendError(format!(
                "cannot synthesize economy snapshot for {context}: {e}"
            ))
        })?;
        let json = serde_json::to_string(&snap).map_err(|e| {
            StorageError::BackendError(format!(
                "cannot serialize synthesized economy snapshot for {context}: {e}"
            ))
        })?;
        Ok(Some((target_height, json)))
    }

    fn synthesize_tip_economy_snapshot_for_prune_from_full_blocks_v1(
        &self,
        tip_height: u64,
        old_base_height: u64,
    ) -> StorageResult<Option<(u64, String)>> {
        self.synthesize_economy_snapshot_from_full_blocks_v1(tip_height, old_base_height, "prune")
    }

    fn economy_snapshot_for_export_height(
        &self,
        window_from: u64,
        window_to: u64,
    ) -> StorageResult<Option<(u64, String)>> {
        if let Some((h, json)) = self.get_economy_snapshot()? {
            if h == window_to {
                return Ok(Some((h, json)));
            }
        }

        if let Some(indexed) = self.get_economy_snapshot_at_height(window_to)? {
            return Ok(Some(indexed));
        }

        let db_base_height = self.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
        if db_base_height == 0 {
            return self.synthesize_economy_snapshot_from_full_blocks_v1(
                window_to,
                db_base_height,
                "snapshot export",
            );
        }

        let _ = window_from;
        Ok(None)
    }

    fn verify_snapshot_economy_state_against_tip_state_v1(
        &self,
        snap: &SnapshotEconomyStateV1,
        require_state_accounts: bool,
    ) -> StorageResult<()> {
        snap.validate_basic().map_err(|e| {
            StorageError::BackendError(format!("snapshot economy state invalid: {e}"))
        })?;

        let root = snap.state_root.trim();
        if root.is_empty() || root == "0" {
            if require_state_accounts {
                return Err(StorageError::BackendError(
                    "snapshot economy state requires non-zero state_root for strict SMT binding"
                        .to_string(),
                ));
            }
            return Ok(());
        }

        let read_balance = |name: &str| -> StorageResult<Option<u64>> {
            match self.snapshot_smt_get_account_at_state_root(
                root,
                Self::snapshot_system_account_key(name),
            ) {
                Ok(maybe) => Ok(maybe.map(|account| account.balance)),
                Err(err) if !require_state_accounts => {
                    // Non-public/test fixtures may carry a non-zero historical state_root
                    // without materializing every system-account SMT path.  Outside public
                    // strict mode the sidecar is still height/base/block/state-root bound;
                    // SMT system-account lookup failures are treated as optional absence.
                    // Public mode keeps failing closed through require_state_accounts=true.
                    let _ = err;
                    Ok(None)
                }
                Err(err) => Err(err),
            }
        };

        match read_balance("total_supply")? {
            Some(actual) if actual == snap.total_supply => {}
            Some(actual) if require_state_accounts => {
                return Err(StorageError::BackendError(format!(
                    "snapshot economy total_supply/SMT mismatch: sidecar={} smt={}",
                    snap.total_supply, actual
                )));
            }
            Some(_) => {
                // Non-public/test fixtures may materialize partial or synthetic system
                // economy accounts that are not the authority being tested.  The sidecar
                // remains hash/tip/state-root bound; public mode is the only mode where
                // SMT system-account equality is mandatory.
            }
            None if require_state_accounts => {
                return Err(StorageError::BackendError(
                    "snapshot economy missing SMT total_supply account".to_string(),
                ));
            }
            None => {}
        }

        match read_balance("treasury_balance")? {
            Some(actual) if actual == snap.treasury_balance => {}
            Some(actual) if require_state_accounts => {
                return Err(StorageError::BackendError(format!(
                    "snapshot economy treasury_balance/SMT mismatch: sidecar={} smt={}",
                    snap.treasury_balance, actual
                )));
            }
            Some(_) => {}
            None if require_state_accounts => {
                return Err(StorageError::BackendError(
                    "snapshot economy missing SMT treasury_balance account".to_string(),
                ));
            }
            None => {}
        }

        match (
            snap.tip_applied_base_fee_per_tx,
            read_balance("base_fee_per_tx")?,
        ) {
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(expected), Some(actual)) if require_state_accounts => {
                return Err(StorageError::BackendError(format!(
                    "snapshot economy base_fee_per_tx/SMT mismatch: sidecar={} smt={}",
                    expected, actual
                )));
            }
            (Some(_), Some(_)) => {}
            (None, Some(_)) if require_state_accounts => {
                return Err(StorageError::BackendError(
                    "snapshot economy sidecar missing tip_applied_base_fee_per_tx while SMT account exists"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {}
            (Some(_), None) if require_state_accounts => {
                return Err(StorageError::BackendError(
                    "snapshot economy missing SMT base_fee_per_tx account".to_string(),
                ));
            }
            (None, None) if require_state_accounts => {
                return Err(StorageError::BackendError(
                    "snapshot economy missing tip_applied_base_fee_per_tx and SMT base_fee_per_tx account"
                        .to_string(),
                ));
            }
            _ => {}
        }

        Ok(())
    }

    fn snapshot_load_pos_params_at_state_root(
        &self,
        state_root_hex: &str,
    ) -> StorageResult<crate::staking::PosParamsV1> {
        let st = self
            .snapshot_smt_get_account_at_state_root(
                state_root_hex,
                crate::staking::k_stake_params(),
            )?
            .ok_or_else(|| {
                StorageError::BackendError(
                    "snapshot consensus bootstrap context missing pos_params at source state_root"
                        .to_string(),
                )
            })?;
        let params =
            crate::staking::decode_params_state(&st).map_err(StorageError::BackendError)?;
        if params.epoch_len == 0 {
            return Err(StorageError::BackendError(
                "snapshot consensus bootstrap context pos_params.epoch_len=0".to_string(),
            ));
        }
        Ok(params)
    }

    fn snapshot_context_max_historical_scan_blocks() -> u64 {
        env_u64("NEWGEN_SNAPSHOT_CONTEXT_MAX_HISTORICAL_SCAN_BLOCKS", 4096).clamp(1, 100_000)
    }

    fn snapshot_context_target_epochs(current_epoch: u64) -> std::collections::BTreeSet<u64> {
        let mut target_epochs = std::collections::BTreeSet::new();
        if current_epoch > 0 {
            target_epochs.insert(current_epoch.saturating_sub(1));
        }
        target_epochs.insert(current_epoch);
        target_epochs
    }

    fn snapshot_export_deadline_ms_v205() -> u64 {
        env_u64("NEWGEN_SNAPSHOT_EXPORT_DEADLINE_MS", 120_000).clamp(5_000, 3_600_000)
    }

    fn snapshot_context_scan_deadline_ms_v205() -> u64 {
        env_u64("NEWGEN_SNAPSHOT_CONTEXT_SCAN_DEADLINE_MS", 30_000).clamp(1_000, 600_000)
    }

    fn snapshot_export_progress_every_blocks_v205() -> u64 {
        env_u64("NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_BLOCKS", 512).clamp(1, 100_000)
    }

    fn snapshot_export_progress_every_state_nodes_v205() -> u64 {
        env_u64("NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_STATE_NODES", 10_000).clamp(1, 10_000_000)
    }

    fn snapshot_elapsed_ms_v205(started: std::time::Instant) -> u64 {
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    fn snapshot_check_deadline_v205(
        started: std::time::Instant,
        deadline_ms: u64,
        stage: &str,
        progress: u64,
    ) -> StorageResult<()> {
        let elapsed_ms = Self::snapshot_elapsed_ms_v205(started);
        if elapsed_ms > deadline_ms {
            return Err(StorageError::BackendError(format!(
                "snapshot_export_deadline_exceeded stage={} elapsed_ms={} deadline_ms={} progress={}",
                stage, elapsed_ms, deadline_ms, progress
            )));
        }
        Ok(())
    }

    fn find_snapshot_epoch_params_source_bounded(
        &self,
        snapshot_height: u64,
        target_epoch: u64,
        min_height: u64,
        max_scan_blocks: u64,
    ) -> StorageResult<Option<(u64, String, crate::staking::PosParamsV1)>> {
        let mut candidate: Option<(u64, String, crate::staking::PosParamsV1)> = None;
        let mut scanned = 0u64;
        let start_height = snapshot_height;
        let min_height = min_height.min(snapshot_height);
        let scan_started = std::time::Instant::now();
        let scan_deadline_ms = Self::snapshot_context_scan_deadline_ms_v205();
        ng_info_throttle!(
            key: format!(
                "snapshot_context_params_scan_start:{}:{}:{}",
                snapshot_height, target_epoch, min_height
            ),
            every_ms: 30_000,
            target: "snapshot.context",
            "event=snapshot_context_params_scan_start snapshot_height={} target_epoch={} start_height={} min_height={} max_scan_blocks={}",
            snapshot_height,
            target_epoch,
            start_height,
            min_height,
            max_scan_blocks
        );

        for height in (min_height..=start_height).rev() {
            Self::snapshot_check_deadline_v205(
                scan_started,
                scan_deadline_ms,
                "context_params_scan",
                scanned,
            )?;
            if scanned >= max_scan_blocks {
                ng_warn_throttle!(
                    key: format!(
                        "snapshot_context_params_scan_bounded_miss:{}:{}:{}",
                        snapshot_height, target_epoch, min_height
                    ),
                    every_ms: 30_000,
                    target: "snapshot.context",
                    "event=snapshot_context_params_scan_bounded_miss snapshot_height={} target_epoch={} min_height={} max_scan_blocks={} scanned={} action=omit_optional_context",
                    snapshot_height,
                    target_epoch,
                    min_height,
                    max_scan_blocks,
                    scanned
                );
                break;
            }
            scanned = scanned.saturating_add(1);
            let Some(block) = self.get_block(height)? else {
                continue;
            };
            if block.state_root.trim().is_empty() {
                continue;
            }
            let params = match self.snapshot_load_pos_params_at_state_root(&block.state_root) {
                Ok(params) => params,
                Err(StorageError::BackendError(e))
                    if e.contains("missing node at depth") || e.contains("missing node") =>
                {
                    if candidate.is_some() {
                        break;
                    }
                    continue;
                }
                Err(err) => return Err(err),
            };
            let epoch = height.saturating_add(1) / params.epoch_len;
            if epoch == target_epoch {
                candidate = Some((height, block.state_root.clone(), params));
                continue;
            }
            if candidate.is_some() && epoch < target_epoch {
                break;
            }
        }
        if let Some((height, _, _)) = candidate.as_ref() {
            ng_info_throttle!(
                key: format!(
                    "snapshot_context_params_scan_ok:{}:{}:{}",
                    snapshot_height, target_epoch, height
                ),
                every_ms: 30_000,
                target: "snapshot.context",
                "event=snapshot_context_params_scan_ok snapshot_height={} target_epoch={} source_height={} scanned={}",
                snapshot_height,
                target_epoch,
                height,
                scanned
            );
        }
        Ok(candidate)
    }

    fn snapshot_bootstrap_source(
        &self,
        block_height: Option<u64>,
        state_root: &str,
        snapshot_height: u64,
        snapshot_state_root: &str,
        carry_forward: bool,
        derived_genesis_seed: bool,
    ) -> crate::snapshot::SnapshotConsensusContextSource {
        let kind = if derived_genesis_seed {
            crate::snapshot::SnapshotConsensusContextSourceKind::DerivedGenesisNetworkSeed
        } else if carry_forward {
            crate::snapshot::SnapshotConsensusContextSourceKind::SnapshotStateRootCarryForward
        } else if block_height == Some(snapshot_height)
            && state_root.trim() == snapshot_state_root.trim()
        {
            crate::snapshot::SnapshotConsensusContextSourceKind::SnapshotStateRoot
        } else {
            crate::snapshot::SnapshotConsensusContextSourceKind::HistoricalBlockStateRoot
        };
        crate::snapshot::SnapshotConsensusContextSource {
            block_height,
            state_root: state_root.to_string(),
            kind,
        }
    }

    fn find_snapshot_account_source_in_height_range(
        &self,
        start_height: u64,
        end_height: u64,
        key: [u8; 32],
    ) -> StorageResult<Option<(u64, String, crate::account::AccountState)>> {
        if start_height > end_height {
            return Ok(None);
        }
        let max_scan_blocks = Self::snapshot_context_max_historical_scan_blocks();
        let mut scanned = 0u64;
        let scan_started = std::time::Instant::now();
        let scan_deadline_ms = Self::snapshot_context_scan_deadline_ms_v205();
        for height in (start_height..=end_height).rev() {
            Self::snapshot_check_deadline_v205(
                scan_started,
                scan_deadline_ms,
                "context_account_scan",
                scanned,
            )?;
            if scanned >= max_scan_blocks {
                ng_warn_throttle!(
                    key: format!(
                        "snapshot_context_account_scan_bounded_miss:{}:{}",
                        end_height, start_height
                    ),
                    every_ms: 30_000,
                    target: "snapshot.context",
                    "event=snapshot_context_account_scan_bounded_miss range_start={} range_end={} max_scan_blocks={} scanned={} action=omit_optional_context",
                    start_height,
                    end_height,
                    max_scan_blocks,
                    scanned
                );
                break;
            }
            scanned = scanned.saturating_add(1);
            let Some(block) = self.get_block(height)? else {
                continue;
            };
            if block.state_root.trim().is_empty() {
                continue;
            }
            match self.snapshot_smt_get_account_at_state_root(&block.state_root, key) {
                Ok(Some(st)) => return Ok(Some((height, block.state_root.clone(), st))),
                Ok(None) => continue,
                Err(StorageError::BackendError(e))
                    if e.contains("missing node at depth") || e.contains("missing node") =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    fn resolve_snapshot_epoch_params_context(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
        current_epoch: u64,
        tip_pos_params: &crate::staking::PosParamsV1,
        target_epoch: u64,
    ) -> StorageResult<
        Option<(
            crate::staking::PosParamsV1,
            crate::snapshot::SnapshotConsensusContextSource,
        )>,
    > {
        // V204 hardening: the current epoch is already anchored at the snapshot
        // state root. Do not scan historical blocks before using the tip source;
        // a reverse scan here was one of the paths that made latest export CPU-bound
        // on pruned Fjall stores.
        if target_epoch == current_epoch {
            return Ok(Some((
                tip_pos_params.clone(),
                self.snapshot_bootstrap_source(
                    Some(snapshot_height),
                    snapshot_state_root,
                    snapshot_height,
                    snapshot_state_root,
                    false,
                    false,
                ),
            )));
        }

        // Older epochs are optional for restart/bootstrap snapshots. Look only in a
        // bounded neighborhood derived from current tip params; never scan the full
        // retained window in the automatic exporter. If params changed around the
        // boundary, each candidate source is still validated by its own on-chain
        // params epoch calculation before use.
        let target_start = target_epoch.saturating_mul(tip_pos_params.epoch_len);
        let target_end = target_start
            .saturating_add(tip_pos_params.epoch_len.saturating_sub(1))
            .min(snapshot_height);
        let min_height = target_start.min(target_end);
        let max_scan_blocks = Self::snapshot_context_max_historical_scan_blocks();

        if let Some((src_height, src_root, params)) = self
            .find_snapshot_epoch_params_source_bounded(
                snapshot_height.min(target_end),
                target_epoch,
                min_height,
                max_scan_blocks,
            )?
        {
            return Ok(Some((
                params,
                self.snapshot_bootstrap_source(
                    Some(src_height),
                    &src_root,
                    snapshot_height,
                    snapshot_state_root,
                    false,
                    false,
                ),
            )));
        }

        Ok(None)
    }

    fn resolve_snapshot_epoch_seed_context(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
        epoch: u64,
        coverage_start_height: u64,
        coverage_end_height: u64,
    ) -> StorageResult<Option<([u8; 32], crate::snapshot::SnapshotConsensusContextSource)>> {
        let next_height = snapshot_height.saturating_add(1);
        let prefer_snapshot_tip =
            next_height >= coverage_start_height && next_height <= coverage_end_height;

        if prefer_snapshot_tip {
            if let Some(state) = self.snapshot_smt_get_account_at_state_root(
                snapshot_state_root,
                crate::pos::k_seed(epoch),
            )? {
                let seed = crate::pos::decode_seed_state(&state)
                    .map(|s| s.seed)
                    .map_err(StorageError::BackendError)?;
                return Ok(Some((
                    seed,
                    self.snapshot_bootstrap_source(
                        Some(snapshot_height),
                        snapshot_state_root,
                        snapshot_height,
                        snapshot_state_root,
                        false,
                        false,
                    ),
                )));
            }
        }

        let source_start = coverage_start_height.saturating_sub(1);
        let source_end = snapshot_height.min(coverage_end_height.saturating_sub(1));
        if let Some((src_height, src_root, state)) = self
            .find_snapshot_account_source_in_height_range(
                source_start,
                source_end,
                crate::pos::k_seed(epoch),
            )?
        {
            let seed = crate::pos::decode_seed_state(&state)
                .map(|s| s.seed)
                .map_err(StorageError::BackendError)?;
            return Ok(Some((
                seed,
                self.snapshot_bootstrap_source(
                    Some(src_height),
                    &src_root,
                    snapshot_height,
                    snapshot_state_root,
                    false,
                    false,
                ),
            )));
        }
        if !prefer_snapshot_tip {
            if let Some(state) = self.snapshot_smt_get_account_at_state_root(
                snapshot_state_root,
                crate::pos::k_seed(epoch),
            )? {
                let seed = crate::pos::decode_seed_state(&state)
                    .map(|s| s.seed)
                    .map_err(StorageError::BackendError)?;
                return Ok(Some((
                    seed,
                    self.snapshot_bootstrap_source(
                        Some(snapshot_height),
                        snapshot_state_root,
                        snapshot_height,
                        snapshot_state_root,
                        false,
                        false,
                    ),
                )));
            }
        }
        if epoch == 0 {
            return Ok(Some((
                crate::pos::seed0_from_network_id(crate::chain_identity::network_id()),
                self.snapshot_bootstrap_source(
                    None,
                    "",
                    snapshot_height,
                    snapshot_state_root,
                    false,
                    true,
                ),
            )));
        }
        Ok(None)
    }

    fn resolve_snapshot_epoch_committee_context(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
        epoch: u64,
        coverage_start_height: u64,
        coverage_end_height: u64,
    ) -> StorageResult<
        Option<(
            SnapshotConsensusCommitteeContext,
            crate::snapshot::SnapshotConsensusContextSource,
        )>,
    > {
        let decode_committee = |state: crate::account::AccountState| -> StorageResult<SnapshotConsensusCommitteeContext> {
            let committee_any = crate::pos::decode_committee_state_any(&state)
                .map_err(StorageError::BackendError)?;
            Ok(match committee_any {
                crate::pos::CommitteeAny::V1(c1) => SnapshotConsensusCommitteeContext::V1 {
                    members_pk_hex: c1.members_pk_hex,
                },
                crate::pos::CommitteeAny::V2(c2) => SnapshotConsensusCommitteeContext::V2 {
                    members: c2.members,
                },
            })
        };

        let next_height = snapshot_height.saturating_add(1);
        let prefer_snapshot_tip =
            next_height >= coverage_start_height && next_height <= coverage_end_height;

        if prefer_snapshot_tip {
            if let Some(committee_state) = self.snapshot_smt_get_account_at_state_root(
                snapshot_state_root,
                crate::pos::k_committee(epoch),
            )? {
                let committee = decode_committee(committee_state)?;
                return Ok(Some((
                    committee,
                    self.snapshot_bootstrap_source(
                        Some(snapshot_height),
                        snapshot_state_root,
                        snapshot_height,
                        snapshot_state_root,
                        false,
                        false,
                    ),
                )));
            }
        }

        let source_start = coverage_start_height.saturating_sub(1);
        let source_end = snapshot_height.min(coverage_end_height.saturating_sub(1));
        if let Some((src_height, src_root, state)) = self
            .find_snapshot_account_source_in_height_range(
                source_start,
                source_end,
                crate::pos::k_committee(epoch),
            )?
        {
            let committee = decode_committee(state)?;
            return Ok(Some((
                committee,
                self.snapshot_bootstrap_source(
                    Some(src_height),
                    &src_root,
                    snapshot_height,
                    snapshot_state_root,
                    false,
                    false,
                ),
            )));
        }
        if !prefer_snapshot_tip {
            if let Some(committee_state) = self.snapshot_smt_get_account_at_state_root(
                snapshot_state_root,
                crate::pos::k_committee(epoch),
            )? {
                let committee = decode_committee(committee_state)?;
                return Ok(Some((
                    committee,
                    self.snapshot_bootstrap_source(
                        Some(snapshot_height),
                        snapshot_state_root,
                        snapshot_height,
                        snapshot_state_root,
                        false,
                        false,
                    ),
                )));
            }
        }
        Ok(None)
    }

    fn build_snapshot_consensus_epoch_bootstrap_context(
        &self,
        snapshot_height: u64,
        snapshot_state_root: &str,
        epoch: u64,
        pos_params: crate::staking::PosParamsV1,
        params_source: crate::snapshot::SnapshotConsensusContextSource,
        require_complete_context: bool,
    ) -> StorageResult<Option<SnapshotConsensusEpochBootstrapContext>> {
        let coverage_start_height = epoch.saturating_mul(pos_params.epoch_len);
        let coverage_end_height =
            coverage_start_height.saturating_add(pos_params.epoch_len.saturating_sub(1));

        let Some((seed, seed_source)) = self.resolve_snapshot_epoch_seed_context(
            snapshot_height,
            snapshot_state_root,
            epoch,
            coverage_start_height,
            coverage_end_height,
        )?
        else {
            if require_complete_context {
                return Err(StorageError::BackendError(format!(
                    "snapshot consensus bootstrap context missing seed for epoch {}",
                    epoch
                )));
            }
            return Ok(None);
        };

        let Some((committee, committee_source)) = self.resolve_snapshot_epoch_committee_context(
            snapshot_height,
            snapshot_state_root,
            epoch,
            coverage_start_height,
            coverage_end_height,
        )?
        else {
            if require_complete_context {
                return Err(StorageError::BackendError(format!(
                    "snapshot consensus bootstrap context missing committee for epoch {}",
                    epoch
                )));
            }
            return Ok(None);
        };

        let ctx = SnapshotConsensusEpochBootstrapContext {
            epoch,
            coverage_start_height,
            coverage_end_height,
            pos_params,
            params_source: Some(params_source),
            seed_source: Some(seed_source),
            committee_source: Some(committee_source),
            legacy_params_source_height: None,
            legacy_params_source_state_root: None,
            seed_epoch: epoch,
            seed_hex: hex::encode(seed),
            committee,
        };
        ctx.validate_basic_with_snapshot(snapshot_height, snapshot_state_root)
            .map_err(StorageError::BackendError)?;
        Ok(Some(ctx))
    }

    fn persisted_snapshot_consensus_epoch_context_usable(
        persisted_ctx: &SnapshotConsensusBootstrapContext,
        epoch_ctx: &SnapshotConsensusEpochBootstrapContext,
        overlap_start: u64,
        overlap_end: u64,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> bool {
        if overlap_start > overlap_end {
            return false;
        }
        if !persisted_ctx.covers_consensus_height(overlap_start)
            || !persisted_ctx.covers_consensus_height(overlap_end)
        {
            return false;
        }
        if persisted_ctx
            .validate_basic(
                persisted_ctx.snapshot_height,
                &persisted_ctx.prev_state_root,
            )
            .is_err()
        {
            return false;
        }
        epoch_ctx.contains_next_height(overlap_start)
            && epoch_ctx.contains_next_height(overlap_end)
            && epoch_ctx
                .validate_basic_with_snapshot(snapshot_height, snapshot_state_root)
                .is_ok()
    }

    fn build_snapshot_consensus_bootstrap_context(
        &self,
        window_from_height: u64,
        snapshot_height: u64,
        snapshot_state_root: &str,
    ) -> StorageResult<SnapshotConsensusBootstrapContext> {
        let next_height = snapshot_height.saturating_add(1);
        let sidecar_from_height = window_from_height;
        let sidecar_to_height = next_height;
        ng_info!(
            target: "snapshot.context",
            "event=snapshot_consensus_context_build_start snapshot_height={} window_from={} sidecar_to={} state_root_prefix={}",
            snapshot_height,
            sidecar_from_height,
            sidecar_to_height,
            snapshot_state_root.chars().take(16).collect::<String>()
        );

        let persisted_bootstrap_context = self.get_snapshot_consensus_bootstrap_context()?;
        if let Some(persisted_ctx) = persisted_bootstrap_context.as_ref() {
            if persisted_ctx
                .validate_basic(snapshot_height, snapshot_state_root)
                .is_ok()
                && persisted_ctx.covers_consensus_height(next_height)
            {
                ng_info!(
                    target: "snapshot.context",
                    "event=snapshot_consensus_context_fast_path_reused snapshot_height={} next_height={} source=persisted_context",
                    snapshot_height,
                    next_height
                );
                return Ok(persisted_ctx.clone());
            }
        }

        let tip_pos_params = self.snapshot_load_pos_params_at_state_root(snapshot_state_root)?;
        let current_epoch = next_height / tip_pos_params.epoch_len;

        let mut epoch_contexts = Vec::new();
        let target_epochs = Self::snapshot_context_target_epochs(current_epoch);
        ng_info!(
            target: "snapshot.context",
            "event=snapshot_consensus_context_target_epochs snapshot_height={} current_epoch={} target_epochs={:?} max_scan_blocks={}",
            snapshot_height,
            current_epoch,
            target_epochs,
            Self::snapshot_context_max_historical_scan_blocks()
        );

        for target_epoch in target_epochs {
            let epoch_start = target_epoch.saturating_mul(tip_pos_params.epoch_len);
            let epoch_end = epoch_start.saturating_add(tip_pos_params.epoch_len.saturating_sub(1));
            let intersects_sidecar_window =
                epoch_start <= sidecar_to_height && epoch_end >= sidecar_from_height;
            // Mainnet contract: current epoch/next-height consensus context is mandatory.
            // Older epochs are emitted only when complete and valid. This avoids over-claiming
            // historical consensus coverage from reachable-only snapshots while still allowing
            // B/C/D to reuse a valid imported sidecar when present.
            let require_complete_context = target_epoch == current_epoch;

            if intersects_sidecar_window {
                if let Some(persisted_ctx) = persisted_bootstrap_context.as_ref() {
                    if let Some(ctx) = persisted_ctx.epoch_context(target_epoch) {
                        let overlap_start = epoch_start.max(sidecar_from_height);
                        let overlap_end = epoch_end.min(sidecar_to_height);
                        if Self::persisted_snapshot_consensus_epoch_context_usable(
                            persisted_ctx,
                            &ctx,
                            overlap_start,
                            overlap_end,
                            snapshot_height,
                            snapshot_state_root,
                        ) {
                            epoch_contexts.push(ctx);
                            continue;
                        }
                    }
                }
            }

            let Some((pos_params, params_source)) = self.resolve_snapshot_epoch_params_context(
                snapshot_height,
                snapshot_state_root,
                current_epoch,
                &tip_pos_params,
                target_epoch,
            )?
            else {
                if require_complete_context {
                    return Err(StorageError::BackendError(format!(
                        "snapshot consensus bootstrap context missing pos_params for epoch {}",
                        target_epoch
                    )));
                }
                continue;
            };
            match self.build_snapshot_consensus_epoch_bootstrap_context(
                snapshot_height,
                snapshot_state_root,
                target_epoch,
                pos_params,
                params_source,
                require_complete_context,
            ) {
                Ok(Some(ctx)) => epoch_contexts.push(ctx),
                Ok(None) => {}
                Err(err) if !require_complete_context => {
                    let detail = Self::snapshot_bootstrap_context_build_error_message(&err);
                    if Self::is_snapshot_bootstrap_context_historical_gap_error(&detail) {
                        continue;
                    }
                    return Err(err);
                }
                Err(err) => return Err(err),
            }
        }

        let mut ctx = SnapshotConsensusBootstrapContext::from_epoch_contexts(
            snapshot_height,
            snapshot_state_root.to_string(),
            epoch_contexts,
        );
        if let Ok(contexts) = ctx.normalized_epoch_contexts() {
            if Self::snapshot_consensus_epoch_contexts_cover_height_range(
                &contexts,
                sidecar_from_height,
                sidecar_to_height,
            ) {
                ctx = ctx.with_historical_consensus_window(sidecar_from_height, sidecar_to_height);
            }
        }
        ctx.validate_basic(snapshot_height, snapshot_state_root)
            .map_err(StorageError::BackendError)?;
        ng_info!(
            target: "snapshot.context",
            "event=snapshot_consensus_context_build_ok snapshot_height={} next_height={} covered_epochs={:?} coverage_start={:?} coverage_end={:?} historical_window={:?}",
            snapshot_height,
            next_height,
            ctx.covered_epochs,
            ctx.coverage_start_height,
            ctx.coverage_end_height,
            ctx.historical_consensus_window()
        );
        Ok(ctx)
    }

    fn snapshot_consensus_epoch_contexts_cover_height_range(
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

    fn snapshot_bootstrap_context_build_error_message(err: &StorageError) -> String {
        match err {
            StorageError::BackendError(msg) => msg.clone(),
            other => other.to_string(),
        }
    }

    fn is_snapshot_bootstrap_context_historical_gap_error(message: &str) -> bool {
        let msg = message.trim();
        msg.contains("missing node at depth")
            || msg.contains("missing node")
            || msg.contains("historical_state_unavailable_after_snapshot_import:")
            || msg.contains(
                "snapshot consensus bootstrap context missing pos_params at source state_root",
            )
            || msg.contains("snapshot consensus bootstrap context missing pos_params for epoch")
            || msg.contains("snapshot consensus bootstrap context missing seed for epoch")
            || msg.contains("snapshot consensus bootstrap context missing committee for epoch")
            || msg.contains("snapshot consensus bootstrap committee v1 must not be empty")
            || msg.contains("snapshot consensus bootstrap committee v2 must not be empty")
            || msg.contains(
                "snapshot consensus bootstrap context does not cover historical consensus window",
            )
    }

    fn classify_snapshot_bootstrap_context_omission_reason(
        snapshot_height: u64,
        tip_height: u64,
        reachable_only: bool,
        error_message: &str,
    ) -> Option<SnapshotConsensusBootstrapContextOmissionReason> {
        if !reachable_only {
            return None;
        }
        if snapshot_height < tip_height
            && Self::is_snapshot_bootstrap_context_historical_gap_error(error_message)
        {
            return Some(
                SnapshotConsensusBootstrapContextOmissionReason::HistoricalStateCoverageUnavailable,
            );
        }
        if Self::is_snapshot_bootstrap_context_historical_gap_error(error_message) {
            return Some(
                SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete,
            );
        }
        None
    }

    fn compact_compute_order_state_store_for_snapshot_header_v207(
        store: &crate::compute_contract::ComputeOrderStateStoreV1,
        snapshot_height: u64,
        snapshot_hash: &str,
    ) -> StorageResult<crate::compute_contract::ComputeOrderStateStoreV1> {
        // V207: the snapshot header is a manifest/control-plane surface, not an
        // unbounded historical event journal.  E2 needs the materialized order
        // state and workload metadata to remain hash-bound and importable; the
        // full per-height event/block-hash history is already represented by the
        // exported block window and can grow without bound on long-running nodes.
        // Keep only the target hash needed by boot/import invariants.
        if !store.complete_from_genesis || store.first_applied_height != 0 {
            return Err(StorageError::BackendError(format!(
                "snapshot export compute order compact sidecar requires genesis-complete store:first_applied_height={} complete_from_genesis={}",
                store.first_applied_height, store.complete_from_genesis
            )));
        }
        if store.last_applied_height != snapshot_height {
            return Err(StorageError::BackendError(format!(
                "snapshot export compute order compact sidecar height mismatch: store_height={} snapshot_height={}",
                store.last_applied_height, snapshot_height
            )));
        }
        let snapshot_hash = snapshot_hash.trim();
        if snapshot_hash.is_empty() && snapshot_height > 0 {
            return Err(StorageError::BackendError(format!(
                "snapshot export compute order compact sidecar missing snapshot hash: height={}",
                snapshot_height
            )));
        }
        if !snapshot_hash.is_empty() && store.last_applied_hash != snapshot_hash {
            return Err(StorageError::BackendError(format!(
                "snapshot export compute order compact sidecar hash mismatch: store_hash={} snapshot_hash={}",
                store.last_applied_hash, snapshot_hash
            )));
        }

        let mut block_hash_by_height = std::collections::BTreeMap::new();
        if !snapshot_hash.is_empty() {
            block_hash_by_height.insert(snapshot_height, snapshot_hash.to_string());
        }

        let compact = crate::compute_contract::ComputeOrderStateStoreV1 {
            format_version: store.format_version.clone(),
            e2_contract_version: store.e2_contract_version.clone(),
            first_applied_height: 0,
            last_applied_height: snapshot_height,
            last_applied_hash: snapshot_hash.to_string(),
            complete_from_genesis: true,
            required_job_kind_activation_height: store.required_job_kind_activation_height,
            orders: store.orders.clone(),
            metadata_by_order_id: store.metadata_by_order_id.clone(),
            events_by_height: std::collections::BTreeMap::new(),
            block_hash_by_height,
        };
        Ok(compact)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_snapshot_v2_bundle<P: AsRef<Path>>(
        &self,
        out_dir: P,
        target_height: Option<u64>,
        window_from_height: Option<u64>,
        include_state_nodes: bool,
        reachable_only: bool,
        chunk_size: usize,
        max_snapshot_bytes: usize,
    ) -> StorageResult<SnapshotMeta> {
        #[derive(Serialize, Deserialize)]
        struct HeaderV2 {
            version: u32,
            base_height: u64,
            window_from: u64,
            window_to: u64,
            include_state_nodes: bool,
            reachable_only: bool,
            snapshot_height: u64,
            snapshot_block_hash: String,
            snapshot_state_root: String,
            genesis_hash: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            created_at_ts: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            finalized_height: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            finalized_hash: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            highest_qc_height: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            highest_qc_round: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            highest_qc_block_hash: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            finality_source: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            finality_binding_version: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            governance_snapshot_height: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            governance_snapshot_json: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            governance_snapshot_hash_hex: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            economy_snapshot_height: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            economy_snapshot_json: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            economy_snapshot_hash_hex: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            compute_order_state_store_json: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            compute_order_state_store_hash_hex: Option<String>,
        }

        fn canonical_snapshot_created_at_ts(tip_block: &Block) -> u64 {
            // Snapshot bundles must be byte-identical across honest peers exporting the
            // same canonical chain window. Using wall-clock export time would make the
            // payload and meta.json diverge cross-peer even when height/state_root are
            // identical. Anchor the timestamp to the checkpoint block instead.
            tip_block.timestamp
        }

        let chunk_size = chunk_size.clamp(SNAPSHOT_V2_CHUNK_MIN_BYTES, SNAPSHOT_V2_CHUNK_MAX_BYTES);
        let max_snapshot_bytes = max_snapshot_bytes.max(1_000_000);
        let export_started_v205 = std::time::Instant::now();
        let export_deadline_ms_v205 = Self::snapshot_export_deadline_ms_v205();
        let progress_every_blocks_v205 = Self::snapshot_export_progress_every_blocks_v205();
        let progress_every_state_nodes_v205 =
            Self::snapshot_export_progress_every_state_nodes_v205();
        ng_info!(
            target: "snapshot.export",
            "event=snapshot_export_storage_start include_state_nodes={} reachable_only={} requested_target_height={:?} requested_window_from={:?} chunk_size={} max_snapshot_bytes={} deadline_ms={}",
            include_state_nodes,
            reachable_only,
            target_height,
            window_from_height,
            chunk_size,
            max_snapshot_bytes,
            export_deadline_ms_v205
        );

        let tip_height = self.meta_get_u64_opt(META_HEIGHT_KEY)?.unwrap_or(0);
        let db_base_height = self.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
        let requested_window_to = target_height.unwrap_or(tip_height);
        let window_to = requested_window_to.min(tip_height);
        if requested_window_to > tip_height {
            ng_warn_throttle!(
                key: format!("snapshot_export_target_height_clamped:{}:{}", requested_window_to, tip_height),
                every_ms: 30_000,
                target: "snapshot.export",
                "event=target_height_clamped requested_height={} tip_height={} effective_height={}",
                requested_window_to,
                tip_height,
                window_to
            );
        }
        let window_from = window_from_height.unwrap_or(db_base_height);
        if window_from < db_base_height {
            return Err(StorageError::BackendError(format!(
                "snapshot window_from {} < db base_height {}",
                window_from, db_base_height
            )));
        }
        if window_from > window_to {
            return Err(StorageError::BackendError(format!(
                "snapshot window_from {} > window_to {}",
                window_from, window_to
            )));
        }
        if window_from > 0 && !include_state_nodes {
            return Err(StorageError::BackendError(format!(
                "snapshot pruned window export requires state nodes: window_from={} window_to={} include_state_nodes=false",
                window_from, window_to
            )));
        }
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "preflight",
            0,
        )?;

        let tipb = self
            .get_block(window_to)?
            .ok_or_else(|| StorageError::BackendError("snapshot missing tip block".to_string()))?;
        let state_root = if tipb.state_root.is_empty() {
            "0".to_string()
        } else {
            tipb.state_root.clone()
        };

        let genesis_hash = self
            .get_block(0)
            .ok()
            .flatten()
            .map(|b| b.hash)
            .or_else(|| {
                self.get_economy_snapshot()
                    .ok()
                    .flatten()
                    .and_then(|(_, js)| {
                        serde_json::from_str::<SnapshotEconomyStateV1>(&js)
                            .ok()
                            .map(|snap| snap.genesis_hash)
                    })
            })
            .unwrap_or_default();

        let (governance_snapshot_height, governance_snapshot_json) = match self
            .get_governance_snapshot()?
        {
            Some((snap_h, snap_js)) => {
                // Validate eagerly so we never export a snapshot with a corrupt governance
                // anchor. Full snapshots may also carry a tip-anchored governance snapshot so
                // post-import runtime rebuild can avoid replaying governance/liveness from
                // genesis when the accompanying state_nodes are reachable-only.
                serde_json::from_str::<GovernanceState>(&snap_js)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                if window_from > 0 {
                    if snap_h >= window_from && snap_h <= window_to {
                        (Some(snap_h), Some(snap_js))
                    } else {
                        return Err(StorageError::BackendError(format!(
                            "snapshot export missing valid governance anchor: snapshot_height={} window=[{}..{}]",
                            snap_h, window_from, window_to
                        )));
                    }
                } else if snap_h == window_to {
                    // Full snapshot: include only a governance snapshot anchored exactly at the
                    // tip. Stale snapshots must not be exported because they would mask replay
                    // drift after import.
                    (Some(snap_h), Some(snap_js))
                } else {
                    (None, None)
                }
            }
            None => {
                if window_from > 0 {
                    return Err(StorageError::BackendError(format!(
                        "snapshot export missing governance snapshot for pruned window [{}..{}]",
                        window_from, window_to
                    )));
                }
                (None, None)
            }
        };

        let (consensus_bootstrap_context, consensus_bootstrap_context_omission_reason) =
            if include_state_nodes && reachable_only {
                match self.build_snapshot_consensus_bootstrap_context(
                    window_from,
                    window_to,
                    &state_root,
                ) {
                    Ok(ctx) => (Some(ctx), None),
                    Err(err) => {
                        let detail = Self::snapshot_bootstrap_context_build_error_message(&err);
                        let omission_reason =
                            Self::classify_snapshot_bootstrap_context_omission_reason(
                                window_to,
                                tip_height,
                                reachable_only,
                                &detail,
                            );
                        match omission_reason {
                            Some(reason) => (None, Some(reason)),
                            None => return Err(err),
                        }
                    }
                }
            } else {
                (None, None)
            };
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "consensus_bootstrap_context",
            window_to,
        )?;

        let governance_snapshot_hash_hex = governance_snapshot_json
            .as_ref()
            .map(|js| sha256_hex(js.as_bytes()));

        let (economy_snapshot_height, economy_snapshot_json, economy_snapshot_hash_hex) = match self
            .economy_snapshot_for_export_height(window_from, window_to)?
        {
            Some((econ_h, econ_json)) => {
                let econ: SnapshotEconomyStateV1 =
                    serde_json::from_str(&econ_json).map_err(|e| {
                        StorageError::BackendError(format!(
                            "snapshot export economy snapshot decode failed: {e}"
                        ))
                    })?;
                econ.validate_basic().map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot export economy snapshot invalid: {e}"
                    ))
                })?;
                if genesis_hash.trim().is_empty() {
                    return Err(StorageError::BackendError(
                        "snapshot export missing genesis hash for economy-bound snapshot"
                            .to_string(),
                    ));
                }
                let genesis_matches = econ.genesis_hash == genesis_hash;
                if econ_h != window_to
                    || econ.height != window_to
                    || econ.base_height != db_base_height
                    || econ.block_hash != tipb.hash
                    || econ.state_root != state_root
                    || !genesis_matches
                {
                    return Err(StorageError::BackendError(format!(
                            "snapshot export economy snapshot binding mismatch height={} indexed_height={} window_to={} stored_base={} db_base={} export_window_from={} block_match={} state_root_match={} genesis_match={}",
                            econ.height,
                            econ_h,
                            window_to,
                            econ.base_height,
                            db_base_height,
                            window_from,
                            econ.block_hash == tipb.hash,
                            econ.state_root == state_root,
                            genesis_matches
                        )));
                }
                self.verify_snapshot_economy_state_against_tip_state_v1(
                    &econ,
                    crate::runtime_mode::public_mode_enabled(),
                )?;
                // The persisted economy sidecar is anchored to the DB retention window.
                // A snapshot export is allowed to choose a narrower retained block window
                // (window_from >= db_base_height) without pruning the local DB first.  The
                // sidecar embedded in the bundle must therefore be rewritten to the bundle
                // base_height, while preserving all tip-bound economic values and policy.
                // Importers verify this rewritten base against the header/base_height.
                let mut export_econ = econ.clone();
                export_econ.base_height = window_from;
                export_econ.policy_hash_hex =
                    SnapshotEconomyStateV1::policy_hash_for(&export_econ.policy).map_err(|e| {
                        StorageError::BackendError(format!(
                            "snapshot export economy policy hash failed: {e}"
                        ))
                    })?;
                export_econ.validate_basic().map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot export rewritten economy snapshot invalid: {e}"
                    ))
                })?;
                let export_econ_json = serde_json::to_string(&export_econ).map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot export economy snapshot serialize failed: {e}"
                    ))
                })?;
                let hash = sha256_hex(export_econ_json.as_bytes());
                (Some(econ_h), Some(export_econ_json), Some(hash))
            }
            None => match self.get_economy_snapshot()? {
                Some((econ_h, _)) => {
                    return Err(StorageError::BackendError(format!(
                            "snapshot export missing economy snapshot for window [{}..{}]: latest stored economy snapshot height={} and no indexed/synthesizable snapshot for target height",
                            window_from, window_to, econ_h
                        )));
                }
                None => {
                    return Err(StorageError::BackendError(format!(
                        "snapshot export missing economy snapshot for window [{}..{}]",
                        window_from, window_to
                    )));
                }
            },
        };

        let rebuild_compute_order_state_store_for_export = |reason: &str| -> StorageResult<
            crate::compute_contract::ComputeOrderStateStoreV1,
        > {
            if window_from > 0 {
                return Err(StorageError::BackendError(format!(
                    "snapshot export pruned window [{}..{}] requires compute order state store sidecar: {reason}",
                    window_from, window_to
                )));
            }
            let chain = self.load_chain()?;
            if chain.first().map(|b| b.index) != Some(0) {
                return Err(StorageError::BackendError(format!(
                    "snapshot export cannot rebuild compute order state store without genesis-complete block window: {reason}"
                )));
            }
            if chain.last().map(|b| b.index).unwrap_or(0) < window_to {
                return Err(StorageError::BackendError(format!(
                    "snapshot export cannot rebuild compute order state store: chain_tip={} window_to={} reason={reason}",
                    chain.last().map(|b| b.index).unwrap_or(0),
                    window_to
                )));
            }
            let required_activation_height = match self.get_governance_snapshot()? {
                Some((_, gov_json)) => {
                    let gov: GovernanceState = serde_json::from_str(&gov_json).map_err(|e| {
                        StorageError::BackendError(format!(
                            "snapshot export governance snapshot decode failed for compute order state rebuild: {e}"
                        ))
                    })?;
                    gov.params.e2_worker_admission_activation_height
                }
                None => 0,
            };
            let upto: Vec<Block> = chain
                .into_iter()
                .take_while(|b| b.index <= window_to)
                .collect();
            let rebuilt =
                crate::compute_contract::compute_order_state_store_rebuild_from_blocks_v1(
                    &upto,
                    required_activation_height,
                )
                .map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot export compute order state store rebuild failed: {e}"
                    ))
                })?;
            self.put_compute_order_state_store_v1(&rebuilt, false)?;
            Ok(rebuilt)
        };

        let bind_compute_order_state_store_for_export = |store: &crate::compute_contract::ComputeOrderStateStoreV1| -> StorageResult<crate::compute_contract::ComputeOrderStateStoreV1> {
            let export_store = crate::compute_contract::compute_order_state_store_bound_to_height_v1(
                store,
                window_to,
                tipb.hash.as_str(),
            )
            .map_err(|e| {
                StorageError::BackendError(format!(
                    "snapshot export compute order state store bind failed: {e}"
                ))
            })?;
            if export_store.last_applied_height != window_to {
                return Err(StorageError::BackendError(format!(
                    "snapshot export compute order state store height mismatch: store_height={} window_to={}",
                    export_store.last_applied_height, window_to
                )));
            }
            if export_store.last_applied_hash != tipb.hash {
                return Err(StorageError::BackendError(format!(
                    "snapshot export compute order state store hash mismatch: store_hash={} snapshot_hash={}",
                    export_store.last_applied_hash, tipb.hash
                )));
            }
            Ok(export_store)
        };

        let export_compute_order_store = match self.get_compute_order_state_store_v1()? {
            Some(store) => match bind_compute_order_state_store_for_export(&store) {
                Ok(export_store) => export_store,
                Err(e) if window_from == 0 => {
                    let rebuilt = rebuild_compute_order_state_store_for_export(&e.to_string())?;
                    bind_compute_order_state_store_for_export(&rebuilt)?
                }
                Err(e) => return Err(e),
            },
            None => {
                let rebuilt = rebuild_compute_order_state_store_for_export("missing_sidecar")?;
                bind_compute_order_state_store_for_export(&rebuilt)?
            }
        };
        let compact_compute_order_store =
            Self::compact_compute_order_state_store_for_snapshot_header_v207(
                &export_compute_order_store,
                window_to,
                tipb.hash.as_str(),
            )?;
        let full_compute_order_sidecar_bytes_v207 = serde_json::to_vec(&export_compute_order_store)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let compute_order_state_store_json = Some(
            serde_json::to_string(&compact_compute_order_store).map_err(|e| {
                StorageError::BackendError(format!(
                    "snapshot export compute order state store serialize failed: {e}"
                ))
            })?,
        );
        let compact_compute_order_sidecar_bytes_v207 = compute_order_state_store_json
            .as_ref()
            .map(|js| js.as_bytes().len())
            .unwrap_or(0);
        if compact_compute_order_sidecar_bytes_v207 < full_compute_order_sidecar_bytes_v207 {
            ng_info!(
                target: "snapshot.export",
                "event=snapshot_compute_order_sidecar_compacted_v207 window_to={} full_bytes={} compact_bytes={} orders={} metadata={} action=keep_materialized_e2_state_drop_historical_event_journal",
                window_to,
                full_compute_order_sidecar_bytes_v207,
                compact_compute_order_sidecar_bytes_v207,
                compact_compute_order_store.orders.len(),
                compact_compute_order_store.metadata_by_order_id.len()
            );
        }
        let compute_order_state_store_hash_hex = compute_order_state_store_json
            .as_ref()
            .map(|js| sha256_hex(js.as_bytes()));

        let finality_meta_for_snapshot =
            self.finality_bft_meta_for_snapshot_export_v209(window_from, window_to)?;
        let (
            finalized_height,
            finalized_hash,
            highest_qc_height,
            highest_qc_round,
            highest_qc_block_hash,
            finality_source,
            finality_binding_version,
        ) = match finality_meta_for_snapshot.as_ref() {
            Some(meta) => (
                Some(meta.finalized_height),
                Some(meta.finalized_hash.clone()),
                Some(meta.highest_qc_height),
                Some(meta.highest_qc_round),
                Some(meta.highest_qc_block_hash.clone()),
                Some("storage_finality_bft_meta_v1".to_string()),
                Some(1u32),
            ),
            None => (None, None, None, None, None, None, None),
        };

        let canonical_created_at_ts = canonical_snapshot_created_at_ts(&tipb);
        let hdr = HeaderV2 {
            version: 2,
            base_height: window_from,
            window_from,
            window_to,
            include_state_nodes,
            reachable_only,
            snapshot_height: window_to,
            snapshot_block_hash: tipb.hash.clone(),
            snapshot_state_root: state_root.clone(),
            genesis_hash: genesis_hash.clone(),
            created_at_ts: Some(canonical_created_at_ts),
            finalized_height,
            finalized_hash: finalized_hash.clone(),
            highest_qc_height,
            highest_qc_round,
            highest_qc_block_hash: highest_qc_block_hash.clone(),
            finality_source: finality_source.clone(),
            finality_binding_version,
            governance_snapshot_height,
            governance_snapshot_json: governance_snapshot_json.clone(),
            governance_snapshot_hash_hex: governance_snapshot_hash_hex.clone(),
            economy_snapshot_height,
            economy_snapshot_json: economy_snapshot_json.clone(),
            economy_snapshot_hash_hex: economy_snapshot_hash_hex.clone(),
            compute_order_state_store_json: compute_order_state_store_json.clone(),
            compute_order_state_store_hash_hex: compute_order_state_store_hash_hex.clone(),
        };

        let hdr_bytes =
            serde_json::to_vec(&hdr).map_err(|e| StorageError::BackendError(e.to_string()))?;
        let (
            governance_sidecar_bytes,
            economy_sidecar_bytes,
            compute_order_sidecar_bytes,
            sidecar_bytes,
        ) = snapshot_v2_sidecar_bytes(
            &governance_snapshot_json,
            &economy_snapshot_json,
            &compute_order_state_store_json,
        );
        let header_warn_bytes = snapshot_v2_header_warn_bytes();
        if hdr_bytes.len() > header_warn_bytes {
            ng_warn!(
                target: "snapshot.export",
                "event=snapshot_v2_header_large_sidecars window_from={} window_to={} header_bytes={} warn_bytes={} sidecar_bytes={} governance_sidecar_bytes={} economy_sidecar_bytes={} compute_order_sidecar_bytes={} action=warn_keep_export_compatible",
                window_from,
                window_to,
                hdr_bytes.len(),
                header_warn_bytes,
                sidecar_bytes,
                governance_sidecar_bytes,
                economy_sidecar_bytes,
                compute_order_sidecar_bytes
            );
        }
        let header_max_bytes = snapshot_v2_header_max_bytes();
        if hdr_bytes.len() > header_max_bytes {
            return Err(StorageError::BackendError(format!(
                "snapshot v2 header too large for export: {} (max={}) sidecar_bytes={} governance_sidecar_bytes={} economy_sidecar_bytes={} compute_order_sidecar_bytes={}",
                hdr_bytes.len(),
                header_max_bytes,
                sidecar_bytes,
                governance_sidecar_bytes,
                economy_sidecar_bytes,
                compute_order_sidecar_bytes
            )));
        }

        let out_dir = out_dir.as_ref();
        let parent = out_dir.parent().unwrap_or_else(|| Path::new("."));
        let tmp_dir = parent.join(format!(
            ".tmp_ngsnap_v2_{}_{}",
            window_to,
            std::process::id()
        ));
        if tmp_dir.exists() {
            fs::remove_dir_all(&tmp_dir).map_err(|e| StorageError::BackendError(e.to_string()))?;
        }
        let chunks_dir = tmp_dir.join("chunks");
        fs::create_dir_all(&chunks_dir).map_err(|e| StorageError::BackendError(e.to_string()))?;

        let mut cw =
            SnapshotV2ChunkWriter::new(chunks_dir.clone(), chunk_size, max_snapshot_bytes)?;

        cw.write_all(b"NGSNAP02")?;
        cw.write_all(&(hdr_bytes.len() as u32).to_be_bytes())?;
        cw.write_all(&hdr_bytes)?;

        for idx in window_from..=window_to {
            let exported_blocks = idx.saturating_sub(window_from).saturating_add(1);
            if exported_blocks == 1 || exported_blocks % progress_every_blocks_v205 == 0 {
                Self::snapshot_check_deadline_v205(
                    export_started_v205,
                    export_deadline_ms_v205,
                    "write_blocks",
                    exported_blocks,
                )?;
                ng_info_throttle!(
                    key: format!("snapshot_export_write_blocks_progress:{}:{}", window_from, window_to),
                    every_ms: 10_000,
                    target: "snapshot.export",
                    "event=snapshot_export_progress stage=write_blocks exported_blocks={} window_from={} window_to={} elapsed_ms={} deadline_ms={}",
                    exported_blocks,
                    window_from,
                    window_to,
                    Self::snapshot_elapsed_ms_v205(export_started_v205),
                    export_deadline_ms_v205
                );
            }
            let b = self.get_block(idx)?.ok_or_else(|| {
                StorageError::BackendError(format!("snapshot missing block {}", idx))
            })?;
            let bytes =
                serde_json::to_vec(&b).map_err(|e| StorageError::BackendError(e.to_string()))?;
            cw.write_all(&(bytes.len() as u32).to_be_bytes())?;
            cw.write_all(&bytes)?;
        }
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "write_blocks",
            window_to.saturating_sub(window_from).saturating_add(1),
        )?;

        if include_state_nodes {
            let max_state_nodes = env_u64("NG_SNAPSHOT_V2_MAX_STATE_NODES", 50_000_000);
            let node_hashes: Vec<[u8; 32]> = if reachable_only {
                self.collect_reachable_state_nodes_for_snapshot_export_v205(
                    &state_root,
                    max_state_nodes,
                    export_started_v205,
                    export_deadline_ms_v205,
                    progress_every_state_nodes_v205,
                )?
            } else {
                let mut out: Vec<[u8; 32]> = Vec::new();
                for item in self.iter_all_cf(ColumnFamily::StateNodes)? {
                    if out.is_empty() || (out.len() as u64) % progress_every_state_nodes_v205 == 0 {
                        Self::snapshot_check_deadline_v205(
                            export_started_v205,
                            export_deadline_ms_v205,
                            "collect_all_state_nodes",
                            out.len() as u64,
                        )?;
                        ng_info_throttle!(
                            key: format!("snapshot_export_collect_all_state_nodes_progress:{}", window_to),
                            every_ms: 10_000,
                            target: "snapshot.export",
                            "event=snapshot_export_progress stage=collect_all_state_nodes collected={} elapsed_ms={} deadline_ms={}",
                            out.len(),
                            Self::snapshot_elapsed_ms_v205(export_started_v205),
                            export_deadline_ms_v205
                        );
                    }
                    let (k, _v) = item?;
                    if k.len() != 32 {
                        continue;
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&k[..]);
                    out.push(a);
                    if out.len() as u64 > max_state_nodes {
                        return Err(StorageError::BackendError(format!(
                            "snapshot too many state_nodes: {} (max={})",
                            out.len(),
                            max_state_nodes
                        )));
                    }
                }
                Self::snapshot_check_deadline_v205(
                    export_started_v205,
                    export_deadline_ms_v205,
                    "collect_all_state_nodes",
                    out.len() as u64,
                )?;
                out.sort();
                out
            };

            let node_hash_count_v205 = node_hashes.len() as u64;
            cw.write_all(&node_hash_count_v205.to_be_bytes())?;

            let max_state_node_bytes = env_usize("NG_SNAPSHOT_V2_MAX_STATE_NODE_BYTES", 256 * 1024);
            for (state_node_idx, h) in node_hashes.into_iter().enumerate() {
                let written_nodes = state_node_idx as u64;
                if written_nodes == 0 || written_nodes % progress_every_state_nodes_v205 == 0 {
                    Self::snapshot_check_deadline_v205(
                        export_started_v205,
                        export_deadline_ms_v205,
                        "write_state_nodes",
                        written_nodes,
                    )?;
                    ng_info_throttle!(
                        key: format!("snapshot_export_write_state_nodes_progress:{}", window_to),
                        every_ms: 10_000,
                        target: "snapshot.export",
                        "event=snapshot_export_progress stage=write_state_nodes written_nodes={} elapsed_ms={} deadline_ms={}",
                        written_nodes,
                        Self::snapshot_elapsed_ms_v205(export_started_v205),
                        export_deadline_ms_v205
                    );
                }
                let v = self.get(ColumnFamily::StateNodes, &h[..])?.ok_or_else(|| {
                    StorageError::BackendError("snapshot state_node missing".to_string())
                })?;
                if v.is_empty() || v.len() > max_state_node_bytes {
                    return Err(StorageError::BackendError(format!(
                        "snapshot state_node blob too large: {} (max={})",
                        v.len(),
                        max_state_node_bytes
                    )));
                }
                cw.write_all(&h)?;
                cw.write_all(&(v.len() as u32).to_be_bytes())?;
                cw.write_all(&v)?;
            }
            Self::snapshot_check_deadline_v205(
                export_started_v205,
                export_deadline_ms_v205,
                "write_state_nodes",
                node_hash_count_v205,
            )?;
        } else {
            cw.write_all(&0u64.to_be_bytes())?;
        }

        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "finish_chunks",
            0,
        )?;
        let (total_bytes, chunk_hashes) = cw.finish()?;
        let chunks = chunk_hashes.len() as u32;
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "build_meta",
            chunks as u64,
        )?;

        let state_coverage_mode = if !include_state_nodes {
            SnapshotStateCoverageMode::NoStateNodes
        } else if reachable_only {
            SnapshotStateCoverageMode::TipReachableOnly
        } else {
            SnapshotStateCoverageMode::FullHistoricalState
        };
        let historical_state_roots_queryable = include_state_nodes && !reachable_only;
        let validator_bootstrap_capable = match state_coverage_mode {
            SnapshotStateCoverageMode::NoStateNodes => false,
            SnapshotStateCoverageMode::TipReachableOnly => consensus_bootstrap_context.is_some(),
            SnapshotStateCoverageMode::FullHistoricalState => historical_state_roots_queryable,
        };
        let snapshot_bootstrap_role = match state_coverage_mode {
            SnapshotStateCoverageMode::FullHistoricalState => {
                SnapshotBootstrapRole::HistoricalStateArchive
            }
            SnapshotStateCoverageMode::TipReachableOnly if validator_bootstrap_capable => {
                SnapshotBootstrapRole::ValidatorBootstrap
            }
            _ => SnapshotBootstrapRole::ReadOnlyTipState,
        };

        let meta = SnapshotMeta {
            version: 2,
            height: window_to,
            base_height: window_from,
            bytes_len: total_bytes,
            chunk_size: chunk_size as u32,
            chunks,
            chunk_hashes_hex: chunk_hashes,
            state_root,
            checkpoint_block_hash: tipb.hash.clone(),
            genesis_hash,
            created_at_ts: canonical_created_at_ts,
            window_from_height: window_from,
            window_to_height: window_to,
            include_state_nodes,
            reachable_state_nodes: include_state_nodes && reachable_only,
            state_coverage_mode,
            historical_state_roots_queryable,
            validator_bootstrap_capable,
            snapshot_bootstrap_role,
            governance_snapshot_height,
            governance_snapshot_hash_hex,
            // The full governance sidecar is already bound inside the hashed
            // snapshot payload header (HeaderV2). Keep meta.json as a bounded
            // manifest so RRv3 discovery remains transport-safe. Legacy import
            // still accepts older bundles whose meta.json carried this sidecar.
            governance_snapshot_json: None,
            economy_snapshot_height,
            economy_snapshot_hash_hex,
            finalized_height,
            finalized_hash,
            highest_qc_height,
            highest_qc_round,
            highest_qc_block_hash,
            finality_source,
            finality_binding_version,
            compute_order_state_store_hash_hex,
            // The full compute-order sidecar is already bound inside the
            // hashed snapshot payload header (HeaderV2). Keep meta.json as a
            // bounded manifest so RRv3 discovery and latest snapshot metadata
            // stay transport-safe. Import remains backward-compatible with
            // older bundles whose meta.json still carried the full sidecar.
            compute_order_state_store_json: None,
            consensus_bootstrap_context,
            consensus_bootstrap_context_omission_reason,
        };
        meta.validate_basic().map_err(StorageError::BackendError)?;
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "write_meta",
            chunks as u64,
        )?;

        let meta_bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let meta_tmp = tmp_dir.join("meta.json.tmp");
        let meta_final = tmp_dir.join("meta.json");
        fs::write(&meta_tmp, meta_bytes).map_err(|e| StorageError::BackendError(e.to_string()))?;
        crate::utils::atomic_replace_file_v1(&meta_tmp, &meta_final)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;

        // Do not delete the currently served bundle until the replacement has been fully
        // materialized and validated. Directory replacement cannot be a single portable
        // atomic operation on all supported platforms, so keep the old bundle as a backup
        // and restore it if the publish step fails. This avoids leaving `latest` empty or
        // permanently broken during an interrupted export.
        //
        // V206 hardening: perform the final deadline check *before* moving the currently
        // served bundle aside. In V205 the check happened after `out_dir -> backup_dir`,
        // which meant a deadline error at publish time could return early with no active
        // `latest/bootstrap_latest` directory. Once the old bundle is moved, the publish
        // section must either install the new bundle or restore the old one.
        Self::snapshot_check_deadline_v205(
            export_started_v205,
            export_deadline_ms_v205,
            "publish_bundle_preflight",
            chunks as u64,
        )?;
        let backup_dir = parent.join(format!(
            ".old_ngsnap_v2_{}_{}",
            window_to,
            std::process::id()
        ));
        if backup_dir.exists() {
            fs::remove_dir_all(&backup_dir)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
        }
        if out_dir.exists() {
            fs::rename(out_dir, &backup_dir).map_err(|e| {
                StorageError::BackendError(format!(
                    "snapshot v2 publish failed to move existing bundle aside: {e}"
                ))
            })?;
        }
        match fs::rename(&tmp_dir, out_dir) {
            Ok(()) => {
                if backup_dir.exists() {
                    let _ = fs::remove_dir_all(&backup_dir);
                }
            }
            Err(e) => {
                if backup_dir.exists() && !out_dir.exists() {
                    let _ = fs::rename(&backup_dir, out_dir);
                }
                return Err(StorageError::BackendError(format!(
                    "snapshot v2 publish failed after staging complete; old bundle restored if possible: {e}"
                )));
            }
        }

        ng_info!(
            target: "snapshot.export",
            "event=snapshot_export_storage_ok height={} window_from={} chunks={} bytes={} elapsed_ms={} deadline_ms={}",
            meta.height,
            meta.window_from_height,
            meta.chunks,
            meta.bytes_len,
            Self::snapshot_elapsed_ms_v205(export_started_v205),
            export_deadline_ms_v205
        );
        Ok(meta)
    }

    fn normalize_imported_snapshot_nft_events_v1(
        &self,
        window_from: u64,
        window_to: u64,
        state_coverage_mode: SnapshotStateCoverageMode,
        historical_state_roots_queryable: bool,
    ) -> StorageResult<()> {
        if window_from > window_to {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: nft event normalize invalid window [{}..{}]",
                window_from, window_to
            )));
        }
        let mut blocks =
            Vec::with_capacity(window_to.saturating_sub(window_from).saturating_add(1) as usize);
        for height in window_from..=window_to {
            let block = self.get_block(height)?.ok_or_else(|| {
                StorageError::BackendError(format!(
                    "snapshot v2: nft event normalize missing block {}",
                    height
                ))
            })?;
            blocks.push(block);
        }
        if blocks.is_empty() {
            return Ok(());
        }
        let has_nft_surface = blocks.iter().any(|block| {
            !block.nft_events.is_empty() || block.transactions.iter().any(crate::nft::is_nft_tx)
        });
        if !has_nft_surface {
            return Ok(());
        }

        let can_recompute_from_genesis = window_from == 0;
        let can_recompute_after_base = state_coverage_mode
            == SnapshotStateCoverageMode::FullHistoricalState
            && historical_state_roots_queryable;

        if !can_recompute_from_genesis && !can_recompute_after_base {
            let mut changed = 0u64;
            for mut block in blocks {
                if !block.nft_events.is_empty() {
                    block.nft_events.clear();
                    self.append_block_inner(&block, false)?;
                    changed = changed.saturating_add(1);
                }
            }
            if changed > 0 {
                ng_warn!(target: "snapshot.import", "event=nft_events_cleared_unverifiable window_from={} window_to={} changed_blocks={} state_coverage_mode={:?}", window_from, window_to, changed, state_coverage_mode);
            }
            return Ok(());
        }

        let verifier = Blockchain::from_blocks_with_storage(blocks.clone(), Arc::new(self.clone()));
        let mut changed = 0u64;
        let mut skipped_base = false;

        for (pos, original) in blocks.iter().enumerate() {
            if pos == 0 && !can_recompute_from_genesis {
                if !original.nft_events.is_empty() {
                    let mut sanitized = original.clone();
                    sanitized.nft_events.clear();
                    self.append_block_inner(&sanitized, false)?;
                    changed = changed.saturating_add(1);
                    skipped_base = true;
                }
                continue;
            }

            let prev_root = if pos == 0 {
                ""
            } else {
                blocks[pos - 1].state_root.as_str()
            };
            let (expected_root, expected_events) = verifier
                .recompute_nft_events_for_block_v1(prev_root, original)
                .map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot v2: nft event recompute failed at height {}: {}",
                        original.index, e
                    ))
                })?;
            if expected_root != original.state_root {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: nft event recompute state_root mismatch at height {} expected={} got={}",
                    original.index, expected_root, original.state_root
                )));
            }
            if expected_events != original.nft_events {
                let mut normalized = original.clone();
                normalized.nft_events = expected_events;
                self.append_block_inner(&normalized, false)?;
                changed = changed.saturating_add(1);
            }
        }

        if changed > 0 || skipped_base {
            ng_info!(target: "snapshot.import", "event=nft_events_normalized window_from={} window_to={} changed_blocks={} skipped_unverifiable_base={}", window_from, window_to, changed, skipped_base);
        }

        Ok(())
    }

    /// Import snapshot bundle (v2). Crash-safe via journal.
    pub fn import_snapshot_v2_bundle<P: AsRef<Path>>(
        &self,
        bundle_dir: P,
        wipe_state_nodes: bool,
    ) -> StorageResult<()> {
        let bundle_dir = bundle_dir.as_ref();
        let meta_path = bundle_dir.join("meta.json");
        let chunks_dir = bundle_dir.join("chunks");

        let meta_bytes =
            fs::read(&meta_path).map_err(|e| StorageError::BackendError(e.to_string()))?;
        let meta: SnapshotMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        meta.validate_basic().map_err(StorageError::BackendError)?;

        let skip_verify = std::env::var("NG_SNAPSHOT_V2_SKIP_HASH_VERIFY")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if skip_verify && crate::runtime_mode::public_mode_enabled() {
            return Err(StorageError::BackendError(
                "NG_SNAPSHOT_V2_SKIP_HASH_VERIFY is forbidden in public mode".to_string(),
            ));
        }
        let verified_payload_bytes = if !skip_verify {
            Some(verify_snapshot_v2_chunks(&chunks_dir, &meta)?)
        } else {
            ng_warn!(
                target: "snapshot.import",
                "event=snapshot_v2_hash_verify_skipped reason=dev_test_env_flag flag=NG_SNAPSHOT_V2_SKIP_HASH_VERIFY"
            );
            None
        };
        if let Some(total) = verified_payload_bytes {
            if total != meta.bytes_len {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: payload bytes mismatch meta={} actual={}",
                    meta.bytes_len, total
                )));
            }
        }

        let mut r = SnapshotV2ChunkReader::new(chunks_dir.clone(), meta.chunks)?;

        let max_hdr = snapshot_v2_header_max_bytes();
        let header_warn_bytes = snapshot_v2_header_warn_bytes();
        let max_block = env_usize("NG_SNAPSHOT_MAX_BLOCK_BYTES", 64 * 1024 * 1024);
        let max_state_nodes = env_u64("NG_SNAPSHOT_MAX_STATE_NODES", 50_000_000);
        let max_state_node_bytes = env_usize("NG_SNAPSHOT_MAX_STATE_NODE_BYTES", 256 * 1024);
        let max_height = env_u64("NG_SNAPSHOT_MAX_HEIGHT", 5_000_000);

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        if &magic != b"NGSNAP02" {
            return Err(StorageError::BackendError(
                "snapshot v2 bad magic".to_string(),
            ));
        }

        let mut lenb = [0u8; 4];
        r.read_exact(&mut lenb)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let hdr_len = u32::from_be_bytes(lenb) as usize;
        if hdr_len == 0 || hdr_len > max_hdr {
            return Err(StorageError::BackendError(format!(
                "snapshot header too large: {} (max={})",
                hdr_len, max_hdr
            )));
        }
        if hdr_len > header_warn_bytes {
            ng_warn!(
                target: "snapshot.import",
                "event=snapshot_v2_header_large hdr_bytes={} warn_bytes={} max_bytes={} action=continue_validating_hash_bound_payload",
                hdr_len,
                header_warn_bytes,
                max_hdr
            );
        }

        let mut hbuf = vec![0u8; hdr_len];
        r.read_exact(&mut hbuf)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;

        #[derive(Serialize, Deserialize)]
        struct HeaderV2 {
            version: u32,
            base_height: u64,
            window_from: u64,
            window_to: u64,
            include_state_nodes: bool,
            reachable_only: bool,
            snapshot_height: u64,
            snapshot_block_hash: String,
            snapshot_state_root: String,
            genesis_hash: String,
            #[serde(default)]
            created_at_ts: Option<u64>,
            #[serde(default)]
            finalized_height: Option<u64>,
            #[serde(default)]
            finalized_hash: Option<String>,
            #[serde(default)]
            highest_qc_height: Option<u64>,
            #[serde(default)]
            highest_qc_round: Option<u32>,
            #[serde(default)]
            highest_qc_block_hash: Option<String>,
            #[serde(default)]
            finality_source: Option<String>,
            #[serde(default)]
            finality_binding_version: Option<u32>,
            #[serde(default)]
            governance_snapshot_height: Option<u64>,
            #[serde(default)]
            governance_snapshot_json: Option<String>,
            #[serde(default)]
            governance_snapshot_hash_hex: Option<String>,
            #[serde(default)]
            economy_snapshot_height: Option<u64>,
            #[serde(default)]
            economy_snapshot_json: Option<String>,
            #[serde(default)]
            economy_snapshot_hash_hex: Option<String>,
            #[serde(default)]
            compute_order_state_store_json: Option<String>,
            #[serde(default)]
            compute_order_state_store_hash_hex: Option<String>,
        }

        let hdr: HeaderV2 =
            serde_json::from_slice(&hbuf).map_err(|e| StorageError::BackendError(e.to_string()))?;
        if hdr.version < 2 {
            return Err(StorageError::BackendError(
                "snapshot v2: bad header version".to_string(),
            ));
        }
        if hdr.window_to > max_height {
            return Err(StorageError::BackendError(format!(
                "snapshot height too large: {} (max={})",
                hdr.window_to, max_height
            )));
        }
        if hdr.window_from > hdr.window_to {
            return Err(StorageError::BackendError(
                "snapshot window invalid".to_string(),
            ));
        }
        if hdr.snapshot_height != hdr.window_to {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: header snapshot_height/window_to mismatch: {} vs {}",
                hdr.snapshot_height, hdr.window_to
            )));
        }
        if hdr.base_height != hdr.window_from {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: header base_height/window_from mismatch: {} vs {}",
                hdr.base_height, hdr.window_from
            )));
        }

        if meta.version != 2 || hdr.version != 2 {
            return Err(StorageError::BackendError(
                "snapshot v2: only version=2 bundles are accepted".to_string(),
            ));
        }
        if meta.height != hdr.snapshot_height {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: meta.height/header.snapshot_height mismatch: {} vs {}",
                meta.height, hdr.snapshot_height
            )));
        }
        if meta.base_height != hdr.base_height {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: meta.base_height/header.base_height mismatch: {} vs {}",
                meta.base_height, hdr.base_height
            )));
        }
        if meta.window_from_height != hdr.window_from || meta.window_to_height != hdr.window_to {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: meta.window/header.window mismatch: [{},{}] vs [{},{}]",
                meta.window_from_height, meta.window_to_height, hdr.window_from, hdr.window_to
            )));
        }
        if meta.include_state_nodes != hdr.include_state_nodes {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: meta.include_state_nodes/header mismatch: {} vs {}",
                meta.include_state_nodes, hdr.include_state_nodes
            )));
        }
        if hdr.base_height > 0 && !hdr.include_state_nodes {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: pruned bundle requires state nodes: base_height={} include_state_nodes=false",
                hdr.base_height
            )));
        }
        if meta.reachable_state_nodes != (hdr.include_state_nodes && hdr.reachable_only) {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: meta.reachable_state_nodes/header mismatch: {} vs {}",
                meta.reachable_state_nodes,
                hdr.include_state_nodes && hdr.reachable_only
            )));
        }
        if meta.state_root != hdr.snapshot_state_root {
            return Err(StorageError::BackendError(
                "snapshot v2: meta.state_root/header snapshot_state_root mismatch".to_string(),
            ));
        }
        if meta.checkpoint_block_hash != hdr.snapshot_block_hash {
            return Err(StorageError::BackendError(
                "snapshot v2: meta.checkpoint_block_hash/header snapshot_block_hash mismatch"
                    .to_string(),
            ));
        }
        if meta.genesis_hash != hdr.genesis_hash {
            return Err(StorageError::BackendError(
                "snapshot v2: meta.genesis_hash/header genesis_hash mismatch".to_string(),
            ));
        }
        match hdr.created_at_ts {
            Some(header_created_at_ts) if meta.created_at_ts != header_created_at_ts => {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: meta.created_at_ts/header mismatch: {} vs {}",
                    meta.created_at_ts, header_created_at_ts
                )));
            }
            None if crate::runtime_mode::public_mode_enabled() => {
                return Err(StorageError::BackendError(
                    "snapshot v2: public import requires created_at_ts in hash-bound header"
                        .to_string(),
                ));
            }
            _ => {}
        }

        let validated_finality_meta: Option<PersistedFinalityBftMetaV1> = match (
            hdr.finalized_height,
            hdr.finalized_hash.as_ref(),
            hdr.highest_qc_height,
            hdr.highest_qc_round,
            hdr.highest_qc_block_hash.as_ref(),
            hdr.finality_binding_version,
            meta.finalized_height,
            meta.finalized_hash.as_ref(),
            meta.highest_qc_height,
            meta.highest_qc_round,
            meta.highest_qc_block_hash.as_ref(),
            meta.finality_binding_version,
        ) {
            (
                Some(finalized_height),
                Some(finalized_hash),
                Some(highest_qc_height),
                Some(highest_qc_round),
                Some(highest_qc_block_hash),
                Some(binding_version),
                Some(meta_finalized_height),
                Some(meta_finalized_hash),
                Some(meta_highest_qc_height),
                Some(meta_highest_qc_round),
                Some(meta_highest_qc_block_hash),
                Some(meta_binding_version),
            ) => {
                if finalized_height != meta_finalized_height
                    || finalized_hash != meta_finalized_hash
                    || highest_qc_height != meta_highest_qc_height
                    || highest_qc_round != meta_highest_qc_round
                    || highest_qc_block_hash != meta_highest_qc_block_hash
                    || binding_version != meta_binding_version
                {
                    return Err(StorageError::BackendError(
                        "snapshot v2: meta/header finality binding mismatch".to_string(),
                    ));
                }
                if binding_version != 1 {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: unsupported finality_binding_version {}",
                        binding_version
                    )));
                }
                if finalized_height > hdr.window_to || highest_qc_height > hdr.window_to {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: finality binding exceeds snapshot height finalized={} highest_qc={} height={}",
                        finalized_height, highest_qc_height, hdr.window_to
                    )));
                }
                if finalized_height > highest_qc_height {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: finalized_height {} exceeds highest_qc_height {}",
                        finalized_height, highest_qc_height
                    )));
                }
                if hdr.base_height > 0 {
                    if finalized_height < hdr.base_height {
                        return Err(StorageError::BackendError(format!(
                            "snapshot v2: finalized_height {} below base_height {}",
                            finalized_height, hdr.base_height
                        )));
                    }
                    if hdr.window_to > hdr.base_height.saturating_add(1)
                        && finalized_height == hdr.base_height
                    {
                        return Err(StorageError::BackendError(format!(
                            "snapshot v2: refusing base_height-as-finality fallback finalized_height={} snapshot_height={}",
                            finalized_height, hdr.window_to
                        )));
                    }
                }
                Some(PersistedFinalityBftMetaV1 {
                    finalized_height,
                    finalized_hash: finalized_hash.to_string(),
                    highest_qc_height,
                    highest_qc_round,
                    highest_qc_block_hash: highest_qc_block_hash.to_string(),
                })
            }
            (None, None, None, None, None, None, None, None, None, None, None, None)
                if hdr.base_height == 0 =>
            {
                None
            }
            (None, None, None, None, None, None, None, None, None, None, None, None) => {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: pruned bundle missing explicit finalized head: base_height={} height={}",
                    hdr.base_height, hdr.window_to
                )));
            }
            _ => {
                return Err(StorageError::BackendError(
                    "snapshot v2: finality binding fields incomplete".to_string(),
                ));
            }
        };

        let validated_economy_snapshot: Option<(u64, String)> = match (
            hdr.economy_snapshot_height,
            hdr.economy_snapshot_json.as_ref(),
            hdr.economy_snapshot_hash_hex.as_ref(),
        ) {
            (None, None, None) => {
                return Err(StorageError::BackendError(
                    "snapshot v2: bundle missing economy snapshot".to_string(),
                ));
            }
            (Some(econ_h), Some(econ_json), Some(econ_hash)) => {
                if meta.economy_snapshot_height != Some(econ_h)
                    || meta.economy_snapshot_hash_hex.as_deref() != Some(econ_hash.as_str())
                {
                    return Err(StorageError::BackendError(
                        "snapshot v2: meta/header economy snapshot mismatch".to_string(),
                    ));
                }
                let actual_hash = sha256_hex(econ_json.as_bytes());
                if actual_hash != *econ_hash {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: economy snapshot hash mismatch: meta/header={} actual={}",
                        econ_hash, actual_hash
                    )));
                }
                let econ: SnapshotEconomyStateV1 =
                    serde_json::from_str(econ_json).map_err(|e| {
                        StorageError::BackendError(format!(
                            "snapshot v2: economy snapshot decode failed: {e}"
                        ))
                    })?;
                econ.validate_basic().map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot v2: economy snapshot invalid: {e}"
                    ))
                })?;
                if hdr.genesis_hash.trim().is_empty() {
                    return Err(StorageError::BackendError(
                        "snapshot v2: header genesis_hash missing for economy-bound snapshot"
                            .to_string(),
                    ));
                }
                let genesis_matches = econ.genesis_hash == hdr.genesis_hash;
                if econ.height != hdr.window_to
                    || econ.base_height != hdr.base_height
                    || econ.block_hash != hdr.snapshot_block_hash
                    || econ.state_root != hdr.snapshot_state_root
                    || !genesis_matches
                {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: economy snapshot binding mismatch height={} window_to={} base={} base_height={} block_match={} state_root_match={} genesis_match={}",
                        econ.height,
                        hdr.window_to,
                        econ.base_height,
                        hdr.base_height,
                        econ.block_hash == hdr.snapshot_block_hash,
                        econ.state_root == hdr.snapshot_state_root,
                        genesis_matches
                    )));
                }
                Some((econ_h, econ_json.clone()))
            }
            _ => {
                return Err(StorageError::BackendError(
                    "snapshot v2: economy snapshot header fields incomplete".to_string(),
                ));
            }
        };

        let validated_compute_order_state_store: Option<
            crate::compute_contract::ComputeOrderStateStoreV1,
        > = match (
            hdr.compute_order_state_store_json.as_ref(),
            hdr.compute_order_state_store_hash_hex.as_ref(),
        ) {
            (Some(js), Some(hash)) => {
                if meta.compute_order_state_store_hash_hex.as_deref() != Some(hash.as_str()) {
                    return Err(StorageError::BackendError(
                        "snapshot v2: meta/header compute order state store hash mismatch"
                            .to_string(),
                    ));
                }
                let actual_hash = sha256_hex(js.as_bytes());
                if actual_hash != *hash {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: compute order state store hash mismatch: meta/header={} actual={}",
                        hash, actual_hash
                    )));
                }
                let store: crate::compute_contract::ComputeOrderStateStoreV1 =
                    serde_json::from_str(js).map_err(|e| {
                        StorageError::BackendError(format!(
                            "snapshot v2: compute order state store decode failed: {e}"
                        ))
                    })?;
                if !store.complete_from_genesis || store.first_applied_height != 0 {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: compute order state store not genesis-complete:first_applied_height={} complete_from_genesis={}",
                        store.first_applied_height, store.complete_from_genesis
                    )));
                }
                if store.last_applied_height != hdr.window_to {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: compute order state store height mismatch: store_height={} window_to={}",
                        store.last_applied_height, hdr.window_to
                    )));
                }
                if store.last_applied_hash != hdr.snapshot_block_hash {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: compute order state store hash mismatch: store_hash={} snapshot_hash={}",
                        store.last_applied_hash, hdr.snapshot_block_hash
                    )));
                }
                Some(store)
            }
            (None, None) if hdr.base_height == 0 && !crate::runtime_mode::public_mode_enabled() => {
                None
            }
            (None, None) => {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: public/pruned bundle missing compute order state store sidecar: base_height={} public_mode={}",
                    hdr.base_height,
                    crate::runtime_mode::public_mode_enabled()
                )));
            }
            _ => {
                return Err(StorageError::BackendError(
                    "snapshot v2: compute order state store header fields incomplete".to_string(),
                ));
            }
        };

        if let Some(ctx) = meta.consensus_bootstrap_context.as_ref() {
            ctx.validate_basic(meta.height, &meta.state_root)
                .map_err(StorageError::BackendError)?;
        }

        let validated_governance_snapshot: Option<(u64, String)> = match (
            hdr.governance_snapshot_height,
            hdr.governance_snapshot_json.as_ref(),
            hdr.governance_snapshot_hash_hex.as_ref(),
            meta.governance_snapshot_height,
            meta.governance_snapshot_json.as_ref(),
            meta.governance_snapshot_hash_hex.as_ref(),
        ) {
            (Some(gov_h), Some(gov_json), Some(gov_hash), meta_h, _legacy_json, meta_hash) => {
                if meta_h != Some(gov_h) || meta_hash.map(|s| s.as_str()) != Some(gov_hash.as_str())
                {
                    return Err(StorageError::BackendError(
                        "snapshot v2: meta/header governance snapshot mismatch".to_string(),
                    ));
                }
                if gov_h < hdr.base_height || gov_h > hdr.window_to {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: governance snapshot height {} outside [{},{}]",
                        gov_h, hdr.base_height, hdr.window_to
                    )));
                }
                let actual_hash = sha256_hex(gov_json.as_bytes());
                if actual_hash != *gov_hash {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: governance snapshot hash mismatch: meta/header={} actual={}",
                        gov_hash, actual_hash
                    )));
                }
                serde_json::from_str::<GovernanceState>(gov_json).map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot v2: governance snapshot decode failed: {e}"
                    ))
                })?;
                Some((gov_h, gov_json.clone()))
            }
            (None, None, None, Some(gov_h), Some(gov_json), maybe_hash) => {
                // Backward compatibility: older bundles carried the governance sidecar
                // directly in meta.json. Accept them, and verify the optional hash when
                // present, but new bundles must carry the full sidecar in HeaderV2.
                if gov_h < hdr.base_height || gov_h > hdr.window_to {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: legacy governance snapshot height {} outside [{},{}]",
                        gov_h, hdr.base_height, hdr.window_to
                    )));
                }
                if let Some(expected_hash) = maybe_hash {
                    let actual_hash = sha256_hex(gov_json.as_bytes());
                    if actual_hash != *expected_hash {
                        return Err(StorageError::BackendError(format!(
                            "snapshot v2: legacy governance snapshot hash mismatch: meta={} actual={}",
                            expected_hash, actual_hash
                        )));
                    }
                }
                serde_json::from_str::<GovernanceState>(gov_json).map_err(|e| {
                    StorageError::BackendError(format!(
                        "snapshot v2: legacy governance snapshot decode failed: {e}"
                    ))
                })?;
                Some((gov_h, gov_json.clone()))
            }
            (None, None, None, None, None, None) if hdr.base_height == 0 => None,
            (None, None, None, None, None, None) => {
                return Err(StorageError::BackendError(format!(
                    "snapshot v2: pruned bundle missing governance snapshot sidecar: base_height={}",
                    hdr.base_height
                )));
            }
            _ => {
                return Err(StorageError::BackendError(
                    "snapshot v2: governance snapshot header fields incomplete".to_string(),
                ));
            }
        };

        // Open the recovery journal only once bundle/hash/header validation has
        // passed and we are about to mutate the DB. Validation-only failures must
        // not be reported later as incomplete imports.
        self.journal_begin("import-snapshot-v2", "snapshot v2 restore")?;

        self.clear_chain_runtime_for_mirror()?;
        self.invalidate_auxiliary_runtime_state_for_chain_replace()?;
        if wipe_state_nodes {
            self.clear_keyspace(ColumnFamily::StateNodes)?;
        }

        for idx in hdr.window_from..=hdr.window_to {
            let mut blen = [0u8; 4];
            r.read_exact(&mut blen)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let n = u32::from_be_bytes(blen) as usize;
            if n == 0 || n > max_block {
                return Err(StorageError::BackendError(format!(
                    "snapshot block blob too large: {} (max={})",
                    n, max_block
                )));
            }
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let b: Block = serde_json::from_slice(&buf)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            if b.index != idx {
                return Err(StorageError::BackendError(format!(
                    "snapshot block index mismatch: expected {} got {}",
                    idx, b.index
                )));
            }
            if idx == hdr.window_from && hdr.window_from == 0 && !hdr.genesis_hash.trim().is_empty()
            {
                if b.hash != hdr.genesis_hash {
                    return Err(StorageError::BackendError(
                        "snapshot v2: payload genesis block hash/header genesis_hash mismatch"
                            .to_string(),
                    ));
                }
            }
            if idx == hdr.window_to {
                let payload_tip_root = if b.state_root.trim().is_empty() {
                    "0"
                } else {
                    b.state_root.as_str()
                };
                if b.hash != hdr.snapshot_block_hash || payload_tip_root != hdr.snapshot_state_root
                {
                    return Err(StorageError::BackendError(format!(
                        "snapshot v2: payload tip/header checkpoint mismatch block_match={} state_root_match={}",
                        b.hash == hdr.snapshot_block_hash,
                        payload_tip_root == hdr.snapshot_state_root
                    )));
                }
            }
            self.append_block_inner(&b, false)?;
        }

        if let Some(finality_meta) = validated_finality_meta.as_ref() {
            self.validate_finality_bft_meta_for_snapshot_v209(
                finality_meta,
                hdr.base_height,
                hdr.window_to,
                "snapshot import finality binding v209",
            )?;
        }

        let mut cntb = [0u8; 8];
        r.read_exact(&mut cntb)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let count = u64::from_be_bytes(cntb);
        if count > max_state_nodes {
            return Err(StorageError::BackendError(format!(
                "snapshot state_nodes count too large: {} (max={})",
                count, max_state_nodes
            )));
        }
        let mut state_batch = <Self as KVStore>::batch(self);
        let mut pending = 0usize;
        for _ in 0..count {
            let mut key = [0u8; 32];
            r.read_exact(&mut key)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let mut vlenb = [0u8; 4];
            r.read_exact(&mut vlenb)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            let vlen = u32::from_be_bytes(vlenb) as usize;
            if vlen == 0 || vlen > max_state_node_bytes {
                return Err(StorageError::BackendError(format!(
                    "snapshot state_node blob too large: {} (max={})",
                    vlen, max_state_node_bytes
                )));
            }
            let mut val = vec![0u8; vlen];
            r.read_exact(&mut val)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            test_disk_full_consume(32 + vlen)?;
            state_batch.put(ColumnFamily::StateNodes, &key[..], &val);
            pending += 1;
            if pending >= 2048 {
                self.write_batch(state_batch)?;
                state_batch = <Self as KVStore>::batch(self);
                pending = 0;
            }
        }
        if pending > 0 {
            self.write_batch(state_batch)?;
        }

        if let Some((_, econ_json)) = validated_economy_snapshot.as_ref() {
            let econ: SnapshotEconomyStateV1 = serde_json::from_str(econ_json).map_err(|e| {
                StorageError::BackendError(format!(
                    "snapshot v2: economy snapshot decode failed during SMT verification: {e}"
                ))
            })?;
            self.verify_snapshot_economy_state_against_tip_state_v1(
                &econ,
                crate::runtime_mode::public_mode_enabled(),
            )
            .map_err(|e| {
                StorageError::BackendError(format!(
                    "snapshot v2: economy snapshot is not semantically bound to imported tip state: {e}"
                ))
            })?;
        }

        let mut tail = [0u8; 1];
        let trailing = r
            .read(&mut tail)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        if trailing != 0 {
            return Err(StorageError::BackendError(
                "snapshot v2: trailing bytes after payload".to_string(),
            ));
        }

        if let Some((gov_h, gov_json)) = validated_governance_snapshot.as_ref() {
            // The NFT event normalizer replays state transitions. NFT admission is governed by
            // canonical governance params, so the imported governance anchor must be available
            // before validating/restoring derived NFT receipts. This stays inside the import
            // journal and is written only after the bundle/header/governance JSON were validated.
            self.put_governance_snapshot(*gov_h, gov_json, false)?;
        }
        if let Some((econ_h, econ_json)) = validated_economy_snapshot.as_ref() {
            self.put_economy_snapshot(*econ_h, econ_json, false)?;
        } else {
            self.clear_economy_snapshot(false)?;
        }
        if let Some(store) = validated_compute_order_state_store.as_ref() {
            self.put_compute_order_state_store_v1(store, false)?;
        } else {
            self.clear_compute_order_state_store_v1(false)?;
        }

        self.normalize_imported_snapshot_nft_events_v1(
            hdr.window_from,
            hdr.window_to,
            meta.state_coverage_mode,
            meta.historical_state_roots_queryable,
        )?;

        self.meta_put_u64(META_BASE_HEIGHT_KEY, hdr.base_height)?;
        if let Some(finality_meta) = validated_finality_meta.as_ref() {
            self.persist_finality_bft_meta_from_snapshot_v209(finality_meta)?;
        }
        if let Some((gov_h, gov_json)) = validated_governance_snapshot.as_ref() {
            self.put_governance_snapshot(*gov_h, gov_json, false)?;
        }
        if meta.include_state_nodes && meta.reachable_state_nodes {
            self.validate_reachable_state_root_closure(&meta.state_root, max_state_nodes)?;
            self.put_snapshot_reachable_state_import_marker(
                &SnapshotReachableStateImportMarker {
                    height: meta.height,
                    state_root: meta.state_root.clone(),
                    window_from_height: meta.window_from_height,
                    window_to_height: meta.window_to_height,
                    state_coverage_mode: meta.state_coverage_mode,
                    historical_state_roots_queryable: meta.historical_state_roots_queryable,
                },
                false,
            )?;
        } else {
            self.clear_snapshot_reachable_state_import_marker(false)?;
        }

        if let Some(ctx) = meta.consensus_bootstrap_context.as_ref() {
            self.put_snapshot_consensus_bootstrap_context(ctx, false)?;
        } else {
            self.clear_snapshot_consensus_bootstrap_context(false)?;
        }

        self.flush_db()?;
        self.journal_clear()?;
        Ok(())
    }

    /// GC/compaction di `state_nodes` mantenendo **solo** i nodi raggiungibili dal `state_root`.
    pub fn gc_state_nodes_to_root(
        &self,
        state_root_hex: &str,
        max_nodes: u64,
        batch: usize,
    ) -> StorageResult<GcStateNodesReport> {
        let started = std::time::Instant::now();
        let batch = batch.clamp(1, 1_000_000);

        let sr = state_root_hex.trim();
        if sr.is_empty() || sr == "0" {
            return Err(StorageError::BackendError(
                "gc-state-nodes requires a non-empty 32-byte state_root".to_string(),
            ));
        }

        let note = format!(
            "root={}.. max_nodes={} batch={}",
            &sr[..sr.len().min(12)],
            max_nodes,
            batch
        );
        self.journal_begin("gc_state_nodes", &note)?;

        let reachable_vec = self.collect_reachable_state_nodes(state_root_hex, max_nodes)?;
        let reachable = reachable_vec.len() as u64;

        let use_hashset = reachable_vec.len() <= 2_000_000;
        let reachable_set: Option<HashSet<[u8; 32]>> = if use_hashset {
            Some(reachable_vec.iter().copied().collect())
        } else {
            None
        };

        let mut scanned: u64 = 0;
        let mut removed: u64 = 0;
        let mut kept: u64 = 0;
        let mut pending: Vec<[u8; 32]> = Vec::with_capacity(batch.min(50_000));

        for item in self.iter_all_cf(ColumnFamily::StateNodes)? {
            let (k, _v) = item?;
            scanned = scanned.saturating_add(1);

            if k.len() != 32 {
                kept = kept.saturating_add(1);
                continue;
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&k);

            let is_reachable = if let Some(ref hs) = reachable_set {
                hs.contains(&key)
            } else {
                reachable_vec.binary_search(&key).is_ok()
            };

            if is_reachable {
                kept = kept.saturating_add(1);
            } else {
                pending.push(key);
                if pending.len() >= batch {
                    let n = pending.len() as u64;
                    let mut wb = <Self as KVStore>::batch(self);
                    for kk in pending.drain(..) {
                        wb.delete(ColumnFamily::StateNodes, &kk[..]);
                    }
                    self.write_batch(wb)?;
                    removed = removed.saturating_add(n);
                }
            }
        }

        if !pending.is_empty() {
            let n = pending.len() as u64;
            let mut wb = <Self as KVStore>::batch(self);
            for kk in pending.drain(..) {
                wb.delete(ColumnFamily::StateNodes, &kk[..]);
            }
            self.write_batch(wb)?;
            removed = removed.saturating_add(n);
        }

        self.flush_db()?;
        self.journal_clear()?;

        Ok(GcStateNodesReport {
            reachable,
            scanned,
            removed,
            kept,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    fn collect_reachable_state_nodes(
        &self,
        state_root_hex: &str,
        max_nodes: u64,
    ) -> StorageResult<Vec<[u8; 32]>> {
        let sr = state_root_hex.trim();
        if sr.is_empty() || sr == "0" {
            return Ok(Vec::new());
        }

        let root_bytes = hex::decode(sr).map_err(|e| StorageError::BackendError(e.to_string()))?;
        if root_bytes.len() != 32 {
            return Err(StorageError::BackendError(
                "state_root hex must be 32 bytes".to_string(),
            ));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);

        if is_virtual_empty_hash(&root) {
            return Ok(Vec::new());
        }

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut q: VecDeque<[u8; 32]> = VecDeque::new();
        q.push_back(root);

        while let Some(h) = q.pop_front() {
            if is_virtual_empty_hash(&h) {
                continue;
            }
            if seen.contains(&h) {
                continue;
            }
            if seen.len() as u64 >= max_nodes {
                return Err(StorageError::BackendError(format!(
                    "reachable state_nodes exceeded max_nodes={}",
                    max_nodes
                )));
            }

            let v = match self.get(ColumnFamily::StateNodes, &h[..])? {
                Some(v) => v,
                None => {
                    let hh = hex::encode(h);
                    if h == root {
                        return Err(StorageError::BackendError(format!(
                            "reachable state_nodes root missing: {}",
                            hh
                        )));
                    }
                    return Err(StorageError::BackendError(format!(
                        "reachable state_nodes broken reference: {}",
                        hh
                    )));
                }
            };

            let node: SmtNode =
                bincode::deserialize(&v).map_err(|e| StorageError::BackendError(e.to_string()))?;
            seen.insert(h);

            match node {
                SmtNode::Branch { left, right } => {
                    q.push_back(left);
                    q.push_back(right);
                }
                SmtNode::Leaf { .. } => {}
            }
        }

        let mut out: Vec<[u8; 32]> = seen.into_iter().collect();
        out.sort();
        Ok(out)
    }

    fn collect_reachable_state_nodes_for_snapshot_export_v205(
        &self,
        state_root_hex: &str,
        max_nodes: u64,
        export_started: std::time::Instant,
        export_deadline_ms: u64,
        progress_every_nodes: u64,
    ) -> StorageResult<Vec<[u8; 32]>> {
        let sr = state_root_hex.trim();
        if sr.is_empty() || sr == "0" {
            return Ok(Vec::new());
        }

        let root_bytes = hex::decode(sr).map_err(|e| StorageError::BackendError(e.to_string()))?;
        if root_bytes.len() != 32 {
            return Err(StorageError::BackendError(
                "state_root hex must be 32 bytes".to_string(),
            ));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);

        if is_virtual_empty_hash(&root) {
            return Ok(Vec::new());
        }

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut q: VecDeque<[u8; 32]> = VecDeque::new();
        q.push_back(root);

        while let Some(h) = q.pop_front() {
            let visited = seen.len() as u64;
            if visited == 0 || visited % progress_every_nodes == 0 {
                Self::snapshot_check_deadline_v205(
                    export_started,
                    export_deadline_ms,
                    "collect_reachable_state_nodes",
                    visited,
                )?;
                ng_info_throttle!(
                    key: format!("snapshot_export_state_node_collect_progress:{}", sr.chars().take(16).collect::<String>()),
                    every_ms: 10_000,
                    target: "snapshot.export",
                    "event=snapshot_export_progress stage=collect_reachable_state_nodes visited={} queue={} elapsed_ms={} deadline_ms={}",
                    visited,
                    q.len(),
                    Self::snapshot_elapsed_ms_v205(export_started),
                    export_deadline_ms
                );
            }

            if is_virtual_empty_hash(&h) {
                continue;
            }
            if seen.contains(&h) {
                continue;
            }
            if seen.len() as u64 >= max_nodes {
                return Err(StorageError::BackendError(format!(
                    "reachable state_nodes exceeded max_nodes={}",
                    max_nodes
                )));
            }

            let v = match self.get(ColumnFamily::StateNodes, &h[..])? {
                Some(v) => v,
                None => {
                    let hh = hex::encode(h);
                    if h == root {
                        return Err(StorageError::BackendError(format!(
                            "reachable state_nodes root missing: {}",
                            hh
                        )));
                    }
                    return Err(StorageError::BackendError(format!(
                        "reachable state_nodes broken reference: {}",
                        hh
                    )));
                }
            };

            let node: SmtNode =
                bincode::deserialize(&v).map_err(|e| StorageError::BackendError(e.to_string()))?;
            seen.insert(h);

            match node {
                SmtNode::Branch { left, right } => {
                    q.push_back(left);
                    q.push_back(right);
                }
                SmtNode::Leaf { .. } => {}
            }
        }

        Self::snapshot_check_deadline_v205(
            export_started,
            export_deadline_ms,
            "collect_reachable_state_nodes",
            seen.len() as u64,
        )?;
        let mut out: Vec<[u8; 32]> = seen.into_iter().collect();
        out.sort();
        Ok(out)
    }

    #[allow(dead_code)]
    fn clear_chain_runtime_for_mirror(&self) -> StorageResult<()> {
        self.clear_keyspace(ColumnFamily::Blocks)?;
        self.clear_keyspace(ColumnFamily::TxIndex)?;
        self.meta_remove(META_HEIGHT_KEY)?;
        self.meta_remove(META_BASE_HEIGHT_KEY)?;
        self.meta_remove(META_TIP_HASH_KEY)?;
        self.meta_remove(META_TIP_STATE_ROOT_KEY)?;
        self.meta_remove(META_GOV_BOOTSTRAP_JSON_KEY)?;
        self.meta_remove(META_GOV_SNAPSHOT_JSON_KEY)?;
        self.meta_remove(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
        self.clear_economy_snapshot(false)?;
        self.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
        self.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
        self.clear_compute_order_state_store_v1(false)?;
        Ok(())
    }

    fn capture_snapshot_consensus_bootstrap_context_for_chain_tip(
        &self,
        blockchain: &Blockchain,
    ) -> StorageResult<Option<SnapshotConsensusBootstrapContext>> {
        let Some(tip) = blockchain.chain.last() else {
            return Ok(None);
        };
        let Some(ctx) = self.get_snapshot_consensus_bootstrap_context()? else {
            return Ok(None);
        };
        match ctx.validate_basic(tip.index, &tip.state_root) {
            Ok(()) => Ok(Some(ctx)),
            Err(_) => Ok(None),
        }
    }

    fn restore_snapshot_consensus_bootstrap_context_after_mirror(
        &self,
        blockchain: &Blockchain,
        captured: Option<&SnapshotConsensusBootstrapContext>,
    ) -> StorageResult<()> {
        let Some(tip) = blockchain.chain.last() else {
            self.clear_snapshot_consensus_bootstrap_context(false)?;
            return Ok(());
        };

        if let Some(ctx) = captured {
            ctx.validate_basic(tip.index, &tip.state_root)
                .map_err(StorageError::BackendError)?;
            self.put_snapshot_consensus_bootstrap_context(ctx, false)?;
        } else {
            self.clear_snapshot_consensus_bootstrap_context(false)?;
        }
        Ok(())
    }

    fn capture_snapshot_reachable_state_import_marker_for_chain_tip(
        &self,
        blockchain: &Blockchain,
    ) -> StorageResult<Option<SnapshotReachableStateImportMarker>> {
        let Some(tip) = blockchain.chain.last() else {
            return Ok(None);
        };
        let Some(marker) = self.get_snapshot_reachable_state_import_marker()? else {
            return Ok(None);
        };
        if marker.height == tip.index
            && marker.state_root.trim() == tip.state_root.trim()
            && !marker.state_root.trim().is_empty()
        {
            Ok(Some(marker))
        } else {
            Ok(None)
        }
    }

    fn restore_snapshot_reachable_state_import_marker_after_mirror(
        &self,
        blockchain: &Blockchain,
        captured: Option<&SnapshotReachableStateImportMarker>,
    ) -> StorageResult<()> {
        let Some(tip) = blockchain.chain.last() else {
            self.clear_snapshot_reachable_state_import_marker(false)?;
            return Ok(());
        };

        if let Some(marker) = captured {
            if marker.height != tip.index || marker.state_root.trim() != tip.state_root.trim() {
                return Err(StorageError::BackendError(
                    "reachable-only snapshot import marker no longer matches chain tip after mirror"
                        .to_string(),
                ));
            }
            self.put_snapshot_reachable_state_import_marker(marker, false)?;
        } else {
            self.clear_snapshot_reachable_state_import_marker(false)?;
        }
        Ok(())
    }

    fn clear_rebuildable_finality_runtime_state(&self) -> StorageResult<()> {
        self.clear_keyspace(ColumnFamily::FinalityBftMeta)?;
        self.clear_keyspace(ColumnFamily::FinalityBftQcArchive)?;
        Ok(())
    }

    fn clear_rebuildable_cognitive_runtime_state(&self) -> StorageResult<()> {
        self.clear_keyspace(ColumnFamily::CognitiveRegistryEntries)?;
        self.clear_keyspace(ColumnFamily::CognitiveRegistryByClaim)?;
        self.clear_keyspace(ColumnFamily::CognitiveRegistryEvents)?;
        self.clear_keyspace(ColumnFamily::CognitiveRegistryMeta)?;
        Ok(())
    }

    pub fn invalidate_auxiliary_runtime_state_for_chain_replace(&self) -> StorageResult<()> {
        // IMPORTANT: preserve FinalityBftLastVote across mirror/repair/truncate.
        //
        // This keyspace is not just a rebuildable runtime cache: it is the durable local
        // anti-equivocation fence for "no double-vote per (height, round)". Clearing it on a
        // chain replace would silently weaken safety after crash/restart by forgetting votes the
        // signer has already emitted.
        //
        // The stores below are instead chain-derived/materialized views that must be invalidated
        // and rebuilt (or left empty deterministically) when the canonical block history changes.
        self.clear_rebuildable_finality_runtime_state()?;
        self.clear_rebuildable_cognitive_runtime_state()?;
        Ok(())
    }

    fn mirror_governance_cache_from_blockchain_best_effort(
        &self,
        blockchain: &Blockchain,
    ) -> StorageResult<()> {
        match &blockchain.governance_bootstrap {
            Some(boot) => {
                let js = serde_json::to_string(boot)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                self.put_governance_bootstrap_json(&js, false)?;
            }
            None => self.meta_remove(META_GOV_BOOTSTRAP_JSON_KEY)?,
        }

        match &blockchain.governance {
            Some(g) => {
                let tip_h = blockchain.height() as u64;
                let js = serde_json::to_string(g)
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                self.put_governance_snapshot(tip_h, &js, false)?;
            }
            None => {
                self.meta_remove(META_GOV_SNAPSHOT_JSON_KEY)?;
                self.meta_remove(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
            }
        }

        Ok(())
    }

    fn mirror_economy_cache_from_blockchain_best_effort(
        &self,
        blockchain: &Blockchain,
    ) -> StorageResult<()> {
        let Some(tip) = blockchain.chain.last() else {
            self.clear_economy_snapshot(false)?;
            return Ok(());
        };
        let snap = blockchain
            .build_snapshot_economy_state_v1(tip)
            .map_err(|e| {
                StorageError::BackendError(format!("economy snapshot mirror failed: {e}"))
            })?;
        let js = serde_json::to_string(&snap).map_err(|e| {
            StorageError::BackendError(format!("economy snapshot serialize failed: {e}"))
        })?;
        self.put_economy_snapshot(tip.index, &js, false)
    }
}

// ---------------------------
// Snapshot v2 helpers (chunk writer/reader + hashing)
// ---------------------------

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

const SNAPSHOT_V2_DEFAULT_HEADER_WARN_BYTES: usize = 2 * 1024 * 1024;
const SNAPSHOT_V2_DEFAULT_HEADER_MAX_BYTES: usize = 4 * 1024 * 1024;

fn snapshot_v2_header_warn_bytes() -> usize {
    env_usize(
        "NG_SNAPSHOT_WARN_HEADER_BYTES",
        SNAPSHOT_V2_DEFAULT_HEADER_WARN_BYTES,
    )
    .max(1)
}

fn snapshot_v2_header_max_bytes() -> usize {
    env_usize(
        "NG_SNAPSHOT_MAX_HEADER_BYTES",
        SNAPSHOT_V2_DEFAULT_HEADER_MAX_BYTES,
    )
    .max(1)
}

fn snapshot_v2_sidecar_bytes(
    governance_snapshot_json: &Option<String>,
    economy_snapshot_json: &Option<String>,
    compute_order_state_store_json: &Option<String>,
) -> (usize, usize, usize, usize) {
    let governance_bytes = governance_snapshot_json
        .as_ref()
        .map(|s| s.len())
        .unwrap_or(0);
    let economy_bytes = economy_snapshot_json.as_ref().map(|s| s.len()).unwrap_or(0);
    let compute_order_bytes = compute_order_state_store_json
        .as_ref()
        .map(|s| s.len())
        .unwrap_or(0);
    (
        governance_bytes,
        economy_bytes,
        compute_order_bytes,
        governance_bytes
            .saturating_add(economy_bytes)
            .saturating_add(compute_order_bytes),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    hex::encode(out)
}

struct SnapshotV2ChunkWriter {
    chunk_dir: PathBuf,
    chunk_size: usize,
    max_bytes: usize,
    index: u32,
    cur_len: usize,
    total_len: u64,
    file: File,
    hasher: Sha256,
    chunk_hashes: Vec<String>,
}

impl SnapshotV2ChunkWriter {
    fn new(chunk_dir: PathBuf, chunk_size: usize, max_bytes: usize) -> StorageResult<Self> {
        fs::create_dir_all(&chunk_dir).map_err(|e| StorageError::BackendError(e.to_string()))?;
        let file_path = chunk_dir.join(format!("{:06}.bin", 0u32));
        let file =
            File::create(&file_path).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(Self {
            chunk_dir,
            chunk_size,
            max_bytes,
            index: 0,
            cur_len: 0,
            total_len: 0,
            file,
            hasher: Sha256::new(),
            chunk_hashes: Vec::new(),
        })
    }

    fn rotate(&mut self) -> StorageResult<()> {
        // finalize current chunk hash
        self.file
            .flush()
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let digest = std::mem::replace(&mut self.hasher, Sha256::new()).finalize();
        self.chunk_hashes.push(hex::encode(digest));

        // next chunk
        self.index = self.index.saturating_add(1);
        self.cur_len = 0;
        let file_path = self.chunk_dir.join(format!("{:06}.bin", self.index));
        self.file =
            File::create(&file_path).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn write_all(&mut self, mut data: &[u8]) -> StorageResult<()> {
        while !data.is_empty() {
            if self.total_len as usize >= self.max_bytes {
                return Err(StorageError::BackendError(format!(
                    "snapshot exceeded max bytes {}",
                    self.max_bytes
                )));
            }

            let rem = self.chunk_size.saturating_sub(self.cur_len);
            if rem == 0 {
                self.rotate()?;
                continue;
            }

            let take = rem.min(data.len());
            let part = &data[..take];

            if (self.total_len as usize).saturating_add(take) > self.max_bytes {
                return Err(StorageError::BackendError(format!(
                    "snapshot would exceed max bytes {}",
                    self.max_bytes
                )));
            }

            self.file
                .write_all(part)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            self.hasher.update(part);
            self.cur_len += take;
            self.total_len += take as u64;
            data = &data[take..];
        }
        Ok(())
    }

    fn finish(mut self) -> StorageResult<(u64, Vec<String>)> {
        self.file
            .flush()
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        let digest = std::mem::replace(&mut self.hasher, Sha256::new()).finalize();
        self.chunk_hashes.push(hex::encode(digest));
        Ok((self.total_len, self.chunk_hashes))
    }
}

struct SnapshotV2ChunkReader {
    chunk_dir: PathBuf,
    chunks: u32,
    index: u32,
    cur: Option<BufReader<File>>,
}

impl SnapshotV2ChunkReader {
    fn new(chunk_dir: PathBuf, chunks: u32) -> StorageResult<Self> {
        if chunks == 0 {
            return Err(StorageError::BackendError(
                "snapshot v2: zero chunks".to_string(),
            ));
        }
        Ok(Self {
            chunk_dir,
            chunks,
            index: 0,
            cur: None,
        })
    }

    fn open_next(&mut self) -> StorageResult<bool> {
        if self.index >= self.chunks {
            self.cur = None;
            return Ok(false);
        }
        let file_path = self.chunk_dir.join(format!("{:06}.bin", self.index));
        let f = File::open(&file_path).map_err(|e| StorageError::BackendError(e.to_string()))?;
        self.cur = Some(BufReader::new(f));
        self.index = self.index.saturating_add(1);
        Ok(true)
    }
}

impl Read for SnapshotV2ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cur.is_none()
                && !self
                    .open_next()
                    .map_err(|e| std::io::Error::other(format!("{:?}", e)))?
            {
                return Ok(0);
            }
            if let Some(r) = &mut self.cur {
                let n = r.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                // EOF: move to next
                self.cur = None;
                continue;
            }
        }
    }
}

fn verify_snapshot_v2_chunks(chunks_dir: &Path, meta: &SnapshotMeta) -> StorageResult<u64> {
    if meta.chunks as usize != meta.chunk_hashes_hex.len() {
        return Err(StorageError::BackendError(
            "snapshot v2: chunk hash list mismatch".to_string(),
        ));
    }

    let mut total_bytes: u64 = 0;
    for i in 0..meta.chunks {
        let file_path = chunks_dir.join(format!("{:06}.bin", i));
        let bytes = fs::read(&file_path).map_err(|e| StorageError::BackendError(e.to_string()))?;
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            StorageError::BackendError("snapshot v2: bytes total overflow".to_string())
        })?;
        let got = sha256_hex(&bytes);
        let exp = meta.chunk_hashes_hex[i as usize].to_lowercase();
        if got != exp {
            return Err(StorageError::BackendError(format!(
                "snapshot v2: chunk hash mismatch idx={} got={} expected={}",
                i, got, exp
            )));
        }
    }
    Ok(total_bytes)
}

// -------------------------
// KVStore implementation (canonical Fjall backend)
// -------------------------
// <-- fine impl ChainStorage

/// 🔹 Funzione di utilità: specchia la Blockchain esistente nel backend canonico.
///
/// - `path`: cartella del DB (es. "db" dentro RUN_A / RUN_B)
/// - `blockchain`: la tua struct Blockchain caricata da JSON
fn boot_deep_mirror_verify_enabled_v317() -> bool {
    if crate::runtime_mode::public_mode_enabled() {
        return true;
    }

    matches!(
        std::env::var("NEWGEN_BOOT_DEEP_MIRROR_VERIFY")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1")
            | Some("true")
            | Some("TRUE")
            | Some("yes")
            | Some("YES")
            | Some("on")
            | Some("ON")
    )
}

fn boot_mirror_auxiliary_rebuild_enabled_v318() -> bool {
    if crate::runtime_mode::public_mode_enabled() {
        return true;
    }

    matches!(
        std::env::var("NEWGEN_BOOT_MIRROR_REBUILD_AUXILIARY_STATE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1")
            | Some("true")
            | Some("TRUE")
            | Some("yes")
            | Some("YES")
            | Some("on")
            | Some("ON")
    )
}

fn storage_chain_matches_blockchain_tip(
    storage: &DbStore,
    blockchain: &Blockchain,
) -> StorageResult<bool> {
    let Some(first) = blockchain.chain.first() else {
        let height = storage.meta_get_u64_opt(META_HEIGHT_KEY)?;
        let has_any_block = storage
            .iter_all_cf(ColumnFamily::Blocks)?
            .next()
            .transpose()?
            .is_some();
        return Ok(height.is_none() && !has_any_block);
    };
    let Some(tip) = blockchain.chain.last() else {
        return Ok(false);
    };
    let meta_height = storage.meta_get_u64_opt(META_HEIGHT_KEY)?;
    if meta_height != Some(tip.index) {
        return Ok(false);
    }
    let meta_base_height = storage.meta_get_u64_opt(META_BASE_HEIGHT_KEY)?.unwrap_or(0);
    if meta_base_height != first.index {
        return Ok(false);
    }
    let meta_tip_hash = storage.meta_get_string_opt(META_TIP_HASH_KEY)?;
    if meta_tip_hash.as_deref() != Some(tip.hash.as_str()) {
        return Ok(false);
    }
    let expected_tip_state_root = if tip.state_root.is_empty() {
        "0".to_string()
    } else {
        tip.state_root.clone()
    };
    let meta_tip_state_root = storage.meta_get_string_opt(META_TIP_STATE_ROOT_KEY)?;
    if meta_tip_state_root.as_deref() != Some(expected_tip_state_root.as_str()) {
        return Ok(false);
    }

    let deep_verify = boot_deep_mirror_verify_enabled_v317();
    if !deep_verify {
        ng_info!(
            target: "storage.mirror",
            "event=mirror_chain_tip_meta_fast_path_v317 height={} base_height={} tip_hash={} tip_state_root={} deep_verify=false public_mode=false",
            tip.index,
            first.index,
            tip.hash,
            expected_tip_state_root
        );
        return Ok(true);
    }

    ng_info!(
        target: "storage.mirror",
        "event=mirror_chain_deep_verify_start_v317 height={} base_height={} blocks={} public_mode={} env_deep_verify={}",
        tip.index,
        first.index,
        blockchain.chain.len(),
        crate::runtime_mode::public_mode_enabled(),
        std::env::var("NEWGEN_BOOT_DEEP_MIRROR_VERIFY").is_ok()
    );

    for block in &blockchain.chain {
        let Some(stored) = storage.get_block(block.index)? else {
            return Ok(false);
        };
        if stored.hash != block.hash
            || stored.previous_hash != block.previous_hash
            || stored.state_root != block.state_root
            || stored.transactions != block.transactions
            || stored.timestamp != block.timestamp
            || stored.miner_pub_key != block.miner_pub_key
            || stored.signature != block.signature
        {
            return Ok(false);
        }
    }

    ng_info!(
        target: "storage.mirror",
        "event=mirror_chain_deep_verify_ok_v317 height={} base_height={} blocks={}",
        tip.index,
        first.index,
        blockchain.chain.len()
    );
    Ok(true)
}

fn repair_tx_index_from_blockchain(
    storage: &DbStore,
    blockchain: &Blockchain,
) -> StorageResult<u64> {
    let mut repaired = 0u64;
    for block in &blockchain.chain {
        for tx in &block.transactions {
            if tx.is_coinbase || tx.hash.is_empty() {
                continue;
            }
            let key = tx.hash.as_bytes();
            let expected = encode_u64(block.index);
            match storage.get(ColumnFamily::TxIndex, key)? {
                Some(v) if v.as_slice() == expected.as_slice() => {}
                _ => {
                    storage.put(ColumnFamily::TxIndex, key, &expected)?;
                    repaired = repaired.saturating_add(1);
                }
            }
        }
    }
    Ok(repaired)
}

fn refresh_existing_chain_runtime_without_destructive_rewrite(
    storage: &DbStore,
    blockchain: &Blockchain,
    captured_bootstrap_ctx: Option<&SnapshotConsensusBootstrapContext>,
    captured_reachable_only_marker: Option<&SnapshotReachableStateImportMarker>,
    rebuild_auxiliary_state: bool,
) -> StorageResult<()> {
    if let Some(first) = blockchain.chain.first() {
        if first.index == 0 {
            storage.meta_remove(META_BASE_HEIGHT_KEY)?;
        } else {
            storage.meta_put_u64(META_BASE_HEIGHT_KEY, first.index)?;
        }
    } else {
        storage.meta_remove(META_BASE_HEIGHT_KEY)?;
        storage.meta_remove(META_HEIGHT_KEY)?;
        storage.meta_remove(META_TIP_HASH_KEY)?;
        storage.meta_remove(META_TIP_STATE_ROOT_KEY)?;
    }

    if let Some(tip) = blockchain.chain.last() {
        storage.meta_put_u64(META_HEIGHT_KEY, tip.index)?;
        storage.meta_put_string(META_TIP_HASH_KEY, &tip.hash)?;
        let tip_state_root = if tip.state_root.is_empty() {
            "0"
        } else {
            tip.state_root.as_str()
        };
        storage.meta_put_string(META_TIP_STATE_ROOT_KEY, tip_state_root)?;
    }

    let repaired_tx_index = repair_tx_index_from_blockchain(storage, blockchain)?;
    storage.mirror_governance_cache_from_blockchain_best_effort(blockchain)?;
    storage.mirror_economy_cache_from_blockchain_best_effort(blockchain)?;
    storage.restore_snapshot_consensus_bootstrap_context_after_mirror(
        blockchain,
        captured_bootstrap_ctx,
    )?;
    storage.restore_snapshot_reachable_state_import_marker_after_mirror(
        blockchain,
        captured_reachable_only_marker,
    )?;

    if rebuild_auxiliary_state {
        let mut rebuild = blockchain.clone();
        rebuild
            .repopulate_persisted_auxiliary_state_from_chain(std::sync::Arc::new(storage.clone()))
            .map_err(StorageError::BackendError)?;
        ng_info!(
            target: "storage.mirror",
            "event=mirror_auxiliary_rebuild_done_v318 reason=explicit_or_public_mode_fast_path"
        );
    } else {
        ng_info!(
            target: "storage.mirror",
            "event=mirror_auxiliary_rebuild_skipped_v318 reason=tip_meta_fast_path_no_chain_replace public_mode=false env_rebuild=false"
        );
    }
    storage.flush_db()?;
    ng_info!(
        target: "storage.mirror",
        "event=mirror_chain_fast_path_ok blocks_written=0 with_state=false tx_index_repaired={} auxiliary_rebuild={}",
        repaired_tx_index,
        rebuild_auxiliary_state
    );
    Ok(())
}

pub fn mirror_blockchain_to_storage(
    storage: &DbStore,
    blockchain: &Blockchain,
) -> StorageResult<()> {
    let note = format!(
        "blocks={} base_height={} with_state=false",
        blockchain.chain.len(),
        blockchain.base_height
    );
    storage.journal_begin("mirror-chain", &note)?;

    let captured_bootstrap_ctx =
        storage.capture_snapshot_consensus_bootstrap_context_for_chain_tip(blockchain)?;
    let captured_reachable_only_marker =
        storage.capture_snapshot_reachable_state_import_marker_for_chain_tip(blockchain)?;

    let mirror_result = (|| {
        if storage_chain_matches_blockchain_tip(storage, blockchain)? {
            return refresh_existing_chain_runtime_without_destructive_rewrite(
                storage,
                blockchain,
                captured_bootstrap_ctx.as_ref(),
                captured_reachable_only_marker.as_ref(),
                boot_mirror_auxiliary_rebuild_enabled_v318(),
            );
        }
        // Pulisce i keyspace canonici della chain: il DB diventa un mirror esatto.
        storage.clear_chain_runtime_for_mirror()?;
        storage.invalidate_auxiliary_runtime_state_for_chain_replace()?;
        // NOTA: NON cancellare state_nodes_tree qui.
        // I nodi SMT sono necessari per validare blocchi con prev_state_root non-vuoto.
        // Se li cancelli ma NON ricostruisci lo state tree (replay), i follower rifiutano i blocchi con:
        //   "missing node at depth 0".
        // Se vuoi un mirror "pulito" anche dello stato, serve un mirror che ricostruisca i nodi SMT (replay).
        // Qui preserviamo state_nodes_tree per mantenere consistenza funzionale del nodo.

        // base_height: importante per DB pruned (il primo blocco potrebbe non essere 0)
        if let Some(first) = blockchain.chain.first() {
            if first.index == 0 {
                storage.meta_remove(META_BASE_HEIGHT_KEY)?;
            } else {
                storage.meta_put_u64(META_BASE_HEIGHT_KEY, first.index)?;
            }
        } else {
            // chain vuota → rimuovi base_height per evitare meta incoerenti
            storage.meta_remove(META_BASE_HEIGHT_KEY)?;
        }

        let mut count: u64 = 0;
        for block in &blockchain.chain {
            // mirror batch: niente flush per ogni blocco
            storage.append_block_inner(block, false)?;
            count += 1;
        }

        storage.mirror_governance_cache_from_blockchain_best_effort(blockchain)?;
        storage.mirror_economy_cache_from_blockchain_best_effort(blockchain)?;
        storage.put_compute_order_state_store_v1(&blockchain.compute_order_state_store, false)?;
        storage.restore_snapshot_consensus_bootstrap_context_after_mirror(
            blockchain,
            captured_bootstrap_ctx.as_ref(),
        )?;
        storage.restore_snapshot_reachable_state_import_marker_after_mirror(
            blockchain,
            captured_reachable_only_marker.as_ref(),
        )?;

        let mut rebuild = blockchain.clone();
        rebuild
            .repopulate_persisted_auxiliary_state_from_chain(std::sync::Arc::new(storage.clone()))
            .map_err(StorageError::BackendError)?;

        // flush una volta sola (molto più pulito e veloce)
        storage.flush_db()?;

        ng_info!(
            target: "storage.mirror",
            "event=mirror_chain_ok blocks_written={} with_state=false",
            count
        );
        Ok(())
    })();

    match mirror_result {
        Ok(()) => {
            storage.journal_clear()?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub fn mirror_blockchain_to_storage_with_state(
    storage: &DbStore,
    blockchain: &Blockchain,
    state_nodes: &[([u8; 32], Vec<u8>)],
) -> StorageResult<()> {
    let note = format!(
        "blocks={} base_height={} with_state=true state_nodes={}",
        blockchain.chain.len(),
        blockchain.base_height,
        state_nodes.len()
    );
    storage.journal_begin("mirror-chain-with-state", &note)?;

    let captured_bootstrap_ctx =
        storage.capture_snapshot_consensus_bootstrap_context_for_chain_tip(blockchain)?;
    let captured_reachable_only_marker =
        storage.capture_snapshot_reachable_state_import_marker_for_chain_tip(blockchain)?;

    let mirror_result = (|| {
        // Mirror "perfetto": blocchi + tx_index + nodi SMT/state in un'unica operazione coerente.
        storage.clear_chain_runtime_for_mirror()?;
        storage.invalidate_auxiliary_runtime_state_for_chain_replace()?;
        storage.clear_keyspace(ColumnFamily::StateNodes)?;

        // base_height: importante per DB pruned (il primo blocco potrebbe non essere 0)
        if let Some(first) = blockchain.chain.first() {
            if first.index == 0 {
                storage.meta_remove(META_BASE_HEIGHT_KEY)?;
            } else {
                storage.meta_put_u64(META_BASE_HEIGHT_KEY, first.index)?;
            }
        } else {
            // chain vuota → rimuovi base_height per evitare meta incoerenti
            storage.meta_remove(META_BASE_HEIGHT_KEY)?;
        }

        // 2) scrivi blocchi senza flush per-blocco
        for block in &blockchain.chain {
            storage.append_block_inner(block, false)?;
        }

        let mut batch = <DbStore as KVStore>::batch(storage);
        let mut pending = 0usize;
        for (key, value) in state_nodes {
            batch.put(ColumnFamily::StateNodes, &key[..], value);
            pending += 1;
            if pending >= 2048 {
                storage.write_batch(batch)?;
                batch = <DbStore as KVStore>::batch(storage);
                pending = 0;
            }
        }
        if pending > 0 {
            storage.write_batch(batch)?;
        }

        storage.mirror_governance_cache_from_blockchain_best_effort(blockchain)?;
        storage.mirror_economy_cache_from_blockchain_best_effort(blockchain)?;
        storage.put_compute_order_state_store_v1(&blockchain.compute_order_state_store, false)?;
        storage.restore_snapshot_consensus_bootstrap_context_after_mirror(
            blockchain,
            captured_bootstrap_ctx.as_ref(),
        )?;
        storage.restore_snapshot_reachable_state_import_marker_after_mirror(
            blockchain,
            captured_reachable_only_marker.as_ref(),
        )?;

        let mut rebuild = blockchain.clone();
        rebuild
            .repopulate_persisted_auxiliary_state_from_chain(std::sync::Arc::new(storage.clone()))
            .map_err(StorageError::BackendError)?;

        storage.flush_db()?;

        ng_info!(
            target: "storage.mirror",
            "event=mirror_chain_ok blocks_written={} with_state=true state_nodes={}",
            blockchain.chain.len(),
            state_nodes.len()
        );
        Ok(())
    })();

    match mirror_result {
        Ok(()) => {
            storage.journal_clear()?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub(crate) fn open_clean_test_dbstore(label: &str) -> StorageResult<DbStore> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("newgen_{}_{}", label, nonce));
    std::fs::create_dir_all(&dir).unwrap();
    let storage = DbStore::open(&dir)?;
    storage.clear_chain_runtime_for_mirror()?;
    storage.clear_keyspace(ColumnFamily::StateNodes)?;
    storage.clear_keyspace(ColumnFamily::FinalityBftLastVote)?;
    storage.clear_keyspace(ColumnFamily::FinalityBftMeta)?;
    storage.clear_keyspace(ColumnFamily::FinalityBftQcArchive)?;
    storage.clear_keyspace(ColumnFamily::CognitiveRegistryEntries)?;
    storage.clear_keyspace(ColumnFamily::CognitiveRegistryByClaim)?;
    storage.clear_keyspace(ColumnFamily::CognitiveRegistryEvents)?;
    storage.clear_keyspace(ColumnFamily::CognitiveRegistryMeta)?;
    storage.meta_remove(META_HEIGHT_KEY)?;
    storage.meta_remove(META_BASE_HEIGHT_KEY)?;
    storage.meta_remove(META_TIP_HASH_KEY)?;
    storage.meta_remove(META_TIP_STATE_ROOT_KEY)?;
    storage.meta_remove(META_GOV_BOOTSTRAP_JSON_KEY)?;
    storage.meta_remove(META_GOV_SNAPSHOT_JSON_KEY)?;
    storage.meta_remove(META_GOV_SNAPSHOT_HEIGHT_KEY)?;
    storage.clear_economy_snapshot(false)?;
    storage.meta_remove(META_SNAPSHOT_CONSENSUS_BOOTSTRAP_JSON_KEY)?;
    storage.meta_remove(META_SNAPSHOT_REACHABLE_STATE_IMPORT_JSON_KEY)?;
    storage.meta_remove(META_JOURNAL_PENDING_KEY)?;
    Ok(storage)
}

#[cfg(test)]
impl DbStore {
    /// Test-only compatibility alias used by legacy test scaffolding.
    pub fn put_block(&self, block: &Block) -> StorageResult<()> {
        self.append_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cognitive_chain::{CognitiveRegistryLifecycleStateV1, CognitiveTxKindV1};
    use crate::tests::test_process_lock;
    use crate::transaction::Transaction;
    use crate::Blockchain;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::path::PathBuf;

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

    fn open_test_storage() -> DbStore {
        open_clean_test_dbstore("storage-test").unwrap()
    }

    #[test]
    fn snapshot_context_target_epochs_v204_is_current_and_previous_only() {
        let epochs = DbStore::snapshot_context_target_epochs(50);
        assert_eq!(epochs.into_iter().collect::<Vec<_>>(), vec![49, 50]);

        let genesis_epoch = DbStore::snapshot_context_target_epochs(0);
        assert_eq!(genesis_epoch.into_iter().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn snapshot_export_deadline_guard_v205_errors_after_deadline() {
        let started = std::time::Instant::now() - std::time::Duration::from_millis(10);
        let err = DbStore::snapshot_check_deadline_v205(started, 1, "unit_test", 42)
            .expect_err("deadline should fail once elapsed_ms exceeds deadline_ms");
        let msg = format!("{:?}", err);
        assert!(msg.contains("snapshot_export_deadline_exceeded"));
        assert!(msg.contains("stage=unit_test"));
        assert!(msg.contains("progress=42"));
    }

    #[test]
    fn snapshot_export_deadline_config_v205_is_clamped() {
        let _guard = EnvGuard::capture(&[
            "NEWGEN_SNAPSHOT_EXPORT_DEADLINE_MS",
            "NEWGEN_SNAPSHOT_CONTEXT_SCAN_DEADLINE_MS",
            "NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_BLOCKS",
            "NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_STATE_NODES",
        ]);
        std::env::set_var("NEWGEN_SNAPSHOT_EXPORT_DEADLINE_MS", "1");
        std::env::set_var("NEWGEN_SNAPSHOT_CONTEXT_SCAN_DEADLINE_MS", "1");
        std::env::set_var("NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_BLOCKS", "0");
        std::env::set_var("NEWGEN_SNAPSHOT_EXPORT_PROGRESS_EVERY_STATE_NODES", "0");

        assert_eq!(DbStore::snapshot_export_deadline_ms_v205(), 5_000);
        assert_eq!(DbStore::snapshot_context_scan_deadline_ms_v205(), 1_000);
        assert_eq!(DbStore::snapshot_export_progress_every_blocks_v205(), 1);
        assert_eq!(
            DbStore::snapshot_export_progress_every_state_nodes_v205(),
            1
        );
    }

    fn linear_blocks(count: u64) -> Vec<Block> {
        let template = Blockchain::new();
        let mut out = Vec::new();
        let mut prev_hash = "0".to_string();
        for idx in 0..count {
            let mut block = template.create_block_dummy();
            block.index = idx;
            block.previous_hash = prev_hash.clone();
            block.timestamp = idx + 1;
            block.hash = block.calculate_hash();
            prev_hash = block.hash.clone();
            out.push(block);
        }
        out
    }

    fn put_tip_economy_snapshot_for_blocks(
        storage: &DbStore,
        blocks: &[Block],
        base_height: u64,
    ) -> String {
        let tip = blocks.last().expect("test chain must have a tip");
        let mut chain = Blockchain::from_blocks(blocks.to_vec());
        chain.base_height = base_height;
        let snap = chain
            .build_snapshot_economy_state_v1(tip)
            .expect("test economy snapshot must be buildable");
        let json = serde_json::to_string(&snap).expect("test economy snapshot must serialize");
        storage
            .put_economy_snapshot(tip.index, &json, false)
            .expect("test economy snapshot must persist");
        json
    }

    fn put_test_finality_meta_for_blocks(storage: &DbStore, blocks: &[Block]) {
        let tip = blocks
            .last()
            .expect("test finality fixture requires a non-empty block window");
        let meta = PersistedFinalityBftMetaV1 {
            finalized_height: tip.index,
            finalized_hash: tip.hash.clone(),
            highest_qc_height: tip.index,
            highest_qc_round: 0,
            highest_qc_block_hash: tip.hash.clone(),
        };
        let bytes = serde_json::to_vec(&meta).expect("test finality metadata must serialize");
        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                b"finality_bft_meta_v1",
                &bytes,
            )
            .expect("test finality metadata must persist before validator-capable snapshot export");
    }

    fn sample_hash(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    fn sample_snapshot_consensus_bootstrap_context(
        snapshot_height: u64,
        prev_state_root: &str,
    ) -> SnapshotConsensusBootstrapContext {
        SnapshotConsensusBootstrapContext::from_epoch_contexts(
            snapshot_height,
            prev_state_root.to_string(),
            vec![SnapshotConsensusEpochBootstrapContext {
                epoch: 0,
                coverage_start_height: 0,
                coverage_end_height: 9,
                pos_params: crate::staking::PosParamsV1 {
                    min_stake: 1,
                    unbonding_epochs: 1,
                    epoch_len: 10,
                    committee_size: 1,
                },
                params_source: None,
                seed_source: None,
                committee_source: None,
                legacy_params_source_height: None,
                legacy_params_source_state_root: None,
                seed_epoch: 0,
                seed_hex: sample_hash(0x55),
                committee: SnapshotConsensusCommitteeContext::V2 {
                    members: vec![crate::pos::CommitteeMemberV2 {
                        pk_hex: sample_hash(0x66),
                        stake: 1,
                    }],
                },
            }],
        )
    }

    #[test]
    fn export_reuses_imported_consensus_sidecar_for_historical_window() {
        use crate::state_smt::StateSmt;

        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("export-reuses-imported-sidecar").unwrap();
        let mut blocks = linear_blocks(3);

        let smt_store = StorageStateNodeStore {
            db: storage.db.clone(),
            inner: storage.state_nodes_keyspace.clone(),
        };
        let smt = StateSmt::new(smt_store);
        let params = crate::staking::PosParamsV1 {
            min_stake: 1,
            unbonding_epochs: 1,
            epoch_len: 10,
            committee_size: 1,
        };
        let root = smt
            .update_account(
                smt.empty_root(),
                crate::staking::k_stake_params(),
                crate::staking::encode_params_state(&params).unwrap(),
            )
            .expect("must materialize tip pos_params for export bootstrap builder");
        let root_hex = hex::encode(root);

        // Intentionally do not materialize seed/committee entries in the local SMT.
        // A fresh local sidecar build would be incomplete; successful export must reuse
        // the imported/persisted sidecar below.

        blocks[2].state_root = root_hex.clone();
        blocks[2].hash = blocks[2].calculate_hash();
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        put_test_finality_meta_for_blocks(&storage, &blocks);

        let imported_ctx = sample_snapshot_consensus_bootstrap_context(2, &root_hex)
            .with_historical_consensus_window(0, 3);
        imported_ctx
            .validate_basic(2, &root_hex)
            .expect("persisted imported sidecar fixture must be valid for snapshot tip");
        storage
            .put_snapshot_consensus_bootstrap_context(&imported_ctx, false)
            .unwrap();

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                true,
                true,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        assert!(meta.validator_bootstrap_capable);
        assert_eq!(
            meta.snapshot_bootstrap_role,
            SnapshotBootstrapRole::ValidatorBootstrap
        );
        assert_eq!(
            meta.consensus_bootstrap_context.as_ref(),
            Some(&imported_ctx),
            "reachable-only export must reuse the imported sidecar when local historical SMT consensus entries are missing"
        );
        assert_eq!(meta.consensus_bootstrap_context_omission_reason, None);
    }

    #[test]
    fn persisted_sidecar_reuse_honors_declared_historical_window() {
        let state_root = sample_hash(0x31);
        let persisted = sample_snapshot_consensus_bootstrap_context(0, &state_root)
            .with_historical_consensus_window(0, 4);
        let epoch_ctx = persisted
            .epoch_context(0)
            .expect("fixture must expose epoch 0 context");

        assert!(DbStore::persisted_snapshot_consensus_epoch_context_usable(
            &persisted,
            &epoch_ctx,
            0,
            4,
            0,
            &state_root,
        ));
        assert!(
            !DbStore::persisted_snapshot_consensus_epoch_context_usable(
                &persisted,
                &epoch_ctx,
                0,
                9,
                0,
                &state_root,
            ),
            "must not reuse an epoch context outside the sidecar declared historical window"
        );
    }

    fn sample_anchor_tx(
        object_hash_hex: String,
        claim_hash_hex: String,
    ) -> crate::cognitive_chain::CognitiveTxV1 {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let env = crate::cognitive_chain::CognitiveAttestationEnvelopeV1 {
            chain_id: crate::chain_identity::chain_id().to_string(),
            genesis_hash: sample_hash(0x11),
            object_hash_hex,
            claim_hash_hex,
            evidence_root_hex: sample_hash(0x22),
            context_hash_hex: sample_hash(0x33),
            policy_id: "default_policy".to_string(),
            model_manifest_hash_hex: sample_hash(0x44),
            created_at_height: 0,
            created_at_ts: 1,
        };
        let msg = env.canonical_bytes().unwrap();
        let sig = sk.sign(&msg);
        crate::cognitive_chain::CognitiveTxV1::Anchor(crate::cognitive_chain::CognitiveTxAnchorV1 {
            attestation_cert: crate::cognitive_chain::CognitiveAttestationCertV1 {
                envelope: env,
                sigs: vec![crate::cognitive_chain::CognitiveAttestationSigV1 {
                    signer_public_key_b64: STANDARD.encode(sk.verifying_key().to_bytes()),
                    signature_b64: STANDARD.encode(sig.to_bytes()),
                }],
            },
        })
    }

    fn write_temp_snapshot_file(bytes: &[u8], name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "newgen-storage-snapshot-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn read_snapshot_v2_header_value(bundle_dir: &std::path::Path) -> serde_json::Value {
        let chunk0 = fs::read(bundle_dir.join("chunks").join("000000.bin")).unwrap();
        assert!(chunk0.len() >= 12, "snapshot chunk0 too short");
        assert_eq!(&chunk0[..8], b"NGSNAP02");
        let hdr_len = u32::from_be_bytes(chunk0[8..12].try_into().unwrap()) as usize;
        let hdr_start = 12usize;
        let hdr_end = hdr_start + hdr_len;
        let hdr_bytes = &chunk0[hdr_start..hdr_end];
        serde_json::from_slice(hdr_bytes).unwrap()
    }

    fn snapshot_bundle_chunk_bytes(bundle_dir: &std::path::Path) -> Vec<Vec<u8>> {
        let mut entries: Vec<_> = fs::read_dir(bundle_dir.join("chunks"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        entries
            .into_iter()
            .map(|path| fs::read(path).unwrap())
            .collect()
    }

    fn header_only_snapshot_bytes(header_json: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"NGSNAP01");
        out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        out.extend_from_slice(header_json);
        out
    }

    fn snapshot_bytes_from_blocks(blocks: &[Block], include_state_nodes: bool) -> Vec<u8> {
        let height = blocks.last().map(|b| b.index);
        let tip_hash = blocks.last().map(|b| b.hash.clone());
        let tip_state_root = blocks.last().map(|b| {
            if b.state_root.is_empty() {
                "0".to_string()
            } else {
                b.state_root.clone()
            }
        });
        let header = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "height": height,
            "tip_hash": tip_hash,
            "tip_state_root": tip_state_root,
            "include_state_nodes": include_state_nodes,
        }))
        .unwrap();
        let mut out = header_only_snapshot_bytes(&header);
        for block in blocks {
            let blob = serde_json::to_vec(block).unwrap();
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&blob);
        }
        out.extend_from_slice(&0u64.to_be_bytes());
        out
    }

    fn seed_stale_auxiliary_runtime_state(storage: &DbStore) {
        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                b"finality_bft_meta_v1",
                br#"{"finalized_height":999,"finalized_hash":"x","highest_qc_height":999,"highest_qc_round":1,"highest_qc_block_hash":"y"}"#,
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                b"qc:00000000000000000009:0000000001",
                br#"{"height":9,"round":1,"block_hash":"stale"}"#,
            )
            .unwrap();
        storage
            .cognitive_registry_set_last_applied_height(999)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(77).unwrap();
        storage
            .put_governance_bootstrap_json("{\"stale\":true}", false)
            .unwrap();
        storage
            .put_governance_snapshot(999, "{\"stale\":true}", false)
            .unwrap();
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let vote = finality_bft::sign_vote_v1(
            &signer,
            crate::chain_identity::chain_id(),
            1,
            3,
            1,
            &sample_hash(0x77),
        )
        .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000003:0000000001",
                &serde_json::to_vec(&vote).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn prune_blocks_below_requires_fresh_governance_snapshot_anchor() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        for block in linear_blocks(3) {
            storage.append_block(&block).unwrap();
        }

        let err = storage.prune_blocks_below(1, 10).unwrap_err();
        match err {
            StorageError::BackendError(msg) => assert!(
                msg.contains("persist a fresh governance snapshot first"),
                "unexpected msg: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(
            storage.get_block(0).unwrap().is_some(),
            "prune must be fail-closed when governance anchor is missing"
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "preflight prune refusal must not leave journal_pending"
        );
    }

    #[test]
    fn prune_blocks_below_synthesizes_fresh_economy_snapshot_from_full_chain_anchor() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();

        let rep = storage.prune_blocks_below(1, 10).unwrap();
        assert_eq!(rep.old_base_height, 0);
        assert_eq!(rep.new_base_height, 1);
        assert_eq!(rep.pruned_blocks, 1);
        assert!(storage.get_block(0).unwrap().is_none());
        assert!(storage.get_block(1).unwrap().is_some());
        let (econ_h, econ_json) = storage.get_economy_snapshot().unwrap().unwrap();
        assert_eq!(econ_h, 2);
        let econ: SnapshotEconomyStateV1 = serde_json::from_str(&econ_json).unwrap();
        assert_eq!(econ.base_height, 1);
    }

    #[test]
    fn prune_blocks_below_accepts_fresh_governance_snapshot_anchor() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let rep = storage.prune_blocks_below(1, 10).unwrap();
        assert_eq!(rep.old_base_height, 0);
        assert_eq!(rep.new_base_height, 1);
        assert_eq!(rep.pruned_blocks, 1);
        assert!(storage.get_block(0).unwrap().is_none());
        assert!(storage.get_block(1).unwrap().is_some());
        assert_eq!(
            storage.meta_get_u64_opt(META_BASE_HEIGHT_KEY).unwrap(),
            Some(1)
        );
        let (econ_h, econ_json) = storage.get_economy_snapshot().unwrap().unwrap();
        assert_eq!(econ_h, 2);
        let econ: SnapshotEconomyStateV1 = serde_json::from_str(&econ_json).unwrap();
        assert_eq!(econ.base_height, 1);
    }

    #[test]
    fn verify_db_flags_pruned_db_with_stale_governance_snapshot_anchor() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        for block in linear_blocks(3) {
            storage.append_block(&block).unwrap();
        }

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(0, &gov_json, false)
            .unwrap();
        storage.meta_put_u64(META_BASE_HEIGHT_KEY, 1).unwrap();

        let rep = storage.verify_db(true).unwrap();
        assert!(!rep.ok);
        assert!(rep.needs_recovery);
        assert!(
            rep.issues
                .iter()
                .any(|issue| issue.contains("governance snapshot height 0 < base_height 1")),
            "issues={:?}",
            rep.issues
        );
    }

    #[test]
    fn repair_db_preserves_pruned_governance_snapshot_on_prune_journal_recovery() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        storage.prune_blocks_below(1, 10).unwrap();

        storage
            .journal_begin("prune-blocks", "simulate crash before journal_clear")
            .unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(rep.ok, "issues={:?}", rep.issues);
        let (snap_h, snap_json) = storage.get_governance_snapshot().unwrap().unwrap();
        assert_eq!(snap_h, 2);
        assert_eq!(snap_json, gov_json);
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair must clear prune journal marker after successful recovery"
        );
    }

    #[test]
    fn classify_snapshot_bootstrap_context_omission_reason_is_expected_for_historical_reachable_only_gap(
    ) {
        let reason = DbStore::classify_snapshot_bootstrap_context_omission_reason(
            1024,
            1485,
            true,
            "snapshot consensus bootstrap context missing seed for epoch 2",
        );
        assert_eq!(
            reason,
            Some(
                SnapshotConsensusBootstrapContextOmissionReason::HistoricalStateCoverageUnavailable,
            )
        );
    }

    #[test]
    fn classify_snapshot_bootstrap_context_omission_reason_is_incomplete_for_tip_reachable_only_gap(
    ) {
        let reason = DbStore::classify_snapshot_bootstrap_context_omission_reason(
            1485,
            1485,
            true,
            "snapshot consensus bootstrap context missing committee for epoch 3",
        );
        assert_eq!(
            reason,
            Some(SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete)
        );
    }

    #[test]
    fn classify_snapshot_bootstrap_context_omission_reason_is_incomplete_for_tip_missing_pos_params_source(
    ) {
        let reason = DbStore::classify_snapshot_bootstrap_context_omission_reason(
            2,
            2,
            true,
            "snapshot consensus bootstrap context missing pos_params at source state_root",
        );
        assert_eq!(
            reason,
            Some(SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete)
        );
    }

    #[allow(dead_code)]
    fn classify_snapshot_bootstrap_context_omission_reason_is_none_for_non_reachable_exports() {
        let reason = DbStore::classify_snapshot_bootstrap_context_omission_reason(
            1024,
            1485,
            false,
            "snapshot consensus bootstrap context missing seed for epoch 2",
        );
        assert_eq!(reason, None);
    }

    #[test]
    fn export_snapshot_v2_bundle_is_canonical_across_exports() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("snapshot-v2-canonical-export").unwrap();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir_a = tempfile::tempdir().unwrap();
        // This fixture only appends linear blocks and does not materialize a reachable
        // StateNodes tree. Canonicality of the export container must remain stable even
        // without state-node inclusion; reachability traversal is covered by dedicated
        // snapshot/state-node tests.
        let meta_a = storage
            .export_snapshot_v2_bundle(
                bundle_dir_a.path(),
                Some(2),
                Some(0),
                false,
                false,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        let bundle_dir_b = tempfile::tempdir().unwrap();
        let meta_b = storage
            .export_snapshot_v2_bundle(
                bundle_dir_b.path(),
                Some(2),
                Some(0),
                false,
                false,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        assert_eq!(meta_a.created_at_ts, 3);
        assert_eq!(meta_b.created_at_ts, 3);
        assert_eq!(meta_a.chunk_hashes_hex, meta_b.chunk_hashes_hex);
        assert_eq!(
            fs::read(bundle_dir_a.path().join("meta.json")).unwrap(),
            fs::read(bundle_dir_b.path().join("meta.json")).unwrap()
        );
        assert_eq!(
            snapshot_bundle_chunk_bytes(bundle_dir_a.path()),
            snapshot_bundle_chunk_bytes(bundle_dir_b.path())
        );
    }

    #[test]
    fn export_snapshot_v2_manifest_omits_compute_order_json_but_header_keeps_sidecar() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("snapshot-v2-meta-slim-compute-sidecar").unwrap();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                false,
                false,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        assert!(
            meta.compute_order_state_store_hash_hex.is_some(),
            "meta must still advertise the compute-order sidecar hash"
        );
        assert!(
            meta.compute_order_state_store_json.is_none(),
            "meta.json must remain a bounded manifest and must not carry the full compute-order JSON sidecar"
        );

        let disk_meta: crate::snapshot::SnapshotMeta =
            serde_json::from_slice(&fs::read(bundle_dir.path().join("meta.json")).unwrap())
                .unwrap();
        assert_eq!(
            disk_meta.compute_order_state_store_hash_hex,
            meta.compute_order_state_store_hash_hex
        );
        assert!(
            disk_meta.compute_order_state_store_json.is_none(),
            "persisted meta.json must omit the compute-order JSON sidecar"
        );

        let hdr = read_snapshot_v2_header_value(bundle_dir.path());
        let header_json = hdr
            .get("compute_order_state_store_json")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry compute-order JSON sidecar for import");
        let header_hash = hdr
            .get("compute_order_state_store_hash_hex")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry compute-order sidecar hash");
        assert_eq!(
            Some(header_hash.to_string()),
            meta.compute_order_state_store_hash_hex
        );
        assert_eq!(sha256_hex(header_json.as_bytes()), header_hash);

        let import_storage =
            open_clean_test_dbstore("snapshot-v2-meta-slim-compute-sidecar-import").unwrap();
        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), false)
            .unwrap();
        let imported_store = import_storage
            .get_compute_order_state_store_v1()
            .unwrap()
            .expect("import must restore compute-order store from the payload header sidecar");
        assert_eq!(imported_store.last_applied_height, 2);
        assert_eq!(imported_store.last_applied_hash, blocks[2].hash);
    }

    #[test]
    fn export_snapshot_v2_bundle_with_state_nodes_is_canonical_across_exports() {
        use crate::account::AccountState;
        use crate::state_smt::StateSmt;

        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("snapshot-v2-canonical-export-with-state-nodes").unwrap();
        let mut blocks = linear_blocks(3);

        let smt_store = StorageStateNodeStore {
            db: storage.db.clone(),
            inner: storage.state_nodes_keyspace.clone(),
        };
        let smt = StateSmt::new(smt_store);
        let account_key = [0x11u8; 32];
        let root = smt
            .update_account(
                smt.empty_root(),
                account_key,
                AccountState {
                    nonce: 1,
                    balance: 42,
                    data: vec![],
                },
            )
            .expect("must build reachable test SMT");
        let root_hex = hex::encode(root);
        blocks[2].state_root = root_hex.clone();
        blocks[2].hash = blocks[2].calculate_hash();
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir_a = tempfile::tempdir().unwrap();
        let meta_a = storage
            .export_snapshot_v2_bundle(
                bundle_dir_a.path(),
                Some(2),
                Some(0),
                true,
                true,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        let bundle_dir_b = tempfile::tempdir().unwrap();
        let meta_b = storage
            .export_snapshot_v2_bundle(
                bundle_dir_b.path(),
                Some(2),
                Some(0),
                true,
                true,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        assert_eq!(meta_a.created_at_ts, 3);
        assert_eq!(meta_b.created_at_ts, 3);
        assert_eq!(meta_a.state_root, root_hex);
        assert_eq!(meta_a.chunk_hashes_hex, meta_b.chunk_hashes_hex);
        assert_eq!(
            fs::read(bundle_dir_a.path().join("meta.json")).unwrap(),
            fs::read(bundle_dir_b.path().join("meta.json")).unwrap()
        );
        assert_eq!(
            snapshot_bundle_chunk_bytes(bundle_dir_a.path()),
            snapshot_bundle_chunk_bytes(bundle_dir_b.path())
        );
    }

    #[test]
    fn export_snapshot_v2_header_binds_created_at_ts_for_canonical_payload() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("snapshot-v2-header-created-at-bound").unwrap();
        let blocks = linear_blocks(2);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(1),
                Some(0),
                false,
                false,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        let header = read_snapshot_v2_header_value(bundle_dir.path());
        assert_eq!(
            header.get("created_at_ts").and_then(|v| v.as_u64()),
            Some(meta.created_at_ts),
            "canonical public snapshot header must bind created_at_ts: {header:?}"
        );
        assert_eq!(meta.created_at_ts, 2);
    }

    #[test]
    fn import_snapshot_v2_accepts_legacy_header_without_created_at_ts_in_dev_mode() {
        let _lock = test_process_lock();
        let export_storage =
            open_clean_test_dbstore("snapshot-v2-legacy-header-no-created-at-export").unwrap();
        let blocks = linear_blocks(2);
        for block in &blocks {
            export_storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&export_storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let _meta = export_storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(1),
                Some(0),
                false,
                false,
                1024 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        let chunk0_path = bundle_dir.path().join("chunks").join("000000.bin");
        let chunk0 = fs::read(&chunk0_path).unwrap();
        assert!(chunk0.len() >= 12);
        assert_eq!(&chunk0[..8], b"NGSNAP02");
        let hdr_len = u32::from_be_bytes(chunk0[8..12].try_into().unwrap()) as usize;
        let hdr_start = 12usize;
        let hdr_end = hdr_start + hdr_len;
        let mut header: serde_json::Value =
            serde_json::from_slice(&chunk0[hdr_start..hdr_end]).unwrap();
        if let Some(obj) = header.as_object_mut() {
            obj.remove("created_at_ts");
        }
        let header_bytes = serde_json::to_vec(&header).unwrap();

        assert!(
            header.get("created_at_ts").is_none(),
            "legacy/dev fixture must omit created_at_ts after mutation"
        );

        let mut legacy_payload = Vec::new();
        legacy_payload.extend_from_slice(b"NGSNAP02");
        legacy_payload.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        legacy_payload.extend_from_slice(&header_bytes);
        legacy_payload.extend_from_slice(&chunk0[hdr_end..]);
        fs::write(&chunk0_path, &legacy_payload).unwrap();

        let mut legacy_meta: SnapshotMeta =
            serde_json::from_slice(&fs::read(bundle_dir.path().join("meta.json")).unwrap())
                .unwrap();
        legacy_meta.bytes_len = legacy_payload.len() as u64;
        legacy_meta.chunk_hashes_hex = vec![sha256_hex(&legacy_payload)];
        fs::write(
            bundle_dir.path().join("meta.json"),
            serde_json::to_vec_pretty(&legacy_meta).unwrap(),
        )
        .unwrap();

        let import_storage =
            open_clean_test_dbstore("snapshot-v2-legacy-header-no-created-at-import").unwrap();
        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), false)
            .unwrap();

        let rep = import_storage.verify_db(true).unwrap();
        assert!(rep.ok, "issues={:?}", rep.issues);
        assert!(import_storage.get_block(0).unwrap().is_some());
        assert!(import_storage.get_block(1).unwrap().is_some());
    }

    #[test]
    fn export_snapshot_v2_pruned_window_requires_state_nodes_mainnet_strict() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let err = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(1),
                false,
                false,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("pruned window export requires state nodes"),
            "err={err:?}"
        );
    }

    #[test]
    fn put_economy_snapshot_indexes_historical_snapshot_by_height() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        let json = put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let indexed = storage.get_economy_snapshot_at_height(2).unwrap().unwrap();
        assert_eq!(indexed.0, 2);
        assert_eq!(indexed.1, json);
    }

    #[test]
    fn export_snapshot_v2_pruned_db_requires_indexed_historical_economy_snapshot() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        storage.meta_put_u64(META_BASE_HEIGHT_KEY, 1).unwrap();

        let chain = Blockchain::new();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();

        let bundle_dir = tempfile::tempdir().unwrap();
        let err = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(1),
                true,
                false,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("missing economy snapshot"),
            "err={err:?}"
        );
    }

    #[test]
    fn export_snapshot_v2_full_window_synthesizes_economy_snapshot_from_full_history() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                false,
                false,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .expect("full-history export must synthesize economy sidecar at target height");
        assert_eq!(meta.economy_snapshot_height, Some(2));
        assert!(meta.economy_snapshot_hash_hex.is_some());

        let hdr = read_snapshot_v2_header_value(bundle_dir.path());
        let header_econ_json = hdr
            .get("economy_snapshot_json")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry synthesized economy sidecar");
        let header_econ: SnapshotEconomyStateV1 = serde_json::from_str(header_econ_json).unwrap();
        assert_eq!(header_econ.height, 2);
        assert_eq!(header_econ.base_height, 0);
        assert_eq!(header_econ.block_hash, blocks[2].hash);
        let expected_econ_hash = sha256_hex(header_econ_json.as_bytes());
        assert_eq!(
            hdr.get("economy_snapshot_hash_hex")
                .and_then(|v| v.as_str()),
            Some(expected_econ_hash.as_str())
        );
    }

    #[test]
    fn export_snapshot_v2_historical_target_synthesizes_economy_when_latest_is_newer() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(4);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        assert_eq!(storage.get_economy_snapshot().unwrap().unwrap().0, 3);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                false,
                false,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .expect("full-history export must synthesize historical economy sidecar when latest is newer");
        assert_eq!(meta.height, 2);
        assert_eq!(meta.economy_snapshot_height, Some(2));

        let hdr = read_snapshot_v2_header_value(bundle_dir.path());
        let header_econ_json = hdr
            .get("economy_snapshot_json")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry historical economy sidecar");
        let header_econ: SnapshotEconomyStateV1 = serde_json::from_str(header_econ_json).unwrap();
        assert_eq!(header_econ.height, 2);
        assert_eq!(header_econ.block_hash, blocks[2].hash);
        assert_eq!(
            header_econ.state_root,
            if blocks[2].state_root.is_empty() {
                "0"
            } else {
                blocks[2].state_root.as_str()
            }
        );
    }

    #[test]
    fn export_snapshot_v2_historical_target_prefers_indexed_economy_snapshot() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(4);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let indexed_json = put_tip_economy_snapshot_for_blocks(&storage, &blocks[..3], 0);
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        assert_eq!(storage.get_economy_snapshot().unwrap().unwrap().0, 3);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                false,
                false,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .expect("export must use the indexed historical economy sidecar when available");
        assert_eq!(meta.economy_snapshot_height, Some(2));

        let hdr = read_snapshot_v2_header_value(bundle_dir.path());
        let header_econ_json = hdr
            .get("economy_snapshot_json")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry indexed historical economy sidecar");
        let header_econ: SnapshotEconomyStateV1 = serde_json::from_str(header_econ_json).unwrap();
        let indexed_econ: SnapshotEconomyStateV1 = serde_json::from_str(&indexed_json).unwrap();
        assert_eq!(header_econ.height, indexed_econ.height);
        assert_eq!(header_econ.block_hash, indexed_econ.block_hash);
        assert_eq!(header_econ.state_root, indexed_econ.state_root);
    }

    #[test]
    fn export_and_import_full_reachable_snapshot_preserve_tip_governance_anchor() {
        use crate::account::AccountState;
        use crate::state_smt::StateSmt;

        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("snapshot-v2-full-reachable-governance-anchor").unwrap();
        let mut blocks = linear_blocks(3);

        let smt_store = StorageStateNodeStore {
            db: storage.db.clone(),
            inner: storage.state_nodes_keyspace.clone(),
        };
        let smt = StateSmt::new(smt_store);
        let root = smt
            .update_account(
                smt.empty_root(),
                [0x22u8; 32],
                AccountState {
                    nonce: 1,
                    balance: 99,
                    data: vec![],
                },
            )
            .expect("must build reachable-only full snapshot test SMT");
        blocks[2].state_root = hex::encode(root);
        blocks[2].hash = blocks[2].calculate_hash();
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let gov_json =
            serde_json::to_string(Blockchain::new().governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                true,
                true,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();
        assert_eq!(meta.base_height, 0);
        assert_eq!(meta.governance_snapshot_height, Some(2));
        let expected_gov_hash = sha256_hex(gov_json.as_bytes());
        assert_eq!(
            meta.governance_snapshot_hash_hex.as_deref(),
            Some(expected_gov_hash.as_str())
        );
        assert!(
            meta.governance_snapshot_json.is_none(),
            "meta.json must remain a bounded manifest and must not carry the full governance JSON sidecar"
        );

        let disk_meta: SnapshotMeta =
            serde_json::from_slice(&fs::read(bundle_dir.path().join("meta.json")).unwrap())
                .unwrap();
        assert_eq!(disk_meta.governance_snapshot_height, Some(2));
        assert_eq!(
            disk_meta.governance_snapshot_hash_hex.as_deref(),
            meta.governance_snapshot_hash_hex.as_deref()
        );
        assert!(disk_meta.governance_snapshot_json.is_none());

        let hdr = read_snapshot_v2_header_value(bundle_dir.path());
        let header_gov_json = hdr
            .get("governance_snapshot_json")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry governance JSON sidecar for import");
        let header_gov_hash = hdr
            .get("governance_snapshot_hash_hex")
            .and_then(|v| v.as_str())
            .expect("snapshot payload header must carry governance sidecar hash");
        assert_eq!(header_gov_json, gov_json);
        assert_eq!(sha256_hex(header_gov_json.as_bytes()), header_gov_hash);
        assert_eq!(
            Some(header_gov_hash),
            meta.governance_snapshot_hash_hex.as_deref()
        );

        let import_storage =
            open_clean_test_dbstore("import-full-reachable-v2-governance-anchor").unwrap();
        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), false)
            .unwrap();

        let rep = import_storage.verify_db(true).unwrap();
        assert!(rep.ok, "issues={:?}", rep.issues);
        let (snap_h, snap_json) = import_storage.get_governance_snapshot().unwrap().unwrap();
        assert_eq!(snap_h, 2);
        assert_eq!(snap_json, gov_json);
    }

    #[test]
    fn import_snapshot_v2_accepts_legacy_governance_sidecar_in_meta_json() {
        use crate::account::AccountState;
        use crate::state_smt::StateSmt;

        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("snapshot-v2-legacy-governance-sidecar-meta").unwrap();
        let mut blocks = linear_blocks(3);

        let smt_store = StorageStateNodeStore {
            db: storage.db.clone(),
            inner: storage.state_nodes_keyspace.clone(),
        };
        let smt = StateSmt::new(smt_store);
        let root = smt
            .update_account(
                smt.empty_root(),
                [0x33u8; 32],
                AccountState {
                    nonce: 1,
                    balance: 7,
                    data: vec![],
                },
            )
            .expect("must build reachable-only legacy governance snapshot SMT");
        blocks[2].state_root = hex::encode(root);
        blocks[2].hash = blocks[2].calculate_hash();
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let gov_json =
            serde_json::to_string(Blockchain::new().governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                true,
                true,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();

        let chunk0_path = bundle_dir.path().join("chunks").join("000000.bin");
        let chunk0 = fs::read(&chunk0_path).unwrap();
        assert_eq!(&chunk0[..8], b"NGSNAP02");
        let hdr_len = u32::from_be_bytes(chunk0[8..12].try_into().unwrap()) as usize;
        let hdr_start = 12usize;
        let hdr_end = hdr_start + hdr_len;
        let mut header: serde_json::Value =
            serde_json::from_slice(&chunk0[hdr_start..hdr_end]).unwrap();
        header
            .as_object_mut()
            .unwrap()
            .remove("governance_snapshot_height");
        header
            .as_object_mut()
            .unwrap()
            .remove("governance_snapshot_json");
        header
            .as_object_mut()
            .unwrap()
            .remove("governance_snapshot_hash_hex");
        let header_bytes = serde_json::to_vec(&header).unwrap();

        let mut legacy_payload = Vec::new();
        legacy_payload.extend_from_slice(b"NGSNAP02");
        legacy_payload.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        legacy_payload.extend_from_slice(&header_bytes);
        legacy_payload.extend_from_slice(&chunk0[hdr_end..]);
        fs::write(&chunk0_path, &legacy_payload).unwrap();

        let mut legacy_meta: SnapshotMeta =
            serde_json::from_slice(&fs::read(bundle_dir.path().join("meta.json")).unwrap())
                .unwrap();
        legacy_meta.governance_snapshot_height = Some(2);
        legacy_meta.governance_snapshot_hash_hex = Some(sha256_hex(gov_json.as_bytes()));
        legacy_meta.governance_snapshot_json = Some(gov_json.clone());
        legacy_meta.bytes_len = snapshot_bundle_chunk_bytes(bundle_dir.path())
            .iter()
            .map(|chunk| chunk.len() as u64)
            .sum();
        legacy_meta.chunk_hashes_hex = snapshot_bundle_chunk_bytes(bundle_dir.path())
            .iter()
            .map(|chunk| sha256_hex(chunk))
            .collect();
        fs::write(
            bundle_dir.path().join("meta.json"),
            serde_json::to_vec_pretty(&legacy_meta).unwrap(),
        )
        .unwrap();

        let import_storage =
            open_clean_test_dbstore("import-v2-legacy-governance-sidecar-meta").unwrap();
        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), false)
            .unwrap();

        let (snap_h, snap_json) = import_storage.get_governance_snapshot().unwrap().unwrap();
        assert_eq!(snap_h, 2);
        assert_eq!(snap_json, gov_json);
    }

    #[test]
    fn import_snapshot_v2_reachable_only_persists_reachable_state_import_marker() {
        use crate::account::AccountState;
        use crate::state_smt::StateSmt;

        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("snapshot-v2-reachable-only-import-marker-src").unwrap();
        let mut blocks = linear_blocks(3);

        let smt_store = StorageStateNodeStore {
            db: storage.db.clone(),
            inner: storage.state_nodes_keyspace.clone(),
        };
        let smt = StateSmt::new(smt_store);
        let root = smt
            .update_account(
                smt.empty_root(),
                [0x33u8; 32],
                AccountState {
                    nonce: 7,
                    balance: 1234,
                    data: vec![],
                },
            )
            .unwrap();
        blocks[2].state_root = hex::encode(root);
        blocks[2].hash = blocks[2].calculate_hash();
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        let meta = storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(2),
                Some(0),
                true,
                true,
                64 * 1024,
                10 * 1024 * 1024,
            )
            .unwrap();
        assert!(meta.reachable_state_nodes);
        assert_eq!(
            meta.state_coverage_mode,
            SnapshotStateCoverageMode::TipReachableOnly
        );
        assert!(!meta.historical_state_roots_queryable);

        let import_storage =
            open_clean_test_dbstore("snapshot-v2-reachable-only-import-marker-dst").unwrap();
        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), true)
            .unwrap();

        let marker = import_storage
            .get_snapshot_reachable_state_import_marker()
            .unwrap()
            .expect("reachable-only import must persist marker");
        assert_eq!(marker.height, meta.height);
        assert_eq!(marker.state_root, meta.state_root);
        assert_eq!(marker.window_from_height, meta.window_from_height);
        assert_eq!(marker.window_to_height, meta.window_to_height);
        assert_eq!(
            marker.state_coverage_mode,
            SnapshotStateCoverageMode::TipReachableOnly
        );
        assert!(!marker.historical_state_roots_queryable);
        assert!(
            import_storage
                .validate_reachable_state_root_closure(&marker.state_root, 1_000_000)
                .unwrap()
                > 0
        );
    }

    #[allow(dead_code)]
    fn snapshot_env_helpers_fallback_to_defaults_on_invalid_values() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&[
            "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_BYTES",
            "NEWGEN_STATE_SYNC_MAX_SNAPSHOT_CHUNKS",
        ]);
        std::env::set_var("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_BYTES", "not-a-number");
        std::env::set_var("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_CHUNKS", "also-bad");

        assert_eq!(env_usize("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_BYTES", 123), 123);
        assert_eq!(env_u64("NEWGEN_STATE_SYNC_MAX_SNAPSHOT_CHUNKS", 456), 456);
    }

    #[test]
    fn import_snapshot_rejects_bad_magic() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let path = write_temp_snapshot_file(b"BADSIGN!", "bad-magic");

        let err = storage.import_snapshot(&path, false).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(msg.contains("bad magic"), "unexpected msg: {msg}")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn import_snapshot_rejects_header_larger_than_limit() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&["NG_SNAPSHOT_MAX_HEADER_BYTES"]);
        std::env::set_var("NG_SNAPSHOT_MAX_HEADER_BYTES", "16");
        let storage = open_test_storage();
        let header = vec![0u8; 32];
        let path = write_temp_snapshot_file(&header_only_snapshot_bytes(&header), "hdr-limit");

        let err = storage.import_snapshot(&path, false).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(msg.contains("header too large"), "unexpected msg: {msg}")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn snapshot_v2_sidecar_byte_accounting_counts_header_sidecars_v186() {
        let gov = Some("g".repeat(11));
        let econ = Some("e".repeat(13));
        let compute = Some("c".repeat(17));

        assert_eq!(
            snapshot_v2_sidecar_bytes(&gov, &econ, &compute),
            (11, 13, 17, 41)
        );
    }

    #[test]
    fn snapshot_v2_header_limits_use_mainnet_safe_defaults_v186() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&[
            "NG_SNAPSHOT_WARN_HEADER_BYTES",
            "NG_SNAPSHOT_MAX_HEADER_BYTES",
        ]);
        std::env::remove_var("NG_SNAPSHOT_WARN_HEADER_BYTES");
        std::env::remove_var("NG_SNAPSHOT_MAX_HEADER_BYTES");

        assert_eq!(
            snapshot_v2_header_warn_bytes(),
            SNAPSHOT_V2_DEFAULT_HEADER_WARN_BYTES
        );
        assert_eq!(
            snapshot_v2_header_max_bytes(),
            SNAPSHOT_V2_DEFAULT_HEADER_MAX_BYTES
        );
    }

    #[test]
    fn import_snapshot_rejects_height_above_limit() {
        let _lock = test_process_lock();
        let _env = EnvGuard::capture(&["NG_SNAPSHOT_MAX_HEIGHT"]);
        std::env::set_var("NG_SNAPSHOT_MAX_HEIGHT", "5");
        let storage = open_test_storage();
        let header = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "height": 9,
            "tip_hash": "tip",
            "tip_state_root": "root",
            "include_state_nodes": false
        }))
        .unwrap();
        let path = write_temp_snapshot_file(&header_only_snapshot_bytes(&header), "height-limit");

        let err = storage.import_snapshot(&path, false).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(msg.contains("height too large"), "unexpected msg: {msg}")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn import_snapshot_validation_failure_does_not_leave_pending_journal() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let path = write_temp_snapshot_file(b"BADSIGN!", "bad-magic-no-journal");

        let _ = storage.import_snapshot(&path, false).unwrap_err();
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "validation-only snapshot import failure must not leave journal_pending"
        );
    }

    #[test]
    fn import_snapshot_v2_validation_failure_does_not_leave_pending_journal() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let empty_bundle = tempfile::tempdir().unwrap();

        let _ = storage
            .import_snapshot_v2_bundle(empty_bundle.path(), false)
            .unwrap_err();
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "validation-only snapshot v2 import failure must not leave journal_pending"
        );
    }

    #[test]
    fn runtime_schema_admission_rejects_non_empty_backend_without_db_version() {
        let _lock = test_process_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(dir.path()).unwrap();
        db.put(ColumnFamily::Blocks, b"block:0", br#"{}"#).unwrap();
        db.meta_remove(META_DB_VERSION_KEY).unwrap();

        let err = DbStore::open(dir.path()).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(msg.contains("db_version missing"), "unexpected msg: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn runtime_schema_admission_rejects_unsupported_db_version() {
        let _lock = test_process_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(dir.path()).unwrap();
        db.meta_put_u32(META_DB_VERSION_KEY, 999).unwrap();

        let err = DbStore::open(dir.path()).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(
                    msg.contains("unsupported runtime db_version"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn canonical_db_open_reuses_same_physical_backend_state() {
        let _lock = test_process_lock();
        let dir = tempfile::tempdir().unwrap();
        let db1 = DbStore::open(dir.path()).unwrap();
        db1.meta_put_string(META_TIP_HASH_KEY, "tip-a").unwrap();
        let db2 = DbStore::open(dir.path()).unwrap();
        assert_eq!(
            db2.meta_get_string_opt(META_TIP_HASH_KEY)
                .unwrap()
                .as_deref(),
            Some("tip-a")
        );
    }

    #[test]
    fn failed_open_evicts_canonical_registry_so_clean_recovery_can_reopen() {
        let _lock = test_process_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(dir.path()).unwrap();
        db.put(ColumnFamily::Blocks, b"block:0", br#"{}"#).unwrap();
        db.meta_remove(META_DB_VERSION_KEY).unwrap();
        drop(db);

        let err = DbStore::open(dir.path()).unwrap_err();
        match err {
            StorageError::BackendError(msg) => {
                assert!(
                    msg.contains("db_version missing") || msg.contains("fail-open"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        std::fs::remove_dir_all(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();

        let reopened = DbStore::open(dir.path())
            .expect("stale canonical handle must be evicted after failed open");
        assert_eq!(reopened.get_height().unwrap_or(0), 0);
    }

    #[test]
    fn interprocess_open_conflict_is_classified_and_never_recovered_as_corruption() {
        let _lock = test_process_lock();
        let err = StorageError::InterprocessOpenConflict {
            path: "/tmp/example-db".to_string(),
            message: "runtime db dir is already locked by another process".to_string(),
        };
        assert!(err.is_interprocess_open_conflict());
        let rendered = err.to_string();
        assert!(rendered.contains("db_dir_locked"));
        assert!(rendered.contains("already locked"));
    }

    #[test]
    fn cognitive_registry_read_paths_fail_closed_on_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(dir.path()).unwrap();
        let object_hash = "11".repeat(32);
        let claim_hash = "22".repeat(32);
        let entry_key = cognitive_registry_entry_storage_key(&object_hash).unwrap();
        db.put(
            ColumnFamily::CognitiveRegistryEntries,
            &entry_key,
            br#"{"object_hash_hex":"bad"}"#,
        )
        .unwrap();
        assert!(db.cognitive_registry_get_entry(&object_hash).is_err());

        let claim_key = cognitive_registry_claim_index_storage_key(&claim_hash).unwrap();
        let bad_claim_rows = serde_json::to_vec(&vec!["bad".to_string()]).unwrap();
        db.put(
            ColumnFamily::CognitiveRegistryByClaim,
            &claim_key,
            &bad_claim_rows,
        )
        .unwrap();
        assert!(db.cognitive_registry_get_claim_index(&claim_hash).is_err());

        let event = CognitiveRegistryEventV1 {
            block_height: 7,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Anchor,
            object_hash_hex: object_hash.clone(),
            claim_hash_hex: claim_hash.clone(),
            old_lifecycle_state: None,
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            related_object_hash_hex: None,
            reason_code: Some("should_not_be_here".to_string()),
            block_hash: "33".repeat(32),
        };
        let event_key = cognitive_registry_event_storage_key(7, 1);
        let event_bytes = serde_json::to_vec(&event).unwrap();
        db.put(
            ColumnFamily::CognitiveRegistryEvents,
            &event_key,
            &event_bytes,
        )
        .unwrap();
        assert!(db.cognitive_registry_get_events_since(0, 10).is_err());
    }

    #[test]
    fn mirror_chain_invalidates_stale_aux_and_rebuilds_cognitive_registry() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("mirror-aux-rebuild").unwrap();

        let mut chain = Blockchain::new();
        chain.genesis_hash = sample_hash(0x11);

        let mut block = crate::block::Block::default();
        block.index = 1;
        block.previous_hash = chain.chain.last().unwrap().hash.clone();
        block.cognitive_txs = vec![sample_anchor_tx(sample_hash(0x66), sample_hash(0x77))];
        block.hash = block.calculate_hash();
        chain.chain.push(block);

        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                b"finality_bft_meta_v1",
                br#"{"finalized_height":999,"finalized_hash":"x","highest_qc_height":999,"highest_qc_round":1,"highest_qc_block_hash":"y"}"#,
            )
            .unwrap();
        storage
            .cognitive_registry_set_last_applied_height(999)
            .unwrap();

        mirror_blockchain_to_storage(&storage, &chain).unwrap();

        let rep = storage.verify_db(true).unwrap();
        assert!(rep.ok, "verify issues after mirror: {:?}", rep.issues);
        assert!(!rep.needs_recovery, "mirror left recovery pending");

        let object_hash = sample_hash(0x66);
        let claim_hash = sample_hash(0x77);
        let entry = storage
            .cognitive_registry_get_entry(&object_hash)
            .unwrap()
            .expect("cognitive registry must be rebuilt from mirrored chain");
        assert_eq!(entry.claim_hash_hex, claim_hash);
        assert_eq!(entry.anchor_height, 1);
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            Some(1)
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "mirror journal must be cleared on success"
        );
    }

    #[test]
    fn mirror_chain_fast_path_repairs_missing_tx_index_without_dropping_bootstrap_context() {
        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("mirror_chain_fast_path_repairs_missing_tx_index").unwrap();
        let mut blocks = linear_blocks(2);
        let tx = Transaction::new(
            "sender".to_string(),
            "receiver".to_string(),
            7,
            1,
            0,
            "sig".to_string(),
            false,
            None,
        );
        blocks[1].transactions = vec![tx.clone()];
        blocks[1].hash = blocks[1].calculate_hash();

        let mut chain = Blockchain::new();
        chain.chain = blocks;
        let tip = chain.chain.last().expect("chain tip must exist");
        let snapshot_height = tip.index;
        let state_root = tip.state_root.clone();

        mirror_blockchain_to_storage(&storage, &chain).unwrap();
        let ctx = sample_snapshot_consensus_bootstrap_context(snapshot_height, &state_root);
        ctx.validate_basic(snapshot_height, &state_root)
            .expect("test bootstrap context must match mirrored chain tip");
        storage
            .put_snapshot_consensus_bootstrap_context(&ctx, false)
            .unwrap();
        storage
            .delete(ColumnFamily::TxIndex, tx.hash.as_bytes())
            .unwrap();

        mirror_blockchain_to_storage(&storage, &chain).unwrap();

        let stored_height = decode_u64(
            &storage
                .get(ColumnFamily::TxIndex, tx.hash.as_bytes())
                .unwrap()
                .expect("missing tx index after fast path repair"),
        )
        .unwrap();
        assert_eq!(stored_height, 1);
        let restored = storage
            .get_snapshot_consensus_bootstrap_context()
            .unwrap()
            .expect("matching bootstrap context must survive idempotent mirror fast path");
        assert_eq!(restored, ctx);
    }

    #[test]
    fn mirror_chain_preserves_matching_snapshot_consensus_bootstrap_context() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("mirror-preserves-snapshot-bootstrap").unwrap();

        let mut chain = Blockchain::new();
        let state_root = sample_hash(0x31);
        chain.chain[0].state_root = state_root.clone();
        let ctx = sample_snapshot_consensus_bootstrap_context(0, &state_root);
        storage
            .put_snapshot_consensus_bootstrap_context(&ctx, false)
            .unwrap();

        mirror_blockchain_to_storage(&storage, &chain).unwrap();

        let persisted = storage
            .get_snapshot_consensus_bootstrap_context()
            .unwrap()
            .expect("matching bootstrap context must survive full mirror");
        assert_eq!(persisted, ctx);
    }

    #[test]
    fn mirror_chain_with_state_preserves_matching_snapshot_consensus_bootstrap_context() {
        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("mirror-with-state-preserves-snapshot-bootstrap").unwrap();

        let mut chain = Blockchain::new();
        let state_root = sample_hash(0x32);
        chain.chain[0].state_root = state_root.clone();
        let ctx = sample_snapshot_consensus_bootstrap_context(0, &state_root);
        storage
            .put_snapshot_consensus_bootstrap_context(&ctx, false)
            .unwrap();

        mirror_blockchain_to_storage_with_state(&storage, &chain, &[]).unwrap();

        let persisted = storage
            .get_snapshot_consensus_bootstrap_context()
            .unwrap()
            .expect("matching bootstrap context must survive full mirror with state");
        assert_eq!(persisted, ctx);
    }

    #[test]
    fn mirror_chain_clears_stale_snapshot_consensus_bootstrap_context() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("mirror-clears-stale-snapshot-bootstrap").unwrap();

        let chain = Blockchain::new();
        let stale = sample_snapshot_consensus_bootstrap_context(99, &sample_hash(0x99));
        storage
            .put_snapshot_consensus_bootstrap_context(&stale, false)
            .unwrap();

        mirror_blockchain_to_storage(&storage, &chain).unwrap();

        assert!(
            storage
                .get_snapshot_consensus_bootstrap_context()
                .unwrap()
                .is_none(),
            "stale bootstrap context must not survive an unrelated mirror"
        );
    }

    #[test]
    fn mirror_chain_preserves_durable_last_vote_store() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("mirror-preserves-last-vote").unwrap();

        let signer = SigningKey::from_bytes(&[8u8; 32]);
        let vote = finality_bft::sign_vote_v1(
            &signer,
            crate::chain_identity::chain_id(),
            1,
            7,
            2,
            &sample_hash(0xaa),
        )
        .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000007:0000000002",
                &serde_json::to_vec(&vote).unwrap(),
            )
            .unwrap();

        let chain = Blockchain::new();
        mirror_blockchain_to_storage(&storage, &chain).unwrap();

        let persisted = storage
            .get(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000007:0000000002",
            )
            .unwrap();
        assert!(
            persisted.is_some(),
            "mirror must preserve last-vote safety state"
        );
    }

    #[test]
    fn repair_db_preserves_durable_last_vote_store() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-preserves-last-vote").unwrap();

        let chain = Blockchain::new();
        let genesis = chain.chain[0].clone();
        storage.append_block(&genesis).unwrap();
        storage.meta_put_u64(META_HEIGHT_KEY, 99).unwrap();
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let vote = finality_bft::sign_vote_v1(
            &signer,
            crate::chain_identity::chain_id(),
            1,
            3,
            1,
            &sample_hash(0x77),
        )
        .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000003:0000000001",
                &serde_json::to_vec(&vote).unwrap(),
            )
            .unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(rep.ok, "repair issues: {:?}", rep.issues);
        assert!(
            storage
                .get(
                    ColumnFamily::FinalityBftLastVote,
                    b"fv:00000000000000000003:0000000001",
                )
                .unwrap()
                .is_some(),
            "repair must preserve last-vote safety state"
        );
    }

    #[test]
    fn repair_db_clears_auxiliary_runtime_state_after_truncate() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-clears-aux").unwrap();

        let chain = Blockchain::new();
        let genesis = chain.chain[0].clone();
        let mut block = crate::block::Block::default();
        block.index = 1;
        block.previous_hash = genesis.hash.clone();
        block.hash = block.calculate_hash();

        storage.append_block(&genesis).unwrap();
        storage.append_block(&block).unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                b"finality_bft_meta_v1",
                br#"{"finalized_height":999,"finalized_hash":"x","highest_qc_height":999,"highest_qc_round":1,"highest_qc_block_hash":"y"}"#,
            )
            .unwrap();
        storage
            .cognitive_registry_set_last_applied_height(999)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(77).unwrap();
        storage.meta_put_u64(META_HEIGHT_KEY, 9).unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(rep.ok, "repair issues: {:?}", rep.issues);
        assert_eq!(storage.get_height().unwrap(), 1);
        assert!(
            storage
                .get(ColumnFamily::FinalityBftMeta, b"finality_bft_meta_v1")
                .unwrap()
                .is_none(),
            "repair must invalidate stale finality meta"
        );
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            None
        );
        assert_eq!(
            storage.cognitive_registry_get_last_event_seq().unwrap(),
            None
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair journal must be cleared on success"
        );
    }

    #[test]
    fn repair_db_true_repairs_corruption_outside_quick_verify_window() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-full-preflight-escalation").unwrap();

        let blocks = linear_blocks(2055);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        // Corrupt an old block that is outside verify_db(false)'s quick window.
        let mut corrupted = blocks[1].clone();
        corrupted.previous_hash = "corrupted-prev-hash".to_string();
        storage
            .put(
                ColumnFamily::Blocks,
                block_key(corrupted.index).as_bytes(),
                &serde_json::to_vec(&corrupted).unwrap(),
            )
            .unwrap();
        storage.flush_db().unwrap();

        let quick = storage.verify_db(false).unwrap();
        assert!(quick.ok, "quick verify should miss the old corruption so repair_db(true) must escalate; issues={:?}", quick.issues);
        assert!(
            !quick.needs_recovery,
            "quick verify unexpectedly requested recovery: {:?}",
            quick.issues
        );

        let rep = storage.repair_db(true).unwrap();
        assert!(
            rep.ok,
            "repair_db(true) must actually repair corruption found by the full preflight: {:?}",
            rep.issues
        );
        assert!(
            !rep.needs_recovery,
            "repair_db(true) left recovery pending after repairing old corruption"
        );

        assert_eq!(storage.get_height().unwrap(), 0, "repair must truncate the chain back to the last good block when corruption is detected outside the quick window");
        assert!(storage.get_block(1).unwrap().is_none(), "repair must delete blocks after the first corrupted height when full preflight finds old corruption");
        let repaired_tip = storage.get_block(0).unwrap().unwrap();
        assert_eq!(
            repaired_tip.hash, blocks[0].hash,
            "repair must preserve the last good canonical block after truncating old corruption"
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair_db(true) must clear journal_pending after repairing corruption outside the quick window"
        );
    }

    #[test]
    fn repair_db_is_noop_on_clean_db_and_preserves_auxiliary_runtime_state() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-noop-clean-db").unwrap();

        let chain = Blockchain::new();
        let genesis = chain.chain[0].clone();
        storage.append_block(&genesis).unwrap();
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let vote = finality_bft::sign_vote_v1(
            &signer,
            crate::chain_identity::chain_id(),
            1,
            0,
            0,
            &genesis.hash,
        )
        .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000000:0000000000",
                &serde_json::to_vec(&vote).unwrap(),
            )
            .unwrap();
        let meta = PersistedFinalityBftMetaV1 {
            finalized_height: 0,
            finalized_hash: genesis.hash.clone(),
            highest_qc_height: 0,
            highest_qc_round: 0,
            highest_qc_block_hash: genesis.hash.clone(),
        };
        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                b"finality_bft_meta_v1",
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
        let qc = finality_bft::FinalityBftCertV1 {
            epoch: 1,
            height: 0,
            round: 0,
            block_hash: genesis.hash.clone(),
            voter_bitset: Vec::new(),
            sigs_b64: Vec::new(),
        };
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                format!("qc:{:016x}:{}", 0u64, genesis.hash).as_bytes(),
                &serde_json::to_vec(&qc).unwrap(),
            )
            .unwrap();
        let object_hash = sample_hash(0x91);
        let claim_hash = sample_hash(0x92);
        let entry = crate::cognitive_chain::CognitiveRegistryEntryV1 {
            object_hash_hex: object_hash.clone(),
            claim_hash_hex: claim_hash.clone(),
            lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            policy_id: "default_policy".to_string(),
            anchor_height: 0,
            anchor_block_hash: genesis.hash.clone(),
            evidence_root_hex: sample_hash(0x93),
            context_hash_hex: sample_hash(0x94),
            model_manifest_hash_hex: sample_hash(0x95),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 0,
        };
        storage.cognitive_registry_put_entry(&entry).unwrap();
        storage
            .cognitive_registry_put_claim_index(&claim_hash, &vec![object_hash.clone()])
            .unwrap();
        let event = CognitiveRegistryEventV1 {
            block_height: 0,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Anchor,
            object_hash_hex: object_hash.clone(),
            claim_hash_hex: claim_hash.clone(),
            old_lifecycle_state: None,
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            related_object_hash_hex: None,
            reason_code: None,
            block_hash: genesis.hash.clone(),
        };
        storage.cognitive_registry_append_event(&event).unwrap();
        storage
            .cognitive_registry_set_last_applied_height(0)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(1).unwrap();
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .meta_put_string(META_GOV_BOOTSTRAP_JSON_KEY, &gov_json)
            .unwrap();
        storage
            .put_governance_snapshot(0, &gov_json, false)
            .unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(rep.ok, "repair issues: {:?}", rep.issues);
        assert!(!rep.needs_recovery, "clean DB repair must remain no-op");
        assert!(
            storage
                .get(
                    ColumnFamily::FinalityBftLastVote,
                    b"fv:00000000000000000000:0000000000",
                )
                .unwrap()
                .is_some(),
            "repair on a clean DB must preserve durable anti-equivocation state"
        );
        assert!(
            storage
                .get(ColumnFamily::FinalityBftMeta, b"finality_bft_meta_v1")
                .unwrap()
                .is_some(),
            "repair on a clean DB must not wipe valid finality meta"
        );
        assert!(
            storage
                .get(
                    ColumnFamily::FinalityBftQcArchive,
                    format!("qc:{:016x}:{}", 0u64, genesis.hash).as_bytes(),
                )
                .unwrap()
                .is_some(),
            "repair on a clean DB must not wipe valid QC archive"
        );
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            storage.cognitive_registry_get_last_event_seq().unwrap(),
            Some(1)
        );
        assert_eq!(
            storage
                .cognitive_registry_get_entry(&object_hash)
                .unwrap()
                .as_ref(),
            Some(&entry)
        );
        assert_eq!(
            storage
                .cognitive_registry_get_claim_index(&claim_hash)
                .unwrap(),
            vec![object_hash.clone()]
        );
        let persisted_events = storage.cognitive_registry_get_events_since(0, 10).unwrap();
        assert_eq!(persisted_events, vec![event.clone()]);
        assert_eq!(
            storage.get_governance_bootstrap_json().unwrap().as_deref(),
            Some(gov_json.as_str())
        );
        let (gov_h, persisted_gov_json) = storage.get_governance_snapshot().unwrap().unwrap();
        assert_eq!(gov_h, 0);
        assert_eq!(persisted_gov_json, gov_json);
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair no-op must not leave a pending journal"
        );
    }

    #[test]
    fn import_snapshot_invalidates_auxiliary_runtime_state_but_preserves_last_vote() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("import-snapshot-clears-aux").unwrap();
        seed_stale_auxiliary_runtime_state(&storage);

        let chain = Blockchain::new();
        let snapshot = snapshot_bytes_from_blocks(&chain.chain, false);
        let path = write_temp_snapshot_file(&snapshot, "clear-aux-v1");

        storage.import_snapshot(&path, false).unwrap();

        let rep = storage.verify_db(true).unwrap();
        assert!(
            rep.ok,
            "verify issues after import-snapshot: {:?}",
            rep.issues
        );
        assert!(
            storage
                .get(ColumnFamily::FinalityBftMeta, b"finality_bft_meta_v1")
                .unwrap()
                .is_none(),
            "import_snapshot must invalidate stale finality meta"
        );
        assert!(
            storage
                .get(
                    ColumnFamily::FinalityBftQcArchive,
                    b"qc:00000000000000000009:0000000001",
                )
                .unwrap()
                .is_none(),
            "import_snapshot must invalidate stale QC archive"
        );
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            None
        );
        assert_eq!(
            storage.cognitive_registry_get_last_event_seq().unwrap(),
            None
        );
        assert_eq!(
            storage.get_governance_bootstrap_json().unwrap(),
            None,
            "import_snapshot must clear stale governance bootstrap cache"
        );
        assert_eq!(
            storage.get_governance_snapshot().unwrap().map(|(_, js)| js),
            None,
            "import_snapshot must clear stale governance snapshot cache"
        );
        assert!(
            storage
                .get(
                    ColumnFamily::FinalityBftLastVote,
                    b"fv:00000000000000000003:0000000001",
                )
                .unwrap()
                .is_some(),
            "import_snapshot must preserve durable anti-equivocation last-vote state"
        );
    }

    #[test]
    fn import_snapshot_v2_invalidates_auxiliary_runtime_state_but_preserves_last_vote() {
        let _lock = test_process_lock();
        let export_storage = open_clean_test_dbstore("export-snapshot-v2").unwrap();
        let chain = Blockchain::new();
        export_storage.append_block(&chain.chain[0]).unwrap();
        put_tip_economy_snapshot_for_blocks(&export_storage, &chain.chain, 0);

        let bundle_dir = tempfile::tempdir().unwrap();
        export_storage
            .export_snapshot_v2_bundle(
                bundle_dir.path(),
                Some(0),
                Some(0),
                false,
                false,
                1024,
                1_000_000,
            )
            .unwrap();

        let import_storage = open_clean_test_dbstore("import-snapshot-v2-clears-aux").unwrap();
        seed_stale_auxiliary_runtime_state(&import_storage);

        import_storage
            .import_snapshot_v2_bundle(bundle_dir.path(), false)
            .unwrap();

        let rep = import_storage.verify_db(true).unwrap();
        assert!(
            rep.ok,
            "verify issues after import-snapshot-v2: {:?}",
            rep.issues
        );
        assert!(
            import_storage
                .get(ColumnFamily::FinalityBftMeta, b"finality_bft_meta_v1")
                .unwrap()
                .is_none(),
            "import_snapshot_v2 must invalidate stale finality meta"
        );
        assert!(
            import_storage
                .get(
                    ColumnFamily::FinalityBftQcArchive,
                    b"qc:00000000000000000009:0000000001",
                )
                .unwrap()
                .is_none(),
            "import_snapshot_v2 must invalidate stale QC archive"
        );
        assert_eq!(
            import_storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            None
        );
        assert_eq!(
            import_storage
                .cognitive_registry_get_last_event_seq()
                .unwrap(),
            None
        );
        assert_eq!(
            import_storage.get_governance_bootstrap_json().unwrap(),
            None,
            "import_snapshot_v2 must clear stale governance bootstrap cache"
        );
        assert_eq!(
            import_storage
                .get_governance_snapshot()
                .unwrap()
                .map(|(_, js)| js),
            None,
            "import_snapshot_v2 must clear stale governance snapshot cache"
        );
        assert!(
            import_storage
                .get(
                    ColumnFamily::FinalityBftLastVote,
                    b"fv:00000000000000000003:0000000001",
                )
                .unwrap()
                .is_some(),
            "import_snapshot_v2 must preserve durable anti-equivocation last-vote state"
        );
    }
    #[test]
    fn verify_db_reports_auxiliary_corruption_without_aborting() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        for block in linear_blocks(3) {
            storage.append_block(&block).unwrap();
        }

        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                FINALITY_BFT_META_DB_KEY.as_bytes(),
                b"not-json",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                b"qc:0000000000000001:bad",
                b"not-json",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::CognitiveRegistryMeta,
                cognitive_registry_meta_last_applied_height_key(),
                b"bad-u64",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_BOOTSTRAP_JSON_KEY.as_bytes(),
                &[0xff, 0xfe, 0xfd],
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes(),
                b"bad-height",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_JSON_KEY.as_bytes(),
                b"{}",
            )
            .unwrap();

        let report = storage.verify_db(true).unwrap();
        assert!(!report.ok);
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("finality_meta decode failed")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("finality_qc_archive")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("cognitive_registry meta last_applied_height decode failed")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("governance bootstrap meta invalid UTF-8")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("governance snapshot height decode failed")));
    }

    #[test]
    fn repair_db_clears_corrupt_rebuildable_auxiliary_state_and_governance_cache() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        for block in linear_blocks(3) {
            storage.append_block(&block).unwrap();
        }

        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                FINALITY_BFT_META_DB_KEY.as_bytes(),
                b"not-json",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                b"qc:0000000000000001:bad",
                b"not-json",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::CognitiveRegistryEntries,
                b"entry:bad",
                br#"{"object_hash_hex":"bad"}"#,
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::CognitiveRegistryMeta,
                cognitive_registry_meta_last_event_seq_key(),
                b"bad-u64",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_BOOTSTRAP_JSON_KEY.as_bytes(),
                &[0xff, 0xfe],
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes(),
                b"bad-height",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_JSON_KEY.as_bytes(),
                b"{}",
            )
            .unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(
            rep.ok,
            "repair must recover rebuildable auxiliary corruption: {:?}",
            rep.issues
        );
        assert!(storage
            .get(
                ColumnFamily::FinalityBftMeta,
                FINALITY_BFT_META_DB_KEY.as_bytes()
            )
            .unwrap()
            .is_none());
        assert!(storage
            .iter_all_cf(ColumnFamily::FinalityBftQcArchive)
            .unwrap()
            .next()
            .is_none());
        assert!(storage
            .iter_all_cf(ColumnFamily::CognitiveRegistryEntries)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(storage.get_governance_bootstrap_json().unwrap(), None);
        assert_eq!(storage.get_governance_snapshot().unwrap(), None);
    }

    #[test]
    fn repair_db_governance_only_corruption_preserves_unrelated_auxiliary_runtime_state() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-governance-only-preserves-aux").unwrap();

        let chain = Blockchain::new();
        let genesis = chain.chain[0].clone();
        storage.append_block(&genesis).unwrap();

        let signer = SigningKey::from_bytes(&[6u8; 32]);
        let vote = finality_bft::sign_vote_v1(
            &signer,
            crate::chain_identity::chain_id(),
            1,
            0,
            0,
            &genesis.hash,
        )
        .unwrap();
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000000:0000000000",
                &serde_json::to_vec(&vote).unwrap(),
            )
            .unwrap();
        let meta = PersistedFinalityBftMetaV1 {
            finalized_height: 0,
            finalized_hash: genesis.hash.clone(),
            highest_qc_height: 0,
            highest_qc_round: 0,
            highest_qc_block_hash: genesis.hash.clone(),
        };
        storage
            .put(
                ColumnFamily::FinalityBftMeta,
                FINALITY_BFT_META_DB_KEY.as_bytes(),
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
        let qc = finality_bft::FinalityBftCertV1 {
            epoch: 1,
            height: 0,
            round: 0,
            block_hash: genesis.hash.clone(),
            voter_bitset: Vec::new(),
            sigs_b64: Vec::new(),
        };
        let qc_key = format!("qc:{:016x}:{}", 0u64, genesis.hash);
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                qc_key.as_bytes(),
                &serde_json::to_vec(&qc).unwrap(),
            )
            .unwrap();

        let object_hash = sample_hash(0xa1);
        let claim_hash = sample_hash(0xa2);
        let entry = crate::cognitive_chain::CognitiveRegistryEntryV1 {
            object_hash_hex: object_hash.clone(),
            claim_hash_hex: claim_hash.clone(),
            lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            policy_id: "default_policy".to_string(),
            anchor_height: 0,
            anchor_block_hash: genesis.hash.clone(),
            evidence_root_hex: sample_hash(0xa3),
            context_hash_hex: sample_hash(0xa4),
            model_manifest_hash_hex: sample_hash(0xa5),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 0,
        };
        storage.cognitive_registry_put_entry(&entry).unwrap();
        storage
            .cognitive_registry_put_claim_index(&claim_hash, &vec![object_hash.clone()])
            .unwrap();
        let event = CognitiveRegistryEventV1 {
            block_height: 0,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Anchor,
            object_hash_hex: object_hash.clone(),
            claim_hash_hex: claim_hash.clone(),
            old_lifecycle_state: None,
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            related_object_hash_hex: None,
            reason_code: None,
            block_hash: genesis.hash.clone(),
        };
        storage.cognitive_registry_append_event(&event).unwrap();
        storage
            .cognitive_registry_set_last_applied_height(0)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(1).unwrap();

        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_BOOTSTRAP_JSON_KEY.as_bytes(),
                &[0xff, 0xfe],
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_HEIGHT_KEY.as_bytes(),
                b"bad-height",
            )
            .unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_JSON_KEY.as_bytes(),
                b"{}",
            )
            .unwrap();

        let rep = storage.repair_db(true).unwrap();
        assert!(rep.ok, "repair should recover governance-only corruption without clobbering unrelated aux state: {:?}", rep.issues);
        assert!(storage
            .get(
                ColumnFamily::FinalityBftMeta,
                FINALITY_BFT_META_DB_KEY.as_bytes()
            )
            .unwrap()
            .is_some());
        assert!(storage
            .get(ColumnFamily::FinalityBftQcArchive, qc_key.as_bytes())
            .unwrap()
            .is_some());
        assert_eq!(
            storage
                .cognitive_registry_get_entry(&object_hash)
                .unwrap()
                .as_ref(),
            Some(&entry)
        );
        assert_eq!(
            storage
                .cognitive_registry_get_claim_index(&claim_hash)
                .unwrap(),
            vec![object_hash.clone()]
        );
        assert_eq!(
            storage.cognitive_registry_get_events_since(0, 10).unwrap(),
            vec![event]
        );
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            storage.cognitive_registry_get_last_event_seq().unwrap(),
            Some(1)
        );
        assert_eq!(storage.get_governance_bootstrap_json().unwrap(), None);
        assert_eq!(storage.get_governance_snapshot().unwrap(), None);
    }

    #[test]
    fn repair_db_false_recovers_auxiliary_corruption_beyond_quick_scan_window() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-false-full-aux-preflight").unwrap();

        for block in linear_blocks(129) {
            storage.append_block(&block).unwrap();
        }

        for idx in 0..128u64 {
            let block = storage.get_block(idx).unwrap().unwrap();
            let qc = finality_bft::FinalityBftCertV1 {
                epoch: 1,
                height: idx,
                round: 0,
                block_hash: block.hash.clone(),
                voter_bitset: Vec::new(),
                sigs_b64: Vec::new(),
            };
            let key = format!("qc:{:016x}:{}", idx, block.hash);
            storage
                .put(
                    ColumnFamily::FinalityBftQcArchive,
                    key.as_bytes(),
                    &serde_json::to_vec(&qc).unwrap(),
                )
                .unwrap();
        }
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                b"qc:0000000000000080:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                b"not-json",
            )
            .unwrap();

        let quick = storage.verify_db(false).unwrap();
        assert!(
            quick.ok,
            "quick verify should miss aux corruption beyond the scan window so repair_db(false) must perform an auxiliary full preflight; issues={:?}",
            quick.issues
        );
        assert!(
            !quick.needs_recovery,
            "quick verify unexpectedly requested recovery before the targeted full aux preflight; issues={:?}",
            quick.issues
        );

        let rep = storage.repair_db(false).unwrap();
        assert!(
            rep.ok,
            "repair_db(false) must recover rebuildable aux corruption found only by the full auxiliary preflight: {:?}",
            rep.issues
        );
        assert!(
            storage
                .iter_all_cf(ColumnFamily::FinalityBftQcArchive)
                .unwrap()
                .next()
                .is_none(),
            "repair_db(false) must clear the QC archive once full auxiliary preflight finds corruption beyond the quick scan window"
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair_db(false) must clear journal_pending after recovering from auxiliary corruption"
        );
    }

    #[test]
    fn repair_db_journal_pending_still_clears_aux_corruption_found_only_by_full_scan() {
        let _lock = test_process_lock();
        let storage = open_clean_test_dbstore("repair-journal-pending-full-aux").unwrap();

        for block in linear_blocks(129) {
            storage.append_block(&block).unwrap();
        }

        for idx in 0..128u64 {
            let block = storage.get_block(idx).unwrap().unwrap();
            let qc = finality_bft::FinalityBftCertV1 {
                epoch: 1,
                height: idx,
                round: 0,
                block_hash: block.hash.clone(),
                voter_bitset: Vec::new(),
                sigs_b64: Vec::new(),
            };
            let key = format!("qc:{:016x}:{}", idx, block.hash);
            storage
                .put(
                    ColumnFamily::FinalityBftQcArchive,
                    key.as_bytes(),
                    &serde_json::to_vec(&qc).unwrap(),
                )
                .unwrap();
        }
        storage
            .put(
                ColumnFamily::FinalityBftQcArchive,
                b"qc:0000000000000080:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                b"not-json",
            )
            .unwrap();
        storage
            .journal_begin("prune-blocks", "test-only pending marker")
            .unwrap();

        let quick = storage.verify_db(false).unwrap();
        assert!(
            quick.issues.iter().all(|issue| issue.starts_with("journal_pending:")),
            "quick verify should only see the pending journal so the repair path must rely on the full aux scan: {:?}",
            quick.issues
        );

        let rep = storage.repair_db(true).unwrap();
        assert!(
            rep.ok,
            "repair must clear rebuildable aux corruption even when a pending journal initially made the preflight look journal-only: {:?}",
            rep.issues
        );
        assert!(
            storage
                .iter_all_cf(ColumnFamily::FinalityBftQcArchive)
                .unwrap()
                .next()
                .is_none(),
            "repair must clear the QC archive once full-scan corruption is detected"
        );
        assert!(
            storage
                .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
                .unwrap()
                .is_none(),
            "repair must clear journal_pending after recovering from full-scan aux corruption"
        );
    }

    #[test]
    fn verify_db_reports_cognitive_orphan_events_and_broken_supersession_links() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let old_object = sample_hash(0x41);
        let new_object = sample_hash(0x42);
        let claim_hash = sample_hash(0x51);
        let missing_related = sample_hash(0x99);
        let anchor_block_hash = blocks[1].hash.clone();

        let old_entry = crate::cognitive_chain::CognitiveRegistryEntryV1 {
            object_hash_hex: old_object.clone(),
            claim_hash_hex: claim_hash.clone(),
            lifecycle_state: CognitiveRegistryLifecycleStateV1::Superseded,
            policy_id: "default_policy".to_string(),
            anchor_height: 1,
            anchor_block_hash: anchor_block_hash.clone(),
            evidence_root_hex: sample_hash(0x61),
            context_hash_hex: sample_hash(0x62),
            model_manifest_hash_hex: sample_hash(0x63),
            supersedes: None,
            superseded_by: Some(new_object.clone()),
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 2,
        };
        let new_entry = crate::cognitive_chain::CognitiveRegistryEntryV1 {
            object_hash_hex: new_object.clone(),
            claim_hash_hex: claim_hash.clone(),
            lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            policy_id: "default_policy".to_string(),
            anchor_height: 2,
            anchor_block_hash: blocks[2].hash.clone(),
            evidence_root_hex: sample_hash(0x64),
            context_hash_hex: sample_hash(0x65),
            model_manifest_hash_hex: sample_hash(0x66),
            supersedes: Some(sample_hash(0x88)),
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 2,
        };
        storage.cognitive_registry_put_entry(&old_entry).unwrap();
        storage.cognitive_registry_put_entry(&new_entry).unwrap();
        storage
            .cognitive_registry_put_claim_index(
                &claim_hash,
                &vec![old_object.clone(), new_object.clone()],
            )
            .unwrap();

        let orphan_event = crate::cognitive_chain::CognitiveRegistryEventV1 {
            block_height: 2,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Supersede,
            object_hash_hex: old_object.clone(),
            claim_hash_hex: claim_hash.clone(),
            old_lifecycle_state: Some(CognitiveRegistryLifecycleStateV1::Active),
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Superseded,
            related_object_hash_hex: Some(missing_related.clone()),
            reason_code: Some("superseded".to_string()),
            block_hash: blocks[2].hash.clone(),
        };
        storage
            .cognitive_registry_append_event(&orphan_event)
            .unwrap();
        storage
            .cognitive_registry_set_last_applied_height(2)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(1).unwrap();

        let report = storage.verify_db(true).unwrap();
        assert!(
            !report.ok,
            "orphan cognitive event / broken links must fail verify"
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("references missing related entry")),
            "issues={:?}",
            report.issues
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("superseded_by backlink mismatch")),
            "issues={:?}",
            report.issues
        );
    }

    #[test]
    fn repair_db_clears_cognitive_registry_when_only_orphan_events_remain() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }

        let orphan_object = sample_hash(0x71);
        let orphan_claim = sample_hash(0x72);
        let orphan_event = crate::cognitive_chain::CognitiveRegistryEventV1 {
            block_height: 2,
            event_seq: 1,
            tx_kind: CognitiveTxKindV1::Anchor,
            object_hash_hex: orphan_object,
            claim_hash_hex: orphan_claim,
            old_lifecycle_state: None,
            new_lifecycle_state: CognitiveRegistryLifecycleStateV1::Active,
            related_object_hash_hex: None,
            reason_code: None,
            block_hash: blocks[2].hash.clone(),
        };
        storage
            .cognitive_registry_append_event(&orphan_event)
            .unwrap();
        storage
            .cognitive_registry_set_last_applied_height(2)
            .unwrap();
        storage.cognitive_registry_set_last_event_seq(1).unwrap();

        let pre = storage.verify_db(true).unwrap();
        assert!(
            pre.issues
                .iter()
                .any(|i| i.contains("references missing entry")),
            "issues={:?}",
            pre.issues
        );

        let rep = storage.repair_db(true).unwrap();
        assert!(
            rep.ok,
            "repair must clear rebuildable orphan cognitive materialization: {:?}",
            rep.issues
        );
        assert!(storage
            .iter_all_cf(ColumnFamily::CognitiveRegistryEvents)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(
            storage
                .cognitive_registry_get_last_applied_height()
                .unwrap(),
            None
        );
        assert_eq!(
            storage.cognitive_registry_get_last_event_seq().unwrap(),
            None
        );
    }

    #[test]
    fn repair_db_refuses_pruned_db_with_corrupt_governance_snapshot_anchor() {
        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("repair-refuses-corrupt-pruned-governance-anchor").unwrap();
        let chain = Blockchain::new();
        let blocks = linear_blocks(3);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(2, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        storage.prune_blocks_below(1, 10).unwrap();
        storage
            .put(
                ColumnFamily::Meta,
                META_GOV_SNAPSHOT_JSON_KEY.as_bytes(),
                b"not-json",
            )
            .unwrap();

        let err = storage.repair_db(true).unwrap_err();
        match err {
            StorageError::BackendError(msg) => assert!(
                msg.contains("pruned db governance snapshot anchor"),
                "unexpected msg: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(storage.meta_get_u64_opt(META_HEIGHT_KEY).unwrap(), Some(2));
        assert_eq!(
            storage.meta_get_u64_opt(META_BASE_HEIGHT_KEY).unwrap(),
            Some(1)
        );
        assert!(storage
            .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
            .unwrap()
            .is_none());
        assert!(storage.get_block(0).unwrap().is_none());
        assert!(storage.get_block(1).unwrap().is_some());
        assert!(storage
            .get(ColumnFamily::Meta, META_GOV_SNAPSHOT_JSON_KEY.as_bytes())
            .unwrap()
            .is_some());
    }

    #[test]
    fn repair_db_refuses_pruned_db_when_truncation_would_invalidate_governance_anchor() {
        let _lock = test_process_lock();
        let storage =
            open_clean_test_dbstore("repair-refuses-pruned-governance-anchor-after-truncate")
                .unwrap();
        let chain = Blockchain::new();
        let blocks = linear_blocks(4);
        for block in &blocks {
            storage.append_block(block).unwrap();
        }
        let gov_json = serde_json::to_string(chain.governance.as_ref().unwrap()).unwrap();
        storage
            .put_governance_snapshot(3, &gov_json, false)
            .unwrap();
        put_tip_economy_snapshot_for_blocks(&storage, &blocks, 0);
        storage.prune_blocks_below(1, 10).unwrap();

        let mut corrupted = storage.get_block(3).unwrap().unwrap();
        corrupted.previous_hash = "deadbeef".to_string();
        storage
            .put(
                ColumnFamily::Blocks,
                block_key(3).as_bytes(),
                &serde_json::to_vec(&corrupted).unwrap(),
            )
            .unwrap();

        let err = storage.repair_db(true).unwrap_err();
        match err {
            StorageError::BackendError(msg) => assert!(
                msg.contains("pruned db governance snapshot anchor"),
                "unexpected msg: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(storage.meta_get_u64_opt(META_HEIGHT_KEY).unwrap(), Some(3));
        assert_eq!(
            storage.meta_get_u64_opt(META_BASE_HEIGHT_KEY).unwrap(),
            Some(1)
        );
        assert!(
            storage.get_block(3).unwrap().is_some(),
            "repair must not truncate canon when the pruned governance anchor would become invalid"
        );
        let (snap_h, snap_json) = storage.get_governance_snapshot().unwrap().unwrap();
        assert_eq!(snap_h, 3);
        assert_eq!(snap_json, gov_json);
        assert!(storage
            .get(ColumnFamily::Meta, META_JOURNAL_PENDING_KEY.as_bytes())
            .unwrap()
            .is_none());
    }

    #[test]
    fn repair_db_refuses_corrupt_finality_last_vote_store() {
        let _lock = test_process_lock();
        let storage = open_test_storage();
        for block in linear_blocks(2) {
            storage.append_block(&block).unwrap();
        }
        storage
            .put(
                ColumnFamily::FinalityBftLastVote,
                b"fv:00000000000000000003:0000000001",
                b"not-json",
            )
            .unwrap();

        let err = storage.repair_db(true).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("repair refused"));
        assert!(rendered.contains("finality last-vote store is corrupted"));
    }

    #[test]
    fn has_state_root_node_treats_empty_contract_values_as_available() {
        let dir = tempfile::tempdir().unwrap();
        let storage = DbStore::open(dir.path()).unwrap();
        assert!(storage.has_state_root_node("").unwrap());
        assert!(storage.has_state_root_node("0").unwrap());
    }

    #[test]
    fn has_state_root_node_reports_false_for_missing_nonempty_root() {
        let dir = tempfile::tempdir().unwrap();
        let storage = DbStore::open(dir.path()).unwrap();
        assert!(!storage
            .has_state_root_node("ad6befa9aabfc36a126fdb0cf950e6c59c63cac96e4b4c5c54382c77ba302c54")
            .unwrap());
    }

    #[test]
    fn atomic_write_file_best_effort_replaces_existing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.lock.info");
        fs::write(&path, br#"{"pid":1}"#).unwrap();
        atomic_write_file_best_effort(&path, br#"{"pid":2,"executable":"node"}"#);
        let bytes = fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.get("pid").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(
            value.get("executable").and_then(|v| v.as_str()),
            Some("node")
        );
    }

    #[test]
    fn storage_error_from_lock_io_includes_existing_holder_details() {
        let dir = tempfile::tempdir().unwrap();
        let lock_info_path = dir.path().join("db.lock.info");
        let holder = serde_json::json!({
            "pid": 4242u64,
            "acquired_at_unix_ms": 123456u64,
            "executable": "newgen_engine"
        });
        fs::write(&lock_info_path, serde_json::to_vec(&holder).unwrap()).unwrap();
        let err = storage_error_from_lock_io(
            dir.path(),
            &lock_info_path,
            std::io::Error::from(std::io::ErrorKind::WouldBlock),
        );
        match err {
            StorageError::InterprocessOpenConflict { message, .. } => {
                assert!(
                    message.contains("pid=4242"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("exe=newgen_engine"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("acquired_at_unix_ms=123456"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compute_order_sidecar_compaction_v207_keeps_e2_materialized_state_and_drops_history() {
        let mut store = crate::compute_contract::ComputeOrderStateStoreV1::default();
        store.complete_from_genesis = true;
        store.first_applied_height = 0;
        store.last_applied_height = 100;
        store.last_applied_hash = "hash100".to_string();
        store.required_job_kind_activation_height = 77;
        for h in 0..=100u64 {
            store.block_hash_by_height.insert(h, format!("hash{h}"));
            store.events_by_height.insert(h, Vec::new());
        }

        let compact = DbStore::compact_compute_order_state_store_for_snapshot_header_v207(
            &store, 100, "hash100",
        )
        .unwrap();

        assert_eq!(compact.first_applied_height, 0);
        assert_eq!(compact.last_applied_height, 100);
        assert_eq!(compact.last_applied_hash, "hash100");
        assert!(compact.complete_from_genesis);
        assert_eq!(compact.required_job_kind_activation_height, 77);
        assert!(compact.events_by_height.is_empty());
        assert_eq!(compact.block_hash_by_height.len(), 1);
        assert_eq!(
            compact.block_hash_by_height.get(&100).map(String::as_str),
            Some("hash100")
        );
    }
}
