use crate::block::Block;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Local;

use crate::storage::{
    mirror_blockchain_to_storage, mirror_blockchain_to_storage_with_state, ChainStorage, DbStore,
    StorageError, DB_PATH,
};
use crate::Blockchain;

/// Nome del file per export/backup JSON (opzionale).
const DATA_FILE: &str = "blockchain.json";
/// File di log operativo (best-effort).
const LOG_FILE: &str = "engine_log.txt";

#[derive(Debug)]
enum PersistCmd {
    /// Legacy append: solo blocchi.
    Append {
        expected_db_tip: u64,
        blocks: Vec<Block>,
        economy_snapshot: Option<(u64, String)>,
    },

    /// Append v2: blocchi + aggiornamenti nodi SMT/state-cache.
    AppendWithState {
        expected_db_tip: u64,
        blocks: Vec<Block>,
        state_nodes: Vec<([u8; 32], Vec<u8>)>,
        economy_snapshot: Option<(u64, String)>,
    },

    /// Full mirror: riscrive completamente blocks + tx_index e reset meta.
    FullMirror { snapshot: Blockchain },

    /// Full mirror + state: riscrive blocks + state_nodes.
    FullMirrorWithState {
        snapshot: Blockchain,
        state_nodes: Vec<([u8; 32], Vec<u8>)>,
    },

    /// Pause persistence writes (flush pending, then drop incoming writes) until Resume.
    Pause,

    /// Resume persistence writes after Pause.
    Resume,

    /// Durability barrier: flush pending + flush DB, then ack.
    Barrier { ack: mpsc::Sender<()> },

    /// Import snapshot v2 bundle from directory into DB (exclusive). Forces Pause.
    ImportSnapshotV2 {
        dir: PathBuf,
        wipe_state_nodes: bool,
        ack: mpsc::Sender<Result<(), String>>,
    },
}

static PERSIST_TX: OnceLock<Mutex<Option<mpsc::Sender<PersistCmd>>>> = OnceLock::new();
static PERSIST_STORAGE: OnceLock<DbStore> = OnceLock::new();

/// Stop immediately on failed canonical persistence instead of allowing a node
/// to participate indefinitely with an in-memory tip ahead of its durable DB.
/// The historical DB is never repaired or modified here.
fn persistence_fail_stop(context: &str, error: &dyn std::fmt::Debug) -> ! {
    ng_error!(target: "storage.persist", "event=persistence_fail_stop context={} err={:?} action=exit", context, error);
    eprintln!("FATAL persistence failure ({}): {:?}. Node stopped; recover from a verified snapshot.", context, error);
    // Unit tests must fail visibly without killing the entire Rust test harness.
    #[cfg(test)]
    panic!("persistence fail-stop in test context={}: {:?}", context, error);
    #[cfg(not(test))]
    std::process::exit(75);
}


fn persist_tx_slot() -> &'static Mutex<Option<mpsc::Sender<PersistCmd>>> {
    PERSIST_TX.get_or_init(|| Mutex::new(None))
}

fn compute_order_activation_height_for_persistence(storage: &DbStore) -> io::Result<u64> {
    match storage
        .get_compute_order_state_store_v1()
        .map_err(storage_err_to_io)?
    {
        Some(store) => Ok(store.required_job_kind_activation_height),
        None => Ok(0),
    }
}

fn prepare_storage_for_persistence(storage: &DbStore) -> Result<(), String> {
    match storage.verify_db(false) {
        Ok(rep) => {
            if !rep.ok || rep.needs_recovery {
                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                let _ = append_log(&format!(
                    "[{}] ⚠️ DB verify non-ok o recovery richiesta (ok={}, needs_recovery={}, issues={}) → repair-db",
                    ts,
                    rep.ok,
                    rep.needs_recovery,
                    rep.issues.len()
                ));
                match storage.repair_db(true) {
                    Ok(rep2) => {
                        if !rep2.ok {
                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = append_log(&format!(
                                "[{}] ❌ DB repair-db FAILED (ok=false). issues={:?}",
                                ts, rep2.issues
                            ));
                            return Err(format!("repair-db failed: {:?}", rep2.issues));
                        }
                    }
                    Err(e) => {
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!(
                            "[{}] ❌ DB repair-db error={:?} (persistence disabled)",
                            ts, e
                        ));
                        return Err(format!("repair-db error: {:?}", e));
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let _ = append_log(&format!(
                "[{}] ❌ DB verify-db error={:?} (persistence disabled)",
                ts, e
            ));
            Err(format!("verify-db error: {:?}", e))
        }
    }
}

fn spawn_persist_worker(storage: DbStore) -> Result<mpsc::Sender<PersistCmd>, String> {
    let (tx, rx) = mpsc::channel::<PersistCmd>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();

    thread::Builder::new()
        .name("newgen-persist-worker".to_string())
        .spawn(move || {
            let prep = prepare_storage_for_persistence(&storage);
            let _ = ready_tx.send(prep.clone());
            if prep.is_err() {
                return;
            }
            persist_worker(rx, storage);
        })
        .map_err(|e| format!("persist worker spawn failed: {e}"))?;

    match ready_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => Ok(tx),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(format!("persist worker startup ack failed: {e}")),
    }
}

pub fn persist_init(storage: DbStore) -> Result<(), String> {
    let _ = PERSIST_STORAGE.set(storage.clone());

    {
        let guard = persist_tx_slot()
            .lock()
            .map_err(|_| "persist worker slot poisoned".to_string())?;
        if guard.is_some() {
            return Ok(());
        }
    }

    let tx = spawn_persist_worker(storage)?;
    let mut guard = persist_tx_slot()
        .lock()
        .map_err(|_| "persist worker slot poisoned".to_string())?;
    *guard = Some(tx);
    Ok(())
}

fn persist_tx() -> Option<mpsc::Sender<PersistCmd>> {
    {
        let guard = persist_tx_slot().lock().ok()?;
        if let Some(tx) = guard.as_ref() {
            return Some(tx.clone());
        }
    }

    let storage = if let Some(storage) = PERSIST_STORAGE.get() {
        storage.clone()
    } else {
        match DbStore::open(DB_PATH) {
            Ok(s) => s,
            Err(e) => {
                ng_warn!(target: "storage.persist", "persist worker DB open failed; persistence disabled err={:?}", e);
                return None;
            }
        }
    };

    match spawn_persist_worker(storage) {
        Ok(tx) => {
            if let Ok(mut guard) = persist_tx_slot().lock() {
                *guard = Some(tx.clone());
            }
            Some(tx)
        }
        Err(e) => {
            ng_warn!(target: "storage.persist", "persist worker init failed; persistence disabled err={}", e);
            None
        }
    }
}

fn persist_try_send(cmd: PersistCmd) -> bool {
    let Some(tx) = persist_tx() else {
        return false;
    };

    match tx.send(cmd) {
        Ok(()) => true,
        Err(_) => {
            if let Ok(mut guard) = persist_tx_slot().lock() {
                *guard = None;
            }
            ng_warn!(target: "storage.persist", "persist worker unavailable (channel closed)");
            false
        }
    }
}

/// Enqueue di 1 blocco (append delta). Non fa I/O.
pub fn persist_enqueue_block(expected_db_tip: u64, block: Block) {
    if !persist_try_send(PersistCmd::Append {
        expected_db_tip,
        blocks: vec![block],
        economy_snapshot: None,
    }) {
        persistence_fail_stop("enqueue_block", &"worker unavailable");
    }
}

/// Enqueue di 1 blocco con economy sidecar tip-bound, scritto atomicamente
/// insieme al blocco dal persistence worker.
pub fn persist_enqueue_block_with_economy_snapshot(
    expected_db_tip: u64,
    block: Block,
    economy_snapshot: Option<(u64, String)>,
) {
    if !persist_try_send(PersistCmd::Append {
        expected_db_tip,
        blocks: vec![block],
        economy_snapshot,
    }) {
        persistence_fail_stop("enqueue_block_with_economy", &"worker unavailable");
    }
}

/// Enqueue di un batch di blocchi (append delta). Non fa I/O.
pub fn persist_enqueue_blocks(expected_db_tip: u64, blocks: Vec<Block>) {
    if blocks.is_empty() {
        return;
    }
    if !persist_try_send(PersistCmd::Append {
        expected_db_tip,
        blocks,
        economy_snapshot: None,
    }) {
        persistence_fail_stop("enqueue_blocks", &"worker unavailable");
    }
}

/// Enqueue di un batch di blocchi + state nodes updates (Append v2). Non fa I/O.
pub fn persist_enqueue_blocks_with_state(
    expected_db_tip: u64,
    blocks: Vec<Block>,
    state_nodes: Vec<([u8; 32], Vec<u8>)>,
) {
    if blocks.is_empty() {
        return;
    }
    if !persist_try_send(PersistCmd::AppendWithState {
        expected_db_tip,
        blocks,
        state_nodes,
        economy_snapshot: None,
    }) {
        persistence_fail_stop("enqueue_blocks_with_state", &"worker unavailable");
    }
}

/// Enqueue di un full mirror (per reorg/repair). Non fa I/O nel chiamante.
pub fn persist_enqueue_full(snapshot: Blockchain) {
    if !persist_try_send(PersistCmd::FullMirror { snapshot }) {
        persistence_fail_stop("enqueue_full_mirror", &"worker unavailable");
    }
}

/// Enqueue di un full mirror + state (per repair/reorg). Non fa I/O nel chiamante.
pub fn persist_enqueue_full_with_state(
    snapshot: Blockchain,
    state_nodes: Vec<([u8; 32], Vec<u8>)>,
) {
    if !persist_try_send(PersistCmd::FullMirrorWithState {
        snapshot,
        state_nodes,
    }) {
        persistence_fail_stop("enqueue_full_mirror_with_state", &"worker unavailable");
    }
}

/// Pause the persistence worker (flush pending, then drop incoming writes) until resumed.
/// Useful to perform exclusive operations (e.g. snapshot import) without DB corruption.
pub fn persist_pause() {
    if !persist_try_send(PersistCmd::Pause) {
        persistence_fail_stop("enqueue_pause", &"worker unavailable");
    }
}

/// Resume the persistence worker after `persist_pause()`.
pub fn persist_resume() {
    if !persist_try_send(PersistCmd::Resume) {
        persistence_fail_stop("enqueue_resume", &"worker unavailable");
    }
}

/// Durability barrier: flush pending writes and flush the DB, then acknowledge.
/// Returns `true` if the barrier completed within `timeout`.
pub fn persist_barrier(timeout: Duration) -> bool {
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    if !persist_try_send(PersistCmd::Barrier { ack: ack_tx }) {
        return false;
    }
    ack_rx.recv_timeout(timeout).is_ok()
}

/// Import a snapshot-v2 bundle directory (expects `meta.json` + `chunks/`).
/// The import is executed *inside* the persistence worker using the already-open DB handle.
pub fn persist_import_snapshot_v2_bundle<P: AsRef<Path>>(
    bundle_dir: P,
    wipe_state_nodes: bool,
    timeout: Duration,
) -> Result<(), String> {
    let (ack_tx, ack_rx) = mpsc::channel::<Result<(), String>>();
    let cmd = PersistCmd::ImportSnapshotV2 {
        dir: bundle_dir.as_ref().to_path_buf(),
        wipe_state_nodes,
        ack: ack_tx,
    };
    if !persist_try_send(cmd) {
        return Err("persist worker unavailable".to_string());
    }

    match ack_rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(e) => Err(format!("persist import timeout/failed to ack: {}", e)),
    }
}

fn persist_worker(rx: mpsc::Receiver<PersistCmd>, storage: DbStore) {
    // rate limit per full mirror (evita loop di mirror in caso di errore ripetuto)
    let mut last_full_mirror = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now);

    // throttle log (evita spam su disco)
    let mut last_ok_log = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now);

    // -----------------------------
    // Smart Flush / Micro-batching
    // -----------------------------
    //
    // Il problema (Windows + multi-processo): flush/fsync per blocco = collo di bottiglia.
    //
    // Policy:
    // - Append (scrittura) può essere batchata.
    // - Flush (durability barrier) viene fatto periodicamente.
    //
    // Env vars:
    // - NEWGEN_DB_FLUSH_EVERY_N_BLOCKS (default 10)
    // - NEWGEN_DB_FLUSH_EVERY_MS       (default 2000)
    // - NEWGEN_DB_PERSIST_BATCH_MAX_BLOCKS (default 25)
    // - NEWGEN_DB_PERSIST_BATCH_MAX_MS     (default 25)
    let flush_every_n_blocks = env_u64("NEWGEN_DB_FLUSH_EVERY_N_BLOCKS", 10).max(1);
    let flush_every_ms = env_u64("NEWGEN_DB_FLUSH_EVERY_MS", 2000).clamp(50, 60_000);

    let batch_max_blocks = env_usize("NEWGEN_DB_PERSIST_BATCH_MAX_BLOCKS", 25).clamp(1, 10_000);
    let batch_max_ms = env_u64("NEWGEN_DB_PERSIST_BATCH_MAX_MS", 25).clamp(5, 10_000);

    // tick granularity: guida sia il batching che il flush-time
    let tick_ms = batch_max_ms.min(flush_every_ms).max(5);

    let mut pending_expected_tip: Option<u64> = None;
    let mut pending_blocks: Vec<Block> = Vec::new();
    let mut pending_last_rx = Instant::now();

    // contatori flush durability
    let mut dirty_blocks: u64 = 0;
    let mut last_disk_flush = Instant::now();

    // StateSync / exclusive operations: pause flag to avoid concurrent writes during imports.
    let mut paused: bool = false;
    let mut dropped_while_paused: u64 = 0;
    let mut last_paused_log = Instant::now();

    let flush_pending = |storage: &DbStore,
                         expected_tip: &mut Option<u64>,
                         blocks: &mut Vec<Block>,
                         dirty_blocks: &mut u64|
     -> io::Result<()> {
        if blocks.is_empty() {
            *expected_tip = None;
            return Ok(());
        }

        let exp = (*expected_tip).unwrap_or_else(|| {
            blocks
                .first()
                .map(|b| b.index.saturating_sub(1))
                .unwrap_or(0)
        });
        // Append batch senza flush: la durability è gestita più sotto.
        storage
            .append_blocks_delta_checked_with_flush(exp, blocks.as_slice(), false)
            .map_err(storage_err_to_io)?;
        storage
            .advance_compute_order_state_store_with_blocks_v1(
                blocks.as_slice(),
                compute_order_activation_height_for_persistence(storage)?,
                false,
            )
            .map_err(storage_err_to_io)?;

        *dirty_blocks = dirty_blocks.saturating_add(blocks.len() as u64);

        blocks.clear();
        *expected_tip = None;
        Ok(())
    };

    let maybe_flush_disk = |storage: &DbStore,
                            dirty_blocks: &mut u64,
                            last_disk_flush: &mut Instant|
     -> io::Result<()> {
        if *dirty_blocks == 0 {
            // niente da flushare
            return Ok(());
        }

        let need_blocks = *dirty_blocks >= flush_every_n_blocks;
        let need_time = last_disk_flush.elapsed() >= Duration::from_millis(flush_every_ms);

        if need_blocks || need_time {
            storage.flush_db().map_err(storage_err_to_io)?;
            *dirty_blocks = 0;
            *last_disk_flush = Instant::now();
        }
        Ok(())
    };

    loop {
        match rx.recv_timeout(Duration::from_millis(tick_ms)) {
            Ok(cmd) => {
                pending_last_rx = Instant::now();

                match cmd {
                    PersistCmd::Pause => {
                        // Flush any pending batched appends before entering paused mode.
                        match flush_pending(
                            &storage,
                            &mut pending_expected_tip,
                            &mut pending_blocks,
                            &mut dirty_blocks,
                        ) {
                            Ok(()) => {}
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⚠️ persist_pause: flush_pending FAILED: {}",
                                    ts, e
                                ));
                                persistence_fail_stop("worker_1_persist_pause_flush_pending_failed", &e);
                            }
                        };

                        if let Err(e) = storage.flush_db() {
                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = append_log(&format!(
                                "[{}] ⚠️ persist_pause: flush_db FAILED: {:?}",
                                ts, e
                            ));
                            persistence_fail_stop("worker_2_persist_pause_flush_db_failed", &e);
                        }

                        paused = true;
                        dropped_while_paused = 0;
                        last_paused_log = Instant::now();

                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!("[{}] ⏸️ persistence PAUSED", ts));
                    }

                    PersistCmd::Resume => {
                        paused = false;
                        let dropped = dropped_while_paused;
                        dropped_while_paused = 0;
                        last_paused_log = Instant::now();

                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!(
                            "[{}] ▶️ persistence RESUMED (dropped_while_paused={})",
                            ts, dropped
                        ));
                    }

                    PersistCmd::Barrier { ack } => {
                        // Durability barrier: flush pending and flush DB.
                        match flush_pending(
                            &storage,
                            &mut pending_expected_tip,
                            &mut pending_blocks,
                            &mut dirty_blocks,
                        ) {
                            Ok(()) => {}
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⚠️ persist_barrier: flush_pending FAILED: {}",
                                    ts, e
                                ));
                                persistence_fail_stop("worker_3_persist_barrier_flush_pending_failed", &e);
                            }
                        };

                        if let Err(e) = storage.flush_db() {
                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = append_log(&format!(
                                "[{}] ⚠️ persist_barrier: flush_db FAILED: {:?}",
                                ts, e
                            ));
                            persistence_fail_stop("worker_4_persist_barrier_flush_db_failed", &e);
                        }

                        let _ = ack.send(());
                    }

                    PersistCmd::ImportSnapshotV2 {
                        dir,
                        wipe_state_nodes,
                        ack,
                    } => {
                        // Force exclusive mode.
                        paused = true;

                        // Flush pending before import.
                        match flush_pending(
                            &storage,
                            &mut pending_expected_tip,
                            &mut pending_blocks,
                            &mut dirty_blocks,
                        ) {
                            Ok(()) => {}
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⚠️ import-snapshot-v2: flush_pending FAILED: {}",
                                    ts, e
                                ));
                                persistence_fail_stop("worker_5_import_snapshot_v2_flush_pending_failed", &e);
                            }
                        };

                        if let Err(e) = storage.flush_db() {
                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = append_log(&format!(
                                "[{}] ⚠️ import-snapshot-v2: pre-flush_db FAILED: {:?}",
                                ts, e
                            ));
                            persistence_fail_stop("worker_6_import_snapshot_v2_pre_flush_db_failed", &e);
                        }

                        // Reset internal batching state.
                        pending_blocks.clear();
                        pending_expected_tip = None;
                        dirty_blocks = 0;

                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!(
                            "[{}] 📥 Import snapshot-v2 requested (dir={}, wipe_state_nodes={})",
                            ts,
                            dir.display(),
                            wipe_state_nodes
                        ));

                        let r: Result<(), String> = storage
                            .import_snapshot_v2_bundle(&dir, wipe_state_nodes)
                            .map_err(|e| format!("{:?}", e))
                            .and_then(|_| storage.flush_db().map_err(|e| format!("{:?}", e)));

                        match &r {
                            Ok(()) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ✅ import-snapshot-v2 OK (dir={})",
                                    ts,
                                    dir.display()
                                ));
                            }
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ❌ import-snapshot-v2 FAILED (dir={} err={})",
                                    ts,
                                    dir.display(),
                                    e
                                ));
                            }
                        }

                        let _ = ack.send(r);
                    }

                    PersistCmd::Append {
                        expected_db_tip,
                        mut blocks,
                        economy_snapshot,
                    } => {
                        if paused {
                            dropped_while_paused =
                                dropped_while_paused.saturating_add(blocks.len() as u64);
                            if last_paused_log.elapsed() >= Duration::from_secs(5) {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⏸️ persist paused: dropping writes (dropped_total={})",
                                    ts, dropped_while_paused
                                ));
                                last_paused_log = Instant::now();
                            }
                            continue;
                        }

                        if blocks.is_empty() {
                            // tick continuo: gestisce flush time-based anche senza eventi
                            match maybe_flush_disk(
                                &storage,
                                &mut dirty_blocks,
                                &mut last_disk_flush,
                            ) {
                                Ok(()) => {}
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ =
                                        append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                                    persistence_fail_stop("worker_7_flush_db_failed", &e);
                                }
                            };
                            continue;
                        }

                        // Economy sidecar must commit in the same DB batch as its tip block.
                        // Do not merge this command into pending block-only batches, otherwise
                        // the sidecar would either be dropped or committed separately.
                        if economy_snapshot.is_some() {
                            match flush_pending(
                                &storage,
                                &mut pending_expected_tip,
                                &mut pending_blocks,
                                &mut dirty_blocks,
                            ) {
                                Ok(()) => {}
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ = append_log(&format!(
                                        "[{}] ⚠️ flush_pending before economy append FAILED: {}",
                                        ts, e
                                    ));
                                    persistence_fail_stop("worker_8_flush_pending_before_economy_append_failed", &e);
                                }
                            };
                            let economy_snapshot_ref = economy_snapshot
                                .as_ref()
                                .map(|(height, json)| (*height, json.as_str()));
                            let r = storage
                                .append_blocks_delta_checked_with_state_nodes_and_economy_snapshot_atomic(
                                    expected_db_tip,
                                    blocks.as_slice(),
                                    &[],
                                    economy_snapshot_ref,
                                    false,
                                );
                            match r.map_err(storage_err_to_io).and_then(|_| {
                                storage
                                    .advance_compute_order_state_store_with_blocks_v1(
                                        blocks.as_slice(),
                                        compute_order_activation_height_for_persistence(&storage)?,
                                        false,
                                    )
                                    .map_err(storage_err_to_io)
                            }) {
                                Ok(()) => {
                                    dirty_blocks = dirty_blocks.saturating_add(blocks.len() as u64);
                                }
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let first = blocks.first().map(|b| b.index).unwrap_or(0);
                                    let last = blocks.last().map(|b| b.index).unwrap_or(0);
                                    let _ = append_log(&format!(
                                        "[{}] ❌ append+economy FAILED expected_db_tip={} range=[{}..{}] err={}",
                                        ts, expected_db_tip, first, last, e
                                    ));
                                    persistence_fail_stop("worker_9_append_economy_failed_expected_db_tip_range_err", &e);
                                }
                            }
                            match maybe_flush_disk(
                                &storage,
                                &mut dirty_blocks,
                                &mut last_disk_flush,
                            ) {
                                Ok(()) => {}
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ =
                                        append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                                    persistence_fail_stop("worker_10_flush_db_failed", &e);
                                }
                            };
                            continue;
                        }

                        // (1) Se abbiamo pending e l'expected tip non combacia, flush pending prima.
                        if let (Some(exp0), Some(last)) =
                            (pending_expected_tip, pending_blocks.last())
                        {
                            // expected tip della nuova chunk deve essere l'ultimo index pending
                            let expected_next = last.index;
                            if expected_db_tip != expected_next || exp0 > expected_db_tip {
                                // discontinuità o incoerenza: chiudiamo batch corrente
                                match flush_pending(
                                    &storage,
                                    &mut pending_expected_tip,
                                    &mut pending_blocks,
                                    &mut dirty_blocks,
                                ) {
                                    Ok(()) => {}
                                    Err(e) => {
                                        let ts =
                                            Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                        let _ = append_log(&format!(
                                            "[{}] ⚠️ flush_pending FAILED: {}",
                                            ts, e
                                        ));
                                        persistence_fail_stop("worker_11_flush_pending_failed", &e);
                                    }
                                };
                            }
                        }

                        // (2) Se non abbiamo pending, inizializza expected tip
                        if pending_blocks.is_empty() {
                            pending_expected_tip = Some(expected_db_tip);
                        }

                        // (3) Accoda blocchi
                        pending_blocks.append(&mut blocks);

                        // (4) Flush pending su soglie
                        let need_batch = pending_blocks.len() >= batch_max_blocks;
                        if need_batch {
                            match flush_pending(
                                &storage,
                                &mut pending_expected_tip,
                                &mut pending_blocks,
                                &mut dirty_blocks,
                            ) {
                                Ok(()) => {}
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ = append_log(&format!(
                                        "[{}] ⚠️ flush_pending FAILED: {}",
                                        ts, e
                                    ));
                                    persistence_fail_stop("worker_12_flush_pending_failed", &e);
                                }
                            };
                        }

                        // (5) Flush durability se necessario
                        match maybe_flush_disk(&storage, &mut dirty_blocks, &mut last_disk_flush) {
                            Ok(()) => {}
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                                persistence_fail_stop("worker_13_flush_db_failed", &e);
                            }
                        };

                        // log ok throttle: non logghiamo ogni blocco
                        if last_ok_log.elapsed() >= Duration::from_secs(10) {
                            if let Some(last) = pending_blocks.last() {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] 🧱 persist pending len={} last_h={} dirty_blocks={} (flush_n={} flush_ms={})",
                                    ts,
                                    pending_blocks.len(),
                                    last.index,
                                    dirty_blocks,
                                    flush_every_n_blocks,
                                    flush_every_ms
                                ));
                            }
                            last_ok_log = Instant::now();
                        }
                    }

                    PersistCmd::AppendWithState {
                        expected_db_tip,
                        blocks,
                        state_nodes,
                        economy_snapshot,
                    } => {
                        if paused {
                            dropped_while_paused = dropped_while_paused
                                .saturating_add(blocks.len() as u64)
                                .saturating_add(state_nodes.len() as u64);
                            if last_paused_log.elapsed() >= Duration::from_secs(5) {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⏸️ persist paused: dropping writes (dropped_total={}, blocks={}, state_nodes={})",
                                    ts, dropped_while_paused, blocks.len(), state_nodes.len()
                                ));
                                last_paused_log = Instant::now();
                            }
                            continue;
                        }

                        // Prima chiudiamo eventuali pending Append.
                        match flush_pending(
                            &storage,
                            &mut pending_expected_tip,
                            &mut pending_blocks,
                            &mut dirty_blocks,
                        ) {
                            Ok(()) => {}
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ =
                                    append_log(&format!("[{}] ⚠️ flush_pending FAILED: {}", ts, e));
                                persistence_fail_stop("worker_14_flush_pending_failed", &e);
                            }
                        };

                        if blocks.is_empty() {
                            match maybe_flush_disk(
                                &storage,
                                &mut dirty_blocks,
                                &mut last_disk_flush,
                            ) {
                                Ok(()) => {}
                                Err(e) => {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ =
                                        append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                                    persistence_fail_stop("worker_15_flush_db_failed", &e);
                                }
                            };
                            continue;
                        }

                        let first = blocks.first().map(|b| b.index).unwrap_or(0);
                        let last = blocks.last().map(|b| b.index).unwrap_or(0);

                        // Commit atomico (write_batch): state_nodes + blocks + tx_index
                        // -> elimina sia "orphan nodes" sia "missing node at depth 0".
                        let economy_snapshot_ref = economy_snapshot
                            .as_ref()
                            .map(|(height, json)| (*height, json.as_str()));
                        let r = storage
                            .append_blocks_delta_checked_with_state_nodes_and_economy_snapshot_atomic(
                                expected_db_tip,
                                &blocks,
                                &state_nodes,
                                economy_snapshot_ref,
                                false,
                            );

                        match r.map_err(storage_err_to_io).and_then(|_| {
                            storage
                                .advance_compute_order_state_store_with_blocks_v1(
                                    blocks.as_slice(),
                                    compute_order_activation_height_for_persistence(&storage)?,
                                    false,
                                )
                                .map_err(storage_err_to_io)
                        }) {
                            Ok(()) => {
                                dirty_blocks = dirty_blocks.saturating_add(blocks.len() as u64);
                                match maybe_flush_disk(
                                    &storage,
                                    &mut dirty_blocks,
                                    &mut last_disk_flush,
                                ) {
                                    Ok(()) => {}
                                    Err(e) => {
                                        let ts =
                                            Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                        let _ = append_log(&format!(
                                            "[{}] ⚠️ flush_db FAILED: {}",
                                            ts, e
                                        ));
                                        persistence_fail_stop("worker_16_flush_db_failed", &e);
                                    }
                                };

                                if last_ok_log.elapsed() >= Duration::from_secs(10) {
                                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    let _ = append_log(&format!(
                                        "[{}] ✅ DB append+state ok: {}..{} (expected_db_tip={}, state_nodes={})",
                                        ts, first, last, expected_db_tip, state_nodes.len()
                                    ));
                                    last_ok_log = Instant::now();
                                }
                            }
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⚠️ DB append+state FAILED: {}..{} (expected_db_tip={}, state_nodes={}) err={}",
                                    ts, first, last, expected_db_tip, state_nodes.len(), e
                                ));
                                persistence_fail_stop("worker_17_db_append_state_failed_expected_db_tip_state_nodes_e", &e);
                            }
                        }
                    }

                    PersistCmd::FullMirror { snapshot } => {
                        if paused {
                            dropped_while_paused =
                                dropped_while_paused.saturating_add(snapshot.chain.len() as u64);
                            if last_paused_log.elapsed() >= Duration::from_secs(5) {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⏸️ persist paused: dropping full-mirror (dropped_total={})",
                                    ts, dropped_while_paused
                                ));
                                last_paused_log = Instant::now();
                            }
                            continue;
                        }

                        // Chiudiamo eventuali pending
                        pending_blocks.clear();
                        pending_expected_tip = None;
                        dirty_blocks = 0;

                        // rate limit full mirror
                        // Serialize consecutive reorg mirrors. The previous rate limiter
                        // discarded the newer canonical snapshot silently.
                        if let Some(delay) = Duration::from_secs(2).checked_sub(last_full_mirror.elapsed()) {
                            thread::sleep(delay);
                        }
                        last_full_mirror = Instant::now();

                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!(
                            "[{}] 🔁 Full mirror requested (height={})",
                            ts,
                            snapshot.chain.len().saturating_sub(1)
                        ));

                        match mirror_blockchain_to_storage(&storage, &snapshot)
                            .map_err(storage_err_to_io)
                        {
                            Ok(()) => {
                                last_disk_flush = Instant::now();
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!("[{}] ✅ Full mirror ok", ts));
                            }
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ =
                                    append_log(&format!("[{}] ❌ Full mirror FAILED: {}", ts, e));
                                persistence_fail_stop("worker_18_full_mirror_failed", &e);
                            }
                        }
                    }

                    PersistCmd::FullMirrorWithState {
                        snapshot,
                        state_nodes,
                    } => {
                        if paused {
                            dropped_while_paused = dropped_while_paused
                                .saturating_add(snapshot.chain.len() as u64)
                                .saturating_add(state_nodes.len() as u64);
                            if last_paused_log.elapsed() >= Duration::from_secs(5) {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ⏸️ persist paused: dropping full-mirror (dropped_total={}, blocks={}, state_nodes={})",
                                    ts, dropped_while_paused, snapshot.chain.len(), state_nodes.len()
                                ));
                                last_paused_log = Instant::now();
                            }
                            continue;
                        }

                        // Chiudiamo eventuali pending
                        pending_blocks.clear();
                        pending_expected_tip = None;
                        dirty_blocks = 0;

                        // Serialize consecutive reorg mirrors. The previous rate limiter
                        // discarded the newer canonical snapshot silently.
                        if let Some(delay) = Duration::from_secs(2).checked_sub(last_full_mirror.elapsed()) {
                            thread::sleep(delay);
                        }
                        last_full_mirror = Instant::now();

                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!(
                            "[{}] 🔁 Full mirror+state requested (height={}, state_nodes={})",
                            ts,
                            snapshot.chain.len().saturating_sub(1),
                            state_nodes.len()
                        ));

                        match mirror_blockchain_to_storage_with_state(
                            &storage,
                            &snapshot,
                            &state_nodes,
                        )
                        .map_err(storage_err_to_io)
                        {
                            Ok(()) => {
                                last_disk_flush = Instant::now();
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!("[{}] ✅ Full mirror+state ok", ts));
                            }
                            Err(e) => {
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let _ = append_log(&format!(
                                    "[{}] ❌ Full mirror+state FAILED: {}",
                                    ts, e
                                ));
                                persistence_fail_stop("worker_19_full_mirror_state_failed", &e);
                            }
                        }
                    }
                }
            }

            Err(mpsc::RecvTimeoutError::Timeout) => {
                // tick: flush pending se inattivo abbastanza
                if !pending_blocks.is_empty()
                    && pending_last_rx.elapsed() >= Duration::from_millis(batch_max_ms)
                {
                    match flush_pending(
                        &storage,
                        &mut pending_expected_tip,
                        &mut pending_blocks,
                        &mut dirty_blocks,
                    ) {
                        Ok(()) => {}
                        Err(e) => {
                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = append_log(&format!("[{}] ⚠️ flush_pending FAILED: {}", ts, e));
                            persistence_fail_stop("worker_20_flush_pending_failed", &e);
                        }
                    };
                }
                match maybe_flush_disk(&storage, &mut dirty_blocks, &mut last_disk_flush) {
                    Ok(()) => {}
                    Err(e) => {
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                        persistence_fail_stop("worker_21_flush_db_failed", &e);
                    }
                };
            }

            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // best effort: persist finale
                match flush_pending(
                    &storage,
                    &mut pending_expected_tip,
                    &mut pending_blocks,
                    &mut dirty_blocks,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!("[{}] ⚠️ flush_pending FAILED: {}", ts, e));
                        persistence_fail_stop("worker_22_flush_pending_failed", &e);
                    }
                };
                match maybe_flush_disk(&storage, &mut dirty_blocks, &mut last_disk_flush) {
                    Ok(()) => {}
                    Err(e) => {
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let _ = append_log(&format!("[{}] ⚠️ flush_db FAILED: {}", ts, e));
                        persistence_fail_stop("worker_23_flush_db_failed", &e);
                    }
                };
                break;
            }
        }
    }
}

/// Ritorna il path assoluto (solo per diagnostica a video)
fn full_path(filename: &str) -> String {
    match std::env::current_dir() {
        Ok(p) => p.join(filename).to_string_lossy().to_string(),
        Err(_) => filename.to_string(),
    }
}

fn storage_err_to_io(e: StorageError) -> io::Error {
    match e {
        StorageError::BackendError(msg) => io::Error::other(msg),
        StorageError::InterprocessOpenConflict { path, message } => io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("runtime db dir locked {}: {}", path, message),
        ),
        StorageError::BlockNotFound(h) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DB corrotto: blocco mancante a height={}", h),
        ),
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Ok(v) => v.trim().parse::<u64>().ok().unwrap_or(default),
        Err(_) => default,
    }
}
fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(v) => v.trim().parse::<usize>().ok().unwrap_or(default),
        Err(_) => default,
    }
}

/// Appende una riga al file di log (con rotazione automatica)
fn append_log(entry: &str) -> Result<(), io::Error> {
    const MAX_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

    if let Ok(meta) = fs::metadata(LOG_FILE) {
        if meta.len() > MAX_SIZE {
            let _ = fs::rename(LOG_FILE, "engine_log.txt.1"); // best-effort
        }
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)?;
    f.write_all(entry.as_bytes())
}

fn is_chain_plausible(chain: &Blockchain) -> bool {
    if chain.chain.is_empty() {
        return false;
    }
    if chain.chain[0].index != 0 {
        return false;
    }
    true
}

fn apply_policy_override_if_present(chain: &mut Blockchain) {
    match crate::blockchain::load_economy_policy_from_disk("config/economy_policy.json") {
        Ok(Some(file)) => {
            chain
                .apply_policy_file_overrides(&file)
                .expect("economy policy admission must succeed after validated disk load");
            ng_info!(target: "economy.boot", "Economy policy refreshed from JSON after disk load");
        }
        Ok(None) => {}
        Err(e) => panic!(
            "economy policy admission failed during persistence refresh (fail-closed): {}",
            e
        ),
    }
}

/// Ricostruisce lo stato di governance rigiocando tutte le governance_txs
fn recompute_governance_from_chain(chain: &mut Blockchain, chain_repaired: bool) {
    // IMPORTANT (mainnet-grade):
    // Non ricostruire la governance usando come "bootstrap" lo stato attuale (post-update),
    // altrimenti dopo un cambio validator_set (es. timelock) il nodo finisce per trattare
    // il set più recente come se fosse quello di genesi (invalidando retroattivamente i blocchi storici).
    //
    // V319: on pruned warm boot without chain repair, prefer a validated persisted
    // governance/finality reconciliation instead of using the heavier after-chain-replace
    // rebuild path. If any guard fails, Blockchain falls back to the previous full rebuild.
    chain.reconcile_governance_after_chain_integrity_check_v319(chain_repaired);
}

/// Export JSON abilitato SOLO se `NEWGEN_EXPORT_JSON=1|true|yes|on`
fn export_json_enabled() -> bool {
    match env::var("NEWGEN_EXPORT_JSON") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

/// Import JSON abilitato SOLO se `NEWGEN_IMPORT_JSON=1|true|yes|on`
/// (serve per migrare vecchie chain; non è il boot normale).
fn import_json_enabled() -> bool {
    let enabled = match env::var("NEWGEN_IMPORT_JSON") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    };
    if enabled && crate::runtime_mode::public_mode_enabled() {
        ng_error!(
            target: "storage.boot",
            "event=legacy_json_import_rejected public_mode=true env=NEWGEN_IMPORT_JSON action=ignore"
        );
        false
    } else {
        enabled
    }
}

// --- EXPORT JSON (opzionale) ---

pub fn export_blockchain_json(blockchain: &Blockchain) -> Result<(), io::Error> {
    export_blockchain_json_to(blockchain, DATA_FILE)
}

pub fn export_blockchain_json_to<P: AsRef<Path>>(
    blockchain: &Blockchain,
    path: P,
) -> Result<(), io::Error> {
    let path = path.as_ref();
    let tmp = path.with_extension("tmp");

    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)?;

    let mut bw = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut bw, blockchain)
        .map_err(|e| io::Error::other(e.to_string()))?;
    bw.flush()?;

    // backup best-effort
    if path.exists() {
        let bak = path.with_extension("bak");
        let _ = fs::copy(path, bak);
    }

    crate::utils::atomic_replace_file_v1(&tmp, path)?;
    Ok(())
}

pub fn append_blocks_delta(expected_db_tip: u64, blocks: &[Block]) -> Result<(), io::Error> {
    if blocks.is_empty() {
        return Ok(());
    }

    let storage =
        DbStore::open(DB_PATH).map_err(|e| io::Error::other(format!("DbStore::open: {e:?}")))?;

    storage
        .append_blocks_delta_checked(expected_db_tip, blocks)
        .map_err(storage_err_to_io)?;
    storage
        .advance_compute_order_state_store_with_blocks_v1(
            blocks,
            compute_order_activation_height_for_persistence(&storage)?,
            true,
        )
        .map_err(storage_err_to_io)?;

    Ok(())
}

// --- SAVE (DB canonico + JSON opzionale) ---

pub fn save_blockchain_with_storage(
    storage: &DbStore,
    blockchain: &Blockchain,
) -> Result<(), io::Error> {
    // DB inizializzato? (esiste il blocco al tip dichiarato dal meta)
    // In modalità pruned, il blocco 0 può non esistere: usare il tip come sentinel.
    let db_tip = storage.get_height().map_err(storage_err_to_io)?;
    let db_has_tip = storage
        .get_block(db_tip)
        .map_err(storage_err_to_io)?
        .is_some();

    if !db_has_tip {
        // DB vuoto: mirror completo sullo stesso handle runtime.
        mirror_blockchain_to_storage(storage, blockchain).map_err(storage_err_to_io)?;
    } else {
        let mem_len = blockchain.chain.len();
        if mem_len == 0 {
            return Ok(());
        }

        // Verifica compatibilità tip DB
        let db_tip_block = storage
            .get_block(db_tip)
            .map_err(storage_err_to_io)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DB tip block missing"))?;

        let mem_tip_at_db_opt = blockchain.block_at_height(db_tip);

        // Se la memchain è più corta del DB (tipicamente dopo rewind/fork-choice),
        // riallineiamo il DB alla memchain (rollback consentito perché DB è mirror).
        match mem_tip_at_db_opt {
            None => {
                mirror_blockchain_to_storage(storage, blockchain).map_err(storage_err_to_io)?;
            }
            Some(mem_tip_at_db) => {
                if mem_tip_at_db.hash != db_tip_block.hash {
                    // Mismatch: risincronizza DB alla memchain sullo stesso handle aperto.
                    mirror_blockchain_to_storage(storage, blockchain).map_err(storage_err_to_io)?;
                } else {
                    // Delta append (DB tip == mem tip). Keep legacy synchronous save aligned
                    // with the main persistence worker contract: if we advance the DB tip, the
                    // tip-bound economy sidecar must advance in the same storage batch. Without
                    // this, repair/manual save paths can leave a full DB whose blocks are at H
                    // while META_ECONOMY_SNAPSHOT_* is still H-1, causing strict snapshot export
                    // or public boot to fail later.
                    let start_height = db_tip.saturating_add(1);
                    let start = start_height.saturating_sub(blockchain.base_height) as usize;
                    if mem_len > start {
                        let delta = &blockchain.chain[start..];
                        let economy_snapshot = delta.last().and_then(|tip| {
                            blockchain.tip_economy_snapshot_for_persistence_v1(tip)
                        });
                        let economy_snapshot_ref = economy_snapshot
                            .as_ref()
                            .map(|(height, json)| (*height, json.as_str()));
                        storage
                            .append_blocks_delta_checked_with_state_nodes_and_economy_snapshot_atomic(
                                db_tip,
                                delta,
                                &[],
                                economy_snapshot_ref,
                                true,
                            )
                            .map_err(storage_err_to_io)?;
                    }
                }
            }
        }
    }

    storage
        .put_compute_order_state_store_v1(&blockchain.compute_order_state_store, true)
        .map_err(storage_err_to_io)?;

    // Export JSON SOLO se esplicitamente abilitato
    if export_json_enabled() {
        let _ = export_blockchain_json(blockchain);
    }

    // Log best-effort
    if let Some(last_block) = blockchain.chain.last() {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let hash_short = last_block.hash.chars().take(8).collect::<String>();
        let line = format!(
            "[{}] ✅ Saved tip #{} | TX:{} | Hash:{} | blocks:{}\n",
            ts,
            last_block.index,
            last_block.transactions.len(),
            hash_short,
            blockchain.chain.len()
        );
        let _ = append_log(&line);
    }

    Ok(())
}

pub fn save_blockchain(blockchain: &Blockchain) -> Result<(), io::Error> {
    let storage =
        DbStore::open(DB_PATH).map_err(|e| io::Error::other(format!("DbStore::open: {e:?}")))?;
    save_blockchain_with_storage(&storage, blockchain)
}

// --- LOAD (DB canonico; JSON solo se NEWGEN_IMPORT_JSON=1) ---

pub fn load_blockchain() -> Blockchain {
    if crate::runtime_mode::public_mode_enabled() {
        return load_blockchain_public_fail_closed().unwrap_or_else(|err| {
            panic!(
                "public mode: refusing legacy load_blockchain genesis/json fallback: {}",
                err
            )
        });
    }

    ng_info!(target: "storage.boot", "Loading blockchain from backend storage path={}", DB_PATH);

    if let Ok(storage) = DbStore::open(DB_PATH) {
        match storage.load_chain() {
            Ok(blocks) if !blocks.is_empty() => {
                let mut chain =
                    Blockchain::from_blocks_with_storage(blocks, Arc::new(storage.clone()));
                apply_policy_override_if_present(&mut chain);

                ng_info!(target: "storage.boot", "Blockchain loaded from backend storage blocks={}", chain.chain.len());
                return chain;
            }
            Ok(_) => {
                ng_info!(target: "storage.boot", "Backend storage empty; falling back to genesis");
                return Blockchain::new();
            }
            Err(e) => {
                ng_warn!(target: "storage.boot", "Failed to read backend storage err={:?}", e)
            }
        }
    } else {
        ng_warn!(target: "storage.boot", "Unable to open backend storage path={}", DB_PATH);
    }

    // JSON NON è boot normale: solo migrazione una tantum
    if import_json_enabled() {
        ng_info!(target: "storage.boot", "Legacy JSON import enabled path={}", full_path(DATA_FILE));
        if let Ok(text) = fs::read_to_string(DATA_FILE) {
            if let Ok(chain) = serde_json::from_str::<Blockchain>(&text) {
                if is_chain_plausible(&chain) {
                    let mut rebuilt = Blockchain::from_blocks(chain.chain);
                    apply_policy_override_if_present(&mut rebuilt);
                    ng_warn!(target: "storage.boot", "Loaded blockchain from legacy JSON blocks={}; next save will migrate to DB", rebuilt.chain.len());
                    return rebuilt;
                }
            }
        }
    }

    ng_warn!(target: "storage.boot", "No valid blockchain source found; falling back to genesis");
    Blockchain::new()
}

pub fn load_blockchain_public_fail_closed() -> Result<Blockchain, String> {
    ng_info!(
        target: "storage.boot",
        "Loading blockchain from backend storage path={} mode=public_fail_closed",
        DB_PATH
    );

    let storage = DbStore::open(DB_PATH).map_err(|e| {
        format!(
            "public mode: unable to open backend storage path={} err={:?}",
            DB_PATH, e
        )
    })?;

    match storage.load_chain() {
        Ok(blocks) if !blocks.is_empty() => {
            let mut chain = Blockchain::from_blocks_with_storage(blocks, Arc::new(storage.clone()));
            apply_policy_override_if_present(&mut chain);

            ng_info!(
                target: "storage.boot",
                "Blockchain loaded from backend storage blocks={} mode=public_fail_closed",
                chain.chain.len()
            );
            Ok(chain)
        }
        Ok(_) => Err(
            "public mode: backend storage empty; refusing implicit genesis fallback".to_string(),
        ),
        Err(e) => Err(format!(
            "public mode: failed to read backend storage; refusing genesis/json fallback err={:?}",
            e
        )),
    }
}

pub fn load_blockchain_opt() -> Option<Blockchain> {
    let chain = load_blockchain();
    if chain.chain.len() > 1 {
        Some(chain)
    } else {
        None
    }
}

// --- CHECK AND REPAIR ---

pub fn check_and_repair_chain(blockchain: &mut Blockchain) -> bool {
    if blockchain.chain.is_empty() {
        ng_info!(target: "storage.boot", "Chain integrity check skipped: chain is empty");
        return false;
    }

    fn recompute_block_hash(block: &crate::block::Block) -> Result<String, String> {
        block.try_calculate_hash()
    }

    let mut repaired = false;

    // Phase 5 (snapshot/pruning): la chain in memoria può iniziare a height > 0.
    // base_height deve sempre essere allineato al primo blocco presente.
    let first_index = blockchain.chain[0].index;
    if blockchain.base_height != first_index {
        ng_warn!(target: "storage.boot", "base_height mismatch detected base_height={} first_index={}; aligning base_height to first block", blockchain.base_height, first_index);
        blockchain.base_height = first_index;
        repaired = true;
    }

    let base = blockchain.base_height;

    let mut i: usize = 0;
    while i < blockchain.chain.len() {
        // 1) Indice atteso = base_height + posizione nella finestra (non 'i' assoluto).
        let expected_index = base.saturating_add(i as u64);
        let block_index = blockchain.chain[i].index;

        if block_index != expected_index {
            ng_warn!(target: "storage.boot", "Chain integrity: invalid block index at pos={} height={} index={} expected={} base_height={}; truncating tail", i, block_index, block_index, expected_index, base);
            blockchain.chain.truncate(i);
            repaired = true;
            break;
        }

        // 2) Hash: è un campo ridondante -> si può ricalcolare e patchare.
        // Importante: farlo PRIMA del check previous_hash, così il prev.hash usato è quello corretto.
        let hash_recomputed = {
            let b = &blockchain.chain[i];
            match recompute_block_hash(b) {
                Ok(v) => v,
                Err(e) => {
                    ng_warn!(target: "storage.boot", "Chain integrity: failed to recompute block hash at pos={} height={} err={}; truncating tail", i, block_index, e);
                    blockchain.chain.truncate(i);
                    repaired = true;
                    break;
                }
            }
        };

        if hash_recomputed != blockchain.chain[i].hash {
            let old = blockchain.chain[i].hash.clone();
            ng_warn!(target: "storage.boot", "Chain integrity: block hash mismatch at pos={} height={} stored={} recomputed={}; patching stored hash", i, block_index, old, hash_recomputed);
            blockchain.chain[i].hash = hash_recomputed;
            repaired = true;
        }

        // 3) previous_hash: verificabile solo dal secondo blocco della finestra in poi.
        // Se la finestra è pruned (base_height>0), il primo blocco non ha il suo predecessore disponibile.
        if i > 0 {
            let prev_hash = blockchain.chain[i - 1].hash.clone();
            let prev_index = blockchain.chain[i - 1].index;

            if blockchain.chain[i].previous_hash != prev_hash {
                ng_warn!(target: "storage.boot", "Chain integrity: previous_hash mismatch at pos={} height={} prev_height={} stored_prev_hash={} expected_prev_hash={}; truncating tail", i, block_index, prev_index, blockchain.chain[i].previous_hash, prev_hash);
                blockchain.chain.truncate(i);
                repaired = true;
                break;
            }
        }

        i += 1;
    }

    if !repaired {
        ng_info!(target: "storage.boot", "Chain integrity check completed valid_blocks={} base_height={}", blockchain.chain.len(), blockchain.base_height);
    } else {
        ng_warn!(target: "storage.boot", "Chain repair applied remaining_blocks={} base_height={}", blockchain.chain.len(), blockchain.base_height);
    }

    recompute_governance_from_chain(blockchain, repaired);
    repaired
}
