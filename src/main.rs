// ===================================
// FILE: src/main.rs (Adattato per P2P Mempool Override)
// ===================================

#![recursion_limit = "256"]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use newgen_engine::anchor_store;
use newgen_engine::checkpoint::{verify_checkpoint_cert, CheckpointCert};
use newgen_engine::explorer;
use newgen_engine::indexer_stream;
use newgen_engine::keyfmt;
use newgen_engine::keystore::{self, KeyRole, KeystoreError};
use newgen_engine::maintenance_params;
use newgen_engine::node_paths::{
    snapshot_v2_auto_dir_from_root, snapshot_v2_bootstrap_latest_dir_from_root,
    snapshot_v2_last_bootstrap_meta_path_from_root,
    snapshot_v2_last_checkpoint_meta_path_from_root, snapshot_v2_last_meta_path_from_root,
    snapshot_v2_latest_dir_from_root, NodePaths, EFFECTIVE_DATA_DIR_ENV,
};
use newgen_engine::snapshot::{
    clamp_snapshot_chunk_bytes_for_rrv3, preferred_bootstrap_snapshot_export_height,
    preferred_checkpoint_snapshot_export_height, snapshot_latest_bundle_refresh_reason,
    SnapshotConsensusBootstrapContextOmissionReason, SnapshotMeta,
};
use newgen_engine::storage::{ChainStorage, DbStore, StorageError, DB_PATH};
use newgen_engine::{ng_debug, ng_error, ng_info, ng_info_throttle, ng_warn, ng_warn_throttle};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::env;
use std::ffi::OsString;
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::{interval, sleep, Duration};

// ====== Moduli locali (crate) ======
use newgen_engine::{
    api,
    netmsg::NetMsg,
    p2p::{self, P2pBootPhase},
    peer_reputation::{PeerReputationManager, ReputationConfig},
    persistence::{
        check_and_repair_chain, load_blockchain_opt, load_blockchain_public_fail_closed,
        persist_barrier, persist_import_snapshot_v2_bundle, persist_init, persist_pause,
        persist_resume, save_blockchain_with_storage,
    },
    security_policy::SecurityPolicy,
    Blockchain, Mempool, SharedChain, SharedMempool,
};

use newgen_engine::error::{ErrorKind, NgError};
use newgen_engine::logging;
use newgen_engine::state_sync::{
    apply_imported_snapshot_to_live_runtime, fetch_checkpoint_cert_latest_from_seeds,
    fetch_snapshot_v2_bundle_from_seeds, fetch_snapshot_v2_bundle_via_runtime_ctrl,
    import_snapshot_v2_bundle_into_live_runtime_and_rearm, notify_state_sync_applied_and_rearm_p2p,
    StateSyncConfig,
};
use newgen_engine::state_sync_supervisor::{
    runtime_statesync_rescue_needed, spawn_state_sync_supervisor, StateSyncReason,
    StateSyncSupervisorConfig,
};
use newgen_engine::storage::mirror_blockchain_to_storage;
use newgen_engine::sync_policy::SyncPolicy;

// ====== File interni ======
use newgen_engine::p2p_peerbook::PeerBook;
use newgen_engine::version::VersionInfo;

fn runtime_inbound_newtx_should_drop_before_locks_v1(
    tx: &newgen_engine::transaction::Transaction,
) -> bool {
    // Coinbase rewards are consensus block payloads only. Runtime inbound gossip
    // must drop them before chain/mempool locks, signature checks, or admission.
    tx.is_coinbase
}

fn default_ports_from_node_id(node_id: &str) -> Option<(u16, u16, u16)> {
    let c = node_id.chars().next()?.to_ascii_uppercase();
    if !c.is_ascii_uppercase() {
        return None;
    }
    let idx: u16 = (c as u8 - b'A') as u16;
    Some((
        8080u16.saturating_add(idx),
        8000u16.saturating_add(idx),
        9000u16.saturating_add(idx),
    ))
}

fn read_snapshot_v2_meta(dir: &Path) -> Option<SnapshotMeta> {
    let meta_path = dir.join("meta.json");
    let bytes = std::fs::read(meta_path).ok()?;
    serde_json::from_slice::<SnapshotMeta>(&bytes).ok()
}

fn should_skip_checkpoint_export_due_to_historical_root_unavailable(
    reachable_only: bool,
    checkpoint_target_height: u64,
    tip_h: u64,
    checkpoint_root_present: bool,
) -> bool {
    reachable_only && checkpoint_target_height < tip_h && !checkpoint_root_present
}

fn snapshot_bundle_meta_modified_at(dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(dir.join("meta.json"))
        .ok()?
        .modified()
        .ok()
}

const STATESYNC_SELF_RESTART_LOCK_INFO_FILE_NAME: &str = ".newgen_fjall_process.lockinfo.json";
const STATESYNC_SELF_RESTART_REASON_ENV: &str = "NEWGEN_INTERNAL_SELF_RESTART_REASON";
const STATESYNC_SELF_RESTART_ATTEMPT_ENV: &str = "NEWGEN_INTERNAL_SELF_RESTART_ATTEMPT";
const STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV: &str = "NEWGEN_INTERNAL_SELF_RESTART_FIRST_AT_MS";
const STATESYNC_SELF_RESTART_DELAY_MS_ENV: &str = "NEWGEN_INTERNAL_SELF_RESTART_DELAY_MS";
const STATESYNC_SELF_RESTART_WINDOW_MS_ENV: &str = "NEWGEN_STATESYNC_SELF_RESTART_WINDOW_MS";
const STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV: &str = "NEWGEN_STATESYNC_SELF_RESTART_MAX_ATTEMPTS";
const STATESYNC_SELF_RESTART_WAIT_LOCK_MS_ENV: &str = "NEWGEN_STATESYNC_SELF_RESTART_WAIT_LOCK_MS";
const STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV: &str =
    "NEWGEN_INTERNAL_SELF_RESTART_EXPECTED_DATA_DIR";
const STATESYNC_SELF_RESTART_CONTEXT_FILE_NAME: &str = ".newgen_statesync_restart_context.json";
const STATESYNC_SELF_RESTART_ON_SUCCESS_ENV: &str = "NEWGEN_STATESYNC_SELF_RESTART_ON_SUCCESS";
const STATESYNC_SELF_RESTART_DEFAULT_DELAY_MS: u64 = 1_500;
const STATESYNC_SELF_RESTART_DEFAULT_WINDOW_MS: u64 = 300_000;
const STATESYNC_SELF_RESTART_DEFAULT_MAX_ATTEMPTS: u32 = 3;
const STATESYNC_SELF_RESTART_DEFAULT_WAIT_LOCK_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelfRestartPlan {
    attempt: u32,
    first_at_ms: u64,
    delay_ms: u64,
    window_ms: u64,
    max_attempts: u32,
    wait_lock_ms: u64,
}

fn env_bool_with_default(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        })
        .unwrap_or(default)
}

fn env_u64_with_default(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32_with_default(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn unix_time_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn compute_statesync_self_restart_plan(now_ms: u64) -> Result<SelfRestartPlan, String> {
    let delay_ms = env_u64_with_default(
        STATESYNC_SELF_RESTART_DELAY_MS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_DELAY_MS,
    )
    .clamp(0, 60_000);
    let window_ms = env_u64_with_default(
        STATESYNC_SELF_RESTART_WINDOW_MS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_WINDOW_MS,
    )
    .clamp(1_000, 3_600_000);
    let wait_lock_ms = env_u64_with_default(
        STATESYNC_SELF_RESTART_WAIT_LOCK_MS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_WAIT_LOCK_MS,
    )
    .clamp(500, 120_000);
    let max_attempts = env_u32_with_default(
        STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_MAX_ATTEMPTS,
    )
    .clamp(1, 16);

    let prior_attempt = env_u32_with_default(STATESYNC_SELF_RESTART_ATTEMPT_ENV, 0);
    let prior_first_at_ms = env_u64_with_default(STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV, 0);

    let chain_active = prior_attempt > 0
        && prior_first_at_ms > 0
        && now_ms.saturating_sub(prior_first_at_ms) <= window_ms;

    let (attempt, first_at_ms) = if chain_active {
        let next_attempt = prior_attempt.saturating_add(1);
        if next_attempt > max_attempts {
            return Err(format!(
                "self-restart guard tripped: prior_attempt={} max_attempts={} window_ms={}",
                prior_attempt, max_attempts, window_ms
            ));
        }
        (next_attempt, prior_first_at_ms)
    } else {
        (1, now_ms)
    };

    Ok(SelfRestartPlan {
        attempt,
        first_at_ms,
        delay_ms,
        window_ms,
        max_attempts,
        wait_lock_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StatesyncSelfRestartContext {
    format_version: u32,
    node_id: String,
    data_dir: String,
    config_dir: String,
    db_dir: String,
    imported_height: u64,
    created_at_ms: u64,
}

fn canonicalize_best_effort(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn paths_match_best_effort(left: &Path, right: &Path) -> bool {
    let left = canonicalize_best_effort(left);
    let right = canonicalize_best_effort(right);
    if left == right {
        return true;
    }

    #[cfg(windows)]
    {
        fn normalize_windows_path_for_compare(path: &Path) -> String {
            let mut s = path.to_string_lossy().replace('/', "\\");
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                s = stripped.to_string();
            }
            s.make_ascii_lowercase();
            s
        }

        return normalize_windows_path_for_compare(&left)
            == normalize_windows_path_for_compare(&right);
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn statesync_self_restart_context_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATESYNC_SELF_RESTART_CONTEXT_FILE_NAME)
}

fn write_json_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create parent dir for {}: {e}", path.display()))?;
    }
    let tmp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        unix_time_millis_now()
    ));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("cannot create temp file {}: {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("cannot write temp file {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("cannot sync temp file {}: {e}", tmp_path.display()))?;
    }
    newgen_engine::utils::atomic_replace_file_v1(&tmp_path, path).map_err(|e| {
        format!(
            "cannot replace {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })
}

fn write_statesync_self_restart_context(
    node_id: &str,
    paths: &NodePaths,
    imported_height: u64,
) -> Result<PathBuf, String> {
    let ctx = StatesyncSelfRestartContext {
        format_version: 1,
        node_id: node_id.to_string(),
        data_dir: paths.data_dir.display().to_string(),
        config_dir: paths.config_dir.display().to_string(),
        db_dir: paths.db_dir.display().to_string(),
        imported_height,
        created_at_ms: unix_time_millis_now(),
    };
    let path = statesync_self_restart_context_path(&paths.data_dir);
    let bytes = serde_json::to_vec_pretty(&ctx)
        .map_err(|e| format!("cannot serialize self-restart context: {e}"))?;
    write_json_atomic(&path, &bytes)?;
    Ok(path)
}

fn read_statesync_self_restart_context(
    paths: &NodePaths,
) -> Result<StatesyncSelfRestartContext, String> {
    let path = statesync_self_restart_context_path(&paths.data_dir);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read self-restart context {}: {e}", path.display()))?;
    let ctx = serde_json::from_slice::<StatesyncSelfRestartContext>(&bytes)
        .map_err(|e| format!("cannot parse self-restart context {}: {e}", path.display()))?;
    if ctx.format_version != 1 {
        return Err(format!(
            "unsupported self-restart context format_version={} path={}",
            ctx.format_version,
            path.display()
        ));
    }
    Ok(ctx)
}

fn ensure_statesync_restart_db_has_materialized_state(db_dir: &Path) -> Result<(), String> {
    let mut has_materialized_entry = false;
    let read_dir = std::fs::read_dir(db_dir)
        .map_err(|e| format!("cannot read db dir {}: {e}", db_dir.display()))?;
    for entry in read_dir {
        let entry =
            entry.map_err(|e| format!("cannot iterate db dir {}: {e}", db_dir.display()))?;
        let name = entry.file_name();
        if name != std::ffi::OsStr::new(STATESYNC_SELF_RESTART_LOCK_INFO_FILE_NAME) {
            has_materialized_entry = true;
            break;
        }
    }

    if !has_materialized_entry {
        return Err(format!(
            "statesync self-restart db dir has no materialized state: {}",
            db_dir.display()
        ));
    }

    Ok(())
}

fn validate_statesync_self_restart_loaded_tip(
    node_id: &str,
    paths: &NodePaths,
    actual_tip_height: u64,
) -> Result<(), String> {
    let reason = match std::env::var(STATESYNC_SELF_RESTART_REASON_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };

    if reason != "statesync_import" {
        return Ok(());
    }

    let ctx = read_statesync_self_restart_context(paths)?;
    if actual_tip_height < ctx.imported_height {
        return Err(format!(
            "statesync self-restart tip regression for node {}: imported_height={} actual_tip={} data_dir={}",
            node_id,
            ctx.imported_height,
            actual_tip_height,
            paths.data_dir.display()
        ));
    }

    let ctx_path = statesync_self_restart_context_path(&paths.data_dir);
    let _ = std::fs::remove_file(&ctx_path);
    Ok(())
}

fn resolve_effective_data_dir(raw_data_dir: &str) -> Result<PathBuf, String> {
    let raw_path = PathBuf::from(raw_data_dir);
    let abs_path = if raw_path.is_absolute() {
        raw_path
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current_dir failed while resolving data-dir: {e}"))?
            .join(raw_path)
    };

    std::fs::create_dir_all(&abs_path).map_err(|e| {
        format!(
            "create_dir_all failed for data-dir {}: {e}",
            abs_path.display()
        )
    })?;

    Ok(std::fs::canonicalize(&abs_path).unwrap_or(abs_path))
}

fn rewrite_statesync_self_restart_args_with_effective_data_dir(
    raw_args: Vec<OsString>,
    effective_data_dir: &Path,
) -> Vec<OsString> {
    let effective_data_dir_os = effective_data_dir.as_os_str().to_os_string();

    let mut rewritten = Vec::with_capacity(raw_args.len().saturating_add(2));
    let mut idx = 0usize;
    let mut replaced = false;

    while idx < raw_args.len() {
        let arg = &raw_args[idx];
        let arg_lossy = arg.to_string_lossy();

        if arg_lossy == "--data-dir" {
            rewritten.push(OsString::from("--data-dir"));
            rewritten.push(effective_data_dir_os.clone());
            replaced = true;
            idx = idx.saturating_add(2);
            continue;
        }

        if arg_lossy.starts_with("--data-dir=") {
            rewritten.push(OsString::from("--data-dir"));
            rewritten.push(effective_data_dir_os.clone());
            replaced = true;
            idx += 1;
            continue;
        }

        rewritten.push(arg.clone());
        idx += 1;
    }

    if !replaced {
        rewritten.push(OsString::from("--data-dir"));
        rewritten.push(effective_data_dir_os);
    }

    rewritten
}

fn validate_statesync_self_restart_boot_context(
    node_id: &str,
    paths: &NodePaths,
) -> Result<(), String> {
    let reason = match std::env::var(STATESYNC_SELF_RESTART_REASON_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };

    if reason != "statesync_import" {
        return Ok(());
    }

    if let Ok(expected_raw) = std::env::var(STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV) {
        let expected_trimmed = expected_raw.trim();
        if !expected_trimmed.is_empty() {
            let expected = canonicalize_best_effort(Path::new(expected_trimmed));
            if !paths_match_best_effort(&expected, &paths.data_dir) {
                return Err(format!(
                    "statesync self-restart data-dir mismatch for node {}: expected={} actual={}",
                    node_id,
                    expected.display(),
                    paths.data_dir.display()
                ));
            }
        }
    }

    if !paths.config_dir.exists() {
        return Err(format!(
            "statesync self-restart missing config dir for node {}: {}",
            node_id,
            paths.config_dir.display()
        ));
    }

    if !paths.db_dir.exists() {
        return Err(format!(
            "statesync self-restart missing db dir for node {}: {}",
            node_id,
            paths.db_dir.display()
        ));
    }

    ensure_statesync_restart_db_has_materialized_state(&paths.db_dir)?;

    if !paths.governance_path().exists() {
        return Err(format!(
            "statesync self-restart missing governance.json for node {}: {}",
            node_id,
            paths.governance_path().display()
        ));
    }

    let ctx = read_statesync_self_restart_context(paths)?;
    if ctx.node_id != node_id {
        return Err(format!(
            "statesync self-restart node mismatch: expected_node={} actual_node={} context_path={}",
            ctx.node_id,
            node_id,
            statesync_self_restart_context_path(&paths.data_dir).display()
        ));
    }

    let expected_data_dir = canonicalize_best_effort(Path::new(&ctx.data_dir));
    if !paths_match_best_effort(&expected_data_dir, &paths.data_dir) {
        return Err(format!(
            "statesync self-restart context data_dir mismatch for node {}: context={} actual={}",
            node_id,
            expected_data_dir.display(),
            paths.data_dir.display()
        ));
    }

    let expected_config_dir = canonicalize_best_effort(Path::new(&ctx.config_dir));
    if !paths_match_best_effort(&expected_config_dir, &paths.config_dir) {
        return Err(format!(
            "statesync self-restart context config_dir mismatch for node {}: context={} actual={}",
            node_id,
            expected_config_dir.display(),
            paths.config_dir.display()
        ));
    }

    let expected_db_dir = canonicalize_best_effort(Path::new(&ctx.db_dir));
    if !paths_match_best_effort(&expected_db_dir, &paths.db_dir) {
        return Err(format!(
            "statesync self-restart context db_dir mismatch for node {}: context={} actual={}",
            node_id,
            expected_db_dir.display(),
            paths.db_dir.display()
        ));
    }

    Ok(())
}

fn spawn_statesync_self_restart(plan: SelfRestartPlan) -> Result<u32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let effective_data_dir = std::env::current_dir()
        .map_err(|e| format!("current_dir failed before self-restart spawn: {e}"))?;
    let raw_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args =
        rewrite_statesync_self_restart_args_with_effective_data_dir(raw_args, &effective_data_dir);

    let mut child = Command::new(&exe);
    child.current_dir(&effective_data_dir);
    child.args(&args);
    child.env(EFFECTIVE_DATA_DIR_ENV, effective_data_dir.as_os_str());
    child.env(STATESYNC_SELF_RESTART_REASON_ENV, "statesync_import");
    child.env(
        STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV,
        effective_data_dir.as_os_str(),
    );
    child.env(STATESYNC_SELF_RESTART_ATTEMPT_ENV, plan.attempt.to_string());
    child.env(
        STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV,
        plan.first_at_ms.to_string(),
    );
    child.env(
        STATESYNC_SELF_RESTART_DELAY_MS_ENV,
        plan.delay_ms.to_string(),
    );
    child.env(
        STATESYNC_SELF_RESTART_WINDOW_MS_ENV,
        plan.window_ms.to_string(),
    );
    child.env(
        STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV,
        plan.max_attempts.to_string(),
    );
    child.env(
        STATESYNC_SELF_RESTART_WAIT_LOCK_MS_ENV,
        plan.wait_lock_ms.to_string(),
    );

    let spawned = child
        .spawn()
        .map_err(|e| format!("spawn replacement child failed: {e}"))?;
    Ok(spawned.id())
}

fn wait_for_statesync_self_restart_lock_release(node_id: &str, db_dir: &Path) {
    let reason = match std::env::var(STATESYNC_SELF_RESTART_REASON_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return,
    };

    let attempt = env_u32_with_default(STATESYNC_SELF_RESTART_ATTEMPT_ENV, 0);
    let delay_ms = env_u64_with_default(
        STATESYNC_SELF_RESTART_DELAY_MS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_DELAY_MS,
    )
    .clamp(0, 60_000);
    let wait_lock_ms = env_u64_with_default(
        STATESYNC_SELF_RESTART_WAIT_LOCK_MS_ENV,
        STATESYNC_SELF_RESTART_DEFAULT_WAIT_LOCK_MS,
    )
    .clamp(500, 120_000);
    let lock_info_path = db_dir.join(STATESYNC_SELF_RESTART_LOCK_INFO_FILE_NAME);

    ng_info!(
        target: "runtime.boot",
        "event=internal_self_restart_resume node={} reason={} attempt={} delay_ms={} wait_lock_ms={}",
        node_id,
        reason,
        attempt,
        delay_ms,
        wait_lock_ms
    );

    if delay_ms > 0 {
        thread::sleep(Duration::from_millis(delay_ms));
    }

    let start = std::time::Instant::now();
    while lock_info_path.exists() && start.elapsed().as_millis() < wait_lock_ms as u128 {
        thread::sleep(Duration::from_millis(100));
    }

    if lock_info_path.exists() {
        ng_warn!(
            target: "runtime.boot",
            "event=internal_self_restart_lock_wait_elapsed node={} reason={} attempt={} lock_info_path={} action=continue_boot",
            node_id,
            reason,
            attempt,
            lock_info_path.display()
        );
    } else {
        ng_info!(
            target: "runtime.boot",
            "event=internal_self_restart_lock_released node={} reason={} attempt={} waited_ms={}",
            node_id,
            reason,
            attempt,
            start.elapsed().as_millis()
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointLatestTargetDisposition {
    ExactCadence,
    FallbackAlignedHeight,
    HoldLastSuccessful,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointLatestTargetSelection {
    target_height: u64,
    disposition: CheckpointLatestTargetDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointLatestPlannerState {
    ideal_target_height: u64,
    effective_target_height: Option<u64>,
    disposition: Option<CheckpointLatestTargetDisposition>,
}

fn checkpoint_export_candidate_heights_desc(
    ideal_target_height: u64,
    snapshot_every_n: u64,
    last_successful_height: Option<u64>,
) -> Vec<u64> {
    let step = snapshot_every_n.max(1);
    let mut heights = Vec::new();
    let mut candidate = ideal_target_height;
    loop {
        if !heights.contains(&candidate) {
            heights.push(candidate);
        }
        if candidate < step {
            break;
        }
        candidate = candidate.saturating_sub(step);
    }
    if let Some(last_successful_height) = last_successful_height {
        if !heights.contains(&last_successful_height) {
            heights.push(last_successful_height);
        }
    }
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();
    heights
}

fn checkpoint_governance_anchor_materializable_v207(
    governance_snapshot_height: Option<u64>,
    candidate_height: u64,
    candidate_window_from: u64,
) -> bool {
    match governance_snapshot_height {
        Some(gov_h) => gov_h <= candidate_height,
        None => candidate_window_from == 0,
    }
}

fn select_checkpoint_latest_target<F>(
    ideal_target_height: u64,
    snapshot_every_n: u64,
    last_successful_height: Option<u64>,
    mut is_exportable: F,
) -> Option<CheckpointLatestTargetSelection>
where
    F: FnMut(u64) -> bool,
{
    for candidate_height in checkpoint_export_candidate_heights_desc(
        ideal_target_height,
        snapshot_every_n,
        last_successful_height,
    ) {
        if !is_exportable(candidate_height) {
            continue;
        }
        let disposition = if candidate_height == ideal_target_height {
            CheckpointLatestTargetDisposition::ExactCadence
        } else if Some(candidate_height) == last_successful_height {
            CheckpointLatestTargetDisposition::HoldLastSuccessful
        } else {
            CheckpointLatestTargetDisposition::FallbackAlignedHeight
        };
        return Some(CheckpointLatestTargetSelection {
            target_height: candidate_height,
            disposition,
        });
    }
    None
}

fn bootstrap_refresh_reason_requires_immediate_export(
    reason: newgen_engine::snapshot::SnapshotLatestBundleRefreshReason,
) -> bool {
    use newgen_engine::snapshot::SnapshotLatestBundleRefreshReason as Reason;

    !matches!(reason, Reason::StaleHeight)
}

fn snapshot_latest_refresh_reason_is_warning_v316(
    reason: newgen_engine::snapshot::SnapshotLatestBundleRefreshReason,
) -> bool {
    use newgen_engine::snapshot::SnapshotLatestBundleRefreshReason as Reason;

    matches!(
        reason,
        Reason::MissingMeta
            | Reason::UnreadableMeta
            | Reason::InvalidMeta
            | Reason::NotTransportServable
            | Reason::MissingChunkFiles
            | Reason::CorruptChunkFiles
            | Reason::StaleCheckpointBlock
    )
}

fn should_export_bootstrap_latest(
    refresh_reason: Option<newgen_engine::snapshot::SnapshotLatestBundleRefreshReason>,
    expected_height: u64,
    last_exported_height: Option<u64>,
    last_exported_at: Option<SystemTime>,
    min_height_delta: u64,
    min_interval_ms: u64,
    now: SystemTime,
) -> bool {
    let Some(reason) = refresh_reason else {
        return false;
    };
    if bootstrap_refresh_reason_requires_immediate_export(reason) {
        return true;
    }

    let min_height_delta = min_height_delta.max(1);
    let height_delta = last_exported_height
        .map(|height| expected_height.saturating_sub(height))
        .unwrap_or(expected_height);
    if height_delta >= min_height_delta {
        return true;
    }

    match last_exported_at.and_then(|ts| now.duration_since(ts).ok()) {
        Some(elapsed) => elapsed.as_millis() >= min_interval_ms as u128,
        None => true,
    }
}

fn extend_seed_list_from_csvish(out: &mut Vec<String>, raw: &str) {
    for part in raw
        .split([',', ';', ' ', '\n', '\t'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        out.push(part.to_string());
    }
}

// cold-start snapshot bootstrap prefers direct seed fetch before the live runtime actor starts.
// If direct seed req/res cannot fetch snapshot metadata, V211 may defer to the
// runtime P2P actor in ColdStartSnapshot mode only. This is still snapshot-only
// and fail-closed: it must not enter JSON/default genesis fallback, live block
// catch-up fallback, or mining while the DB is empty.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdStartStorageState {
    Empty,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdStartBootstrapPlan {
    ImportExplicitSnapshot,
    DirectSeedBootstrap,
    JsonFallback,
    FailClosed,
}

#[derive(Debug)]
enum ColdStartBootstrapResolution {
    Ready(Blockchain),
    DeferRuntimeActor {
        out_dir: PathBuf,
        reason: String,
        boot_phase: P2pBootPhase,
    },
    JsonFallback {
        reason: String,
    },
    FailClosed {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeActorBootstrapFailurePlan {
    EnterFallbackLiveSync,
    FailClosed,
}

fn describe_cold_start_storage_state(state: ColdStartStorageState) -> &'static str {
    match state {
        ColdStartStorageState::Empty => "DB vuoto",
        ColdStartStorageState::Invalid => "backend storage invalido/corrotto",
    }
}

fn decide_cold_start_bootstrap_plan(
    _storage_state: ColdStartStorageState,
    has_explicit_snapshot: bool,
    auto_state_sync_enabled: bool,
    has_seeds: bool,
    public_mode: bool,
) -> ColdStartBootstrapPlan {
    if has_explicit_snapshot {
        return ColdStartBootstrapPlan::ImportExplicitSnapshot;
    }
    if auto_state_sync_enabled && has_seeds {
        return ColdStartBootstrapPlan::DirectSeedBootstrap;
    }
    if public_mode {
        return ColdStartBootstrapPlan::FailClosed;
    }
    ColdStartBootstrapPlan::JsonFallback
}

fn env_truthy_opt_in_v1(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let t = v.trim();
            t == "1"
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn allow_large_gap_block_fallback_env_v1() -> bool {
    env_truthy_opt_in_v1("NEWGEN_ALLOW_LARGE_GAP_BLOCK_FALLBACK")
}

fn allow_runtime_actor_coldstart_fallback_env_v1() -> bool {
    env_truthy_opt_in_v1("NEWGEN_ALLOW_RUNTIME_ACTOR_COLDSTART_FALLBACK")
}

fn allow_snapshot_coldstart_json_fallback_env_v1() -> bool {
    env_truthy_opt_in_v1("NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK")
}

fn decide_runtime_actor_failure_plan(
    public_mode: bool,
    allow_large_gap_block_fallback: bool,
) -> RuntimeActorBootstrapFailurePlan {
    if public_mode || !allow_large_gap_block_fallback {
        RuntimeActorBootstrapFailurePlan::FailClosed
    } else {
        RuntimeActorBootstrapFailurePlan::EnterFallbackLiveSync
    }
}

fn direct_seed_failure_can_defer_to_runtime_snapshot_v211(public_mode: bool) -> bool {
    // V211: this is not the old lab fallback. Non-public cold starts may use the
    // already-hardened runtime RRv3 snapshot path, but only in ColdStartSnapshot
    // phase. Public mode remains strict because it must boot from an explicitly
    // anchored snapshot path or a successful direct seed path before runtime.
    !public_mode
}

fn cold_start_runtime_snapshot_pending_v211(
    pending_out_dir: &Option<PathBuf>,
    pending_phase: Option<P2pBootPhase>,
) -> bool {
    pending_out_dir.is_some() && matches!(pending_phase, Some(P2pBootPhase::ColdStartSnapshot))
}

fn decide_runtime_snapshot_failure_plan_v211(
    pending_phase: Option<P2pBootPhase>,
    public_mode: bool,
    allow_large_gap_block_fallback: bool,
) -> RuntimeActorBootstrapFailurePlan {
    if matches!(pending_phase, Some(P2pBootPhase::ColdStartSnapshot)) {
        RuntimeActorBootstrapFailurePlan::FailClosed
    } else {
        decide_runtime_actor_failure_plan(public_mode, allow_large_gap_block_fallback)
    }
}

fn quarantine_runtime_db_dir_for_cold_start(
    db_dir: &Path,
    node_id_str: &str,
) -> Result<Option<PathBuf>, String> {
    newgen_engine::storage::evict_canonical_db_for_path(db_dir);
    if !db_dir.exists() {
        return Ok(None);
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    let backup = db_dir.with_file_name(format!("db_quarantine_{}_{}", node_id_str, ts));

    std::fs::rename(db_dir, &backup).map_err(|e| {
        format!(
            "cannot quarantine invalid runtime db {} -> {}: {}",
            db_dir.display(),
            backup.display(),
            e
        )
    })?;
    std::fs::create_dir_all(db_dir).map_err(|e| {
        format!(
            "cannot recreate runtime db directory {} after quarantine: {}",
            db_dir.display(),
            e
        )
    })?;
    Ok(Some(backup))
}

async fn import_snapshot_dir_for_cold_start(
    storage: Arc<DbStore>,
    dir: &Path,
    paths: &NodePaths,
    node_id_str: &str,
    public_mode: bool,
    chain_id: &str,
    peer: Option<&String>,
) -> Result<Blockchain, String> {
    let expected_genesis_hash = Blockchain::new().genesis_hash.clone();
    let meta = read_snapshot_v2_meta(dir)
        .ok_or_else(|| format!("impossibile leggere meta.json in {}", dir.display()))?;

    if meta.genesis_hash != expected_genesis_hash {
        return Err(format!(
            "snapshot v2 genesis mismatch: meta.genesis_hash={} != expected={}",
            meta.genesis_hash, expected_genesis_hash
        ));
    }

    if public_mode {
        let cache_path = anchor_store::default_anchor_cache_path(paths);
        let mut cert_opt: Option<CheckpointCert> = None;

        if let Ok(p) = std::env::var("NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH") {
            let t = p.trim();
            if !t.is_empty() {
                cert_opt = Some(read_checkpoint_cert_from_path(t)?);
            }
        }

        if cert_opt.is_none() {
            cert_opt = anchor_store::load_checkpoint_cert(&cache_path);
        }

        if cert_opt.is_none() {
            let auto_fetch = env_bool("NEWGEN_AUTO_ANCHOR_FETCH", true);
            let seeds = collect_seed_multiaddrs(peer);
            if auto_fetch && !seeds.is_empty() {
                let cfg = StateSyncConfig {
                    chain_id: chain_id.to_string(),
                    expected_genesis_hash: expected_genesis_hash.clone(),
                    public_mode: true,
                    anchor_cache_path: Some(cache_path.clone()),
                    auto_fetch_anchor: true,
                    ..StateSyncConfig::default()
                };

                match fetch_checkpoint_cert_latest_from_seeds(seeds, cfg).await {
                    Ok(Some(c)) => cert_opt = Some(c),
                    Ok(None) => {}
                    Err(e) => {
                        ng_warn!(
                            target: "state_sync.anchor",
                            "event=cold_start_anchor_discovery_failed node={} err={}",
                            node_id_str,
                            e
                        );
                    }
                }
            }
        }

        let cert = cert_opt.ok_or_else(|| {
            "--public: missing trust anchor (CheckpointCert). Provide NEWGEN_TRUSTED_CHECKPOINT_CERT_PATH, or ensure seeds are reachable for RRv3 anchor discovery.".to_string()
        })?;

        verify_snapshot_meta_against_checkpoint_cert(
            &meta,
            chain_id,
            &expected_genesis_hash,
            &cert,
        )
        .map_err(|e| format!("--public: snapshot-v2 anchor verification failed: {e}"))?;

        let _ = anchor_store::save_checkpoint_cert(&cache_path, &cert);
        ng_info!(
            target: "snapshot.bootstrap",
            "event=anchor_verified node={} mode=public source=signed_checkpoint_cert",
            node_id_str
        );
    }

    ng_info!(
        target: "snapshot.bootstrap",
        "event=snapshot_meta_verified node={} height={} base_height={} window_from={} window_to={} state_root={}",
        node_id_str,
        meta.height,
        meta.base_height,
        meta.window_from_height,
        meta.window_to_height,
        meta.state_root
    );

    storage
        .import_snapshot_v2_bundle(dir, true)
        .map_err(|e| format!("import snapshot v2 failed: {:?}", e))?;

    ng_info!(
        target: "snapshot.bootstrap",
        "event=snapshot_import_applied node={} source=local_bundle",
        node_id_str
    );
    let blocks2 = storage
        .load_chain()
        .map_err(|e| format!("reload post-import snapshot failed: {:?}", e))?;
    if blocks2.is_empty() {
        return Err("import snapshot riuscito ma DB resta vuoto".to_string());
    }
    ng_info!(
        target: "snapshot.bootstrap",
        "event=chain_reloaded_from_snapshot node={} source=local_bundle blocks={}",
        node_id_str,
        blocks2.len()
    );
    Ok(Blockchain::from_blocks_with_storage(blocks2, storage))
}

async fn direct_seed_bootstrap_for_cold_start(
    storage: Arc<DbStore>,
    out_dir: &Path,
    seeds: Vec<String>,
    paths: &NodePaths,
    node_id_str: &str,
    public_mode: bool,
    chain_id: &str,
) -> Result<Blockchain, String> {
    let expected_genesis_hash = Blockchain::new().genesis_hash.clone();
    let cfg = StateSyncConfig {
        chain_id: chain_id.to_string(),
        expected_genesis_hash,
        public_mode,
        anchor_cache_path: Some(anchor_store::default_anchor_cache_path(paths)),
        auto_fetch_anchor: true,
        ..StateSyncConfig::default()
    };

    let meta = fetch_snapshot_v2_bundle_from_seeds(seeds, out_dir, None, cfg)
        .await
        .map_err(|e| format!("state-sync automatico diretto da seeds fallito: {e}"))?;

    ng_info!(
        target: "state_sync.bootstrap",
        "event=snapshot_bundle_downloaded node={} source=seeds height={} base_height={} window_from={} window_to={} chunks={} state_root={}",
        node_id_str,
        meta.height,
        meta.base_height,
        meta.window_from_height,
        meta.window_to_height,
        meta.chunks,
        meta.state_root
    );

    storage
        .import_snapshot_v2_bundle(out_dir, true)
        .map_err(|e| format!("import snapshot v2 da seeds fallito: {:?}", e))?;

    ng_info!(
        target: "state_sync.bootstrap",
        "event=snapshot_import_applied node={} source=seed_bundle",
        node_id_str
    );
    let blocks2 = storage
        .load_chain()
        .map_err(|e| format!("reload post-import snapshot da seeds fallito: {:?}", e))?;
    if blocks2.is_empty() {
        return Err("import snapshot da seeds riuscito ma DB resta vuoto".to_string());
    }

    ng_info!(
        target: "state_sync.bootstrap",
        "event=chain_reloaded_from_snapshot node={} source=seed_bundle blocks={}",
        node_id_str,
        blocks2.len()
    );
    Ok(Blockchain::from_blocks_with_storage(blocks2, storage))
}

async fn resolve_cold_start_bootstrap(
    storage_state: ColdStartStorageState,
    storage: Arc<DbStore>,
    bootstrap_snapshot_v2_dir: Option<&PathBuf>,
    auto_state_sync_enabled: bool,
    auto_state_sync_seeds: &[String],
    paths: &NodePaths,
    node_id_str: &str,
    public_mode: bool,
    chain_id: &str,
    peer: Option<&String>,
) -> ColdStartBootstrapResolution {
    let plan = decide_cold_start_bootstrap_plan(
        storage_state,
        bootstrap_snapshot_v2_dir.is_some(),
        auto_state_sync_enabled,
        !auto_state_sync_seeds.is_empty(),
        public_mode,
    );

    match plan {
        ColdStartBootstrapPlan::ImportExplicitSnapshot => {
            let dir = bootstrap_snapshot_v2_dir
                .expect("explicit snapshot dir required by ImportExplicitSnapshot plan");
            ng_info!(
                target: "snapshot.bootstrap",
                "event=cold_start_snapshot_import_attempt node={} storage_state={} dir={}",
                node_id_str,
                describe_cold_start_storage_state(storage_state),
                dir.display()
            );
            match import_snapshot_dir_for_cold_start(
                storage,
                dir.as_path(),
                paths,
                node_id_str,
                public_mode,
                chain_id,
                peer,
            )
            .await
            {
                Ok(blockchain) => ColdStartBootstrapResolution::Ready(blockchain),
                Err(reason) => {
                    if public_mode {
                        ColdStartBootstrapResolution::FailClosed {
                            reason: format!(
                                "--public: explicit bootstrap snapshot import failed; refusing JSON/default fallback: {}",
                                reason
                            ),
                        }
                    } else if allow_snapshot_coldstart_json_fallback_env_v1() {
                        ColdStartBootstrapResolution::JsonFallback {
                            reason: format!(
                                "explicit bootstrap snapshot import failed; JSON fallback explicitly enabled by NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK=1; err={}",
                                reason
                            ),
                        }
                    } else {
                        ColdStartBootstrapResolution::FailClosed {
                            reason: format!(
                                "explicit bootstrap snapshot import failed before live P2P; refusing JSON/default fallback by default (set NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK=1 only for lab debugging); err={}",
                                reason
                            ),
                        }
                    }
                }
            }
        }
        ColdStartBootstrapPlan::DirectSeedBootstrap => {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            let out_dir = paths
                .snapshots_dir
                .join(format!("net_bootstrap_{}_{}", node_id_str, ts));
            ng_info!(
                target: "state_sync.bootstrap",
                "event=cold_start_seed_bootstrap_attempt node={} storage_state={} seeds={} out_dir={}",
                node_id_str,
                describe_cold_start_storage_state(storage_state),
                auto_state_sync_seeds.len(),
                out_dir.display()
            );

            match direct_seed_bootstrap_for_cold_start(
                storage,
                &out_dir,
                auto_state_sync_seeds.to_vec(),
                paths,
                node_id_str,
                public_mode,
                chain_id,
            )
            .await
            {
                Ok(blockchain) => ColdStartBootstrapResolution::Ready(blockchain),
                Err(reason) => {
                    if public_mode {
                        ColdStartBootstrapResolution::FailClosed {
                            reason: format!(
                                "--public: direct seed bootstrap failed; refusing runtime actor/default genesis fallback: {}",
                                reason
                            ),
                        }
                    } else if direct_seed_failure_can_defer_to_runtime_snapshot_v211(public_mode) {
                        ColdStartBootstrapResolution::DeferRuntimeActor {
                            out_dir,
                            reason: format!(
                                "direct seed bootstrap failed; deferring to runtime P2P snapshot-only cold-start bootstrap (V211); no JSON/default fallback, no live block fallback, no mining; err={}",
                                reason
                            ),
                            boot_phase: P2pBootPhase::ColdStartSnapshot,
                        }
                    } else {
                        ColdStartBootstrapResolution::FailClosed {
                            reason: format!(
                                "direct seed bootstrap failed before runtime snapshot bootstrap became allowed; refusing JSON/default fallback; err={}",
                                reason
                            ),
                        }
                    }
                }
            }
        }
        ColdStartBootstrapPlan::JsonFallback => {
            if public_mode {
                ColdStartBootstrapResolution::FailClosed {
                    reason: format!(
                        "--public: {} cannot use JSON/default fallback",
                        describe_cold_start_storage_state(storage_state)
                    ),
                }
            } else {
                ColdStartBootstrapResolution::JsonFallback {
                    reason: format!(
                        "{}: auto state-sync disabilitato o senza seeds; fallback JSON",
                        describe_cold_start_storage_state(storage_state)
                    ),
                }
            }
        }
        ColdStartBootstrapPlan::FailClosed => ColdStartBootstrapResolution::FailClosed {
            reason: format!(
                "--public: {} ma bootstrap snapshot ancorato non disponibile (auto state-sync disabilitato o senza seeds)",
                describe_cold_start_storage_state(storage_state)
            ),
        },
    }
}

fn load_blockchain_for_boot_or_exit(
    public_mode: bool,
    node_id_str: &str,
    context: &str,
) -> Blockchain {
    if public_mode {
        match load_blockchain_public_fail_closed() {
            Ok(chain) => chain,
            Err(err) => {
                ng_error!(
                    target: "storage.boot",
                    "event=public_boot_load_fail_closed node={} context={} err={} action=exit",
                    node_id_str,
                    context,
                    err
                );
                std::process::exit(2);
            }
        }
    } else {
        load_blockchain_opt().unwrap_or_default()
    }
}

fn collect_seed_multiaddrs(peer: Option<&String>) -> Vec<String> {
    let mut seeds: Vec<String> = Vec::new();

    if let Some(p) = peer {
        extend_seed_list_from_csvish(&mut seeds, p);
    }

    for env_name in ["NEWGEN_BOOTSTRAP_PEERS", "NEWGEN_STATESYNC_SEEDS"] {
        if let Ok(v) = std::env::var(env_name) {
            extend_seed_list_from_csvish(&mut seeds, &v);
        }
    }

    seeds.sort();
    seeds.dedup();
    seeds
}

fn quorum_k_2of3(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (2 * n).div_ceil(3)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

fn validator_set_hash_hex(validators_hex: &std::collections::HashSet<String>) -> String {
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

async fn set_runtime_boot_phase(
    ctrl: &tokio::sync::mpsc::UnboundedSender<p2p::P2pControl>,
    phase: P2pBootPhase,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    if ctrl
        .send(p2p::P2pControl::SetBootPhase { phase, ack: tx })
        .is_ok()
    {
        let _ = tokio::time::timeout(Duration::from_secs(2), rx).await;
    }
}

fn load_bootstrap_validators_hex() -> Result<std::collections::HashSet<String>, String> {
    let gov = newgen_engine::governance_provider::load_governance_bootstrap_required_quiet(
        "config/governance.json",
    )
    .map_err(|e| {
        format!(
            "governance bootstrap required for anchor verification: {}",
            e
        )
    })?;

    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
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
    chain_id: &str,
    expected_genesis_hash: &str,
    cert: &CheckpointCert,
) -> Result<(), String> {
    if cert.checkpoint.chain_id != chain_id {
        return Err("anchor chain_id mismatch".to_string());
    }
    if !expected_genesis_hash.trim().is_empty()
        && cert.checkpoint.genesis_hash != expected_genesis_hash
    {
        return Err("anchor genesis_hash mismatch".to_string());
    }
    if meta.genesis_hash.trim().is_empty() {
        return Err("snapshot meta missing genesis_hash (public mode)".to_string());
    }
    if !expected_genesis_hash.trim().is_empty() && meta.genesis_hash != expected_genesis_hash {
        return Err("snapshot meta genesis_hash mismatch".to_string());
    }
    if meta.genesis_hash != cert.checkpoint.genesis_hash {
        return Err("snapshot meta genesis_hash != anchor genesis_hash".to_string());
    }
    if cert.checkpoint.height != meta.height {
        return Err("anchor height mismatch vs snapshot meta".to_string());
    }
    if cert.checkpoint.block_hash != meta.checkpoint_block_hash {
        return Err("anchor checkpoint hash mismatch vs snapshot meta".to_string());
    }

    let allowed_signers_hex = load_bootstrap_validators_hex()?;
    let vset_hash = validator_set_hash_hex(&allowed_signers_hex);
    if cert.checkpoint.validator_set_hash != vset_hash {
        return Err("anchor validator_set_hash mismatch".to_string());
    }
    let quorum_k = quorum_k_2of3(allowed_signers_hex.len());
    verify_checkpoint_cert(cert, quorum_k, &allowed_signers_hex)
        .map_err(|e| format!("anchor checkpoint cert invalid: {e}"))?;
    Ok(())
}

// ----------------------------------------------------------
// Runtime maintenance loop: deterministic pruning (Phase 5)
// - Trigger: every NEWGEN_PRUNE_EVERY_N_BLOCKS (default 512)
// - Policy: keep last NEWGEN_RETAIN_WINDOW_BLOCKS (default 50_000)
// - Work cap: NEWGEN_PRUNE_MAX_BLOCKS_PER_RUN (default 10_000)
// Notes:
// - Pruning is NOT consensus-critical, but in --public you should keep these knobs identical across nodes
//   (or publish them via governance) to avoid frequent no-overlap situations.
// ----------------------------------------------------------

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

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name).ok().map(|s| s.to_ascii_lowercase()) {
        Some(v) if v == "1" || v == "true" || v == "yes" => true,
        Some(v) if v == "0" || v == "false" || v == "no" => false,
        _ => default,
    }
}

fn prune_in_memory_chain_to_base_height(ch: &mut Blockchain, new_base_height: u64) -> usize {
    if ch.chain.is_empty() {
        ch.base_height = new_base_height;
        return 0;
    }

    // Find first block kept in-window.
    let pos = match ch.chain.iter().position(|b| b.index >= new_base_height) {
        Some(p) => p,
        None => {
            // Extreme case: requested base beyond our tip → keep only the tip (shouldn't happen with sane knobs).
            let tip = ch.chain.last().cloned();
            ch.chain.clear();
            if let Some(t) = tip {
                ch.chain.push(t);
            }
            ch.base_height = ch.chain.first().map(|b| b.index).unwrap_or(new_base_height);
            return 0;
        }
    };

    if pos == 0 {
        ch.base_height = ch.chain.first().map(|b| b.index).unwrap_or(new_base_height);
        return 0;
    }

    let kept = ch.chain.split_off(pos);
    let pruned = pos;
    ch.chain = kept;
    ch.base_height = ch.chain.first().map(|b| b.index).unwrap_or(new_base_height);
    pruned
}

fn persist_governance_anchor_for_prune(
    storage: &DbStore,
    bootstrap_json: Option<String>,
    snapshot_height: u64,
    snapshot_json: String,
) -> Result<(), String> {
    if let Some(js) = bootstrap_json.as_deref() {
        storage
            .put_governance_bootstrap_json(js, false)
            .map_err(|e| format!("put_governance_bootstrap_json failed: {e:?}"))?;
    }

    storage
        .put_governance_snapshot(snapshot_height, &snapshot_json, false)
        .map_err(|e| format!("put_governance_snapshot failed: {e:?}"))?;

    storage
        .flush_db()
        .map_err(|e| format!("flush_db after governance snapshot failed: {e:?}"))?;

    Ok(())
}

fn spawn_pruning_maintenance_loop(
    node_id: String,
    public_mode: bool,
    chain: SharedChain,
    storage: Arc<DbStore>,
    last_snapshot_ok_height: Arc<AtomicU64>,
) {
    // In public mode, pruning maintenance is always enabled (protocol-defined params).
    // In non-public mode, allow opt-out via env for local testing.
    let enabled = if public_mode {
        true
    } else {
        env_bool("NEWGEN_MAINTENANCE_PRUNE", true)
    };
    if !enabled {
        ng_info!(
            target: "snapshot.prune",
            "event=maintenance_prune_disabled node={} source=env",
            node_id
        );
        return;
    }

    let poll_ms = env_u64("NEWGEN_PRUNE_POLL_MS", 1500).clamp(250, 10_000);

    if public_mode {
        ng_info!(
            target: "snapshot.prune",
            "event=maintenance_prune_enabled node={} mode=public params_source=smt poll_ms={}",
            node_id,
            poll_ms
        );
    } else {
        let prune_every_n = env_u64("NEWGEN_PRUNE_EVERY_N_BLOCKS", 512).max(1);
        let retain_window = env_u64("NEWGEN_RETAIN_WINDOW_BLOCKS", 50_000).max(1000);
        let max_blocks_per_run =
            env_usize("NEWGEN_PRUNE_MAX_BLOCKS_PER_RUN", 10_000).clamp(1, 1_000_000);

        ng_info!(
            target: "snapshot.prune",
            "event=maintenance_prune_enabled node={} mode=dev every_n={} retain_window={} max_blocks_per_run={} poll_ms={} public_mode={}",
            node_id,
            prune_every_n,
            retain_window,
            max_blocks_per_run,
            poll_ms,
            public_mode
        );
    }

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(poll_ms));
        // Start from the next multiple.
        let mut next_trigger_h: u64 = 0;
        let mut last_prune_every_n: u64 = 0;
        let mut printed_public_params = false;

        loop {
            tick.tick().await;

            // Tip/base/state_root snapshot (short lock).
            let (tip_h, base_h, tip_state_root) = {
                let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                let tip = ch.chain.last().map(|b| b.index).unwrap_or(ch.base_height);
                let base = ch.chain.first().map(|b| b.index).unwrap_or(ch.base_height);
                let tip_root = ch
                    .chain
                    .last()
                    .map(|b| b.state_root.clone())
                    .unwrap_or_default();
                (tip, base, tip_root)
            };

            // Resolve pruning params (protocol-defined in public mode; env-defined in dev mode).
            let (prune_every_n, retain_window, max_blocks_per_run, prune_requires_snapshot) =
                if public_mode {
                    if tip_state_root.trim().is_empty() {
                        ng_error!(
                            target: "snapshot.export",
                            "event=public_snapshot_params_load_failed node={} reason=missing_tip_state_root",
                            node_id
                        );
                        std::process::exit(2);
                    }

                    match maintenance_params::load_from_state_root(&storage, tip_state_root.trim())
                    {
                        Ok(Some(p)) => {
                            let pe = p.prune_every_n_blocks.max(1);
                            let rw = p.retain_window_blocks.max(1000);
                            let mx_u64 = p.prune_max_blocks_per_run.max(1);
                            let mx = (mx_u64.min(usize::MAX as u64)) as usize;
                            let prs = p.prune_requires_snapshot;

                            if !printed_public_params {
                                ng_info!(
                                    target: "snapshot.prune",
                                    "event=public_prune_params_loaded node={} every_n={} retain_window={} max_blocks_per_run={} prune_requires_snapshot={} poll_ms={}",
                                    node_id,
                                    pe,
                                    rw,
                                    mx,
                                    prs,
                                    poll_ms
                                );
                                printed_public_params = true;
                            }

                            (pe, rw, mx, prs)
                        }
                        Ok(None) => {
                            ng_error!(
                                target: "snapshot.export",
                                "event=public_snapshot_params_load_failed node={} reason=missing_protocol_params_in_smt",
                                node_id
                            );
                            std::process::exit(2);
                        }
                        Err(e) => {
                            ng_error!(
                                target: "snapshot.prune",
                                "event=public_prune_params_load_failed node={} err={} action=abort",
                                node_id,
                                e
                            );
                            std::process::exit(2);
                        }
                    }
                } else {
                    let pe = env_u64("NEWGEN_PRUNE_EVERY_N_BLOCKS", 512).max(1);
                    let rw = env_u64("NEWGEN_RETAIN_WINDOW_BLOCKS", 50_000).max(1000);
                    let mx =
                        env_usize("NEWGEN_PRUNE_MAX_BLOCKS_PER_RUN", 10_000).clamp(1, 1_000_000);
                    let prs = env_bool("NEWGEN_PRUNE_REQUIRES_SNAPSHOT", false);
                    (pe, rw, mx, prs)
                };

            // Too early: nothing to prune.
            if tip_h <= retain_window {
                continue;
            }

            // Initialize trigger on first tick with a tip, or if cadence changes.
            if next_trigger_h == 0 || prune_every_n != last_prune_every_n {
                next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                last_prune_every_n = prune_every_n;
            }

            // Only run on schedule.
            if tip_h < next_trigger_h {
                continue;
            }

            // Compute desired new base (keep last retain_window blocks).
            let desired_base = tip_h.saturating_sub(retain_window);
            if desired_base <= base_h {
                // Still not time to advance base.
                next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                continue;
            }

            // Optional safety gate: only prune if we have snapshot coverage (hands-off ops).
            if prune_requires_snapshot {
                let last_ok = last_snapshot_ok_height.load(Ordering::Relaxed);
                if last_ok == 0 || last_ok < desired_base {
                    ng_info_throttle!(
                        key: format!("snapshot_prune_skip_snapshot_gate:{}", node_id),
                        every_ms: 30_000,
                        target: "snapshot.prune",
                        "event=prune_skipped node={} reason=requires_snapshot_coverage tip_height={} desired_base={} last_snapshot_ok_height={}",
                        node_id,
                        tip_h,
                        desired_base,
                        last_ok
                    );
                    next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                    continue;
                }
            }

            let prune_governance_anchor = {
                let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                let tip_for_snapshot = ch.chain.last().map(|b| b.index).unwrap_or(ch.base_height);
                let Some(gov) = ch.governance.as_ref() else {
                    ng_warn_throttle!(
                        key: format!("snapshot_prune_skip_missing_governance:{}", node_id),
                        every_ms: 30_000,
                        target: "snapshot.prune",
                        "event=prune_skipped node={} reason=governance_runtime_missing tip_height={} desired_base={} action=await_runtime_state",
                        node_id,
                        tip_h,
                        desired_base
                    );
                    next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                    continue;
                };
                let snapshot_json = match serde_json::to_string(gov) {
                    Ok(js) => js,
                    Err(e) => {
                        ng_warn_throttle!(
                            key: format!("snapshot_prune_skip_governance_serialize:{}", node_id),
                            every_ms: 30_000,
                            target: "snapshot.prune",
                            "event=prune_skipped node={} reason=governance_snapshot_serialize_failed tip_height={} desired_base={} err={}",
                            node_id,
                            tip_h,
                            desired_base,
                            e
                        );
                        next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                        continue;
                    }
                };
                let bootstrap_json = ch
                    .governance_bootstrap
                    .as_ref()
                    .and_then(|g| serde_json::to_string(g).ok());
                (bootstrap_json, tip_for_snapshot, snapshot_json)
            };

            if let Err(e) = persist_governance_anchor_for_prune(
                storage.as_ref(),
                prune_governance_anchor.0,
                prune_governance_anchor.1,
                prune_governance_anchor.2,
            ) {
                ng_warn_throttle!(
                    key: format!("snapshot_prune_skip_anchor_persist:{}", node_id),
                    every_ms: 30_000,
                    target: "snapshot.prune",
                    "event=prune_skipped node={} reason=governance_anchor_persist_failed tip_height={} desired_base={} err={}",
                    node_id,
                    tip_h,
                    desired_base,
                    e
                );
                next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                continue;
            }

            // Prune DB first (authoritative); it will clamp to current DB state.
            match storage.prune_blocks_below(desired_base, max_blocks_per_run) {
                Ok(rep) => {
                    if rep.pruned_blocks == 0 {
                        next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
                        continue;
                    }

                    // Mirror in-memory window to new base.
                    let pruned_mem = {
                        let mut ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        prune_in_memory_chain_to_base_height(&mut ch, rep.new_base_height)
                    };
                    ng_info!(
                        target: "snapshot.prune",
                        "event=prune_ok node={} old_base_height={} new_base_height={} pruned_blocks={} pruned_tx_index={} memory_pruned_blocks={} tip_height={}",
                        node_id,
                        rep.old_base_height,
                        rep.new_base_height,
                        rep.pruned_blocks,
                        rep.pruned_tx_index,
                        pruned_mem,
                        tip_h
                    );
                }
                Err(e) => {
                    ng_warn_throttle!(
                        key: format!("snapshot_prune_failed:{}:{}", node_id, desired_base),
                        every_ms: 30_000,
                        target: "snapshot.prune",
                        "event=prune_failed node={} desired_base={} tip_height={} err={:?} retry=best_effort",
                        node_id,
                        desired_base,
                        tip_h,
                        e
                    );
                }
            }

            next_trigger_h = ((tip_h / prune_every_n) + 1) * prune_every_n;
        }
    });
}

fn log_snapshot_bootstrap_context_omission(
    node_id: &str,
    bundle_kind: &str,
    target_height: u64,
    window_from: u64,
    omission_reason: SnapshotConsensusBootstrapContextOmissionReason,
) {
    let message = omission_reason.as_str();
    match omission_reason {
        SnapshotConsensusBootstrapContextOmissionReason::HistoricalStateCoverageUnavailable => {
            ng_info!(
                target: "snapshot.export",
                "event=bootstrap_context_omitted node={} bundle={} target_height={} window_from={} reason={}",
                node_id,
                bundle_kind,
                target_height,
                window_from,
                message
            );
        }
        SnapshotConsensusBootstrapContextOmissionReason::ConsensusContextIncomplete => {
            ng_warn!(
                target: "snapshot.export",
                "event=bootstrap_context_omitted node={} bundle={} target_height={} window_from={} reason={}",
                node_id,
                bundle_kind,
                target_height,
                window_from,
                message
            );
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SnapshotExportFailureBackoff {
    key: Option<String>,
    failed_at: Option<SystemTime>,
}

impl SnapshotExportFailureBackoff {
    fn clear(&mut self) {
        self.key = None;
        self.failed_at = None;
    }

    fn record_failure(&mut self, key: String, now: SystemTime) {
        self.key = Some(key);
        self.failed_at = Some(now);
    }

    fn remaining_ms(&self, key: &str, now: SystemTime, backoff_ms: u64) -> Option<u64> {
        let Some(stored_key) = self.key.as_deref() else {
            return None;
        };
        if stored_key != key {
            return None;
        }
        let Some(failed_at) = self.failed_at else {
            return None;
        };
        let elapsed_ms = now
            .duration_since(failed_at)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        if elapsed_ms >= backoff_ms {
            None
        } else {
            Some(backoff_ms.saturating_sub(elapsed_ms))
        }
    }
}

fn snapshot_export_failure_key(bundle: &str, target_height: u64, window_from: u64) -> String {
    format!("{}:{}:{}", bundle, target_height, window_from)
}

fn parse_labeled_u64_v320(msg: &str, label: &str) -> Option<u64> {
    msg.split(|c: char| c == ':' || c == ',' || c.is_whitespace() || c == ')' || c == '"')
        .find_map(|part| part.strip_prefix(label)?.parse::<u64>().ok())
}

fn snapshot_export_error_is_transient_compute_order_target_stale_v320(
    err: &newgen_engine::storage::StorageError,
) -> bool {
    let msg = err.to_string();
    if !msg.contains("compute_order_state_store_event_history_unavailable") {
        return false;
    }

    let Some(target_height) = parse_labeled_u64_v320(&msg, "target_height=") else {
        return false;
    };
    let Some(missing_height) = parse_labeled_u64_v320(&msg, "missing_height=") else {
        return false;
    };
    let Some(store_height) = parse_labeled_u64_v320(&msg, "store_height=") else {
        return false;
    };

    // V320b: defer only the exact stale-target race observed during
    // bootstrap-latest export: target H was selected, then the local
    // compute-order store advanced to H+1 before the compact sidecar bind.
    // The missing height must be 0 because compacted materialized stores
    // intentionally drop the historical event journal; other missing heights
    // remain real export failures and keep the old WARN/backoff path.
    missing_height == 0 && store_height == target_height.saturating_add(1)
}

fn spawn_snapshot_export_loop(
    node_id: String,
    public_mode: bool,
    chain: SharedChain,
    storage: Arc<DbStore>,
    snapshots_dir: PathBuf,
    last_snapshot_ok_height: Arc<AtomicU64>,
    statesync_quarantine: Arc<AtomicBool>,
) {
    // In public mode, snapshot cadence is protocol-defined, so enabled by default.
    // In non-public mode, allow opt-out via env for local testing.
    let enabled = if public_mode {
        true
    } else {
        env_bool("NEWGEN_MAINTENANCE_SNAPSHOT", true)
    };
    if !enabled {
        return;
    }

    let rr_v3_max_frame_bytes = SyncPolicy::load_or_exit().snapshot_rr_v3_max_frame_bytes;
    let poll_ms = env_u64("NEWGEN_SNAPSHOT_POLL_MS", 1500).clamp(200, 30_000);
    let bootstrap_latest_min_height_delta =
        env_u64("NEWGEN_BOOTSTRAP_LATEST_MIN_HEIGHT_DELTA", 4).max(1);
    let bootstrap_latest_min_interval_ms =
        env_u64("NEWGEN_BOOTSTRAP_LATEST_MIN_INTERVAL_MS", 60_000).clamp(1_000, 3_600_000);

    // Persistent pointer to the last successful snapshot (helps prune gating across restarts).
    let auto_dir = snapshot_v2_auto_dir_from_root(&snapshots_dir);
    let _ = std::fs::create_dir_all(&auto_dir);
    let last_meta_path = snapshot_v2_last_meta_path_from_root(&snapshots_dir);
    let last_checkpoint_meta_path = snapshot_v2_last_checkpoint_meta_path_from_root(&snapshots_dir);
    let last_bootstrap_meta_path = snapshot_v2_last_bootstrap_meta_path_from_root(&snapshots_dir);
    if let Ok(b) =
        std::fs::read(&last_checkpoint_meta_path).or_else(|_| std::fs::read(&last_meta_path))
    {
        if let Ok(m) = serde_json::from_slice::<SnapshotMeta>(&b) {
            if m.height > 0 {
                last_snapshot_ok_height.store(m.height, Ordering::Relaxed);
            }
        }
    }
    let bootstrap_latest_dir = snapshot_v2_bootstrap_latest_dir_from_root(&snapshots_dir);
    let bootstrap_latest_meta_path = bootstrap_latest_dir.join("meta.json");
    let bootstrap_latest_height = std::fs::read(&bootstrap_latest_meta_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<SnapshotMeta>(&b).ok())
        .map(|m| m.height);
    let bootstrap_latest_exported_at = snapshot_bundle_meta_modified_at(&bootstrap_latest_dir);
    let checkpoint_latest_dir = snapshot_v2_latest_dir_from_root(&snapshots_dir);
    let checkpoint_latest_height = read_snapshot_v2_meta(&checkpoint_latest_dir).map(|m| m.height);

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(poll_ms));
        // Start from the next multiple.
        let mut next_trigger_h: u64 = 0;
        let mut last_snapshot_every_n: u64 = 0;
        let mut last_bootstrap_snapshot_height: Option<u64> = bootstrap_latest_height;
        let mut last_bootstrap_snapshot_exported_at: Option<SystemTime> =
            bootstrap_latest_exported_at;
        let mut last_checkpoint_snapshot_height: Option<u64> = checkpoint_latest_height;
        let mut last_checkpoint_planner_state: Option<CheckpointLatestPlannerState> = None;
        let mut printed_public_params = false;
        let mut printed_transport_clamp = false;
        let mut last_checkpoint_bootstrap_omission: Option<(
            u64,
            SnapshotConsensusBootstrapContextOmissionReason,
        )> = None;
        let mut last_bootstrap_bootstrap_omission: Option<(
            u64,
            SnapshotConsensusBootstrapContextOmissionReason,
        )> = None;
        let export_failure_backoff_ms =
            env_u64("NEWGEN_SNAPSHOT_EXPORT_FAILURE_BACKOFF_MS", 60_000).clamp(5_000, 3_600_000);
        let mut bootstrap_export_failure_backoff = SnapshotExportFailureBackoff::default();
        let mut checkpoint_export_failure_backoff = SnapshotExportFailureBackoff::default();

        loop {
            tick.tick().await;

            // Avoid snapshot export while a state-sync apply is running.
            if statesync_quarantine.load(Ordering::Relaxed) {
                continue;
            }

            // Tip/state_root snapshot (short lock).
            let (tip_h, tip_state_root, tip_has_block) = {
                let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                let tip_block = ch.chain.last();
                let tip = tip_block.map(|b| b.index).unwrap_or(ch.base_height);
                let tip_root = tip_block.map(|b| b.state_root.clone()).unwrap_or_default();
                (tip, tip_root, tip_block.is_some())
            };

            if !tip_has_block {
                continue;
            }

            // Resolve snapshot cadence (protocol-defined in public mode; env-defined in dev mode).
            let (
                snapshot_every_n,
                retain_window,
                chunk_size_bytes,
                max_snapshot_bytes,
                reachable_only,
            ) = if public_mode {
                if tip_state_root.trim().is_empty() {
                    if tip_h == 0 {
                        continue;
                    }
                    ng_error!(
                        target: "snapshot.export",
                        "event=public_snapshot_params_load_failed node={} reason=missing_tip_state_root",
                        node_id
                    );
                    std::process::exit(2);
                }

                match maintenance_params::load_from_state_root(&storage, tip_state_root.trim()) {
                    Ok(Some(p)) => {
                        let sn = p.snapshot_every_n_blocks.max(1);
                        let rw = p.retain_window_blocks.max(1000);
                        let cs = p.snapshot_chunk_size.max(64 * 1024);
                        let mx = p.snapshot_max_bytes.max(32 * 1024 * 1024);
                        let ro = p.snapshot_reachable_only;

                        if !printed_public_params {
                            ng_info!(
                                target: "snapshot.export",
                                "event=public_snapshot_params_loaded node={} every_n={} retain_window={} chunk_bytes={} max_bytes={} reachable_only={} poll_ms={}",
                                node_id,
                                sn,
                                rw,
                                cs,
                                mx,
                                ro,
                                poll_ms
                            );
                            printed_public_params = true;
                        }

                        (sn, rw, cs, mx, ro)
                    }
                    Ok(None) => {
                        ng_error!(
                            target: "snapshot.export",
                            "event=public_snapshot_params_load_failed node={} reason=missing_protocol_params_in_smt",
                            node_id
                        );
                        std::process::exit(2);
                    }
                    Err(e) => {
                        ng_error!(
                            target: "snapshot.export",
                            "event=public_snapshot_params_load_failed node={} err={}",
                            node_id,
                            e
                        );
                        std::process::exit(2);
                    }
                }
            } else {
                let sn = env_u64("NEWGEN_SNAPSHOT_EVERY_N_BLOCKS", 512).max(1);
                let rw = env_u64("NEWGEN_RETAIN_WINDOW_BLOCKS", 50_000).max(1000);
                let cs = env_u64("NEWGEN_SNAPSHOT_CHUNK_BYTES", 4 * 1024 * 1024)
                    .clamp(64 * 1024, 128 * 1024 * 1024);
                let mx = env_u64("NEWGEN_SNAPSHOT_MAX_BYTES", 512 * 1024 * 1024)
                    .clamp(32 * 1024 * 1024, 8 * 1024 * 1024 * 1024);
                let ro = env_bool("NEWGEN_SNAPSHOT_REACHABLE_ONLY", true);
                (sn, rw, cs, mx, ro)
            };

            let checkpoint_ideal_target_height =
                preferred_checkpoint_snapshot_export_height(tip_h, snapshot_every_n);
            let checkpoint_out_dir = snapshot_v2_latest_dir_from_root(&snapshots_dir);
            let checkpoint_target_selection = match storage.get_governance_snapshot() {
                Ok(Some((gov_h, _))) if gov_h > checkpoint_ideal_target_height => {
                    ng_info_throttle!(
                        key: format!(
                            "snapshot_checkpoint_future_governance_anchor_fast_defer:{}:{}:{}",
                            node_id, checkpoint_ideal_target_height, gov_h
                        ),
                        every_ms: 30_000,
                        target: "snapshot.export",
                        "event=checkpoint_export_deferred node={} bundle=checkpoint-latest ideal_target_height={} governance_anchor_height={} reason=future_governance_anchor action=skip_historical_candidate_scan",
                        node_id,
                        checkpoint_ideal_target_height,
                        gov_h
                    );
                    None
                }
                Ok(_) => select_checkpoint_latest_target(
                    checkpoint_ideal_target_height,
                    snapshot_every_n,
                    last_checkpoint_snapshot_height,
                    |candidate_height| {
                        let Some(candidate_anchor) =
                            storage.get_block(candidate_height).ok().flatten()
                        else {
                            return false;
                        };
                        let candidate_window_from = candidate_height.saturating_sub(retain_window);
                        match storage.get_governance_snapshot() {
                            Ok(Some((gov_h, _)))
                                if !checkpoint_governance_anchor_materializable_v207(
                                    Some(gov_h),
                                    candidate_height,
                                    candidate_window_from,
                                ) =>
                            {
                                ng_info_throttle!(
                                    key: format!("snapshot_checkpoint_future_governance_anchor:{}:{}:{}", node_id, candidate_height, gov_h),
                                    every_ms: 30_000,
                                    target: "snapshot.export",
                                    "event=checkpoint_export_candidate_rejected node={} bundle=checkpoint-latest target_height={} window_from={} governance_anchor_height={} reason=future_governance_anchor action=hold_last_successful_or_wait_for_tip_aligned_checkpoint",
                                    node_id,
                                    candidate_height,
                                    candidate_window_from,
                                    gov_h
                                );
                                return false;
                            }
                            Ok(None)
                                if !checkpoint_governance_anchor_materializable_v207(
                                    None,
                                    candidate_height,
                                    candidate_window_from,
                                ) =>
                            {
                                ng_info_throttle!(
                                    key: format!("snapshot_checkpoint_missing_governance_anchor:{}:{}", node_id, candidate_height),
                                    every_ms: 30_000,
                                    target: "snapshot.export",
                                    "event=checkpoint_export_candidate_rejected node={} bundle=checkpoint-latest target_height={} window_from={} reason=missing_governance_anchor action=hold_last_successful_or_wait",
                                    node_id,
                                    candidate_height,
                                    candidate_window_from
                                );
                                return false;
                            }
                            Err(e) => {
                                ng_warn_throttle!(
                                    key: format!("snapshot_checkpoint_governance_anchor_check_failed:{}:{}", node_id, candidate_height),
                                    every_ms: 30_000,
                                    target: "snapshot.export",
                                    "event=checkpoint_export_candidate_rejected node={} bundle=checkpoint-latest target_height={} window_from={} reason=governance_anchor_check_failed err={:?} action=fail_closed",
                                    node_id,
                                    candidate_height,
                                    candidate_window_from,
                                    e
                                );
                                return false;
                            }
                            _ => {}
                        }
                        let candidate_state_root = candidate_anchor.state_root.trim();
                        let candidate_root_present = match storage
                            .has_state_root_node(candidate_state_root)
                        {
                            Ok(present) => present,
                            Err(e) => {
                                ng_warn_throttle!(
                                    key: format!("snapshot_checkpoint_preflight_failed:{}:{}", node_id, candidate_height),
                                    every_ms: 30_000,
                                    target: "snapshot.export",
                                    "event=checkpoint_export_preflight_failed node={} bundle=checkpoint-latest target_height={} state_root={} err={:?}",
                                    node_id,
                                    candidate_height,
                                    candidate_state_root,
                                    e
                                );
                                true
                            }
                        };
                        !should_skip_checkpoint_export_due_to_historical_root_unavailable(
                            reachable_only,
                            candidate_height,
                            tip_h,
                            candidate_root_present,
                        )
                    },
                ),
                Err(e) => {
                    ng_warn_throttle!(
                        key: format!("snapshot_checkpoint_governance_anchor_fast_check_failed:{}", node_id),
                        every_ms: 30_000,
                        target: "snapshot.export",
                        "event=checkpoint_export_deferred node={} bundle=checkpoint-latest ideal_target_height={} reason=governance_anchor_check_failed err={:?} action=fail_closed",
                        node_id,
                        checkpoint_ideal_target_height,
                        e
                    );
                    None
                }
            };
            let checkpoint_planner_state = match checkpoint_target_selection {
                Some(selection) => CheckpointLatestPlannerState {
                    ideal_target_height: checkpoint_ideal_target_height,
                    effective_target_height: Some(selection.target_height),
                    disposition: Some(selection.disposition),
                },
                None => CheckpointLatestPlannerState {
                    ideal_target_height: checkpoint_ideal_target_height,
                    effective_target_height: None,
                    disposition: None,
                },
            };
            if Some(checkpoint_planner_state) != last_checkpoint_planner_state {
                match checkpoint_target_selection {
                    Some(CheckpointLatestTargetSelection {
                        target_height,
                        disposition: CheckpointLatestTargetDisposition::FallbackAlignedHeight,
                    }) => {
                        ng_info!(
                            target: "snapshot.latest",
                            "event=checkpoint_export_target_fallback node={} bundle=checkpoint-latest ideal_target_height={} effective_target_height={} reachable_only={} action=export_most_recent_materializable_checkpoint",
                            node_id,
                            checkpoint_ideal_target_height,
                            target_height,
                            reachable_only
                        );
                    }
                    Some(CheckpointLatestTargetSelection {
                        target_height,
                        disposition: CheckpointLatestTargetDisposition::HoldLastSuccessful,
                    }) => {
                        ng_info!(
                            target: "snapshot.latest",
                            "event=checkpoint_export_deferred node={} bundle=checkpoint-latest ideal_target_height={} held_target_height={} reachable_only={} action=keep_last_successful_until_materializable",
                            node_id,
                            checkpoint_ideal_target_height,
                            target_height,
                            reachable_only
                        );
                    }
                    None => {
                        ng_info!(
                            target: "snapshot.latest",
                            "event=checkpoint_export_deferred node={} bundle=checkpoint-latest ideal_target_height={} reachable_only={} action=wait_for_materializable_checkpoint",
                            node_id,
                            checkpoint_ideal_target_height,
                            reachable_only
                        );
                    }
                    _ => {}
                }
                last_checkpoint_planner_state = Some(checkpoint_planner_state);
            }
            let checkpoint_target_height =
                checkpoint_target_selection.map(|selection| selection.target_height);
            let checkpoint_window_from =
                checkpoint_target_height.map(|height| height.saturating_sub(retain_window));
            let checkpoint_anchor = checkpoint_target_height
                .and_then(|height| storage.get_block(height).ok().flatten());
            let checkpoint_block_hash = checkpoint_anchor.as_ref().map(|b| b.hash.as_str());
            let checkpoint_created_at_ts = checkpoint_anchor.as_ref().map(|b| b.timestamp);
            let checkpoint_refresh_reason = checkpoint_target_height.and_then(|height| {
                snapshot_latest_bundle_refresh_reason(
                    &checkpoint_out_dir,
                    rr_v3_max_frame_bytes,
                    Some(height),
                    checkpoint_window_from,
                    checkpoint_block_hash,
                    checkpoint_created_at_ts,
                )
            });
            if let Some(reason) = checkpoint_refresh_reason.as_ref() {
                if snapshot_latest_refresh_reason_is_warning_v316(*reason) {
                    ng_warn_throttle!(
                        key: format!("snapshot_checkpoint_refresh_required:{}:{}", node_id, reason.as_str()),
                        every_ms: 30_000,
                        target: "snapshot.latest",
                        "event=latest_refresh_required node={} bundle=checkpoint-latest reason={} action=force_export target_height={:?} ideal_target_height={}",
                        node_id,
                        reason.as_str(),
                        checkpoint_target_height,
                        checkpoint_ideal_target_height
                    );
                } else {
                    ng_info_throttle!(
                        key: format!("snapshot_checkpoint_refresh_required:{}:{}", node_id, reason.as_str()),
                        every_ms: 30_000,
                        target: "snapshot.latest",
                        "event=latest_refresh_required node={} bundle=checkpoint-latest reason={} action=force_export target_height={:?} ideal_target_height={}",
                        node_id,
                        reason.as_str(),
                        checkpoint_target_height,
                        checkpoint_ideal_target_height
                    );
                }
            }
            let should_export_checkpoint = checkpoint_target_height.is_some()
                && (tip_h >= next_trigger_h || checkpoint_refresh_reason.is_some());

            let bootstrap_target_height = preferred_bootstrap_snapshot_export_height(tip_h);
            let bootstrap_window_from = bootstrap_target_height.saturating_sub(retain_window);
            let bootstrap_anchor = storage.get_block(bootstrap_target_height).ok().flatten();
            let bootstrap_block_hash = bootstrap_anchor.as_ref().map(|b| b.hash.as_str());
            let bootstrap_created_at_ts = bootstrap_anchor.as_ref().map(|b| b.timestamp);
            let bootstrap_out_dir = snapshot_v2_bootstrap_latest_dir_from_root(&snapshots_dir);
            let bootstrap_refresh_reason = snapshot_latest_bundle_refresh_reason(
                &bootstrap_out_dir,
                rr_v3_max_frame_bytes,
                Some(bootstrap_target_height),
                Some(bootstrap_window_from),
                bootstrap_block_hash,
                bootstrap_created_at_ts,
            );
            let now = SystemTime::now();
            let should_export_bootstrap = should_export_bootstrap_latest(
                bootstrap_refresh_reason,
                bootstrap_target_height,
                last_bootstrap_snapshot_height,
                last_bootstrap_snapshot_exported_at,
                bootstrap_latest_min_height_delta,
                bootstrap_latest_min_interval_ms,
                now,
            );
            if let Some(reason) = bootstrap_refresh_reason {
                if should_export_bootstrap {
                    if snapshot_latest_refresh_reason_is_warning_v316(reason) {
                        ng_warn_throttle!(
                            key: format!("snapshot_bootstrap_refresh_required:{}:{}", node_id, reason.as_str()),
                            every_ms: 30_000,
                            target: "snapshot.latest",
                            "event=latest_refresh_required node={} bundle=bootstrap-latest reason={} action=force_export",
                            node_id,
                            reason.as_str()
                        );
                    } else {
                        ng_info_throttle!(
                            key: format!("snapshot_bootstrap_refresh_required:{}:{}", node_id, reason.as_str()),
                            every_ms: 30_000,
                            target: "snapshot.latest",
                            "event=latest_refresh_required node={} bundle=bootstrap-latest reason={} action=force_export",
                            node_id,
                            reason.as_str()
                        );
                    }
                } else {
                    let height_delta = last_bootstrap_snapshot_height
                        .map(|height| bootstrap_target_height.saturating_sub(height))
                        .unwrap_or(bootstrap_target_height);
                    let since_last_export_ms = last_bootstrap_snapshot_exported_at
                        .and_then(|ts| now.duration_since(ts).ok())
                        .map(|elapsed| elapsed.as_millis() as u64);
                    ng_info_throttle!(
                        key: format!("snapshot_bootstrap_refresh_deferred:{}:{}", node_id, reason.as_str()),
                        every_ms: 30_000,
                        target: "snapshot.latest",
                        "event=latest_refresh_deferred node={} bundle=bootstrap-latest reason={} action=wait_for_rate_limit target_height={} last_export_height={:?} height_delta={} min_height_delta={} since_last_export_ms={:?} min_interval_ms={}",
                        node_id,
                        reason.as_str(),
                        bootstrap_target_height,
                        last_bootstrap_snapshot_height,
                        height_delta,
                        bootstrap_latest_min_height_delta,
                        since_last_export_ms,
                        bootstrap_latest_min_interval_ms
                    );
                }
            }

            let requested_chunk_sz = (chunk_size_bytes.min(usize::MAX as u64)) as usize;
            let chunk_sz =
                clamp_snapshot_chunk_bytes_for_rrv3(requested_chunk_sz, rr_v3_max_frame_bytes);
            if !printed_transport_clamp && chunk_sz != requested_chunk_sz {
                ng_info!(
                    target: "snapshot.export",
                    "event=transport_chunk_clamp node={} requested_chunk_bytes={} effective_chunk_bytes={} snapshot_rr_v3_max_frame_bytes={}",
                    node_id,
                    requested_chunk_sz,
                    chunk_sz,
                    rr_v3_max_frame_bytes
                );
                printed_transport_clamp = true;
            }

            // Initialize trigger on first tick with a tip, or if cadence changes.
            if next_trigger_h == 0 || snapshot_every_n != last_snapshot_every_n {
                next_trigger_h = ((tip_h / snapshot_every_n) + 1) * snapshot_every_n;
                last_snapshot_every_n = snapshot_every_n;
            }

            if !should_export_checkpoint && !should_export_bootstrap {
                continue;
            }

            let max_b = (max_snapshot_bytes.min(usize::MAX as u64)) as usize;

            if should_export_bootstrap {
                let bootstrap_export_key = snapshot_export_failure_key(
                    "bootstrap-latest",
                    bootstrap_target_height,
                    bootstrap_window_from,
                );
                if let Some(remaining_ms) = bootstrap_export_failure_backoff.remaining_ms(
                    &bootstrap_export_key,
                    now,
                    export_failure_backoff_ms,
                ) {
                    ng_info_throttle!(
                        key: format!("snapshot_bootstrap_export_retry_backoff:{}:{}", node_id, bootstrap_export_key),
                        every_ms: 30_000,
                        target: "snapshot.export",
                        "event=snapshot_export_retry_backoff node={} bundle=bootstrap-latest target_height={} window_from={} remaining_ms={} action=skip_retry",
                        node_id,
                        bootstrap_target_height,
                        bootstrap_window_from,
                        remaining_ms
                    );
                } else {
                    ng_info!(
                        target: "snapshot.export",
                        "event=snapshot_export_start node={} bundle=bootstrap-latest tip={} target_height={} window_from={} include_state_nodes=true reachable_only={} chunk_bytes={} max_bytes={}",
                        node_id,
                        tip_h,
                        bootstrap_target_height,
                        bootstrap_window_from,
                        reachable_only,
                        chunk_sz,
                        max_b
                    );
                    let bootstrap_export_started_v205 = std::time::Instant::now();
                    match storage.export_snapshot_v2_bundle(
                        &bootstrap_out_dir,
                        Some(bootstrap_target_height),
                        Some(bootstrap_window_from),
                        true,
                        reachable_only,
                        chunk_sz,
                        max_b,
                    ) {
                        Ok(meta) => {
                            bootstrap_export_failure_backoff.clear();
                            last_bootstrap_snapshot_height = Some(meta.height);
                            last_bootstrap_snapshot_exported_at =
                                snapshot_bundle_meta_modified_at(&bootstrap_out_dir)
                                    .or(Some(SystemTime::now()));
                            if let Ok(bytes) = serde_json::to_vec_pretty(&meta) {
                                let tmp = last_bootstrap_meta_path.with_extension("json.tmp");
                                if std::fs::write(&tmp, bytes).is_ok() {
                                    let _ = newgen_engine::utils::atomic_replace_file_v1(
                                        &tmp,
                                        &last_bootstrap_meta_path,
                                    );
                                }
                            }
                            ng_info!(
                                target: "snapshot.latest",
                                "event=snapshot_export_ok node={} bundle=bootstrap-latest height={} window_from={} chunks={} reachable_only={} duration_ms={} bytes={}",
                                node_id,
                                meta.height,
                                meta.window_from_height,
                                meta.chunk_hashes_hex.len(),
                                reachable_only,
                                bootstrap_export_started_v205.elapsed().as_millis(),
                                meta.bytes_len
                            );
                            match meta.consensus_bootstrap_context_omission_reason {
                                Some(reason)
                                    if last_bootstrap_bootstrap_omission
                                        != Some((meta.height, reason)) =>
                                {
                                    log_snapshot_bootstrap_context_omission(
                                        &node_id,
                                        "bootstrap-latest",
                                        meta.height,
                                        meta.window_from_height,
                                        reason,
                                    );
                                    last_bootstrap_bootstrap_omission = Some((meta.height, reason));
                                }
                                Some(_) => {}
                                None => last_bootstrap_bootstrap_omission = None,
                            }
                        }
                        Err(e)
                            if snapshot_export_error_is_transient_compute_order_target_stale_v320(
                                &e,
                            ) =>
                        {
                            ng_info_throttle!(
                                key: format!("snapshot_bootstrap_export_stale_target_v320:{}:{}:{}", node_id, bootstrap_target_height, bootstrap_window_from),
                                every_ms: 30_000,
                                target: "snapshot.export",
                                "event=snapshot_export_deferred_v320 node={} bundle=bootstrap-latest reason=compute_order_store_ahead_of_selected_target action=retry_at_current_tip tip={} target_height={} window_from={} duration_ms={} err={}",
                                node_id,
                                tip_h,
                                bootstrap_target_height,
                                bootstrap_window_from,
                                bootstrap_export_started_v205.elapsed().as_millis(),
                                e
                            );
                        }
                        Err(e) => {
                            bootstrap_export_failure_backoff
                                .record_failure(bootstrap_export_key.clone(), now);
                            ng_warn_throttle!(
                                key: format!("snapshot_bootstrap_export_failed:{}:{}:{}", node_id, bootstrap_target_height, bootstrap_window_from),
                                every_ms: 30_000,
                                target: "snapshot.export",
                                "event=snapshot_export_failed node={} bundle=bootstrap-latest tip={} target_height={} window_from={} duration_ms={} err={:?}",
                                node_id,
                                tip_h,
                                bootstrap_target_height,
                                bootstrap_window_from,
                                bootstrap_export_started_v205.elapsed().as_millis(),
                                e
                            );
                        }
                    }
                }
            }

            if should_export_checkpoint {
                let checkpoint_target_height = checkpoint_target_height
                    .expect("checkpoint target must exist when export is requested");
                let checkpoint_window_from = checkpoint_window_from
                    .expect("checkpoint window_from must exist when export is requested");
                let checkpoint_export_key = snapshot_export_failure_key(
                    "checkpoint-latest",
                    checkpoint_target_height,
                    checkpoint_window_from,
                );
                if let Some(remaining_ms) = checkpoint_export_failure_backoff.remaining_ms(
                    &checkpoint_export_key,
                    now,
                    export_failure_backoff_ms,
                ) {
                    ng_info_throttle!(
                        key: format!("snapshot_checkpoint_export_retry_backoff:{}:{}", node_id, checkpoint_export_key),
                        every_ms: 30_000,
                        target: "snapshot.export",
                        "event=snapshot_export_retry_backoff node={} bundle=checkpoint-latest target_height={} window_from={} remaining_ms={} action=skip_retry",
                        node_id,
                        checkpoint_target_height,
                        checkpoint_window_from,
                        remaining_ms
                    );
                } else {
                    ng_info!(
                        target: "snapshot.export",
                        "event=snapshot_export_start node={} bundle=checkpoint-latest tip={} target_height={} window_from={} include_state_nodes=true reachable_only={} chunk_bytes={} max_bytes={}",
                        node_id,
                        tip_h,
                        checkpoint_target_height,
                        checkpoint_window_from,
                        reachable_only,
                        chunk_sz,
                        max_b
                    );
                    let checkpoint_export_started_v205 = std::time::Instant::now();
                    match storage.export_snapshot_v2_bundle(
                        &checkpoint_out_dir,
                        Some(checkpoint_target_height),
                        Some(checkpoint_window_from),
                        true,
                        reachable_only,
                        chunk_sz,
                        max_b,
                    ) {
                        Ok(meta) => {
                            checkpoint_export_failure_backoff.clear();
                            // Update checkpoint pointers outside the cadenced checkpoint bundle directory.
                            if let Ok(bytes) = serde_json::to_vec_pretty(&meta) {
                                let tmp = last_checkpoint_meta_path.with_extension("json.tmp");
                                if std::fs::write(&tmp, &bytes).is_ok() {
                                    let _ = newgen_engine::utils::atomic_replace_file_v1(
                                        &tmp,
                                        &last_checkpoint_meta_path,
                                    );
                                }
                                let legacy_tmp = last_meta_path.with_extension("json.tmp");
                                if std::fs::write(&legacy_tmp, bytes).is_ok() {
                                    let _ = newgen_engine::utils::atomic_replace_file_v1(
                                        &legacy_tmp,
                                        &last_meta_path,
                                    );
                                }
                            }

                            last_snapshot_ok_height.store(meta.height, Ordering::Relaxed);
                            last_checkpoint_snapshot_height = Some(meta.height);
                            ng_info!(
                                target: "snapshot.latest",
                                "event=snapshot_export_ok node={} bundle=checkpoint-latest height={} window_from={} chunks={} reachable_only={} duration_ms={} bytes={}",
                                node_id,
                                meta.height,
                                meta.window_from_height,
                                meta.chunk_hashes_hex.len(),
                                reachable_only,
                                checkpoint_export_started_v205.elapsed().as_millis(),
                                meta.bytes_len
                            );
                            match meta.consensus_bootstrap_context_omission_reason {
                                Some(reason)
                                    if last_checkpoint_bootstrap_omission
                                        != Some((meta.height, reason)) =>
                                {
                                    log_snapshot_bootstrap_context_omission(
                                        &node_id,
                                        "checkpoint-latest",
                                        meta.height,
                                        meta.window_from_height,
                                        reason,
                                    );
                                    last_checkpoint_bootstrap_omission =
                                        Some((meta.height, reason));
                                }
                                Some(_) => {}
                                None => last_checkpoint_bootstrap_omission = None,
                            }
                        }
                        Err(e) => {
                            checkpoint_export_failure_backoff
                                .record_failure(checkpoint_export_key.clone(), now);
                            ng_warn_throttle!(
                                key: format!("snapshot_checkpoint_export_failed:{}:{}:{}", node_id, checkpoint_target_height, checkpoint_window_from),
                                every_ms: 30_000,
                                target: "snapshot.export",
                                "event=snapshot_export_failed node={} bundle=checkpoint-latest tip={} target_height={} window_from={} duration_ms={} err={:?}",
                                node_id,
                                tip_h,
                                checkpoint_target_height,
                                checkpoint_window_from,
                                checkpoint_export_started_v205.elapsed().as_millis(),
                                e
                            );
                        }
                    }
                }
            }

            // Advance trigger.
            next_trigger_h = ((tip_h / snapshot_every_n) + 1) * snapshot_every_n;
        }
    });
}

// ----------------------------------------------------------
// Storage maintenance commands (mainnet-grade, backend-neutral runtime path)
// Usage examples:
//   newgen_engine verify-db --full [--path <db>]
//   newgen_engine repair-db [--verify-after|--no-verify-after] [--path <db>]
//   newgen_engine export-snapshot <file> [--with-state|--no-state] [--path <db>]
//   newgen_engine import-snapshot <file> [--wipe-state|--keep-state] [--path <db>]
//   newgen_engine migrate-db [--path <db>]    # runtime schema check only; clean active-backend bootstrap, legacy physical migration stays offline
// ----------------------------------------------------------

#[cfg(test)]
mod snapshot_export_loop_tests {
    use super::{
        bootstrap_refresh_reason_requires_immediate_export,
        checkpoint_export_candidate_heights_desc, checkpoint_governance_anchor_materializable_v207,
        select_checkpoint_latest_target, should_export_bootstrap_latest,
        should_skip_checkpoint_export_due_to_historical_root_unavailable,
        snapshot_export_failure_key, CheckpointLatestTargetDisposition,
        CheckpointLatestTargetSelection, SnapshotExportFailureBackoff,
    };
    use newgen_engine::snapshot::SnapshotLatestBundleRefreshReason as RefreshReason;
    use std::time::{Duration, SystemTime};

    #[test]
    fn skips_historical_checkpoint_export_when_reachable_only_root_missing() {
        assert!(
            should_skip_checkpoint_export_due_to_historical_root_unavailable(
                true, 2048, 2253, false
            )
        );
    }

    #[test]
    fn does_not_skip_when_checkpoint_is_tip_or_root_is_present() {
        assert!(
            !should_skip_checkpoint_export_due_to_historical_root_unavailable(
                true, 2253, 2253, false
            )
        );
        assert!(
            !should_skip_checkpoint_export_due_to_historical_root_unavailable(
                true, 2048, 2253, true
            )
        );
        assert!(
            !should_skip_checkpoint_export_due_to_historical_root_unavailable(
                false, 2048, 2253, false
            )
        );
    }

    #[test]
    fn checkpoint_candidate_heights_include_fallbacks_and_last_successful() {
        assert_eq!(
            checkpoint_export_candidate_heights_desc(2048, 512, Some(1536)),
            vec![2048, 1536, 1024, 512, 0]
        );
        assert_eq!(
            checkpoint_export_candidate_heights_desc(2048, 512, Some(1792)),
            vec![2048, 1792, 1536, 1024, 512, 0]
        );
    }

    #[test]
    fn checkpoint_target_falls_back_to_most_recent_materializable_height() {
        let selection = select_checkpoint_latest_target(2048, 512, Some(1024), |height| {
            matches!(height, 1536 | 1024)
        });
        assert_eq!(
            selection,
            Some(CheckpointLatestTargetSelection {
                target_height: 1536,
                disposition: CheckpointLatestTargetDisposition::FallbackAlignedHeight,
            })
        );
    }

    #[test]
    fn checkpoint_target_keeps_last_successful_until_newer_height_materializes() {
        let selection =
            select_checkpoint_latest_target(2048, 512, Some(1024), |height| height == 1024);
        assert_eq!(
            selection,
            Some(CheckpointLatestTargetSelection {
                target_height: 1024,
                disposition: CheckpointLatestTargetDisposition::HoldLastSuccessful,
            })
        );
    }

    #[test]
    fn checkpoint_governance_anchor_materialization_v207_rejects_future_or_missing_pruned_anchor() {
        assert!(checkpoint_governance_anchor_materializable_v207(
            Some(50179),
            50179,
            179
        ));
        assert!(!checkpoint_governance_anchor_materializable_v207(
            Some(50179),
            50176,
            176
        ));
        assert!(checkpoint_governance_anchor_materializable_v207(None, 0, 0));
        assert!(!checkpoint_governance_anchor_materializable_v207(
            None, 50176, 176
        ));
    }

    #[test]
    fn checkpoint_target_returns_none_when_no_candidate_is_materializable() {
        assert_eq!(
            select_checkpoint_latest_target(2048, 512, Some(1024), |_| false),
            None
        );
    }

    #[test]
    fn bootstrap_refresh_structural_reasons_bypass_rate_limit() {
        assert!(bootstrap_refresh_reason_requires_immediate_export(
            RefreshReason::MissingMeta
        ));
        assert!(bootstrap_refresh_reason_requires_immediate_export(
            RefreshReason::CorruptChunkFiles
        ));
        assert!(bootstrap_refresh_reason_requires_immediate_export(
            RefreshReason::StaleCheckpointBlock
        ));
        assert!(!bootstrap_refresh_reason_requires_immediate_export(
            RefreshReason::StaleHeight
        ));
    }

    #[test]
    fn bootstrap_stale_height_is_deferred_until_rate_limit_or_height_delta() {
        let now = SystemTime::now();
        assert!(!should_export_bootstrap_latest(
            Some(RefreshReason::StaleHeight),
            100,
            Some(99),
            Some(now),
            4,
            60_000,
            now,
        ));
        assert!(should_export_bootstrap_latest(
            Some(RefreshReason::StaleHeight),
            103,
            Some(99),
            Some(now),
            4,
            60_000,
            now,
        ));
        assert!(should_export_bootstrap_latest(
            Some(RefreshReason::StaleHeight),
            100,
            Some(99),
            Some(now - Duration::from_secs(61)),
            4,
            60_000,
            now,
        ));
    }

    #[test]
    fn bootstrap_missing_last_export_history_refreshes_safely() {
        let now = SystemTime::now();
        assert!(should_export_bootstrap_latest(
            Some(RefreshReason::StaleHeight),
            42,
            None,
            None,
            4,
            60_000,
            now,
        ));
    }

    #[test]
    fn snapshot_export_failure_backoff_is_target_scoped_v187() {
        let now = SystemTime::now();
        let key_a = snapshot_export_failure_key("checkpoint-latest", 39_424, 0);
        let key_b = snapshot_export_failure_key("checkpoint-latest", 39_936, 0);
        let mut backoff = SnapshotExportFailureBackoff::default();

        assert_eq!(backoff.remaining_ms(&key_a, now, 60_000), None);
        backoff.record_failure(key_a.clone(), now);
        assert!(backoff.remaining_ms(&key_a, now, 60_000).is_some());
        assert_eq!(backoff.remaining_ms(&key_b, now, 60_000), None);
        assert_eq!(
            backoff.remaining_ms(&key_a, now + Duration::from_secs(61), 60_000),
            None
        );

        backoff.clear();
        assert_eq!(backoff.remaining_ms(&key_a, now, 60_000), None);
    }
}

#[cfg(test)]
mod v188_runtime_inbound_tx_tests {
    use super::runtime_inbound_newtx_should_drop_before_locks_v1;
    use newgen_engine::transaction::Transaction;

    fn tx(is_coinbase: bool) -> Transaction {
        Transaction::new(
            if is_coinbase { "COINBASE" } else { "user" }.to_string(),
            "receiver".to_string(),
            1,
            1,
            1,
            String::new(),
            is_coinbase,
            None,
        )
    }

    #[test]
    fn runtime_inbound_coinbase_newtx_drop_is_prelock_v188() {
        assert!(runtime_inbound_newtx_should_drop_before_locks_v1(&tx(true)));
        assert!(!runtime_inbound_newtx_should_drop_before_locks_v1(&tx(
            false
        )));
    }
}

fn print_storage_cmd_help() {
    eprintln!("Storage commands:");
    eprintln!("  verify-db [--full] [--path <db>]");
    eprintln!("  repair-db [--verify-after|--no-verify-after] [--path <db>]");
    eprintln!("  export-snapshot <file> [--with-state|--no-state] [--path <db>]  # legacy v1; disabled in public mode");
    eprintln!("  export-snapshot-v2 <dir> [--height <h>] [--from-height <h>] [--chunk-size <bytes>] [--max-bytes <bytes>] [--reachable-only|--all-state-nodes] [--with-state|--no-state] [--path <db>]");
    eprintln!("  import-snapshot <file> [--wipe-state|--keep-state] [--path <db>]  # legacy v1; disabled in public mode");
    eprintln!("  import-snapshot-v2 <dir> [--wipe-state|--keep-state] [--path <db>]");
    eprintln!("  gc-state-nodes --state-root <hex>|--from-snapshot-v2 <dir> [--batch <n>] [--max-nodes <n>] [--path <db>]");
    eprintln!(
        "  migrate-db [--path <db>]  # runtime schema check (clean active-backend bootstrap; legacy physical migration stays offline)"
    );
}

fn print_verify_report(rep: &newgen_engine::storage::VerifyReport) {
    eprintln!("ok            : {}", rep.ok);
    eprintln!("height        : {:?}", rep.height);
    eprintln!("needs_recovery: {}", rep.needs_recovery);
    eprintln!("issues        : {}", rep.issues.len());
    for (i, s) in rep.issues.iter().enumerate() {
        eprintln!("  {:>2}. {}", i + 1, s);
    }
}

fn handle_storage_subcommand() -> Result<bool, Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        return Ok(false);
    }

    let cmd = argv[1].as_str();
    let is_storage_cmd = matches!(
        cmd,
        "verify-db"
            | "repair-db"
            | "export-snapshot"
            | "import-snapshot"
            | "export-snapshot-v2"
            | "import-snapshot-v2"
            | "gc-state-nodes"
            | "migrate-db"
    );
    if !is_storage_cmd {
        return Ok(false);
    }
    if matches!(cmd, "export-snapshot" | "import-snapshot")
        && newgen_engine::runtime_mode::public_mode_enabled()
    {
        return Err(
            "legacy snapshot v1 import/export is disabled in public mode; use export-snapshot-v2/import-snapshot-v2".into(),
        );
    }

    // defaults
    let mut db_path: String = DB_PATH.to_string();
    let mut full = false;
    let mut include_state = true;
    let mut wipe_state = true;
    let mut verify_after = true;

    // snapshot v2 knobs
    let mut snap_v2_height: Option<u64> = None;
    let mut snap_v2_from_height: Option<u64> = None;
    let mut snap_v2_chunk_size: usize = 1_048_576;
    let mut snap_v2_max_bytes: usize = 2_000_000_000; // 2GB default safety cap
    let mut snap_v2_reachable_only: bool = true;

    // gc-state-nodes knobs
    let mut gc_state_root: Option<String> = None;
    let mut gc_from_snapshot_v2: Option<String> = None;
    let mut gc_batch: usize = 10_000;
    let mut gc_max_nodes: u64 = std::env::var("NEWGEN_GC_MAX_NODES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(10_000_000);

    let mut positional: Vec<String> = Vec::new();
    let mut i = 2usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "--path" | "--db" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --path");
                    std::process::exit(2);
                }
                db_path = argv[i].clone();
            }
            "--full" => full = true,
            "--quick" => full = false,
            "--with-state" => include_state = true,
            "--no-state" => include_state = false,
            "--wipe-state" => wipe_state = true,
            "--keep-state" => wipe_state = false,
            "--height" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --height");
                    std::process::exit(2);
                }
                snap_v2_height = argv[i].parse::<u64>().ok();
            }
            "--from-height" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --from-height");
                    std::process::exit(2);
                }
                snap_v2_from_height = argv[i].parse::<u64>().ok();
            }
            "--chunk-size" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --chunk-size");
                    std::process::exit(2);
                }
                snap_v2_chunk_size = argv[i].parse::<usize>().unwrap_or(snap_v2_chunk_size);
            }
            "--max-bytes" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --max-bytes");
                    std::process::exit(2);
                }
                snap_v2_max_bytes = argv[i].parse::<usize>().unwrap_or(snap_v2_max_bytes);
            }
            "--reachable-only" => snap_v2_reachable_only = true,
            "--all-state-nodes" => snap_v2_reachable_only = false,
            "--verify-after" => verify_after = true,
            "--no-verify-after" => verify_after = false,
            "--state-root" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --state-root");
                    std::process::exit(2);
                }
                gc_state_root = Some(argv[i].clone());
            }
            "--from-snapshot-v2" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --from-snapshot-v2");
                    std::process::exit(2);
                }
                gc_from_snapshot_v2 = Some(argv[i].clone());
            }
            "--batch" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --batch");
                    std::process::exit(2);
                }
                gc_batch = argv[i].parse::<usize>().unwrap_or(gc_batch);
            }
            "--max-nodes" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --max-nodes");
                    std::process::exit(2);
                }
                gc_max_nodes = argv[i].parse::<u64>().unwrap_or(gc_max_nodes);
            }
            "--help" | "-h" => {
                print_storage_cmd_help();
                std::process::exit(0);
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    match cmd {
        "migrate-db" => {
            let _storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            newgen_engine::storage::ensure_runtime_storage_schema_current()
                .map_err(|e| format!("runtime schema check failed: {}", e))?;
            eprintln!(
                "OK: runtime storage schema is current (path={}). {}",
                db_path,
                newgen_engine::storage::runtime_storage_bootstrap_strategy_note()
            );
            std::process::exit(0);
        }

        "gc-state-nodes" => {
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;

            let root = if let Some(r) = gc_state_root.clone() {
                r
            } else if let Some(d) = gc_from_snapshot_v2.clone() {
                let meta = read_snapshot_v2_meta(Path::new(&d))
                    .ok_or_else(|| format!("cannot read snapshot v2 meta.json from dir: {}", d))?;
                meta.state_root
            } else {
                eprintln!("gc-state-nodes requires --state-root <hex> or --from-snapshot-v2 <dir>");
                std::process::exit(2);
            };

            let rep = storage
                .gc_state_nodes_to_root(&root, gc_max_nodes, gc_batch)
                .map_err(|e| format!("gc-state-nodes failed: {:?}", e))?;

            eprintln!("GC state_nodes completed:");
            eprintln!("  reachable : {}", rep.reachable);
            eprintln!("  scanned   : {}", rep.scanned);
            eprintln!("  kept      : {}", rep.kept);
            eprintln!("  removed   : {}", rep.removed);
            eprintln!("  duration  : {} ms", rep.duration_ms);
            std::process::exit(0);
        }
        "verify-db" => {
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            let rep = storage
                .verify_db(full)
                .map_err(|e| format!("verify-db failed: {:?}", e))?;
            print_verify_report(&rep);
            if rep.ok && !rep.needs_recovery {
                std::process::exit(0);
            } else {
                std::process::exit(2);
            }
        }
        "repair-db" => {
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            let rep = storage
                .repair_db(verify_after)
                .map_err(|e| format!("repair-db failed: {:?}", e))?;
            print_verify_report(&rep);
            if rep.ok {
                std::process::exit(0);
            } else {
                std::process::exit(2);
            }
        }
        "export-snapshot-v2" => {
            if positional.len() != 1 {
                eprintln!("export-snapshot-v2 requires <dir>");
                print_storage_cmd_help();
                std::process::exit(2);
            }
            let out_dir = &positional[0];
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            let rr_v3_max_frame_bytes = SyncPolicy::load_or_exit().snapshot_rr_v3_max_frame_bytes;
            let effective_chunk_size =
                clamp_snapshot_chunk_bytes_for_rrv3(snap_v2_chunk_size, rr_v3_max_frame_bytes);
            if effective_chunk_size != snap_v2_chunk_size {
                eprintln!(
                    "ℹ️ export-snapshot-v2: requested chunk_size={} clamped to transport-safe {} (snapshot_rr_v3_max_frame_bytes={})",
                    snap_v2_chunk_size, effective_chunk_size, rr_v3_max_frame_bytes
                );
            }
            let meta = storage
                .export_snapshot_v2_bundle(
                    out_dir,
                    snap_v2_height,
                    snap_v2_from_height,
                    include_state,
                    snap_v2_reachable_only,
                    effective_chunk_size,
                    snap_v2_max_bytes,
                )
                .map_err(|e| format!("export-snapshot-v2 failed: {:?}", e))?;
            eprintln!(
        "OK: export-snapshot-v2 completed (path={}, dir={}, height={}, from={}, chunks={}, bytes_len={})",
        db_path,
        out_dir,
        meta.height,
        meta.window_from_height,
        meta.chunks,
        meta.bytes_len
    );
            std::process::exit(0);
        }
        "import-snapshot-v2" => {
            if positional.len() != 1 {
                eprintln!("import-snapshot-v2 requires <dir>");
                print_storage_cmd_help();
                std::process::exit(2);
            }
            let inp_dir = &positional[0];
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            storage
                .import_snapshot_v2_bundle(inp_dir, wipe_state)
                .map_err(|e| format!("import-snapshot-v2 failed: {:?}", e))?;
            eprintln!(
                "OK: import-snapshot-v2 completed (path={}, dir={}, wipe_state_nodes={})",
                db_path, inp_dir, wipe_state
            );
            std::process::exit(0);
        }
        "export-snapshot" => {
            if positional.len() != 1 {
                eprintln!("export-snapshot requires <file>");
                print_storage_cmd_help();
                std::process::exit(2);
            }
            let out = &positional[0];
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            storage
                .export_snapshot(out, include_state)
                .map_err(|e| format!("export-snapshot failed: {:?}", e))?;
            eprintln!(
                "OK: export-snapshot completed (path={}, file={}, include_state_nodes={})",
                db_path, out, include_state
            );
            std::process::exit(0);
        }
        "import-snapshot" => {
            if positional.len() != 1 {
                eprintln!("import-snapshot requires <file>");
                print_storage_cmd_help();
                std::process::exit(2);
            }
            let inp = &positional[0];
            let storage =
                DbStore::open(&db_path).map_err(|e| format!("storage open failed: {:?}", e))?;
            storage
                .import_snapshot(inp, wipe_state)
                .map_err(|e| format!("import-snapshot failed: {:?}", e))?;
            eprintln!(
                "OK: import-snapshot completed (path={}, file={}, wipe_state_nodes={})",
                db_path, inp, wipe_state
            );
            std::process::exit(0);
        }
        _ => {
            print_storage_cmd_help();
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Maintenance / storage commands (exit after completion)
    if handle_storage_subcommand()? {
        return Ok(());
    }

    println!("\n🚀 NewGen Engine™ — Step 49 (Governance Live & P2P Mempool)");

    // 🔹 Legge le costanti di versione dalla src/version.rs
    let v = VersionInfo::current();
    println!(
        "   ➜ Versione software: {} | protocol={} (min_supported={})",
        v.software_version, v.protocol_version, v.min_supported_protocol_version
    );

    // -------------------------------
    // CLI
    // -------------------------------
    let mut port: Option<u16> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut api_port: Option<u16> = None;
    let mut explorer_port: Option<u16> = None;
    let mut indexer_stream_bind: Option<String> = None; // Data Bridge (Indexer SQL)
    let mut indexer_stream_token: Option<String> = None; // shared-secret token
    let mut indexer_stream_backlog: usize = 2000; // bounded replay window
    let mut node_id: Option<String> = None; // Aggiunto per i log
    let mut data_dir: Option<String> = None;
    let mut public_mode = false;
    let mut follower_mode = false;

    // Snapshot bootstrap v2: explicit local bundle path or automatic seed-based cold-start fetch.
    let mut bootstrap_snapshot_v2: Option<String> = None;

    // Step 43: modalità manutenzione "solo reindex"
    let mut reindex_only = false;

    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().and_then(|v| v.parse().ok()),
            "--peer" => {
                if let Some(v) = args.next() {
                    extend_seed_list_from_csvish(&mut peers, &v);
                }
            }
            "--api-port" => api_port = args.next().and_then(|v| v.parse().ok()),
            "--explorer-port" => explorer_port = args.next().and_then(|v| v.parse().ok()),
            "--indexer-stream-bind" => indexer_stream_bind = args.next(),
            "--indexer-stream-token" => indexer_stream_token = args.next(),
            "--indexer-stream-backlog" => {
                if let Some(v) = args.next() {
                    if let Ok(n) = v.parse::<usize>() {
                        indexer_stream_backlog = n;
                    }
                }
            }
            "--node" => node_id = args.next(), // Aggiunto per i log
            "--data-dir" => data_dir = args.next(),
            _ if a.starts_with("--data-dir=") => {
                data_dir = Some(a["--data-dir=".len()..].to_string())
            }
            "--bootstrap-snapshot-v2" => bootstrap_snapshot_v2 = args.next(),
            "--public" => public_mode = true,
            "--follower" => follower_mode = true,

            // 👇 NUOVO: modalità manutenzione
            "--reindex-only" => {
                reindex_only = true;
            }
            _ => {}
        }
    }
    peers.sort();
    peers.dedup();
    let mut peer: Option<String> = if peers.is_empty() {
        None
    } else {
        Some(peers.join(","))
    };

    let node_id_str = node_id.clone().unwrap_or_else(|| "N/A".to_string());

    // -------------------------------
    // Data-dir: congela una root assoluta e stabile per tutto il nodo.
    // Il processo può fare chdir nel data-dir per compatibilità, ma NodePaths e
    // il self-restart devono sempre riferirsi al data-dir effettivo assoluto.
    // -------------------------------
    let data_dir = data_dir.unwrap_or_else(|| ".".to_string());
    let abs_data_dir = resolve_effective_data_dir(&data_dir)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    std::env::set_var(EFFECTIVE_DATA_DIR_ENV, abs_data_dir.as_os_str());
    std::env::set_current_dir(&abs_data_dir)?;

    let paths = NodePaths::from_data_dir(abs_data_dir.clone());
    validate_statesync_self_restart_boot_context(&node_id_str, &paths)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    // runtime dirs (best-effort): db/snapshots/logs.
    // config_dir viene creato solo dopo il guard di restart, così un child con
    // root sbagliata non materializza config vuote e non degrada verso genesis.
    std::fs::create_dir_all(&paths.db_dir)?;
    std::fs::create_dir_all(&paths.snapshots_dir)?;
    std::fs::create_dir_all(&paths.logs_dir)?;
    std::fs::create_dir_all(&paths.config_dir)?;

    // Keystore path standard: config/secrets/keystore.json (override con NEWGEN_KEYSTORE_PATH)
    if std::env::var("NEWGEN_KEYSTORE_PATH").is_err() {
        let ks_path = paths.config_dir.join("secrets").join("keystore.json");
        if let Some(parent) = ks_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::env::set_var(
            "NEWGEN_KEYSTORE_PATH",
            ks_path.to_string_lossy().to_string(),
        );
    }

    // Professional logging: console INFO + file DEBUG (configurable via env)
    logging::init_from_env(node_id_str.clone(), Some(paths.log_file_path(&node_id_str)));

    // Internal self-restart handoff after state-sync import success.
    // The replacement child waits briefly and then waits for the DB lock-info file to disappear,
    // so it does not race the exiting parent on the same runtime directory.
    wait_for_statesync_self_restart_lock_release(&node_id_str, &paths.db_dir);

    // Canonical chain_id (used for snapshot anchor verification and state-sync config)
    let chain_id: String = match newgen_engine::chain_identity::try_chain_id() {
        Ok(v) => v.to_string(),
        Err(e) => {
            ng_error!(
                target: "runtime.boot",
                "event=chain_identity_resolution_failed err={} action=abort",
                e
            );
            std::process::exit(2);
        }
    };

    // Boot fingerprint (useful in canary/WAN)
    newgen_engine::utils::emit_boot_fingerprint_once(&node_id_str);

    // In public mode non accettiamo boot “silenziosi”
    if public_mode {
        // Mainnet/Public mode: richiedi commitment del governance bootstrap in genesis.json
        std::env::set_var("NEWGEN_REQUIRE_BOOTSTRAP_COMMITMENT", "1");
        if !paths.config_dir.exists() {
            ng_error!(
                target: "runtime.boot",
                "event=public_boot_missing_config path={} action=abort",
                paths.config_dir.display()
            );
            std::process::exit(2);
        }
        if !paths.genesis_path().exists() {
            ng_error!(
                target: "runtime.boot",
                "event=public_boot_missing_genesis path={} action=abort",
                paths.genesis_path().display()
            );
            std::process::exit(2);
        }
        if !paths.governance_path().exists() {
            ng_error!(
                target: "runtime.boot",
                "event=public_boot_missing_governance path={} action=abort",
                paths.governance_path().display()
            );
            std::process::exit(2);
        }
        if !paths.economy_policy_path().exists() {
            ng_error!(
                target: "runtime.boot",
                "event=public_boot_missing_economy_policy path={} action=abort",
                paths.economy_policy_path().display()
            );
            std::process::exit(2);
        }
        if !paths.p2p_policy_path().exists() {
            ng_error!(
                target: "runtime.boot",
                "event=public_boot_missing_p2p_policy path={} action=abort",
                paths.p2p_policy_path().display()
            );
            std::process::exit(2);
        }
    }

    // Default ports: se passi --node A/B/C/... puoi omettere --port/--api-port/--explorer-port.
    if !reindex_only && (port.is_none() || api_port.is_none() || explorer_port.is_none()) {
        if let Some(ref nid) = node_id {
            if let Some((dp, da, de)) = default_ports_from_node_id(nid) {
                if port.is_none() {
                    port = Some(dp);
                }
                if api_port.is_none() {
                    api_port = Some(da);
                }
                if explorer_port.is_none() {
                    explorer_port = Some(de);
                }
            }
        }
    }

    // Canonical runtime export for public/dev mode.
    // This is done once, early in boot, and mirrors the value onto the legacy
    // alias so all lower layers read a consistent fail-closed value.
    newgen_engine::runtime_mode::export_public_mode(public_mode);

    if follower_mode {
        ng_info!(
            target: "runtime.boot",
            "event=follower_mode_enabled node={} local_signing=false p2p=true api_read_only=true",
            node_id_str
        );
    }

    if let Some(dir) = bootstrap_snapshot_v2.as_ref() {
        // Flag snapshot bootstrap v2 (Phase 5): se DB è vuoto, importeremo questa snapshot prima dell’avvio.
        std::env::set_var("NEWGEN_BOOTSTRAP_SNAPSHOT_V2", dir);
        ng_info!(
            target: "snapshot.bootstrap",
            "event=bootstrap_snapshot_dir_configured node={} dir={}",
            node_id_str,
            dir
        );
    }

    // Default bootstrap in dev: se non sei A e non passi --peer, prova a dialare A in locale.
    if !reindex_only && !public_mode && peer.is_none() && !node_id_str.eq_ignore_ascii_case("A") {
        peer = Some("/ip4/127.0.0.1/tcp/8080".to_string());
    }

    // In modalità --reindex-only NON richiediamo le porte.
    // In modalità normale sì, come prima.
    let port = if reindex_only {
        0
    } else {
        port.expect("ERRORE: --port richiesto (oppure usa --node A per default)")
    };

    let api_port = if reindex_only {
        0
    } else {
        api_port.expect("ERRORE: --api-port richiesto (oppure usa --node A per default)")
    };

    let explorer_port = if reindex_only {
        0
    } else {
        explorer_port.expect("ERRORE: --explorer-port richiesto (oppure usa --node A per default)")
    };

    // Log di configurazione P2P solo se stiamo avviando davvero il nodo
    if !reindex_only {
        ng_info!(
            target: "runtime.boot",
            "event=runtime_ports_configured node={} p2p_port={} peer={:?} api_port={} explorer_port={}",
            node_id_str,
            port,
            peer,
            api_port,
            explorer_port
        );
    }

    // -------------------------------
    // Stato condiviso
    // -------------------------------

    // STEP 42 — Canonical source: storage backend (except in --reindex-only)
    let bootstrap_snapshot_v2_dir: Option<PathBuf> = bootstrap_snapshot_v2
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("NEWGEN_BOOTSTRAP_SNAPSHOT_V2")
                .ok()
                .map(PathBuf::from)
        });

    let auto_state_sync_enabled = std::env::var("NEWGEN_AUTO_STATE_SYNC")
        .ok()
        .map(|v| {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        })
        .unwrap_or(true);
    let auto_state_sync_seeds = collect_seed_multiaddrs(peer.as_ref());
    let mut pending_auto_state_sync_out_dir: Option<PathBuf> = None;
    let mut pending_runtime_actor_boot_phase: Option<P2pBootPhase> = None;
    let mut entered_fallback_live_sync = false;
    let mut forced_cold_start_storage_state: Option<ColdStartStorageState> = None;

    let storage = if reindex_only {
        Arc::new(DbStore::open(DB_PATH).unwrap_or_else(|e| match e {
            StorageError::InterprocessOpenConflict { path, message } => {
                panic!(
                    "DbStore::open({}) refused because {}: {}",
                    DB_PATH, path, message
                );
            }
            other => panic!("DbStore::open({}) failed: {:?}", DB_PATH, other),
        }))
    } else {
        match DbStore::open(DB_PATH) {
            Ok(db) => Arc::new(db),
            Err(e) if e.is_interprocess_open_conflict() => {
                ng_error!(
                    target: "storage.boot",
                    "event=db_open_refused node={} db_path={} err={} action=abort reason=data_dir_in_use",
                    node_id_str,
                    DB_PATH,
                    e
                );
                std::process::exit(2);
            }
            Err(e) => {
                ng_warn!(
                    target: "storage.boot",
                    "event=db_open_failed node={} db_path={} err={:?} action=evaluate_cold_start_recovery",
                    node_id_str,
                    DB_PATH,
                    e
                );
                match decide_cold_start_bootstrap_plan(
                    ColdStartStorageState::Invalid,
                    bootstrap_snapshot_v2_dir.is_some(),
                    auto_state_sync_enabled,
                    !auto_state_sync_seeds.is_empty(),
                    public_mode,
                ) {
                    ColdStartBootstrapPlan::FailClosed => {
                        ng_error!(
                            target: "storage.boot",
                            "event=cold_start_fail_closed node={} reason=storage_unavailable_without_anchored_bootstrap public_mode=true",
                            node_id_str
                        );
                        std::process::exit(2);
                    }
                    recovery_plan => {
                        match quarantine_runtime_db_dir_for_cold_start(&paths.db_dir, &node_id_str)
                        {
                            Ok(Some(backup)) => {
                                ng_warn!(
                                    target: "storage.boot",
                                    "event=storage_quarantined_for_cold_start node={} backup_path={} plan={:?}",
                                    node_id_str,
                                    backup.display(),
                                    recovery_plan
                                );
                            }
                            Ok(None) => {}
                            Err(qe) => {
                                ng_error!(
                                    target: "storage.boot",
                                    "event=storage_quarantine_failed node={} err={} action=abort",
                                    node_id_str,
                                    qe
                                );
                                std::process::exit(2);
                            }
                        }
                        forced_cold_start_storage_state = Some(ColdStartStorageState::Invalid);
                        Arc::new(DbStore::open(DB_PATH).unwrap_or_else(|e2| {
                            panic!(
                                "DbStore::open({}) failed after quarantine-based cold-start recovery: {:?}",
                                DB_PATH, e2
                            );
                        }))
                    }
                }
            }
        }
    };

    let mut blockchain = if reindex_only {
        ng_info!(
            target: "storage.boot",
            "event=reindex_only_json_source node={}",
            node_id_str
        );
        load_blockchain_for_boot_or_exit(public_mode, &node_id_str, "reindex_only_json_source")
    } else if let Some(storage_state) = forced_cold_start_storage_state {
        match resolve_cold_start_bootstrap(
            storage_state,
            storage.clone(),
            bootstrap_snapshot_v2_dir.as_ref(),
            auto_state_sync_enabled,
            &auto_state_sync_seeds,
            &paths,
            &node_id_str,
            public_mode,
            &chain_id,
            peer.as_ref(),
        )
        .await
        {
            ColdStartBootstrapResolution::Ready(blockchain) => blockchain,
            ColdStartBootstrapResolution::DeferRuntimeActor {
                out_dir,
                reason,
                boot_phase,
            } => {
                ng_warn!(
                    target: "state_sync.bootstrap",
                    "event=cold_start_runtime_actor_bootstrap node={} reason={} action=defer_to_runtime_actor",
                    node_id_str,
                    reason
                );
                pending_auto_state_sync_out_dir = Some(out_dir);
                pending_runtime_actor_boot_phase = Some(boot_phase);
                load_blockchain_for_boot_or_exit(public_mode, &node_id_str, "cold_start_fallback")
            }
            ColdStartBootstrapResolution::JsonFallback { reason } => {
                ng_warn!(
                    target: "storage.boot",
                    "event=cold_start_json_fallback node={} reason={}",
                    node_id_str,
                    reason
                );
                load_blockchain_for_boot_or_exit(public_mode, &node_id_str, "cold_start_fallback")
            }
            ColdStartBootstrapResolution::FailClosed { reason } => {
                ng_error!(
                    target: "storage.boot",
                    "event=cold_start_fail_closed node={} reason={}",
                    node_id_str,
                    reason
                );
                std::process::exit(2);
            }
        }
    } else {
        match storage.load_chain() {
            Ok(blocks) if !blocks.is_empty() => {
                ng_info!(
                    target: "storage.boot",
                    "event=chain_loaded_from_storage node={} blocks={}",
                    node_id_str,
                    blocks.len()
                );
                Blockchain::from_blocks_with_storage(blocks, storage.clone())
            }
            Ok(_) => match resolve_cold_start_bootstrap(
                ColdStartStorageState::Empty,
                storage.clone(),
                bootstrap_snapshot_v2_dir.as_ref(),
                auto_state_sync_enabled,
                &auto_state_sync_seeds,
                &paths,
                &node_id_str,
                public_mode,
                &chain_id,
                peer.as_ref(),
            )
            .await
            {
                ColdStartBootstrapResolution::Ready(blockchain) => blockchain,
                ColdStartBootstrapResolution::DeferRuntimeActor {
                    out_dir,
                    reason,
                    boot_phase,
                } => {
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=cold_start_runtime_actor_bootstrap node={} reason={} action=defer_to_runtime_actor",
                        node_id_str,
                        reason
                    );
                    pending_auto_state_sync_out_dir = Some(out_dir);
                    pending_runtime_actor_boot_phase = Some(boot_phase);
                    load_blockchain_for_boot_or_exit(
                        public_mode,
                        &node_id_str,
                        "cold_start_fallback",
                    )
                }
                ColdStartBootstrapResolution::JsonFallback { reason } => {
                    ng_warn!(
                        target: "storage.boot",
                        "event=cold_start_json_fallback node={} reason={}",
                        node_id_str,
                        reason
                    );
                    load_blockchain_for_boot_or_exit(
                        public_mode,
                        &node_id_str,
                        "cold_start_fallback",
                    )
                }
                ColdStartBootstrapResolution::FailClosed { reason } => {
                    ng_error!(
                        target: "storage.boot",
                        "event=cold_start_fail_closed node={} reason={}",
                        node_id_str,
                        reason
                    );
                    std::process::exit(2);
                }
            },
            Err(e) => {
                ng_warn!(
                    target: "storage.boot",
                    "event=load_chain_invalid node={} err={:?} action=evaluate_cold_start_recovery",
                    node_id_str,
                    e
                );
                match resolve_cold_start_bootstrap(
                    ColdStartStorageState::Invalid,
                    storage.clone(),
                    bootstrap_snapshot_v2_dir.as_ref(),
                    auto_state_sync_enabled,
                    &auto_state_sync_seeds,
                    &paths,
                    &node_id_str,
                    public_mode,
                    &chain_id,
                    peer.as_ref(),
                )
                .await
                {
                    ColdStartBootstrapResolution::Ready(blockchain) => blockchain,
                    ColdStartBootstrapResolution::DeferRuntimeActor {
                        out_dir,
                        reason,
                        boot_phase,
                    } => {
                        ng_warn!(
                            target: "state_sync.bootstrap",
                            "event=cold_start_runtime_actor_bootstrap node={} reason={} action=defer_to_runtime_actor",
                            node_id_str,
                            reason
                        );
                        pending_auto_state_sync_out_dir = Some(out_dir);
                        pending_runtime_actor_boot_phase = Some(boot_phase);
                        load_blockchain_for_boot_or_exit(
                            public_mode,
                            &node_id_str,
                            "cold_start_fallback",
                        )
                    }
                    ColdStartBootstrapResolution::JsonFallback { reason } => {
                        ng_warn!(
                            target: "storage.boot",
                            "event=cold_start_json_fallback node={} reason={}",
                            node_id_str,
                            reason
                        );
                        load_blockchain_for_boot_or_exit(
                            public_mode,
                            &node_id_str,
                            "cold_start_fallback",
                        )
                    }
                    ColdStartBootstrapResolution::FailClosed { reason } => {
                        ng_error!(
                            target: "storage.boot",
                            "event=cold_start_fail_closed node={} reason={}",
                            node_id_str,
                            reason
                        );
                        std::process::exit(2);
                    }
                }
            }
        }
    };

    validate_statesync_self_restart_loaded_tip(&node_id_str, &paths, blockchain.tip_height_u64())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    // Guard: if the loaded chain DB/JSON predates governance persistence, bootstrap from config/governance.json.
    // Phase 1: lo state_root (SMT) richiede lo storage iniettato (niente open "nascosti").
    if !blockchain.has_attached_storage() {
        blockchain.attach_storage(storage.clone());
    }

    // Runtime source/DB consistency guard before repair and the STEP 42 mirror.
    // A prepared cold-start snapshot intentionally uses a temporary shell chain.
    if !reindex_only && !cold_start_runtime_snapshot_pending_v211(
        &pending_auto_state_sync_out_dir,
        pending_runtime_actor_boot_phase,
    ) {
        let initialized = storage.is_initialized().unwrap_or_else(|err| {
            ng_error!(target: "storage.boot", "event=storage_preflight_failed node={} err={:?} action=abort", node_id_str, err);
            std::process::exit(75);
        });
        if initialized {
            let persisted_tip = storage.get_height().unwrap_or_else(|err| {
                ng_error!(target: "storage.boot", "event=storage_preflight_height_failed node={} err={:?} action=abort", node_id_str, err);
                std::process::exit(75);
            });
            let loaded_tip = blockchain.chain.last().map(|b| b.index).unwrap_or(0);
            if persisted_tip != loaded_tip {
                ng_error!(target: "storage.boot", "event=storage_pre_mirror_height_mismatch node={} persisted={} loaded={} action=abort", node_id_str, persisted_tip, loaded_tip);
                std::process::exit(75);
            }
        }
    }

    // STEP 43 — Controllo integrità & riparazione.
    // Public/freeze mode must never silently patch/truncate and persist a corrupted chain.
    // We run the legacy repair checker on a clone as validate-only; if it would repair, boot aborts.
    if public_mode {
        let mut check_only = blockchain.clone();
        let would_repair = check_and_repair_chain(&mut check_only);
        if would_repair {
            ng_error!(
                target: "storage.boot",
                "event=chain_integrity_repair_required node={} public_mode=true action=abort reason=repair_disabled_in_public_mode",
                node_id_str
            );
            std::process::exit(2);
        }
        ng_info!(
            target: "storage.boot",
            "event=chain_integrity_ok node={} repaired=false public_mode=true",
            node_id_str
        );
    } else {
        let repaired = check_and_repair_chain(&mut blockchain);
        if repaired {
            ng_warn!(
                target: "storage.boot",
                "event=chain_repaired node={} action=save_truncated_version",
                node_id_str
            );
            if let Err(err) = save_blockchain_with_storage(storage.as_ref(), &blockchain) {
                ng_warn!(
                    target: "storage.boot",
                    "event=chain_repair_save_failed node={} err={:?}",
                    node_id_str,
                    err
                );
            }
        } else {
            ng_info!(
                target: "storage.boot",
                "event=chain_integrity_ok node={} repaired=false",
                node_id_str
            );
        }
    }

    match blockchain.replay_durable_governance_ingress_wal_v1() {
        Ok(restored) => {
            ng_info!(
                target: "gov.queue",
                "event=governance_ingress_wal_replayed node={} restored_pending={}",
                node_id_str,
                restored
            );
        }
        Err(err) => {
            ng_error!(
                target: "gov.queue",
                "event=governance_ingress_wal_replay_failed node={} err={} action=abort",
                node_id_str,
                err
            );
            std::process::exit(2);
        }
    }

    // STEP 42 — Mirror della chain nel backend storage (sempre, dopo eventuale riparazione),
    // except during V211 cold-start runtime-snapshot bootstrap. In that mode the
    // in-memory chain is only a temporary runtime shell used to start the P2P
    // snapshot actor; persisting it would turn a failed snapshot attempt into a
    // dirty low-height DB and could prevent the next boot from retrying cleanly.
    if cold_start_runtime_snapshot_pending_v211(
        &pending_auto_state_sync_out_dir,
        pending_runtime_actor_boot_phase,
    ) {
        ng_info!(
            target: "storage.boot",
            "event=chain_mirror_skipped node={} reason=pending_cold_start_runtime_snapshot_v211 action=preserve_empty_db_until_snapshot_import",
            node_id_str
        );
    } else if let Err(err) = mirror_blockchain_to_storage(storage.as_ref(), &blockchain) {
        ng_error!(
            target: "storage.boot",
            "event=mirror_storage_failed node={} err={:?} action=abort",
            node_id_str,
            err
        );
        std::process::exit(1);
    } else {
        let height = blockchain.chain.len().saturating_sub(1) as u64;
        ng_info!(
            target: "storage.boot",
            "event=mirror_storage_ok node={} height={}",
            node_id_str,
            height
        );
    }

    // STEP 58B — Boot safety: se DB ha i blocchi ma non i nodi SMT, il nodo morirà al blocco #1.
    // Questo rende RUN_C/RUN_D robusti anche su DB fresh.
    if let Err(e) = blockchain.ensure_state_smt_ready() {
        ng_error!(
            target: "storage.boot",
            "event=state_smt_init_failed node={} err={} action=abort",
            node_id_str,
            e
        );
        std::process::exit(3);
    }

    if !reindex_only {
        if let Err(e) = persist_init(storage.as_ref().clone()) {
            ng_error!(
                target: "storage.boot",
                "event=persistence_worker_init_failed node={} err={} action=abort",
                node_id_str,
                e
            );
            std::process::exit(2);
        }
    }

    // STEP 42 — Check altezza DB vs chain tip in memoria (solo log, niente panico)
    {
        let db_height = storage.get_height().unwrap_or_else(|err| {
            ng_error!(target: "storage.boot", "event=storage_post_mirror_height_failed node={} err={:?} action=abort", node_id_str, err);
            std::process::exit(75);
        });
        let chain_tip_height = blockchain.chain.last().map(|b| b.index).unwrap_or(0);

        if db_height != chain_tip_height {
            ng_error!(
                target: "storage.boot",
                "event=storage_height_mismatch node={} chain_tip_height={} db_height={} action=abort",
                node_id_str,
                chain_tip_height,
                db_height
            );
            if !cold_start_runtime_snapshot_pending_v211(
                &pending_auto_state_sync_out_dir,
                pending_runtime_actor_boot_phase,
            ) {
                std::process::exit(75);
            }
        } else {
            ng_info!(
                target: "storage.boot",
                "event=storage_height_match node={} height={}",
                node_id_str,
                db_height
            );
        }
    }

    // 🔧 STEP 43 — Modalità manutenzione: solo reindex e uscita
    if reindex_only {
        ng_info!(
            target: "storage.boot",
            "event=reindex_only_complete node={} action=exit",
            node_id_str
        );
        return Ok(());
    }

    // -------------------------------
    // Data Bridge (Indexer SQL): TCP JSONL stream
    // -------------------------------
    if let Some(bind) = indexer_stream_bind.clone() {
        // Fail-fast: se non è loopback, richiedi token (evita esposizione accidentale).
        if let Ok(sa) = bind.parse::<SocketAddr>() {
            if !sa.ip().is_loopback() && indexer_stream_token.is_none() {
                ng_error!(
                    target: "databridge.boot",
                    "event=indexer_stream_bind_missing_token bind={} action=abort",
                    bind
                );
                std::process::exit(2);
            }
        }

        match indexer_stream::spawn_indexer_stream(
            &bind,
            indexer_stream_token.clone(),
            indexer_stream_backlog,
        )
        .await
        {
            Ok(publisher) => {
                // Seed backlog dalla chain canonica attuale (bounded replay su connect).
                publisher.seed_from_chain(&blockchain.chain);
                blockchain.attach_indexer_stream(publisher);
                ng_info!(
                    target: "databridge.boot",
                    "event=indexer_stream_enabled node={} bind={} backlog_blocks={}",
                    node_id_str,
                    bind,
                    indexer_stream_backlog
                );
            }
            Err(e) => {
                ng_error!(
                    target: "databridge.boot",
                    "event=indexer_stream_bind_failed node={} bind={} err={}",
                    node_id_str,
                    bind,
                    e
                );
            }
        }
    }

    let policy = match SecurityPolicy::init_from_paths(&paths, public_mode) {
        Ok(p) => p,
        Err(e) => {
            ng_error!(
                target: "runtime.boot",
                "event=security_policy_load_failed err={} action=abort",
                e
            );
            std::process::exit(2);
        }
    };

    blockchain.apply_security_policy_runtime(&policy);
    ng_info!(
        target: "runtime.boot",
        "event=security_runtime_injected node={} min_fee_per_tx={} min_fee_per_byte={} max_block_size={}",
        node_id_str,
        blockchain.security_runtime.min_fee_per_tx,
        blockchain.security_runtime.min_fee_per_byte,
        blockchain.security_runtime.max_block_size
    );

    let security_policy = Arc::new(policy.clone());
    let chain: SharedChain = Arc::new(Mutex::new(blockchain));
    let mempool: SharedMempool = Arc::new(Mutex::new(Mempool::from_security_policy(&policy)));

    // V185 status-cache hardening: seed /status degraded fallback from the already-loaded
    // chain before P2P/snapshot actors can make the chain lock busy. This ensures the first
    // degraded /status response after boot still contains real height/finality/hash context.
    {
        let g = chain.lock().unwrap_or_else(|e| e.into_inner());
        api::publish_runtime_status_cache_from_chain_v1(&g);
    }

    // Keep mempool admission aligned with the already-loaded chain economic policy from boot.
    // Mempool::from_security_policy seeds from the security floor, while adaptive fee uses
    // blockchain.policy.base_fee_per_tx. Seeding here closes the startup window before P2P/API
    // actors get a chance to re-sync the hint.
    {
        let base_fee_per_tx = {
            let g = chain.lock().unwrap_or_else(|e| e.into_inner());
            g.base_fee_per_tx()
        };
        let previous_hint = {
            let mut mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
            let (_, _, previous_hint) = mp.fee_policy_snapshot();
            mp.set_base_fee_per_tx_hint(base_fee_per_tx);
            previous_hint
        };
        ng_info!(
            target: "runtime.boot",
            "event=mempool_base_fee_hint_seeded node={} base_fee_per_tx={} previous_hint={}",
            node_id_str,
            base_fee_per_tx,
            previous_hint
        );
    }

    let peerbook: PeerBook = PeerBook::new();
    // Seed the local PeerBook with bootstrap peers as "protected" (non-consensus, ops-only).
    // This does NOT affect the current P2P dialer (which has its own bounded candidates), but
    // it ensures the peerbook itself is not trivially poisoned by FIFO eviction.
    {
        // Sources: CLI --peer and NEWGEN_BOOTSTRAP_PEERS.
        let mut seeds: Vec<String> = Vec::new();
        if let Some(p) = peer.as_ref() {
            seeds.extend(collect_seed_multiaddrs(Some(p)).into_iter());
        } else {
            seeds.extend(collect_seed_multiaddrs(None).into_iter());
        }
        // Optional extra protected list.
        if let Ok(v) = std::env::var("NEWGEN_PEERBOOK_PROTECT") {
            extend_seed_list_from_csvish(&mut seeds, &v);
        }
        seeds.sort();
        seeds.dedup();

        if !seeds.is_empty() {
            let pb = &peerbook;
            for s in seeds {
                pb.add_protected_peer(s);
            }
            let (u, p, cap, prot_cap) = pb.stats();
            ng_info!(target: "p2p.peerbook", "[{}] PeerBook seeded: unknown={} protected={} cap={}/{}", node_id_str, u, p, cap, prot_cap);
        }
    }

    let last_snapshot_ok_height = Arc::new(AtomicU64::new(0));

    // Phase 5 — Runtime maintenance: periodic pruning to keep DB growth bounded.
    // Safe to run best-effort: prunes only below the rollback window.
    spawn_pruning_maintenance_loop(
        node_id_str.clone(),
        public_mode,
        chain.clone(),
        storage.clone(),
        last_snapshot_ok_height.clone(),
    );

    // ✅ Step 49c: applica subito alla mempool gli override ricostruiti dalla governance
    {
        let delta_opt = {
            let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
            ch.governance.as_ref().map(|g| g.mempool_overrides.clone())
        };

        if let Some(delta) = delta_opt {
            mempool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .apply_governance_overrides(&delta);
        }
    }

    // ✅ PASSO 29: Crea il Gestore Reputazione in modo coerente con SecurityPolicy.
    // Phase 2 hardening: soglie, score iniziale, pesi e ban runtime derivano dalla
    // security_policy validata. In public/mainnet mode una policy incoerente deve
    // fallire in boot invece di degradare a default interni divergenti.
    let rep_cfg = ReputationConfig::from_security_policy_v1(
        &policy,
        paths
            .data_dir
            .join("reputation.json")
            .to_string_lossy()
            .to_string(),
        Some(node_id_str.clone()),
    )
    .map_err(|e| format!("invalid runtime reputation config derived from security_policy: {e}"))?;

    let reputation_manager: Arc<Mutex<PeerReputationManager>> =
        Arc::new(Mutex::new(PeerReputationManager::new(rep_cfg)));
    {
        let delta_opt = {
            let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
            ch.governance
                .as_ref()
                .map(|g| g.reputation_overrides.clone())
        };
        if let Some(delta) = delta_opt {
            reputation_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .apply_governance_overrides(&delta);
        }
    }
    {
        let mut ch = chain.lock().unwrap_or_else(|e| e.into_inner());

        // 🔗 Aggancia il motore reputazione alla Blockchain
        ch.reputation = Some(Arc::clone(&reputation_manager));

        if follower_mode {
            ch.set_miner_sk_b64(String::new());
            ch.is_authorized_miner = false;
            ch.set_proposal_gate_open(false);
            ch.set_p2p_ready_for_mining(false);
            ch.set_runtime_sync_caught_up(false);
            ch.set_runtime_bootstrap_complete(false);
            ng_info!(
                target: "runtime.boot",
                "event=follower_mode_runtime_gate node={} validator_signing_required=false mining_enabled=false",
                node_id_str
            );
        } else {
            // In mainnet/public: nessun keygen. In dev: keygen SOLO se esplicitamente permesso.
            let allow_keygen =
                !public_mode && std::env::var("NEWGEN_ALLOW_KEYGEN").ok().as_deref() == Some("1");

            let ks_path = keystore::keystore_path();

            // --- Validator signing key (miner) dal keystore ---
            let miner_seed_32: [u8; 32] = match keystore::load_secret_bytes(
                KeyRole::ValidatorSigning,
                public_mode,
            ) {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        ng_error!(
                            target: "runtime.boot",
                            "event=validator_signing_key_invalid_length found_len={} expected_len=32 action=abort",
                            bytes.len()
                        );
                        std::process::exit(2);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[..32]);
                    arr
                }
                Err(KeystoreError::MissingEntry(_)) if allow_keygen => {
                    use rand::rngs::OsRng;
                    use rand::RngCore;
                    let mut arr = [0u8; 32];
                    OsRng.fill_bytes(&mut arr);

                    // richiede NEWGEN_KEYSTORE_PASSPHRASE
                    keystore::init_entry(KeyRole::ValidatorSigning, &arr, None).unwrap_or_else(
                        |e| {
                            ng_error!(
                                target: "runtime.boot",
                                "event=validator_signing_key_init_failed err={:?} action=abort",
                                e
                            );
                            std::process::exit(2);
                        },
                    );

                    arr
                }
                Err(e) => {
                    ng_error!(
                        target: "runtime.boot",
                        "event=validator_signing_key_missing keystore_path={} err={:?} public_mode={} allow_keygen={} action=abort",
                        ks_path.display(),
                        e,
                        public_mode,
                        allow_keygen
                    );
                    std::process::exit(2);
                }
            };

            // Inject runtime: la chiave miner non vive in economy_policy.json.
            let miner_sk_b64 = STANDARD.encode(miner_seed_32);
            ch.set_miner_sk_b64(miner_sk_b64);

            // Deriva pubkey hex per allowed_miners / log
            let miner_sk = SigningKey::from_bytes(&miner_seed_32);
            let _miner_pub_hex = hex::encode(miner_sk.verifying_key().to_bytes());

            // Hardening: in --public non accettiamo config permissiva (validator_set vuoto + allowed_miners vuota)
            if public_mode {
                let onchain_set_nonempty = ch
                    .governance
                    .as_ref()
                    .map(|g| !g.validator_set.entries.is_empty())
                    .unwrap_or(false);
                if !onchain_set_nonempty && ch.consensus.allowed_miners.is_empty() {
                    ng_error!(
                        target: "runtime.boot",
                        "event=public_boot_permissive_miner_config_rejected action=abort"
                    );
                    std::process::exit(2);
                }
            }

            // Devnet permissivo SOLO se esplicitamente abilitato (feature + env).
            // In --public è sempre disabilitato.
            let dev_permissive = !public_mode
                && cfg!(feature = "devnet-permissive-miners")
                && std::env::var("NEWGEN_DEVNET_PERMISSIVE_MINERS")
                    .ok()
                    .as_deref()
                    == Some("1");

            let (runtime_pub_hex, runtime_authorized, auth_reason) =
                match ch.local_miner_authorization_status() {
                    Ok(v) => v,
                    Err(e) => {
                        ng_error!(
                            target: "runtime.boot",
                            "event=local_miner_authorization_eval_failed err={} action=abort",
                            e
                        );
                        std::process::exit(2);
                    }
                };

            let authorized = runtime_authorized || dev_permissive;
            ch.is_authorized_miner = authorized;

            // IMPORTANTISSIMO:
            // - `is_authorized_miner` = autorizzazione locale del signer/miner.
            // - `proposal_gate_open` = hard gate stretto consumato dal proposal path.
            // - `p2p_ready_for_mining` = readiness osservabile/debounced per API/UI/log.
            // Nessuno dei due gate runtime deve essere `true` al boot.
            ch.set_proposal_gate_open(false);
            ch.set_p2p_ready_for_mining(false);
            ch.set_runtime_sync_caught_up(false);
            ch.set_runtime_bootstrap_complete(false);
            {
                let mut rep = reputation_manager.lock().unwrap_or_else(|e| e.into_inner());
                if authorized {
                    rep.set_local_source_attester_identity(
                        Some(runtime_pub_hex.clone()),
                        Some(miner_seed_32),
                    );
                } else {
                    rep.set_local_source_attester_identity(None, None);
                }
            }
            if !authorized {
                ng_warn!(
                    target: "runtime.boot",
                    "event=local_miner_unauthorized node={} pubkey_hex={} reason={} fail_closed=true",
                    node_id_str,
                    runtime_pub_hex,
                    auth_reason
                );
                if dev_permissive {
                    ng_warn!(
                        target: "runtime.boot",
                        "event=devnet_permissive_miners_override_active node={} action=disable_in_mainnet",
                        node_id_str
                    );
                } else {
                    ng_warn!(
                        target: "runtime.boot",
                        "event=local_miner_authorization_remediation node={} remediation=configure_validator_set_or_allowed_miners_or_explicit_devnet_override",
                        node_id_str
                    );
                }
            } else {
                ng_info!(
                    target: "runtime.boot",
                    "event=local_miner_authorized node={} pubkey_prefix={} keystore_path={} source={}",
                    node_id_str,
                    &runtime_pub_hex[..8],
                    ks_path.display(),
                    if dev_permissive && !runtime_authorized {
                        "devnet_permissive_override"
                    } else {
                        &auth_reason
                    }
                );
            }
        }
    }

    // -------------------------------
    // Avvio P2P e canali app

    // -------------------------------
    // Phase 5 — Runtime StateSync Supervisor wiring (NoOverlap / GapStall triggers)
    // -------------------------------
    let statesync_quarantine = Arc::new(AtomicBool::new(false));

    // -------------------------------
    // Live P2P runtime actor (single instance from cold-start to steady-state)
    // -------------------------------
    let has_runtime_bootstrap_config = peer.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || std::env::var("NEWGEN_BOOTSTRAP_PEERS")
            .ok()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        || std::env::var("NEWGEN_STATESYNC_SEEDS")
            .ok()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
    let local_chain_has_tip = {
        let g = chain.lock().unwrap_or_else(|e| e.into_inner());
        // V202: RestartCatchup eligibility must use the logical tip, not raw
        // chain.is_empty(). A pruned/snapshot node can have a non-zero base/tip
        // even if the in-memory Vec is empty or windowed.
        g.tip_height_u64() > 0
    };
    let initial_boot_phase = if let Some(phase) = pending_runtime_actor_boot_phase {
        phase
    } else if pending_auto_state_sync_out_dir.is_some() {
        P2pBootPhase::ColdStartSnapshot
    } else if has_runtime_bootstrap_config && local_chain_has_tip {
        P2pBootPhase::RestartCatchup
    } else {
        P2pBootPhase::SteadyState
    };

    let p2p_handle = p2p::start_p2p_node(
        port,
        peer.clone(),
        node_id_str.clone(),
        Arc::clone(&reputation_manager),
        Arc::clone(&chain),
        Arc::clone(&mempool),
        paths.clone(),
        public_mode,
        peerbook.clone(),
        initial_boot_phase,
    )
    .await?;

    if let Some(out_dir) = pending_auto_state_sync_out_dir.clone() {
        if matches!(
            pending_runtime_actor_boot_phase,
            Some(P2pBootPhase::ColdStartSnapshot | P2pBootPhase::FallbackLiveSync)
        ) {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let _ = p2p_handle
                .ctrl
                .send(p2p::P2pControl::NudgeBootstrapConnectivity { response: tx });
            let _ = tokio::time::timeout(Duration::from_secs(1), rx).await;
        }
        let expected_genesis_hash = {
            let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
            ch.genesis_hash.clone()
        };
        let cfg = StateSyncConfig {
            chain_id: chain_id.clone(),
            expected_genesis_hash,
            public_mode,
            anchor_cache_path: Some(anchor_store::default_anchor_cache_path(&paths)),
            auto_fetch_anchor: true,
            ..StateSyncConfig::default()
        };
        match fetch_snapshot_v2_bundle_via_runtime_ctrl(
            p2p_handle.ctrl.clone(),
            &out_dir,
            None,
            cfg,
        )
        .await
        {
            Ok(meta) => {
                ng_info!(
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_bundle_downloaded node={} height={} base_height={} window_from={} window_to={} chunks={} state_root={}",
                    node_id_str,
                    meta.height,
                    meta.base_height,
                    meta.window_from_height,
                    meta.window_to_height,
                    meta.chunks,
                    meta.state_root
                );
                if let Err(e) = import_snapshot_v2_bundle_into_live_runtime_and_rearm(
                    storage.clone(),
                    &out_dir,
                    &chain,
                    &mempool,
                    &security_policy,
                    &p2p_handle.ctrl,
                )
                .await
                {
                    return Err(std::io::Error::other(format!(
                        "startup snapshot apply failed: {}",
                        e
                    ))
                    .into());
                }
                ng_info!(
                    target: "state_sync.bootstrap",
                    "event=runtime_snapshot_applied node={} mode=cold_start_live_runtime next_phase=RestartCatchup",
                    node_id_str
                );
            }
            Err(e) => match decide_runtime_snapshot_failure_plan_v211(
                pending_runtime_actor_boot_phase,
                public_mode,
                allow_large_gap_block_fallback_env_v1(),
            ) {
                RuntimeActorBootstrapFailurePlan::FailClosed => {
                    ng_error!(
                        target: "state_sync.bootstrap",
                        "event=runtime_snapshot_failed node={} phase={:?} action=abort reason=snapshot_required_fail_closed_v211 allow_large_gap_block_fallback={} err={}",
                        node_id_str,
                        pending_runtime_actor_boot_phase,
                        allow_large_gap_block_fallback_env_v1(),
                        e
                    );
                    std::process::exit(2);
                }
                RuntimeActorBootstrapFailurePlan::EnterFallbackLiveSync => {
                    ng_warn!(
                        target: "state_sync.bootstrap",
                        "event=runtime_snapshot_failed node={} mode=non_public action=enter_fallback_live_sync reason=explicit_large_gap_block_fallback_allowed operator_override=true bounded_by_p2p_snapshot_priority_gate=true err={}",
                        node_id_str,
                        e
                    );
                    entered_fallback_live_sync = true;
                    set_runtime_boot_phase(&p2p_handle.ctrl, P2pBootPhase::FallbackLiveSync).await;
                }
            },
        }
    }

    // Phase 5 — Runtime snapshot loop: export snapshot v2 bundles every K blocks (protocol-defined in --public).
    spawn_snapshot_export_loop(
        node_id_str.clone(),
        public_mode,
        chain.clone(),
        storage.clone(),
        paths.snapshots_dir.clone(),
        last_snapshot_ok_height.clone(),
        statesync_quarantine.clone(),
    );

    // Notify P2P when a snapshot has been applied in-process (no-reboot path)
    let (statesync_applied_tx, mut statesync_applied_rx) =
        tokio::sync::mpsc::unbounded_channel::<()>();

    let statesync_supervisor_enabled = std::env::var("NEWGEN_STATESYNC_SUPERVISOR")
        .ok()
        .map(|v| {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        })
        .unwrap_or(true);

    if statesync_supervisor_enabled {
        // Seeds: peer + NEWGEN_BOOTSTRAP_PEERS + NEWGEN_STATESYNC_SEEDS
        let mut seeds: Vec<String> = Vec::new();

        if let Some(p) = peer.as_ref() {
            extend_seed_list_from_csvish(&mut seeds, p);
        }

        if let Ok(list) = std::env::var("NEWGEN_BOOTSTRAP_PEERS") {
            extend_seed_list_from_csvish(&mut seeds, &list);
        }

        if let Ok(list) = std::env::var("NEWGEN_STATESYNC_SEEDS") {
            extend_seed_list_from_csvish(&mut seeds, &list);
        }

        seeds.sort();
        seeds.dedup();

        if seeds.is_empty() {
            ng_info!(
                target: "state_sync.supervisor",
                "event=supervisor_enabled_without_seeds node={}",
                node_id_str
            );
        } else {
            let exit_on_success = env_bool_with_default("NEWGEN_STATESYNC_EXIT_ON_SUCCESS", true);
            let self_restart_on_success =
                env_bool_with_default(STATESYNC_SELF_RESTART_ON_SUCCESS_ENV, true);
            let wipe_state_nodes = env_bool_with_default("NEWGEN_STATESYNC_WIPE_STATE_NODES", true);

            let import_timeout_sec =
                env_u64_with_default("NEWGEN_STATESYNC_IMPORT_TIMEOUT_SEC", 900).clamp(30, 7200);

            let storage_for_action = Arc::clone(&storage);
            let mempool_for_action = Arc::clone(&mempool);
            let applied_tx_for_action = statesync_applied_tx.clone();
            let node_id_for_action = node_id_str.clone();
            let chain_for_action = Arc::clone(&chain);
            let paths_for_action = paths.clone();
            let chain_id_for_action = chain_id.clone();
            let public_mode_for_action = public_mode;
            let quarantine_for_action = Arc::clone(&statesync_quarantine);
            let live_ctrl_for_action = p2p_handle.ctrl.clone();
            let seeds_for_action = seeds.clone();
            let security_policy_for_action = Arc::clone(&security_policy);

            let action = Arc::new(move |reason: StateSyncReason| {
                let node_id = node_id_for_action.clone();
                let chain = Arc::clone(&chain_for_action);
                let storage = Arc::clone(&storage_for_action);
                let mempool = Arc::clone(&mempool_for_action);
                let applied_tx = applied_tx_for_action.clone();
                let paths = paths_for_action.clone();
                let chain_id = chain_id_for_action.clone();
                let quarantine = Arc::clone(&quarantine_for_action);
                let live_ctrl = live_ctrl_for_action.clone();
                let seeds = seeds_for_action.clone();
                let security_policy = Arc::clone(&security_policy_for_action);

                async move {
                    let rescue_needed_before_fetch = {
                        let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        runtime_statesync_rescue_needed(
                            ch.runtime_bootstrap_complete,
                            ch.runtime_sync_caught_up,
                        )
                    };
                    if !rescue_needed_before_fetch {
                        ng_info!(
                            target: "state_sync.supervisor",
                            "event=supervisor_skip_rescue node={} reason={:?} state=already_caught_up",
                            node_id,
                            reason
                        );
                        return Ok(());
                    }

                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs();
                    let out_dir = paths
                        .snapshots_dir
                        .join(format!("runtime_statesync_{}", ts));
                    std::fs::create_dir_all(&out_dir).map_err(|e| {
                        NgError::new(ErrorKind::Internal, format!("create_dir_all failed: {}", e))
                    })?;

                    let (expected_genesis_hash, actual_local_height_before_fetch) = {
                        let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        // Use the chain abstraction instead of raw chain.last(): pruned/snapshot
                        // state can have an empty in-memory block vector with a non-zero base/tip.
                        let local_height = ch.tip_height_u64();
                        (ch.genesis_hash.clone(), local_height)
                    };
                    let trigger_local_height = reason.local_height_hint();
                    let reference_peer_height = reason.reference_peer_height();
                    // The local chain lock is the source of truth for the lower progress bound.
                    // Trigger hints are diagnostic only; the peer height hint is used as an
                    // upper freshness reference so RestartCatchup cannot accept a tiny forward
                    // move while peers are thousands of blocks ahead.
                    let local_height_before_fetch = actual_local_height_before_fetch;
                    let min_acceptable_snapshot_height =
                        local_height_before_fetch.saturating_add(1);

                    let cfg = StateSyncConfig {
                        chain_id,
                        expected_genesis_hash,
                        min_acceptable_snapshot_height: Some(min_acceptable_snapshot_height),
                        reference_peer_height,
                        public_mode: public_mode_for_action,
                        anchor_cache_path: Some(anchor_store::default_anchor_cache_path(&paths)),
                        auto_fetch_anchor: true,
                        ..StateSyncConfig::default()
                    };

                    ng_info!(
                        target: "state_sync.supervisor",
                        "event=supervisor_action_started node={} reason={:?} actual_local_height={} trigger_local_height_hint={:?} reference_peer_height={:?} min_acceptable_snapshot_height={}",
                        node_id,
                        reason,
                        actual_local_height_before_fetch,
                        trigger_local_height,
                        reference_peer_height,
                        min_acceptable_snapshot_height
                    );

                    let meta = if !seeds.is_empty() {
                        match fetch_snapshot_v2_bundle_from_seeds(
                            seeds.clone(),
                            &out_dir,
                            None,
                            cfg.clone(),
                        )
                        .await
                        {
                            Ok(meta) => {
                                ng_info!(
                                    target: "state_sync.supervisor",
                                    "event=direct_seed_rescue_succeeded node={} reason={:?}",
                                    node_id,
                                    reason
                                );
                                meta
                            }
                            Err(seed_err) => {
                                ng_warn!(
                                    target: "state_sync.supervisor",
                                    "event=direct_seed_rescue_failed node={} action=fallback_live_runtime err={}",
                                    node_id,
                                    seed_err
                                );
                                fetch_snapshot_v2_bundle_via_runtime_ctrl(live_ctrl, &out_dir, None, cfg)
                                    .await
                                    .map_err(|e| {
                                        NgError::new(
                                            ErrorKind::Internal,
                                            format!("statesync fetch failed (seed rescue err: {}; runtime err: {})", seed_err, e),
                                        )
                                    })?
                            }
                        }
                    } else {
                        fetch_snapshot_v2_bundle_via_runtime_ctrl(live_ctrl, &out_dir, None, cfg)
                            .await
                            .map_err(|e| {
                                NgError::new(
                                    ErrorKind::Internal,
                                    format!("statesync fetch failed: {}", e),
                                )
                            })?
                    };

                    if meta.height < min_acceptable_snapshot_height {
                        let _ = std::fs::remove_dir_all(&out_dir);
                        ng_error!(
                            target: "state_sync.supervisor",
                            "event=runtime_statesync_rejected_non_progressive node={} reason={:?} local_height={} min_acceptable_snapshot_height={} snapshot_height={} action=abort_import",
                            node_id,
                            reason,
                            local_height_before_fetch,
                            min_acceptable_snapshot_height,
                            meta.height
                        );
                        return Err(NgError::new(
                            ErrorKind::Internal,
                            format!(
                                "statesync snapshot did not advance local tip: snapshot_height={} local_height={} min_acceptable_snapshot_height={}",
                                meta.height,
                                local_height_before_fetch,
                                min_acceptable_snapshot_height
                            ),
                        ));
                    }

                    // V202: re-check the local logical tip immediately before apply.
                    // Fetching/downloading can take time; if the node advanced locally in
                    // the meantime, importing an older snapshot would be non-progressive.
                    let current_local_height_before_apply = {
                        let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        ch.tip_height_u64()
                    };
                    let current_min_acceptable_snapshot_height =
                        current_local_height_before_apply.saturating_add(1);
                    if meta.height < current_min_acceptable_snapshot_height {
                        let _ = std::fs::remove_dir_all(&out_dir);
                        ng_error!(
                            target: "state_sync.supervisor",
                            "event=runtime_statesync_rejected_stale_before_apply node={} reason={:?} current_local_height={} current_min_acceptable_snapshot_height={} snapshot_height={} action=abort_import",
                            node_id,
                            reason,
                            current_local_height_before_apply,
                            current_min_acceptable_snapshot_height,
                            meta.height
                        );
                        return Err(NgError::new(
                            ErrorKind::Internal,
                            format!(
                                "statesync snapshot became stale before apply: snapshot_height={} current_local_height={} current_min_acceptable_snapshot_height={}",
                                meta.height,
                                current_local_height_before_apply,
                                current_min_acceptable_snapshot_height
                            ),
                        ));
                    }

                    let rescue_needed_before_apply = {
                        let ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        runtime_statesync_rescue_needed(
                            ch.runtime_bootstrap_complete,
                            ch.runtime_sync_caught_up,
                        )
                    };
                    if !rescue_needed_before_apply {
                        let _ = std::fs::remove_dir_all(&out_dir);
                        ng_info!(
                            target: "state_sync.supervisor",
                            "event=supervisor_rescue_cancelled node={} reason={:?} state=already_converged",
                            node_id,
                            reason
                        );
                        return Ok(());
                    }

                    // Quarantine only once we have a concrete snapshot to import.
                    quarantine.store(true, Ordering::Relaxed);

                    // Best-effort: stop mining/readiness during exclusive import/apply.
                    {
                        let mut ch = chain.lock().unwrap_or_else(|e| e.into_inner());
                        ch.set_proposal_gate_open(false);
                        ch.set_p2p_ready_for_mining(false);
                        ch.set_runtime_sync_caught_up(false);
                        ch.set_runtime_bootstrap_complete(false);
                    }

                    // Import snapshot *inside* persistence worker to avoid multi-open / races.
                    let out_dir2 = out_dir.clone();
                    let wipe = wipe_state_nodes;
                    let barrier_timeout = std::time::Duration::from_secs(20);
                    let import_timeout = std::time::Duration::from_secs(import_timeout_sec);

                    // Import snapshot (exclusive) inside persistence worker.
                    // Mainnet-grade safety: if anything fails after persist_pause(), we MUST resume persistence
                    // and drop quarantine to avoid deadlock.
                    let import_res: Result<(), NgError> =
                        tokio::task::spawn_blocking(move || -> Result<(), String> {
                            persist_pause();
                            if !persist_barrier(barrier_timeout) {
                                return Err("persist barrier timeout".to_string());
                            }
                            persist_import_snapshot_v2_bundle(&out_dir2, wipe, import_timeout)?;
                            Ok(())
                        })
                        .await
                        .map_err(|e| {
                            NgError::new(
                                ErrorKind::Internal,
                                format!("spawn_blocking join failed: {}", e),
                            )
                        })
                        .and_then(|r| {
                            r.map_err(|e| {
                                NgError::new(
                                    ErrorKind::Internal,
                                    format!("snapshot import failed: {}", e),
                                )
                            })
                        });

                    if let Err(e) = import_res {
                        // Ensure we don't keep dropping writes forever.
                        persist_resume();
                        quarantine.store(false, Ordering::Relaxed);
                        return Err(e);
                    }

                    if exit_on_success {
                        if self_restart_on_success {
                            match compute_statesync_self_restart_plan(unix_time_millis_now()) {
                                Ok(restart_plan) => match write_statesync_self_restart_context(
                                    &node_id,
                                    &paths,
                                    meta.height,
                                ) {
                                    Ok(restart_ctx_path) => {
                                        match spawn_statesync_self_restart(restart_plan) {
                                            Ok(child_pid) => {
                                                ng_info!(
                                                    target: "state_sync.supervisor",
                                                    "event=runtime_statesync_import_ok node={} height={} window_from={} chunks={} action=spawn_internal_restart child_pid={} restart_attempt={} exit_code=0",
                                                    node_id,
                                                    meta.height,
                                                    meta.window_from_height,
                                                    meta.chunks,
                                                    child_pid,
                                                    restart_plan.attempt
                                                );
                                                std::process::exit(0);
                                            }
                                            Err(err) => {
                                                let _ = std::fs::remove_file(&restart_ctx_path);
                                                ng_error!(
                                                    target: "state_sync.supervisor",
                                                    "event=internal_self_restart_spawn_failed node={} height={} window_from={} chunks={} err={} action=fallback_apply_in_process",
                                                    node_id,
                                                    meta.height,
                                                    meta.window_from_height,
                                                    meta.chunks,
                                                    err
                                                );
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        ng_error!(
                                            target: "state_sync.supervisor",
                                            "event=internal_self_restart_context_write_failed node={} height={} window_from={} chunks={} err={} action=fallback_apply_in_process",
                                            node_id,
                                            meta.height,
                                            meta.window_from_height,
                                            meta.chunks,
                                            err
                                        );
                                    }
                                },
                                Err(err) => {
                                    ng_warn!(
                                        target: "state_sync.supervisor",
                                        "event=internal_self_restart_guard_open node={} height={} window_from={} chunks={} err={} action=fallback_apply_in_process",
                                        node_id,
                                        meta.height,
                                        meta.window_from_height,
                                        meta.chunks,
                                        err
                                    );
                                }
                            }
                        } else {
                            ng_info!(
                                target: "state_sync.supervisor",
                                "event=runtime_statesync_import_ok node={} height={} window_from={} chunks={} action=exit_clean_restart",
                                node_id,
                                meta.height,
                                meta.window_from_height,
                                meta.chunks
                            );
                            std::process::exit(90);
                        }
                    }

                    ng_info!(
                        target: "state_sync.supervisor",
                        "event=runtime_statesync_import_ok node={} height={} window_from={} chunks={} action=apply_in_process",
                        node_id,
                        meta.height,
                        meta.window_from_height,
                        meta.chunks
                    );

                    // Rebuild chain from DB and reset mempool, then unquarantine.
                    let chain2 = Arc::clone(&chain);
                    let storage2 = Arc::clone(&storage);
                    let mempool2 = Arc::clone(&mempool);
                    let security_policy2 = security_policy.clone();

                    let apply_res: Result<(), NgError> =
                        tokio::task::spawn_blocking(move || -> Result<(), String> {
                            apply_imported_snapshot_to_live_runtime(
                                storage2,
                                &chain2,
                                &mempool2,
                                &security_policy2,
                            )
                        })
                        .await
                        .map_err(|e| {
                            NgError::new(
                                ErrorKind::Internal,
                                format!("spawn_blocking join failed: {}", e),
                            )
                        })
                        .and_then(|r| {
                            r.map_err(|e| {
                                NgError::new(
                                    ErrorKind::Internal,
                                    format!("in-process apply failed: {}", e),
                                )
                            })
                        });

                    if let Err(e) = apply_res {
                        persist_resume();
                        quarantine.store(false, Ordering::Relaxed);
                        return Err(e);
                    }

                    // Resume persistence after exclusive import.
                    persist_resume();

                    // Notify main → P2P control loop to reset inflight/caches.
                    // IMPORTANT: we keep quarantine=true until P2P acks the reset (handshake in main).
                    let _ = applied_tx.send(());

                    Ok(())
                }
            });

            let handle = spawn_state_sync_supervisor(StateSyncSupervisorConfig::from_env(), action);
            if entered_fallback_live_sync {
                handle.trigger(StateSyncReason::Manual {
                    detail: "startup entered fallback live sync after bootstrap failure"
                        .to_string(),
                });
            }
            p2p::set_state_sync_supervisor_handle(handle);

            ng_info!(
                target: "state_sync.supervisor",
                "event=supervisor_active node={} seeds={}",
                node_id_str,
                seeds.len()
            );
        }
    } else {
        ng_info!(
            target: "state_sync.supervisor",
            "event=supervisor_disabled node={} source=env",
            node_id_str
        );
    }

    let tx_p2p = p2p_handle.tx_out.clone();
    let mut rx_from_p2p = p2p_handle.rx_in;

    // Bridge: supervisor action (no-reboot) notifies P2P to reset inflight sync state
    // and re-arm post-snapshot catch-up.
    // Mainnet-grade handshake: keep quarantine=true until P2P acks both reset and RestartCatchup arm.
    {
        let ctrl = p2p_handle.ctrl.clone();
        let quarantine = Arc::clone(&statesync_quarantine);
        tokio::spawn(async move {
            while let Some(()) = statesync_applied_rx.recv().await {
                if let Err(e) = notify_state_sync_applied_and_rearm_p2p(&ctrl).await {
                    ng_warn!(
                        target: "state_sync.supervisor",
                        "event=post_snapshot_p2p_rearm_failed action=unquarantine_fail_safe err={}",
                        e
                    );
                }

                quarantine.store(false, Ordering::Relaxed);
            }
        });
    }

    // -------------------------------
    // API HTTP
    // -------------------------------
    {
        let chain_api = Arc::clone(&chain);
        let mempool_api = Arc::clone(&mempool);
        let tx_api = tx_p2p.clone();
        tokio::spawn(async move {
            api::serve_api(
                chain_api,
                mempool_api,
                tx_api,
                api_port,
                storage.clone(),
                public_mode,
                follower_mode,
            )
            .await;
        });
    }

    // -------------------------------
    // Explorer web
    // -------------------------------
    let explorer_base_dir = paths.data_dir.clone();
    tokio::spawn(async move {
        explorer::start_explorer_server(&explorer_base_dir, explorer_port).await;
    });

    // -------------------------------
    // Listener P2P → aggiorna chain/mempool (STEP 29 LOGIC)
    // -------------------------------
    {
        let chain = Arc::clone(&chain);
        let mempool = Arc::clone(&mempool);
        let tx_p2p_handle = tx_p2p.clone();
        let rep_man_loop = Arc::clone(&reputation_manager);

        let statesync_quarantine_loop = Arc::clone(&statesync_quarantine);

        tokio::spawn(async move {
            while let Some(msg) = rx_from_p2p.recv().await {
                if statesync_quarantine_loop.load(Ordering::Relaxed) {
                    match &msg {
                        NetMsg::NewTx(_) | NetMsg::NewBlock(_) => {
                            continue;
                        }
                        _ => {}
                    }
                }

                match msg {
                    NetMsg::NewTx(tx) => {
                        if runtime_inbound_newtx_should_drop_before_locks_v1(&tx) {
                            ng_warn_throttle!(
                                key: "runtime_inbound_coinbase_newtx_dropped".to_string(),
                                every_ms: 30_000,
                                target: "p2p.tx",
                                "event=inbound_coinbase_newtx_dropped action=drop_before_chain_or_mempool_lock"
                            );
                            continue;
                        }

                        let nft_policy_ok = {
                            let local_chain = chain.lock().unwrap_or_else(|e| e.into_inner());
                            let next_height = local_chain.tip_height_u64().saturating_add(1);
                            match local_chain
                                .validate_tx_public_admission_at_height_v1(&tx, next_height)
                            {
                                Ok(_) => true,
                                Err(e) => {
                                    ng_debug!(target: "p2p.tx", "event=nft_state_invalid_tx_dropped tx_hash={} reason={}", tx.hash, e);
                                    false
                                }
                            }
                        };
                        if !nft_policy_ok {
                            continue;
                        }
                        let mut mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
                        let is_new = mp.add(tx.clone());
                        if is_new {
                            if let Err(e) = tx_p2p_handle.send(NetMsg::NewTx(tx.clone())) {
                                ng_warn_throttle!(
                                    key: "runtime_relay_tx_failed".to_string(),
                                    every_ms: 10_000,
                                    target: "p2p.engine",
                                    "event=relay_tx_failed err={}",
                                    e
                                );
                            }
                        }
                    }

                    NetMsg::NewBlock(b) => {
                        ng_info!(
                            target: "p2p.engine",
                            "event=new_block_received_for_local_apply height={}",
                            b.index
                        );

                        let mut local_chain = chain.lock().unwrap_or_else(|e| e.into_inner());
                        let rep_man_guard = rep_man_loop.lock().unwrap_or_else(|e| e.into_inner());

                        let latest_block = local_chain.get_latest_block();

                        if b.previous_hash == latest_block.hash && b.index == latest_block.index + 1
                        {
                            // 🔹 1. Costruisci catena candidata
                            let mut candidate_chain = local_chain.clone();
                            candidate_chain.chain.push(b.clone());

                            // 🔹 2. Chiedi se la catena candidata è migliore
                            if local_chain.try_adopt_longer_valid(&candidate_chain, &rep_man_guard)
                            {
                                // ✅ 3. COMMIT: sostituisci la chain locale
                                *local_chain = candidate_chain;

                                // ✅ 4. Applica effetti economici + pulizia mempool
                                {
                                    let mut mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
                                    mp.remove_batch(&b.transactions);
                                } // 👈 Rilascia lock mempool PRIMA di on_block_applied

                                // Apply block governance è ora implicito dentro on_block_applied o
                                // gestito dalla copia locale, ma qui stiamo lavorando sulla chain principale.
                                // Nota: try_adopt_longer_valid clona policy e governance dalla candidata,
                                // quindi lo stato è già aggiornato.

                                // Aggiorna solo statistiche e mempool runtime
                                local_chain.on_block_applied(&b, Some(&mempool));

                                ng_info!(
                                    target: "p2p.engine",
                                    "event=remote_block_applied height={} action=accepted",
                                    b.index
                                );
                            } else {
                                ng_warn!(
                                    target: "p2p.engine",
                                    "event=remote_block_rejected_not_better height={}",
                                    b.index
                                );
                            }
                        } else if b.index > latest_block.index + 1 {
                            // SyncRequest chunked
                            // Pruning-aware: `from` è un'altezza assoluta (block.index), non la len() del Vec.
                            let from = latest_block.index.saturating_add(1);
                            let limit = 32;
                            if let Err(e) = tx_p2p_handle.send(NetMsg::SyncRequest { from, limit })
                            {
                                ng_warn_throttle!(
                                    key: "runtime_sync_request_send_failed".to_string(),
                                    every_ms: 10_000,
                                    target: "p2p.engine",
                                    "event=sync_request_send_failed err={}",
                                    e
                                );
                            }
                        } else {
                            // Blocco vecchio
                            ng_info!(
                                target: "p2p.engine",
                                "event=remote_block_ignored_old height={} local_tip_height={}",
                                b.index,
                                latest_block.index
                            );
                        }
                    }

                    NetMsg::SyncResponse { blocks } => {
                        ng_debug!(
                            target: "p2p.engine",
                            "event=sync_response_received_via_engine blocks={} handled_by=p2p_rs",
                            blocks.len()
                        );
                    }

                    _ => {}
                }
            }
        });
    }

    // -------------------------------
    // Sync-on-start.
    // In un devnet multi-nodo è meglio chiedere SEMPRE un catch-up iniziale al peer,
    // anche se abbiamo già 1..N blocchi localmente (es. se abbiamo minato 1 blocco
    // prima dell'handshake). È una singola richiesta leggera.
    // -------------------------------
    if peer.is_some() {
        sleep(Duration::from_secs(2)).await;

        let local_next_height = chain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .chain
            .last()
            .map(|b| b.index.saturating_add(1))
            .unwrap_or(1)
            .max(1);
        let limit = 64;
        let _ = tx_p2p.send(NetMsg::SyncRequest {
            from: local_next_height,
            limit,
        });
        ng_info!(
            target: "p2p.sync",
            "event=initial_sync_request_sent from={} limit={} local_next_height={}",
            local_next_height,
            limit,
            local_next_height
        );
    }
    // -------------------------------
    // Miner loop (unico)
    // -------------------------------
    {
        let chain = Arc::clone(&chain);
        let mempool = Arc::clone(&mempool);
        let tx_for_miner = tx_p2p.clone();

        tokio::spawn(async move {
            // tick frequente: la logica interna produce max 1 volta per slot
            let mut tick = interval(Duration::from_millis(750));

            // Richiede una breve stabilità di rete prima di produrre (evita race all'avvio / durante catch-up).
            let mut ready_streak: u8 = 0;

            loop {
                tick.tick().await;

                // Prima condizione: P2P deve dichiarare "ready"
                let (authorized, p2p_ready) = {
                    let guard = chain.lock().unwrap_or_else(|e| e.into_inner());

                    // Follower-mode: non fare warm-up della streak, ma NON saltare il tick.
                    // Nota: tick_slot_pacing() è safe: in follower mode esce subito (no mining).
                    let authorized = guard.is_authorized_miner;
                    let p2p_ready = guard.p2p_ready_for_mining;

                    if authorized {
                        if p2p_ready {
                            ready_streak = ready_streak.saturating_add(1);
                        } else {
                            ready_streak = 0;
                        }
                    } else {
                        ready_streak = 0;
                    }

                    (authorized, p2p_ready)
                };

                // Seconda condizione: richiedi almeno 2 tick consecutivi in ready (solo per miner autorizzati).
                if authorized {
                    if !p2p_ready {
                        continue;
                    }
                    if ready_streak < 2 {
                        continue;
                    }
                }

                let mut guard = chain.lock().unwrap_or_else(|e| e.into_inner());
                guard.tick_slot_pacing(&mempool, &tx_for_miner);
            }
        });
    }

    // Banner UX: evita confusione in follower mode.
    let authorized = {
        chain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_authorized_miner
    };
    if authorized {
        println!("🛰️ Nodo operativo ✅ — Mining + P2P + Sync attivi");
    } else {
        println!(
            "🛰️ Nodo operativo ✅ — FOLLOWER MODE (Sync + Validazione attivi; Mining disabilitato)"
        );
    }

    // keep alive
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

#[cfg(test)]
mod cold_start_bootstrap_tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn with_env_vars<K, V, F>(vars: &[(K, Option<V>)], f: F)
    where
        K: AsRef<str>,
        V: AsRef<str>,
        F: FnOnce(),
    {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.as_ref().to_string(), std::env::var(key.as_ref()).ok()))
            .collect();
        for (key, value) in vars {
            match value {
                Some(v) => std::env::set_var(key.as_ref(), v.as_ref()),
                None => std::env::remove_var(key.as_ref()),
            }
        }
        f();
        for (key, value) in saved {
            match value {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }

    #[test]
    fn empty_db_prefers_explicit_snapshot_when_present() {
        let plan =
            decide_cold_start_bootstrap_plan(ColdStartStorageState::Empty, true, true, true, false);
        assert_eq!(plan, ColdStartBootstrapPlan::ImportExplicitSnapshot);
    }

    #[test]
    fn empty_db_prefers_direct_seed_bootstrap_before_json() {
        let plan = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Empty,
            false,
            true,
            true,
            false,
        );
        assert_eq!(plan, ColdStartBootstrapPlan::DirectSeedBootstrap);
    }

    #[test]
    fn invalid_storage_also_prefers_direct_seed_bootstrap() {
        let plan = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Invalid,
            false,
            true,
            true,
            false,
        );
        assert_eq!(plan, ColdStartBootstrapPlan::DirectSeedBootstrap);
    }

    #[test]
    fn public_mode_without_anchorable_bootstrap_fails_closed() {
        let plan = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Empty,
            false,
            false,
            false,
            true,
        );
        assert_eq!(plan, ColdStartBootstrapPlan::FailClosed);
    }

    #[test]
    fn non_public_without_bootstrap_inputs_falls_back_to_json() {
        let plan = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Invalid,
            false,
            false,
            false,
            false,
        );
        assert_eq!(plan, ColdStartBootstrapPlan::JsonFallback);
    }

    #[test]
    fn runtime_actor_failure_is_fail_closed_in_public_mode() {
        assert_eq!(
            decide_runtime_actor_failure_plan(true, false),
            RuntimeActorBootstrapFailurePlan::FailClosed
        );
    }

    #[test]
    fn invalid_storage_prefers_same_recovery_plan_as_empty_db() {
        let invalid = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Invalid,
            false,
            true,
            true,
            false,
        );
        let empty = decide_cold_start_bootstrap_plan(
            ColdStartStorageState::Empty,
            false,
            true,
            true,
            false,
        );
        assert_eq!(invalid, empty);
    }

    #[test]
    fn runtime_actor_failure_is_fail_closed_by_default_even_in_non_public_mode_v191() {
        assert_eq!(
            decide_runtime_actor_failure_plan(false, false),
            RuntimeActorBootstrapFailurePlan::FailClosed
        );
    }

    #[test]
    fn runtime_actor_failure_fallback_requires_explicit_operator_opt_in_v191() {
        assert_eq!(
            decide_runtime_actor_failure_plan(false, true),
            RuntimeActorBootstrapFailurePlan::EnterFallbackLiveSync
        );
    }

    #[test]
    fn runtime_actor_coldstart_fallback_env_is_off_by_default_v197() {
        with_env_vars(
            &[(
                "NEWGEN_ALLOW_RUNTIME_ACTOR_COLDSTART_FALLBACK",
                None::<&str>,
            )],
            || {
                assert!(!allow_runtime_actor_coldstart_fallback_env_v1());
            },
        );
    }

    #[test]
    fn runtime_actor_coldstart_fallback_requires_explicit_lab_opt_in_v197() {
        with_env_vars(
            &[("NEWGEN_ALLOW_RUNTIME_ACTOR_COLDSTART_FALLBACK", Some("1"))],
            || {
                assert!(allow_runtime_actor_coldstart_fallback_env_v1());
            },
        );
        with_env_vars(
            &[(
                "NEWGEN_ALLOW_RUNTIME_ACTOR_COLDSTART_FALLBACK",
                Some("true"),
            )],
            || {
                assert!(allow_runtime_actor_coldstart_fallback_env_v1());
            },
        );
        with_env_vars(
            &[("NEWGEN_ALLOW_RUNTIME_ACTOR_COLDSTART_FALLBACK", Some("0"))],
            || {
                assert!(!allow_runtime_actor_coldstart_fallback_env_v1());
            },
        );
    }

    #[test]
    fn direct_seed_failure_defers_to_runtime_snapshot_only_in_non_public_v211() {
        assert!(direct_seed_failure_can_defer_to_runtime_snapshot_v211(
            false
        ));
        assert!(!direct_seed_failure_can_defer_to_runtime_snapshot_v211(
            true
        ));
    }

    #[test]
    fn cold_start_runtime_snapshot_pending_skips_pre_snapshot_storage_mirror_v211() {
        let out_dir = Some(PathBuf::from("/tmp/newgen-v211-coldstart"));
        assert!(cold_start_runtime_snapshot_pending_v211(
            &out_dir,
            Some(P2pBootPhase::ColdStartSnapshot)
        ));
        assert!(!cold_start_runtime_snapshot_pending_v211(
            &out_dir,
            Some(P2pBootPhase::FallbackLiveSync)
        ));
        assert!(!cold_start_runtime_snapshot_pending_v211(
            &None,
            Some(P2pBootPhase::ColdStartSnapshot)
        ));
    }

    #[test]
    fn cold_start_runtime_snapshot_failure_is_fail_closed_even_with_large_gap_opt_in_v211() {
        assert_eq!(
            decide_runtime_snapshot_failure_plan_v211(
                Some(P2pBootPhase::ColdStartSnapshot),
                false,
                true
            ),
            RuntimeActorBootstrapFailurePlan::FailClosed
        );
        assert_eq!(
            decide_runtime_snapshot_failure_plan_v211(
                Some(P2pBootPhase::FallbackLiveSync),
                false,
                true
            ),
            RuntimeActorBootstrapFailurePlan::EnterFallbackLiveSync
        );
    }

    #[test]
    fn explicit_snapshot_json_fallback_env_is_off_by_default_v198() {
        with_env_vars(
            &[(
                "NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK",
                None::<&str>,
            )],
            || {
                assert!(!allow_snapshot_coldstart_json_fallback_env_v1());
            },
        );
    }

    #[test]
    fn explicit_snapshot_json_fallback_requires_explicit_lab_opt_in_v198() {
        with_env_vars(
            &[("NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK", Some("1"))],
            || {
                assert!(allow_snapshot_coldstart_json_fallback_env_v1());
            },
        );
        with_env_vars(
            &[(
                "NEWGEN_ALLOW_SNAPSHOT_COLDSTART_JSON_FALLBACK",
                Some("false"),
            )],
            || {
                assert!(!allow_snapshot_coldstart_json_fallback_env_v1());
            },
        );
    }

    #[test]
    fn collect_seed_multiaddrs_reads_statesync_seeds_for_direct_coldstart_v197() {
        with_env_vars(
            &[
                ("NEWGEN_BOOTSTRAP_PEERS", None::<&str>),
                (
                    "NEWGEN_STATESYNC_SEEDS",
                    Some("/ip4/127.0.0.1/tcp/7001/p2p/12D3KooWStateSyncSeed"),
                ),
            ],
            || {
                let seeds = collect_seed_multiaddrs(None);
                assert_eq!(
                    seeds,
                    vec!["/ip4/127.0.0.1/tcp/7001/p2p/12D3KooWStateSyncSeed".to_string()]
                );
            },
        );
    }

    #[test]
    fn quarantine_invalid_runtime_db_moves_old_dir_and_recreates_db_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::write(db_dir.join("sentinel.bin"), b"old").unwrap();

        let backup = quarantine_runtime_db_dir_for_cold_start(&db_dir, "TEST")
            .unwrap()
            .expect("backup path expected");

        assert!(db_dir.exists(), "db dir should be recreated");
        assert!(
            db_dir.read_dir().unwrap().next().is_none(),
            "recreated db dir must be empty"
        );
        assert!(backup.exists(), "quarantine backup should exist");
        assert!(
            backup.join("sentinel.bin").exists(),
            "old data must be preserved in quarantine backup"
        );
    }

    #[test]
    fn statesync_self_restart_plan_starts_new_chain_when_window_expired() {
        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_ATTEMPT_ENV, Some("3")),
                (STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV, Some("1000")),
                (STATESYNC_SELF_RESTART_WINDOW_MS_ENV, Some("5000")),
                (STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV, Some("4")),
            ],
            || {
                let plan = compute_statesync_self_restart_plan(7_000).unwrap();
                assert_eq!(plan.attempt, 1);
                assert_eq!(plan.first_at_ms, 7_000);
            },
        );
    }

    #[test]
    fn statesync_self_restart_plan_increments_attempt_within_window() {
        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_ATTEMPT_ENV, Some("1")),
                (STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV, Some("2000")),
                (STATESYNC_SELF_RESTART_WINDOW_MS_ENV, Some("10000")),
                (STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV, Some("4")),
            ],
            || {
                let plan = compute_statesync_self_restart_plan(6_000).unwrap();
                assert_eq!(plan.attempt, 2);
                assert_eq!(plan.first_at_ms, 2_000);
            },
        );
    }

    #[test]
    fn statesync_self_restart_plan_trips_guard_after_max_attempts() {
        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_ATTEMPT_ENV, Some("3")),
                (STATESYNC_SELF_RESTART_FIRST_AT_MS_ENV, Some("2000")),
                (STATESYNC_SELF_RESTART_WINDOW_MS_ENV, Some("10000")),
                (STATESYNC_SELF_RESTART_MAX_ATTEMPTS_ENV, Some("3")),
            ],
            || {
                let err = compute_statesync_self_restart_plan(6_000).unwrap_err();
                assert!(err.contains("self-restart guard tripped"));
            },
        );
    }

    #[test]
    fn rewrite_restart_args_replaces_split_data_dir_with_absolute_path() {
        let rewritten = rewrite_statesync_self_restart_args_with_effective_data_dir(
            vec![
                OsString::from("--node"),
                OsString::from("D"),
                OsString::from("--data-dir"),
                OsString::from(r".\runtime\D"),
                OsString::from("--port"),
                OsString::from("7004"),
            ],
            Path::new(r"C:\work\CODE_ASSETS\runtime\D"),
        );

        let rewritten: Vec<String> = rewritten
            .into_iter()
            .map(|v| v.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            rewritten,
            vec![
                "--node",
                "D",
                "--data-dir",
                r"C:\work\CODE_ASSETS\runtime\D",
                "--port",
                "7004",
            ]
        );
    }

    #[test]
    fn rewrite_restart_args_replaces_inline_data_dir_with_absolute_path() {
        let rewritten = rewrite_statesync_self_restart_args_with_effective_data_dir(
            vec![
                OsString::from("--node"),
                OsString::from("D"),
                OsString::from(r"--data-dir=.\runtime\D"),
            ],
            Path::new(r"C:\work\CODE_ASSETS\runtime\D"),
        );

        let rewritten: Vec<String> = rewritten
            .into_iter()
            .map(|v| v.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            rewritten,
            vec![
                "--node",
                "D",
                "--data-dir",
                r"C:\work\CODE_ASSETS\runtime\D",
            ]
        );
    }

    #[test]
    fn paths_match_best_effort_accepts_canonical_equivalent_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("runtime").join("D");
        std::fs::create_dir_all(&actual).unwrap();
        let canonical = std::fs::canonicalize(&actual).unwrap();
        assert!(paths_match_best_effort(&canonical, &actual));
        assert!(paths_match_best_effort(&actual, &canonical));
    }

    #[test]
    fn validate_restart_boot_context_requires_materialized_db_and_context_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("runtime").join("D");
        std::fs::create_dir_all(actual.join("config")).unwrap();
        std::fs::create_dir_all(actual.join("db").join("keyspaces")).unwrap();
        std::fs::write(actual.join("config").join("governance.json"), b"{}").unwrap();
        std::fs::write(actual.join("db").join("keyspaces").join("sentinel"), b"ok").unwrap();
        let paths = NodePaths::from_data_dir(&actual);
        let ctx_path = write_statesync_self_restart_context("D", &paths, 1207).unwrap();

        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_REASON_ENV, Some("statesync_import")),
                (
                    STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV,
                    Some(actual.to_string_lossy().as_ref()),
                ),
            ],
            || {
                validate_statesync_self_restart_boot_context("D", &paths).unwrap();
                validate_statesync_self_restart_loaded_tip("D", &paths, 1207).unwrap();
            },
        );

        assert!(
            !ctx_path.exists(),
            "restart context should be removed after successful continuity validation"
        );
    }

    #[test]
    fn validate_restart_loaded_tip_rejects_regression_below_imported_height() {
        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("runtime").join("D");
        std::fs::create_dir_all(actual.join("config")).unwrap();
        std::fs::create_dir_all(actual.join("db").join("keyspaces")).unwrap();
        std::fs::write(actual.join("config").join("governance.json"), b"{}").unwrap();
        std::fs::write(actual.join("db").join("keyspaces").join("sentinel"), b"ok").unwrap();
        let paths = NodePaths::from_data_dir(&actual);
        write_statesync_self_restart_context("D", &paths, 1207).unwrap();

        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_REASON_ENV, Some("statesync_import")),
                (
                    STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV,
                    Some(actual.to_string_lossy().as_ref()),
                ),
            ],
            || {
                validate_statesync_self_restart_boot_context("D", &paths).unwrap();
                let err = validate_statesync_self_restart_loaded_tip("D", &paths, 0).unwrap_err();
                assert!(err.contains("tip regression"));
            },
        );
    }

    #[test]
    fn validate_restart_boot_context_rejects_data_dir_mismatch_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("runtime").join("D");
        let expected = tmp.path().join("runtime").join("expected_D");
        std::fs::create_dir_all(actual.join("config")).unwrap();
        std::fs::create_dir_all(actual.join("db")).unwrap();
        std::fs::write(actual.join("config").join("governance.json"), b"{}").unwrap();
        let paths = NodePaths::from_data_dir(&actual);

        with_env_vars(
            &[
                (STATESYNC_SELF_RESTART_REASON_ENV, Some("statesync_import")),
                (
                    STATESYNC_SELF_RESTART_EXPECTED_DATA_DIR_ENV,
                    Some(expected.to_string_lossy().as_ref()),
                ),
            ],
            || {
                let err = validate_statesync_self_restart_boot_context("D", &paths).unwrap_err();
                assert!(err.contains("data-dir mismatch"));
            },
        );
    }
}
