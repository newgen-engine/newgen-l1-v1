use std::sync::OnceLock;

use crate::version::{
    GIT_COMMIT, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION, SOFTWARE_VERSION,
};

/// Legacy sentinel (NOT a security anchor).
/// Kept only for backward compatibility with older tooling/logs.
pub const FINAL_HASH_HEX: &str = "7b5f7a48c0086eef1bdfcf3019b0c2dabb31aa9a47bf746d2e4847cfd87d9abc";

static BOOT_FINGERPRINT_ONCE: OnceLock<()> = OnceLock::new();

pub fn build_fingerprint() -> String {
    let git = GIT_COMMIT.unwrap_or("unknown");
    format!(
        "sw={} proto={} min_proto={} git={}",
        SOFTWARE_VERSION, PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION, git
    )
}

/// Logga una sola volta per processo: fingerprint build/protocollo.
///
/// Sicuro per canary/WAN: aiuta a capire “che binario gira” sui nodi remoti.
pub fn emit_boot_fingerprint_once(node_tag: &str) {
    if BOOT_FINGERPRINT_ONCE.set(()).is_ok() {
        ng_info!(
            target: "boot.fingerprint",
            "BuildFingerprint node={} {}",
            node_tag,
            build_fingerprint()
        );
    }
}

/// Banner opzionale controllato da env.
/// Default: OFF. Abilita con NEWGEN_PRINT_BANNER=1.
pub fn print_mission_accomplished() {
    let enabled = std::env::var("NEWGEN_PRINT_BANNER")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if enabled {
        ng_info!(
            target: "boot.banner",
            "🚀 MISSION ACCOMPLISHED 🚀 ({})",
            build_fingerprint()
        );
    }
}

/// Return true for common environment flag spellings.
pub fn env_flag_enabled_v1(name: &str) -> bool {
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

/// Unified CORS policy helper for debug-only allow-any behavior.
/// Debug builds may be permissive for local/dev, but public mode must never
/// inherit debug allow_any_origin implicitly.
pub fn debug_cors_allow_any_for_mode_v1(surface: &str, public_mode: bool) -> bool {
    if cfg!(debug_assertions) && !public_mode {
        true
    } else {
        if cfg!(debug_assertions) && public_mode {
            eprintln!(
                "⚠️ [{} CORS] debug allow_any_origin disabled because public_mode=true",
                surface
            );
        }
        false
    }
}

/// Unified CORS policy helper for env-requested allow-any behavior.
/// In public mode, a separate explicit public override is required so a legacy
/// dev env var cannot silently widen browser access.
pub fn requested_any_cors_allowed_for_mode_v1(
    surface: &str,
    requested_allow_any: bool,
    public_mode: bool,
    explicit_public_override: bool,
) -> bool {
    if requested_allow_any && public_mode && !explicit_public_override {
        eprintln!(
            "⚠️ [{} CORS] allow_any_origin request ignored because public_mode=true; set explicit public override only after review",
            surface
        );
        false
    } else {
        requested_allow_any
    }
}

/// Replace a file with a fully-written temporary file using the strongest
/// platform semantics available without changing the caller's persistence model.
///
/// Contract:
/// - caller must have already written and fsync'ed `tmp_path` when durability matters;
/// - on Unix, `rename(tmp, target)` is atomic over an existing file;
/// - on Windows, replacing an existing destination via rename may fail, so we try
///   a direct rename first, then the native MoveFileExW replace/write-through API,
///   and only then a documented remove+rename fallback. The fallback is intentionally
///   centralized here so Windows crash-window risk is explicit and auditable instead
///   of being duplicated ad hoc.
///
/// This helper also best-effort fsyncs the parent directory after a successful
/// replacement on Unix platforms.
pub fn atomic_replace_file_v1(
    tmp_path: &std::path::Path,
    target_path: &std::path::Path,
) -> std::io::Result<()> {
    match std::fs::rename(tmp_path, target_path) {
        Ok(()) => {
            fsync_parent_dir_best_effort_v1(target_path);
            Ok(())
        }
        Err(first_err) => {
            #[cfg(windows)]
            {
                match windows_move_file_ex_replace_v1(tmp_path, target_path) {
                    Ok(()) => {
                        fsync_parent_dir_best_effort_v1(target_path);
                        return Ok(());
                    }
                    Err(native_err) => {
                        eprintln!(
                            "⚠️ [ATOMIC REPLACE] native MoveFileExW replace failed for {} -> {}; falling back to remove+rename (direct rename: {}; native replace: {})",
                            tmp_path.display(),
                            target_path.display(),
                            first_err,
                            native_err
                        );
                        // Last-resort compatibility fallback for older Windows/filesystem/handle
                        // combinations. This is intentionally centralized and noisy; callers must
                        // not duplicate remove+rename ad hoc.
                        if target_path.exists() {
                            std::fs::remove_file(target_path)?;
                        }
                        std::fs::rename(tmp_path, target_path)
                            .map(|_| {
                                fsync_parent_dir_best_effort_v1(target_path);
                            })
                            .map_err(|second_err| {
                                std::io::Error::new(
                                    second_err.kind(),
                                    format!(
                                        "atomic_replace_file_v1 failed for {} -> {} (direct rename: {}; native replace: {}; fallback rename: {})",
                                        tmp_path.display(),
                                        target_path.display(),
                                        first_err,
                                        native_err,
                                        second_err
                                    ),
                                )
                            })
                    }
                }
            }
            #[cfg(not(windows))]
            {
                Err(first_err)
            }
        }
    }
}

#[cfg(windows)]
fn windows_move_file_ex_replace_v1(
    tmp_path: &std::path::Path,
    target_path: &std::path::Path,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }

    fn wide_null(path: &std::path::Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let src = wide_null(tmp_path);
    let dst = wide_null(target_path);
    let ok = unsafe {
        MoveFileExW(
            src.as_ptr(),
            dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn fsync_parent_dir_best_effort_v1(path: &std::path::Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
