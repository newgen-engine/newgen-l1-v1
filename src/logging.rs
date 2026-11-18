// src/logging.rs
// Zero-deps, dual-stream logger for NewGen Engine
// - Console: INFO (default) + WARN/ERROR
// - File: DEBUG (default) (or TRACE)
// - Structured single-line logs with node_tag
// - Throttling
// - Size-based rotation

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
static TEST_LOG_CAPTURE: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

#[cfg(test)]
fn test_log_capture_buf() -> &'static Mutex<Vec<String>> {
    TEST_LOG_CAPTURE.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(test)]
fn capture_test_log_line(line: &str) {
    if let Ok(mut buf) = test_log_capture_buf().lock() {
        buf.push(line.to_string());
    }
}

#[cfg(test)]
pub fn clear_test_log_capture() {
    if let Ok(mut buf) = test_log_capture_buf().lock() {
        buf.clear();
    }
}

#[cfg(test)]
pub fn snapshot_test_log_capture() -> Vec<String> {
    test_log_capture_buf()
        .lock()
        .map(|buf| buf.clone())
        .unwrap_or_default()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct InitOptions {
    pub node_tag: String,
    pub console_level: Level,
    pub file_level: Level,
    pub file_path: Option<PathBuf>,
    pub rotate_bytes: u64,
    pub rotate_keep: usize,
    pub file_overwrite: bool,
}

impl InitOptions {
    pub fn from_env(node_tag: String, file_path: Option<PathBuf>) -> Self {
        let console_level = std::env::var("NEWGEN_LOG")
            .ok()
            .and_then(|v| Level::parse(&v))
            .or_else(|| {
                std::env::var("RUST_LOG")
                    .ok()
                    .and_then(|v| Level::parse(&v))
            })
            .unwrap_or(Level::Info);

        let file_level = std::env::var("NEWGEN_LOG_FILE")
            .ok()
            .and_then(|v| Level::parse(&v))
            .unwrap_or(Level::Debug);

        let rotate_mb = std::env::var("NEWGEN_LOG_ROTATE_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100);

        let rotate_keep = std::env::var("NEWGEN_LOG_ROTATE_KEEP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5);

        let file_overwrite = std::env::var("NEWGEN_LOG_FILE_OVERWRITE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        Self {
            node_tag,
            console_level,
            file_level,
            file_path,
            rotate_bytes: rotate_mb.saturating_mul(1024).saturating_mul(1024),
            rotate_keep: rotate_keep.max(1),
            file_overwrite,
        }
    }
}

struct FileSink {
    path: PathBuf,
    file: File,
    bytes_written: u64,
    rotate_bytes: u64,
    rotate_keep: usize,
    last_rotate_fail_ms: u128,
}

impl FileSink {
    fn open(
        path: PathBuf,
        overwrite: bool,
        rotate_bytes: u64,
        rotate_keep: usize,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if overwrite {
            opts.truncate(true);
        } else {
            opts.append(true);
        }
        let file = opts.open(&path)?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            file,
            bytes_written,
            rotate_bytes,
            rotate_keep,
            last_rotate_fail_ms: 0,
        })
    }

    fn rotate_if_needed(&mut self) {
        if self.rotate_bytes == 0 || self.bytes_written < self.rotate_bytes {
            return;
        }

        // Avoid tight rotation loops if rotation is failing (e.g., Windows rename blocked by a viewer)
        let now = now_ms();
        if self.last_rotate_fail_ms != 0 && now.saturating_sub(self.last_rotate_fail_ms) < 60_000 {
            return;
        }

        // Flush best-effort before rotating
        let _ = self.file.flush();

        let base = self.path.clone();
        let dir = base.parent().unwrap_or(Path::new("."));
        let tmp_path = dir.join(format!(".newgen_log_rotate_{}.tmp", std::process::id()));

        // Open a temp file so we can drop the handle to `base` before rename (important on Windows).
        let tmp_file = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
        {
            Ok(f) => f,
            Err(_) => {
                self.last_rotate_fail_ms = now;
                return;
            }
        };

        // Replace handle (drops old handle to base)
        let old = std::mem::replace(&mut self.file, tmp_file);
        drop(old);

        // Ensure destination for oldest is free (Windows rename doesn't overwrite)
        let oldest = base.with_extension(format!("log.{}", self.rotate_keep));
        let _ = std::fs::remove_file(&oldest);

        // Shift: .1 -> .2 ... (.keep-1) -> .keep
        for i in (1..self.rotate_keep).rev() {
            let src = base.with_extension(format!("log.{}", i));
            let dst = base.with_extension(format!("log.{}", i + 1));
            if src.exists() {
                let _ = std::fs::rename(&src, &dst);
            }
        }

        // Move base -> .1
        let first = base.with_extension("log.1");
        if std::fs::rename(&base, &first).is_err() {
            // Rotation blocked. Reopen base in append mode and keep going.
            match OpenOptions::new().create(true).append(true).open(&base) {
                Ok(f) => {
                    self.file = f;
                }
                Err(_) => {
                    // keep temp handle; next writes will go to temp
                }
            }
            self.last_rotate_fail_ms = now;
            let _ = std::fs::remove_file(&tmp_path);
            return;
        }

        // Reopen base truncated (new current log)
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&base)
        {
            Ok(f) => {
                self.file = f;
                self.bytes_written = 0;
            }
            Err(_) => {
                self.last_rotate_fail_ms = now;
                // If reopen fails, fallback to temp handle; caller will continue writing.
            }
        }

        let _ = std::fs::remove_file(&tmp_path);
    }

    fn write_line(&mut self, line: &str, flush: bool) {
        self.rotate_if_needed();
        if let Ok(n) = self.file.write(line.as_bytes()) {
            self.bytes_written = self.bytes_written.saturating_add(n as u64);
        }
        let _ = self.file.write_all(b"\n");
        self.bytes_written = self.bytes_written.saturating_add(1);
        if flush {
            let _ = self.file.flush();
        }
    }

    fn flush(&mut self) {
        let _ = self.file.flush();
    }
}

struct LoggerInner {
    file: Option<FileSink>,
}

pub struct Logger {
    node: String,
    console_level: Level,
    file_level: Level,
    inner: Mutex<LoggerInner>,
    throttle: Mutex<HashMap<String, u128>>, // last_ts_ms
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn is_initialized() -> bool {
    LOGGER.get().is_some()
}

pub fn init(opts: InitOptions) {
    // idempotent
    if LOGGER.get().is_some() {
        return;
    }

    let file = opts.file_path.clone().and_then(|p| {
        FileSink::open(p, opts.file_overwrite, opts.rotate_bytes, opts.rotate_keep).ok()
    });

    let logger = Logger {
        node: opts.node_tag,
        console_level: opts.console_level,
        file_level: opts.file_level,
        inner: Mutex::new(LoggerInner { file }),
        throttle: Mutex::new(HashMap::new()),
    };

    let _ = LOGGER.set(logger);

    // Panic hook: best-effort immediate flush
    std::panic::set_hook(Box::new(|panic_info| {
        // Minimal lock usage; try_lock to avoid deadlock during panic.
        if let Some(lg) = LOGGER.get() {
            let msg = format!("panic: {}", panic_info);
            lg.log_internal(Level::Error, "panic", &msg, true);
            lg.flush_best_effort();
        } else {
            let _ = writeln!(io::stderr(), "panic: {}", panic_info);
        }
    }));
}

pub fn init_from_env(node_tag: String, file_path: Option<PathBuf>) {
    init(InitOptions::from_env(node_tag, file_path));
}

pub fn ensure_initialized_from_env(node_tag: &str, file_path: Option<PathBuf>) {
    if is_initialized() {
        return;
    }
    init_from_env(node_tag.to_string(), file_path);
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.flush_best_effort();
    }
}

impl Logger {
    fn flush_best_effort(&self) {
        if let Ok(mut inner) = self.inner.try_lock() {
            if let Some(f) = inner.file.as_mut() {
                f.flush();
            }
        }
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
    }

    fn should_log(&self, level: Level) -> (bool, bool) {
        let to_console = level <= self.console_level;
        let to_file = level <= self.file_level;
        (to_console, to_file)
    }

    fn log_internal(&self, level: Level, target: &str, msg: &str, force_flush: bool) {
        let ts = now_ms();
        let line = format!(
            "ts={} level={} node={} target={} {}",
            ts,
            level.as_str(),
            self.node,
            target,
            msg
        );

        #[cfg(test)]
        capture_test_log_line(&line);

        let (to_console, to_file) = self.should_log(level);

        if to_console {
            // WARN/ERROR to stderr, others to stdout
            if level <= Level::Warn {
                let _ = writeln!(io::stderr(), "{}", line);
            } else {
                let _ = writeln!(io::stdout(), "{}", line);
            }
        }

        if to_file {
            if let Ok(mut inner) = self.inner.lock() {
                if let Some(f) = inner.file.as_mut() {
                    // flush WARN/ERROR or forced flush
                    let flush = force_flush || level <= Level::Warn;
                    f.write_line(&line, flush);
                }
            }
        }

        if force_flush || level <= Level::Warn {
            let _ = io::stderr().flush();
            let _ = io::stdout().flush();
        }
    }

    fn should_log_throttle(&self, key: &str, every_ms: u64) -> bool {
        let now = now_ms();
        if let Ok(mut map) = self.throttle.lock() {
            let last = map.get(key).copied().unwrap_or(0);
            if now.saturating_sub(last) >= every_ms as u128 {
                map.insert(key.to_string(), now);
                return true;
            }
        }
        false
    }
}

pub fn log(level: Level, target: &str, args: fmt::Arguments<'_>) {
    if let Some(lg) = LOGGER.get() {
        let (to_console, to_file) = lg.should_log(level);
        if !to_console && !to_file {
            return;
        }
        let mut s = String::new();
        let _ = fmt::write(&mut s, args);
        lg.log_internal(level, target, &s, false);
    } else {
        // Fallback: console only
        let mut s = String::new();
        let _ = fmt::write(&mut s, args);
        #[cfg(test)]
        {
            let line = format!("level={} target={} {}", level.as_str(), target, s);
            capture_test_log_line(&line);
        }
        let _ = writeln!(io::stderr(), "{}", s);
    }
}

pub fn log_throttle<K: Into<String>>(
    level: Level,
    key: K,
    every_ms: u64,
    target: &str,
    args: fmt::Arguments<'_>,
) {
    let key: String = key.into();
    if let Some(lg) = LOGGER.get() {
        let (to_console, to_file) = lg.should_log(level);
        if !to_console && !to_file {
            return;
        }
        if !lg.should_log_throttle(&key, every_ms) {
            return;
        }
        let mut s = String::new();
        let _ = fmt::write(&mut s, args);
        lg.log_internal(level, target, &s, false);
    } else {
        // If logger not initialized, do not throttle; write once.
        log(level, target, args);
    }
}

pub fn flush() {
    if let Some(lg) = LOGGER.get() {
        lg.flush_best_effort();
    }
}

// ---- Macros (crate-wide) ----

#[macro_export]
macro_rules! ng_error {
    (target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Error, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_warn {
    (target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Warn, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_info {
    (target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Info, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_debug {
    (target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Debug, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_trace {
    (target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Trace, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_error_throttle {
    (key: $key:expr, every_ms: $every:expr, target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log_throttle($crate::logging::Level::Error, $key, $every, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_warn_throttle {
    (key: $key:expr, every_ms: $every:expr, target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log_throttle($crate::logging::Level::Warn, $key, $every, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_info_throttle {
    (key: $key:expr, every_ms: $every:expr, target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log_throttle($crate::logging::Level::Info, $key, $every, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_debug_throttle {
    (key: $key:expr, every_ms: $every:expr, target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log_throttle($crate::logging::Level::Debug, $key, $every, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! ng_trace_throttle {
    (key: $key:expr, every_ms: $every:expr, target: $target:expr, $($arg:tt)*) => {
        $crate::logging::log_throttle($crate::logging::Level::Trace, $key, $every, $target, format_args!($($arg)*))
    };
}
