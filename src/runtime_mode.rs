#[cfg(test)]
use std::{
    cell::Cell,
    sync::{Mutex, MutexGuard, OnceLock},
};

fn parse_boolish(raw: &str) -> Option<bool> {
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" | "" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeModeError {
    InvalidBooleanPayload { var: &'static str, value: String },
    AliasMismatch { canonical: String, legacy: String },
}

impl std::fmt::Display for RuntimeModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBooleanPayload { var, value } => {
                write!(f, "Invalid boolean payload for {}: '{}'", var, value)
            }
            Self::AliasMismatch { canonical, legacy } => write!(
                f,
                "Public-mode env mismatch: NEWGEN_PUBLIC={} but NEWGEN_PUBLIC_MODE={}",
                canonical, legacy
            ),
        }
    }
}

impl std::error::Error for RuntimeModeError {}

#[cfg(test)]
fn read_bool_env(name: &str) -> Option<bool> {
    std::env::var(name).ok().and_then(|v| parse_boolish(&v))
}

#[cfg(test)]
fn test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
thread_local! {
    static TEST_ENV_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
struct TestEnvLockGuard {
    _guard: Option<MutexGuard<'static, ()>>,
    held_prev: bool,
}

#[cfg(test)]
impl TestEnvLockGuard {
    fn new() -> Self {
        let mut held_prev = false;
        let mut guard_opt = None;

        TEST_ENV_LOCK_HELD.with(|c| {
            if c.get() {
                held_prev = true;
            } else {
                // Acquire the global lock and mark as held for this thread.
                let g = test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
                c.set(true);
                guard_opt = Some(g);
            }
        });

        Self {
            _guard: guard_opt,
            held_prev,
        }
    }
}

#[cfg(test)]
impl Drop for TestEnvLockGuard {
    fn drop(&mut self) {
        if !self.held_prev {
            TEST_ENV_LOCK_HELD.with(|c| c.set(false));
            // _guard drops here
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct EnvGuard {
    prev_public: Option<String>,
    prev_public_mode: Option<String>,
    prev_network_mode: Option<String>,
}

#[cfg(test)]
impl EnvGuard {
    fn new_clean() -> Self {
        let prev_public = std::env::var("NEWGEN_PUBLIC").ok();
        let prev_public_mode = std::env::var("NEWGEN_PUBLIC_MODE").ok();
        let prev_network_mode = std::env::var("NEWGEN_NETWORK_MODE").ok();

        // Clear for a clean baseline
        std::env::remove_var("NEWGEN_PUBLIC");
        std::env::remove_var("NEWGEN_PUBLIC_MODE");
        std::env::remove_var("NEWGEN_NETWORK_MODE");

        Self {
            prev_public,
            prev_public_mode,
            prev_network_mode,
        }
    }
}

#[cfg(test)]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev_public {
            Some(v) => std::env::set_var("NEWGEN_PUBLIC", v),
            None => std::env::remove_var("NEWGEN_PUBLIC"),
        }
        match &self.prev_public_mode {
            Some(v) => std::env::set_var("NEWGEN_PUBLIC_MODE", v),
            None => std::env::remove_var("NEWGEN_PUBLIC_MODE"),
        }
        match &self.prev_network_mode {
            Some(v) => std::env::set_var("NEWGEN_NETWORK_MODE", v),
            None => std::env::remove_var("NEWGEN_NETWORK_MODE"),
        }
    }
}

/// Canonical public-mode resolver for the whole runtime.
///
/// Rules:
/// - `NEWGEN_PUBLIC` is the canonical source of truth.
/// - `NEWGEN_PUBLIC_MODE` is accepted only as a backward-compatible alias.
/// - If both are present and disagree, the resolver returns an error.
/// - If either variable contains an invalid boolean payload, the resolver returns an error.
pub fn try_public_mode_enabled() -> Result<bool, RuntimeModeError> {
    #[cfg(test)]
    let _g = TestEnvLockGuard::new();

    let canonical_raw = std::env::var("NEWGEN_PUBLIC").ok();
    let legacy_raw = std::env::var("NEWGEN_PUBLIC_MODE").ok();

    let canonical = canonical_raw
        .as_deref()
        .map(|v| {
            parse_boolish(v).ok_or_else(|| RuntimeModeError::InvalidBooleanPayload {
                var: "NEWGEN_PUBLIC",
                value: v.to_string(),
            })
        })
        .transpose()?;
    let legacy = legacy_raw
        .as_deref()
        .map(|v| {
            parse_boolish(v).ok_or_else(|| RuntimeModeError::InvalidBooleanPayload {
                var: "NEWGEN_PUBLIC_MODE",
                value: v.to_string(),
            })
        })
        .transpose()?;

    match (canonical, legacy) {
        (Some(a), Some(b)) if a != b => Err(RuntimeModeError::AliasMismatch {
            canonical: canonical_raw.as_deref().unwrap_or("<unset>").to_string(),
            legacy: legacy_raw.as_deref().unwrap_or("<unset>").to_string(),
        }),
        (Some(v), _) => Ok(v),
        (None, Some(v)) => Ok(v),
        (None, None) => Ok(false),
    }
}

pub fn public_mode_enabled() -> bool {
    match try_public_mode_enabled() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "❌ [BOOT] Runtime mode configuration error: {}. Entering public_mode fail-closed.",
                e
            );
            true
        }
    }
}

/// Exports the canonical runtime mode to all supported env aliases.
///
/// This is the only function that should write public-mode env state.
pub fn export_public_mode(enabled: bool) {
    let v = if enabled { "1" } else { "0" };
    let network_mode = if enabled { "public" } else { "dev" };
    std::env::set_var("NEWGEN_PUBLIC", v);
    std::env::set_var("NEWGEN_PUBLIC_MODE", v);
    std::env::set_var("NEWGEN_NETWORK_MODE", network_mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_false_when_unset() {
        let _l = TestEnvLockGuard::new();
        let _g = EnvGuard::new_clean();
        assert!(!public_mode_enabled());
    }

    #[test]
    fn canonical_env_is_respected() {
        let _l = TestEnvLockGuard::new();
        let _g = EnvGuard::new_clean();
        std::env::set_var("NEWGEN_PUBLIC", "1");
        assert!(public_mode_enabled());
    }

    #[test]
    fn legacy_alias_is_respected_for_backcompat() {
        let _l = TestEnvLockGuard::new();
        let _g = EnvGuard::new_clean();
        std::env::set_var("NEWGEN_PUBLIC_MODE", "true");
        assert!(public_mode_enabled());
    }

    #[test]
    fn mismatch_is_reported_as_error() {
        let _l = TestEnvLockGuard::new();
        let _g = EnvGuard::new_clean();
        std::env::set_var("NEWGEN_PUBLIC", "1");
        std::env::set_var("NEWGEN_PUBLIC_MODE", "0");
        let err = try_public_mode_enabled().expect_err("must fail");
        assert!(err.to_string().contains("Public-mode env mismatch"));
    }

    #[test]
    fn export_sets_both_aliases_and_network_mode() {
        let _l = TestEnvLockGuard::new();
        let _g = EnvGuard::new_clean();
        export_public_mode(true);
        assert_eq!(read_bool_env("NEWGEN_PUBLIC"), Some(true));
        assert_eq!(read_bool_env("NEWGEN_PUBLIC_MODE"), Some(true));
        assert_eq!(std::env::var("NEWGEN_NETWORK_MODE").unwrap(), "public");
    }
}
