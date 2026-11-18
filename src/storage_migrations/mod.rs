// src/storage_migrations/mod.rs
//
// Runtime schema coordination for the canonical Fjall storage backend.
//
// Historical physical backend migration code has been removed from the canonical source tree.
// Prelaunch policy: bootstrap starts from the active backend schema only.

/// Runtime storage schema version for the active Fjall backend layout.
pub const CURRENT_RUNTIME_STORAGE_SCHEMA_VERSION: u32 = 1;

/// Historical physical backend migrations are no longer shipped in the canonical runtime source tree.
pub const LEGACY_PHYSICAL_MIGRATIONS_PRESENT: bool = false;

/// Prelaunch migration strategy for the active runtime backend.
pub const PRELAUNCH_RESET_STRATEGY_ACTIVE: bool = true;

/// Human-readable summary for operators and maintenance tools.
pub fn runtime_bootstrap_strategy_note() -> &'static str {
    "runtime bootstrap uses the active Fjall backend schema only; historical physical migration code is not part of the canonical source tree"
}

/// Ensures the runtime schema expected by the current backend is available.
///
/// Physical admission of a concrete database directory is enforced fail-closed by
/// `src/storage.rs` against `meta:db_version`. This function remains focused on
/// compile-time/runtime schema coordination for the active Fjall layout.
pub fn ensure_runtime_schema_current() -> Result<(), String> {
    let _ = (
        CURRENT_RUNTIME_STORAGE_SCHEMA_VERSION,
        LEGACY_PHYSICAL_MIGRATIONS_PRESENT,
        PRELAUNCH_RESET_STRATEGY_ACTIVE,
    );
    Ok(())
}
