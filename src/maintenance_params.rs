// src/maintenance_params.rs
//
// Consensus-critical maintenance parameters (pruning / housekeeping / snapshot cadence)
// anchored in the SMT.
// Stored under sys/maintenance/params as an AccountState.data record.
//
// Record format:
//   [data_version:u8][tag:u8][bincode(payload)]
//
// v1: pruning-only
// v2: pruning + snapshot cadence + prune gating

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::account::AccountState;
use crate::state_smt::{bytes32_from_hex, sys_key, StateSmt};
use crate::storage::DbStore;

pub const MAINT_DATA_VERSION_V1: u8 = 1;
pub const MAINT_DATA_VERSION_V2: u8 = 2;

const TAG_PARAMS: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceParamsV1 {
    /// Keep at least this many recent blocks available (rollback/pruning window).
    pub retain_window_blocks: u64,
    /// Run pruning maintenance every N blocks (soft cadence).
    pub prune_every_n_blocks: u64,
    /// Cap work per maintenance tick (safety guard).
    pub prune_max_blocks_per_run: u64,
}

impl Default for MaintenanceParamsV1 {
    fn default() -> Self {
        Self {
            // Default values chosen to match the previous maintenance loop defaults.
            retain_window_blocks: 50_000,
            prune_every_n_blocks: 512,
            prune_max_blocks_per_run: 10_000,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceParamsV2 {
    /// Keep at least this many recent blocks available (rollback/pruning window).
    pub retain_window_blocks: u64,
    /// Run pruning maintenance every N blocks (soft cadence).
    pub prune_every_n_blocks: u64,
    /// Cap work per maintenance tick (safety guard).
    pub prune_max_blocks_per_run: u64,

    /// Export snapshot v2 bundle every K blocks (soft cadence).
    pub snapshot_every_n_blocks: u64,
    /// Snapshot chunk size (bytes). Used by snapshot v2 exporter.
    pub snapshot_chunk_size: u64,
    /// Maximum snapshot bundle size (bytes). Hard safety cap.
    pub snapshot_max_bytes: u64,
    /// If true, include only reachable state nodes from tip state_root.
    pub snapshot_reachable_only: bool,

    /// If true, pruning is allowed only when a recent snapshot has succeeded.
    pub prune_requires_snapshot: bool,
}

impl Default for MaintenanceParamsV2 {
    fn default() -> Self {
        // Mainnet-safe defaults: snapshot cadence aligned to pruning cadence by default.
        Self {
            retain_window_blocks: 50_000,
            prune_every_n_blocks: 512,
            prune_max_blocks_per_run: 10_000,

            snapshot_every_n_blocks: 512,
            snapshot_chunk_size: 4 * 1024 * 1024,  // 4 MiB
            snapshot_max_bytes: 512 * 1024 * 1024, // 512 MiB
            snapshot_reachable_only: true,

            prune_requires_snapshot: true,
        }
    }
}

impl From<MaintenanceParamsV1> for MaintenanceParamsV2 {
    fn from(v1: MaintenanceParamsV1) -> Self {
        MaintenanceParamsV2 {
            retain_window_blocks: v1.retain_window_blocks,
            prune_every_n_blocks: v1.prune_every_n_blocks,
            prune_max_blocks_per_run: v1.prune_max_blocks_per_run,
            ..MaintenanceParamsV2::default()
        }
    }
}

pub fn k_maintenance_params() -> [u8; 32] {
    sys_key("maintenance/params")
}

fn bincode_fixed_le() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

fn as_state_from_data(data: Vec<u8>) -> AccountState {
    AccountState {
        nonce: 0,
        balance: 0,
        data,
    }
}

fn enc_record<T: Serialize>(ver: u8, tag: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.push(ver);
    out.push(tag);
    let payload = bincode_fixed_le()
        .serialize(v)
        .map_err(|e| format!("bincode serialize: {e}"))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

fn dec_record<T: for<'de> Deserialize<'de>>(
    expected_ver: u8,
    tag: u8,
    data: &[u8],
) -> Result<T, String> {
    if data.len() < 2 {
        return Err("maint_data_too_short".to_string());
    }
    if data[0] != expected_ver {
        return Err(format!(
            "maint_bad_version expected={} got={}",
            expected_ver, data[0]
        ));
    }
    if data[1] != tag {
        return Err(format!("maint_bad_tag expected={} got={}", tag, data[1]));
    }
    bincode_fixed_le()
        .deserialize(&data[2..])
        .map_err(|e| format!("bincode deserialize: {e}"))
}

pub fn encode_params_state_v1(params: &MaintenanceParamsV1) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(
        MAINT_DATA_VERSION_V1,
        TAG_PARAMS,
        params,
    )?))
}

pub fn encode_params_state(params: &MaintenanceParamsV2) -> Result<AccountState, String> {
    Ok(as_state_from_data(enc_record(
        MAINT_DATA_VERSION_V2,
        TAG_PARAMS,
        params,
    )?))
}

/// Decode maintenance params from SMT record.
/// - If stored as v2: return v2.
/// - If stored as v1: upgrade to v2 using defaults for new fields.
pub fn decode_params_state_any(st: &AccountState) -> Result<MaintenanceParamsV2, String> {
    if st.data.len() < 2 {
        return Err("maint_data_too_short".to_string());
    }
    let ver = st.data[0];
    match ver {
        MAINT_DATA_VERSION_V2 => {
            dec_record::<MaintenanceParamsV2>(MAINT_DATA_VERSION_V2, TAG_PARAMS, &st.data)
        }
        MAINT_DATA_VERSION_V1 => {
            let v1 =
                dec_record::<MaintenanceParamsV1>(MAINT_DATA_VERSION_V1, TAG_PARAMS, &st.data)?;
            Ok(MaintenanceParamsV2::from(v1))
        }
        _ => Err(format!("maint_unsupported_version={}", ver)),
    }
}

/// Returns Ok(None) if the record does not exist (e.g. legacy chains), otherwise Ok(Some(params_v2)).
pub fn load_from_state_root(
    storage: &DbStore,
    state_root_hex: &str,
) -> Result<Option<MaintenanceParamsV2>, String> {
    let root = bytes32_from_hex(state_root_hex)?;
    let smt = StateSmt::new(storage.state_node_store());
    let k = k_maintenance_params();
    match smt.get_account(root, k) {
        Ok(Some(st)) => Ok(Some(decode_params_state_any(&st)?)),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("SMT get_account maintenance_params failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_decoding_upgrades_to_v2_defaults() {
        let v1 = MaintenanceParamsV1 {
            retain_window_blocks: 111,
            prune_every_n_blocks: 222,
            prune_max_blocks_per_run: 333,
        };
        let st = encode_params_state_v1(&v1).unwrap();
        let got = decode_params_state_any(&st).unwrap();
        assert_eq!(got.retain_window_blocks, 111);
        assert_eq!(got.prune_every_n_blocks, 222);
        assert_eq!(got.prune_max_blocks_per_run, 333);
        assert_eq!(
            got.snapshot_every_n_blocks,
            MaintenanceParamsV2::default().snapshot_every_n_blocks
        );
        assert!(got.prune_requires_snapshot);
    }

    #[test]
    fn v2_roundtrip_preserves_all_fields() {
        let params = MaintenanceParamsV2 {
            retain_window_blocks: 10,
            prune_every_n_blocks: 11,
            prune_max_blocks_per_run: 12,
            snapshot_every_n_blocks: 13,
            snapshot_chunk_size: 14,
            snapshot_max_bytes: 15,
            snapshot_reachable_only: false,
            prune_requires_snapshot: false,
        };
        let st = encode_params_state(&params).unwrap();
        let got = decode_params_state_any(&st).unwrap();
        assert_eq!(got, params);
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let st = AccountState {
            nonce: 0,
            balance: 0,
            data: vec![99, 1, 0, 0],
        };
        assert!(decode_params_state_any(&st)
            .unwrap_err()
            .contains("unsupported_version"));
    }
}
