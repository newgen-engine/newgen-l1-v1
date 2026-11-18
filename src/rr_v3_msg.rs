use crate::checkpoint::CheckpointCert;
use crate::headers::BlockHeader;
use crate::snapshot::SnapshotMeta;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RrV3Msg {
    // Existing v3 header sync
    GetHeaders {
        from_height: u64,
        limit: u32,
    },
    Headers {
        headers: Vec<BlockHeader>,
    },

    // Phase 5 — Snapshot v2 (chunked bundle) over RR v3
    GetSnapshotV2Latest,
    GetSnapshotV2Meta {
        height: u64,
    },
    SnapshotV2Meta {
        meta: Option<SnapshotMeta>,
        meta_sha256_hex: Option<String>,
    },

    GetSnapshotV2Chunk {
        height: u64,
        chunk_index: u32,
    },
    SnapshotV2Chunk {
        height: u64,
        chunk_index: u32,
        data_b64: String,
    },

    // Mainnet — Checkpoint Cert (trust anchor) discovery over RR v3
    GetCheckpointCertLatest,
    CheckpointCertLatest {
        cert: Option<CheckpointCert>,
        cert_sha256_hex: Option<String>,
    },

    Error {
        code: u32,
        message: String,
    },
}

pub fn encode_v3_result(msg: &RrV3Msg) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}

/// Legacy: logga su errore e ritorna vec vuoto (caller dovrebbe droppare).
pub fn encode_v3(msg: &RrV3Msg) -> Vec<u8> {
    match encode_v3_result(msg) {
        Ok(v) => v,
        Err(e) => {
            ng_error!(target: "p2p.rrv3", "encode_v3 failed: {e}");
            Vec::new()
        }
    }
}

pub fn decode_v3(data: &[u8]) -> Option<RrV3Msg> {
    serde_json::from_slice(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{Council, GovernanceParams, GovernanceState, ValidatorSet};
    use crate::snapshot::SnapshotStateCoverageMode;

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

    fn sample_meta() -> SnapshotMeta {
        SnapshotMeta {
            version: 2,
            height: 10,
            base_height: 8,
            bytes_len: 123,
            chunk_size: 32,
            chunks: 2,
            chunk_hashes_hex: vec!["aa".repeat(32), "bb".repeat(32)],
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

    #[test]
    fn snapshot_meta_message_roundtrip() {
        let msg = RrV3Msg::SnapshotV2Meta {
            meta: Some(sample_meta()),
            meta_sha256_hex: Some("aa".repeat(32)),
        };
        let enc = encode_v3_result(&msg).unwrap();
        let dec = decode_v3(&enc).unwrap();
        assert_eq!(format!("{:?}", dec), format!("{:?}", msg));
    }

    #[test]
    fn error_message_roundtrip() {
        let msg = RrV3Msg::Error {
            code: 42,
            message: "bad-snapshot".to_string(),
        };
        let enc = encode_v3(&msg);
        let dec = decode_v3(&enc).unwrap();
        assert_eq!(format!("{:?}", dec), format!("{:?}", msg));
    }
}
