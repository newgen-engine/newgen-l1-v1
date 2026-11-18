pub const COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1: u16 = 1;

fn default_cognitive_registry_surface_format_version_v1() -> u16 {
    COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum ChainSettlementStateV1 {
    Unknown,
    Unsettled,
    SettledPending,
    SettledFinal,
    Revoked,
    Disputed,
    Expired,
    Superseded,
}

impl ChainSettlementStateV1 {
    pub fn from_db_str(input: &str) -> Self {
        match input.trim().to_ascii_lowercase().as_str() {
            "unsettled" => Self::Unsettled,
            "settled_pending" => Self::SettledPending,
            "settled_final" => Self::SettledFinal,
            "revoked" => Self::Revoked,
            "disputed" | "contested" => Self::Disputed,
            "expired" => Self::Expired,
            "superseded" => Self::Superseded,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum ChainRegistryEffectiveStatusV1 {
    AnchoredPending,
    AnchoredFinal,
    Contested,
    Revoked,
    Superseded,
}

impl Default for ChainRegistryEffectiveStatusV1 {
    fn default() -> Self { Self::AnchoredPending }
}

impl ChainRegistryEffectiveStatusV1 {
    pub fn as_settlement_state(self) -> ChainSettlementStateV1 {
        match self {
            Self::AnchoredPending => ChainSettlementStateV1::SettledPending,
            Self::AnchoredFinal => ChainSettlementStateV1::SettledFinal,
            Self::Contested => ChainSettlementStateV1::Disputed,
            Self::Revoked => ChainSettlementStateV1::Revoked,
            Self::Superseded => ChainSettlementStateV1::Superseded,
        }
    }

    pub fn from_str(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "anchored_pending" => Some(Self::AnchoredPending),
            "anchored_final" => Some(Self::AnchoredFinal),
            "contested" => Some(Self::Contested),
            "revoked" => Some(Self::Revoked),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConsensusFinalityViewV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub tip_height: u64,
    #[serde(default)] pub tip_hash: String,
    #[serde(default)] pub finalized_height: u64,
    #[serde(default)] pub finalized_hash: String,
    #[serde(default)] pub highest_qc_height: u64,
    #[serde(default)] pub highest_qc_round: u64,
    #[serde(default)] pub highest_qc_block_hash: String,
    #[serde(default)] pub bft_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRegistryReconciliationContextV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub chain_id: String,
    #[serde(default)] pub genesis_hash: String,
    #[serde(default)] pub tip_height: u64,
    #[serde(default)] pub tip_hash: String,
    #[serde(default)] pub finalized_height: u64,
    #[serde(default)] pub finalized_hash: String,
    #[serde(default)] pub highest_qc_height: u64,
    #[serde(default)] pub highest_qc_round: u64,
    #[serde(default)] pub highest_qc_block_hash: String,
    #[serde(default)] pub registry_last_applied_height: Option<u64>,
    #[serde(default)] pub registry_last_event_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRegistryStatusViewV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub object_hash_hex: String,
    #[serde(default)] pub claim_hash_hex: String,
    #[serde(default)] pub lifecycle_state: String,
    pub effective_status: ChainRegistryEffectiveStatusV1,
    #[serde(default)] pub anchor_height: u64,
    #[serde(default)] pub anchor_block_hash: String,
    #[serde(default)] pub policy_id: String,
    #[serde(default)] pub supersedes: Option<String>,
    #[serde(default)] pub superseded_by: Option<String>,
    #[serde(default)] pub dispute_ref: Option<String>,
    #[serde(default)] pub revoke_ref: Option<String>,
    #[serde(default)] pub updated_at_height: u64,
    #[serde(default)] pub is_finalized: bool,
    #[serde(default)] pub reconciliation_context: ChainRegistryReconciliationContextV1,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRegistryObjectEntryV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub object_hash_hex: String,
    #[serde(default)] pub claim_hash_hex: String,
    #[serde(default)] pub lifecycle_state: String,
    #[serde(default)] pub policy_id: String,
    #[serde(default)] pub anchor_height: u64,
    #[serde(default)] pub anchor_block_hash: String,
    #[serde(default)] pub evidence_root_hex: String,
    #[serde(default)] pub context_hash_hex: String,
    #[serde(default)] pub model_manifest_hash_hex: String,
    #[serde(default)] pub supersedes: Option<String>,
    #[serde(default)] pub superseded_by: Option<String>,
    #[serde(default)] pub dispute_ref: Option<String>,
    #[serde(default)] pub revoke_ref: Option<String>,
    #[serde(default)] pub updated_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRegistryObjectViewV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub entry: ChainRegistryObjectEntryV1,
    #[serde(default)] pub status_view: ChainRegistryStatusViewV1,
}

pub type ChainRegistryMetaViewV1 = ChainRegistryReconciliationContextV1;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAnchorV1 {
    #[serde(default = "default_cognitive_registry_surface_format_version_v1")] pub format_version: u16,
    #[serde(default)] pub object_hash_hex: Option<String>,
    #[serde(default)] pub claim_hash_hex: Option<String>,
    #[serde(default)] pub attest_root_hex: Option<String>,
    #[serde(default)] pub settlement_state: Option<ChainSettlementStateV1>,
    #[serde(default)] pub registry_snapshot_height: Option<u64>,
    #[serde(default)] pub signed_weight: Option<u32>,
    #[serde(default)] pub eligible_weight: Option<u32>,
    #[serde(default)] pub settlement_flags: u16,
    #[serde(default)] pub chain_id: Option<String>,
    #[serde(default)] pub genesis_hash: Option<String>,
    #[serde(default)] pub anchor_height: Option<u64>,
    #[serde(default)] pub anchor_block_hash: Option<String>,
    #[serde(default)] pub finalized_height: Option<u64>,
    #[serde(default)] pub tip_height: Option<u64>,
    #[serde(default)] pub policy_id: Option<String>,
    #[serde(default)] pub context_hash_hex: Option<String>,
    #[serde(default)] pub model_manifest_hash_hex: Option<String>,
    #[serde(default)] pub registry_last_event_seq: Option<u64>,
    #[serde(default)] pub effective_status: Option<ChainRegistryEffectiveStatusV1>,
}


impl Default for ChainConsensusFinalityViewV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            tip_height: 0,
            tip_hash: String::new(),
            finalized_height: 0,
            finalized_hash: String::new(),
            highest_qc_height: 0,
            highest_qc_round: 0,
            highest_qc_block_hash: String::new(),
            bft_active: false,
        }
    }
}

impl Default for ChainRegistryReconciliationContextV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            chain_id: String::new(),
            genesis_hash: String::new(),
            tip_height: 0,
            tip_hash: String::new(),
            finalized_height: 0,
            finalized_hash: String::new(),
            highest_qc_height: 0,
            highest_qc_round: 0,
            highest_qc_block_hash: String::new(),
            registry_last_applied_height: None,
            registry_last_event_seq: None,
        }
    }
}

impl Default for ChainRegistryStatusViewV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            object_hash_hex: String::new(),
            claim_hash_hex: String::new(),
            lifecycle_state: String::new(),
            effective_status: ChainRegistryEffectiveStatusV1::AnchoredPending,
            anchor_height: 0,
            anchor_block_hash: String::new(),
            policy_id: String::new(),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 0,
            is_finalized: false,
            reconciliation_context: ChainRegistryReconciliationContextV1::default(),
        }
    }
}

impl Default for ChainRegistryObjectEntryV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            object_hash_hex: String::new(),
            claim_hash_hex: String::new(),
            lifecycle_state: String::new(),
            policy_id: String::new(),
            anchor_height: 0,
            anchor_block_hash: String::new(),
            evidence_root_hex: String::new(),
            context_hash_hex: String::new(),
            model_manifest_hash_hex: String::new(),
            supersedes: None,
            superseded_by: None,
            dispute_ref: None,
            revoke_ref: None,
            updated_at_height: 0,
        }
    }
}

impl Default for ChainRegistryObjectViewV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            entry: ChainRegistryObjectEntryV1::default(),
            status_view: ChainRegistryStatusViewV1::default(),
        }
    }
}

impl Default for ChainAnchorV1 {
    fn default() -> Self {
        Self {
            format_version: COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1,
            object_hash_hex: None,
            claim_hash_hex: None,
            attest_root_hex: None,
            settlement_state: None,
            registry_snapshot_height: None,
            signed_weight: None,
            eligible_weight: None,
            settlement_flags: 0,
            chain_id: None,
            genesis_hash: None,
            anchor_height: None,
            anchor_block_hash: None,
            finalized_height: None,
            tip_height: None,
            policy_id: None,
            context_hash_hex: None,
            model_manifest_hash_hex: None,
            registry_last_event_seq: None,
            effective_status: None,
        }
    }
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

pub fn validate_chain_consensus_finality_view_v1(view: &ChainConsensusFinalityViewV1) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if view.tip_height > 0 && is_blank(&view.tip_hash) {
        return Err("tip_hash is required when tip_height > 0".to_string());
    }
    if view.finalized_height > 0 && is_blank(&view.finalized_hash) {
        return Err("finalized_hash is required when finalized_height > 0".to_string());
    }
    if view.highest_qc_height > 0 && is_blank(&view.highest_qc_block_hash) {
        return Err("highest_qc_block_hash is required when highest_qc_height > 0".to_string());
    }
    if view.finalized_height > view.tip_height {
        return Err("finalized_height must be <= tip_height".to_string());
    }
    Ok(())
}

pub fn validate_chain_registry_reconciliation_context_v1(ctx: &ChainRegistryReconciliationContextV1) -> Result<(), String> {
    if ctx.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&ctx.chain_id) {
        return Err("chain_id is required".to_string());
    }
    if is_blank(&ctx.genesis_hash) {
        return Err("genesis_hash is required".to_string());
    }
    if ctx.tip_height > 0 && is_blank(&ctx.tip_hash) {
        return Err("tip_hash is required when tip_height > 0".to_string());
    }
    if ctx.finalized_height > 0 && is_blank(&ctx.finalized_hash) {
        return Err("finalized_hash is required when finalized_height > 0".to_string());
    }
    if ctx.finalized_height > ctx.tip_height {
        return Err("finalized_height must be <= tip_height".to_string());
    }
    Ok(())
}

pub fn validate_chain_registry_status_view_v1(view: &ChainRegistryStatusViewV1) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&view.object_hash_hex) {
        return Err("object_hash_hex is required".to_string());
    }
    if is_blank(&view.claim_hash_hex) {
        return Err("claim_hash_hex is required".to_string());
    }
    if is_blank(&view.lifecycle_state) {
        return Err("lifecycle_state is required".to_string());
    }
    if is_blank(&view.anchor_block_hash) && view.anchor_height > 0 {
        return Err("anchor_block_hash is required when anchor_height > 0".to_string());
    }
    if is_blank(&view.policy_id) {
        return Err("policy_id is required".to_string());
    }
    validate_chain_registry_reconciliation_context_v1(&view.reconciliation_context)?;
    Ok(())
}

pub fn validate_chain_registry_object_entry_v1(entry: &ChainRegistryObjectEntryV1) -> Result<(), String> {
    if entry.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if is_blank(&entry.object_hash_hex) {
        return Err("object_hash_hex is required".to_string());
    }
    if is_blank(&entry.claim_hash_hex) {
        return Err("claim_hash_hex is required".to_string());
    }
    if is_blank(&entry.lifecycle_state) {
        return Err("lifecycle_state is required".to_string());
    }
    if is_blank(&entry.policy_id) {
        return Err("policy_id is required".to_string());
    }
    if entry.anchor_height > 0 && is_blank(&entry.anchor_block_hash) {
        return Err("anchor_block_hash is required when anchor_height > 0".to_string());
    }
    Ok(())
}

pub fn validate_chain_registry_object_view_v1(view: &ChainRegistryObjectViewV1) -> Result<(), String> {
    if view.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    validate_chain_registry_object_entry_v1(&view.entry)?;
    validate_chain_registry_status_view_v1(&view.status_view)?;
    if view.entry.object_hash_hex != view.status_view.object_hash_hex {
        return Err("entry/status object_hash_hex mismatch".to_string());
    }
    if view.entry.claim_hash_hex != view.status_view.claim_hash_hex {
        return Err("entry/status claim_hash_hex mismatch".to_string());
    }
    Ok(())
}

pub fn validate_chain_anchor_v1(anchor: &ChainAnchorV1) -> Result<(), String> {
    if anchor.format_version != COGNITIVE_REGISTRY_SURFACE_FORMAT_VERSION_V1 {
        return Err("unsupported format_version".to_string());
    }
    if anchor.anchor_height.unwrap_or(0) > 0 && anchor.anchor_block_hash.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err("anchor_block_hash is required when anchor_height > 0".to_string());
    }
    if anchor.finalized_height.unwrap_or(0) > anchor.tip_height.unwrap_or(0) && anchor.tip_height.is_some() {
        return Err("finalized_height must be <= tip_height".to_string());
    }
    Ok(())
}

impl ChainAnchorV1 {
    pub fn has_material_anchor(&self) -> bool {
        self.object_hash_hex.is_some()
            || self.claim_hash_hex.is_some()
            || self.attest_root_hex.is_some()
            || self.settlement_state.is_some()
            || self.registry_snapshot_height.is_some()
            || self.anchor_height.is_some()
            || self.effective_status.is_some()
    }

    pub fn has_reconciled_chain_state(&self) -> bool {
        self.effective_status.is_some()
            || self.finalized_height.is_some()
            || self.registry_snapshot_height.is_some()
            || self.anchor_height.is_some()
    }

    pub fn apply_reconciliation_context(&mut self, ctx: &ChainRegistryReconciliationContextV1) {
        if !ctx.chain_id.trim().is_empty() { self.chain_id = Some(ctx.chain_id.clone()); }
        if !ctx.genesis_hash.trim().is_empty() { self.genesis_hash = Some(ctx.genesis_hash.clone()); }
        self.tip_height = Some(ctx.tip_height);
        self.finalized_height = Some(ctx.finalized_height);
        self.registry_snapshot_height = ctx.registry_last_applied_height;
        self.registry_last_event_seq = ctx.registry_last_event_seq;
    }

    pub fn apply_status_view(&mut self, view: &ChainRegistryStatusViewV1) {
        if !view.object_hash_hex.trim().is_empty() { self.object_hash_hex = Some(view.object_hash_hex.clone()); }
        if !view.claim_hash_hex.trim().is_empty() { self.claim_hash_hex = Some(view.claim_hash_hex.clone()); }
        self.effective_status = Some(view.effective_status);
        self.settlement_state = Some(view.effective_status.as_settlement_state());
        self.anchor_height = Some(view.anchor_height);
        if !view.anchor_block_hash.trim().is_empty() { self.anchor_block_hash = Some(view.anchor_block_hash.clone()); }
        if !view.policy_id.trim().is_empty() { self.policy_id = Some(view.policy_id.clone()); }
        self.apply_reconciliation_context(&view.reconciliation_context);
    }

    pub fn apply_object_view(&mut self, view: &ChainRegistryObjectViewV1) {
        self.apply_status_view(&view.status_view);
        if !view.entry.evidence_root_hex.trim().is_empty() { self.attest_root_hex = Some(view.entry.evidence_root_hex.clone()); }
        if !view.entry.context_hash_hex.trim().is_empty() { self.context_hash_hex = Some(view.entry.context_hash_hex.clone()); }
        if !view.entry.model_manifest_hash_hex.trim().is_empty() { self.model_manifest_hash_hex = Some(view.entry.model_manifest_hash_hex.clone()); }
    }
}
