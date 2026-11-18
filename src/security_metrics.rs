use serde::Serialize;

use crate::blockchain::SlashingState;

/// Bucket per la distribuzione A-score
#[derive(Serialize, Clone, Debug)]
pub struct AScoreBucket {
    pub label: String,
    pub count: u32,
}

/// Metriche aggregate della reputazione/A-score
#[derive(Serialize, Clone, Debug, Default)]
pub struct ReputationMetrics {
    pub buckets: Vec<AScoreBucket>,
    pub peers_good: u32,
    pub peers_probation: u32,
    pub peers_banned: u32,
    pub total_ban_events: u64,
    pub total_unban_events: u64,
}

/// Contatori di eventi di sicurezza lato P2P
#[derive(Serialize, Clone, Debug, Default)]
pub struct SecurityEventCounters {
    pub spam: u64,
    pub invalid_block: u64,
    pub disconnect: u64,
}

/// Riassunto di un singolo evento di slashing
#[derive(Serialize, Clone, Debug)]
pub struct SlashingEventSummary {
    pub validator_pubkey: String,
    pub reason: String,
    pub height: u64,
    pub penalty_amount: u64,
    pub jailed_until_height: Option<u64>,
}

/// Metriche aggregate di slashing
#[derive(Serialize, Clone, Debug, Default)]
pub struct SlashingMetrics {
    pub validators_with_debt: u32,
    pub total_pending_slash_debt: u64,
    pub total_slashed_amount: u64,
    pub recent_events: Vec<SlashingEventSummary>,
}

/// Payload completo esposto via /api/v2/security/metrics
#[derive(Serialize, Clone, Debug, Default)]
pub struct SecurityMetrics {
    pub a_score: ReputationMetrics,
    pub events: SecurityEventCounters,
    pub slashing: SlashingMetrics,
}

impl SlashingMetrics {
    /// Costruisce le metriche di slashing a partire dallo SlashingState
    pub fn from_state(state: &SlashingState, max_events: usize) -> Self {
        let mut validators_with_debt = 0u32;
        let mut total_pending_slash_debt = 0u64;
        let mut total_slashed_amount = 0u64;

        for info in state.validators.values() {
            if info.pending_slash_debt > 0 {
                validators_with_debt += 1;
                total_pending_slash_debt =
                    total_pending_slash_debt.saturating_add(info.pending_slash_debt);
            }
            total_slashed_amount = total_slashed_amount.saturating_add(info.total_slashed_amount);
        }

        // ultimi N eventi (se la lista è lunga)
        let mut recent_events = Vec::new();
        let len = state.events.len();
        let start = len.saturating_sub(max_events);
        for ev in state.events.iter().skip(start) {
            recent_events.push(SlashingEventSummary {
                validator_pubkey: ev.validator_pubkey.clone(),
                reason: format!("{:?}", ev.reason),
                height: ev.height,
                penalty_amount: ev.penalty_amount,
                jailed_until_height: ev.jailed_until_height,
            });
        }

        SlashingMetrics {
            validators_with_debt,
            total_pending_slash_debt,
            total_slashed_amount,
            recent_events,
        }
    }
}
