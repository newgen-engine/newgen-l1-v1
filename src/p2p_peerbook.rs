use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// PeerBook: utility locale (non-consensus) per tenere traccia di indirizzi peer "utili".
///
/// Mainnet-grade hardening:
/// - bounded (anti-OOM): cap totale e cap dedicato ai peer "protected"
/// - eviction tiered: prima evict "unknown", poi "protected" (solo se necessario)
/// - aggiornamenti idempotenti: i peer già presenti non duplicano memoria
/// - nessun println!; usa log throttled
///
/// Nota sicurezza:
/// Questo modulo NON è una protezione completa contro eclipse (quella vive nel dialer/rotation/diversity del P2P),
/// ma evita che una FIFO pura renda banale "spingere fuori" peer seed/known.
#[derive(Clone, Debug)]
pub struct PeerBook {
    inner: Arc<Mutex<PeerBookInner>>,
    max_total: usize,
    max_protected: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerKind {
    Unknown,
    Protected,
}

#[derive(Debug)]
struct PeerBookInner {
    kind: HashMap<String, PeerKind>,
    // FIFO queues (stale entries are skipped at eviction time)
    q_unknown: VecDeque<String>,
    q_protected: VecDeque<String>,
    n_unknown: usize,
    n_protected: usize,
}

impl Default for PeerBook {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBook {
    pub fn new() -> Self {
        let max_total = std::env::var("NEWGEN_PEERBOOK_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 64)
            .unwrap_or(4096);

        // Reserve capacity for "protected" peers (seeds/static/known-good).
        // Default: 512, clamped to [32, max_total].
        let max_protected = std::env::var("NEWGEN_PEERBOOK_PROTECTED_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 32)
            .unwrap_or(512)
            .min(max_total)
            .max(32);

        Self {
            inner: Arc::new(Mutex::new(PeerBookInner {
                kind: HashMap::new(),
                q_unknown: VecDeque::new(),
                q_protected: VecDeque::new(),
                n_unknown: 0,
                n_protected: 0,
            })),
            max_total,
            max_protected,
        }
    }

    /// Aggiunge un peer "unknown" (best-effort).
    pub fn add_peer(&self, addr: String) {
        self.add_peer_impl(addr, PeerKind::Unknown);
    }

    /// Aggiunge o promuove un peer come "protected".
    /// Usa questo per seed/static peers o per peer con alta reputazione (se mappati a multiaddr).
    pub fn add_protected_peer(&self, addr: String) {
        self.add_peer_impl(addr, PeerKind::Protected);
    }

    /// Promuove un peer esistente a "protected" (no-op se non esiste).
    pub fn protect_peer(&self, addr: &str) {
        let a = addr.trim();
        if a.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cur) = g.kind.get(a).copied() else {
            return;
        };
        if cur == PeerKind::Protected {
            return;
        }
        g.kind.insert(a.to_string(), PeerKind::Protected);
        // adjust counts
        g.n_unknown = g.n_unknown.saturating_sub(1);
        g.n_protected = g.n_protected.saturating_add(1);
        g.q_protected.push_back(a.to_string());
        self.enforce_caps_locked(&mut g);
    }

    /// Declassa un peer protetto a "unknown" (no-op se non esiste o non è protetto).
    /// Utile se un peer prima affidabile perde reputazione (hysteresis).
    pub fn demote_peer(&self, addr: &str) {
        let a = addr.trim();
        if a.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cur) = g.kind.get(a).copied() else {
            return;
        };
        if cur != PeerKind::Protected {
            return;
        }
        g.kind.insert(a.to_string(), PeerKind::Unknown);
        g.n_protected = g.n_protected.saturating_sub(1);
        g.n_unknown = g.n_unknown.saturating_add(1);
        g.q_unknown.push_back(a.to_string());
        self.enforce_caps_locked(&mut g);
    }

    fn add_peer_impl(&self, addr: String, k: PeerKind) {
        let addr = addr.trim().to_string();
        if addr.is_empty() {
            return;
        }

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        match g.kind.get(&addr).copied() {
            Some(existing) => {
                // Upgrade path: unknown -> protected
                if existing == PeerKind::Unknown && k == PeerKind::Protected {
                    g.kind.insert(addr.clone(), PeerKind::Protected);
                    g.n_unknown = g.n_unknown.saturating_sub(1);
                    g.n_protected = g.n_protected.saturating_add(1);
                    g.q_protected.push_back(addr.clone());

                    ng_info_throttle!(
                        key: "peerbook.upgrade",
                        every_ms: 5000,
                        target: "p2p.peerbook",
                        "PeerBook upgrade->protected: {} (u={},p={},cap={}/{})",
                        addr,
                        g.n_unknown,
                        g.n_protected,
                        self.max_total,
                        self.max_protected
                    );
                }
                return;
            }
            None => {
                g.kind.insert(addr.clone(), k);
                match k {
                    PeerKind::Unknown => {
                        g.n_unknown += 1;
                        g.q_unknown.push_back(addr.clone());
                    }
                    PeerKind::Protected => {
                        g.n_protected += 1;
                        g.q_protected.push_back(addr.clone());
                    }
                }
            }
        }

        self.enforce_caps_locked(&mut g);

        ng_info_throttle!(
            key: "peerbook.add",
            every_ms: 5000,
            target: "p2p.peerbook",
            "PeerBook add: {} (u={},p={},cap={}/{})",
            addr,
            g.n_unknown,
            g.n_protected,
            self.max_total,
            self.max_protected
        );
    }

    fn enforce_caps_locked(&self, g: &mut PeerBookInner) {
        // 1) Enforce protected cap (evict oldest protected beyond reserved cap).
        while g.n_protected > self.max_protected {
            if let Some(old) = pop_front_kind(&mut g.q_protected, &g.kind, PeerKind::Protected) {
                g.kind.remove(&old);
                g.n_protected = g.n_protected.saturating_sub(1);
            } else {
                break;
            }
        }

        // 2) Enforce total cap: evict unknown first.
        while g.n_unknown + g.n_protected > self.max_total {
            if let Some(old) = pop_front_kind(&mut g.q_unknown, &g.kind, PeerKind::Unknown) {
                g.kind.remove(&old);
                g.n_unknown = g.n_unknown.saturating_sub(1);
                continue;
            }
            // Last resort: evict protected if no unknown remain.
            if let Some(old) = pop_front_kind(&mut g.q_protected, &g.kind, PeerKind::Protected) {
                g.kind.remove(&old);
                g.n_protected = g.n_protected.saturating_sub(1);
            } else {
                break;
            }
        }

        // 3) Compact queues if they grow too much due to stale entries (peer flapping / promote-demote).
        self.maybe_compact_locked(g);
    }

    fn maybe_compact_locked(&self, g: &mut PeerBookInner) {
        let qlen = g.q_unknown.len().saturating_add(g.q_protected.len());
        let threshold = self.max_total.saturating_mul(8).max(1024);
        if qlen <= threshold {
            return;
        }

        // Rebuild queues from current kind map, deduping stale entries.
        let mut seen: HashSet<String> = HashSet::new();
        let mut new_unknown: VecDeque<String> = VecDeque::new();
        let mut new_protected: VecDeque<String> = VecDeque::new();

        // Preserve relative order as much as possible using existing queues.
        for old in g.q_protected.drain(..) {
            if !seen.insert(old.clone()) {
                continue;
            }
            match g.kind.get(&old).copied() {
                Some(PeerKind::Protected) => new_protected.push_back(old),
                Some(PeerKind::Unknown) => new_unknown.push_back(old),
                None => {}
            }
        }
        for old in g.q_unknown.drain(..) {
            if !seen.insert(old.clone()) {
                continue;
            }
            match g.kind.get(&old).copied() {
                Some(PeerKind::Protected) => new_protected.push_back(old),
                Some(PeerKind::Unknown) => new_unknown.push_back(old),
                None => {}
            }
        }

        // Safety net: if kind contains entries not present in queues (shouldn't happen), append them.
        for (addr, k) in g.kind.iter() {
            if seen.contains(addr) {
                continue;
            }
            match k {
                PeerKind::Protected => new_protected.push_back(addr.clone()),
                PeerKind::Unknown => new_unknown.push_back(addr.clone()),
            }
        }

        g.q_unknown = new_unknown;
        g.q_protected = new_protected;

        // Recompute counters defensively (avoid drift).
        let mut u = 0usize;
        let mut p = 0usize;
        for k in g.kind.values() {
            match k {
                PeerKind::Unknown => u += 1,
                PeerKind::Protected => p += 1,
            }
        }
        g.n_unknown = u;
        g.n_protected = p;

        ng_info_throttle!(
            key: "peerbook.compact",
            every_ms: 10_000,
            target: "p2p.peerbook",
            "PeerBook compacted queues (u={},p={},qlen={},threshold={})",
            g.n_unknown,
            g.n_protected,
            qlen,
            threshold
        );
    }

    /// Restituisce tutti i peer conosciuti (snapshot).
    pub fn list(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.kind.keys().cloned().collect()
    }

    /// Unisce la lista di un altro nodo (best-effort, bounded).
    pub fn merge(&self, others: Vec<String>) {
        for p in others {
            self.add_peer(p);
        }
    }

    /// Statistiche utili per audit/monitoring.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            g.n_unknown,
            g.n_protected,
            self.max_total,
            self.max_protected,
        )
    }
}

fn pop_front_kind(
    q: &mut VecDeque<String>,
    kind: &HashMap<String, PeerKind>,
    want: PeerKind,
) -> Option<String> {
    while let Some(old) = q.pop_front() {
        if kind.get(&old).copied() == Some(want) {
            return Some(old);
        }
        // stale entry; skip
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_process_lock;

    fn reset_env() {
        std::env::remove_var("NEWGEN_PEERBOOK_MAX_ENTRIES");
        std::env::remove_var("NEWGEN_PEERBOOK_PROTECTED_MAX");
    }

    #[test]
    fn bounded_peerbook_evicts_unknown_before_protected() {
        let _g = test_process_lock();
        reset_env();
        std::env::set_var("NEWGEN_PEERBOOK_MAX_ENTRIES", "64");
        std::env::set_var("NEWGEN_PEERBOOK_PROTECTED_MAX", "32");

        let pb = PeerBook::new();
        for i in 0..32 {
            pb.add_protected_peer(format!("prot-{i}"));
        }
        for i in 0..40 {
            pb.add_peer(format!("unk-{i}"));
        }

        let peers = pb.list();
        let (unknown, protected, total_cap, protected_cap) = pb.stats();
        assert_eq!(protected, 32);
        assert_eq!(total_cap, 64);
        assert_eq!(protected_cap, 32);
        assert_eq!(unknown + protected, 64);
        for i in 0..32 {
            assert!(peers.contains(&format!("prot-{i}")));
        }
        reset_env();
    }

    #[test]
    fn protect_demote_and_merge_are_idempotent() {
        let _g = test_process_lock();
        reset_env();
        std::env::set_var("NEWGEN_PEERBOOK_MAX_ENTRIES", "64");
        std::env::set_var("NEWGEN_PEERBOOK_PROTECTED_MAX", "32");

        let pb = PeerBook::new();
        pb.add_peer("peer-a".to_string());
        pb.add_peer("peer-a".to_string());
        pb.protect_peer("peer-a");
        pb.protect_peer("peer-a");
        let (_, protected, _, _) = pb.stats();
        assert_eq!(protected, 1);

        pb.demote_peer("peer-a");
        let (unknown, protected, _, _) = pb.stats();
        assert_eq!((unknown, protected), (1, 0));

        pb.merge(vec![
            "peer-a".to_string(),
            "peer-b".to_string(),
            "peer-b".to_string(),
        ]);
        let listed = pb.list();
        assert!(listed.contains(&"peer-a".to_string()));
        assert!(listed.contains(&"peer-b".to_string()));
        reset_env();
    }
}
