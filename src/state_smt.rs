use crate::account::AccountState;
use crate::storage::StorageStateNodeStore;
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmtNode {
    Branch { left: [u8; 32], right: [u8; 32] }, // internal nodes
    Leaf { key: [u8; 32], value: AccountState }, // only stored at depth=256
}

// Global, per-process cache: key = node hash, value = decoded node.
// Safe because nodes are content-addressed (hash -> immutable value).
//
// IMPORTANT: bounded to avoid unbounded RAM growth on long-running nodes.
// The cache is intentionally approximate (sharded FIFO-ish), not a precise LRU,
// to avoid a global hot lock in read-heavy or highly concurrent workloads.
const DEFAULT_SMT_NODE_CACHE_CAP: usize = 200_000;
const DEFAULT_SMT_NODE_CACHE_SHARDS: usize = 64;

fn smt_node_cache_cap() -> usize {
    static CAP: OnceLock<usize> = OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("NEWGEN_SMT_NODE_CACHE_CAP")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 10_000)
            .unwrap_or(DEFAULT_SMT_NODE_CACHE_CAP)
    })
}

fn smt_node_cache_shards() -> usize {
    static SHARDS: OnceLock<usize> = OnceLock::new();
    *SHARDS.get_or_init(|| {
        let requested = std::env::var("NEWGEN_SMT_NODE_CACHE_SHARDS")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 2)
            .unwrap_or(DEFAULT_SMT_NODE_CACHE_SHARDS);
        requested.next_power_of_two()
    })
}

type CachedNode = Arc<SmtNode>;

#[derive(Debug)]
struct NodeCacheShard {
    map: HashMap<[u8; 32], CachedNode>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}

impl NodeCacheShard {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap.min(16_384)),
            order: VecDeque::with_capacity(cap.min(16_384)),
            cap,
        }
    }

    fn get(&self, k: &[u8; 32]) -> Option<CachedNode> {
        self.map.get(k).cloned()
    }

    fn insert_arc(&mut self, k: [u8; 32], node: CachedNode) {
        if self.map.contains_key(&k) {
            return;
        }
        self.map.insert(k, node);
        self.order.push_back(k);
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.map.len() > self.cap {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            self.map.remove(&old_key);
        }
    }
}

#[derive(Debug)]
struct ShardedNodeCache {
    shards: Vec<RwLock<NodeCacheShard>>,
    mask: usize,
}

impl ShardedNodeCache {
    fn new(total_cap: usize, requested_shards: usize) -> Self {
        let shard_count = requested_shards.max(2).next_power_of_two();
        let base_cap = total_cap / shard_count;
        let remainder = total_cap % shard_count;
        let mut shards = Vec::with_capacity(shard_count);
        for idx in 0..shard_count {
            let shard_cap = base_cap + usize::from(idx < remainder);
            shards.push(RwLock::new(NodeCacheShard::new(shard_cap)));
        }
        Self {
            shards,
            mask: shard_count - 1,
        }
    }

    #[inline]
    fn shard_index(&self, key: &[u8; 32]) -> usize {
        let mut v = [0u8; 8];
        v.copy_from_slice(&key[..8]);
        (u64::from_le_bytes(v) as usize) & self.mask
    }

    #[inline]
    fn read_shard(&self, idx: usize) -> RwLockReadGuard<'_, NodeCacheShard> {
        match self.shards[idx].read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[inline]
    fn write_shard(&self, idx: usize) -> RwLockWriteGuard<'_, NodeCacheShard> {
        match self.shards[idx].write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<CachedNode> {
        let idx = self.shard_index(key);
        let shard = self.read_shard(idx);
        shard.get(key)
    }

    fn insert(&self, key: [u8; 32], node: SmtNode) {
        self.insert_arc(key, Arc::new(node));
    }

    fn insert_arc(&self, key: [u8; 32], node: CachedNode) {
        let idx = self.shard_index(&key);
        let mut shard = self.write_shard(idx);
        shard.insert_arc(key, node);
    }

    fn insert_many<I: IntoIterator<Item = ([u8; 32], SmtNode)>>(&self, it: I) {
        let mut staged: Vec<(usize, [u8; 32], CachedNode)> = Vec::new();
        for (key, node) in it {
            let idx = self.shard_index(&key);
            staged.push((idx, key, Arc::new(node)));
        }
        if staged.is_empty() {
            return;
        }
        staged.sort_unstable_by_key(|(idx, ..)| *idx);
        let mut iter = staged.into_iter().peekable();
        while let Some((shard_idx, key, node)) = iter.next() {
            let mut shard = self.write_shard(shard_idx);
            shard.insert_arc(key, node);
            while let Some((next_idx, _, _)) = iter.peek() {
                if *next_idx != shard_idx {
                    break;
                }
                let (_, key, node) = iter.next().expect("peeked entry must exist");
                shard.insert_arc(key, node);
            }
        }
    }

    fn clear(&self) {
        for idx in 0..self.shards.len() {
            let mut shard = self.write_shard(idx);
            shard.map.clear();
            shard.order.clear();
        }
    }
}

static SMT_NODE_CACHE: OnceLock<Arc<ShardedNodeCache>> = OnceLock::new();

fn node_cache() -> Arc<ShardedNodeCache> {
    SMT_NODE_CACHE
        .get_or_init(|| {
            Arc::new(ShardedNodeCache::new(
                smt_node_cache_cap(),
                smt_node_cache_shards(),
            ))
        })
        .clone()
}

pub(crate) fn clear_global_node_cache() {
    if let Some(cache) = SMT_NODE_CACHE.get() {
        cache.clear();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtProofSibling {
    pub hash_hex: String,
    pub side: String, // "left" or "right" (sibling side relative to the running hash)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtAccountProof {
    pub state_root: String, // hex
    pub key_hex: String,    // hex of addr_key (32 bytes)
    pub value: Option<AccountState>,
    pub leaf_hash: String,              // hex
    pub siblings: Vec<SmtProofSibling>, // 256 entries
    pub rule: SmtRule,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtRule {
    pub leaf_hashing: String,
    pub node_hashing: String,
    pub empty_hashing: String,
    pub key_bits: u32,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Deriva una chiave SMT (32 bytes) a partire da una stringa di address (es. pk_b64).
/// Scelta deterministica: SHA256( address.trim().as_bytes() ).
pub fn addr_key(address: &str) -> [u8; 32] {
    sha256(address.trim().as_bytes())
}

/// Deriva una chiave SMT (32 bytes) per lo **spazio riservato di sistema**.
///
/// Consensus-critical: la formula deve restare stabile.
///
/// Scelta: `addr_key("\0sys/<name>")` con byte 0 forzato a `0x00`.
/// Questo riduce il rischio di collisione con chiavi utente.
pub fn sys_key(name: &str) -> [u8; 32] {
    let mut k = addr_key(&format!("\0sys/{}", name));
    k[0] = 0x00;
    k
}

pub fn hex32(x: &[u8; 32]) -> String {
    hex::encode(x)
}

pub fn bytes32_from_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes hex, got {}", v.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn bit_at(key: &[u8; 32], depth: usize) -> u8 {
    // depth 0 = MSB of byte0
    let byte = depth / 8;
    let bit = 7 - (depth % 8);
    (key[byte] >> bit) & 1
}

fn leaf_hash(key: &[u8; 32], value: &AccountState) -> [u8; 32] {
    // H( 0x00 || key || H(0x02 || bincode_fixed_le(value)) )

    // bincode deterministico: fixint + little endian
    let vb = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .serialize(value)
        .expect("bincode AccountState (fixed, le)");

    // vh = Sha256(0x02 || vb)
    let vh = {
        let mut h = Sha256::new();
        h.update([0x02]);
        h.update(&vb);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    };

    // out = Sha256(0x00 || key || vh)
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(key);
    h.update(vh);
    let d = h.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // H( 0x01 || L || R )
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

fn empty_hashes() -> [[u8; 32]; 257] {
    // empty[256] is the hash of an empty leaf
    // empty[d] = H(0x01 || empty[d+1] || empty[d+1])
    let mut empty = [[0u8; 32]; 257];
    empty[256] = sha256(&[0xEE]); // stable constant
    for d in (0..256).rev() {
        empty[d] = branch_hash(&empty[d + 1], &empty[d + 1]);
    }
    empty
}

fn smt_empty_hashes_static() -> &'static [[u8; 32]; 257] {
    static EMPTY: OnceLock<[[u8; 32]; 257]> = OnceLock::new();
    EMPTY.get_or_init(empty_hashes)
}

/// Returns true if `h` is one of the canonical virtual empty hashes of the SMT.
/// These hashes are valid structural sentinels and are not expected to exist in the physical node store.
pub fn is_virtual_empty_hash(h: &[u8; 32]) -> bool {
    smt_empty_hashes_static().iter().any(|x| x == h)
}

#[derive(Clone, Debug, Default)]
pub struct SmtWriteBatch {
    pub(crate) puts: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) deletes: Vec<Vec<u8>>,
}

impl SmtWriteBatch {
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.puts.push((key.to_vec(), value.to_vec()));
    }

    pub fn delete(&mut self, key: &[u8]) {
        self.deletes.push(key.to_vec());
    }
}

#[derive(Clone, Default)]
pub struct TempSmtNodeStore {
    nodes: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl TempSmtNodeStore {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_node_decoded(&self, key: &[u8]) -> Result<Option<SmtNode>, String> {
        let guard = self
            .nodes
            .lock()
            .map_err(|_| "temp_smt_lock_poisoned".to_string())?;
        let Some(bytes) = guard.get(key) else {
            return Ok(None);
        };
        let node: SmtNode =
            bincode::deserialize(bytes).map_err(|e| format!("bincode node: {e}"))?;
        Ok(Some(node))
    }

    fn put_node(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut guard = self
            .nodes
            .lock()
            .map_err(|_| "temp_smt_lock_poisoned".to_string())?;
        guard.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn write_batch(&self, batch: SmtWriteBatch) -> Result<(), String> {
        let mut guard = self
            .nodes
            .lock()
            .map_err(|_| "temp_smt_lock_poisoned".to_string())?;
        for (k, v) in batch.puts {
            guard.insert(k, v);
        }
        for k in batch.deletes {
            guard.remove(&k);
        }
        Ok(())
    }
}

#[derive(Clone)]
enum NodeStoreHandle {
    Persisted(StorageStateNodeStore),
    Temp(TempSmtNodeStore),
}

impl NodeStoreHandle {
    fn get_node_decoded(&self, key: &[u8]) -> Result<Option<SmtNode>, String> {
        match self {
            Self::Persisted(store) => store.get_node_decoded(key),
            Self::Temp(store) => store.get_node_decoded(key),
        }
    }

    fn put_node(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        match self {
            Self::Persisted(store) => store.put_node(key, value),
            Self::Temp(store) => store.put_node(key, value),
        }
    }

    fn write_batch(&self, batch: SmtWriteBatch) -> Result<(), String> {
        match self {
            Self::Persisted(store) => store.write_batch(batch),
            Self::Temp(store) => store.write_batch(batch),
        }
    }
}

// Important: the canonical SMT runtime is backend-agnostic at the interface boundary and uses only the active storage abstraction.
// Callers must use either:
// - StorageStateNodeStore for persisted runtime state
// - TempSmtNodeStore for ephemeral/tests

pub struct StateSmt {
    nodes: NodeStoreHandle,
    empty: [[u8; 32]; 257],
    cache: Arc<ShardedNodeCache>,
}
impl StateSmt {
    pub(crate) fn new(store: StorageStateNodeStore) -> Self {
        Self {
            nodes: NodeStoreHandle::Persisted(store),
            empty: empty_hashes(),
            cache: node_cache(),
        }
    }

    pub fn ephemeral() -> Self {
        Self {
            nodes: NodeStoreHandle::Temp(TempSmtNodeStore::new()),
            empty: empty_hashes(),
            cache: node_cache(),
        }
    }
    pub fn empty_root(&self) -> [u8; 32] {
        self.empty[0]
    }

    fn get_node_arc(&self, h: &[u8; 32]) -> Result<Option<CachedNode>, String> {
        if is_virtual_empty_hash(h) {
            return Ok(None);
        }

        let hk = *h;
        if let Some(n) = self.cache.get(&hk) {
            return Ok(Some(n));
        }

        let Some(node) = self.nodes.get_node_decoded(h.as_slice())? else {
            return Ok(None);
        };
        let node = Arc::new(node);
        self.cache.insert_arc(hk, node.clone());
        Ok(Some(node))
    }

    #[allow(dead_code)]
    // Helper retained for future SMT optimization / diagnostics.
    fn put_node(&self, node: &SmtNode) -> Result<[u8; 32], String> {
        let h = match node {
            SmtNode::Leaf { key, value } => leaf_hash(key, value),
            SmtNode::Branch { left, right } => branch_hash(left, right),
        };
        let bytes = bincode::serialize(node).map_err(|e| format!("bincode serialize: {e}"))?;
        self.nodes.put_node(h.as_slice(), &bytes)?;

        self.cache.insert(h, node.clone());
        Ok(h)
    }

    pub fn update_account(
        &self,
        prev_root: [u8; 32],
        key: [u8; 32],
        new_value: AccountState,
    ) -> Result<[u8; 32], String> {
        // Walk down collecting siblings
        let mut siblings: Vec<([u8; 32], u8)> = Vec::with_capacity(256);
        let mut cur = prev_root;

        for depth in 0..256 {
            let b = bit_at(&key, depth);
            let (left, right) = if cur == self.empty[depth] {
                (self.empty[depth + 1], self.empty[depth + 1])
            } else {
                let n = self
                    .get_node_arc(&cur)?
                    .ok_or_else(|| format!("missing node at depth {depth}"))?;
                match &*n {
                    SmtNode::Branch { left, right } => (*left, *right),
                    SmtNode::Leaf { .. } => {
                        return Err(format!("unexpected leaf at depth {depth}"))
                    }
                }
            };

            if b == 0 {
                siblings.push((right, 1)); // sibling is right
                cur = left;
            } else {
                siblings.push((left, 0)); // sibling is left
                cur = right;
            }
        }

        // Batch all node writes (big win on Windows + multi-node local tests)
        let mut batch = SmtWriteBatch::default();
        let mut cache_updates: Vec<([u8; 32], SmtNode)> = Vec::with_capacity(257);

        // New leaf at depth 256
        let leaf = SmtNode::Leaf {
            key,
            value: new_value,
        };
        let leaf_h = leaf_hash(
            &key,
            match &leaf {
                SmtNode::Leaf { value, .. } => value,
                _ => unreachable!(),
            },
        );
        let leaf_bytes =
            bincode::serialize(&leaf).map_err(|e| format!("bincode serialize: {e}"))?;
        batch.put(leaf_h.as_slice(), &leaf_bytes);
        cache_updates.push((leaf_h, leaf));
        let mut acc = leaf_h;

        // Rebuild path up (256 branches)
        for depth in (0..256).rev() {
            let (sib, _sib_side) = siblings[depth];
            let b = bit_at(&key, depth);
            let (left, right) = if b == 0 { (acc, sib) } else { (sib, acc) };

            let br = SmtNode::Branch { left, right };
            let h = branch_hash(&left, &right);
            let bytes = bincode::serialize(&br).map_err(|e| format!("bincode serialize: {e}"))?;
            batch.put(h.as_slice(), &bytes);
            cache_updates.push((h, br));
            acc = h;
        }

        self.nodes.write_batch(batch)?;

        self.cache.insert_many(cache_updates);

        Ok(acc)
    }

    /// Elimina (logicamente) un account dalla SMT, riportando la leaf a "empty".
    ///
    /// Consensus-critical: questa operazione deve produrre lo stesso root su tutti i nodi.
    /// Nota: i nodi content-addressed non vengono rimossi dal DB; diventano semplicemente non referenziati.
    pub fn delete_account(&self, prev_root: [u8; 32], key: [u8; 32]) -> Result<[u8; 32], String> {
        // Walk down collecting siblings (come update_account)
        let mut siblings: Vec<([u8; 32], u8)> = Vec::with_capacity(256);
        let mut cur = prev_root;

        for depth in 0..256 {
            let b = bit_at(&key, depth);
            let (left, right) = if cur == self.empty[depth] {
                (self.empty[depth + 1], self.empty[depth + 1])
            } else {
                let n = self
                    .get_node_arc(&cur)?
                    .ok_or_else(|| format!("missing node at depth {depth}"))?;
                match &*n {
                    SmtNode::Branch { left, right } => (*left, *right),
                    SmtNode::Leaf { .. } => {
                        return Err(format!("unexpected leaf at depth {depth}"))
                    }
                }
            };

            if b == 0 {
                siblings.push((right, 1)); // sibling is right
                cur = left;
            } else {
                siblings.push((left, 0)); // sibling is left
                cur = right;
            }
        }

        // Rebuild path up starting from empty leaf.
        let mut batch = SmtWriteBatch::default();
        let mut cache_updates: Vec<([u8; 32], SmtNode)> = Vec::with_capacity(256);

        // At depth 256, deleted leaf = empty hash
        let mut acc = self.empty[256];

        for depth in (0..256).rev() {
            let (sib, _sib_side) = siblings[depth];
            let b = bit_at(&key, depth);

            let (left, right) = if b == 0 { (acc, sib) } else { (sib, acc) };

            // If both children are empty, this node collapses to the precomputed empty hash.
            if left == self.empty[depth + 1] && right == self.empty[depth + 1] {
                acc = self.empty[depth];
                continue;
            }

            let br = SmtNode::Branch { left, right };
            let h = branch_hash(&left, &right);
            let bytes = bincode::serialize(&br).map_err(|e| format!("bincode serialize: {e}"))?;
            batch.put(h.as_slice(), &bytes);
            cache_updates.push((h, br));
            acc = h;
        }

        self.nodes.write_batch(batch)?;

        self.cache.insert_many(cache_updates);

        Ok(acc)
    }

    /// Lettura leggera (no-proof) dello stato account: usa questa in hot-path (state_root),
    /// e riserva `prove_account` alle API.
    pub fn get_account(
        &self,
        root: [u8; 32],
        key: [u8; 32],
    ) -> Result<Option<AccountState>, String> {
        let mut cur = root;

        for depth in 0..256 {
            let b = bit_at(&key, depth);

            if cur == self.empty[depth] {
                return Ok(None);
            }

            let n = self
                .get_node_arc(&cur)?
                .ok_or_else(|| format!("missing node at depth {depth}"))?;

            match &*n {
                SmtNode::Branch { left, right } => {
                    cur = if b == 0 { *left } else { *right };
                }
                SmtNode::Leaf { .. } => return Err(format!("unexpected leaf at depth {depth}")),
            }
        }

        if cur == self.empty[256] {
            return Ok(None);
        }

        let n = self
            .get_node_arc(&cur)?
            .ok_or_else(|| "missing node at depth 256".to_string())?;

        match &*n {
            SmtNode::Leaf {
                key: leaf_key,
                value,
            } => {
                if *leaf_key != key {
                    return Err("leaf key mismatch".to_string());
                }
                Ok(Some(value.clone()))
            }
            SmtNode::Branch { .. } => Err("expected leaf at depth 256".to_string()),
        }
    }

    pub fn prove_account(&self, root: [u8; 32], key: [u8; 32]) -> Result<SmtAccountProof, String> {
        let mut cur = root;
        let mut sibs: Vec<SmtProofSibling> = Vec::with_capacity(256);

        for depth in 0..256 {
            let b = bit_at(&key, depth);
            let (left, right) = if cur == self.empty[depth] {
                (self.empty[depth + 1], self.empty[depth + 1])
            } else {
                let n = self
                    .get_node_arc(&cur)?
                    .ok_or_else(|| format!("missing node at depth {depth}"))?;
                match &*n {
                    SmtNode::Branch { left, right } => (*left, *right),
                    SmtNode::Leaf { .. } => {
                        return Err(format!("unexpected leaf at depth {depth}"))
                    }
                }
            };

            if b == 0 {
                // go left; sibling is right
                sibs.push(SmtProofSibling {
                    hash_hex: hex32(&right),
                    side: "right".to_string(),
                });
                cur = left;
            } else {
                // go right; sibling is left
                sibs.push(SmtProofSibling {
                    hash_hex: hex32(&left),
                    side: "left".to_string(),
                });
                cur = right;
            }
        }

        // cur is leaf hash (or empty[256])
        let (value, leaf_hash_hex) = if cur == self.empty[256] {
            (None, hex32(&cur))
        } else {
            let n = self
                .get_node_arc(&cur)?
                .ok_or_else(|| "missing leaf node".to_string())?;
            match &*n {
                SmtNode::Leaf { key: k2, value } => {
                    if *k2 != key {
                        return Err("leaf key mismatch".to_string());
                    }
                    (Some(value.clone()), hex32(&cur))
                }
                _ => return Err("expected leaf".to_string()),
            }
        };

        Ok(SmtAccountProof {
            state_root: hex32(&root),
            key_hex: hex32(&key),
            value,
            leaf_hash: leaf_hash_hex,
            siblings: sibs,
            rule: SmtRule {
                leaf_hashing: "SHA256(00||key||SHA256(02||bincode(AccountState)))".to_string(),
                node_hashing: "SHA256(01||L||R)".to_string(),
                empty_hashing: "empty[256]=SHA256(EE); empty[d]=SHA256(01||empty[d+1]||empty[d+1])"
                    .to_string(),
                key_bits: 256,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn sample_account(nonce: u64, balance: u64) -> AccountState {
        AccountState {
            nonce,
            balance,
            data: Vec::new(),
        }
    }

    #[test]
    fn sharded_node_cache_insert_and_get() {
        let cache = ShardedNodeCache::new(16, 4);
        let key = [7u8; 32];
        let node = SmtNode::Leaf {
            key,
            value: sample_account(1, 2),
        };
        cache.insert(key, node.clone());
        let got = cache.get(&key).expect("cache hit");
        assert_eq!((*got).clone(), node);
    }

    #[test]
    fn sharded_node_cache_respects_capacity_per_shard() {
        let cache = ShardedNodeCache::new(8, 4);
        for i in 0..16u8 {
            let mut key = [0u8; 32];
            key[0] = i; // vary the low bits so inserts actually spread across shards
            cache.insert(
                key,
                SmtNode::Leaf {
                    key,
                    value: sample_account(i as u64, i as u64),
                },
            );
        }
        let total: usize = cache
            .shards
            .iter()
            .map(|s| match s.read() {
                Ok(g) => g.map.len(),
                Err(p) => p.into_inner().map.len(),
            })
            .sum();
        assert_eq!(
            total, 8,
            "cache should respect the configured global bound exactly"
        );
    }

    #[test]
    fn state_smt_cache_survives_concurrent_reads_and_writes() {
        let smt = Arc::new(StateSmt::ephemeral());
        let mut handles = Vec::new();
        for worker in 0..8u8 {
            let smt = smt.clone();
            handles.push(thread::spawn(move || {
                let mut root = smt.empty_root();
                for round in 0..32u8 {
                    let mut key = [0u8; 32];
                    key[0] = worker;
                    key[31] = round;
                    let value = sample_account(round as u64, (worker as u64) << 8 | round as u64);
                    root = smt
                        .update_account(root, key, value.clone())
                        .expect("update_account");
                    let got = smt.get_account(root, key).expect("get_account");
                    assert_eq!(got, Some(value));
                }
                root
            }));
        }
        for h in handles {
            let _ = h.join().expect("thread join");
        }
    }
}
