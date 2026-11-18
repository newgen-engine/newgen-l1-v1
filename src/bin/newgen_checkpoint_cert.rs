use newgen_engine::anchor_store;
use newgen_engine::checkpoint::{
    build_checkpoint_cert, sign_checkpoint, Checkpoint, CheckpointCert, CheckpointSig,
};
use newgen_engine::governance_provider;
use newgen_engine::keyfmt;
use newgen_engine::keystore::{self, KeyRole};
use newgen_engine::snapshot::SnapshotMeta;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
struct SignedCheckpointFileV1 {
    format_version: u32,
    checkpoint: Checkpoint,
    sig: CheckpointSig,
}

#[derive(Debug, Deserialize)]
struct GenesisConfigForCheckpointTool {
    chain_id: String,
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  newgen_checkpoint_cert export-local --chain-dir <DIR> --nodes A,B,C [--meta auto/latest|auto/bootstrap_latest|<meta.json>]\n  newgen_checkpoint_cert sign --meta <meta.json> --governance <governance.json> --keystore <keystore.json> --out <sig.json>\n  newgen_checkpoint_cert build --meta <meta.json> --governance <governance.json> --out <cert.json> --sig <sig.json> [--sig <sig.json> ...]\n\nEnv required for signing/export-local:\n  NEWGEN_KEYSTORE_PASSPHRASE or NEWGEN_KEYSTORE_PASSPHRASE_FILE\n\nNotes:\n  export-local writes data/anchors/checkpoint_cert_latest.json for every listed node.\n  The checkpoint is bound to meta.height/meta.checkpoint_block_hash/meta.genesis_hash and the governance validator set hash."
    );
    std::process::exit(2);
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < args.len() {
        if args[i] == name {
            out.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn read_meta(path: &Path) -> Result<SnapshotMeta, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read meta {}: {e}", path.display()))?;
    let meta: SnapshotMeta = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid snapshot meta {}: {e}", path.display()))?;
    meta.validate_basic().map_err(|e| {
        format!(
            "snapshot meta basic validation failed {}: {e}",
            path.display()
        )
    })?;
    Ok(meta)
}

fn load_validators_hex(governance_path: &Path) -> Result<HashSet<String>, String> {
    let gov = governance_provider::load_governance_bootstrap_required_quiet(
        governance_path.to_string_lossy().as_ref(),
    )
    .map_err(|e| {
        format!(
            "cannot load governance bootstrap {}: {e}",
            governance_path.display()
        )
    })?;
    let mut set = HashSet::new();
    for e in gov.validator_set.entries {
        let h = keyfmt::pk_hex_from_any(&e.pub_key)
            .map_err(|_| format!("invalid validator pub_key in {}", governance_path.display()))?;
        set.insert(h);
    }
    if set.is_empty() {
        return Err("governance validator_set is empty".to_string());
    }
    Ok(set)
}

fn validator_set_hash_hex(validators: &HashSet<String>) -> String {
    let mut v: Vec<String> = validators.iter().cloned().collect();
    v.sort();
    v.dedup();
    let joined = v.join("\n");
    let mut h = Sha256::new();
    h.update(b"newgen.validator_set.v1\n");
    h.update(joined.as_bytes());
    hex::encode(h.finalize())
}

fn quorum_k_2of3(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (2usize.saturating_mul(n) + 2) / 3
}

fn chain_id_from_genesis_next_to_governance(governance_path: &Path) -> Result<String, String> {
    let genesis_path = governance_path
        .parent()
        .ok_or_else(|| {
            format!(
                "governance path has no parent: {}",
                governance_path.display()
            )
        })?
        .join("genesis.json");
    let bytes = fs::read(&genesis_path)
        .map_err(|e| format!("cannot read genesis {}: {e}", genesis_path.display()))?;
    let g: GenesisConfigForCheckpointTool = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid genesis {}: {e}", genesis_path.display()))?;
    if g.chain_id.trim().is_empty() {
        return Err(format!(
            "genesis {} has empty chain_id",
            genesis_path.display()
        ));
    }
    Ok(g.chain_id)
}

fn checkpoint_from_meta(meta: &SnapshotMeta, governance_path: &Path) -> Result<Checkpoint, String> {
    let validators = load_validators_hex(governance_path)?;
    let vset_hash = validator_set_hash_hex(&validators);
    let chain_id = chain_id_from_genesis_next_to_governance(governance_path)?;
    if meta.genesis_hash.trim().is_empty() {
        return Err("snapshot meta missing genesis_hash".to_string());
    }
    if meta.checkpoint_block_hash.trim().is_empty() {
        return Err("snapshot meta missing checkpoint_block_hash".to_string());
    }
    Ok(Checkpoint {
        height: meta.height,
        block_hash: meta.checkpoint_block_hash.clone(),
        chain_id,
        genesis_hash: meta.genesis_hash.clone(),
        validator_set_hash: vset_hash,
        ts: meta.created_at_ts,
    })
}

fn sign_with_keystore(ckpt: &Checkpoint, keystore_path: &Path) -> Result<CheckpointSig, String> {
    std::env::set_var("NEWGEN_KEYSTORE_PATH", keystore_path);
    let sk = keystore::load_secret_bytes(KeyRole::ValidatorSigning, true).map_err(|e| {
        format!(
            "cannot load validator_signing from {}: {:?}",
            keystore_path.display(),
            e
        )
    })?;
    if sk.len() != 32 {
        return Err(format!(
            "validator_signing in {} has len={} expected=32",
            keystore_path.display(),
            sk.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk[..32]);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
    sign_checkpoint(&signing_key, ckpt)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|e| format!("cannot serialize json: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    newgen_engine::utils::atomic_replace_file_v1(&tmp, path)
        .map_err(|e| format!("cannot atomically replace {}: {e}", path.display()))
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let meta_path =
        PathBuf::from(flag(args, "--meta").ok_or_else(|| "--meta missing".to_string())?);
    let gov_path = PathBuf::from(
        flag(args, "--governance").ok_or_else(|| "--governance missing".to_string())?,
    );
    let ks_path =
        PathBuf::from(flag(args, "--keystore").ok_or_else(|| "--keystore missing".to_string())?);
    let out = PathBuf::from(flag(args, "--out").ok_or_else(|| "--out missing".to_string())?);
    let meta = read_meta(&meta_path)?;
    let ckpt = checkpoint_from_meta(&meta, &gov_path)?;
    let sig = sign_with_keystore(&ckpt, &ks_path)?;
    let signed = SignedCheckpointFileV1 {
        format_version: 1,
        checkpoint: ckpt,
        sig,
    };
    write_json_atomic(&out, &signed)?;
    println!("[OK] checkpoint signature written: {}", out.display());
    Ok(())
}

fn build_cert(
    meta_path: &Path,
    gov_path: &Path,
    sig_paths: &[String],
) -> Result<CheckpointCert, String> {
    let meta = read_meta(meta_path)?;
    let ckpt = checkpoint_from_meta(&meta, gov_path)?;
    let allowed = load_validators_hex(gov_path)?;
    let quorum = quorum_k_2of3(allowed.len());
    let mut sigs_by_pk_b64: HashMap<String, CheckpointSig> = HashMap::new();
    for sp in sig_paths {
        let path = PathBuf::from(sp);
        let bytes =
            fs::read(&path).map_err(|e| format!("cannot read sig {}: {e}", path.display()))?;
        let signed: SignedCheckpointFileV1 = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid sig json {}: {e}", path.display()))?;
        if signed.format_version != 1 {
            return Err(format!(
                "unsupported sig format_version in {}",
                path.display()
            ));
        }
        if signed.checkpoint != ckpt {
            return Err(format!(
                "signature checkpoint mismatch in {}",
                path.display()
            ));
        }
        sigs_by_pk_b64.insert(signed.sig.signer_pk_b64.clone(), signed.sig);
    }
    build_checkpoint_cert(ckpt, &sigs_by_pk_b64, quorum, &allowed)
}

fn cmd_build(args: &[String]) -> Result<(), String> {
    let meta_path =
        PathBuf::from(flag(args, "--meta").ok_or_else(|| "--meta missing".to_string())?);
    let gov_path = PathBuf::from(
        flag(args, "--governance").ok_or_else(|| "--governance missing".to_string())?,
    );
    let out = PathBuf::from(flag(args, "--out").ok_or_else(|| "--out missing".to_string())?);
    let sig_paths = flags(args, "--sig");
    if sig_paths.is_empty() {
        return Err("at least one --sig required".to_string());
    }
    let cert = build_cert(&meta_path, &gov_path, &sig_paths)?;
    write_json_atomic(&out, &cert)?;
    println!("[OK] checkpoint cert written: {}", out.display());
    Ok(())
}

fn resolve_meta_path(chain_dir: &Path, meta_arg: Option<String>, first_node: &str) -> PathBuf {
    match meta_arg.as_deref() {
        Some(path) if path.ends_with(".json") || path.contains('/') || path.contains('\\') => {
            PathBuf::from(path)
        }
        Some("auto/bootstrap_latest") => chain_dir.join(format!(
            "node{first_node}/data/snapshots/auto/bootstrap_latest/meta.json"
        )),
        Some("auto/latest") | None => chain_dir.join(format!(
            "node{first_node}/data/snapshots/auto/latest/meta.json"
        )),
        Some(other) => chain_dir.join(format!("node{first_node}/data/snapshots/{other}/meta.json")),
    }
}

fn cmd_export_local(args: &[String]) -> Result<(), String> {
    let chain_dir =
        PathBuf::from(flag(args, "--chain-dir").ok_or_else(|| "--chain-dir missing".to_string())?);
    let nodes_arg = flag(args, "--nodes").ok_or_else(|| "--nodes missing".to_string())?;
    let nodes: Vec<String> = nodes_arg
        .split(',')
        .map(|s| s.trim().trim_start_matches("node").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if nodes.is_empty() {
        return Err("--nodes resolved to empty set".to_string());
    }
    let first_node = nodes[0].clone();
    let meta_path = resolve_meta_path(&chain_dir, flag(args, "--meta"), &first_node);
    let gov_path = chain_dir.join(format!("node{first_node}/data/config/governance.json"));
    let meta = read_meta(&meta_path)?;
    let ckpt = checkpoint_from_meta(&meta, &gov_path)?;
    let allowed = load_validators_hex(&gov_path)?;
    let quorum = quorum_k_2of3(allowed.len());

    let mut sigs_by_pk_b64: HashMap<String, CheckpointSig> = HashMap::new();
    for n in &nodes {
        let ks = chain_dir.join(format!("node{n}/data/config/secrets/keystore.json"));
        let sig = sign_with_keystore(&ckpt, &ks)?;
        sigs_by_pk_b64.insert(sig.signer_pk_b64.clone(), sig);
    }
    let cert = build_checkpoint_cert(ckpt, &sigs_by_pk_b64, quorum, &allowed)?;

    for n in &nodes {
        let out = chain_dir.join(format!("node{n}/data/anchors/checkpoint_cert_latest.json"));
        anchor_store::save_checkpoint_cert(&out, &cert)?;
        println!("[OK] wrote {}", out.display());
    }
    println!(
        "[OK] checkpoint cert exported height={} sigs={} sha256={}",
        cert.checkpoint.height,
        cert.sigs.len(),
        anchor_store::checkpoint_cert_sha256_hex(&cert)
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let res = match cmd {
        "sign" => cmd_sign(&args[2..]),
        "build" => cmd_build(&args[2..]),
        "export-local" => cmd_export_local(&args[2..]),
        _ => usage(),
    };
    if let Err(e) = res {
        eprintln!("[ERR] {e}");
        std::process::exit(1);
    }
}
