use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use std::fs;

use newgen_engine::keystore::{self, KeyRole};

#[derive(Deserialize)]
struct MasterKeysJson {
    sk_b64: String,
    pk_b64: String,
}

fn usage() -> ! {
    eprintln!(
        "Usage:
  newgen_keys init-node                 # init validator_signing + p2p_identity (random)
  newgen_keys init-follower             # init solo p2p_identity locale (kit follower / read-only)
  newgen_keys import-node [master_keys] # import validator_signing da master_keys.json + init p2p_identity se manca
  newgen_keys init-ca                   # init wallet_ca (solo OFFLINE)
  newgen_keys show                      # mostra pubkey validator + info keystore

Env required:
  NEWGEN_KEYSTORE_PASSPHRASE oppure NEWGEN_KEYSTORE_PASSPHRASE_FILE
Optional:
  NEWGEN_KEYSTORE_PATH         (es: config\\secrets\\keystore.json)
  NEWGEN_KEYSTORE_PASSPHRASE_FILE (es: config\\secrets\\keystore.passphrase)
"
    );
    std::process::exit(2);
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if cmd.is_empty() {
        usage();
    }

    // Fail-closed: serve una passphrase inline o un file passphrase.
    let has_pass = std::env::var("NEWGEN_KEYSTORE_PASSPHRASE")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let has_pass_file = std::env::var("NEWGEN_KEYSTORE_PASSPHRASE_FILE")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if !has_pass && !has_pass_file {
        eprintln!("❌ Missing NEWGEN_KEYSTORE_PASSPHRASE or NEWGEN_KEYSTORE_PASSPHRASE_FILE");
        std::process::exit(2);
    }

    match cmd.as_str() {
        "init-node" => init_node(),
        "init-follower" => init_follower(),
        "import-node" => import_node(),
        "init-ca" => init_ca(),
        "show" => show(),
        _ => usage(),
    }
}

fn ensure_passphrase_material() {
    if std::env::var("NEWGEN_KEYSTORE_PASSPHRASE")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }

    let Some(path_s) = std::env::var("NEWGEN_KEYSTORE_PASSPHRASE_FILE").ok() else {
        eprintln!("❌ Missing NEWGEN_KEYSTORE_PASSPHRASE or NEWGEN_KEYSTORE_PASSPHRASE_FILE");
        std::process::exit(2);
    };

    let path = std::path::PathBuf::from(path_s);
    if path.exists() {
        let txt = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("❌ cannot read passphrase file {}: {e}", path.display());
            std::process::exit(2);
        });
        if txt.trim().is_empty() {
            eprintln!("❌ passphrase file is empty: {}", path.display());
            std::process::exit(2);
        }
        return;
    }

    if let Some(dir) = path.parent() {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("❌ cannot create passphrase dir {}: {e}", dir.display());
            std::process::exit(2);
        }
    }

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let pass = STANDARD.encode(secret);

    fs::write(&path, format!("{}\n", pass)).unwrap_or_else(|e| {
        eprintln!("❌ cannot write passphrase file {}: {e}", path.display());
        std::process::exit(2);
    });
}

fn init_node() {
    ensure_passphrase_material();
    // validator_signing random (DEV)
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    keystore::init_entry(KeyRole::ValidatorSigning, &seed, None).unwrap_or_else(|e| {
        eprintln!("❌ init validator_signing failed: {:?}", e);
        std::process::exit(2);
    });

    // p2p identity
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let bytes = kp.to_protobuf_encoding().expect("p2p keypair encode");
    keystore::init_entry(KeyRole::P2PIdentity, &bytes, None).unwrap_or_else(|e| {
        eprintln!("❌ init p2p_identity failed: {:?}", e);
        std::process::exit(2);
    });

    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let pk_b64 = STANDARD.encode(pk.to_bytes());
    let peer_id = libp2p::PeerId::from_public_key(&kp.public());

    println!("✅ init-node OK");
    println!("keystore: {}", keystore::keystore_path().display());
    println!("validator_pk_b64: {}", pk_b64);
    println!("p2p_peer_id: {}", peer_id);
}

fn init_follower() {
    ensure_passphrase_material();

    if let Ok(bytes) = keystore::load_secret_bytes(KeyRole::P2PIdentity, false) {
        let kp = libp2p::identity::Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|e| {
            eprintln!("❌ existing p2p_identity invalid: {e}");
            std::process::exit(2);
        });
        let peer_id = libp2p::PeerId::from_public_key(&kp.public());
        println!("✅ init-follower OK (already present)");
        println!("keystore: {}", keystore::keystore_path().display());
        println!("p2p_peer_id: {}", peer_id);
        return;
    }

    let kp = libp2p::identity::Keypair::generate_ed25519();
    let bytes = kp.to_protobuf_encoding().expect("p2p keypair encode");
    keystore::init_entry(KeyRole::P2PIdentity, &bytes, None).unwrap_or_else(|e| {
        eprintln!("❌ init p2p_identity failed: {:?}", e);
        std::process::exit(2);
    });

    let peer_id = libp2p::PeerId::from_public_key(&kp.public());
    println!("✅ init-follower OK");
    println!("keystore: {}", keystore::keystore_path().display());
    println!("p2p_peer_id: {}", peer_id);
}

fn import_node() {
    ensure_passphrase_material();
    let path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "master_keys.json".to_string());

    let txt = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("❌ cannot read {path}: {e}");
        std::process::exit(2);
    });

    let mk: MasterKeysJson = serde_json::from_str(&txt).unwrap_or_else(|e| {
        eprintln!("❌ invalid master_keys json ({path}): {e}");
        std::process::exit(2);
    });

    let sk = STANDARD.decode(mk.sk_b64.trim()).unwrap_or_else(|e| {
        eprintln!("❌ master_keys.sk_b64 invalid base64: {e}");
        std::process::exit(2);
    });
    if sk.len() != 32 {
        eprintln!("❌ master_keys.sk_b64 must be 32 bytes, got {}", sk.len());
        std::process::exit(2);
    }

    // Scrive validator_signing coerente con master_keys/governance
    keystore::init_entry(KeyRole::ValidatorSigning, &sk, Some(mk.pk_b64.clone())).unwrap_or_else(
        |e| {
            eprintln!("❌ import validator_signing failed: {:?}", e);
            std::process::exit(2);
        },
    );

    // Se p2p_identity manca, inizializzala una volta
    if keystore::load_secret_bytes(KeyRole::P2PIdentity, false).is_err() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = kp.to_protobuf_encoding().expect("p2p keypair encode");
        keystore::init_entry(KeyRole::P2PIdentity, &bytes, None).unwrap_or_else(|e| {
            eprintln!("❌ init p2p_identity failed: {:?}", e);
            std::process::exit(2);
        });
    }

    println!("✅ import-node OK");
    println!("keystore: {}", keystore::keystore_path().display());
    println!("validator_pk_b64: {}", mk.pk_b64);
    show();
}

fn init_ca() {
    ensure_passphrase_material();
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    keystore::init_entry(KeyRole::WalletCA, &seed, None).unwrap_or_else(|e| {
        eprintln!("❌ init wallet_ca failed: {:?}", e);
        std::process::exit(2);
    });

    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let pk_b64 = STANDARD.encode(pk.to_bytes());

    println!("✅ init-ca OK (OFFLINE ONLY)");
    println!("keystore: {}", keystore::keystore_path().display());
    println!("wallet_ca_pk_b64: {}", pk_b64);
}

fn show() {
    ensure_passphrase_material();
    println!("keystore: {}", keystore::keystore_path().display());

    if let Ok(sk) = keystore::load_secret_bytes(KeyRole::ValidatorSigning, false) {
        if sk.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk[..32]);
            let pk = ed25519_dalek::SigningKey::from_bytes(&arr).verifying_key();
            println!("validator_pk_b64: {}", STANDARD.encode(pk.to_bytes()));
        } else {
            println!("validator_signing present but invalid len={}", sk.len());
        }
    } else {
        println!("validator_signing: (missing)");
    }

    if let Ok(bytes) = keystore::load_secret_bytes(KeyRole::P2PIdentity, false) {
        match libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            Ok(kp) => println!(
                "p2p_peer_id: {}",
                libp2p::PeerId::from_public_key(&kp.public())
            ),
            Err(_) => println!("p2p_identity present but invalid"),
        }
    } else {
        println!("p2p_identity: (missing)");
    }
}
