use base64::{engine::general_purpose::STANDARD, Engine as _};
use libp2p::futures::StreamExt;
use libp2p::identity;
use libp2p::multiaddr::Protocol;
use libp2p::request_response;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp::Config as TcpConfig, yamux, Multiaddr, PeerId, Swarm};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

use newgen_engine::protocol_ids::RR_V3;
use newgen_engine::rr_v3_msg::{decode_v3, encode_v3, RrV3Msg};
use newgen_engine::rr_v3_transport::{NewgenHeadersCodec, RRv3Request, RRv3Response};

fn verify_downloaded_snapshot_bytes_len_v1(
    chunks_dir: &Path,
    expected_chunks: u64,
    expected_bytes_len: u64,
) -> Result<u64, String> {
    let mut total: u64 = 0;
    for i in 0..expected_chunks {
        let p = chunks_dir.join(format!("{:06}.bin", i));
        let len = std::fs::metadata(&p)
            .map_err(|e| {
                format!(
                    "snapshot chunk {} missing/unreadable at {}: {}",
                    i,
                    p.display(),
                    e
                )
            })?
            .len();
        total = total
            .checked_add(len)
            .ok_or_else(|| "snapshot chunk bytes_len overflow".to_string())?;
    }

    if total != expected_bytes_len {
        return Err(format!(
            "snapshot bytes_len mismatch: meta.bytes_len={} actual={}",
            expected_bytes_len, total
        ));
    }

    Ok(total)
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  fetch_snapshot_v2 --peer <multiaddr-with-/p2p/> --out <dir> [--height <h>]\n\nExamples:\n  fetch_snapshot_v2 --peer /ip4/127.0.0.1/tcp/8080/p2p/12D3KooW... --out snapshots/bootstrap\n  fetch_snapshot_v2 --peer /dns4/node.example.com/tcp/8080/p2p/12D3KooW... --out snapshots/bootstrap --height 12345\n\nNotes:\n  - Uses RRv3 (protocol: /newgen/rr/3) to fetch a snapshot-v2 bundle (meta.json + chunks/).\n  - Verifies SHA256 of each chunk vs meta.chunk_hashes_hex.\n",
    );
    std::process::exit(2);
}

fn arg_value(argv: &[String], key: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == key)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

fn has_flag(argv: &[String], key: &str) -> bool {
    argv.iter().any(|a| a == key)
}

fn parse_peer_from_multiaddr(addr: &Multiaddr) -> Result<PeerId, String> {
    for p in addr.iter() {
        if let Protocol::P2p(mh) = p {
            return Ok(mh);
        }
    }
    Err("peer multiaddr must include trailing /p2p/<peer_id>".to_string())
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

// RRv3 codec (shared with runtime P2P): crate::rr_v3_transport

// --- Behaviour (reqres only)
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "FetchEvent")]
struct FetchBehaviour {
    reqres_v3: request_response::Behaviour<NewgenHeadersCodec>,
}

#[derive(Debug)]
enum FetchEvent {
    ReqResV3(request_response::Event<RRv3Request, RRv3Response>),
}

impl From<request_response::Event<RRv3Request, RRv3Response>> for FetchEvent {
    fn from(e: request_response::Event<RRv3Request, RRv3Response>) -> Self {
        Self::ReqResV3(e)
    }
}

fn out_paths(out_dir: &Path) -> (PathBuf, PathBuf) {
    let meta = out_dir.join("meta.json");
    let chunks = out_dir.join("chunks");
    (meta, chunks)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 || has_flag(&argv, "--help") || has_flag(&argv, "-h") {
        usage();
    }

    let peer_addr = arg_value(&argv, "--peer").unwrap_or_default();
    let out_dir = arg_value(&argv, "--out").unwrap_or_default();
    if peer_addr.is_empty() || out_dir.is_empty() {
        usage();
    }

    let height_opt = arg_value(&argv, "--height").and_then(|s| s.parse::<u64>().ok());

    let addr: Multiaddr = peer_addr.parse().unwrap_or_else(|e| {
        eprintln!("❌ bad --peer multiaddr: {e}");
        std::process::exit(2);
    });
    let peer_id = parse_peer_from_multiaddr(&addr).unwrap_or_else(|e| {
        eprintln!("❌ {e}");
        std::process::exit(2);
    });

    // Codec cap: must be >= server rr_v3_max_frame_bytes, else reads fail.
    let cap = env_usize("NEWGEN_RR_V3_MAX_FRAME_BYTES", 16 * 1024 * 1024)
        .clamp(1024 * 1024, 256 * 1024 * 1024);
    let timeout_ms = std::env::var("NEWGEN_FETCH_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(15_000);

    // Build swarm
    let local_keys = identity::Keypair::generate_ed25519();
    let cfg = request_response::Config::default()
        .with_request_timeout(Duration::from_millis(timeout_ms.max(300)));
    let protocols = std::iter::once((RR_V3.to_string(), request_response::ProtocolSupport::Full));
    let reqres_v3 = request_response::Behaviour::with_codec(
        NewgenHeadersCodec {
            max_frame_bytes: cap,
        },
        protocols,
        cfg,
    );

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_keys)
        .with_tokio()
        .with_tcp(
            TcpConfig::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap_or_else(|e| {
            eprintln!("❌ swarm builder (tcp/noise/yamux) failed: {e}");
            std::process::exit(2);
        })
        .with_behaviour(move |_| Ok(FetchBehaviour { reqres_v3 }))
        .unwrap_or_else(|e| {
            eprintln!("❌ swarm builder behaviour failed: {e}");
            std::process::exit(2);
        })
        .build();

    // Listen on ephemeral local port
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    // Dial
    if let Err(e) = swarm.dial(addr.clone()) {
        eprintln!("❌ dial failed: {e}");
        std::process::exit(2);
    }
    eprintln!("dialing peer: {peer_id}");

    // Wait connection
    let mut connected = false;
    while let Some(ev) = swarm.next().await {
        if let SwarmEvent::ConnectionEstablished { peer_id: pid, .. } = &ev {
            if *pid == peer_id {
                connected = true;
                break;
            }
        }
    }
    if !connected {
        eprintln!("❌ connection not established");
        std::process::exit(2);
    }

    // Helper: send request and await response
    async fn rr_call(
        swarm: &mut Swarm<FetchBehaviour>,
        peer: PeerId,
        msg: RrV3Msg,
        timeout_ms: u64,
    ) -> Result<RrV3Msg, String> {
        let req_id = swarm
            .behaviour_mut()
            .reqres_v3
            .send_request(&peer, RRv3Request(encode_v3(&msg)));

        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let next = tokio::time::timeout_at(deadline, swarm.next())
                .await
                .map_err(|_| "timeout".to_string())?;
            let ev = match next {
                Some(e) => e,
                None => return Err("swarm ended".to_string()),
            };

            if let SwarmEvent::Behaviour(FetchEvent::ReqResV3(e)) = ev {
                match e {
                    request_response::Event::Message { peer: p, message } if p == peer => {
                        match message {
                            request_response::Message::Response {
                                request_id,
                                response,
                            } => {
                                if request_id == req_id {
                                    let bytes = response.0;
                                    let msg = decode_v3(&bytes)
                                        .ok_or_else(|| "invalid RRv3 JSON".to_string())?;
                                    return Ok(msg);
                                }
                            }
                            request_response::Message::Request { .. } => {}
                        }
                    }
                    request_response::Event::OutboundFailure {
                        request_id, error, ..
                    } if request_id == req_id => {
                        return Err(format!("outbound failure: {error:?}"));
                    }
                    _ => {}
                }
            }
        }
    }

    // --- Fetch meta
    let meta_msg = if let Some(h) = height_opt {
        RrV3Msg::GetSnapshotV2Meta { height: h }
    } else {
        RrV3Msg::GetSnapshotV2Latest
    };

    let resp = rr_call(&mut swarm, peer_id, meta_msg, timeout_ms)
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ meta request failed: {e}");
            std::process::exit(2);
        });

    let (meta, _sha_opt) = match resp {
        RrV3Msg::SnapshotV2Meta {
            meta: Some(m),
            meta_sha256_hex,
        } => (m, meta_sha256_hex),
        RrV3Msg::SnapshotV2Meta { meta: None, .. } => {
            eprintln!("❌ peer has no snapshot v2 available");
            std::process::exit(2);
        }
        RrV3Msg::Error { code, message } => {
            eprintln!("❌ peer error (code={code}): {message}");
            std::process::exit(2);
        }
        other => {
            eprintln!("❌ unexpected meta response: {other:?}");
            std::process::exit(2);
        }
    };

    if meta.chunks == 0 {
        eprintln!("❌ snapshot meta invalid: chunks=0");
        std::process::exit(2);
    }
    if meta.chunk_hashes_hex.len() != meta.chunks as usize {
        eprintln!(
            "❌ snapshot meta invalid: chunk_hashes_hex.len()={} but chunks={}",
            meta.chunk_hashes_hex.len(),
            meta.chunks
        );
        std::process::exit(2);
    }

    let out_dir = PathBuf::from(out_dir);
    let (meta_path, chunks_dir) = out_paths(&out_dir);
    std::fs::create_dir_all(&chunks_dir).unwrap_or_else(|e| {
        eprintln!("❌ cannot create out dir: {e}");
        std::process::exit(2);
    });

    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap_or_else(|e| {
        eprintln!("❌ cannot serialize meta.json: {e}");
        std::process::exit(2);
    });
    std::fs::write(&meta_path, &meta_bytes).unwrap_or_else(|e| {
        eprintln!("❌ cannot write meta.json: {e}");
        std::process::exit(2);
    });

    eprintln!(
        "snapshot v2 meta: height={} base_height={} chunks={} chunk_size={} bytes_len={} include_state_nodes={}",
        meta.height,
        meta.base_height,
        meta.chunks,
        meta.chunk_size,
        meta.bytes_len,
        meta.include_state_nodes
    );

    // --- Fetch chunks
    for i in 0..meta.chunks {
        let resp = rr_call(
            &mut swarm,
            peer_id,
            RrV3Msg::GetSnapshotV2Chunk {
                height: meta.height,
                chunk_index: i,
            },
            timeout_ms,
        )
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ chunk {i} request failed: {e}");
            std::process::exit(2);
        });

        let (height, idx, data_b64) = match resp {
            RrV3Msg::SnapshotV2Chunk {
                height,
                chunk_index,
                data_b64,
            } => (height, chunk_index, data_b64),
            RrV3Msg::Error { code, message } => {
                eprintln!("❌ peer error on chunk {i} (code={code}): {message}");
                std::process::exit(2);
            }
            other => {
                eprintln!("❌ unexpected chunk response: {other:?}");
                std::process::exit(2);
            }
        };

        if height != meta.height || idx != i {
            eprintln!(
                "❌ chunk mismatch: expected height={} idx={} got height={} idx={}",
                meta.height, i, height, idx
            );
            std::process::exit(2);
        }

        let bytes = STANDARD.decode(data_b64.as_bytes()).unwrap_or_else(|e| {
            eprintln!("❌ chunk {i} invalid base64: {e}");
            std::process::exit(2);
        });

        let got = sha256_hex(&bytes);
        let exp = meta.chunk_hashes_hex[i as usize].trim().to_string();
        if got != exp {
            eprintln!("❌ chunk {i} sha256 mismatch: expected={exp} got={got}");
            std::process::exit(2);
        }

        let fname = format!("{:06}.bin", i);
        let fpath = chunks_dir.join(fname);
        std::fs::write(&fpath, &bytes).unwrap_or_else(|e| {
            eprintln!("❌ cannot write chunk file: {e}");
            std::process::exit(2);
        });

        eprintln!(
            "downloaded chunk {}/{} ({} bytes)",
            i + 1,
            meta.chunks,
            bytes.len()
        );
    }

    // Final fail-closed contract check: meta.bytes_len is part of the signed snapshot contract.
    // A mismatch means the downloaded bundle is not the advertised snapshot and must not be
    // used by operators, tests, or bootstrap flows.
    let total = verify_downloaded_snapshot_bytes_len_v1(
        &chunks_dir,
        u64::from(meta.chunks),
        meta.bytes_len,
    )
    .unwrap_or_else(|e| {
        eprintln!("❌ {e}");
        std::process::exit(2);
    });

    eprintln!(
        "snapshot v2 bytes_len verified: meta.bytes_len={} actual={}",
        meta.bytes_len, total
    );

    println!("✅ Snapshot v2 bundle downloaded to: {}", out_dir.display());
}
