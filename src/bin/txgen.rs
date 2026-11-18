use newgen_engine::chain_identity;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use newgen_engine::wallet::{sign_payload_ed25519, SignedTransaction, TransactionPayload};

fn http_post_json(host: &str, port: u16, path: &str, json: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect error: {e}"))?;

    let body_len = json.len();
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
Host: {host}:{port}\r\n\
Content-Type: application/json\r\n\
Content-Length: {body_len}\r\n\
Connection: close\r\n\
\r\n\
{json}"
    );

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write error: {e}"))?;

    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("read error: {e}"))?;

    Ok(resp)
}

fn decode_chunked_body(body: &str) -> Result<String, String> {
    let bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut out = Vec::new();
    loop {
        let rest = &bytes[cursor..];
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunk header terminator missing".to_string())?;
        let size_line = std::str::from_utf8(&rest[..line_end])
            .map_err(|e| format!("chunk header utf8 failed: {e}"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_line, 16)
            .map_err(|e| format!("chunk size parse failed: {e}"))?;
        cursor += line_end + 2;
        if size == 0 {
            return String::from_utf8(out).map_err(|e| format!("chunk body utf8 failed: {e}"));
        }
        if bytes.len() < cursor.saturating_add(size).saturating_add(2) {
            return Err("chunk payload truncated".to_string());
        }
        out.extend_from_slice(&bytes[cursor..cursor + size]);
        if &bytes[cursor + size..cursor + size + 2] != b"\r\n" {
            return Err("chunk trailer missing".to_string());
        }
        cursor += size + 2;
    }
}

fn http_body_from_response(resp: &str) -> Result<String, String> {
    let (headers, body) = if let Some((headers, body)) = resp.split_once("\r\n\r\n") {
        (headers, body)
    } else if let Some((headers, body)) = resp.split_once("\n\n") {
        (headers, body)
    } else {
        return Ok(resp.to_string());
    };
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked_body(body)
    } else {
        Ok(body.to_string())
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage:\n\
         legacy stress:\n\
         cargo run --bin txgen -- --host 127.0.0.1 --ports 8000,8001 --senders 10 --tx-per-sender 3 --amount 1 --fee 100\n\
         \n\
         NFT non-custodial helpers:\n\
         cargo run --bin txgen -- nft-build-create --host 127.0.0.1 --port 8001 --from <pk_b64> --symbol <SYM> --name <name> --base-uri <uri> --metadata-hash-hex <64hex> [--max-supply <u64>] [--asset-type collectible] [--transfer-policy transferable] [--mintable true] [--burnable true] [--revocable false] [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-mint --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --to <pk_b64> --token-uri <uri> --metadata-hash-hex <64hex> [--expires-at-height <u64>] [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-transfer --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> --to <pk_b64> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-approve --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> [--approved <pk_b64>] [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-set-approval-for-all --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --operator <pk_b64> --approved true|false [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-burn --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-revoke --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-set-token-uri --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> --token-uri <uri> --metadata-hash-hex <64hex> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-set-collection-uri --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --base-uri <uri> --metadata-hash-hex <64hex> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-freeze-token --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --serial <u64> --frozen true|false [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-set-collection-policy --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --mintable true|false --burnable true|false --transfer-policy transferable|soulbound|issuer_only_transfer|frozen --revocable true|false [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-set-issuer --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --issuer <pk_b64> [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-build-pause --host 127.0.0.1 --port 8001 --from <pk_b64> --collection-id <u64> --paused true|false [--nonce <u64>] [--max-fee <u64>] [--priority-fee <u64>] [--signing-key-b64 <sk_b64>] [--submit]\n\
         cargo run --bin txgen -- nft-submit-signed --host 127.0.0.1 --port 8001 --file signed_tx.json\n\
         \n\
         Legacy options:\n\
         --host <ip>                 (default: 127.0.0.1)\n\
         --ports <p1,p2,...>         (default: 8000)  e.g. 8000,8001\n\
         --path <url_path>           (default: /api/v2/tx/submit_signed)\n\
         --senders <n>               (default: 1)\n\
         --tx-per-sender <n>         (default: 25)\n\
         --amount <u64>              (default: 1)\n\
         --fee <u64>                 (default: 100)\n\
         --receiver <pk_b64>         optional: fixa receiver invece di generarne uno nuovo\n\
         --memo <string>             optional memo\n"
    );
    std::process::exit(0);
}

fn parse_ports(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let p: u16 = part.parse().unwrap_or_else(|_| usage_and_exit());
        ports.push(p);
    }
    if ports.is_empty() {
        usage_and_exit();
    }
    ports
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
}

fn required_arg(args: &[String], key: &str) -> String {
    arg_value(args, key).unwrap_or_else(|| usage_and_exit())
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|a| a == key)
}

fn optional_u64(args: &[String], key: &str) -> Option<u64> {
    arg_value(args, key).map(|v| v.parse::<u64>().unwrap_or_else(|_| usage_and_exit()))
}

fn required_u64(args: &[String], key: &str) -> u64 {
    required_arg(args, key)
        .parse::<u64>()
        .unwrap_or_else(|_| usage_and_exit())
}

fn optional_bool(args: &[String], key: &str, default: bool) -> bool {
    arg_value(args, key)
        .map(|v| match v.as_str() {
            "true" => true,
            "false" => false,
            _ => usage_and_exit(),
        })
        .unwrap_or(default)
}

fn required_bool(args: &[String], key: &str) -> bool {
    match required_arg(args, key).as_str() {
        "true" => true,
        "false" => false,
        _ => usage_and_exit(),
    }
}

fn add_common_nft_wallet_fields(body: &mut serde_json::Value, args: &[String]) {
    if let Some(nonce) = optional_u64(args, "--nonce") {
        body["nonce"] = serde_json::json!(nonce);
    }
    if let Some(max_fee) = optional_u64(args, "--max-fee") {
        body["max_fee_per_tx"] = serde_json::json!(max_fee);
    }
    if let Some(priority_fee) = optional_u64(args, "--priority-fee") {
        body["priority_fee"] = serde_json::json!(priority_fee);
    }
}

fn maybe_sign_and_optionally_submit(
    host: &str,
    port: u16,
    build_response: &str,
    args: &[String],
) -> Result<(), String> {
    let Some(sk_b64) = arg_value(args, "--signing-key-b64") else {
        return Ok(());
    };
    let body = http_body_from_response(build_response)?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("build response JSON parse failed: {e}"))?;
    if json.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err("refusing to sign non-ok build_unsigned response".to_string());
    }
    let payload_value = json
        .get("payload")
        .ok_or_else(|| "build_unsigned response missing payload".to_string())?
        .clone();
    let payload: TransactionPayload =
        serde_json::from_value(payload_value).map_err(|e| format!("payload decode failed: {e}"))?;
    let signature_b64 =
        sign_payload_ed25519(&sk_b64, &payload).map_err(|e| format!("sign error: {e}"))?;
    let signed = SignedTransaction {
        public_key_b64: payload.from.clone(),
        payload,
        signature_b64,
    };
    let signed_json = serde_json::to_string_pretty(&signed)
        .map_err(|e| format!("signed tx serialize failed: {e}"))?;
    println!("[TXGEN][NFT] signed_transaction_json:\n{signed_json}");

    if has_flag(args, "--submit") {
        let resp = http_post_json(host, port, "/api/v2/tx/submit_signed", &signed_json)?;
        println!("[TXGEN][NFT] submit response:\n{resp}");
    }

    Ok(())
}

fn post_nft_build_request(
    host: &str,
    port: u16,
    mut body: serde_json::Value,
    args: &[String],
) -> Result<(), String> {
    add_common_nft_wallet_fields(&mut body, args);
    let req = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let resp = http_post_json(host, port, "/api/v2/nft/build_unsigned", &req)?;
    println!("{resp}");
    maybe_sign_and_optionally_submit(host, port, &resp, args)
}

fn run_nft_cli(command: &str, args: &[String]) -> Result<(), String> {
    let host = arg_value(args, "--host").unwrap_or_else(|| "127.0.0.1".to_string());
    let port = arg_value(args, "--port")
        .unwrap_or_else(|| "8000".to_string())
        .parse::<u16>()
        .unwrap_or_else(|_| usage_and_exit());

    match command {
        "nft-build-create" => {
            let mut body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "create_collection",
                "symbol": required_arg(args, "--symbol"),
                "name": required_arg(args, "--name"),
                "base_uri": required_arg(args, "--base-uri"),
                "metadata_hash_hex": required_arg(args, "--metadata-hash-hex"),
                "mintable": optional_bool(args, "--mintable", true),
                "burnable": optional_bool(args, "--burnable", true),
                "asset_type": arg_value(args, "--asset-type").unwrap_or_else(|| "collectible".to_string()),
                "transfer_policy": arg_value(args, "--transfer-policy").unwrap_or_else(|| "transferable".to_string()),
                "revocable": optional_bool(args, "--revocable", false)
            });
            body["max_supply"] = match optional_u64(args, "--max-supply") {
                Some(max_supply) => serde_json::json!(max_supply),
                None => serde_json::Value::Null,
            };
            add_common_nft_wallet_fields(&mut body, args);
            let req = serde_json::to_string(&body).map_err(|e| e.to_string())?;
            let resp = http_post_json(&host, port, "/api/v2/nft/build_unsigned", &req)?;
            println!("{resp}");
            maybe_sign_and_optionally_submit(&host, port, &resp, args)
        }
        "nft-build-mint" => {
            let mut body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "mint",
                "collection_id": required_u64(args, "--collection-id"),
                "to": required_arg(args, "--to"),
                "token_uri": required_arg(args, "--token-uri"),
                "metadata_hash_hex": required_arg(args, "--metadata-hash-hex")
            });
            body["expires_at_height"] = match optional_u64(args, "--expires-at-height") {
                Some(exp) => serde_json::json!(exp),
                None => serde_json::Value::Null,
            };
            add_common_nft_wallet_fields(&mut body, args);
            let req = serde_json::to_string(&body).map_err(|e| e.to_string())?;
            let resp = http_post_json(&host, port, "/api/v2/nft/build_unsigned", &req)?;
            println!("{resp}");
            maybe_sign_and_optionally_submit(&host, port, &resp, args)
        }
        "nft-build-transfer" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "transfer",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial"),
                "to": required_arg(args, "--to")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-approve" => {
            let mut body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "approve",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial"),
                "approved": serde_json::Value::Null
            });
            if let Some(approved) = arg_value(args, "--approved") {
                body["approved"] = serde_json::json!(approved);
            }
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-set-approval-for-all" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "set_approval_for_all",
                "collection_id": required_u64(args, "--collection-id"),
                "operator": required_arg(args, "--operator"),
                "approved": required_bool(args, "--approved")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-burn" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "burn",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-revoke" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "revoke",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-set-token-uri" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "set_token_uri",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial"),
                "token_uri": required_arg(args, "--token-uri"),
                "metadata_hash_hex": required_arg(args, "--metadata-hash-hex")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-set-collection-uri" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "set_collection_uri",
                "collection_id": required_u64(args, "--collection-id"),
                "base_uri": required_arg(args, "--base-uri"),
                "metadata_hash_hex": required_arg(args, "--metadata-hash-hex")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-freeze-token" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "freeze_token",
                "collection_id": required_u64(args, "--collection-id"),
                "serial": required_u64(args, "--serial"),
                "frozen": required_bool(args, "--frozen")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-set-collection-policy" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "set_collection_policy",
                "collection_id": required_u64(args, "--collection-id"),
                "mintable": required_bool(args, "--mintable"),
                "burnable": required_bool(args, "--burnable"),
                "transfer_policy": required_arg(args, "--transfer-policy"),
                "revocable": required_bool(args, "--revocable")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-set-issuer" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "set_issuer",
                "collection_id": required_u64(args, "--collection-id"),
                "issuer": required_arg(args, "--issuer")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-build-pause" => {
            let body = serde_json::json!({
                "from": required_arg(args, "--from"),
                "op": "pause",
                "collection_id": required_u64(args, "--collection-id"),
                "paused": required_bool(args, "--paused")
            });
            post_nft_build_request(&host, port, body, args)
        }
        "nft-submit-signed" => {
            let path = required_arg(args, "--file");
            let body = fs::read_to_string(&path)
                .map_err(|e| format!("read signed tx file failed: {e}"))?;
            let resp = http_post_json(&host, port, "/api/v2/tx/submit_signed", &body)?;
            println!("{resp}");
            Ok(())
        }
        _ => Err(format!("unknown NFT command: {command}")),
    }
}

fn main() {
    let all_args: Vec<String> = env::args().skip(1).collect();
    if let Some(command) = all_args.first() {
        if matches!(
            command.as_str(),
            "nft-build-create"
                | "nft-build-mint"
                | "nft-build-transfer"
                | "nft-build-approve"
                | "nft-build-set-approval-for-all"
                | "nft-build-burn"
                | "nft-build-revoke"
                | "nft-build-set-token-uri"
                | "nft-build-set-collection-uri"
                | "nft-build-freeze-token"
                | "nft-build-set-collection-policy"
                | "nft-build-set-issuer"
                | "nft-build-pause"
                | "nft-submit-signed"
        ) {
            if let Err(e) = run_nft_cli(command, &all_args[1..]) {
                eprintln!("[TXGEN][NFT][ERR] {e}");
                std::process::exit(1);
            }
            return;
        }
    }

    let mut host = "127.0.0.1".to_string();
    let mut ports: Vec<u16> = vec![8000];
    let mut path = "/api/v2/tx/submit_signed".to_string();

    let mut senders: usize = 1;
    let mut tx_per_sender: usize = 25;
    let mut amount: u64 = 1;
    let mut fee: u64 = 100;

    let mut receiver_override: Option<String> = None;
    let mut memo: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host = args.next().unwrap_or_else(|| usage_and_exit()),
            "--ports" => ports = parse_ports(&args.next().unwrap_or_else(|| usage_and_exit())),
            "--path" => path = args.next().unwrap_or_else(|| usage_and_exit()),

            "--senders" => {
                senders = args
                    .next()
                    .unwrap_or_else(|| usage_and_exit())
                    .parse()
                    .unwrap_or_else(|_| usage_and_exit())
            }
            "--tx-per-sender" => {
                tx_per_sender = args
                    .next()
                    .unwrap_or_else(|| usage_and_exit())
                    .parse()
                    .unwrap_or_else(|_| usage_and_exit())
            }
            "--amount" => {
                amount = args
                    .next()
                    .unwrap_or_else(|| usage_and_exit())
                    .parse()
                    .unwrap_or_else(|_| usage_and_exit())
            }
            "--fee" => {
                fee = args
                    .next()
                    .unwrap_or_else(|| usage_and_exit())
                    .parse()
                    .unwrap_or_else(|_| usage_and_exit())
            }

            "--receiver" => {
                receiver_override = Some(args.next().unwrap_or_else(|| usage_and_exit()))
            }
            "--memo" => memo = Some(args.next().unwrap_or_else(|| usage_and_exit())),
            _ => usage_and_exit(),
        }
    }

    // Receiver: override o fresh
    let recv_pk_b64 = if let Some(pk) = receiver_override.clone() {
        pk
    } else {
        let mut csprng = OsRng;
        let recv_sk = SigningKey::generate(&mut csprng);
        STANDARD.encode(recv_sk.verifying_key().to_bytes())
    };

    println!("[TXGEN] receiver_pk_b64={recv_pk_b64}");
    println!(
        "[TXGEN] params: senders={} tx_per_sender={} amount={} fee={} ports={:?} path={}",
        senders, tx_per_sender, amount, fee, ports, path
    );

    let mut csprng = OsRng;

    for s in 0..senders {
        let sk = SigningKey::generate(&mut csprng);
        let pk_b64 = STANDARD.encode(sk.verifying_key().to_bytes());
        let sk_b64 = STANDARD.encode(sk.to_bytes());

        println!("[TXGEN] sender[{s}] pk_b64={pk_b64}");

        for i in 0..tx_per_sender {
            let nonce = (i as u64) + 1;

            let payload = TransactionPayload {
                network_id: chain_identity::network_id().to_string(),
                from: pk_b64.clone(),
                to: recv_pk_b64.clone(),
                amount,
                max_fee_per_tx: fee,
                nonce,
                memo: memo.clone(),
            };

            let sig_b64 = sign_payload_ed25519(&sk_b64, &payload)
                .unwrap_or_else(|e| panic!("sign error: {e}"));

            let signed = SignedTransaction {
                payload,
                public_key_b64: pk_b64.clone(),
                signature_b64: sig_b64,
            };

            let json = serde_json::to_string(&signed).expect("json serialize failed");

            // invia la STESSA tx a tutte le porte
            for &port in &ports {
                let resp = http_post_json(&host, port, &path, &json)
                    .unwrap_or_else(|e| panic!("http post failed: {e}"));

                let status_line = resp.lines().next().unwrap_or("");
                let ok_hint = if resp.contains("\"status\":\"ok\"") {
                    "OK"
                } else {
                    "ERR"
                };

                println!(
                    "[TXGEN] submit sender[{s}] nonce={nonce} fee={fee} -> {ok_hint} | {host}:{port} | {status_line}"
                );
            }
        }
    }

    println!("[TXGEN] done.");
}
