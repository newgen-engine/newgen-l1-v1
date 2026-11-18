use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use newgen_engine::wallet::{
    sign_payload_ed25519, verify_signed_transaction, SignedTransaction, TransactionPayload,
};
use newgen_engine::wallet_secure::SecureWallet;

const DEFAULT_CHAIN_API: &str = "http://127.0.0.1:8005";
const DEFAULT_WALLET_PATH: &str = "wallets/wallet.json";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 15;
const NGT_DECIMALS: u32 = 6;
const MAX_MEMO_BYTES: usize = 512;
const MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;
const HTTP_READ_CHUNK_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiScheme {
    Http,
    Https,
}

impl ApiScheme {
    fn as_str(self) -> &'static str {
        match self {
            ApiScheme::Http => "http",
            ApiScheme::Https => "https",
        }
    }
}

#[derive(Debug, Clone)]
struct ApiTarget {
    scheme: ApiScheme,
    host: String,
    port: u16,
    base_path: String,
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status_code: u16,
    body: String,
}

#[derive(Debug, Clone)]
struct CliConfig {
    api: ApiTarget,
    wallet_path: PathBuf,
    timeout: Duration,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("[ERR] {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_usage();
        return Ok(());
    }

    let cmd = args[0].as_str();
    let rest = &args[1..];
    let cfg = CliConfig::from_env()?;

    match cmd {
        "create" => cmd_create(rest, &cfg),
        "show" => cmd_show(rest, &cfg),
        "balance" => cmd_balance(rest, &cfg),
        "next-nonce" | "next_nonce" => cmd_next_nonce(rest, &cfg),
        "send" => cmd_send(rest, &cfg),
        "tx-status" | "tx_status" => cmd_tx_status(rest, &cfg),
        "history" => cmd_history(rest, &cfg),
        "nft-assets" | "nft_assets" => cmd_nft_assets(rest, &cfg),
        "nft-owner-collections" | "nft_owner_collections" => cmd_nft_owner_collections(rest, &cfg),
        "nft-collection" | "nft_collection" => cmd_nft_collection(rest, &cfg),
        "nft-token" | "nft_token" => cmd_nft_token(rest, &cfg),
        "nft-policy" | "nft_policy" => cmd_nft_policy(rest, &cfg),
        "nft-preflight" | "nft_preflight" => cmd_nft_preflight(rest, &cfg),
        "nft-create-collection" | "nft_create_collection" => cmd_nft_create_collection(rest, &cfg),
        "nft-mint" | "nft_mint" => cmd_nft_mint(rest, &cfg),
        "nft-transfer" | "nft_transfer" => cmd_nft_transfer(rest, &cfg),
        _ => Err(format!(
            "unknown command '{cmd}'. Run: newgen_wallet --help"
        )),
    }
}

impl CliConfig {
    fn from_env() -> Result<Self, String> {
        let api_raw =
            env::var("NEWGEN_CHAIN_API").unwrap_or_else(|_| DEFAULT_CHAIN_API.to_string());
        let api = parse_http_url(&api_raw)?;
        let wallet_path = env::var("NEWGEN_WALLET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_WALLET_PATH));
        let timeout_secs = env::var("NEWGEN_WALLET_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS)
            .clamp(1, 120);
        Ok(Self {
            api,
            wallet_path,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn print_usage() {
    println!(
        "NewGen Wallet Client V1\n\n\
Usage:\n\
  newgen_wallet create [--force]\n\
  newgen_wallet show\n\
  newgen_wallet balance [--address <public_key_b64>]\n\
  newgen_wallet next-nonce [--address <public_key_b64>]\n\
  newgen_wallet send --to <public_key_b64> --amount-ngt <decimal> [--memo <text>] [--max-fee-atomic <u64>] --yes\n\
  newgen_wallet tx-status --tx <hash_hex>\n\
  newgen_wallet history [--address <public_key_b64>] [--blocks <n>] [--max-txs <n>]\n\
  newgen_wallet nft-assets [--owner <public_key_b64>] [--cursor <n>] [--limit <n>]\n\
  newgen_wallet nft-owner-collections [--owner <public_key_b64>] [--cursor <n>] [--limit <n>]\n\
  newgen_wallet nft-collection --collection-id <u64>\n\
  newgen_wallet nft-token --collection-id <u64> --serial <u64>\n\
  newgen_wallet nft-policy\n\
  newgen_wallet nft-preflight --op <create_collection|mint|transfer>\n\
  newgen_wallet nft-create-collection --symbol <SYM> --name <NAME> --metadata-hash-hex <64hex> --base-uri <URI> --asset-type <kind> --transfer-policy <policy> --mintable <true|false> --burnable <true|false> --revocable <true|false> [--max-supply <u64>] [--max-fee-atomic <u64>] [--priority-fee-atomic <u64>] [--nonce <u64>] --yes\n\
  newgen_wallet nft-mint --collection-id <u64> --to <public_key_b64> --token-uri <URI> --metadata-hash-hex <64hex> [--expires-at-height <u64>] [--max-fee-atomic <u64>] [--priority-fee-atomic <u64>] [--nonce <u64>] --yes\n\
  newgen_wallet nft-transfer --collection-id <u64> --serial <u64> --to <public_key_b64> [--max-fee-atomic <u64>] [--priority-fee-atomic <u64>] [--nonce <u64>] --yes\n\n\
Environment:\n\
  NEWGEN_CHAIN_API=https://rpc.testnet.newgenengine.net  # or http://127.0.0.1:8005 for local lab\n\
  NEWGEN_WALLET_PATH=wallets\\wallet.json\n\
  NEWGEN_WALLET_PASSWORD_FILE=wallets\\wallet.passphrase\n\
  NEWGEN_WALLET_PASSWORD=<password>\n\
  NEWGEN_WALLET_HTTP_TIMEOUT_SECS=15\n\
  NEWGEN_WALLET_ALLOW_REMOTE_HTTP=1  # private/lab only; HTTPS is allowed for public RPC\n\n\
Wallet V1 address model:\n\
  receive_key/current_chain_address = Ed25519 public_key_b64.\n\
  NG1 display addresses are not spendable/fundable in Wallet V1.\n"
    );
}

fn cmd_create(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let force = has_flag(args, "--force");
    if cfg.wallet_path.exists() && !force {
        return Err(format!(
            "wallet already exists at {}. Refusing to overwrite. Use --force only if you intentionally want to replace it.",
            cfg.wallet_path.display()
        ));
    }
    let password = wallet_password()?;
    ensure_parent_dir(&cfg.wallet_path)?;

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let sk_bytes = signing_key.to_bytes();
    let wallet = SecureWallet::encrypt(&sk_bytes, &password)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;

    let json = serde_json::to_string_pretty(&wallet)
        .map_err(|e| format!("wallet serialize failed: {e}"))?;
    write_wallet_file_atomic(&cfg.wallet_path, json.as_bytes(), force)?;

    println!("[OK] wallet created");
    println!("wallet_path={}", cfg.wallet_path.display());
    println!("receive_key={}", wallet.public_key);
    println!("current_chain_address={}", wallet.public_key);
    println!("display_address_ng1={}", wallet.address);
    println!("warning=Wallet V1 uses receive_key/public_key_b64 for receiving and spending. Do not fund NG1 display addresses yet.");
    Ok(())
}

fn cmd_show(_args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let wallet = load_wallet(&cfg.wallet_path)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;
    println!("wallet_path={}", cfg.wallet_path.display());
    println!("receive_key={}", wallet.public_key);
    println!("current_chain_address={}", wallet.public_key);
    println!("display_address_ng1={}", wallet.address);
    println!("created_at={}", wallet.created_at);
    println!("version={}", wallet.version);
    println!(
        "warning=Private key is encrypted in wallet.json and is never printed by this command."
    );
    Ok(())
}

fn cmd_balance(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let address = address_arg_or_wallet(args, cfg)?;
    let json = api_get_json(
        cfg,
        &format!(
            "/api/v2/wallet/balance/{}",
            url_encode_path_segment(&address)
        ),
    )?;
    let balance = json_nonnegative_u64_field(&json, "balance")?;
    println!("address={address}");
    println!("balance_atomic={balance}");
    println!("balance_ngt={}", format_atomic_ngt(balance));
    println!(
        "raw_json={}",
        serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

fn cmd_next_nonce(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let address = address_arg_or_wallet(args, cfg)?;
    let json = api_get_json(
        cfg,
        &format!(
            "/api/v2/wallet/next_nonce/{}",
            url_encode_path_segment(&address)
        ),
    )?;
    let nonce = json_u64_field(&json, "next_nonce")?;
    println!("address={address}");
    println!("next_nonce={nonce}");
    println!(
        "raw_json={}",
        serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

fn cmd_send(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let to = required_arg(args, "--to")?;
    validate_spendable_wallet_v1_address(&to, "--to")?;
    let amount_raw = required_arg(args, "--amount-ngt")?;
    let amount = parse_ngt_amount_to_atomic(&amount_raw)?;
    if amount == 0 {
        return Err("amount must be greater than zero".to_string());
    }
    let memo = optional_arg(args, "--memo");
    if let Some(m) = &memo {
        if m.as_bytes().len() > MAX_MEMO_BYTES {
            return Err(format!("memo too large: max {} bytes", MAX_MEMO_BYTES));
        }
    }
    let yes = has_flag(args, "--yes");
    if !yes {
        return Err("send requires --yes to prevent accidental transfers".to_string());
    }

    let wallet = load_wallet(&cfg.wallet_path)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;
    let from = wallet.public_key.clone();
    let password = wallet_password()?;
    let sk_bytes = wallet.decrypt_result(&password)?;
    if sk_bytes.len() != 32 {
        return Err(format!(
            "wallet decrypted key length invalid: {}",
            sk_bytes.len()
        ));
    }
    let sk_b64 = STANDARD.encode(&sk_bytes);

    let status = api_get_json(cfg, "/status")?;
    let network_id = json_string_field(&status, "network_id")?;
    let base_fee = json_u64_field(&status, "base_fee_per_tx")?;
    let max_fee = match optional_arg(args, "--max-fee-atomic") {
        Some(v) => parse_u64_strict(&v, "--max-fee-atomic")?,
        None => base_fee,
    };
    if max_fee < base_fee {
        return Err(format!(
            "max_fee_too_low: provided={} required_at_least={}",
            max_fee, base_fee
        ));
    }

    let nonce_json = api_get_json(
        cfg,
        &format!(
            "/api/v2/wallet/next_nonce/{}",
            url_encode_path_segment(&from)
        ),
    )?;
    let nonce = json_u64_field(&nonce_json, "next_nonce")?;

    let balance_json = api_get_json(
        cfg,
        &format!("/api/v2/wallet/balance/{}", url_encode_path_segment(&from)),
    )?;
    let balance = json_nonnegative_u64_field(&balance_json, "balance")?;
    let required_total = checked_amount_plus_fee(amount, max_fee)?;
    if balance < required_total {
        return Err(format!(
            "insufficient_funds: balance_atomic={} required_atomic={} amount_atomic={} max_fee_atomic={}",
            balance, required_total, amount, max_fee
        ));
    }

    let payload = TransactionPayload {
        network_id,
        from: from.clone(),
        to: to.clone(),
        amount,
        max_fee_per_tx: max_fee,
        nonce,
        memo,
    };
    let signature_b64 = sign_payload_ed25519(&sk_b64, &payload)?;
    let signed = SignedTransaction {
        payload,
        public_key_b64: from.clone(),
        signature_b64,
    };
    verify_signed_transaction(&signed)?;

    let signed_json =
        serde_json::to_string(&signed).map_err(|e| format!("signed tx serialize failed: {e}"))?;
    let submit = api_post_json(cfg, "/api/v2/tx/submit_signed", &signed_json)?;
    if submit.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(format!("submit rejected: {}", compact_json(&submit)));
    }
    let tx_hash = json_string_field(&submit, "tx_hash")?;

    println!("[OK] tx submitted");
    println!("tx_hash={tx_hash}");
    println!("from={from}");
    println!("to={to}");
    println!("amount_atomic={amount}");
    println!("amount_ngt={}", format_atomic_ngt(amount));
    println!("max_fee_per_tx={max_fee}");
    println!("nonce={nonce}");
    println!("status_path=/api/v2/tx/by-hash/{tx_hash}");
    Ok(())
}

fn cmd_tx_status(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let tx = required_arg(args, "--tx")?;
    validate_tx_hash_hex(&tx)?;
    let json = api_get_json(cfg, &format!("/api/v2/tx/by-hash/{tx}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| compact_json(&json))
    );
    Ok(())
}

fn cmd_history(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let address = address_arg_or_wallet(args, cfg)?;
    let blocks = optional_arg(args, "--blocks")
        .map(|v| parse_u64_strict(&v, "--blocks"))
        .transpose()?
        .unwrap_or(200)
        .min(300);
    let max_txs = optional_arg(args, "--max-txs")
        .map(|v| parse_u64_strict(&v, "--max-txs"))
        .transpose()?
        .unwrap_or(200)
        .min(5000);
    let path = format!(
        "/api/tx/history/{}?blocks={}&max_txs={}&only_user_txs=true",
        url_encode_path_segment(&address),
        blocks,
        max_txs
    );
    let json = api_get_json(cfg, &path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| compact_json(&json))
    );
    Ok(())
}

fn cmd_nft_assets(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let owner = owner_arg_or_wallet(args, cfg)?;
    let cursor = optional_arg(args, "--cursor")
        .map(|v| parse_u64_strict(&v, "--cursor"))
        .transpose()?
        .unwrap_or(0);
    let limit = optional_arg(args, "--limit")
        .map(|v| parse_u64_strict(&v, "--limit"))
        .transpose()?
        .unwrap_or(50)
        .clamp(1, 200);
    let path = format!(
        "/api/v2/nft/wallet?owner={}&cursor={}&limit={}",
        url_encode_path_segment(&owner),
        cursor,
        limit
    );
    print_json(api_get_json(cfg, &path)?)
}

fn cmd_nft_owner_collections(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let owner = owner_arg_or_wallet(args, cfg)?;
    let cursor = optional_arg(args, "--cursor")
        .map(|v| parse_u64_strict(&v, "--cursor"))
        .transpose()?
        .unwrap_or(0);
    let limit = optional_arg(args, "--limit")
        .map(|v| parse_u64_strict(&v, "--limit"))
        .transpose()?
        .unwrap_or(50)
        .clamp(1, 200);
    let path = format!(
        "/api/v2/nft/owner_collections?owner={}&cursor={}&limit={}",
        url_encode_path_segment(&owner),
        cursor,
        limit
    );
    print_json(api_get_json(cfg, &path)?)
}

fn cmd_nft_collection(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let collection_id = required_nonzero_u64_arg(args, "--collection-id")?;
    print_json(api_get_json(
        cfg,
        &format!("/api/v2/nft/collection?id={collection_id}"),
    )?)
}

fn cmd_nft_token(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let collection_id = required_nonzero_u64_arg(args, "--collection-id")?;
    let serial = required_nonzero_u64_arg(args, "--serial")?;
    print_json(api_get_json(
        cfg,
        &format!("/api/v2/nft/token?collection_id={collection_id}&serial={serial}"),
    )?)
}

fn cmd_nft_policy(_args: &[String], cfg: &CliConfig) -> Result<(), String> {
    print_json(api_get_json(cfg, "/api/v2/nft/policy")?)
}

fn cmd_nft_preflight(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    let op = optional_arg(args, "--op")
        .or_else(|| args.iter().find(|a| !a.starts_with('-')).cloned())
        .ok_or_else(|| {
            "missing required NFT operation: use --op <create_collection|mint|transfer>".to_string()
        })?;
    let op = normalize_nft_cli_op(&op)?;
    let from = wallet_receive_key(cfg).ok();
    let report = preflight_nft_operation(cfg, &op, from.as_deref())?;
    println!("[OK] nft preflight accepted");
    println!("op={op}");
    println!(
        "source_commitment={}",
        json_required_string(&report, "source_commitment")?
    );
    println!(
        "policy_hash={}",
        json_required_string(&report, "policy_hash")?
    );
    if let Some(required) = report.get("required_fee_atomic").and_then(|v| v.as_u64()) {
        println!("required_fee_atomic={required}");
    }
    if let Some(balance) = report.get("balance_atomic").and_then(|v| v.as_u64()) {
        println!("balance_atomic={balance}");
    }
    Ok(())
}

fn cmd_nft_create_collection(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    require_yes(args, "nft-create-collection")?;
    let from = wallet_receive_key(cfg)?;
    let mut body = json!({
        "from": from,
        "op": "create_collection",
        "symbol": required_arg(args, "--symbol")?,
        "name": required_arg(args, "--name")?,
        "max_supply": optional_u64_json_arg(args, "--max-supply")?,
        "base_uri": required_arg(args, "--base-uri")?,
        "metadata_hash_hex": required_hash32_hex_arg(args, "--metadata-hash-hex")?,
        "mintable": required_bool_arg(args, "--mintable")?,
        "burnable": required_bool_arg(args, "--burnable")?,
        "asset_type": required_arg(args, "--asset-type")?,
        "transfer_policy": required_arg(args, "--transfer-policy")?,
        "revocable": required_bool_arg(args, "--revocable")?,
    });
    add_optional_tx_controls(&mut body, args)?;
    build_sign_submit_nft(cfg, body, "nft-create-collection")
}

fn cmd_nft_mint(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    require_yes(args, "nft-mint")?;
    let from = wallet_receive_key(cfg)?;
    let to = required_arg(args, "--to")?;
    validate_spendable_wallet_v1_address(&to, "--to")?;
    let mut body = json!({
        "from": from,
        "op": "mint",
        "collection_id": required_nonzero_u64_arg(args, "--collection-id")?,
        "to": to,
        "token_uri": required_arg(args, "--token-uri")?,
        "metadata_hash_hex": required_hash32_hex_arg(args, "--metadata-hash-hex")?,
        "expires_at_height": optional_u64_json_arg(args, "--expires-at-height")?,
    });
    add_optional_tx_controls(&mut body, args)?;
    build_sign_submit_nft(cfg, body, "nft-mint")
}

fn cmd_nft_transfer(args: &[String], cfg: &CliConfig) -> Result<(), String> {
    require_yes(args, "nft-transfer")?;
    let from = wallet_receive_key(cfg)?;
    let to = required_arg(args, "--to")?;
    validate_spendable_wallet_v1_address(&to, "--to")?;
    let mut body = json!({
        "from": from,
        "op": "transfer",
        "collection_id": required_nonzero_u64_arg(args, "--collection-id")?,
        "serial": required_nonzero_u64_arg(args, "--serial")?,
        "to": to,
    });
    add_optional_tx_controls(&mut body, args)?;
    build_sign_submit_nft(cfg, body, "nft-transfer")
}

fn build_sign_submit_nft(
    cfg: &CliConfig,
    build_body: Value,
    operation_label: &str,
) -> Result<(), String> {
    let wallet = load_wallet(&cfg.wallet_path)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;

    // Public-mainnet UX: do every finalized-policy and balance preflight before asking
    // for the wallet password. The private key is decrypted only after the operation is
    // known to be currently admissible by finalized NFT policy.
    let requested_op = json_required_string(&build_body, "op")?;
    preflight_nft_operation(cfg, &requested_op, Some(&wallet.public_key))?;

    let password = wallet_password()?;
    let sk_bytes = wallet.decrypt_result(&password)?;
    if sk_bytes.len() != 32 {
        return Err(format!(
            "wallet decrypted key length invalid: {}",
            sk_bytes.len()
        ));
    }
    let sk_b64 = STANDARD.encode(&sk_bytes);
    let build_body_s = serde_json::to_string(&build_body)
        .map_err(|e| format!("nft build request serialize failed: {e}"))?;
    let built = api_post_json(cfg, "/api/v2/nft/build_unsigned", &build_body_s)?;
    if built.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(format!(
            "nft build_unsigned rejected: {}",
            compact_json(&built)
        ));
    }

    let submit_path = json_required_string(&built, "submit_path")?;
    if submit_path != "/api/v2/tx/submit_signed" {
        return Err(format!(
            "unsupported submit_path from nft builder: {submit_path}"
        ));
    }

    let payload_value = built.get("payload").cloned().ok_or_else(|| {
        format!(
            "nft build_unsigned response missing payload: {}",
            compact_json(&built)
        )
    })?;
    let payload: TransactionPayload = serde_json::from_value(payload_value).map_err(|e| {
        format!(
            "nft payload decode failed: {e}; response={}",
            compact_json(&built)
        )
    })?;
    verify_nft_built_payload_matches_intent(
        cfg,
        &build_body,
        &built,
        &payload,
        &wallet.public_key,
    )?;

    let signature_b64 = sign_payload_ed25519(&sk_b64, &payload)?;
    let signed = SignedTransaction {
        payload,
        public_key_b64: wallet.public_key.clone(),
        signature_b64,
    };
    verify_signed_transaction(&signed)?;
    let signed_json = serde_json::to_string(&signed)
        .map_err(|e| format!("signed nft tx serialize failed: {e}"))?;
    let submit = api_post_json(cfg, &submit_path, &signed_json)?;
    if submit.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(format!(
            "nft submit rejected: {}; note=policy_may_change_before_inclusion_submit_can_still_fail_after_finalized_preflight",
            compact_json(&submit)
        ));
    }
    let tx_hash = json_string_field(&submit, "tx_hash")?;
    let op = json_required_string(&built, "op")?;
    println!("[OK] nft tx submitted");
    println!("operation={operation_label}");
    println!("policy_note=finalized policy was checked before signing; inclusion can still fail if governance policy changes before the transaction is admitted");
    println!("op={op}");
    println!("tx_hash={tx_hash}");
    println!("from={}", signed.public_key_b64);
    if let Some(fee) = built.get("fee") {
        println!("fee={}", compact_json(fee));
    }
    if let Some(nonce) = built.get("nonce") {
        println!("nonce={}", compact_json(nonce));
    }
    println!("status_path=/api/v2/tx/by-hash/{tx_hash}");
    Ok(())
}

fn verify_nft_built_payload_matches_intent(
    cfg: &CliConfig,
    requested: &Value,
    built: &Value,
    payload: &TransactionPayload,
    wallet_public_key: &str,
) -> Result<(), String> {
    let status = api_get_json(cfg, "/status")?;
    let network_id = json_string_field(&status, "network_id")?;

    if payload.network_id != network_id {
        return Err(format!(
            "nft payload network_id mismatch: status={} payload={}",
            network_id, payload.network_id
        ));
    }
    if payload.from != wallet_public_key {
        return Err(format!(
            "nft payload sender mismatch: wallet={} payload.from={}",
            wallet_public_key, payload.from
        ));
    }
    if payload.to != newgen_engine::nft::NFT_RECEIVER {
        return Err(format!(
            "nft payload receiver mismatch: expected={} got={}",
            newgen_engine::nft::NFT_RECEIVER,
            payload.to
        ));
    }
    if payload.amount != 0 {
        return Err(format!(
            "nft payload amount must be zero, got {}",
            payload.amount
        ));
    }
    let built_fee = built.get("fee").ok_or_else(|| {
        format!(
            "nft build_unsigned missing fee object: {}",
            compact_json(built)
        )
    })?;
    let expected_max_fee = expected_nft_max_fee_from_request(requested, built_fee)?;
    let built_max_fee = json_u64_field(built_fee, "max_fee_per_tx")?;
    if built_max_fee != expected_max_fee {
        return Err(format!(
            "nft build fee-intent mismatch: fee.max_fee_per_tx={} expected={}",
            built_max_fee, expected_max_fee
        ));
    }
    if payload.max_fee_per_tx != expected_max_fee {
        return Err(format!(
            "nft payload fee-intent mismatch: payload.max_fee_per_tx={} expected={}",
            payload.max_fee_per_tx, expected_max_fee
        ));
    }

    let requested_op = json_required_string(requested, "op")?;
    let built_op = json_required_string(built, "op")?;
    if built_op != requested_op {
        return Err(format!(
            "nft build op mismatch: requested={} built={}",
            requested_op, built_op
        ));
    }
    if let Some(req_nonce) = requested.get("nonce").and_then(|v| v.as_u64()) {
        if payload.nonce != req_nonce {
            return Err(format!(
                "nft payload nonce mismatch: requested={} payload={}",
                req_nonce, payload.nonce
            ));
        }
    }

    let payload_memo = payload
        .memo
        .as_ref()
        .ok_or_else(|| "nft payload memo missing".to_string())?;
    let memo_json: Value = serde_json::from_str(payload_memo)
        .map_err(|e| format!("nft payload memo is not valid JSON: {e}"))?;
    let built_memo = built
        .get("memo")
        .ok_or_else(|| "nft build_unsigned missing memo".to_string())?;
    if &memo_json != built_memo {
        return Err(format!(
            "nft memo mismatch between payload and builder response: payload={} built={}",
            compact_json(&memo_json),
            compact_json(built_memo)
        ));
    }
    verify_nft_memo_matches_request(&requested_op, requested, &memo_json)
}

fn normalize_nft_cli_op(op: &str) -> Result<String, String> {
    match op.trim().replace('-', "_").as_str() {
        "create" | "create_collection" | "nft_create_collection" => {
            Ok("create_collection".to_string())
        }
        "mint" | "nft_mint" => Ok("mint".to_string()),
        "transfer" | "nft_transfer" => Ok("transfer".to_string()),
        other => Err(format!(
            "unsupported_nft_preflight_op: {} (expected create_collection, mint, or transfer)",
            other
        )),
    }
}

fn preflight_nft_operation(cfg: &CliConfig, op: &str, from: Option<&str>) -> Result<Value, String> {
    let op = normalize_nft_cli_op(op)?;
    let policy = api_get_json(cfg, "/api/v2/nft/policy")?;
    if policy.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(format!("nft_policy_unavailable: {}", compact_json(&policy)));
    }
    if json_bool_field(&policy, "enabled")? == false {
        return Err("nft_disabled: finalized NFT policy is disabled".to_string());
    }
    if json_bool_field(&policy, "active")? == false {
        let activation_height = json_u64_field(&policy, "activation_height").unwrap_or(0);
        let finalized_height = json_u64_field(&policy, "finalized_height").unwrap_or(0);
        return Err(format!(
            "nft_activation_pending: activation_height={} finalized_height={}",
            activation_height, finalized_height
        ));
    }
    let public_key = match op.as_str() {
        "create_collection" => "public_create_enabled",
        "mint" => "public_mint_enabled",
        "transfer" => "public_transfer_enabled",
        _ => unreachable!(),
    };
    if json_bool_field(&policy, public_key)? == false {
        return Err(format!(
            "nft_{}_disabled: finalized policy denies this operation",
            op
        ));
    }
    let caps = policy
        .get("caps")
        .ok_or_else(|| format!("nft policy missing caps object: {}", compact_json(&policy)))?;
    for key in [
        "max_collections_per_owner",
        "max_tokens_per_collection",
        "max_tokens_per_owner",
    ] {
        let v = json_u64_field(caps, key)?;
        if v == 0 {
            return Err(format!("nft_caps_zero: {key}=0"));
        }
    }
    if json_bool_field(&policy, "metadata_hash_required")? == false {
        return Err("nft_metadata_hash_not_required: refusing weak public NFT policy".to_string());
    }

    let fees = policy
        .get("fees")
        .ok_or_else(|| format!("nft policy missing fees object: {}", compact_json(&policy)))?;
    let base_fee = json_u64_field(fees, "base_fee_per_tx")?;
    let op_fee_key = match op.as_str() {
        "create_collection" => "create_fee_native",
        "mint" => "mint_fee_native",
        "transfer" => "transfer_fee_native",
        _ => unreachable!(),
    };
    let op_fee = json_u64_field(fees, op_fee_key)?;
    let required_fee = base_fee.checked_add(op_fee).ok_or_else(|| {
        format!(
            "nft_fee_overflow: base_fee_per_tx={} {}={}",
            base_fee, op_fee_key, op_fee
        )
    })?;

    let mut report = json!({
        "status": "ok",
        "op": op,
        "source_commitment": json_required_string(&policy, "source_commitment")?,
        "policy_hash": json_required_string(&policy, "policy_hash")?,
        "required_fee_atomic": required_fee,
    });

    if let Some(address) = from {
        let balance_json = api_get_json(
            cfg,
            &format!(
                "/api/v2/wallet/balance/{}",
                url_encode_path_segment(address)
            ),
        )?;
        let balance = json_nonnegative_u64_field(&balance_json, "balance")?;
        if balance < required_fee {
            return Err(format!(
                "insufficient_funds_for_base_fee_plus_nft_fee: balance_atomic={} required_atomic={}",
                balance, required_fee
            ));
        }
        report["balance_atomic"] = json!(balance);
    }

    Ok(report)
}

fn json_bool_field(json: &Value, field: &str) -> Result<bool, String> {
    json.get(field).and_then(|v| v.as_bool()).ok_or_else(|| {
        format!(
            "response missing bool field '{field}': {}",
            compact_json(json)
        )
    })
}

fn expected_nft_max_fee_from_request(requested: &Value, built_fee: &Value) -> Result<u64, String> {
    let builder_base_fee = json_u64_field(built_fee, "base_fee_per_tx")?;
    if let Some(req_max_fee_v) = requested.get("max_fee_per_tx") {
        let req_max_fee = req_max_fee_v.as_u64().ok_or_else(|| {
            format!(
                "nft requested max_fee_per_tx must be u64 when present: {}",
                compact_json(requested)
            )
        })?;
        if req_max_fee < builder_base_fee {
            return Err(format!(
                "nft requested max_fee_per_tx below builder base fee: requested={} base_fee={}",
                req_max_fee, builder_base_fee
            ));
        }
        return Ok(req_max_fee);
    }

    let priority_fee = match requested.get("priority_fee") {
        Some(Value::Null) | None => 0,
        Some(v) => v.as_u64().ok_or_else(|| {
            format!(
                "nft requested priority_fee must be u64 when present: {}",
                compact_json(requested)
            )
        })?,
    };
    builder_base_fee.checked_add(priority_fee).ok_or_else(|| {
        format!(
            "nft expected max_fee_per_tx overflow: base_fee_per_tx={} priority_fee={}",
            builder_base_fee, priority_fee
        )
    })
}

fn verify_nft_memo_matches_request(
    op: &str,
    requested: &Value,
    memo: &Value,
) -> Result<(), String> {
    json_expect_u64(memo, "v", 1)?;
    json_expect_string(memo, "op", op)?;
    match op {
        "create_collection" => {
            json_expect_string(memo, "ctx", "NEWGEN:NFTV1:CREATE_COLLECTION")?;
            json_expect_same_string(requested, memo, "symbol")?;
            json_expect_same_string(requested, memo, "name")?;
            json_expect_same_nullable_u64(requested, memo, "max_supply")?;
            json_expect_same_string(requested, memo, "base_uri")?;
            json_expect_same_string(requested, memo, "metadata_hash_hex")?;
            json_expect_same_bool(requested, memo, "mintable")?;
            json_expect_same_bool(requested, memo, "burnable")?;
            json_expect_same_string(requested, memo, "asset_type")?;
            json_expect_same_string(requested, memo, "transfer_policy")?;
            json_expect_same_bool(requested, memo, "revocable")?;
        }
        "mint" => {
            json_expect_string(memo, "ctx", "NEWGEN:NFTV1:MINT")?;
            json_expect_same_u64(requested, memo, "collection_id")?;
            json_expect_same_string(requested, memo, "to")?;
            json_expect_same_string(requested, memo, "token_uri")?;
            json_expect_same_string(requested, memo, "metadata_hash_hex")?;
            json_expect_same_nullable_u64(requested, memo, "expires_at_height")?;
        }
        "transfer" => {
            json_expect_string(memo, "ctx", "NEWGEN:NFTV1:TRANSFER")?;
            json_expect_same_u64(requested, memo, "collection_id")?;
            json_expect_same_u64(requested, memo, "serial")?;
            json_expect_same_string(requested, memo, "to")?;
        }
        other => {
            return Err(format!(
                "unsupported NFT wallet operation for intent verification: {other}"
            ))
        }
    }
    Ok(())
}

fn json_required_string<'a>(json: &'a Value, field: &str) -> Result<&'a str, String> {
    json.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing string field '{}': {}", field, compact_json(json)))
}

fn json_expect_string(json: &Value, field: &str, expected: &str) -> Result<(), String> {
    let got = json_required_string(json, field)?;
    if got != expected {
        return Err(format!(
            "field '{}' mismatch: expected='{}' got='{}'",
            field, expected, got
        ));
    }
    Ok(())
}

fn json_expect_u64(json: &Value, field: &str, expected: u64) -> Result<(), String> {
    let got = json_u64_field(json, field)?;
    if got != expected {
        return Err(format!(
            "field '{}' mismatch: expected={} got={}",
            field, expected, got
        ));
    }
    Ok(())
}

fn json_expect_same_string(requested: &Value, actual: &Value, field: &str) -> Result<(), String> {
    let expected = json_required_string(requested, field)?;
    json_expect_string(actual, field, expected)
}

fn json_expect_same_u64(requested: &Value, actual: &Value, field: &str) -> Result<(), String> {
    let expected = json_u64_field(requested, field)?;
    json_expect_u64(actual, field, expected)
}

fn json_expect_same_bool(requested: &Value, actual: &Value, field: &str) -> Result<(), String> {
    let expected = requested
        .get(field)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| {
            format!(
                "missing bool field '{}': {}",
                field,
                compact_json(requested)
            )
        })?;
    let got = actual
        .get(field)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("missing bool field '{}': {}", field, compact_json(actual)))?;
    if got != expected {
        return Err(format!(
            "field '{}' mismatch: expected={} got={}",
            field, expected, got
        ));
    }
    Ok(())
}

fn json_expect_same_nullable_u64(
    requested: &Value,
    actual: &Value,
    field: &str,
) -> Result<(), String> {
    match (requested.get(field), actual.get(field)) {
        (Some(Value::Null), Some(Value::Null)) => Ok(()),
        (Some(Value::Number(_)), Some(Value::Number(_))) => {
            json_expect_same_u64(requested, actual, field)
        }
        (Some(exp), Some(got)) => Err(format!(
            "field '{}' mismatch: expected={} got={}",
            field, exp, got
        )),
        _ => Err(format!(
            "field '{}' missing: requested={} actual={}",
            field,
            compact_json(requested),
            compact_json(actual)
        )),
    }
}

fn print_json(json: Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| compact_json(&json))
    );
    Ok(())
}

fn wallet_receive_key(cfg: &CliConfig) -> Result<String, String> {
    let wallet = load_wallet(&cfg.wallet_path)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;
    Ok(wallet.public_key)
}

fn owner_arg_or_wallet(args: &[String], cfg: &CliConfig) -> Result<String, String> {
    if let Some(owner) = optional_arg(args, "--owner") {
        validate_spendable_wallet_v1_address(&owner, "--owner")?;
        return Ok(owner);
    }
    wallet_receive_key(cfg)
}

fn require_yes(args: &[String], command: &str) -> Result<(), String> {
    if has_flag(args, "--yes") {
        Ok(())
    } else {
        Err(format!(
            "{command} requires --yes to prevent accidental NFT transactions"
        ))
    }
}

fn required_nonzero_u64_arg(args: &[String], key: &str) -> Result<u64, String> {
    let v = parse_u64_strict(&required_arg(args, key)?, key)?;
    if v == 0 {
        return Err(format!("{key}: expected non-zero u64"));
    }
    Ok(v)
}

fn optional_u64_json_arg(args: &[String], key: &str) -> Result<Value, String> {
    match optional_arg(args, key) {
        Some(v) => Ok(Value::from(parse_u64_strict(&v, key)?)),
        None => Ok(Value::Null),
    }
}

fn required_bool_arg(args: &[String], key: &str) -> Result<bool, String> {
    parse_bool_strict(&required_arg(args, key)?, key)
}

fn parse_bool_strict(value: &str, label: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("{label}: expected true/false")),
    }
}

fn required_hash32_hex_arg(args: &[String], key: &str) -> Result<String, String> {
    let value = required_arg(args, key)?;
    validate_hash32_hex(&value, key)?;
    Ok(value.to_ascii_lowercase())
}

fn validate_hash32_hex(value: &str, label: &str) -> Result<(), String> {
    let v = value.trim();
    if v.len() != 64 || !v.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{label}: expected 32-byte hash as 64 hex characters"
        ));
    }
    Ok(())
}

fn add_optional_tx_controls(body: &mut Value, args: &[String]) -> Result<(), String> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| "internal_error: NFT request body must be object".to_string())?;
    if let Some(v) = optional_arg(args, "--max-fee-atomic") {
        obj.insert(
            "max_fee_per_tx".to_string(),
            Value::from(parse_u64_strict(&v, "--max-fee-atomic")?),
        );
    }
    if let Some(v) = optional_arg(args, "--priority-fee-atomic") {
        obj.insert(
            "priority_fee".to_string(),
            Value::from(parse_u64_strict(&v, "--priority-fee-atomic")?),
        );
    }
    if let Some(v) = optional_arg(args, "--nonce") {
        obj.insert(
            "nonce".to_string(),
            Value::from(parse_u64_strict(&v, "--nonce")?),
        );
    }
    Ok(())
}

fn wallet_password() -> Result<String, String> {
    if let Ok(path) = env::var("NEWGEN_WALLET_PASSWORD_FILE") {
        let trimmed_path = path.trim();
        if trimmed_path.is_empty() {
            return Err("NEWGEN_WALLET_PASSWORD_FILE is set but empty".to_string());
        }
        let raw = fs::read_to_string(trimmed_path).map_err(|e| {
            format!(
                "cannot read NEWGEN_WALLET_PASSWORD_FILE {}: {e}",
                trimmed_path
            )
        })?;
        return validate_wallet_password(
            raw.trim_end_matches(|c| c == '\r' || c == '\n').to_string(),
            "NEWGEN_WALLET_PASSWORD_FILE",
        );
    }

    let password = env::var("NEWGEN_WALLET_PASSWORD").map_err(|_| {
        "missing wallet password. Set NEWGEN_WALLET_PASSWORD_FILE or NEWGEN_WALLET_PASSWORD before running wallet commands.".to_string()
    })?;
    validate_wallet_password(password, "NEWGEN_WALLET_PASSWORD")
}

fn validate_wallet_password(password: String, source: &str) -> Result<String, String> {
    if password.len() < 8 {
        return Err(format!(
            "{source}: wallet password too short: minimum 8 characters"
        ));
    }
    Ok(password)
}

fn load_wallet(path: &Path) -> Result<SecureWallet, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("cannot read wallet {}: {e}", path.display()))?;
    serde_json::from_slice::<SecureWallet>(&bytes)
        .map_err(|e| format!("wallet JSON decode failed {}: {e}", path.display()))
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create wallet dir {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

fn write_wallet_file_atomic(
    path: &Path,
    bytes: &[u8],
    allow_overwrite: bool,
) -> Result<(), String> {
    ensure_parent_dir(path)?;
    if path.exists() && !allow_overwrite {
        return Err(format!(
            "wallet already exists at {}. Refusing to overwrite. Use --force only if you intentionally want to replace it.",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| format!("wallet path has invalid file name: {}", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        current_unix_nanos_for_tmp_name()
    ));

    let write_result = (|| -> Result<(), String> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("cannot create tmp wallet {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("cannot write tmp wallet {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("cannot fsync tmp wallet {}: {e}", tmp.display()))?;
        if path.exists() && !allow_overwrite {
            return Err(format!(
                "wallet appeared during create at {}; refusing to overwrite",
                path.display()
            ));
        }
        newgen_engine::utils::atomic_replace_file_v1(&tmp, path)
            .map_err(|e| format!("cannot atomically replace wallet {}: {e}", path.display()))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

fn current_unix_nanos_for_tmp_name() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn address_arg_or_wallet(args: &[String], cfg: &CliConfig) -> Result<String, String> {
    if let Some(address) = optional_arg(args, "--address") {
        validate_spendable_wallet_v1_address(&address, "--address")?;
        return Ok(address);
    }
    let wallet = load_wallet(&cfg.wallet_path)?;
    validate_public_key_b64_32(&wallet.public_key, "wallet.public_key")?;
    Ok(wallet.public_key)
}

fn validate_spendable_wallet_v1_address(value: &str, label: &str) -> Result<(), String> {
    if value.trim().starts_with("NG1") {
        return Err(format!(
            "{label}: NG1 display addresses are not spendable/fundable in Wallet V1. Use receive_key/public_key_b64."
        ));
    }
    validate_public_key_b64_32(value, label)
}

// Wallet V1 public recipients are canonical receive_key/public_key_b64 values.
// At this boundary we can safely enforce encoding and length. We must not claim
// to prove key ownership or spendability from the public key bytes alone; that is
// proven later by submit_signed signature verification.
fn validate_public_key_b64_32(value: &str, label: &str) -> Result<(), String> {
    let raw = STANDARD
        .decode(value.trim())
        .map_err(|e| format!("{label}: invalid base64 public key: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "{label}: invalid Ed25519 public key length: expected 32 bytes got {}",
            raw.len()
        ));
    }
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{label}: cannot convert public key to [u8; 32]"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| format!("{label}: invalid Ed25519 public key bytes: {e}"))?;
    Ok(())
}

fn checked_amount_plus_fee(amount: u64, max_fee: u64) -> Result<u64, String> {
    amount
        .checked_add(max_fee)
        .ok_or_else(|| "amount_plus_fee_overflow".to_string())
}

fn validate_tx_hash_hex(value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.len() != 64 || !v.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err("tx hash must be 64 hex characters".to_string());
    }
    Ok(())
}

fn parse_ngt_amount_to_atomic(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with('+') {
        return Err("invalid amount".to_string());
    }
    let mut parts = s.split('.');
    let whole = parts.next().unwrap_or("0");
    let frac = parts.next();
    if parts.next().is_some() {
        return Err("invalid amount: too many decimal points".to_string());
    }
    if whole.is_empty() || !whole.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return Err("invalid amount whole part".to_string());
    }
    let whole_val = whole
        .parse::<u64>()
        .map_err(|_| "amount whole part overflow".to_string())?;
    let scale = 10u64.pow(NGT_DECIMALS);
    let mut frac_val = 0u64;
    if let Some(frac_raw) = frac {
        if frac_raw.len() > NGT_DECIMALS as usize {
            return Err(format!("too many decimals: max {NGT_DECIMALS}"));
        }
        if !frac_raw.as_bytes().iter().all(|b| b.is_ascii_digit()) {
            return Err("invalid amount fractional part".to_string());
        }
        let mut padded = frac_raw.to_string();
        while padded.len() < NGT_DECIMALS as usize {
            padded.push('0');
        }
        if !padded.is_empty() {
            frac_val = padded
                .parse::<u64>()
                .map_err(|_| "amount fractional part overflow".to_string())?;
        }
    }
    whole_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| "amount overflow".to_string())
}

fn format_atomic_ngt(value: u64) -> String {
    let scale = 10u64.pow(NGT_DECIMALS);
    let whole = value / scale;
    let frac = value % scale;
    format!("{}.{:06}", whole, frac)
}

fn json_u64_field(json: &Value, field: &str) -> Result<u64, String> {
    json.get(field).and_then(|v| v.as_u64()).ok_or_else(|| {
        format!(
            "response missing nonnegative u64 field '{field}': {}",
            compact_json(json)
        )
    })
}

fn json_nonnegative_u64_field(json: &Value, field: &str) -> Result<u64, String> {
    match json.get(field) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("field '{field}' is negative or overflows u64")),
        Some(other) => Err(format!("field '{field}' is not a number: {other}")),
        None => Err(format!(
            "response missing field '{field}': {}",
            compact_json(json)
        )),
    }
}

fn json_string_field(json: &Value, field: &str) -> Result<String, String> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            format!(
                "response missing string field '{field}': {}",
                compact_json(json)
            )
        })
}

fn compact_json(json: &Value) -> String {
    serde_json::to_string(json).unwrap_or_else(|_| "<invalid-json>".to_string())
}

fn parse_u64_strict(value: &str, label: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{label}: expected u64"))
}

fn required_arg(args: &[String], key: &str) -> Result<String, String> {
    optional_arg(args, key).ok_or_else(|| format!("missing required argument {key}"))
}

fn optional_arg(args: &[String], key: &str) -> Option<String> {
    let mut i = 0usize;
    while i + 1 < args.len() {
        if args[i] == key {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|a| a == key)
}

fn parse_http_url(raw: &str) -> Result<ApiTarget, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, without_scheme, default_port) = if let Some(rest) =
        trimmed.strip_prefix("https://")
    {
        (ApiScheme::Https, rest, 443u16)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (ApiScheme::Http, rest, 80u16)
    } else {
        return Err("unsupported_rpc_scheme: NEWGEN_CHAIN_API must use https:// for public RPC or http:// for loopback/private lab".to_string());
    };
    let (host_port, base_path_raw) = match without_scheme.split_once('/') {
        Some((hp, path)) => (hp, format!("/{path}")),
        None => (without_scheme, String::new()),
    };
    if host_port.is_empty() {
        return Err("NEWGEN_CHAIN_API missing host".to_string());
    }
    let (host, port) = if let Some((host, port_s)) = host_port.rsplit_once(':') {
        let port = port_s
            .parse::<u16>()
            .map_err(|_| "NEWGEN_CHAIN_API port invalid".to_string())?;
        (host.to_string(), port)
    } else {
        (host_port.to_string(), default_port)
    };
    if host.is_empty() {
        return Err("NEWGEN_CHAIN_API host empty".to_string());
    }
    if scheme == ApiScheme::Http
        && !is_loopback_or_localhost(&host)
        && !env_flag_true("NEWGEN_WALLET_ALLOW_REMOTE_HTTP")
    {
        return Err(format!(
            "unsupported_rpc_scheme: remote plain HTTP is denied for wallet CLI host '{}'. Use https:// for public RPC, or set NEWGEN_WALLET_ALLOW_REMOTE_HTTP=1 only for controlled private testnet/lab use.",
            host
        ));
    }
    Ok(ApiTarget {
        scheme,
        host,
        port,
        base_path: base_path_raw.trim_end_matches('/').to_string(),
    })
}

fn is_loopback_or_localhost(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h.starts_with("127.")
}

fn env_flag_true(key: &str) -> bool {
    env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn api_get_json(cfg: &CliConfig, path: &str) -> Result<Value, String> {
    let resp = http_request_json(cfg, "GET", path, None)?;
    ensure_success_json_status("GET", path, &resp)?;
    serde_json::from_str::<Value>(&resp.body)
        .map_err(|e| format!("GET {path} JSON parse failed: {e}; body={}", resp.body))
}

fn api_post_json(cfg: &CliConfig, path: &str, body: &str) -> Result<Value, String> {
    let resp = http_request_json(cfg, "POST", path, Some(body))?;
    ensure_success_json_status("POST", path, &resp)?;
    serde_json::from_str::<Value>(&resp.body)
        .map_err(|e| format!("POST {path} JSON parse failed: {e}; body={}", resp.body))
}

fn ensure_success_json_status(method: &str, path: &str, resp: &HttpResponse) -> Result<(), String> {
    if (300..400).contains(&resp.status_code) {
        return Err(format!(
            "http_redirect_not_followed: {method} {path} returned status={} body={}",
            resp.status_code, resp.body
        ));
    }
    if !(200..300).contains(&resp.status_code) {
        return Err(format!(
            "{method} {path} failed status={} body={}",
            resp.status_code, resp.body
        ));
    }
    Ok(())
}

fn http_request_json(
    cfg: &CliConfig,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    let addr = resolve_one(&cfg.api.host, cfg.api.port)?;
    let tcp = TcpStream::connect_timeout(&addr, cfg.timeout).map_err(|e| {
        format!(
            "connect {}://{}:{} failed: {e}",
            cfg.api.scheme.as_str(),
            cfg.api.host,
            cfg.api.port
        )
    })?;
    tcp.set_read_timeout(Some(cfg.timeout))
        .map_err(|e| format!("set read timeout failed: {e}"))?;
    tcp.set_write_timeout(Some(cfg.timeout))
        .map_err(|e| format!("set write timeout failed: {e}"))?;

    match cfg.api.scheme {
        ApiScheme::Http => send_http_request_over_stream(cfg, tcp, method, path, body),
        ApiScheme::Https => {
            let connector = native_tls::TlsConnector::builder()
                .build()
                .map_err(|e| format!("https_tls_error: tls connector build failed: {e}"))?;
            let tls = connector.connect(&cfg.api.host, tcp).map_err(|e| {
                format!(
                    "https_tls_error: TLS handshake failed for {}:{}: {e}",
                    cfg.api.host, cfg.api.port
                )
            })?;
            send_http_request_over_stream(cfg, tls, method, path, body)
        }
    }
}

fn send_http_request_over_stream<S: Read + Write>(
    cfg: &CliConfig,
    mut stream: S,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    let request_path = format!("{}{}", cfg.api.base_path, path);
    let host_header = if (cfg.api.scheme == ApiScheme::Http && cfg.api.port == 80)
        || (cfg.api.scheme == ApiScheme::Https && cfg.api.port == 443)
    {
        cfg.api.host.clone()
    } else {
        format!("{}:{}", cfg.api.host, cfg.api.port)
    };
    let body = body.unwrap_or("");
    let req = if method == "POST" {
        format!(
            "POST {request_path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.as_bytes().len(),
            body
        )
    } else {
        format!(
            "GET {request_path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        )
    };
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write request failed: {e}"))?;
    let resp = read_http_response_bounded(&mut stream)?;
    parse_http_response(&resp)
}

fn read_http_response_bounded<S: Read>(stream: &mut S) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; HTTP_READ_CHUNK_BYTES];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read response failed: {e}"))?;
        if n == 0 {
            break;
        }
        let next_len = buf
            .len()
            .checked_add(n)
            .ok_or_else(|| "http_response_too_large: length overflow".to_string())?;
        if next_len > MAX_HTTP_RESPONSE_BYTES {
            return Err(format!(
                "http_response_too_large: max_bytes={}",
                MAX_HTTP_RESPONSE_BYTES
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf).map_err(|e| format!("HTTP response is not valid UTF-8: {e}"))
}

fn resolve_one(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS/addr resolve failed for {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address resolved for {host}:{port}"))
}

fn parse_http_response(raw: &str) -> Result<HttpResponse, String> {
    let (headers, body_raw) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .ok_or_else(|| "HTTP response missing header/body separator".to_string())?;
    let status_line = headers.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("HTTP status line invalid: {status_line}"))?
        .parse::<u16>()
        .map_err(|_| format!("HTTP status code invalid: {status_line}"))?;
    let body = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked_body(body_raw)?
    } else {
        body_raw.to_string()
    };
    Ok(HttpResponse { status_code, body })
}

fn decode_chunked_body(body: &str) -> Result<String, String> {
    let bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut out = Vec::new();
    loop {
        let rest = bytes
            .get(cursor..)
            .ok_or_else(|| "chunk cursor out of bounds".to_string())?;
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
        let decoded_len = out
            .len()
            .checked_add(size)
            .ok_or_else(|| "http_response_too_large: decoded chunk length overflow".to_string())?;
        if decoded_len > MAX_HTTP_RESPONSE_BYTES {
            return Err(format!(
                "http_response_too_large: decoded_body_max_bytes={}",
                MAX_HTTP_RESPONSE_BYTES
            ));
        }
        out.extend_from_slice(&bytes[cursor..cursor + size]);
        if &bytes[cursor + size..cursor + size + 2] != b"\r\n" {
            return Err("chunk trailer missing".to_string());
        }
        cursor += size + 2;
    }
}

fn url_encode_path_segment(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_parser_uses_six_decimals() {
        assert_eq!(parse_ngt_amount_to_atomic("0.000001").unwrap(), 1);
        assert_eq!(parse_ngt_amount_to_atomic("1").unwrap(), 1_000_000);
        assert_eq!(parse_ngt_amount_to_atomic("1.250000").unwrap(), 1_250_000);
        assert!(parse_ngt_amount_to_atomic("1.0000001").is_err());
        assert!(parse_ngt_amount_to_atomic("-1").is_err());
    }

    #[test]
    fn wallet_v1_rejects_ng1_display_address() {
        assert!(validate_spendable_wallet_v1_address("NG1abc", "--to").is_err());
    }

    #[test]
    fn wallet_v1_accepts_valid_ed25519_standard_b64_pubkey() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = STANDARD.encode(signing_key.verifying_key().to_bytes());
        assert!(validate_spendable_wallet_v1_address(&pk, "--to").is_ok());
    }

    #[test]
    fn wallet_v1_accepts_canonical_32_byte_receive_key_shape_without_claiming_ownership() {
        let pk = STANDARD.encode([0xffu8; 32]);
        assert!(validate_spendable_wallet_v1_address(&pk, "--to").is_ok());
    }

    #[test]
    fn wallet_v1_rejects_wrong_pubkey_length() {
        let pk = STANDARD.encode([7u8; 31]);
        assert!(validate_spendable_wallet_v1_address(&pk, "--to").is_err());
    }

    #[test]
    fn path_encoder_encodes_base64_reserved_chars() {
        assert_eq!(url_encode_path_segment("+/="), "%2B%2F%3D");
    }

    #[test]
    fn balance_parser_rejects_negative() {
        let v = serde_json::json!({"balance": -1});
        assert!(json_nonnegative_u64_field(&v, "balance").is_err());
    }

    #[test]
    fn checked_amount_plus_fee_rejects_overflow() {
        assert_eq!(checked_amount_plus_fee(10, 20).unwrap(), 30);
        assert!(checked_amount_plus_fee(u64::MAX, 1).is_err());
    }

    #[test]
    fn wallet_password_validation_rejects_short_password() {
        assert!(validate_wallet_password("short".to_string(), "test").is_err());
        assert!(validate_wallet_password("long-enough".to_string(), "test").is_ok());
    }

    #[test]
    fn atomic_wallet_write_refuses_existing_without_force() {
        let dir = std::env::temp_dir().join(format!(
            "newgen-wallet-test-{}-{}",
            std::process::id(),
            current_unix_nanos_for_tmp_name()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        write_wallet_file_atomic(&path, b"one", false).unwrap();
        assert!(write_wallet_file_atomic(&path, b"two", false).is_err());
        write_wallet_file_atomic(&path, b"two", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chunked_decoder_rejects_oversized_decoded_body() {
        let body = format!(
            "{:x}\r\n{}\r\n0\r\n\r\n",
            MAX_HTTP_RESPONSE_BYTES + 1,
            "a".repeat(MAX_HTTP_RESPONSE_BYTES + 1)
        );
        assert!(decode_chunked_body(&body).is_err());
    }

    #[test]
    fn parse_http_response_rejects_oversized_chunked_body() {
        let body = format!(
            "{:x}\r\n{}\r\n0\r\n\r\n",
            MAX_HTTP_RESPONSE_BYTES + 1,
            "a".repeat(MAX_HTTP_RESPONSE_BYTES + 1)
        );
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            body
        );
        assert!(parse_http_response(&raw).is_err());
    }

    #[test]
    fn api_url_accepts_localhost_by_default() {
        let api = parse_http_url("http://127.0.0.1:8005").unwrap();
        assert_eq!(api.host, "127.0.0.1");
        assert_eq!(api.port, 8005);
    }

    #[test]
    fn loopback_host_detector_is_strict() {
        assert!(is_loopback_or_localhost("localhost"));
        assert!(is_loopback_or_localhost("127.0.0.1"));
        assert!(!is_loopback_or_localhost("203.0.113.17"));
    }

    #[test]
    fn nft_hash32_validator_rejects_bad_values() {
        assert!(validate_hash32_hex(&"a".repeat(64), "hash").is_ok());
        assert!(validate_hash32_hex(&"a".repeat(63), "hash").is_err());
        assert!(validate_hash32_hex(&"z".repeat(64), "hash").is_err());
    }

    #[test]
    fn bool_parser_is_strict_for_nft_flags() {
        assert_eq!(parse_bool_strict("true", "b").unwrap(), true);
        assert_eq!(parse_bool_strict("0", "b").unwrap(), false);
        assert!(parse_bool_strict("maybe", "b").is_err());
    }

    #[test]
    fn optional_u64_json_arg_uses_null_when_missing() {
        let args: Vec<String> = vec![];
        assert!(optional_u64_json_arg(&args, "--max-supply")
            .unwrap()
            .is_null());
    }

    #[test]
    fn nft_intent_verification_rejects_mint_to_mismatch() {
        let requested = serde_json::json!({
            "from": "sender",
            "op": "mint",
            "collection_id": 7,
            "to": "receiver-a",
            "token_uri": "https://example.invalid/1.json",
            "metadata_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expires_at_height": null
        });
        let memo = serde_json::json!({
            "v": 1,
            "ctx": "NEWGEN:NFTV1:MINT",
            "op": "mint",
            "collection_id": 7,
            "to": "receiver-b",
            "token_uri": "https://example.invalid/1.json",
            "metadata_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expires_at_height": null
        });
        assert!(verify_nft_memo_matches_request("mint", &requested, &memo).is_err());
    }

    #[test]
    fn nft_intent_verification_accepts_transfer_exact_intent() {
        let requested = serde_json::json!({
            "from": "sender",
            "op": "transfer",
            "collection_id": 7,
            "serial": 3,
            "to": "receiver"
        });
        let memo = serde_json::json!({
            "v": 1,
            "ctx": "NEWGEN:NFTV1:TRANSFER",
            "op": "transfer",
            "collection_id": 7,
            "serial": 3,
            "to": "receiver"
        });
        assert!(verify_nft_memo_matches_request("transfer", &requested, &memo).is_ok());
    }

    #[test]
    fn nft_intent_verification_rejects_create_collection_hash_mismatch() {
        let requested = serde_json::json!({
            "from": "sender",
            "op": "create_collection",
            "symbol": "TEST",
            "name": "Test Collection",
            "max_supply": null,
            "base_uri": "https://example.invalid/nft/",
            "metadata_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "mintable": true,
            "burnable": false,
            "asset_type": "collectible",
            "transfer_policy": "transferable",
            "revocable": false
        });
        let memo = serde_json::json!({
            "v": 1,
            "ctx": "NEWGEN:NFTV1:CREATE_COLLECTION",
            "op": "create_collection",
            "symbol": "TEST",
            "name": "Test Collection",
            "max_supply": null,
            "base_uri": "https://example.invalid/nft/",
            "metadata_hash_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "mintable": true,
            "burnable": false,
            "asset_type": "collectible",
            "transfer_policy": "transferable",
            "revocable": false
        });
        assert!(verify_nft_memo_matches_request("create_collection", &requested, &memo).is_err());
    }

    #[test]
    fn nft_expected_fee_uses_base_fee_when_no_fee_args() {
        let requested = serde_json::json!({"op":"mint"});
        let fee = serde_json::json!({"base_fee_per_tx": 100u64, "max_fee_per_tx": 100u64});
        assert_eq!(
            expected_nft_max_fee_from_request(&requested, &fee).unwrap(),
            100
        );
    }

    #[test]
    fn nft_expected_fee_uses_base_plus_priority_fee() {
        let requested = serde_json::json!({"op":"mint", "priority_fee": 7u64});
        let fee = serde_json::json!({"base_fee_per_tx": 100u64, "max_fee_per_tx": 107u64});
        assert_eq!(
            expected_nft_max_fee_from_request(&requested, &fee).unwrap(),
            107
        );
    }

    #[test]
    fn nft_expected_fee_prefers_explicit_max_fee() {
        let requested =
            serde_json::json!({"op":"mint", "max_fee_per_tx": 150u64, "priority_fee": 999u64});
        let fee = serde_json::json!({"base_fee_per_tx": 100u64, "max_fee_per_tx": 150u64});
        assert_eq!(
            expected_nft_max_fee_from_request(&requested, &fee).unwrap(),
            150
        );
    }

    #[test]
    fn nft_expected_fee_rejects_priority_overflow() {
        let requested = serde_json::json!({"op":"mint", "priority_fee": u64::MAX});
        let fee = serde_json::json!({"base_fee_per_tx": 1u64, "max_fee_per_tx": u64::MAX});
        assert!(expected_nft_max_fee_from_request(&requested, &fee).is_err());
    }

    #[test]
    fn nft_expected_fee_rejects_explicit_max_below_base() {
        let requested = serde_json::json!({"op":"mint", "max_fee_per_tx": 99u64});
        let fee = serde_json::json!({"base_fee_per_tx": 100u64, "max_fee_per_tx": 99u64});
        assert!(expected_nft_max_fee_from_request(&requested, &fee).is_err());
    }
    #[test]
    fn parse_http_url_accepts_https_public_rpc_default_port() {
        let target = parse_http_url("https://rpc.testnet.newgenengine.net").unwrap();
        assert_eq!(target.scheme, ApiScheme::Https);
        assert_eq!(target.host, "rpc.testnet.newgenengine.net");
        assert_eq!(target.port, 443);
        assert_eq!(target.base_path, "");
    }

    #[test]
    fn parse_http_url_rejects_unsupported_rpc_scheme() {
        let err = parse_http_url("ftp://rpc.testnet.newgenengine.net").unwrap_err();
        assert!(err.contains("unsupported_rpc_scheme"));
    }

    #[test]
    fn parse_http_url_denies_remote_plain_http_by_default() {
        std::env::remove_var("NEWGEN_WALLET_ALLOW_REMOTE_HTTP");
        let err = parse_http_url("http://rpc.testnet.newgenengine.net").unwrap_err();
        assert!(err.contains("unsupported_rpc_scheme"));
    }

    #[test]
    fn nft_cli_op_normalization_is_strict() {
        assert_eq!(
            normalize_nft_cli_op("create-collection").unwrap(),
            "create_collection"
        );
        assert_eq!(normalize_nft_cli_op("mint").unwrap(), "mint");
        assert_eq!(normalize_nft_cli_op("transfer").unwrap(), "transfer");
        assert!(normalize_nft_cli_op("burn").is_err());
    }

    #[test]
    fn wallet_http_client_rejects_redirects_explicitly_v46() {
        let resp = HttpResponse {
            status_code: 302,
            body: "{\"status\":\"redirect\"}".to_string(),
        };
        let err = ensure_success_json_status("GET", "/api/v2/nft/policy", &resp).unwrap_err();
        assert!(err.contains("http_redirect_not_followed"));
    }
}
