// src/explorer.rs
//
// Static explorer UI server (Warp).
// Mainnet-grade hardening:
// - bind address controllabile via env
// - CORS allow-any solo se esplicitamente richiesto (o in local dev)
// - NFT public pages are read-only/linkable and consume canonical API read models.

use std::env;
use std::path::{Path, PathBuf};
use warp::Filter;

fn explorer_static_dir_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join("explorer_ui")
}

fn explorer_api_base_v1() -> String {
    env::var("NEWGEN_EXPLORER_API_BASE")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string())
}

fn explorer_escape_html_v1(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn explorer_script_json_string_v1(input: &str) -> String {
    serde_json::to_string(input)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn explorer_nft_shell_html_v1(title: &str, api_base: &str, body: &str, script: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title} · NewGen NFT</title>
  <style>
    :root {{ color-scheme: dark; --bg:#07111f; --panel:#0d1a2d; --muted:#8ea3bd; --text:#eaf2ff; --line:#1e3453; --accent:#6aa7ff; --bad:#ff8a8a; }}
    body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: radial-gradient(circle at top left,#10233e,#07111f 52%); color:var(--text); }}
    main {{ max-width:1120px; margin:0 auto; padding:32px 20px 48px; }}
    nav {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:28px; }}
    a {{ color:var(--accent); text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    h1 {{ margin:0 0 8px; font-size:32px; letter-spacing:-0.03em; }}
    .sub {{ color:var(--muted); margin:0 0 24px; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(260px,1fr)); gap:14px; }}
    .card {{ background:rgba(13,26,45,.88); border:1px solid var(--line); border-radius:16px; padding:16px; box-shadow:0 14px 36px rgba(0,0,0,.25); }}
    .row {{ display:flex; justify-content:space-between; gap:12px; border-top:1px solid var(--line); padding-top:10px; margin-top:10px; }}
    .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    code, pre {{ background:#06101d; border:1px solid var(--line); border-radius:10px; padding:2px 6px; color:#d7e7ff; }}
    pre {{ overflow:auto; padding:12px; }}
    input, button {{ background:#071423; color:var(--text); border:1px solid var(--line); border-radius:10px; padding:10px 12px; }}
    button {{ cursor:pointer; }}
    button:hover {{ border-color:var(--accent); }}
    .muted {{ color:var(--muted); }}
    .error {{ color:var(--bad); }}
    .pager {{ margin:16px 0 0; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  </style>
</head>
<body>
<main>
  <nav>
    <a href="/">Explorer</a>
    <a href="/nft">NFT Assets</a>
    <a href="/nft/recent">NFT Activity</a>
  </nav>
  {body}
</main>
<script>
const API_BASE = {api_base_json};
async function api(path) {{
  const res = await fetch(API_BASE + path, {{ cache: 'no-store' }});
  const json = await res.json();
  if (!res.ok || json.status === 'error') throw new Error(json.message || JSON.stringify(json));
  return json;
}}
function esc(x) {{ return String(x ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c])); }}
function short(x) {{ x = String(x ?? ''); return x.length > 24 ? x.slice(0,12)+'…'+x.slice(-8) : x; }}
{script}
</script>
</body>
</html>"#,
        title = explorer_escape_html_v1(title),
        body = body,
        script = script,
        api_base_json = explorer_script_json_string_v1(api_base)
    )
}

fn explorer_nft_index_html_v1(api_base: &str) -> String {
    explorer_nft_shell_html_v1(
        "NFT Assets",
        api_base,
        r#"<h1>NFT Assets</h1>
<p class="sub">Read-only Digital Asset Layer view. Data is loaded from finalized chain state/API read models; no marketplace actions are exposed here.</p>
<div class="card"><div class="label">API base</div><code id="apiBase"></code></div>
<h2>Collections</h2>
<div id="collections" class="grid"><div class="card muted">Loading…</div></div>
<div id="collectionsPager" class="pager"></div>"#,
        r#"document.getElementById('apiBase').textContent = API_BASE;
(async () => {
  const out = document.getElementById('collections');
  const cursor = new URLSearchParams(location.search).get('cursor') || '1';
  try {
    const data = await api(`/api/v2/nft/collections?cursor=${encodeURIComponent(cursor)}&limit=48`);
    if (!data.collections.length) { out.innerHTML = '<div class="card muted">No collections observed.</div>'; return; }
    out.innerHTML = data.collections.map(c => `
      <section class="card">
        <div class="label">Collection #${esc(c.id)}</div>
        <h3><a href="/nft/collection/${esc(c.id)}">${esc(c.name)} (${esc(c.symbol)})</a></h3>
        <p class="muted">${esc(c.asset_type)} · ${esc(c.transfer_policy)}</p>
        <div class="row"><span>Live supply</span><strong>${esc(c.live_supply)}</strong></div>
        <div class="row"><span>Indexed tokens</span><strong>${esc(c.token_count_indexed)}</strong></div>
        <div class="row"><span>Owner</span><code>${esc(short(c.owner_b64))}</code></div>
      </section>`).join('');
    document.getElementById('collectionsPager').innerHTML = data.next_cursor ? `<a href="/nft?cursor=${esc(data.next_cursor)}">Next page</a>` : '<span class="muted">End of finalized collection list.</span>';
  } catch (e) { out.innerHTML = `<div class="card error">${esc(e.message)}</div>`; }
})();"#,
    )
}

fn explorer_nft_recent_html_v1(api_base: &str) -> String {
    explorer_nft_shell_html_v1(
        "NFT Activity",
        api_base,
        r#"<h1>NFT Activity</h1>
<p class="sub">Recent state-derived NFT events from <code>Block.nft_events</code>. These are not memo previews.</p>
<div id="events" class="grid"><div class="card muted">Loading…</div></div>
<div id="eventsPager" class="pager"></div>"#,
        r#"(async () => {
  const out = document.getElementById('events');
  const cursor = new URLSearchParams(location.search).get('cursor') || '0';
  try {
    const data = await api(`/api/v2/nft/recent_activity?window=512&cursor=${encodeURIComponent(cursor)}&limit=80`);
    if (!data.events.length) { out.innerHTML = '<div class="card muted">No NFT events observed.</div>'; return; }
    out.innerHTML = data.events.map(e => `
      <section class="card">
        <div class="label">${esc(e.kind)} · block ${esc(e.block_height)}</div>
        <h3>${esc(e.asset_id || ('collection #' + (e.collection_id ?? '?')))}</h3>
        <p class="muted">op=${esc(e.op)} tx=<code>${esc(short(e.tx_hash))}</code></p>
        ${e.collection_id ? `<a href="/nft/collection/${esc(e.collection_id)}">Collection</a>` : ''}
        ${e.collection_id && e.serial ? ` · <a href="/nft/collection/${esc(e.collection_id)}/token/${esc(e.serial)}">Token</a>` : ''}
      </section>`).join('');
    document.getElementById('eventsPager').innerHTML = data.next_cursor ? `<a href="/nft/recent?cursor=${esc(data.next_cursor)}">Next page</a>` : '<span class="muted">End of finalized activity window.</span>';
  } catch (e) { out.innerHTML = `<div class="card error">${esc(e.message)}</div>`; }
})();"#,
    )
}

fn explorer_nft_collection_html_v1(api_base: &str, collection_id: u64) -> String {
    let body = format!(
        r#"<h1>Collection #{}</h1>
<p class="sub">Collection detail and paginated token inventory.</p>
<div id="collection" class="card muted">Loading…</div>
<h2>Tokens</h2>
<div id="tokens" class="grid"><div class="card muted">Loading…</div></div>
<div id="tokensPager" class="pager"></div>"#,
        collection_id
    );
    let script = format!(
        r#"const COLLECTION_ID = {};
(async () => {{
  const cOut = document.getElementById('collection');
  const tOut = document.getElementById('tokens');
  try {{
    const data = await api(`/api/v2/nft/collection?id=${{COLLECTION_ID}}`);
    const c = data.collection;
    cOut.innerHTML = `<h2>${{esc(c.name)}} (${{esc(c.symbol)}})</h2>
      <p class="muted">${{esc(c.asset_type)}} · ${{esc(c.transfer_policy)}} · paused=${{esc(c.cfg.paused)}}</p>
      <div class="row"><span>Owner</span><code>${{esc(short(c.owner_b64))}}</code></div>
      <div class="row"><span>Issuer</span><code>${{esc(short(c.issuer_b64))}}</code></div>
      <div class="row"><span>Live / minted</span><strong>${{esc(c.live_supply)}} / ${{esc(c.total_minted)}}</strong></div>
      <div class="row"><span>Metadata hash</span><code>${{esc(short(c.metadata_hash_hex))}}</code></div>`;
    const cursor = new URLSearchParams(location.search).get('cursor') || '0';
    const tokens = await api(`/api/v2/nft/collection_tokens?collection_id=${{COLLECTION_ID}}&cursor=${{encodeURIComponent(cursor)}}&limit=80`);
    if (!tokens.tokens.length) {{ tOut.innerHTML = '<div class="card muted">No live indexed tokens.</div>'; return; }}
    tOut.innerHTML = tokens.tokens.map(t => `<section class="card">
      <div class="label">${{esc(t.asset_id)}}</div>
      <h3><a href="/nft/collection/${{esc(t.collection_id)}}/token/${{esc(t.serial)}}">Token #${{esc(t.serial)}}</a></h3>
      <p class="muted">owner <code>${{esc(short(t.owner_b64))}}</code></p>
      <div class="row"><span>Status</span><strong>${{esc(t.token.status || t.token.Status || '')}}</strong></div>
    </section>`).join('');
    document.getElementById('tokensPager').innerHTML = tokens.next_cursor ? `<a href="/nft/collection/${{esc(COLLECTION_ID)}}?cursor=${{esc(tokens.next_cursor)}}">Next page</a>` : '<span class="muted">End of finalized token list.</span>';
  }} catch (e) {{ cOut.innerHTML = `<span class="error">${{esc(e.message)}}</span>`; tOut.innerHTML = ''; }}
}})();"#,
        collection_id
    );
    explorer_nft_shell_html_v1("NFT Collection", api_base, &body, &script)
}

fn explorer_nft_token_html_v1(api_base: &str, collection_id: u64, serial: u64) -> String {
    let body = format!(
        r#"<h1>Token #{}:{}</h1>
<p class="sub">Token detail from canonical NFT read model.</p>
<div id="token" class="card muted">Loading…</div>"#,
        collection_id, serial
    );
    let script = format!(
        r#"const COLLECTION_ID = {}; const SERIAL = {};
(async () => {{
  const out = document.getElementById('token');
  try {{
    const data = await api(`/api/v2/nft/token?collection_id=${{COLLECTION_ID}}&serial=${{SERIAL}}`);
    const t = data.token;
    out.innerHTML = `<div class="label">${{esc(t.asset_id)}}</div>
      <h2>${{esc(t.collection.name)}} · token #${{esc(t.serial)}}</h2>
      <p class="muted">status=${{esc(t.status)}} · stored=${{esc(t.stored_status || t.status)}} · minted_height=${{esc(t.minted_height)}}</p>
      <div class="row"><span>Owner</span><code>${{esc(short(t.owner_b64 || 'none'))}}</code></div>
      <div class="row"><span>Owner state</span><strong>${{esc(t.owner_state || (t.owner_b64 ? 'present' : 'none'))}}</strong></div>
      <div class="row"><span>Approved</span><code>${{esc(short(t.approved_b64 || 'none'))}}</code></div>
      <div class="row"><span>URI</span><code>${{esc(t.token_uri)}}</code></div>
      <div class="row"><span>Metadata hash</span><code>${{esc(t.metadata_hash_hex)}}</code></div>
      <p><a href="/nft/collection/${{COLLECTION_ID}}">Back to collection</a>${{t.owner_b64 ? ' · <a href="/wallet/assets?owner=' + encodeURIComponent(t.owner_b64) + '">Owner assets</a>' : ''}}</p>`;
  }} catch (e) {{ out.innerHTML = `<span class="error">${{esc(e.message)}}</span>`; }}
}})();"#,
        collection_id, serial
    );
    explorer_nft_shell_html_v1("NFT Token", api_base, &body, &script)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ExplorerWalletAssetsQueryV1 {
    owner: String,
}

fn explorer_wallet_assets_html_v1(api_base: &str, owner: &str) -> String {
    let owner_escaped = explorer_escape_html_v1(owner);
    let body = format!(
        r#"<h1>Wallet assets</h1>
<p class="sub"><code>{}</code></p>
<div id="assets" class="grid"><div class="card muted">Loading…</div></div>
<div id="assetsPager" class="pager"></div>"#,
        owner_escaped
    );
    let owner_json = explorer_script_json_string_v1(owner);
    let script = format!(
        r#"const OWNER = {};
(async () => {{
  const out = document.getElementById('assets');
  try {{
    const cursor = new URLSearchParams(location.search).get('cursor') || '0';
    const data = await api(`/api/v2/nft/wallet?owner=${{encodeURIComponent(OWNER)}}&cursor=${{encodeURIComponent(cursor)}}&limit=100`);
    if (!data.tokens.length) {{ out.innerHTML = '<div class="card muted">No live indexed NFT assets.</div>'; return; }}
    out.innerHTML = data.tokens.map(t => `<section class="card">
      <div class="label">${{esc(t.asset_id)}}</div>
      <h3><a href="/nft/collection/${{esc(t.collection_id)}}/token/${{esc(t.serial)}}">${{esc(t.token.collection.name)}} #${{esc(t.serial)}}</a></h3>
      <p class="muted">${{esc(t.token.collection.asset_type)}} · ${{esc(t.token.collection.transfer_policy)}}</p>
      <div class="row"><span>Status</span><strong>${{esc(t.token.status || '')}}</strong></div>
    </section>`).join('');
    document.getElementById('assetsPager').innerHTML = data.next_cursor ? `<a href="/wallet/assets?owner=${{encodeURIComponent(OWNER)}}&cursor=${{esc(data.next_cursor)}}">Next page</a>` : '<span class="muted">End of finalized wallet asset list.</span>';
  }} catch (e) {{ out.innerHTML = `<div class="card error">${{esc(e.message)}}</div>`; }}
}})();"#,
        owner_json
    );
    explorer_nft_shell_html_v1("Wallet Assets", api_base, &body, &script)
}

/// Avvia il server statico dell'Explorer UI
pub async fn start_explorer_server(base_dir: &Path, port: u16) {
    let static_dir = explorer_static_dir_from_base(base_dir);

    ng_info!(
        target: "explorer",
        "Servendo file da: {}",
        static_dir.display()
    );

    let api_base = explorer_api_base_v1();
    let api_base_index = api_base.clone();
    let api_base_recent = api_base.clone();
    let api_base_collection = api_base.clone();
    let api_base_token = api_base.clone();
    let api_base_wallet = api_base.clone();

    // Rotta per tutti i file statici + root index.html
    let static_files = warp::fs::dir(static_dir.clone());
    let root = warp::path::end().and(warp::fs::file(static_dir.join("index.html")));
    let nft_index = warp::path!("nft")
        .and(warp::path::end())
        .map(move || warp::reply::html(explorer_nft_index_html_v1(&api_base_index)));
    let nft_recent = warp::path!("nft" / "recent")
        .and(warp::path::end())
        .map(move || warp::reply::html(explorer_nft_recent_html_v1(&api_base_recent)));
    let nft_collection = warp::path!("nft" / "collection" / u64)
        .and(warp::path::end())
        .map(move |collection_id| {
            warp::reply::html(explorer_nft_collection_html_v1(
                &api_base_collection,
                collection_id,
            ))
        });
    let nft_token = warp::path!("nft" / "collection" / u64 / "token" / u64)
        .and(warp::path::end())
        .map(move |collection_id, serial| {
            warp::reply::html(explorer_nft_token_html_v1(
                &api_base_token,
                collection_id,
                serial,
            ))
        });
    let wallet_assets = warp::path!("wallet" / "assets")
        .and(warp::path::end())
        .and(warp::query::<ExplorerWalletAssetsQueryV1>())
        .map(move |q: ExplorerWalletAssetsQueryV1| {
            warp::reply::html(explorer_wallet_assets_html_v1(&api_base_wallet, &q.owner))
        });

    // CORS: di default OFF (safe). Abilita allow-any solo se esplicitamente richiesto.
    let requested_allow_any_cors = env::var("NEWGEN_EXPLORER_CORS_ANY")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let explicit_public_allow_any_cors = env::var("NEWGEN_EXPLORER_ALLOW_PUBLIC_CORS_ANY")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let public_mode = crate::runtime_mode::public_mode_enabled();
    let allow_any_cors = crate::utils::requested_any_cors_allowed_for_mode_v1(
        "EXPLORER",
        requested_allow_any_cors,
        public_mode,
        explicit_public_allow_any_cors,
    );

    // Unifica i tipi: applichiamo SEMPRE un CORS filter.
    // In modalità safe (default) consente solo loopback origins; in modalità allow-any abilita wide-open.
    let cors = {
        let base = warp::cors().allow_methods(vec!["GET"]);
        if allow_any_cors {
            base.allow_any_origin()
        } else {
            base.allow_origin("http://127.0.0.1")
                .allow_origin("http://localhost")
        }
    };

    let routes = root
        .or(nft_index)
        .or(nft_recent)
        .or(nft_collection)
        .or(nft_token)
        .or(wallet_assets)
        .or(static_files)
        .with(cors);

    // Bind address: prefer NEWGEN_EXPLORER_BIND_ADDR, fallback NEWGEN_API_BIND_ADDR, default 127.0.0.1
    let expl_bind_host = env::var("NEWGEN_EXPLORER_BIND_ADDR")
        .or_else(|_| env::var("NEWGEN_EXPLORER_HOST"))
        .or_else(|_| env::var("NEWGEN_API_BIND_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let expl_bind_ip = expl_bind_host
        .parse::<std::net::IpAddr>()
        .unwrap_or_else(|_| {
            ng_warn!(
                target: "explorer",
                "NEWGEN_EXPLORER_BIND_ADDR='{}' non valido → fallback 127.0.0.1",
                expl_bind_host
            );
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });

    let addr = std::net::SocketAddr::new(expl_bind_ip, port);
    ng_info!(target: "explorer", "Explorer attivo su http://{}", addr);

    warp::serve(routes).run(addr).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explorer_static_dir_is_anchored_to_explicit_base_dir() {
        let base_dir = Path::new("/tmp/newgen/runtime/D");
        assert_eq!(
            explorer_static_dir_from_base(base_dir),
            PathBuf::from("/tmp/newgen/runtime/D/explorer_ui")
        );
    }

    #[test]
    fn explorer_nft_pages_are_linkable_and_read_only() {
        let html = explorer_nft_collection_html_v1("http://127.0.0.1:8001", 7);
        assert!(html.contains("Collection #7"));
        assert!(html.contains("/api/v2/nft/collection?id=${COLLECTION_ID}"));
        assert!(!html.to_ascii_lowercase().contains("marketplace"));
    }

    #[test]
    fn explorer_wallet_asset_page_escapes_owner() {
        let html = explorer_wallet_assets_html_v1("http://127.0.0.1:8001", "<bad>");
        assert!(html.contains("&lt;bad&gt;"));
        assert!(!html.contains("<bad>"));
    }

    #[test]
    fn explorer_nft_pages_include_pagination_controls() {
        let index = explorer_nft_index_html_v1("http://127.0.0.1:8001");
        assert!(index.contains("collectionsPager"));
        assert!(index.contains("next_cursor"));
        let recent = explorer_nft_recent_html_v1("http://127.0.0.1:8001");
        assert!(recent.contains("eventsPager"));
        assert!(recent.contains("next_cursor"));
        let collection = explorer_nft_collection_html_v1("http://127.0.0.1:8001", 1);
        assert!(collection.contains("tokensPager"));
        assert!(collection.contains("next_cursor"));
        let wallet = explorer_wallet_assets_html_v1("http://127.0.0.1:8001", "owner");
        assert!(wallet.contains("assetsPager"));
        assert!(wallet.contains("next_cursor"));
    }
}
