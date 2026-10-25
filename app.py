#!/usr/bin/env python3
"""
Firebase URL Extractor
- Crawls a web app, downloads HTML + linked JS bundles
- Extracts Firebase config (apiKey, authDomain, databaseURL, etc.) and URLs
- Web UI served on :8080
"""
import re
import socket
import ipaddress
import concurrent.futures
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
import urllib3

urllib3.disable_warnings()  # recon tool: tolerate self-signed certs

app = Flask(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}
MAX_BYTES = 6 * 1024 * 1024   # 6 MB per file
TIMEOUT   = 12

# ----------------------------- patterns -----------------------------------
PATTERNS = {
    "api_keys":        r"AIza[0-9A-Za-z_\-]{35}",
    "auth_domains":    r"\b[a-z0-9][a-z0-9\-]{0,62}\.firebaseapp\.com\b",
    "database_urls":   r"\b[a-z0-9][a-z0-9\-]{0,62}\.firebaseio\.com\b",
    "regional_db":     r"\b[a-z0-9][a-z0-9\-]{0,62}\."
                       r"(?:us-central1|europe-west1|asia-southeast1|asia-east1|"
                       r"asia-northeast1|australia-southeast1|southamerica-east1|"
                       r"northamerica-northeast1)\.firebasedatabase\.app\b",
    "storage_urls":    r"firebasestorage\.googleapis\.com/v0/b/[A-Za-z0-9_\-\.]+",
    "storage_buckets": r"\b[a-z0-9][a-z0-9\-]{0,62}\.appspot\.com\b",
    "cloud_functions": r"https?://[a-z0-9\-]+\.cloudfunctions\.net/[A-Za-z0-9_\-]+",
    "cloud_run":       r"https?://[a-z0-9\-]+\.run\.app",
    "hosting_domains": r"\b[a-z0-9][a-z0-9\-]{0,62}\.web\.app\b",
    "measurement_ids": r"\bG-[A-Z0-9]{10}\b",
    "sender_ids":      r'"messagingSenderId"\s*:\s*"(\d+)"',
}

CONFIG_RE = re.compile(
    r'["\']?(apiKey|authDomain|databaseURL|projectId|storageBucket|'
    r'messagingSenderId|appId|measurementId|region)["\']?\s*[:=]\s*["\']'
    r'([^"\']{3,400})["\']'
)


# ----------------------------- SSRF guard ---------------------------------
def is_safe_url(url: str):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False, "only http/https allowed"
        host = p.hostname
        if not host:
            return False, "invalid host"
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False, f"blocked internal address {ip}"
        return True, None
    except Exception as e:
        return False, str(e)


# ----------------------------- fetcher ------------------------------------
def fetch(url: str):
    """Return (status_code, text, final_url). Safe-fails."""
    ok, _ = is_safe_url(url)
    if not ok:
        return None, "", url
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         stream=True, verify=False, allow_redirects=True)
        buf, total = [], 0
        for chunk in r.iter_content(65536):
            buf.append(chunk)
            total += len(chunk)
            if total > MAX_BYTES:
                break
        return r.status_code, b"".join(buf).decode("utf-8", errors="ignore"), r.url
    except Exception:
        return None, "", url


# ----------------------------- extractor ----------------------------------
def extract(text: str, findings: dict):
    for name, pat in PATTERNS.items():
        for m in re.findall(pat, text):
            if isinstance(m, tuple):
                m = m[0]
            findings[name].add(m)
    for field, value in CONFIG_RE.findall(text):
        findings["config_fields"][field].add(value)


def normalize(findings: dict):
    """Prefix bare firebase domains with https:// and dedupe."""
    out = defaultdict(list)
    for k, vals in findings.items():
        if k == "config_fields":
            out[k] = {f: sorted(v) for f, v in vals.items()}
            continue
        for v in vals:
            if k in ("auth_domains", "database_urls", "regional_db",
                     "hosting_domains") and not v.startswith("http"):
                v = "https://" + v
            if k == "storage_buckets":
                v = "gs://" + v
            out[k].append(v)
        out[k] = sorted(set(out[k]))
    return out


# ----------------------------- scanner ------------------------------------
def scan(target: str, include_js: bool, max_js: int):
    ok, err = is_safe_url(target)
    if not ok:
        return {"error": f"Refused: {err}"}

    findings = defaultdict(set)
    stats = {"html_files": 0, "js_files": 0, "bytes": 0}
    errors = []

    status, html, final_url = fetch(target)
    if status is None:
        return {"error": "Failed to fetch target"}

    stats["html_files"] = 1
    stats["bytes"] += len(html)
    extract(html, findings)

    # Collect JS links
    js_urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href")
            if not src:
                continue
            full = urljoin(final_url, src)
            if full.endswith(".js") or (tag.get("type") or "").endswith("javascript"):
                js_urls.append(full)
    except Exception as e:
        errors.append(f"HTML parse: {e}")

    js_urls = list(dict.fromkeys(js_urls))[:max_js]

    if include_js and js_urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(fetch, u): u for u in js_urls}
            for f in concurrent.futures.as_completed(futs):
                u = futs[f]
                st, body, _ = f.result()
                if st and body:
                    stats["js_files"] += 1
                    stats["bytes"] += len(body)
                    extract(body, findings)
                else:
                    errors.append(f"fetch failed: {u}")

    result = normalize(findings)
    result["_stats"] = stats
    result["_target"] = target
    result["_errors"] = errors[:20]
    return result


# ----------------------------- routes -------------------------------------
@app.route("/")
def index():
    return INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not re.match(r"^https?://", url):
        url = "https://" + url
    include_js = bool(data.get("include_js", True))
    try:
        max_js = int(data.get("max_js", 30))
    except (TypeError, ValueError):
        max_js = 30
    max_js = max(1, min(max_js, 100))
    try:
        return jsonify(scan(url, include_js, max_js))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------------------- UI -----------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firebase URL Extractor</title>
<style>
  :root{
    --bg:#0b0f17; --panel:#131a26; --panel2:#1a2332; --border:#253145;
    --text:#e6edf7; --muted:#8b9ab1; --accent:#ffb74d; --accent2:#ff8f00;
    --ok:#4ade80; --err:#f87171;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
       background:radial-gradient(1200px 600px at 20% -10%,#1c2436 0%,#0b0f17 55%);
       color:var(--text);min-height:100vh;padding:32px 16px}
  .wrap{max-width:1000px;margin:0 auto}
  header{margin-bottom:24px}
  h1{margin:0 0 6px;font-size:26px;letter-spacing:.3px}
  h1 .icon{color:var(--accent)}
  .sub{color:var(--muted);font-size:14px}
  form{background:var(--panel);border:1px solid var(--border);border-radius:14px;
       padding:18px;margin-bottom:22px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
  .row{display:flex;gap:10px;flex-wrap:wrap}
  input[type=text]{flex:1 1 320px;background:var(--panel2);border:1px solid var(--border);
       color:var(--text);padding:12px 14px;border-radius:10px;font-size:15px;outline:none}
  input[type=text]:focus{border-color:var(--accent)}
  button{cursor:pointer;border:none;border-radius:10px;padding:12px 22px;font-size:15px;
       font-weight:600;color:#151515;background:linear-gradient(135deg,var(--accent),var(--accent2))}
  button:disabled{opacity:.55;cursor:not-allowed}
  .opts{margin-top:12px;display:flex;gap:20px;flex-wrap:wrap;color:var(--muted);font-size:13.5px;align-items:center}
  .opts label{display:flex;gap:7px;align-items:center;cursor:pointer}
  .opts input[type=number]{width:70px;background:var(--panel2);border:1px solid var(--border);
       color:var(--text);padding:5px 8px;border-radius:8px}
  #status{color:var(--muted);font-size:13.5px;min-height:20px;margin-bottom:14px}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid var(--border);
        border-top-color:var(--accent);border-radius:50%;animation:s .7s linear infinite;
        vertical-align:-2px;margin-right:6px}
  @keyframes s{to{transform:rotate(360deg)}}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
        padding:14px 16px;margin-bottom:12px}
  .card h3{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.8px;
           color:var(--accent);display:flex;justify-content:space-between;align-items:center}
  .card h3 span.count{background:var(--panel2);color:var(--muted);font-size:11px;
           padding:2px 8px;border-radius:20px;letter-spacing:0}
  .item{display:flex;align-items:center;justify-content:space-between;gap:10px;
        padding:8px 10px;background:var(--panel2);border-radius:8px;margin-bottom:6px;
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
        word-break:break-all}
  .item .val{flex:1}
  .copy{background:transparent;border:1px solid var(--border);color:var(--muted);
        padding:4px 9px;font-size:11.5px;border-radius:6px;font-weight:600;
        cursor:pointer;flex-shrink:0}
  .copy:hover{border-color:var(--accent);color:var(--accent)}
  .summary{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-bottom:14px}
  .summary b{color:var(--text)}
  .err{color:var(--err);font-size:13px}
  .footer{color:var(--muted);font-size:12px;margin-top:26px;text-align:center;line-height:1.6}
  .grid{display:grid;grid-template-columns:1fr;gap:12px}
  @media(min-width:760px){.grid{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1><span class="icon">🔥</span> Firebase URL Extractor</h1>
    <div class="sub">Crawl a web app · download JS bundles · extract Firebase endpoints &amp; config</div>
  </header>

  <form id="f">
    <div class="row">
      <input id="url" type="text" placeholder="https://target-app.com" required>
      <button id="btn" type="submit">Scan</button>
    </div>
    <div class="opts">
      <label><input id="include_js" type="checkbox" checked> Crawl JS bundles</label>
      <label>Max JS files <input id="max_js" type="number" min="1" max="100" value="30"></label>
    </div>
  </form>

  <div id="status"></div>
  <div id="out"></div>

  <div class="footer">
    For authorized security testing only. Only scan apps you own or have permission to test.
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const LABELS = {
  api_keys:'API Keys', auth_domains:'Auth Domains', database_urls:'Realtime DB URLs',
  regional_db:'Regional DB URLs', storage_urls:'Storage URLs',
  storage_buckets:'Storage Buckets', cloud_functions:'Cloud Functions',
  cloud_run:'Cloud Run URLs', hosting_domains:'Hosting Domains',
  measurement_ids:'Measurement IDs', sender_ids:'Sender IDs'
};

async function copy(txt, btn){
  try{ await navigator.clipboard.writeText(txt); }
  catch{ /* fallback */ }
  const old = btn.textContent; btn.textContent = 'Copied!';
  setTimeout(()=>btn.textContent = old, 900);
}

function renderSection(key, values){
  if(!values || !values.length) return '';
  const items = values.map(v => `
    <div class="item">
      <span class="val">${esc(v)}</span>
      <button class="copy" data-v="${esc(v)}">Copy</button>
    </div>`).join('');
  return `<div class="card">
    <h3>${esc(LABELS[key]||key)} <span class="count">${values.length}</span></h3>
    ${items}
  </div>`;
}

function render(data){
  const out = $('#out');
  if(data.error){ out.innerHTML = `<div class="card err">⚠ ${esc(data.error)}</div>`; return; }

  const s = data._stats || {};
  const total = Object.keys(LABELS).reduce((n,k)=> n + (data[k]?.length||0), 0);
  let html = `<div class="summary">
    Target: <b>${esc(data._target||'')}</b> ·
    HTML: <b>${s.html_files||0}</b> ·
    JS: <b>${s.js_files||0}</b> ·
    Size: <b>${((s.bytes||0)/1024).toFixed(1)} KB</b> ·
    Findings: <b>${total}</b>
  </div>`;

  // Config fields (structured)
  const cf = data.config_fields || {};
  const cfKeys = Object.keys(cf).filter(k => cf[k].length);
  if(cfKeys.length){
    html += `<div class="card"><h3>Firebase Config Fields <span class="count">${cfKeys.length}</span></h3>`;
    cfKeys.forEach(k => {
      cf[k].forEach(v => {
        html += `<div class="item">
          <span class="val"><b>${esc(k)}</b>: ${esc(v)}</span>
          <button class="copy" data-v="${esc(v)}">Copy</button>
        </div>`;
      });
    });
    html += `</div>`;
  }

  html += '<div class="grid">';
  Object.keys(LABELS).forEach(k => html += renderSection(k, data[k]));
  html += '</div>';

  if(data._errors && data._errors.length){
    html += `<div class="card"><h3>Fetch Warnings <span class="count">${data._errors.length}</span></h3>`
          + data._errors.map(e => `<div class="item err">${esc(e)}</div>`).join('')
          + `</div>`;
  }

  out.innerHTML = html;
  out.querySelectorAll('.copy').forEach(b => {
    b.addEventListener('click', () => copy(b.dataset.v, b));
  });
}

$('#f').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('#btn'), status = $('#status');
  btn.disabled = true;
  $('#out').innerHTML = '';
  status.innerHTML = '<span class="spin"></span>Scanning target and fetching JS bundles…';

  try{
    const res = await fetch('/api/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        url: $('#url').value.trim(),
        include_js: $('#include_js').checked,
        max_js: parseInt($('#max_js').value,10) || 30
      })
    });
    const data = await res.json();
    status.textContent = '';
    render(data);
  }catch(err){
    status.textContent = '';
    render({error:'Request failed: '+err.message});
  }finally{
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)