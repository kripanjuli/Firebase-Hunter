#!/usr/bin/env python3
"""
APK Firebase URL Extractor
- Accepts .apk / .xapk / .apks / .zip upload
- Unzips, extracts ASCII + UTF-16LE strings from every file
  (works on DEX bytecode, resources.arsc, XML, assets, native libs)
- Regexes for Firebase endpoints, keys, project IDs
- Web UI on :8080
"""
import io
import os
import re
import zipfile
import tempfile
from collections import defaultdict

from flask import Flask, request, jsonify

# Optional manifest parsing
try:
    from pyaxmlparser import APK as _AXMLAPK
    HAS_AXML = True
except Exception:
    HAS_AXML = False

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024   # 300 MB upload cap

MAX_FILE_SIZE = 120 * 1024 * 1024                       # 120 MB per entry after unzip

# ----------------------------- patterns -----------------------------------
PATTERNS = {
    "api_keys":         r"AIza[0-9A-Za-z_\-]{35}",
    "auth_domains":     r"\b[a-z0-9][a-z0-9\-]{0,62}\.firebaseapp\.com\b",
    "database_urls":    r"\b[a-z0-9][a-z0-9\-]{0,62}\.firebaseio\.com\b",
    "regional_db":      r"\b[a-z0-9][a-z0-9\-]{0,62}\."
                        r"(?:us-central1|europe-west1|asia-southeast1|asia-east1|"
                        r"asia-northeast1|australia-southeast1|southamerica-east1|"
                        r"northamerica-northeast1)\.firebasedatabase\.app\b",
    "storage_urls":     r"firebasestorage\.googleapis\.com/v0/b/[A-Za-z0-9_\-\.]+",
    "storage_buckets":  r"\b[a-z0-9][a-z0-9\-]{0,62}\.appspot\.com\b",
    "cloud_functions":  r"https?://[a-z0-9\-]+\.cloudfunctions\.net/[A-Za-z0-9_\-]+",
    "cloud_run":        r"https?://[a-z0-9\-]+\.run\.app",
    "hosting_domains":  r"\b[a-z0-9][a-z0-9\-]{0,62}\.web\.app\b",
    "google_app_ids":   r"\b1:\d{6,15}:android:[0-9a-f]{10,}\b",
    "oauth_client_ids": r"\b\d{10,15}-[a-z0-9]{20,}\.apps\.googleusercontent\.com\b",
    "measurement_ids":  r"\bG-[A-Z0-9]{10}\b",
    "sender_ids":       r'"?(?:gcm_defaultSenderId|messagingSenderId|project_number)"?\s*[:=]\s*["\']?(\d{6,15})["\']?',
    "project_ids":      r'"project_id"\s*[:=]\s*["\']([a-z0-9][a-z0-9\-]{4,28}[a-z0-9])["\']',
}

# ----------------------------- strings ------------------------------------
ASCII_RE  = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE  = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

def strings_from_bytes(data: bytes):
    """Emulates `strings` but returns a set (ASCII + UTF-16LE)."""
    out = set()
    for m in ASCII_RE.finditer(data):
        out.add(m.group().decode("ascii", "ignore"))
    for m in UTF16_RE.finditer(data):
        try:
            out.add(m.group().decode("utf-16-le", "ignore"))
        except Exception:
            pass
    return out

# ----------------------------- scanning -----------------------------------
def _scan_entries(zf: zipfile.ZipFile, findings: dict, stats: dict, errors: list):
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if name.startswith("__MACOSX/") or name.endswith("/"):
            continue
        if info.file_size > MAX_FILE_SIZE:
            errors.append(f"skip {name}: {info.file_size} bytes > {MAX_FILE_SIZE}")
            continue
        try:
            data = zf.read(info)
        except Exception as e:
            errors.append(f"read {name}: {e}")
            continue

        stats["files"] += 1
        stats["bytes"] += len(data)
        if name.startswith("classes") and name.endswith(".dex"):
            stats["dex_files"] += 1
        elif name == "resources.arsc":
            stats["has_arsc"] = True
        elif name == "AndroidManifest.xml":
            stats["has_manifest"] = True

        blob = "\n".join(strings_from_bytes(data))
        for key, pat in PATTERNS.items():
            for m in re.findall(pat, blob):
                if isinstance(m, tuple):
                    m = m[0]
                findings[key].add(m)

        del data  # free per-entry memory


def _normalize(findings: dict):
    out = {}
    for k, vals in findings.items():
        cleaned = []
        for v in vals:
            if k in ("auth_domains", "database_urls", "regional_db", "hosting_domains") \
                    and not v.startswith("http"):
                v = "https://" + v
            if k == "storage_buckets":
                v = "gs://" + v
            cleaned.append(v)
        out[k] = sorted(set(cleaned))
    return out


def scan_apk(path: str, label: str = ""):
    """Scan a single .apk file path."""
    findings = defaultdict(set)
    stats = {"files": 0, "dex_files": 0, "bytes": 0,
             "has_arsc": False, "has_manifest": False}
    errors = []

    try:
        with zipfile.ZipFile(path) as zf:
            _scan_entries(zf, findings, stats, errors)
    except zipfile.BadZipFile as e:
        return {"error": f"Not a valid APK/ZIP: {e}"}

    manifest = {}
    if HAS_AXML:
        try:
            a = _AXMLAPK(path)
            manifest = {
                "package":       a.package,
                "app_name":      a.application,
                "version_name":  a.version_name,
                "version_code":  str(a.version_code or ""),
            }
        except Exception as e:
            errors.append(f"manifest parse: {e}")

    result = _normalize(findings)
    result["_apk"] = label or os.path.basename(path)
    result["_manifest"] = manifest
    result["_stats"] = stats
    result["_errors"] = errors[:30]
    return result


def scan_upload(path: str):
    """Detect XAPK/APKS bundles and scan each inner APK."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            inner = [n for n in names
                     if n.lower().endswith(".apk")
                     and not n.startswith("__MACOSX/")]
    except zipfile.BadZipFile as e:
        return {"error": f"Not a valid APK/ZIP: {e}"}

    if not inner:
        return scan_apk(path)

    # Bundle (XAPK/APKS): scan each inner apk, merge results
    merged = defaultdict(set)
    sub = []
    all_errors = []
    combined_stats = {"files": 0, "dex_files": 0, "bytes": 0,
                      "has_arsc": False, "has_manifest": False}

    with zipfile.ZipFile(path) as zf:
        for name in inner:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                tmp.write(zf.read(name))
                tmp.close()
            try:
                r = scan_apk(tmp.name, label=name)
                if "error" in r:
                    all_errors.append(f"{name}: {r['error']}")
                    continue
                sub.append({"apk": name,
                            "package": r.get("_manifest", {}).get("package", ""),
                            "findings": sum(len(v) for k, v in r.items()
                                            if isinstance(v, list))})
                for k, vals in r.items():
                    if isinstance(vals, list):
                        merged[k].update(vals)
                    elif k == "_stats":
                        for sk, sv in vals.items():
                            if isinstance(sv, bool):
                                combined_stats[sk] = combined_stats[sk] or sv
                            else:
                                combined_stats[sk] += sv
                all_errors.extend(f"{name}: {e}" for e in r.get("_errors", []))
            finally:
                try: os.unlink(tmp.name)
                except OSError: pass

    out = {k: sorted(v) for k, v in merged.items()}
    out["_apk"] = os.path.basename(path)
    out["_bundle_of"] = sub
    out["_stats"] = combined_stats
    out["_errors"] = all_errors[:30]
    return out


# ----------------------------- routes -------------------------------------
@app.route("/")
def index():
    return INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    if not f.filename.lower().endswith((".apk", ".xapk", ".apks", ".zip")):
        return jsonify({"error": "file must be .apk/.xapk/.apks/.zip"}), 400

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
    try:
        f.save(tmp.name)
        tmp.close()
        return jsonify(scan_upload(tmp.name))
    except Exception as e:
        return jsonify({"error": f"scan failed: {e}"}), 500
    finally:
        try: os.unlink(tmp.name)
        except OSError: pass


# ----------------------------- UI -----------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APK Firebase Extractor</title>
<style>
  :root{
    --bg:#0b0f17; --panel:#131a26; --panel2:#1a2332; --border:#253145;
    --text:#e6edf7; --muted:#8b9ab1; --accent:#ffb74d; --accent2:#ff8f00;
    --err:#f87171; --ok:#4ade80;
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
  .dropzone{border:2px dashed var(--border);border-radius:12px;padding:32px 20px;
            text-align:center;cursor:pointer;transition:.18s;background:var(--panel2);
            position:relative}
  .dropzone:hover,.dropzone.drag{border-color:var(--accent);background:#1e283a}
  .dz-icon{font-size:38px;margin-bottom:8px}
  .dz-hint{color:var(--muted);font-size:12.5px;margin-top:8px}
  .link{color:var(--accent);text-decoration:underline}
  .dz-file{margin-top:12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;
           color:var(--ok);min-height:18px;word-break:break-all}
  button[type=submit]{margin-top:16px;width:100%;cursor:pointer;border:none;
       border-radius:10px;padding:13px 22px;font-size:15px;font-weight:600;
       color:#151515;background:linear-gradient(135deg,var(--accent),var(--accent2))}
  button[type=submit]:disabled{opacity:.55;cursor:not-allowed}
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
  .grid{display:grid;grid-template-columns:1fr;gap:12px}
  @media(min-width:760px){.grid{grid-template-columns:1fr 1fr}}
  .meta{font-size:12.5px;color:var(--muted);margin-bottom:14px;padding:10px 14px;
        background:var(--panel2);border-radius:8px;line-height:1.7;font-family:ui-monospace,Menlo,monospace}
  .meta b{color:var(--text)}
  .actions{display:flex;gap:10px;margin-bottom:14px}
  .actions button{background:var(--panel2);color:var(--text);border:1px solid var(--border);
                  padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer;font-weight:600}
  .actions button:hover{border-color:var(--accent);color:var(--accent)}
  .footer{color:var(--muted);font-size:12px;margin-top:26px;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1><span class="icon">🔥</span> APK Firebase Extractor</h1>
    <div class="sub">Upload an APK · extract Firebase URLs, keys &amp; project IDs from DEX + resources</div>
  </header>

  <form id="f">
    <div class="dropzone" id="drop">
      <div class="dz-icon">📦</div>
      <div>Drop APK here or <span class="link">click to browse</span></div>
      <div class="dz-hint">.apk · .xapk · .apks · .zip &nbsp;|&nbsp; max 300 MB</div>
      <div class="dz-file" id="fname"></div>
      <input type="file" id="file" accept=".apk,.xapk,.apks,.zip,application/vnd.android.package-archive,application/zip" hidden>
    </div>
    <button id="btn" type="submit" disabled>Scan APK</button>
  </form>

  <div id="status"></div>
  <div id="out"></div>

  <div class="footer">For authorized security testing only · Only analyze APKs you own or have permission to test.</div>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const LABELS = {
  api_keys:'API Keys', auth_domains:'Auth Domains', database_urls:'Realtime DB URLs',
  regional_db:'Regional DB URLs', storage_urls:'Storage URLs',
  storage_buckets:'Storage Buckets', cloud_functions:'Cloud Functions',
  cloud_run:'Cloud Run URLs', hosting_domains:'Hosting Domains',
  google_app_ids:'Google App IDs', oauth_client_ids:'OAuth Client IDs',
  measurement_ids:'Measurement IDs', sender_ids:'Sender IDs', project_ids:'Project IDs'
};

let currentFile = null;

function setFile(f){
  currentFile = f;
  $('#fname').textContent = f ? `${f.name}  ·  ${(f.size/1024/1024).toFixed(1)} MB` : '';
  $('#btn').disabled = !f;
}

function setStatus(html){ $('#status').innerHTML = html || ''; }

$('#drop').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', e => setFile(e.target.files[0] || null));

['dragenter','dragover'].forEach(ev => $('#drop').addEventListener(ev, e => {
  e.preventDefault(); $('#drop').classList.add('drag');
}));
['dragleave','drop'].forEach(ev => $('#drop').addEventListener(ev, e => {
  e.preventDefault(); $('#drop').classList.remove('drag');
}));
$('#drop').addEventListener('drop', e => {
  const f = e.dataTransfer.files[0];
  if (f) setFile(f);
});

async function copy(txt, btn){
  try{ await navigator.clipboard.writeText(txt); } catch {}
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
  if(data.error){
    out.innerHTML = `<div class="card err">⚠ ${esc(data.error)}</div>`;
    return;
  }
  const s = data._stats || {};
  const m = data._manifest || {};
  const total = Object.keys(LABELS).reduce((n,k)=> n + (data[k]?.length||0), 0);

  let meta = `<div class="meta">`;
  meta += `<div>APK: <b>${esc(data._apk||'')}</b></div>`;
  if(m.package)      meta += `<div>Package: <b>${esc(m.package)}</b></div>`;
  if(m.app_name)     meta += `<div>App: <b>${esc(m.app_name)}</b></div>`;
  if(m.version_name) meta += `<div>Version: <b>${esc(m.version_name)}</b> (${esc(m.version_code||'')})</div>`;
  meta += `<div>Files: <b>${s.files||0}</b> · DEX: <b>${s.dex_files||0}</b> · `
       + `Size: <b>${((s.bytes||0)/1024/1024).toFixed(2)} MB</b> · `
       + `ARSC: <b>${s.has_arsc?'yes':'no'}</b> · Manifest: <b>${s.has_manifest?'yes':'no'}</b></div>`;
  meta += `<div>Findings: <b>${total}</b></div>`;
  meta += `</div>`;

  let html = meta;
  html += `<div class="actions">
             <button id="dl">⬇ Download JSON</button>
             <button id="cp_all">📋 Copy all URLs</button>
           </div>`;

  if(Array.isArray(data._bundle_of) && data._bundle_of.length){
    html += `<div class="card"><h3>Bundle Contents <span class="count">${data._bundle_of.length}</span></h3>`
          + data._bundle_of.map(b =>
              `<div class="item"><span class="val">${esc(b.apk)} — ${esc(b.package||'')} (${b.findings} findings)</span></div>`).join('')
          + `</div>`;
  }

  html += '<div class="grid">';
  Object.keys(LABELS).forEach(k => html += renderSection(k, data[k]));
  html += '</div>';

  if(data._errors && data._errors.length){
    html += `<div class="card"><h3>Warnings <span class="count">${data._errors.length}</span></h3>`
          + data._errors.map(e => `<div class="item err">${esc(e)}</div>`).join('')
          + `</div>`;
  }

  out.innerHTML = html;

  out.querySelectorAll('.copy').forEach(b => {
    b.addEventListener('click', () => copy(b.dataset.v, b));
  });

  $('#dl').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (data._apk||'findings').replace(/\.[^.]+$/, '') + '.firebase.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  $('#cp_all').addEventListener('click', () => {
    const urls = [];
    ['auth_domains','database_urls','regional_db','storage_urls',
     'storage_buckets','cloud_functions','cloud_run','hosting_domains']
      .forEach(k => (data[k]||[]).forEach(v => urls.push(v)));
    copy(urls.join('\n'), $('#cp_all'));
  });
}

$('#f').addEventListener('submit', async e => {
  e.preventDefault();
  if(!currentFile) return;
  const btn = $('#btn');
  btn.disabled = true;
  $('#out').innerHTML = '';
  setStatus('<span class="spin"></span>Uploading & scanning (DEX + resources.arsc)…');

  const fd = new FormData();
  fd.append('file', currentFile);

  try{
    const res = await fetch('/api/scan', { method:'POST', body: fd });
    const data = await res.json();
    setStatus('');
    render(data);
  }catch(err){
    setStatus('');
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