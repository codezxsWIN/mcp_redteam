from __future__ import annotations

import json
import time
import traceback
import uuid
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from .. import presets as presets_mod
from ..client.transport import TargetSpec, parse_target
from ..config import Settings
from ..probes import PROBE_NAMES
from ..report.finding import ScanReport, Severity
from ..report.html_out import to_html
from ..scanner import scan_target


# ---------------------------------------------------------------------------
# In-memory session history (per running server process). Tiny on purpose.
# ---------------------------------------------------------------------------

_HISTORY: list[dict[str, Any]] = []
_HISTORY_MAX = 20


def _push_history(entry: dict[str, Any]) -> None:
    _HISTORY.insert(0, entry)
    del _HISTORY[_HISTORY_MAX:]


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

_CSS = """
:root{
  --bg:#0a0b0d;
  --bg-soft:#0f1115;
  --panel:#0d0f12;
  --panel-soft:#111418;
  --line:rgba(255,255,255,.07);
  --line-2:rgba(255,255,255,.13);
  --text:#e9ebee;
  --muted:#9aa0a8;
  --dim:#5e646d;
  --accent:#f5a524;
  --accent-2:#e07b2c;
  --ok:#4cc38a;
  --crit:#f0544f;
  --high:#f2a33c;
  --med:#e6c34a;
  --low:#8ba0b6;
  --info:#7d8590;
}

*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{
  color:var(--text);
  background:
    radial-gradient(680px 360px at 16% -12%, rgba(245,165,36,.055), transparent 64%),
    linear-gradient(180deg, var(--bg) 0%, #070809 100%);
  font-family:'Manrope','Segoe UI',Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}

body::before{
  content:'';
  position:fixed;
  inset:0;
  pointer-events:none;
  background-image:radial-gradient(rgba(255,255,255,.05) 1px, transparent 1.4px);
  background-size:22px 22px;
  mask-image:radial-gradient(circle at 50% 36%, rgba(0,0,0,.5), transparent 90%);
}

a{color:var(--accent);text-decoration:none}
code,pre{font-family:'JetBrains Mono',Consolas,"Courier New",monospace}

.frame{
  margin:12px;
  max-width:1460px;
  margin-inline:auto;
  border:1px solid var(--line);
  border-radius:16px;
  background:var(--panel);
  box-shadow:0 26px 70px rgba(0,0,0,.45);
}

.topbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  padding:16px 18px;
  border-bottom:1px solid var(--line);
  background:linear-gradient(180deg, rgba(255,255,255,.02), transparent);
}

.brand{display:flex;align-items:center;gap:10px}
.brand .logo{
  width:30px;
  height:30px;
  border-radius:7px;
  display:grid;
  place-items:center;
  font-weight:800;
  font-size:12px;
  font-family:'JetBrains Mono',monospace;
  color:#120a02;
  background:var(--accent);
  box-shadow:0 0 0 1px rgba(245,165,36,.35), 0 6px 18px rgba(245,165,36,.18);
}

.brand .name{
  display:block;
  font-size:14px;
  font-weight:700;
  letter-spacing:1.5px;
  font-family:'JetBrains Mono',monospace;
}

.brand .tag{
  display:block;
  color:var(--muted);
  font-size:11px;
  letter-spacing:.2px;
}

.top-meta{
  display:flex;
  align-items:center;
  gap:10px;
}

.version-chip{
  border:1px solid var(--line-2);
  border-radius:6px;
  padding:5px 11px;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:1.4px;
  font-family:'JetBrains Mono',monospace;
  color:var(--accent);
  background:rgba(245,165,36,.08);
}

.gh-link{
  display:inline-flex;
  align-items:center;
  gap:7px;
  border:1px solid var(--line-2);
  border-radius:6px;
  padding:5px 11px;
  font-size:11px;
  letter-spacing:.4px;
  font-family:'JetBrains Mono',monospace;
  color:var(--text);
  background:var(--bg-soft);
  transition:border-color .15s ease, color .15s ease;
}

.gh-link:hover{border-color:var(--accent);color:var(--accent)}
.gh-link svg{width:15px;height:15px;fill:currentColor}

.pill{
  display:inline-flex;
  align-items:center;
  gap:8px;
  border:1px solid var(--line-2);
  border-radius:6px;
  padding:5px 10px;
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:1px;
  font-family:'JetBrains Mono',monospace;
  color:var(--muted);
  background:var(--bg-soft);
}

.pill .dot{
  width:8px;
  height:8px;
  border-radius:50%;
  background:var(--ok);
}

.pill.busy .dot{
  background:var(--high);
  animation:pulse 1s ease-in-out infinite;
}

@keyframes pulse{50%{opacity:.35}}

.shell{
  padding:14px;
  display:grid;
  grid-template-columns:330px minmax(0,1fr);
  gap:14px;
}

.sidepanel,
.hero,
.history,
.resultframe,
.placeholder,
.statcard,
footer{
  border:1px solid var(--line);
  border-radius:14px;
  background:var(--panel-soft);
}

.sidepanel{
  padding:14px;
  height:fit-content;
}

.panel-head{
  border:1px solid var(--line);
  border-left:2px solid var(--accent);
  border-radius:10px;
  padding:11px;
  margin-bottom:12px;
  background:rgba(245,165,36,.05);
}

.panel-head b{
  display:block;
  font-size:12px;
  margin-bottom:4px;
}

.panel-head span{
  font-size:12px;
  color:var(--muted);
  line-height:1.45;
}

.section{margin:0 0 12px}

.section h3{
  margin:0 0 8px;
  color:var(--dim);
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:1.6px;
  font-family:'JetBrains Mono',monospace;
}

.input,.select{
  width:100%;
  border:1px solid var(--line);
  border-radius:10px;
  background:var(--bg-soft);
  color:var(--text);
  padding:9px 10px;
  font-size:13px;
}

.input:focus,.select:focus{
  outline:none;
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(245,165,36,.16);
}

.hint{
  margin:6px 0 0;
  color:var(--dim);
  font-size:11px;
  line-height:1.45;
}

.chips{display:flex;flex-wrap:wrap;gap:6px}

.chip{
  border:1px solid var(--line);
  border-radius:10px;
  background:var(--bg-soft);
  color:var(--text);
  padding:6px 9px;
  font-size:12px;
  display:inline-flex;
  align-items:center;
  gap:6px;
  cursor:pointer;
}

.chip .sub{font-size:10px;color:var(--muted)}

.chip.active{
  border-color:var(--accent);
  color:var(--accent);
  background:rgba(245,165,36,.1);
}

.chip.active .sub{color:var(--accent-2)}

.probes{display:grid;grid-template-columns:1fr 1fr;gap:6px}

.probes label{
  border:1px solid var(--line);
  border-radius:10px;
  background:var(--bg-soft);
  padding:7px 8px;
  font-size:12px;
  display:flex;
  align-items:center;
  gap:8px;
}

.probes input{accent-color:var(--accent)}

.btn{
  width:100%;
  border:1px solid var(--accent);
  border-radius:8px;
  padding:12px;
  cursor:pointer;
  font-size:11px;
  font-weight:700;
  text-transform:uppercase;
  letter-spacing:1.4px;
  font-family:'JetBrains Mono',monospace;
  color:#120a02;
  background:var(--accent);
}

.btn:disabled{opacity:.55;cursor:wait}

.status{
  margin-top:10px;
  min-height:18px;
  font-size:12px;
  color:var(--muted);
  line-height:1.4;
}

.status.err{
  color:var(--crit);
  white-space:pre-wrap;
  font-size:11.5px;
  font-family:Consolas,"Courier New",monospace;
}

.main{min-width:0;display:flex;flex-direction:column;gap:18px}

.hero{
  padding:44px 40px 40px;
  background:
    radial-gradient(420px 240px at 88% 4%, rgba(245,165,36,.05), transparent 72%),
    var(--panel-soft);
  position:relative;
}

.hero::before{
  content:'';
  position:absolute;
  left:0;top:0;bottom:0;
  width:2px;
  background:linear-gradient(180deg, var(--accent), transparent 70%);
}

.hero-kicker{
  color:var(--accent);
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:2.4px;
  font-family:'JetBrains Mono',monospace;
}

.hero-kicker .spark{
  display:inline-block;
  width:6px;
  height:6px;
  margin-right:10px;
  border-radius:2px;
  background:var(--accent);
  box-shadow:0 0 10px rgba(245,165,36,.6);
}

.hero h1{
  margin:18px 0 0;
  max-width:880px;
  font-family:'Manrope','Segoe UI',Arial,sans-serif;
  font-size:clamp(38px,5vw,64px);
  font-weight:800;
  line-height:1.02;
  letter-spacing:-1.2px;
}

.hero p{
  margin:18px 0 0;
  color:var(--muted);
  font-family:'Manrope','Segoe UI',Arial,sans-serif;
  font-size:15px;
  line-height:1.6;
  max-width:680px;
}

.hero-meta{
  margin-top:16px;
  display:flex;
  flex-wrap:wrap;
  gap:8px;
}

.hero-meta span{
  border:1px solid var(--line-2);
  border-radius:6px;
  padding:5px 10px;
  font-size:11px;
  letter-spacing:.4px;
  font-family:'JetBrains Mono',monospace;
  color:var(--muted);
  background:var(--bg-soft);
}

.launch-grid{
  display:grid;
  grid-template-columns:1.15fr .85fr;
  gap:10px;
}

.info-card{
  border:1px solid var(--line);
  border-radius:12px;
  background:var(--panel-soft);
  padding:14px;
}

.info-card h3{
  margin:0;
  font-size:14px;
  letter-spacing:.2px;
}

.info-card p{
  margin:9px 0 0;
  color:var(--muted);
  font-size:13px;
  line-height:1.5;
}

.info-list{
  margin:10px 0 0;
  padding-left:18px;
  color:var(--text);
  font-size:12.5px;
  line-height:1.55;
}

.cmd{
  margin:10px 0 0;
  border:1px solid var(--line-2);
  border-radius:8px;
  padding:10px 12px;
  background:#070809;
  color:var(--accent);
  font-size:12px;
  font-family:'JetBrains Mono',monospace;
  overflow:auto;
}

.info-note{
  margin-top:9px;
  color:var(--dim);
  font-size:12px;
}

.launch-steps{
  margin:10px 0 0;
  padding-left:18px;
  color:var(--text);
  font-size:12.5px;
  line-height:1.55;
}

.feature-grid{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:10px;
}

.feature-card{
  border:1px solid var(--line);
  border-radius:10px;
  padding:13px;
  background:var(--panel-soft);
}

.feature-pill{
  display:inline-block;
  border:1px solid var(--line-2);
  border-radius:6px;
  padding:4px 9px;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:1.4px;
  font-family:'JetBrains Mono',monospace;
  color:var(--accent);
  background:rgba(245,165,36,.06);
}

.feature-card h4{
  margin:9px 0 0;
  font-size:15px;
  letter-spacing:.2px;
}

.feature-card p{
  margin:7px 0 0;
  color:var(--muted);
  font-size:13px;
  line-height:1.48;
}

.howto{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:1px;
  border:1px solid var(--line);
  border-radius:12px;
  background:var(--line);
  overflow:hidden;
}

.howto .step{
  padding:16px 18px;
  background:var(--panel-soft);
}

.howto .step .num{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;
  letter-spacing:1.4px;
  color:var(--accent);
}

.howto .step h4{
  margin:9px 0 0;
  font-size:14px;
  font-weight:700;
  letter-spacing:-.2px;
}

.howto .step p{
  margin:6px 0 0;
  color:var(--muted);
  font-size:12.5px;
  line-height:1.5;
}

@media (max-width:920px){
  .howto{grid-template-columns:1fr}
}

.statcards{
  display:grid;
  grid-template-columns:repeat(6,minmax(106px,1fr));
  gap:8px;
}

.statcard{padding:10px;background:var(--panel-soft)}

.statcard .n{font-size:22px;font-weight:800;line-height:1;font-family:'JetBrains Mono',monospace}

.statcard .l{
  margin-top:6px;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:1.2px;
  font-family:'JetBrains Mono',monospace;
  color:var(--muted);
}

.bar{
  height:4px;
  margin-top:8px;
  border-radius:2px;
  background:rgba(255,255,255,.07);
  overflow:hidden;
}

.bar > span{
  display:block;
  height:100%;
  width:var(--w,0%);
  background:var(--accent);
  border-radius:2px;
}

.statcard.total .n{color:var(--accent)}
.statcard.crit .n{color:var(--crit)} .statcard.crit .bar > span{background:var(--crit)}
.statcard.high .n{color:var(--high)} .statcard.high .bar > span{background:var(--high)}
.statcard.med .n{color:var(--med)} .statcard.med .bar > span{background:var(--med)}
.statcard.low .n{color:var(--low)} .statcard.low .bar > span{background:var(--low)}
.statcard.info .n{color:var(--info)} .statcard.info .bar > span{background:var(--info)}

.resultframe{
  width:100%;
  height:60vh;
  min-height:500px;
  background:var(--bg-soft);
}

.placeholder{
  width:100%;
  height:60vh;
  min-height:500px;
  display:grid;
  place-items:center;
  text-align:center;
  padding:24px;
}

.placeholder .big{font-size:24px;font-weight:700}

.placeholder .ex{
  margin-top:10px;
  color:var(--dim);
  font-size:12px;
  font-family:'JetBrains Mono',Consolas,"Courier New",monospace;
}

.history{padding:10px;background:var(--panel-soft)}

.history h3{
  margin:0 0 9px;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:1.6px;
  font-family:'JetBrains Mono',monospace;
  color:var(--dim);
}

.history-list{display:grid;gap:7px}

.history-item{
  display:grid;
  grid-template-columns:auto 54px minmax(170px,1.2fr) minmax(90px,.8fr) 56px 70px;
  gap:10px;
  align-items:center;
  border:1px solid var(--line);
  border-radius:10px;
  padding:8px 9px;
  background:var(--bg-soft);
  cursor:pointer;
}

.history-item .target{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.history-item .server{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted);font-size:11.5px}
.history-item .age{color:var(--muted);font-size:11.5px}

.sev{display:inline-block;padding:3px 8px;border-radius:5px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;color:#0a0b0d}
.sev.critical{background:var(--crit)}
.sev.high{background:var(--high)}
.sev.medium{background:var(--med)}
.sev.low{background:var(--low)}
.sev.info{background:var(--info)}
.sev.none{background:#2a2e35;color:#9aa0a8}

footer{
  margin:0 12px 12px;
  padding:10px 12px;
  display:flex;
  justify-content:space-between;
  gap:10px;
  font-size:11px;
  color:var(--muted);
}

@media (max-width:1200px){
  .feature-grid{grid-template-columns:1fr 1fr}
  .statcards{grid-template-columns:repeat(3,1fr)}
  .history-item{grid-template-columns:auto 54px minmax(110px,1fr) 60px}
  .history-item .server,.history-item .age{display:none}
}

@media (max-width:920px){
  .frame{margin:8px}
  .topbar{padding:10px 12px}
  .brand .tag{display:none}
  .version-chip{display:none}
  .shell{grid-template-columns:1fr;padding:10px}
  .hero{padding:16px}
  .hero h1{font-size:38px}
  .hero-meta span{font-size:10px}
  .launch-grid{grid-template-columns:1fr}
  .feature-grid{grid-template-columns:1fr}
  .statcards{grid-template-columns:repeat(2,1fr)}
  .probes{grid-template-columns:1fr}
  .history-item{grid-template-columns:auto 1fr 56px;gap:8px}
  .history-item .server,.history-item .age{display:none}
  footer{margin:0 10px 10px;flex-direction:column}
}
"""

_JS = r"""
let SELECTED_PRESET = null;
let PRESETS = [];

async function loadPresets(){
  const r = await fetch('/api/presets');
  const d = await r.json();
  PRESETS = d.presets || [];
  const wrap = document.getElementById('presetChips');
  wrap.innerHTML = '';
  for (const p of PRESETS){
    const el = document.createElement('button');
    el.className = 'chip';
    el.dataset.name = p.name;
    el.innerHTML = `${p.name}<span class="sub">${p.launcher}</span>`;
    el.title = p.summary + (p.env_vars && p.env_vars.length ? ` - needs env: ${p.env_vars.join(', ')}` : '');
    el.onclick = () => selectPreset(p.name);
    wrap.appendChild(el);
  }
}

function selectPreset(name){
  SELECTED_PRESET = name;
  const custom = document.getElementById('customTarget');
  if (custom) custom.value = '';
  document.querySelectorAll('#presetChips .chip').forEach(c =>
    c.classList.toggle('active', c.dataset.name === name)
  );
}

function clearPreset(){
  SELECTED_PRESET = null;
  document.querySelectorAll('#presetChips .chip').forEach(c => c.classList.remove('active'));
}

function onCustomTargetInput(){
  const v = document.getElementById('customTarget').value.trim();
  if (v) clearPreset();
}

function setBusy(busy, msg){
  document.getElementById('run').disabled = busy;
  document.body.classList.toggle('busy', busy);
  document.getElementById('statusPill').classList.toggle('busy', busy);
  document.getElementById('statusPill').querySelector('.label').textContent =
    busy ? 'scanning' : 'idle';
  const st = document.getElementById('status');
  st.className = 'status';
  st.textContent = msg || '';
}

function setError(msg){
  const st = document.getElementById('status');
  st.className = 'status err';
  st.textContent = msg;
  document.getElementById('run').disabled = false;
  document.body.classList.remove('busy');
  document.getElementById('statusPill').classList.remove('busy');
  document.getElementById('statusPill').querySelector('.label').textContent = 'error';
}

function renderStats(stats){
  const grid = document.getElementById('statcards');
  const sevs = [['critical','crit'],['high','high'],['medium','med'],['low','low'],['info','info']];
  const total = Number(stats.total || 0);
  let html = `<div class="statcard total"><div class="n">${total}</div><div class="l">total findings</div><div class="bar"><span style="--w:100%"></span></div></div>`;
  for (const [k,cls] of sevs){
    const v = Number((stats.by_sev || {})[k] || 0);
    const pct = total > 0 ? Math.max(6, Math.round((v / total) * 100)) : 0;
    html += `<div class="statcard ${cls}"><div class="n">${v}</div><div class="l">${k}</div><div class="bar"><span style="--w:${pct}%"></span></div></div>`;
  }
  grid.innerHTML = html;
  grid.style.display = 'grid';
}

function renderHistory(history){
  const wrap = document.getElementById('historyWrap');
  if (!history.length){ wrap.innerHTML = ''; return; }
  let rows = '';
  for (const h of history){
    const sev = h.max_severity || 'none';
    rows += `<div class="history-item" onclick="showRun('${h.id}')">
      <span class="sev ${sev}">${sev}</span>
      <b>${h.findings}</b>
      <div class="target"><code>${escapeHtml(h.label)}</code></div>
      <div class="server">${h.server || '-'}</div>
      <div>${Number(h.duration_s || 0).toFixed(1)}s</div>
      <div class="age">${h.age}</div>
    </div>`;
  }
  wrap.innerHTML = `<h3>Recent runs</h3><div class="history-list">${rows}</div>`;
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function refreshHistory(){
  try{
    const r = await fetch('/api/history');
    const d = await r.json();
    renderHistory(d.history || []);
  } catch(e) {}
}

async function showRun(id){
  const r = await fetch('/api/history/' + id);
  const d = await r.json();
  if (!d.ok){ setError(d.error || 'run not found'); return; }
  document.getElementById('placeholder').style.display = 'none';
  const f = document.getElementById('frame');
  f.style.display = 'block';
  f.srcdoc = d.html;
  renderStats(d.stats);
}

async function run(){
  const probes = [...document.querySelectorAll('.probes input:checked')].map(c => c.value);
  const sev = document.getElementById('sev').value;
  const custom = (document.getElementById('customTarget').value || '').trim();

  let url, body, busyMsg;
  if (custom){
    url = '/api/scan';
    body = {target: custom, probes, severity: sev};
    busyMsg = 'Running scan...';
  } else if (SELECTED_PRESET){
    url = '/api/scan-preset';
    body = {preset: SELECTED_PRESET, probes, severity: sev};
    busyMsg = `Running preset "${SELECTED_PRESET}" ...`;
  } else {
    setError('Enter a target above or pick a preset.');
    return;
  }

  setBusy(true, busyMsg);

  try{
    const r = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!d.ok){ setError('Scan failed: ' + d.error); return; }
    document.getElementById('placeholder').style.display = 'none';
    const f = document.getElementById('frame');
    f.style.display = 'block';
    f.srcdoc = d.html;
    renderStats(d.stats);
    setBusy(false, d.summary);
    refreshHistory();
  } catch(e){
    setError('Request failed: ' + e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadPresets();
  refreshHistory();
});
"""


_INDEX_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-redteam - runtime red-team for MCP servers</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=JetBrains+Mono:wght@400;600&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>__CSS__</style>
</head>
<body>
<div class="frame">
<div class="topbar">
  <div class="brand">
    <div class="logo">R</div>
    <div>
      <span class="name">MCP REDTEAM</span>
      <span class="tag">Open Source • MCP Runtime Security</span>
    </div>
  </div>
  <div class="top-meta">
    <span class="version-chip">Public Launch Build</span>
    <div class="pill" id="statusPill"><span class="dot"></span><span class="label">idle</span></div>
    <a class="gh-link" href="https://github.com/codezxsWIN" target="_blank" rel="noopener noreferrer" title="View on GitHub"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>GitHub</a>
  </div>
</div>

<div class="shell">
  <aside class="sidepanel">
    <div class="panel-head">
      <b>Scan Console</b>
      <span>Point at your MCP server (custom target) or use a one-click preset, then run probes and review transcript-backed findings.</span>
    </div>

    <div class="section">
      <h3>Target <span style="color:var(--dim);font-weight:400;text-transform:none;letter-spacing:0">your server</span></h3>
      <input type="text" id="customTarget" class="input" placeholder="stdio:python -m tests.fixtures.vulnerable_server" oninput="onCustomTargetInput()" autocomplete="off" spellcheck="false">
      <p class="hint"><code>stdio:command args</code> · <code>https://host/mcp</code> · path to <code>mcp.json</code></p>
    </div>

    <div class="section">
      <h3>Presets <span style="color:var(--dim);font-weight:400;text-transform:none;letter-spacing:0">or pick one</span></h3>
      <div class="chips" id="presetChips"></div>
    </div>

    <div class="section">
      <h3>Probes</h3>
      <div class="probes" id="probes">__PROBES__</div>
    </div>

    <div class="section">
      <h3>Severity threshold</h3>
      <select id="sev" class="select">__SEV__</select>
    </div>

    <button class="btn" id="run" onclick="run()">Run scan</button>
    <div class="status" id="status"></div>
  </aside>

  <main class="main">
    <div class="hero">
      <div class="hero-kicker"><span class="spark"></span>Open Source • MCP Runtime</div>
      <h1>Production-grade MCP security, with evidence you can ship.</h1>
      <p>Connect to a Model Context Protocol server over stdio or streamable HTTP, run curated offensive probes, and generate transcript-backed findings for confident go-live decisions.</p>
      <div class="hero-meta">
        <span>MCP-native probe suite</span>
        <span>Severity-based release gating</span>
        <span>Replayable run history</span>
      </div>
    </div>

    <div class="howto">
      <div class="step">
        <div class="num">01 / CONNECT</div>
        <h4>Point at a server</h4>
        <p>Enter a stdio command, HTTP URL, or <code>mcp.json</code> path — or pick a preset.</p>
      </div>
      <div class="step">
        <div class="num">02 / PROBE</div>
        <h4>Run the suite</h4>
        <p>Curated adversarial probes test for tool poisoning, output injection, rug pulls, and exfiltration.</p>
      </div>
      <div class="step">
        <div class="num">03 / DECIDE</div>
        <h4>Review evidence</h4>
        <p>Get transcript-backed findings with severity gating to make a confident go-live call.</p>
      </div>
    </div>

    <div class="statcards" id="statcards" style="display:none"></div>

    <iframe class="resultframe" id="frame" style="display:none"></iframe>
    <div class="placeholder" id="placeholder">
      <div>
        <div class="big">No scan yet</div>
        <div>Hit <b style="color:var(--accent)">Run scan</b> after entering a target or picking a preset.</div>
        <div class="ex">try target: <code>stdio:python -m tests.fixtures.vulnerable_server</code> or preset <b>vulnerable</b></div>
      </div>
    </div>

    <div class="history" id="historyWrap"></div>
  </main>
</div>

<footer>
  <div>mcp-redteam dashboard - for authorized security research only</div>
  <div><a href="https://github.com/codezxsWIN" target="_blank" rel="noopener noreferrer">github.com/codezxsWIN</a> · __PROBE_LIST__</div>
</footer>
</div>

<script>__JS__</script>
</body></html>"""


def _index_html() -> str:
    checks = "".join(
        f'<label><input type="checkbox" value="{p}" checked>{p}</label>'
        for p in PROBE_NAMES
    )
    opts = "".join(
        f'<option value="{s.name}"{" selected" if s.name == "medium" else ""}>{s.name}</option>'
        for s in sorted(Severity, key=lambda x: -int(x))
    )
    return (
        _INDEX_TEMPLATE
        .replace("__CSS__", _CSS)
        .replace("__JS__", _JS)
        .replace("__PROBES__", checks)
        .replace("__SEV__", opts)
        .replace("__PROBE_LIST__", "probes: " + ", ".join(PROBE_NAMES))
    )


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------


async def _index(_request: Request) -> HTMLResponse:
    return HTMLResponse(_index_html())


def _public_presets() -> list[Any]:
  return [
    p
    for p in presets_mod.PRESETS
    if p.launcher != "docker" and not p.env_vars
  ]


def _is_public_preset(name: str) -> bool:
  return any(p.name == name for p in _public_presets())


async def _list_presets(_request: Request) -> JSONResponse:
    return JSONResponse({
        "presets": [
            {
                "name": p.name,
                "summary": p.summary,
                "launcher": p.launcher,
        "takes_arg": False,
        "arg_help": None,
        "env_vars": [],
            }
      for p in _public_presets()
        ]
    })


async def _history_list(_request: Request) -> JSONResponse:
    now = time.time()
    out = []
    for h in _HISTORY:
        age_s = now - h["ts"]
        out.append({
            "id": h["id"],
            "label": h["label"],
            "server": h["server"],
            "findings": h["findings"],
            "max_severity": h["max_severity"],
            "duration_s": h["duration_s"],
            "age": _humanize(age_s),
        })
    return JSONResponse({"history": out})


async def _history_get(request: Request) -> JSONResponse:
    hid = request.path_params["hid"]
    for h in _HISTORY:
        if h["id"] == hid:
            return JSONResponse({
                "ok": True,
                "html": h["html"],
                "stats": h["stats"],
                "summary": h["summary"],
            })
    return JSONResponse({"ok": False, "error": "not found"}, status_code=404)


def _humanize(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def _stats(reports: list[ScanReport]) -> dict[str, Any]:
    by_sev: dict[str, int] = {}
    total = 0
    for r in reports:
        for k, v in r.counts_by_severity().items():
            by_sev[k] = by_sev.get(k, 0) + v
            total += v
    return {"total": total, "by_sev": by_sev}


def _summary(reports: list[ScanReport]) -> str:
    total = sum(len(r.findings) for r in reports)
    worst = max(
        (r.max_severity() for r in reports if r.max_severity() is not None),
        default=None,
    )
    servers = ", ".join(r.server.name or "?" for r in reports)
    worst_txt = worst.name if worst is not None else "none"
    return f"{total} finding(s) across {len(reports)} server(s) [{servers}] - max severity {worst_txt}"


def _combine_html(reports: list[ScanReport]) -> str:
    if len(reports) == 1:
        return to_html(reports[0])
    return "<hr>".join(to_html(r) for r in reports)


def _record(
    label: str,
    reports: list[ScanReport],
    elapsed: float,
    html_payload: str,
    stats: dict[str, Any],
    summary: str,
) -> None:
    worst = max(
        (r.max_severity() for r in reports if r.max_severity() is not None),
        default=None,
    )
    _push_history({
        "id": uuid.uuid4().hex[:10],
        "label": label,
        "server": ", ".join(r.server.name or "?" for r in reports) or None,
        "findings": stats["total"],
        "max_severity": worst.name if worst is not None else None,
        "duration_s": round(elapsed, 2),
        "ts": time.time(),
        "html": html_payload,
        "stats": stats,
        "summary": summary,
    })


async def _run_specs(
    specs: list[TargetSpec],
    settings: Settings,
    probes: list[str] | None,
) -> list[ScanReport]:
    out: list[ScanReport] = []
    for spec in specs:
        out.append(await scan_target(spec, settings, probes))
    return out


def _parse_probes_payload(body: dict) -> list[str] | None:
    probes = body.get("probes") or None
    if probes is not None and not isinstance(probes, list):
        raise ValueError("probes must be a list")
    return probes or None


def _parse_severity(body: dict) -> Severity:
    sev = str(body.get("severity", "medium"))
    try:
        return Severity.parse(sev)
    except (KeyError, ValueError):
        return Severity.medium


async def _scan_preset(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

    name = str(body.get("preset", "")).strip()
    if not name:
        return JSONResponse({"ok": False, "error": "missing preset name"}, status_code=400)

    if not _is_public_preset(name):
      return JSONResponse({"ok": False, "error": "preset is not available in public mode"}, status_code=400)

    try:
        probes = _parse_probes_payload(body)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    threshold = _parse_severity(body)

    try:
        spec = presets_mod.resolve(name, None)
    except (KeyError, ValueError, RuntimeError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    settings = Settings(severity_threshold=threshold)
    t0 = time.time()
    try:
        reports = await _run_specs([spec], settings, probes)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            },
            status_code=500,
        )
    elapsed = time.time() - t0

    html_payload = _combine_html(reports)
    stats = _stats(reports)
    label = f"preset:{name}"
    summary = _summary(reports) + f" - {elapsed:.1f}s"
    _record(
        label=label,
        reports=reports,
        elapsed=elapsed,
        html_payload=html_payload,
        stats=stats,
        summary=summary,
    )

    return JSONResponse({"ok": True, "html": html_payload, "stats": stats, "summary": summary})


async def _scan(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

    target = str(body.get("target", "")).strip()
    if not target:
        return JSONResponse({"ok": False, "error": "missing target"}, status_code=400)

    try:
        probes = _parse_probes_payload(body)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    try:
        specs = parse_target(target)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    threshold = _parse_severity(body)
    settings = Settings(severity_threshold=threshold)
    t0 = time.time()
    try:
        reports = await _run_specs(specs, settings, probes)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            },
            status_code=500,
        )
    elapsed = time.time() - t0

    html_payload = _combine_html(reports)
    stats = _stats(reports)
    summary = _summary(reports) + f" - {elapsed:.1f}s"
    _record(
        label=target,
        reports=reports,
        elapsed=elapsed,
        html_payload=html_payload,
        stats=stats,
        summary=summary,
    )

    return JSONResponse({"ok": True, "html": html_payload, "stats": stats, "summary": summary})


def build_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/", _index, methods=["GET"]),
            Route("/api/presets", _list_presets, methods=["GET"]),
            Route("/api/scan", _scan, methods=["POST"]),
            Route("/api/scan-preset", _scan_preset, methods=["POST"]),
            Route("/api/history", _history_list, methods=["GET"]),
            Route("/api/history/{hid}", _history_get, methods=["GET"]),
        ]
    )


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(build_app(), host=host, port=port, log_level="warning")
