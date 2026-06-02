from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .finding import Finding, ScanReport

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CSS = """
:root {
  --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
  --muted: #8b949e; --critical: #ff5c5c; --high: #ff8c42; --medium: #f2cc60;
  --low: #58a6ff; --info: #8b949e; --accent: #6e9fff;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
header { padding: 24px 32px; border-bottom: 1px solid var(--border); background: var(--panel); }
header h1 { margin: 0; font-size: 22px; letter-spacing: .3px; }
header h1 .rt { color: var(--accent); }
header .meta { margin-top: 8px; color: var(--muted); font-size: 13px; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 18px; min-width: 120px; }
.card .n { font-size: 26px; font-weight: 700; }
.card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 14px; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
tr:last-child td { border-bottom: none; }
tr.frow { cursor: pointer; }
tr.frow:hover { background: #1c2330; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
  font-weight: 700; color: #0d1117; }
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); }
.badge.low { background: var(--low); }
.badge.info { background: var(--info); }
code { background: #0d1117; border: 1px solid var(--border); border-radius: 5px;
  padding: 1px 6px; font-size: 13px; }
.detail { display: none; }
.detail.open { display: table-row; }
.detail td { background: #0d1117; padding: 0; }
.detail-inner { padding: 18px 22px; }
.detail-inner h4 { margin: 14px 0 6px; font-size: 13px; color: var(--accent);
  text-transform: uppercase; letter-spacing: .5px; }
.detail-inner p { margin: 4px 0; line-height: 1.5; }
.step { display: flex; gap: 8px; align-items: baseline; margin: 3px 0; font-size: 14px; }
.arrow { color: var(--accent); font-weight: 700; }
pre { background: #010409; border: 1px solid var(--border); border-radius: 6px;
  padding: 10px 12px; overflow-x: auto; font-size: 12.5px; margin: 6px 0; }
.empty { text-align: center; color: var(--muted); padding: 40px; }
.muted { color: var(--muted); }
"""

_TOGGLE_JS = """
function toggle(id){var e=document.getElementById(id);if(e)e.classList.toggle('open');}
"""


def _esc(text: object) -> str:
    return html.escape(str(text))


def _sorted(report: ScanReport) -> list[Finding]:
    return sorted(report.findings, key=lambda f: (_SEV_ORDER.get(f.severity.name, 9), f.probe))


def _transcript_html(f: Finding) -> str:
    rows: list[str] = []
    for step in f.evidence.transcript:
        arrow = "&rarr;" if step.direction == "request" else "&larr;"
        method = f" <code>{_esc(step.method)}</code>" if step.method else ""
        rows.append(
            f'<div class="step"><span class="arrow">{arrow}</span>'
            f'<span><b>{_esc(step.direction)}</b>{method} — {_esc(step.summary)}</span></div>'
        )
        if step.data is not None:
            body = json.dumps(step.data, indent=2, ensure_ascii=False, default=str)
            rows.append(f"<pre>{_esc(body)}</pre>")
    return "".join(rows)


def _finding_rows(report: ScanReport) -> str:
    rows: list[str] = []
    for i, f in enumerate(_sorted(report)):
        subject = f.tool or f.resource or "—"
        det_id = f"d{i}"
        rows.append(
            f'<tr class="frow" onclick="toggle(\'{det_id}\')">'
            f'<td><span class="badge {f.severity.name}">{f.severity.name}</span></td>'
            f"<td><code>{_esc(f.probe)}</code></td>"
            f"<td><code>{_esc(subject)}</code></td>"
            f"<td>{_esc(f.title)}</td></tr>"
        )
        steps = "".join(f"<li>{_esc(s)}</li>" for s in f.reproduction)
        notes = "".join(f"<li>{_esc(n)}</li>" for n in f.evidence.notes)
        rows.append(
            f'<tr class="detail" id="{det_id}"><td colspan="4"><div class="detail-inner">'
            f"<p>{_esc(f.description)}</p>"
            f"<h4>Category</h4><p>{_esc(f.category)}</p>"
            + (f"<h4>Reproduction steps</h4><ol>{steps}</ol>" if steps else "")
            + (f"<h4>Transcript</h4>{_transcript_html(f)}" if f.evidence.transcript else "")
            + (f"<h4>Notes</h4><ul>{notes}</ul>" if notes else "")
            + (f"<h4>Remediation</h4><p>{_esc(f.remediation)}</p>" if f.remediation else "")
            + "</div></td></tr>"
        )
    return "".join(rows)


def to_html(report: ScanReport) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = report.counts_by_severity()
    ordered = sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))
    cards = "".join(
        f'<div class="card"><div class="n">{v}</div>'
        f'<div class="l"><span class="badge {k}">{k}</span></div></div>'
        for k, v in ordered
        if v
    )
    total_card = (
        f'<div class="card"><div class="n">{len(report.findings)}</div>'
        f'<div class="l">findings</div></div>'
    )
    dur = f" · {report.duration_seconds}s" if report.duration_seconds is not None else ""

    body = (
        f'<div class="cards">{total_card}{cards}</div>'
        + '<table><thead><tr><th>Severity</th><th>Probe</th><th>Subject</th>'
        + "<th>Title</th></tr></thead><tbody>"
        + _finding_rows(report)
        + "</tbody></table>"
        if report.findings
        else '<div class="empty">No findings.</div>'
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-redteam report</title>
<style>{_CSS}</style></head>
<body>
<header>
  <h1><span class="rt">mcp-redteam</span> report</h1>
  <div class="meta">
    Target: <code>{_esc(report.target)}</code> &nbsp;·&nbsp;
    Server: {_esc(report.server.name or "?")} v{_esc(report.server.version or "?")}
    ({_esc(report.server.transport)}) &nbsp;·&nbsp;
    {report.tool_count} tools, {report.resource_count} resources &nbsp;·&nbsp;
    {ts}{dur}
  </div>
</header>
<div class="wrap">{body}
  <p class="muted" style="margin-top:24px;font-size:12px;">
    Click any finding row to expand its reproduction transcript.
    Probes run: {_esc(", ".join(report.probes_run) or "none")}.
  </p>
</div>
<script>{_TOGGLE_JS}</script>
</body></html>"""


def write_html(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(report), encoding="utf-8")
    return path
