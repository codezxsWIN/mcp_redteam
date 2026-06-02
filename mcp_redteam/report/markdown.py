from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .finding import Finding, Interaction, ScanReport

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_findings(report: ScanReport) -> list[Finding]:
    return sorted(report.findings, key=lambda f: (_SEV_ORDER.get(f.severity.name, 9), f.probe))


def _render_interaction(step: Interaction) -> list[str]:
    arrow = "→" if step.direction == "request" else "←"
    head = f"- {arrow} **{step.direction}**"
    if step.method:
        head += f" `{step.method}`"
    head += f" — {step.summary}"
    lines = [head]
    if step.data is not None:
        lines.append("")
        lines.append("  ```json")
        body = json.dumps(step.data, indent=2, ensure_ascii=False, default=str)
        lines.extend("  " + ln for ln in body.splitlines())
        lines.append("  ```")
    return lines


def to_markdown(report: ScanReport) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = report.counts_by_severity()
    lines: list[str] = []
    lines.append("# mcp-redteam report")
    lines.append("")
    lines.append(f"- **Target:** `{report.target}`")
    lines.append(
        f"- **Server:** {report.server.name or '?'} v{report.server.version or '?'} "
        f"({report.server.transport})"
    )
    lines.append(f"- **When:** {ts}")
    if report.duration_seconds is not None:
        lines.append(f"- **Duration:** {report.duration_seconds}s")
    lines.append(f"- **Probes:** {', '.join(report.probes_run) or 'none'}")
    lines.append(
        f"- **Enumerated:** {report.tool_count} tool(s), {report.resource_count} resource(s)"
    )
    lines.append(
        "- **Findings:** "
        + f"{len(report.findings)} "
        + "("
        + ", ".join(f"{k}: {v}" for k, v in counts.items() if v)
        + ")"
        if report.findings
        else "- **Findings:** 0"
    )
    lines.append("")

    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    findings = _sorted_findings(report)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Probe | Tool/Resource | Title |")
    lines.append("|---|---|---|---|")
    for f in findings:
        subject = f.tool or f.resource or "—"
        lines.append(f"| **{f.severity.name}** | `{f.probe}` | `{subject}` | {f.title} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. [{f.severity.name.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **Probe:** `{f.probe}`")
        lines.append(f"- **Category:** {f.category}")
        if f.tool:
            lines.append(f"- **Tool:** `{f.tool}`")
        if f.resource:
            lines.append(f"- **Resource:** `{f.resource}`")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.reproduction:
            lines.append("**Reproduction steps:**")
            lines.append("")
            for n, step in enumerate(f.reproduction, 1):
                lines.append(f"{n}. {step}")
            lines.append("")
        if f.evidence.transcript:
            lines.append("**Transcript:**")
            lines.append("")
            for step in f.evidence.transcript:
                lines.extend(_render_interaction(step))
            lines.append("")
        if f.evidence.notes:
            lines.append("**Notes:**")
            lines.append("")
            for note in f.evidence.notes:
                lines.append(f"- {note}")
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")

    return "\n".join(lines) + "\n"


def write_markdown(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_markdown(report), encoding="utf-8")
    return path
