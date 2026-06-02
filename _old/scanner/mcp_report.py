"""
Render MCP scan results to the terminal (rich) and Markdown.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .mcp_scanner import McpScanResult


SEVERITY_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "white",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def print_mcp_report(result: McpScanResult, target: str) -> None:
    console = Console()
    info = result.server_info
    console.rule(f"[bold]promptprobe MCP report — {target}")
    console.print(
        f"Server: [bold]{info.get('name', '?')}[/] "
        f"v{info.get('version', '?')}   "
        f"Tools enumerated: [bold]{len(result.tools)}[/]   "
        f"Findings: [bright_red]{len(result.findings)}[/]"
    )

    if result.tools:
        tt = Table(title="Discovered tools", show_lines=False, header_style="bold")
        tt.add_column("Name", width=16)
        tt.add_column("Args", width=24)
        tt.add_column("Description")
        for t in result.tools:
            props = (t.get("inputSchema") or {}).get("properties") or {}
            args = ", ".join(props.keys()) or "—"
            desc = (t.get("description") or "").splitlines()[0]
            tt.add_row(t.get("name", "?"), args, desc[:80])
        console.print(tt)

    if not result.findings:
        console.print("\n[green]No findings.[/]")
        return

    findings = sorted(
        result.findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.probe),
    )

    ft = Table(title="Findings", show_lines=False, header_style="bold")
    ft.add_column("Sev", width=10)
    ft.add_column("Tool", width=14)
    ft.add_column("Probe", width=22)
    ft.add_column("Title")
    for f in findings:
        sev_color = SEVERITY_COLOR.get(f.severity, "white")
        ft.add_row(
            f"[{sev_color}]{f.severity}[/]",
            f.tool or "—",
            f.probe,
            f.title,
        )
    console.print(ft)

    console.rule("[bold red]Reproducible PoCs")
    for f in findings:
        sev_color = SEVERITY_COLOR.get(f.severity, "white")
        console.print(
            f"\n[{sev_color}]{f.severity.upper()}[/] "
            f"[bold]{f.title}[/]"
        )
        console.print(f"[dim]probe:[/]    {f.probe}")
        console.print(f"[dim]category:[/] {f.category}")
        console.print(f"[dim]tool:[/]     {f.tool or '—'}")
        console.print(f"[dim]detail:[/]   {f.detail}")
        if f.request:
            console.print(f"[dim]request:[/]  {json.dumps(f.request)}")
        if f.evidence:
            ev = f.evidence.strip().replace("\r", "")
            if len(ev) > 280:
                ev = ev[:280] + "…"
            console.print(f"[dim]evidence:[/] {ev}")


def write_mcp_markdown(result: McpScanResult, target: str, out: Path) -> Path:
    info = result.server_info
    lines: list[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append(f"# promptprobe MCP report\n")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Server:** {info.get('name', '?')} v{info.get('version', '?')}")
    lines.append(f"- **When:** {ts}")
    lines.append(
        f"- **Findings:** {len(result.findings)} across "
        f"{len(result.tools)} enumerated tool(s)\n"
    )

    lines.append("## Tool catalog\n")
    lines.append("| Tool | Arguments | Description |")
    lines.append("|---|---|---|")
    for t in result.tools:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        args = ", ".join(props.keys()) or "—"
        desc = (t.get("description") or "").splitlines()[0]
        lines.append(f"| `{t.get('name','?')}` | `{args}` | {desc} |")

    lines.append("\n## Findings\n")
    findings = sorted(
        result.findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.probe),
    )
    lines.append("| Severity | Tool | Probe | Title |")
    lines.append("|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| **{f.severity}** | `{f.tool or '—'}` | `{f.probe}` | {f.title} |"
        )

    if findings:
        lines.append("\n## Reproducible PoCs\n")
        for f in findings:
            lines.append(f"### {f.severity.upper()} — {f.title}\n")
            lines.append(f"- **Probe:** `{f.probe}`")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **Tool:** `{f.tool or '—'}`\n")
            lines.append(f"{f.detail}\n")
            if f.request:
                lines.append("**Request:**\n")
                lines.append("```json")
                lines.append(json.dumps(f.request, indent=2))
                lines.append("```\n")
            if f.evidence:
                lines.append("**Evidence:**\n")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```\n")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
