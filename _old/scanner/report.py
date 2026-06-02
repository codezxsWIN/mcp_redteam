"""
Render scan results to the terminal and (optionally) a Markdown file.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .scanner import Finding


SEVERITY_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "white",
}


def _summary(findings: list[Finding]) -> dict[str, int]:
    s = {"total": len(findings), "vulnerable": 0, "safe": 0, "errors": 0}
    for f in findings:
        if f.error:
            s["errors"] += 1
        elif f.success:
            s["vulnerable"] += 1
        else:
            s["safe"] += 1
    return s


def print_report(findings: list[Finding], target: str) -> None:
    console = Console()
    summary = _summary(findings)

    console.rule(f"[bold]promptprobe report — {target}")
    console.print(
        f"Tested [bold]{summary['total']}[/] payloads  "
        f"[bright_red]{summary['vulnerable']} vulnerable[/]  "
        f"[green]{summary['safe']} safe[/]  "
        f"[yellow]{summary['errors']} errors[/]"
    )

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Result", width=8)
    table.add_column("Severity", width=10)
    table.add_column("ID", width=22)
    table.add_column("Category", width=24)
    table.add_column("Description")

    for f in findings:
        if f.error:
            result = "[yellow]ERROR[/]"
        elif f.success:
            result = "[bright_red]VULN[/]"
        else:
            result = "[green]safe[/]"

        sev_color = SEVERITY_COLOR.get(f.payload.severity, "white")
        sev = f"[{sev_color}]{f.payload.severity}[/]"
        table.add_row(result, sev, f.payload.id, f.payload.category, f.payload.description)

    console.print(table)

    vulns = [f for f in findings if f.success]
    if vulns:
        console.rule("[bold red]Vulnerable findings — reproducible PoCs")
        for f in vulns:
            console.print(f"\n[bold red]{f.payload.id}[/]  ({f.payload.severity})")
            console.print(f"[dim]category:[/] {f.payload.category}")
            console.print(f"[dim]judge:[/]    {f.verdict.judge} — {f.verdict.reason}")
            console.print(f"[dim]prompt:[/]   {f.payload.prompt}")
            console.print(f"[dim]response:[/] {f.response[:300]}{'…' if len(f.response) > 300 else ''}")


def write_markdown(findings: list[Finding], target: str, out: Path) -> Path:
    summary = _summary(findings)
    lines: list[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"# promptprobe report\n")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **When:** {ts}")
    lines.append(
        f"- **Summary:** {summary['vulnerable']} vulnerable / "
        f"{summary['safe']} safe / {summary['errors']} errors "
        f"(out of {summary['total']})\n"
    )

    lines.append("## Findings\n")
    lines.append("| Result | Severity | ID | Category | Description |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        result = "ERROR" if f.error else ("**VULN**" if f.success else "safe")
        lines.append(
            f"| {result} | {f.payload.severity} | `{f.payload.id}` | "
            f"{f.payload.category} | {f.payload.description} |"
        )

    vulns = [f for f in findings if f.success]
    if vulns:
        lines.append("\n## Reproducible PoCs\n")
        for f in vulns:
            lines.append(f"### `{f.payload.id}` — {f.payload.severity}\n")
            lines.append(f"- **Category:** {f.payload.category}")
            lines.append(f"- **Judge:** {f.verdict.judge} — {f.verdict.reason}\n")
            lines.append("**Prompt:**\n")
            lines.append("```")
            lines.append(f.payload.prompt)
            lines.append("```\n")
            lines.append("**Response:**\n")
            lines.append("```")
            lines.append(f.response)
            lines.append("```\n")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
