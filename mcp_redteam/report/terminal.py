from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .finding import ScanReport

_SEV_STYLE = {
    "critical": "bold bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_report(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    console.rule(f"[bold]mcp-redteam — {report.target}")
    console.print(
        f"Server: [bold]{report.server.name or '?'}[/] v{report.server.version or '?'} "
        f"([italic]{report.server.transport}[/])   "
        f"Tools: [bold]{report.tool_count}[/]   "
        f"Resources: [bold]{report.resource_count}[/]   "
        f"Findings: [bright_red]{len(report.findings)}[/]"
    )

    if not report.findings:
        console.print("\n[green]No findings.[/]")
        return

    findings = sorted(
        report.findings, key=lambda f: (_SEV_ORDER.get(f.severity.name, 9), f.probe)
    )
    table = Table(title="Findings", header_style="bold", show_lines=False)
    table.add_column("Severity", width=10)
    table.add_column("Probe", width=18)
    table.add_column("Subject", width=20)
    table.add_column("Title")
    for f in findings:
        style = _SEV_STYLE.get(f.severity.name, "white")
        subject = f.tool or f.resource or "—"
        table.add_row(
            f"[{style}]{f.severity.name}[/]", f.probe, subject, f.title
        )
    console.print(table)

    counts = {k: v for k, v in report.counts_by_severity().items() if v}
    summary = "   ".join(f"[{_SEV_STYLE.get(k,'white')}]{k}: {v}[/]" for k, v in counts.items())
    console.print(f"\n{summary}")
