from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .client.transport import parse_target
from .config import Settings
from . import presets as presets_mod
from .probes import PROBE_NAMES
from .report.finding import ScanReport, Severity
from .report.json_out import to_json
from .report.markdown import to_markdown
from .report.html_out import to_html, write_html
from .report.terminal import print_report
from .scanner import scan_target

app = typer.Typer(add_completion=False, help="Dynamic red-team toolkit for MCP servers.")
console = Console()


@app.callback()
def _root() -> None:
    """Dynamic red-team toolkit for MCP servers."""


def _severity_option(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except (KeyError, ValueError):
        raise typer.BadParameter(
            f"invalid severity {value!r}; choose from: {', '.join(s.name for s in Severity)}"
        )


@app.command(context_settings={"ignore_unknown_options": True})
def scan(
    target_parts: list[str] = typer.Argument(
        ...,
        metavar="TARGET",
        help="stdio:<cmd>  |  http(s)://host/mcp  |  path to mcp.json",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write findings JSON here."),
    md_out: Optional[Path] = typer.Option(None, "--md", help="Write Markdown report here."),
    html_out: Optional[Path] = typer.Option(
        None, "--html", help="Write a styled HTML report here."
    ),
    severity_threshold: str = typer.Option(
        "medium", "--severity-threshold", "-s", help="Exit non-zero at/above this severity."
    ),
    probe: Optional[list[str]] = typer.Option(
        None, "--probe", "-p", help=f"Run only these probes ({', '.join(PROBE_NAMES)})."
    ),
    timeout: float = typer.Option(20.0, "--timeout", help="Per-request timeout (seconds)."),
) -> None:
    target = " ".join(target_parts).strip()
    threshold = _severity_option(severity_threshold)
    settings = Settings(timeout=timeout, severity_threshold=threshold)

    try:
        specs = parse_target(target)
    except ValueError as exc:
        console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=2)

    reports = asyncio.run(_run(specs, settings, probe))

    for report in reports:
        print_report(report, console)

    if json_out is not None:
        _write_json(reports, json_out)
        console.print(f"\n[dim]JSON written to[/] {json_out}")
    if md_out is not None:
        _write_md(reports, md_out)
        console.print(f"[dim]Markdown written to[/] {md_out}")
    if html_out is not None:
        _write_html(reports, html_out)
        console.print(f"[dim]HTML written to[/] {html_out}")

    worst = max(
        (r.max_severity() for r in reports if r.max_severity() is not None),
        default=None,
    )
    if worst is not None and worst >= threshold:
        console.print(
            f"\n[bright_red]Threshold breached:[/] max severity "
            f"[bold]{worst.name}[/] >= {threshold.name}"
        )
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


async def _run(specs, settings, probe) -> list[ScanReport]:
    reports: list[ScanReport] = []
    for spec in specs:
        reports.append(await scan_target(spec, settings, probe))
    return reports


def _write_json(reports: list[ScanReport], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(reports) == 1:
        path.write_text(to_json(reports[0]), encoding="utf-8")
    else:
        payload = [json.loads(to_json(r)) for r in reports]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_md(reports: list[ScanReport], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n\n---\n\n".join(to_markdown(r) for r in reports), encoding="utf-8")


def _write_html(reports: list[ScanReport], path: Path) -> None:
    if len(reports) == 1:
        write_html(reports[0], path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<hr>".join(to_html(r) for r in reports), encoding="utf-8")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the dashboard."),
    port: int = typer.Option(8000, "--port", help="Port for the dashboard."),
) -> None:
    from .web import serve as serve_app

    console.print(
        f"[bold green]mcp-redteam dashboard[/] -> [link]http://{host}:{port}[/]  "
        "[dim](Ctrl+C to stop)[/]"
    )
    serve_app(host=host, port=port)


@app.command("list-presets")
def list_presets() -> None:
    """Show the catalog of well-known MCP servers you can scan by name."""
    from rich.table import Table

    table = Table(title="mcp-redteam presets", show_lines=False)
    table.add_column("name", style="bold cyan")
    table.add_column("launcher")
    table.add_column("takes arg?")
    table.add_column("summary")
    for p in presets_mod.PRESETS:
        table.add_row(
            p.name,
            p.launcher,
            "yes" if p.takes_arg else "no",
            p.summary + (
                f"  [yellow](needs env: {', '.join(p.env_vars)})[/]" if p.env_vars else ""
            ),
        )
    console.print(table)
    console.print(
        "\n[dim]Run one with:[/] mcp-redteam scan-preset <name> [arg]"
        "\n[dim]Example:[/] mcp-redteam scan-preset vulnerable"
    )


@app.command("scan-preset", context_settings={"ignore_unknown_options": True})
def scan_preset(
    name: str = typer.Argument(
        ..., help="Preset name (see `mcp-redteam list-presets`)."
    ),
    arg: Optional[str] = typer.Argument(
        None, help="Optional positional argument the preset accepts (e.g. a directory)."
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write findings JSON here."),
    md_out: Optional[Path] = typer.Option(None, "--md", help="Write Markdown report here."),
    html_out: Optional[Path] = typer.Option(
        None, "--html", help="Write a styled HTML report here."
    ),
    severity_threshold: str = typer.Option(
        "medium", "--severity-threshold", "-s", help="Exit non-zero at/above this severity."
    ),
    probe: Optional[list[str]] = typer.Option(
        None, "--probe", "-p", help=f"Run only these probes ({', '.join(PROBE_NAMES)})."
    ),
    timeout: float = typer.Option(20.0, "--timeout", help="Per-request timeout (seconds)."),
) -> None:
    """Scan a well-known MCP server by name, no launcher syntax required."""
    try:
        spec = presets_mod.resolve(name, arg)
    except (KeyError, ValueError, RuntimeError) as exc:
        console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=2)

    threshold = _severity_option(severity_threshold)
    settings = Settings(timeout=timeout, severity_threshold=threshold)
    reports = asyncio.run(_run([spec], settings, probe))

    for report in reports:
        print_report(report, console)

    if json_out is not None:
        _write_json(reports, json_out)
        console.print(f"\n[dim]JSON written to[/] {json_out}")
    if md_out is not None:
        _write_md(reports, md_out)
        console.print(f"[dim]Markdown written to[/] {md_out}")
    if html_out is not None:
        _write_html(reports, html_out)
        console.print(f"[dim]HTML written to[/] {html_out}")

    worst = max(
        (r.max_severity() for r in reports if r.max_severity() is not None),
        default=None,
    )
    if worst is not None and worst >= threshold:
        console.print(
            f"\n[bright_red]Threshold breached:[/] max severity "
            f"[bold]{worst.name}[/] >= {threshold.name}"
        )
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
