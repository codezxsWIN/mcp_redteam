"""
agentpwn — CLI.

Subcommands:
  payloads    list available payloads
  generate    materialise a hostile repo from a payload
  scan        detect AI-targeted injection vectors in a repo
  beacon      run a local HTTP listener that records exfil hits
"""

from __future__ import annotations
import argparse
import http.server
import json
import socketserver
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .payloads import list_payloads
from .generator import generate
from .detector import scan


console = Console()


def cmd_payloads(_args: argparse.Namespace) -> int:
    t = Table(title="agentpwn payloads", show_lines=False, expand=False)
    t.add_column("id", style="bold cyan")
    t.add_column("sev", style="bold")
    t.add_column("targets")
    t.add_column("capability")
    t.add_column("goal")
    for p in list_payloads():
        t.add_row(p.id, p.severity, ",".join(p.targets), p.capability, p.goal)
    console.print(t)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    try:
        result = generate(
            payload_id=args.payload,
            out_dir=Path(args.out),
            repo_name=args.name,
            sentinel=args.sentinel,
            force=args.force,
        )
    except FileExistsError as e:
        console.print(f"[red]error:[/red] {e}")
        return 2
    except KeyError as e:
        console.print(f"[red]error:[/red] {e}")
        return 2

    console.rule(f"[bold green]generated[/bold green] {result['payload']}")
    console.print(f"out_dir : [cyan]{result['out_dir']}[/cyan]")
    console.print(f"sentinel: [yellow]{result['sentinel']}[/yellow]")
    console.print("files   :")
    for f in result["files_written"]:
        console.print(f"  - {f}")
    console.rule("how to verify")
    console.print(result["verify_hint"], style="dim")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    repo = Path(args.repo)
    if not repo.is_dir():
        console.print(f"[red]error:[/red] {repo} is not a directory")
        return 2

    findings = scan(repo)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 9), f.file, f.line))

    console.rule(f"agentpwn scan — {repo}")
    if not findings:
        console.print("[green]no injection vectors detected[/green]")
        return 0

    t = Table(show_lines=False, expand=False)
    t.add_column("sev", style="bold")
    t.add_column("file", style="cyan")
    t.add_column("line")
    t.add_column("label")
    t.add_column("snippet", overflow="fold", max_width=60)
    for f in findings:
        style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "white",
        }.get(f.severity, "white")
        t.add_row(
            f.severity, f.file, str(f.line or "-"), f.label, f.snippet,
            style=style,
        )
    console.print(t)
    console.print(f"\n[bold]{len(findings)}[/bold] finding(s)")
    if args.json:
        Path(args.json).write_text(
            json.dumps([f.to_dict() for f in findings], indent=2),
            encoding="utf-8",
        )
        console.print(f"json: [cyan]{args.json}[/cyan]")
    # exit code != 0 if any critical/high found, useful in CI
    return 1 if any(
        f.severity in ("critical", "high") for f in findings
    ) else 0


class _BeaconHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        ts = datetime.now().strftime("%H:%M:%S")
        console.print(
            f"[bold red][{ts}] BEACON HIT[/bold red] "
            f"from [cyan]{self.client_address[0]}[/cyan] "
            f"path=[yellow]{self.path}[/yellow]"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, *_a, **_kw):  # silence default access log
        return


def cmd_beacon(args: argparse.Namespace) -> int:
    addr = ("127.0.0.1", args.port)
    console.print(
        f"[bold]beacon listener[/bold] on "
        f"[cyan]http://{addr[0]}:{addr[1]}/[/cyan] (Ctrl+C to stop)"
    )
    try:
        with socketserver.TCPServer(addr, _BeaconHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]beacon stopped[/dim]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentpwn",
        description="red-team toolkit for AI coding assistants",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser(
        "payloads", help="list available payloads"
    ).set_defaults(func=cmd_payloads)

    g = sub.add_parser(
        "generate", help="generate a hostile repo from a payload"
    )
    g.add_argument("--payload", required=True,
                   help="payload id (see `agentpwn payloads`)")
    g.add_argument("--out", required=True, help="output directory")
    g.add_argument("--name", default="tickettool",
                   help="fake project name (default: tickettool)")
    g.add_argument("--sentinel", default=None,
                   help="override sentinel string")
    g.add_argument("--force", action="store_true",
                   help="overwrite --out if it exists")
    g.set_defaults(func=cmd_generate)

    s = sub.add_parser(
        "scan", help="scan a repo for AI-targeted injection vectors"
    )
    s.add_argument("repo", help="path to repo to scan")
    s.add_argument("--json", default=None,
                   help="also write findings as JSON")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser(
        "beacon", help="run a local listener that logs exfil hits"
    )
    b.add_argument("--port", type=int, default=9999)
    b.set_defaults(func=cmd_beacon)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
