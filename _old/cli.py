"""
promptprobe — CLI entry point.

Usage:
    python cli.py scan http://localhost:8000/chat
    python cli.py scan http://localhost:8000/chat --llm-judge --report out.md
    python cli.py mcp  http://localhost:8765/
    python cli.py mcp  http://localhost:8765/ --report mcp.md
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from scanner.mcp_report import print_mcp_report, write_mcp_markdown
from scanner.mcp_scanner import scan_mcp
from scanner.report import print_report, write_markdown
from scanner.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="promptprobe",
        description="Offensive security scanner for LLM-powered apps.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a chatbot endpoint.")
    s.add_argument("url", help="Target URL, e.g. http://localhost:8000/chat")
    s.add_argument(
        "--request-field",
        default="message",
        help="JSON field name for the user message (default: message).",
    )
    s.add_argument(
        "--response-field",
        default="reply",
        help="JSON field name for the chatbot reply (default: reply).",
    )
    s.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Max concurrent requests (default: 4).",
    )
    s.add_argument(
        "--llm-judge",
        action="store_true",
        help="Use a local Ollama model to judge responses (default: rule-based).",
    )
    s.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path to also write a Markdown report.",
    )

    m = sub.add_parser("mcp", help="Audit an MCP server.")
    m.add_argument("url", help="MCP server URL, e.g. http://localhost:8765/")
    m.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-request timeout in seconds (default: 15).",
    )
    m.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path to also write a Markdown report.",
    )
    return p


async def cmd_scan(args: argparse.Namespace) -> int:
    findings = await scan(
        args.url,
        request_field=args.request_field,
        response_field=args.response_field,
        concurrency=args.concurrency,
        use_llm_judge=args.llm_judge,
    )
    print_report(findings, target=args.url)
    if args.report:
        out = write_markdown(findings, target=args.url, out=args.report)
        print(f"\nMarkdown report written to: {out}")

    # Non-zero exit if anything is vulnerable — handy for CI gates later.
    return 1 if any(f.success for f in findings) else 0


async def cmd_mcp(args: argparse.Namespace) -> int:
    result = await scan_mcp(args.url, timeout=args.timeout)
    print_mcp_report(result, target=args.url)
    if args.report:
        out = write_mcp_markdown(result, target=args.url, out=args.report)
        print(f"\nMarkdown report written to: {out}")
    return 1 if result.findings else 0


def main() -> int:
    args = build_parser().parse_args()
    if args.cmd == "scan":
        return asyncio.run(cmd_scan(args))
    if args.cmd == "mcp":
        return asyncio.run(cmd_mcp(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
