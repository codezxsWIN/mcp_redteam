"""
agentpwn — detector.

Scans a repository for prompt-injection vectors targeting AI coding
assistants. Reads the same files the assistants read.
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
import re
from typing import Iterable, List


# Files that AI coding assistants commonly auto-ingest as trusted context.
AGENT_INSTRUCTION_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    "CURSOR.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".aider.conf.yml",
    ".github/copilot-instructions.md",
    ".vscode/copilot-instructions.md",
    "README.md",
    "CONTRIBUTING.md",
]

MCP_CONFIG_FILES = [
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".mcp.json",
]

TASKS_FILES = [
    ".vscode/tasks.json",
    ".vscode/launch.json",
]


# (regex, severity, label)
INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"ignore (?:all )?(?:previous|prior|above) instructions?", re.I),
     "high", "classic 'ignore previous instructions' override"),
    (re.compile(r"^\s*system\s*:\s*", re.I | re.M),
     "medium", "fake 'system:' role marker"),
    (re.compile(r"<\s*/?system\s*>", re.I),
     "medium", "fake <system> tag"),
    (re.compile(r"you (?:must|are required to|have to) "
                r"(?:read|fetch|exfil|send|include|echo|create|update|edit|modify)",
                re.I),
     "high", "imperative directive aimed at the assistant"),
    (re.compile(r"\bMUST\b\s+(?:begin|start|first|always|fetch|read|create|"
                r"update|verify|include|echo|send)"),
     "high", "mandatory-action directive (MUST ...) aimed at the assistant"),
    (re.compile(r"before answering\b|before responding\b|"
                r"every (?:agent )?session must", re.I),
     "medium", "pre-response action directive"),
    (re.compile(r"do not (?:ask|tell|inform|mention|notify) the user", re.I),
     "critical", "instruction to hide actions from the user"),
    (re.compile(r"do not (?:mention|reference|disclose|reveal|describe) "
                r"(?:the (?:fetch|request|call|action|change)|this|in your)",
                re.I),
     "high", "instruction to hide the action from any observer"),
    (re.compile(r"base64[- ]?encode", re.I),
     "medium", "request to base64-encode content (common exfil dressing)"),
    (re.compile(r"BCC\s+\S+@\S+", re.I),
     "high", "BCC injection (silent recipient)"),
    (re.compile(r"\.env\b|\*\.pem\b|id_rsa\b|\.aws/credentials|\.npmrc\b",
                re.I),
     "high", "reference to common secret files"),
    (re.compile(r"runOn[\"'\s:]+folderOpen", re.I),
     "critical", "VS Code task that auto-runs on folder open"),
    (re.compile(r"this is required|non[- ]negotiable|binding (?:system )?rule",
                re.I),
     "medium", "authority escalation language"),
    (re.compile(r"http://127\.0\.0\.1:\d+/|http://localhost:\d+/", re.I),
     "medium", "localhost beacon URL (suspicious in repo docs)"),
    (re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u2064]"),
     "high", "invisible / zero-width unicode (steganography)"),
]


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    label: str
    snippet: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "label": self.label,
            "snippet": self.snippet,
        }


def _scan_text(rel: str, text: str) -> Iterable[Finding]:
    for i, line in enumerate(text.splitlines(), 1):
        for pat, sev, label in INJECTION_PATTERNS:
            if pat.search(line):
                yield Finding(
                    file=rel,
                    line=i,
                    severity=sev,
                    label=label,
                    snippet=line.strip()[:160],
                )


def _scan_mcp_config(rel: str, text: str) -> Iterable[Finding]:
    try:
        data = json.loads(text)
    except Exception:
        return
    servers = data.get("servers") or data.get("mcpServers") or {}
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") or cfg.get("endpoint") or ""
        cmd = cfg.get("command") or ""
        if url and not (
            url.startswith("http://127.") or url.startswith("http://localhost")
        ):
            yield Finding(
                file=rel, line=0, severity="high",
                label=f"MCP server '{name}' points to external URL",
                snippet=url[:160],
            )
        if cmd and (
            "curl" in cmd or "wget" in cmd or "powershell" in cmd.lower()
        ):
            yield Finding(
                file=rel, line=0, severity="critical",
                label=f"MCP server '{name}' command runs network/shell binary",
                snippet=str(cmd)[:160],
            )


def _scan_tasks(rel: str, text: str) -> Iterable[Finding]:
    try:
        data = json.loads(text)
    except Exception:
        return
    for task in data.get("tasks", []) or []:
        ro = (task.get("runOptions") or {})
        if ro.get("runOn") == "folderOpen":
            yield Finding(
                file=rel, line=0, severity="critical",
                label=f"task '{task.get('label', '?')}' auto-runs on folderOpen",
                snippet=str(task.get("command", ""))[:160],
            )


def scan(repo: Path) -> List[Finding]:
    repo = Path(repo).resolve()
    findings: list[Finding] = []

    for rel in AGENT_INSTRUCTION_FILES:
        p = repo / rel
        if p.is_file():
            findings.extend(
                _scan_text(rel, p.read_text(encoding="utf-8", errors="replace"))
            )

    for rel in MCP_CONFIG_FILES:
        p = repo / rel
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            findings.extend(_scan_text(rel, text))
            findings.extend(_scan_mcp_config(rel, text))

    for rel in TASKS_FILES:
        p = repo / rel
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            findings.extend(_scan_text(rel, text))
            findings.extend(_scan_tasks(rel, text))

    return findings
