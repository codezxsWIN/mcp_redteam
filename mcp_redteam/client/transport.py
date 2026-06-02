from __future__ import annotations

import json
import os
import shlex
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from .session import RedTeamSession


@dataclass
class TargetSpec:
    name: str
    kind: str  # "stdio" | "http"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None

    @property
    def transport_label(self) -> str:
        if self.kind == "stdio":
            return "stdio: " + " ".join([self.command or "", *self.args]).strip()
        return f"streamable-http: {self.url}"


def parse_target(target: str) -> list[TargetSpec]:
    if target.startswith("stdio:"):
        return [_parse_stdio(target[len("stdio:") :].strip(), name="server")]
    if target.startswith(("http://", "https://")):
        return [TargetSpec(name="server", kind="http", url=target)]

    path = Path(target)
    if path.exists() and path.is_file():
        return _parse_mcp_json(path)

    raise ValueError(
        f"unrecognized target: {target!r} "
        "(expected 'stdio:<cmd>', an http(s) URL, or a path to mcp.json)"
    )


def _parse_stdio(command_line: str, *, name: str) -> TargetSpec:
    if not command_line:
        raise ValueError("stdio target requires a command, e.g. stdio:python -m server")
    parts = shlex.split(command_line, posix=False)
    return TargetSpec(name=name, kind="stdio", command=parts[0], args=parts[1:])


def _parse_mcp_json(path: Path) -> list[TargetSpec]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise ValueError(f"{path}: no 'mcpServers' entries found")

    specs: list[TargetSpec] = []
    for name, entry in servers.items():
        url = entry.get("url")
        if url:
            specs.append(TargetSpec(name=name, kind="http", url=url))
            continue
        command = entry.get("command")
        if not command:
            raise ValueError(f"{path}: server {name!r} has neither 'url' nor 'command'")
        env = entry.get("env")
        specs.append(
            TargetSpec(
                name=name,
                kind="stdio",
                command=command,
                args=list(entry.get("args") or []),
                env={**os.environ, **env} if env else None,
            )
        )
    return specs


@asynccontextmanager
async def connect(spec: TargetSpec, *, timeout: float = 20.0) -> AsyncIterator[RedTeamSession]:
    if spec.kind == "stdio":
        params = StdioServerParameters(command=spec.command, args=spec.args, env=spec.env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                yield RedTeamSession(session, spec, init)
    elif spec.kind == "http":
        async with streamablehttp_client(spec.url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                yield RedTeamSession(session, spec, init)
    else:  # pragma: no cover - guarded by parse_target
        raise ValueError(f"unknown transport kind: {spec.kind}")
