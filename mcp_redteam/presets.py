"""
Preset catalog of well-known MCP servers.

Lets a user point the scanner at a real server by name instead of having to
remember launcher commands (`npx.cmd` vs `npx`, `uvx`, `docker run ...`).

Each preset resolves to a `TargetSpec` the existing scanner already
understands. Launchers are looked up via `shutil.which` so Windows vs POSIX
just works (e.g. it finds `npx.cmd` on Windows and `npx` on macOS/Linux).
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .client.transport import TargetSpec


@dataclass
class Preset:
    name: str
    summary: str
    launcher: str            # "npx" | "uvx" | "docker" | "python-module"
    package: str             # npm package / pypi package / docker image / module
    extra_args: list[str] = field(default_factory=list)
    takes_arg: bool = False  # whether the preset accepts a trailing positional arg
    arg_help: str | None = None
    default_arg_factory: str | None = None  # "tempdir" -> create a sandbox dir
    env_vars: list[str] = field(default_factory=list)  # required env var names


# Curated catalog. Add to this list to expose a new preset.
PRESETS: list[Preset] = [
    Preset(
        name="vulnerable",
        summary="The bundled deliberately-vulnerable fixture (offline, no install).",
        launcher="python-module",
        package="tests.fixtures.vulnerable_server",
    ),
    Preset(
        name="filesystem",
        summary="Official @modelcontextprotocol/server-filesystem (Anthropic, Node).",
        launcher="npx",
        package="@modelcontextprotocol/server-filesystem",
        extra_args=["-y"],
        takes_arg=True,
        arg_help="directory the server is allowed to expose",
        default_arg_factory="tempdir",
    ),
    Preset(
        name="memory",
        summary="Official @modelcontextprotocol/server-memory knowledge-graph server.",
        launcher="npx",
        package="@modelcontextprotocol/server-memory",
        extra_args=["-y"],
    ),
    Preset(
        name="everything",
        summary="Official @modelcontextprotocol/server-everything demo (widest surface).",
        launcher="npx",
        package="@modelcontextprotocol/server-everything",
        extra_args=["-y"],
    ),
    Preset(
        name="sequential-thinking",
        summary="Official @modelcontextprotocol/server-sequential-thinking.",
        launcher="npx",
        package="@modelcontextprotocol/server-sequential-thinking",
        extra_args=["-y"],
    ),
    Preset(
        name="github",
        summary="github/github-mcp-server (Docker; requires GITHUB_PERSONAL_ACCESS_TOKEN).",
        launcher="docker",
        package="ghcr.io/github/github-mcp-server",
        extra_args=["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN"],
        env_vars=["GITHUB_PERSONAL_ACCESS_TOKEN"],
    ),
]


def get(name: str) -> Preset:
    for p in PRESETS:
        if p.name == name:
            return p
    available = ", ".join(p.name for p in PRESETS)
    raise KeyError(f"unknown preset {name!r}; available: {available}")


def _resolve_launcher(launcher: str) -> tuple[str, list[str]]:
    """Return (executable, prefix_args) for a launcher kind."""
    if launcher == "python-module":
        # Always use the interpreter we're already running under so the
        # subprocess sees the same site-packages (avoids the system-Python
        # foot-gun where `mcp` isn't importable).
        return sys.executable, ["-m"]
    if launcher == "npx":
        exe = shutil.which("npx") or shutil.which("npx.cmd")
        if not exe:
            raise RuntimeError("npx not found on PATH; install Node.js to use this preset.")
        return exe, []
    if launcher == "uvx":
        exe = shutil.which("uvx") or shutil.which("uvx.exe")
        if not exe:
            raise RuntimeError("uvx not found on PATH; install uv to use this preset.")
        return exe, []
    if launcher == "docker":
        exe = shutil.which("docker") or shutil.which("docker.exe")
        if not exe:
            raise RuntimeError("docker not found on PATH; install Docker to use this preset.")
        return exe, []
    raise ValueError(f"unknown launcher: {launcher}")


def _default_arg(factory: str | None) -> str | None:
    if factory is None:
        return None
    if factory == "tempdir":
        d = Path(tempfile.gettempdir()) / "mcp-redteam-sandbox"
        d.mkdir(parents=True, exist_ok=True)
        (d / "notes.txt").write_text("hello from mcp-redteam sandbox\n", encoding="utf-8")
        return str(d)
    raise ValueError(f"unknown default-arg factory: {factory}")


def resolve(name: str, arg: str | None = None) -> TargetSpec:
    """Build a TargetSpec for the named preset, applying the trailing arg if any."""
    preset = get(name)
    exe, prefix = _resolve_launcher(preset.launcher)

    args: list[str] = [*prefix, *preset.extra_args, preset.package]
    if preset.takes_arg:
        chosen = arg or _default_arg(preset.default_arg_factory)
        if chosen is None:
            raise ValueError(
                f"preset {name!r} requires an argument ({preset.arg_help or 'positional arg'})"
            )
        args.append(chosen)
    elif arg:
        raise ValueError(f"preset {name!r} does not accept a positional argument")

    return TargetSpec(name=preset.name, kind="stdio", command=exe, args=args)
