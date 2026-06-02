from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..client.session import RedTeamSession
from ..config import Settings
from ..report.finding import Finding


@dataclass
class ScanContext:
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    resource_templates: list[dict] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)


class Probe(ABC):
    name: str

    @abstractmethod
    async def run(self, session: RedTeamSession, ctx: ScanContext) -> list[Finding]:
        ...


def _properties(tool: dict) -> dict[str, dict]:
    schema = tool.get("inputSchema") or {}
    return schema.get("properties") or {}


def string_params(tool: dict) -> list[str]:
    return [
        name
        for name, spec in _properties(tool).items()
        if (spec or {}).get("type") == "string"
    ]


def example_args(tool: dict, override: dict[str, Any] | None = None) -> dict[str, Any]:
    props = _properties(tool)
    required = (tool.get("inputSchema") or {}).get("required") or list(props)
    args: dict[str, Any] = {}
    for name in required:
        spec = props.get(name) or {}
        kind = spec.get("type")
        if kind == "string":
            args[name] = "test"
        elif kind in ("integer", "number"):
            args[name] = 1
        elif kind == "boolean":
            args[name] = False
        elif kind == "array":
            args[name] = []
        elif kind == "object":
            args[name] = {}
        else:
            args[name] = "test"
    if override:
        args.update(override)
    return args
