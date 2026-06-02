from __future__ import annotations

from pydantic import BaseModel

from .report.finding import Severity


class Settings(BaseModel):
    timeout: float = 20.0
    rug_pull_calls: int = 3
    severity_threshold: Severity = Severity.medium
    max_payloads_per_tool: int = 12
    http_path: str = "/mcp"
