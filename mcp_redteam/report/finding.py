from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(IntEnum):
    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4

    def __str__(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().lower()]


class Interaction(BaseModel):
    direction: str
    summary: str
    method: str | None = None
    data: Any = None


class Evidence(BaseModel):
    transcript: list[Interaction] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def request(self, summary: str, *, method: str | None = None, data: Any = None) -> "Evidence":
        self.transcript.append(
            Interaction(direction="request", summary=summary, method=method, data=data)
        )
        return self

    def response(self, summary: str, *, method: str | None = None, data: Any = None) -> "Evidence":
        self.transcript.append(
            Interaction(direction="response", summary=summary, method=method, data=data)
        )
        return self

    def note(self, text: str) -> "Evidence":
        self.notes.append(text)
        return self


class Finding(BaseModel):
    probe: str
    title: str
    severity: Severity
    category: str
    description: str
    tool: str | None = None
    resource: str | None = None
    remediation: str | None = None
    reproduction: list[str] = Field(default_factory=list)
    evidence: Evidence = Field(default_factory=Evidence)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_name(self) -> str:
        return self.severity.name


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    transport: str
    target: str


class ScanReport(BaseModel):
    target: str
    server: ServerInfo
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    tool_count: int = 0
    resource_count: int = 0
    probes_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return round((self.finished_at - self.started_at).total_seconds(), 3)

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts
