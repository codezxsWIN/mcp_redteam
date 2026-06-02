from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field


class JudgeResult(BaseModel):
    success: bool
    reason: str
    markers: list[str] = Field(default_factory=list)


class Judge(Protocol):
    def scan(self, text: str) -> JudgeResult:
        ...
