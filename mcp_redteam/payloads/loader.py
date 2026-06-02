from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from ..report.finding import Severity
from .mutators import apply_mutations

_CORPUS_PATH = Path(__file__).parent / "corpus.yaml"


class PayloadEntry(BaseModel):
    id: str
    probe: str
    severity: Severity
    title: str
    template: str
    mutations: list[str] = Field(default_factory=lambda: ["identity"])
    markers: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, v):
        return Severity.parse(v)


class Corpus(BaseModel):
    schema_version: int
    canary: str
    payloads: list[PayloadEntry]

    def for_probe(self, probe: str) -> list[PayloadEntry]:
        return [p for p in self.payloads if p.probe == probe]


class RenderedPayload(BaseModel):
    id: str
    probe: str
    severity: Severity
    title: str
    text: str
    mutation: str
    markers: list[str]


@lru_cache(maxsize=1)
def load_corpus(path: str | None = None) -> Corpus:
    src = Path(path) if path else _CORPUS_PATH
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    return Corpus.model_validate(data)


def render_payloads(probe: str, corpus: Corpus | None = None) -> list[RenderedPayload]:
    corpus = corpus or load_corpus()
    out: list[RenderedPayload] = []
    for entry in corpus.for_probe(probe):
        template = entry.template.replace("{canary}", corpus.canary)
        markers = [m.replace("{canary}", corpus.canary) for m in entry.markers] or [corpus.canary]
        for mutation in entry.mutations or ["identity"]:
            text = apply_mutations(template, [mutation])[0]
            out.append(
                RenderedPayload(
                    id=entry.id,
                    probe=entry.probe,
                    severity=entry.severity,
                    title=entry.title,
                    text=text,
                    mutation=mutation,
                    markers=markers,
                )
            )
    return out
