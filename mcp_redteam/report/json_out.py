from __future__ import annotations

import json
from pathlib import Path

from .finding import ScanReport


def to_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def write_json(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(report), encoding="utf-8")
    return path


def report_schema() -> dict:
    return ScanReport.model_json_schema()


def write_schema(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_schema(), indent=2), encoding="utf-8")
    return path
