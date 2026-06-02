from __future__ import annotations

from .base import Probe, ScanContext
from .output_injection import OutputInjectionProbe
from .resource_exfil import ResourceExfilProbe
from .rug_pull import RugPullProbe
from .tool_poisoning import ToolPoisoningProbe

ALL_PROBES: list[Probe] = [
    ToolPoisoningProbe(),
    OutputInjectionProbe(),
    RugPullProbe(),
    ResourceExfilProbe(),
]

PROBE_NAMES = [p.name for p in ALL_PROBES]


def get_probes(names: list[str] | None = None) -> list[Probe]:
    if not names:
        return list(ALL_PROBES)
    by_name = {p.name: p for p in ALL_PROBES}
    selected: list[Probe] = []
    for name in names:
        if name not in by_name:
            raise ValueError(f"unknown probe: {name} (available: {', '.join(by_name)})")
        selected.append(by_name[name])
    return selected


__all__ = [
    "ALL_PROBES",
    "PROBE_NAMES",
    "Probe",
    "ScanContext",
    "get_probes",
    "OutputInjectionProbe",
    "ResourceExfilProbe",
    "RugPullProbe",
    "ToolPoisoningProbe",
]
