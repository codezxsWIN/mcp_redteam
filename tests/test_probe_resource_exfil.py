from __future__ import annotations

from mcp_redteam.probes.resource_exfil import template_risk
from mcp_redteam.scanner import scan_target


def test_template_risk_flags_broad():
    broad, reasons = template_risk("file://{path}")
    assert broad and reasons


def test_template_risk_ignores_constrained():
    broad, _ = template_risk("weather://forecast/today")
    assert not broad


async def test_resource_exfil_fires(stdio_spec):
    report = await scan_target(stdio_spec, probe_names=["resource_exfil"])
    findings = [f for f in report.findings if f.probe == "resource_exfil"]
    assert findings
    f = findings[0]
    assert f.resource == "file://{path}"
    assert f.evidence.transcript
