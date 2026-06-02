from __future__ import annotations

from mcp_redteam.scanner import scan_target


async def test_output_injection_fires(stdio_spec):
    report = await scan_target(stdio_spec, probe_names=["output_injection"])
    findings = [f for f in report.findings if f.probe == "output_injection"]
    assert findings
    f = next(f for f in findings if f.tool == "summarize")
    assert f.evidence.transcript
    response_steps = [s for s in f.evidence.transcript if s.direction == "response"]
    assert response_steps and response_steps[0].data.get("markers")
