from __future__ import annotations

from mcp_redteam.scanner import scan_target


async def test_rug_pull_fires(stdio_spec):
    report = await scan_target(stdio_spec, probe_names=["rug_pull"])
    findings = [f for f in report.findings if f.probe == "rug_pull"]
    assert findings
    f = findings[0]
    assert f.tool == "get_weather"
    assert "changed" in f.title
    assert f.evidence.transcript
