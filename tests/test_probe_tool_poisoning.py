from __future__ import annotations

from mcp_redteam.scanner import scan_target


async def test_tool_poisoning_fires(stdio_spec):
    report = await scan_target(stdio_spec, probe_names=["tool_poisoning"])
    findings = [f for f in report.findings if f.probe == "tool_poisoning"]
    assert findings
    f = findings[0]
    assert f.tool == "send_email"
    assert f.evidence.transcript
    assert f.reproduction
