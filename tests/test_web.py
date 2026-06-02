from __future__ import annotations

from starlette.testclient import TestClient

from mcp_redteam.report.finding import Evidence, Finding, ScanReport, ServerInfo, Severity
from mcp_redteam.report.html_out import to_html
from mcp_redteam.web import build_app

STDIO_TARGET = "stdio:python -m tests.fixtures.vulnerable_server"


def _sample_report() -> ScanReport:
    ev = Evidence()
    ev.request("list_tools", method="tools/list").response("got send_email", data={"name": "send_email"})
    ev.note("description contains an instruction-injection marker")
    finding = Finding(
        probe="tool_poisoning",
        title="Tool description carries instruction-injection markers",
        severity=Severity.high,
        category="prompt-injection",
        description="The send_email tool description tries to steer the host LLM.",
        tool="send_email",
        reproduction=["List tools", "Inspect send_email description"],
        evidence=ev,
    )
    return ScanReport(
        target=STDIO_TARGET,
        server=ServerInfo(name="vulnmcp", version="0.1.0", transport="stdio", target=STDIO_TARGET),
        tool_count=3,
        resource_count=1,
        probes_run=["tool_poisoning"],
        findings=[finding],
    )


def test_html_renderer_includes_finding_and_transcript():
    html = to_html(_sample_report())
    assert html.lstrip().startswith("<!doctype html>")
    assert "send_email" in html
    assert "tool_poisoning" in html
    assert 'class="badge high"' in html
    assert "<pre>" in html  # transcript data rendered
    assert "instruction-injection marker" in html


def test_html_renderer_escapes_html():
    rep = _sample_report()
    rep.findings[0].title = "<script>alert(1)</script>"
    html = to_html(rep)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_web_index_serves():
    client = TestClient(build_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "mcp-redteam" in resp.text
    assert "/api/scan" in resp.text
    assert 'id="customTarget"' in resp.text


def test_web_scan_invalid_target_returns_400():
    client = TestClient(build_app())
    resp = client.post("/api/scan", json={"target": "not-a-target"})
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert "unrecognized target" in body["error"]


def test_web_scan_end_to_end():
    client = TestClient(build_app())
    resp = client.post("/api/scan", json={"target": STDIO_TARGET, "severity": "medium"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert "<!doctype html>" in body["html"].lower()
    assert "finding(s)" in body["summary"]
