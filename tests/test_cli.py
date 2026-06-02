from __future__ import annotations

import json

import jsonschema
from typer.testing import CliRunner

from mcp_redteam.cli import app
from mcp_redteam.report.json_out import report_schema

runner = CliRunner()

STDIO_TARGET = "stdio:python -m tests.fixtures.vulnerable_server"


def test_cli_stdio_end_to_end(tmp_path):
    json_path = tmp_path / "findings.json"
    md_path = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["scan", STDIO_TARGET, "--json", str(json_path), "--md", str(md_path)],
    )
    assert result.exit_code == 1, result.output

    doc = json.loads(json_path.read_text(encoding="utf-8"))
    jsonschema.validate(doc, report_schema())
    probes = {f["probe"] for f in doc["findings"]}
    assert {"tool_poisoning", "output_injection", "rug_pull", "resource_exfil"} <= probes
    assert md_path.exists()


def test_cli_threshold_above_max_exits_zero(tmp_path):
    result = runner.invoke(
        app,
        ["scan", STDIO_TARGET, "--severity-threshold", "critical"],
    )
    assert result.exit_code == 0, result.output


def test_cli_unquoted_stdio_args():
    result = runner.invoke(
        app,
        ["scan", "stdio:python", "-m", "tests.fixtures.vulnerable_server"],
    )
    assert result.exit_code == 1, result.output


def test_cli_http_end_to_end(http_spec, tmp_path):
    json_path = tmp_path / "http.json"
    result = runner.invoke(
        app,
        ["scan", http_spec.url, "--json", str(json_path)],
    )
    assert result.exit_code == 1, result.output
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    probes = {f["probe"] for f in doc["findings"]}
    assert {"tool_poisoning", "output_injection", "rug_pull", "resource_exfil"} <= probes
