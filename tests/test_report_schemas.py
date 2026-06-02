from __future__ import annotations

import json

import jsonschema

from mcp_redteam.payloads.loader import load_corpus, render_payloads
from mcp_redteam.report.json_out import report_schema, to_json
from mcp_redteam.report.markdown import to_markdown
from mcp_redteam.scanner import scan_target


def test_corpus_loads_and_renders():
    corpus = load_corpus()
    assert corpus.schema_version == 1
    rendered = render_payloads("output_injection", corpus)
    assert rendered
    assert all(corpus.canary in p.markers for p in rendered)
    assert any(p.mutation == "base64" for p in rendered)


async def test_json_validates_against_schema(stdio_spec):
    report = await scan_target(stdio_spec)
    doc = json.loads(to_json(report))
    jsonschema.validate(doc, report_schema())
    assert doc["findings"]


async def test_markdown_renders(stdio_spec):
    report = await scan_target(stdio_spec)
    md = to_markdown(report)
    assert "# mcp-redteam report" in md
    assert "## Findings" in md
    assert "Transcript:" in md
    assert "Reproduction steps:" in md
