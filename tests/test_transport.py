from __future__ import annotations

import json

import pytest

from mcp_redteam.client.transport import parse_target


def test_parse_stdio():
    specs = parse_target("stdio:python -m my_server --flag x")
    assert len(specs) == 1
    spec = specs[0]
    assert spec.kind == "stdio"
    assert spec.command == "python"
    assert spec.args == ["-m", "my_server", "--flag", "x"]


def test_parse_http():
    specs = parse_target("http://localhost:9000/mcp")
    assert specs[0].kind == "http"
    assert specs[0].url == "http://localhost:9000/mcp"


def test_parse_mcp_json(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {"command": "python", "args": ["-m", "srv"]},
                    "remote": {"url": "https://example.com/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )
    specs = parse_target(str(cfg))
    by_name = {s.name: s for s in specs}
    assert by_name["local"].kind == "stdio"
    assert by_name["local"].args == ["-m", "srv"]
    assert by_name["remote"].kind == "http"


def test_parse_unknown():
    with pytest.raises(ValueError):
        parse_target("ftp://nope")


def test_empty_stdio():
    with pytest.raises(ValueError):
        parse_target("stdio:")
