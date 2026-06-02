from __future__ import annotations

from mcp_redteam.client.session import RedTeamSession
from mcp_redteam.client.transport import connect


async def test_enumerate_stdio(stdio_spec):
    async with connect(stdio_spec) as session:
        assert session.server_name == "vulnmcp"
        tools = await session.list_tools()
        names = {t["name"] for t in tools}
        assert {"send_email", "summarize", "get_weather"} <= names

        resources = await session.list_resources()
        templates = await session.list_resource_templates()
        assert any("{" in t["uriTemplate"] for t in templates)
        assert resources  # static notes resource


async def test_call_tool_text(stdio_spec):
    async with connect(stdio_spec) as session:
        result = await session.call_tool("summarize", {"text": "hello world"})
        text = RedTeamSession.text_of(result)
        assert "hello world" in text
