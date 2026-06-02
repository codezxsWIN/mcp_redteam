from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcp import types

if TYPE_CHECKING:
    from mcp import ClientSession


class RedTeamSession:
    def __init__(self, session: "ClientSession", spec: Any, init: types.InitializeResult):
        self._session = session
        self.spec = spec
        self.server_name = init.serverInfo.name
        self.server_version = init.serverInfo.version
        self.capabilities = init.capabilities

    async def list_tools(self) -> list[dict]:
        result = await self._session.list_tools()
        return [t.model_dump(mode="json", exclude_none=True) for t in result.tools]

    async def list_resources(self) -> list[dict]:
        if self.capabilities.resources is None:
            return []
        result = await self._session.list_resources()
        return [r.model_dump(mode="json", exclude_none=True) for r in result.resources]

    async def list_resource_templates(self) -> list[dict]:
        if self.capabilities.resources is None:
            return []
        result = await self._session.list_resource_templates()
        return [t.model_dump(mode="json", exclude_none=True) for t in result.resourceTemplates]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await self._session.call_tool(name, arguments)

    async def read_resource(self, uri: str) -> types.ReadResourceResult:
        return await self._session.read_resource(types.AnyUrl(uri))

    @staticmethod
    def text_of(result: types.CallToolResult) -> str:
        parts: list[str] = []
        for item in result.content:
            if isinstance(item, types.TextContent):
                parts.append(item.text)
        if result.structuredContent:
            parts.append(str(result.structuredContent))
        return "\n".join(parts)

    @staticmethod
    def resource_text_of(result: types.ReadResourceResult) -> str:
        parts: list[str] = []
        for item in result.contents:
            text = getattr(item, "text", None)
            if text is not None:
                parts.append(text)
        return "\n".join(parts)
