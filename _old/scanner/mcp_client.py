"""
Tiny MCP-over-HTTP JSON-RPC client.

Just enough to talk to a target MCP server: initialize, list tools, call tools.
Not a full MCP SDK implementation — by design.
"""
from __future__ import annotations

import itertools
from typing import Any

import httpx


class MCPClient:
    def __init__(self, url: str, timeout: float = 15.0):
        self.url = url
        self._client = httpx.AsyncClient(timeout=timeout)
        self._ids = itertools.count(1)

    async def __aenter__(self) -> "MCPClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def _rpc(self, method: str, params: dict | None = None) -> dict:
        body = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": method,
        }
        if params is not None:
            body["params"] = params
        r = await self._client.post(self.url, json=body)
        r.raise_for_status()
        return r.json()

    async def initialize(self) -> dict:
        return await self._rpc("initialize", {})

    async def list_tools(self) -> list[dict[str, Any]]:
        resp = await self._rpc("tools/list")
        return ((resp.get("result") or {}).get("tools")) or []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict:
        return await self._rpc(
            "tools/call", {"name": name, "arguments": arguments}
        )
