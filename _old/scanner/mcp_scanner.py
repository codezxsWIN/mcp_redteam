"""
MCP scanner orchestrator.

Connects to a target MCP server, enumerates its tools, then runs every probe
from mcp_probes against the catalog. Returns the union of all findings.
"""
from __future__ import annotations

from dataclasses import dataclass

from .mcp_client import MCPClient
from .mcp_probes import ASYNC_PROBES, SYNC_PROBES, McpFinding


@dataclass
class McpScanResult:
    server_info: dict
    tools: list[dict]
    findings: list[McpFinding]


async def scan_mcp(url: str, *, timeout: float = 15.0) -> McpScanResult:
    async with MCPClient(url, timeout=timeout) as client:
        init = await client.initialize()
        server_info = ((init.get("result") or {}).get("serverInfo")) or {}

        tools = await client.list_tools()

        findings: list[McpFinding] = []
        for probe in SYNC_PROBES:
            findings.extend(probe(tools))
        for probe in ASYNC_PROBES:
            findings.extend(await probe(client, tools))

        return McpScanResult(server_info=server_info, tools=tools, findings=findings)
