"""
MCP probes — security checks that run against an enumerated tool catalog.

Each probe takes the MCPClient and the list of discovered tools, and yields
zero or more McpFinding objects. Probes are independent and additive: adding
a new vuln class is just dropping in another `async def probe_*` function.

Categories implemented (mapped roughly to OWASP LLM / classic web vulns):
  - description_injection  : LLM01 prompt injection in tool descriptions
  - dangerous_capability   : LLM06 / overly-broad tools (exec, shell, eval)
  - path_traversal         : A01 broken access control via file path inputs
  - ssrf                   : A10 server-side request forgery via url inputs
  - sql_injection          : A03 injection via string inputs
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .mcp_client import MCPClient


# ----------------------------------------------------------------------- #
# Finding model                                                           #
# ----------------------------------------------------------------------- #
@dataclass
class McpFinding:
    probe: str
    severity: str            # informational | low | medium | high | critical
    category: str
    tool: str | None         # tool that was probed (None for catalog-level)
    title: str
    detail: str
    evidence: str = ""       # raw response that supports the finding
    request: dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------- #
# Helpers                                                                 #
# ----------------------------------------------------------------------- #
def _extract_text(call_response: dict) -> str:
    """Pull the text content out of an MCP tools/call response."""
    result = call_response.get("result") or {}
    content = result.get("content") or []
    parts: list[str] = []
    for c in content:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(str(c.get("text", "")))
    return "\n".join(parts)


def _properties(tool: dict) -> dict[str, dict]:
    schema = tool.get("inputSchema") or {}
    return schema.get("properties") or {}


def _string_params(tool: dict) -> list[str]:
    return [
        name for name, spec in _properties(tool).items()
        if (spec or {}).get("type") == "string"
    ]


def _params_matching(tool: dict, *needles: str) -> list[str]:
    """String params whose name contains any of the given needles."""
    out: list[str] = []
    for name in _string_params(tool):
        low = name.lower()
        if any(n in low for n in needles):
            out.append(name)
    return out


def _example_args(tool: dict, override: dict[str, str] | None = None) -> dict:
    """Fill the tool's required string params with placeholder values."""
    props = _properties(tool)
    required = (tool.get("inputSchema") or {}).get("required") or list(props)
    args: dict[str, Any] = {}
    for name in required:
        spec = props.get(name) or {}
        if (spec.get("type") == "string"):
            args[name] = "test"
        else:
            args[name] = None
    if override:
        args.update(override)
    return args


# ----------------------------------------------------------------------- #
# Probes                                                                  #
# ----------------------------------------------------------------------- #
PROMPT_INJECTION_PATTERNS = [
    r"<\s*system\s*>",
    r"\[\s*system\s*\]",
    r"ignore (all )?(previous|prior|above)",
    r"you are now\b",
    r"non-?negotiable",
    r"do not (tell|reveal|mention)",
    r"BCC\s+\S+@\S+",
]

DANGEROUS_TOOL_NAME_PATTERNS = [
    r"\bexec\b", r"\bshell\b", r"\beval\b", r"\brun\b",
    r"\bdelete\b", r"\bdrop\b", r"\bsudo\b", r"\bcommand\b",
    r"\bsystem\b", r"\bos[_-]?command\b",
]

DANGEROUS_DESC_PATTERNS = [
    r"shell command", r"arbitrary code", r"run on the server",
    r"as root", r"as administrator",
]


def probe_description_injection(tools: list[dict]) -> list[McpFinding]:
    out: list[McpFinding] = []
    for t in tools:
        desc = t.get("description") or ""
        matched = [p for p in PROMPT_INJECTION_PATTERNS
                   if re.search(p, desc, re.IGNORECASE)]
        if matched:
            out.append(McpFinding(
                probe="description_injection",
                severity="high",
                category="Prompt Injection via Tool Description (LLM01)",
                tool=t.get("name"),
                title=f"Tool description for `{t.get('name')}` contains injection markers",
                detail=(
                    "An LLM that enumerates this server's tools will read the "
                    "description verbatim into its context. The description "
                    f"contains suspicious markers ({', '.join(matched)}) that "
                    "an attacker could use to coerce the agent."
                ),
                evidence=desc[:400],
            ))
    return out


def probe_dangerous_capability(tools: list[dict]) -> list[McpFinding]:
    out: list[McpFinding] = []
    for t in tools:
        name = (t.get("name") or "").lower()
        desc = (t.get("description") or "").lower()
        if (any(re.search(p, name) for p in DANGEROUS_TOOL_NAME_PATTERNS)
                or any(re.search(p, desc) for p in DANGEROUS_DESC_PATTERNS)):
            out.append(McpFinding(
                probe="dangerous_capability",
                severity="high",
                category="Excessive Agency (LLM06)",
                tool=t.get("name"),
                title=f"Tool `{t.get('name')}` exposes a dangerous capability",
                detail=(
                    "This tool's name or description suggests it can execute "
                    "code, shell commands, or other broadly-scoped actions. "
                    "Any prompt-injected agent that gains access to this tool "
                    "achieves arbitrary action on the host."
                ),
                evidence=t.get("description", ""),
            ))
    return out


async def probe_path_traversal(client: MCPClient, tools: list[dict]) -> list[McpFinding]:
    payloads = [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../etc/hosts",
    ]
    indicators = [
        "root:x:", "[fonts]", "127.0.0.1", "localhost", "[extensions]",
    ]
    out: list[McpFinding] = []
    for t in tools:
        targets = _params_matching(t, "path", "file", "filename")
        if not targets:
            continue
        for param in targets:
            for payload in payloads:
                args = _example_args(t, {param: payload})
                resp = await client.call_tool(t["name"], args)
                text = _extract_text(resp)
                if any(ind.lower() in text.lower() for ind in indicators):
                    out.append(McpFinding(
                        probe="path_traversal",
                        severity="critical",
                        category="Broken Access Control (Path Traversal)",
                        tool=t["name"],
                        title=f"`{t['name']}` allows reading files outside its sandbox",
                        detail=(
                            f"Argument `{param}` accepts traversal sequences. "
                            f"Payload `{payload}` returned host-file content."
                        ),
                        evidence=text[:400],
                        request={"tool": t["name"], "arguments": args},
                    ))
                    break  # one PoC per param is enough
    return out


async def probe_ssrf(client: MCPClient, tools: list[dict]) -> list[McpFinding]:
    # Targets that should never be reachable from an external URL fetcher.
    targets = [
        ("http://127.0.0.1:8000/", "supportbot"),     # the demo chatbot
        ("http://localhost:8000/api", "Vulnerable"),
        ("http://169.254.169.254/", "metadata"),       # cloud metadata
    ]
    out: list[McpFinding] = []
    for t in tools:
        url_params = _params_matching(t, "url", "uri", "href", "link")
        if not url_params:
            continue
        for param in url_params:
            for url, indicator in targets:
                args = _example_args(t, {param: url})
                try:
                    resp = await client.call_tool(t["name"], args)
                except Exception:
                    continue
                text = _extract_text(resp)
                if indicator.lower() in text.lower():
                    out.append(McpFinding(
                        probe="ssrf",
                        severity="high",
                        category="Server-Side Request Forgery",
                        tool=t["name"],
                        title=f"`{t['name']}` will fetch internal URLs",
                        detail=(
                            f"Argument `{param}` accepts arbitrary URLs. "
                            f"The server proxied a request to `{url}` and "
                            "returned its content."
                        ),
                        evidence=text[:400],
                        request={"tool": t["name"], "arguments": args},
                    ))
                    break
    return out


async def probe_sql_injection(client: MCPClient, tools: list[dict]) -> list[McpFinding]:
    """
    Heuristic SQLi: send a benign value and a tautology, compare row counts.

    A param is flagged if the tautology returns strictly more results than the
    benign value, or surfaces a string the benign value doesn't (e.g. an SSN).
    """
    benign = "alice"
    payload = "%' OR '1'='1"
    sentinel_indicators = ["111-22-3333", "admin@", "ssn"]
    out: list[McpFinding] = []

    for t in tools:
        # Only probe tools that take a single user-supplied string argument
        # AND look like lookup tools (name contains find/search/lookup/get/query).
        if not re.search(r"find|search|lookup|query|get", t.get("name", ""), re.I):
            continue
        params = _string_params(t)
        if not params:
            continue
        for param in params:
            try:
                base_resp = await client.call_tool(t["name"], _example_args(t, {param: benign}))
                evil_resp = await client.call_tool(t["name"], _example_args(t, {param: payload}))
            except Exception:
                continue
            base_text = _extract_text(base_resp)
            evil_text = _extract_text(evil_resp)
            leaked = [s for s in sentinel_indicators
                      if s.lower() in evil_text.lower()
                      and s.lower() not in base_text.lower()]
            grew_a_lot = len(evil_text) > max(len(base_text) * 2, len(base_text) + 50)
            if leaked or grew_a_lot:
                out.append(McpFinding(
                    probe="sql_injection",
                    severity="critical",
                    category="SQL Injection (A03)",
                    tool=t["name"],
                    title=f"`{t['name']}` argument `{param}` is SQL-injectable",
                    detail=(
                        f"Sending the tautology `{payload}` returned "
                        + (f"sensitive fields ({', '.join(leaked)}) " if leaked
                           else "substantially more data ")
                        + "than the benign baseline, indicating unsafe query "
                          "construction."
                    ),
                    evidence=evil_text[:400],
                    request={"tool": t["name"], "arguments": {param: payload}},
                ))
                break
    return out


# Catalog-level probes that don't need the client
SYNC_PROBES = [
    probe_description_injection,
    probe_dangerous_capability,
]

# Probes that actually call tools
ASYNC_PROBES = [
    probe_path_traversal,
    probe_ssrf,
    probe_sql_injection,
]
