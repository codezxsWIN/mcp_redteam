# LinkedIn Launch Draft

## Short Post

I built `mcp-redteam`, a runtime red-team harness for Model Context Protocol
servers.

Most MCP safety checks are static: they inspect config files or tool
descriptions. That is useful, but it misses what happens when a server is live.
`mcp-redteam` connects to an MCP server over stdio or streamable HTTP, runs a
small set of adversarial probes, and produces evidence with full request and
response transcripts.

Current probes cover:

- Tool poisoning in live tool definitions.
- Output-side prompt injection.
- Rug-pull behavior where tool descriptions mutate after approval.
- Over-broad resource templates that can expose unintended data.

It also includes a vulnerable MCP fixture, CI-friendly severity thresholds, JSON
and Markdown output, standalone HTML reports, and a local dashboard for demos and
triage.

The goal is simple: make MCP security findings reproducible enough that builders
can fix them before agents depend on them.

Repo: https://github.com/codezxsWIN/mcp-redteam

#AISecurity #ModelContextProtocol #LLMSecurity #RedTeam #Cybersecurity

## Image Suggestion

Use `dashboard-desktop.png` as the main image. Suggested alt text:

> Screenshot of the mcp-redteam dashboard showing MCP probe controls and a scan
> results area for runtime security findings.

## Longer Post

MCP servers are quickly becoming part of the trust boundary for AI agents. They
give agents tools, resources, and access to external systems. That also means a
malicious or compromised MCP server can try to influence the host LLM, change
tool behavior after approval, or expose resources outside the boundary a user
expected.

I built `mcp-redteam` to make those behaviors testable at runtime.

Instead of only scanning config files, it connects to a running MCP server,
exercises it with adversarial probes, and records evidence: request/response
transcripts, severity, and step-by-step reproduction. It supports stdio,
streamable HTTP, JSON/Markdown/HTML reports, and a local dashboard.

The first probe set focuses on four practical risks:

- Tool poisoning.
- Output-side prompt injection.
- Rug-pull behavior after initial tool approval.
- Over-broad resource templates.

There is also a bundled vulnerable server so the whole workflow can be verified
in one command.

I am treating this as an early research tool, but the direction is clear: MCP
security reports should be reproducible, transcript-backed, and easy to plug
into CI before a server is trusted by real agents.

Repo: https://github.com/codezxsWIN/mcp-redteam

#AISecurity #ModelContextProtocol #LLMSecurity #RedTeam #Cybersecurity