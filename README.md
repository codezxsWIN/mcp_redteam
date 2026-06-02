# mcp-redteam

**Runtime red-team testing for Model Context Protocol (MCP) servers.**

`mcp-redteam` connects to a running MCP server, exercises it with a curated
attack-payload library, and produces evidence you can act on: request/response
transcripts, severity, and reproduction steps for every finding.

It is not a static config linter. Static scanners are useful for catching risky
strings in `mcp.json` files and tool descriptions. `mcp-redteam` is the
complementary runtime harness: it talks to the live server and records what the
server actually does.

![mcp-redteam dashboard](dashboard-desktop.png)

> For authorized security research only. Run this against systems you own or
> have explicit permission to test.

## Why it exists

MCP servers sit between an agent and the outside world. A malicious or
compromised server can try to steer the host LLM, mutate tool definitions after
approval, or expose resources beyond the boundary a user expected. Those risks
are easiest to understand when you have concrete runtime evidence, not just a
warning label.

`mcp-redteam` gives security engineers, agent builders, and platform teams a
repeatable way to probe those behaviors before an MCP server is trusted in a
real workflow.

## Theory

### MCP as a trust boundary

In a Model Context Protocol deployment, three parties interact: the **user**,
the **host** (the client application and its LLM), and one or more **MCP
servers** that expose tools, resources, and prompts. The user trusts the host.
The host, in turn, treats whatever a server returns — tool descriptions, tool
output, resource contents — as trustworthy context and feeds it to the LLM.

That implicit trust is the boundary `mcp-redteam` interrogates. The protocol was
designed for capability discovery and invocation, not for adversarial isolation:
nothing in the wire format guarantees that a tool's description is benign, that
its output is data rather than instructions, or that its advertised capabilities
stay constant after approval. A server that an agent depends on is therefore
part of the agent's attack surface.

### The confused-deputy core

Every probe here is a variation on one classical idea: the **confused deputy**.
The LLM is a privileged actor that acts on behalf of the user, but it cannot
reliably distinguish *content it should reason about* from *instructions it
should obey*. A malicious server exploits that ambiguity to make the deputy
(the LLM) act against the principal (the user) using the deputy's own authority.

The four probe families map onto distinct points where that confusion can be
induced:

| Attack class | Where the injection enters | What the server abuses |
|---|---|---|
| **Tool poisoning** | Tool / parameter *descriptions* read before any call | Trust in metadata at discovery time |
| **Output injection** | Tool *output* returned during a call | Failure to separate data from instructions |
| **Rug pull** | Tool *definitions* after initial approval | Trust persistence across time (TOCTOU) |
| **Resource exfiltration** | Resource *URI templates* | Over-broad capability grants |

### Why runtime evidence

Static analysis can flag a suspicious string in an `mcp.json` file or a tool
description, but it cannot observe behavior that only appears at runtime: output
that changes with input, a tool catalog that mutates after the first call, or a
resource template that resolves to data outside its intended scope. These are
*time-of-check to time-of-use* (TOCTOU) and *data-dependent* behaviors, and the
only sound way to detect them is to **drive the live server and record what it
actually does**.

`mcp-redteam` therefore treats a finding as a falsifiable claim backed by a
transcript. Each probe follows the same loop:

```
payload corpus → mutators → probe drives the server → judge → evidence
```

- **Corpus + mutators.** A versioned payload library (`corpus.yaml`) is expanded
  at load time with encodings real attackers use — base64, zero-width
  characters, and Unicode tag-block smuggling — so detection is not tied to a
  single literal string.
- **Probe.** Each probe exercises one trust assumption (read descriptions, send
  adversarial input, re-list after calls, enumerate resources) and captures the
  full request/response transcript.
- **Judge.** A pluggable success oracle decides whether a behavior is a finding.
  The default judge is heuristic (marker detection, catalog diffing); the `Judge`
  seam lets an LLM-as-judge backend slot in later without changing probes.
- **Evidence.** Every finding carries severity plus step-by-step reproduction,
  so a reviewer can replay it rather than trust a label.

This is the project's central thesis: **MCP security claims should be
reproducible and transcript-backed, not assertions** — the same standard a
red-team report is held to before anyone acts on it.

## Highlights

- Exercises live MCP servers over stdio and streamable HTTP.
- Detects output-side prompt injection, tool poisoning, rug-pull behavior, and
  over-broad resource templates.
- Captures full request/response transcripts and step-by-step reproduction.
- Generates terminal, JSON, Markdown, and standalone HTML reports.
- Ships with a local web dashboard for demos and triage.
- Includes an intentionally vulnerable MCP server for one-command validation.
- Supports CI gating with severity-based exit codes.

## Install

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```pwsh
git clone https://github.com/codezxsWIN/mcp-redteam.git
cd mcp-redteam
uv sync
```

For local development without cloning from GitHub yet, run `uv sync` from this
repository root.

## Quick start

Scan the bundled vulnerable server over stdio:

```pwsh
uv run mcp-redteam scan stdio:python -m tests.fixtures.vulnerable_server
```

Write machine- and human-readable reports, and gate CI on severity:

```pwsh
uv run mcp-redteam scan stdio:python -m tests.fixtures.vulnerable_server `
  --json findings.json --md report.md --html report.html --severity-threshold high
```

The process exits non-zero when any finding is at or above
`--severity-threshold` (default `medium`), so it drops straight into CI.

### Web dashboard

Prefer a point-and-click view for demos or triage? Launch the bundled dashboard:

```pwsh
uv run mcp-redteam serve
```

Open <http://127.0.0.1:8000>, enter a target (e.g.
`stdio:python -m tests.fixtures.vulnerable_server`), pick which probes to run and
a severity threshold, and hit **Run scan**. Findings render as a severity-colored
table; click any row to expand its full reproduction transcript. The dashboard is
served by Starlette/uvicorn (installed by `uv sync`). Bind/port are configurable
with `--host` / `--port`.

The same styled view is available offline as a standalone file via `--html report.html`.

### Targets

| Form | Example |
|---|---|
| stdio command | `stdio:python -m my_server` |
| streamable HTTP | `http://127.0.0.1:8000/mcp` |
| `mcp.json` | `./mcp.json` (scans every server listed; findings grouped per server) |

## Example run (bundled vulnerable server)

```
$ uv run mcp-redteam scan stdio:python -m tests.fixtures.vulnerable_server
──────────────── mcp-redteam — stdio: python -m tests.fixtures.vulnerable_server ────────────────
Server: vulnmcp v1.27.1 (stdio)   Tools: 3   Resources: 2   Findings: 6
                                   Findings
┌──────────┬──────────────────┬─────────────┬────────────────────────────────────────────┐
│ Severity │ Probe            │ Subject     │ Title                                       │
├──────────┼──────────────────┼─────────────┼────────────────────────────────────────────┤
│ high     │ output_injection │ send_email  │ Tool returns attacker-controllable …       │
│ high     │ output_injection │ summarize   │ Tool returns attacker-controllable …       │
│ high     │ output_injection │ get_weather │ Tool returns attacker-controllable …       │
│ high     │ tool_poisoning   │ send_email  │ Tool description carries injection markers  │
│ high     │ rug_pull         │ get_weather │ Tool catalog mutated after use              │
│ high     │ resource_exfil   │ file://{…}  │ Over-broad resource template               │
└──────────┴──────────────────┴─────────────┴────────────────────────────────────────────┘
```

Each finding in `--json` / `--md` / `--html` (and in the dashboard) includes the
full request/response transcript
and step-by-step reproduction. For example, the `rug_pull` finding records the
baseline `tools/list`, the calls performed, and the post-call `tools/list` diff
that proves `get_weather`'s description changed after it was trusted.

## Probes (v0.1)

| Probe | What it does | Threat |
|---|---|---|
| `tool_poisoning` | Scans live tool/parameter descriptions for instruction-injection markers | A server steers the host LLM before any tool runs |
| `output_injection` | Sends adversarial inputs, scans tool **output** for injection markers | A server feeds the host LLM instructions disguised as data |
| `rug_pull` | Snapshots tool defs, makes N calls, re-lists, diffs | A server swaps in malicious behavior after approval |
| `resource_exfil` | Enumerates resources/templates, flags over-broad URI templates (and confirms a contained read) | A server reads files/data beyond its intended boundary |

Run a subset with `--probe`:

```pwsh
uv run mcp-redteam scan <target> --probe rug_pull --probe resource_exfil
```

The payload library lives in `mcp_redteam/payloads/corpus.yaml` (versioned) and
is expanded at load time by `mutators.py` (base64, zero-width, unicode tag-block
smuggling). The success judge is heuristic today and sits behind a pluggable
`Judge` seam (`mcp_redteam/judge/`) so an LLM-as-judge backend can be added later.

## Reports

Use `--json`, `--md`, and `--html` to write artifacts for machines, humans, and
offline review:

```pwsh
uv run mcp-redteam scan stdio:python -m tests.fixtures.vulnerable_server `
  --json findings.json `
  --md report.md `
  --html report.html
```

The JSON schema is covered by tests, the Markdown report is easy to paste into a
ticket, and the HTML report is self-contained for sharing with reviewers.

## Threat model

The adversary **controls the MCP server**. The MCP client is honest, and the
user trusts the client's LLM. The goal is to surface server behaviors that let a
malicious server (a) influence the LLM, (b) exfiltrate data, or (c) escape
intended tool boundaries.

## Scope

**In scope (v0.1):** live stdio + streamable-HTTP servers; the four probes
above; terminal / JSON / Markdown / HTML reporting; a local web dashboard
(`serve`); CI exit codes; the bundled vulnerable server.

**Out of scope (backlog):** `shadowing` / `confused_deputy` (need multi-server
orchestration), `auth_bypass`, an LLM-as-judge backend (seam only), SSE
transport, GitHub Action / telemetry, scanning client apps
(Cursor, Claude Desktop), and static config linting (covered by Invariant et al.).

## Safety notes

This repository contains intentionally vulnerable fixtures and generated hostile
demo repositories used to validate scanner behavior. Treat directories named
`hostile-*` as unsafe test material: inspect them only in isolated editor
windows, do not install or run them as normal projects, and do not point agents
with secrets or broad filesystem access at them.

Findings are examples of risky behavior, not proof of exploitation against a
third-party system. Always obtain authorization before scanning.

## Development

```pwsh
uv run pytest
```

The test suite spins up the bundled vulnerable server over both stdio and
streamable HTTP and asserts every probe fires with a transcript.

## Project status

`mcp-redteam` is an early research tool. The current focus is a small,
well-evidenced probe set for runtime MCP behavior. Contributions that improve
probe accuracy, reporting, transport coverage, or reproducibility are welcome.
