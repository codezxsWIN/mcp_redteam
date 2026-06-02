from __future__ import annotations

from ..client.session import RedTeamSession
from ..judge.heuristic import scan_for_injection
from ..report.finding import Evidence, Finding, Severity
from .base import Probe, ScanContext


class ToolPoisoningProbe(Probe):
    name = "tool_poisoning"

    async def run(self, session: RedTeamSession, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            name = tool.get("name", "?")
            description = tool.get("description") or ""
            surfaces = {"description": description}
            schema = tool.get("inputSchema") or {}
            for param, spec in (schema.get("properties") or {}).items():
                pdesc = (spec or {}).get("description")
                if pdesc:
                    surfaces[f"param:{param}"] = pdesc

            hits: dict[str, list[str]] = {}
            for where, text in surfaces.items():
                markers = scan_for_injection(text)
                if markers:
                    hits[where] = markers
            if not hits:
                continue

            flat = sorted({m for ms in hits.values() for m in ms})
            evidence = Evidence()
            evidence.request(
                "tools/list enumeration", method="tools/list", data={"tool": name}
            )
            evidence.response(
                "tool definition exposes injection markers",
                method="tools/list",
                data={"tool": name, "surfaces": hits, "description": description[:600]},
            )
            findings.append(
                Finding(
                    probe=self.name,
                    title=f"Tool `{name}` description carries prompt-injection markers",
                    severity=Severity.high,
                    category="Tool Poisoning (LLM01 prompt injection)",
                    tool=name,
                    description=(
                        "A host LLM enumerating this server reads the tool definition "
                        "verbatim into its context. The definition contains attacker-style "
                        f"control markers ({', '.join(flat)}), which a malicious server can "
                        "use to coerce the agent before any tool is even called."
                    ),
                    remediation=(
                        "Treat tool/parameter descriptions as untrusted. Strip control "
                        "phrases and non-printable characters; never inline server text into "
                        "the system prompt without sanitisation."
                    ),
                    reproduction=[
                        f"Connect to the target ({session.spec.transport_label}).",
                        "Call tools/list.",
                        f"Inspect the definition of `{name}`.",
                        f"Observe injection markers in: {', '.join(hits)}.",
                    ],
                    evidence=evidence,
                )
            )
        return findings
