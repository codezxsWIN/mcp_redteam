from __future__ import annotations

from ..client.session import RedTeamSession
from ..judge.heuristic import HeuristicJudge
from ..payloads.loader import load_corpus, render_payloads
from ..report.finding import Evidence, Finding
from .base import Probe, ScanContext, example_args, string_params


class OutputInjectionProbe(Probe):
    name = "output_injection"

    async def run(self, session: RedTeamSession, ctx: ScanContext) -> list[Finding]:
        corpus = load_corpus()
        payloads = render_payloads(self.name, corpus)
        judge = HeuristicJudge(extra_markers=[corpus.canary])
        cap = ctx.settings.max_payloads_per_tool

        findings: list[Finding] = []
        for tool in ctx.tools:
            name = tool.get("name", "?")
            params = string_params(tool)
            if not params:
                continue
            if await self._probe_tool(session, name, tool, params, payloads, judge, cap, findings):
                continue
        return findings

    async def _probe_tool(self, session, name, tool, params, payloads, judge, cap, findings) -> bool:
        sent = 0
        for param in params:
            for payload in payloads:
                if sent >= cap:
                    return False
                sent += 1
                args = example_args(tool, {param: payload.text})
                try:
                    result = await session.call_tool(name, args)
                except Exception:
                    continue
                output = RedTeamSession.text_of(result)
                verdict = judge.scan(output)
                if not verdict.success:
                    continue

                evidence = Evidence()
                evidence.request(
                    f"tools/call {name} with adversarial `{param}`",
                    method="tools/call",
                    data={"name": name, "arguments": args},
                )
                evidence.response(
                    "tool output carries injection markers",
                    method="tools/call",
                    data={"output": output[:800], "markers": verdict.markers},
                )
                findings.append(
                    Finding(
                        probe=self.name,
                        title=f"Tool `{name}` returns attacker-controllable injection in its output",
                        severity=payload.severity,
                        category="Output-side Prompt Injection (LLM01)",
                        tool=name,
                        description=(
                            f"Argument `{param}` was sent payload `{payload.id}` "
                            f"(mutation: {payload.mutation}). The tool output contains "
                            f"injection markers ({', '.join(verdict.markers)}) that a host "
                            "LLM would ingest as instructions when summarising the result."
                        ),
                        remediation=(
                            "Sanitise/encode tool output before returning it; do not echo "
                            "untrusted input. Hosts should treat tool output as data, never "
                            "as instructions."
                        ),
                        reproduction=[
                            f"Connect to the target ({session.spec.transport_label}).",
                            f"Call `{name}` with arguments: {args}.",
                            "Read the returned content.",
                            f"Observe injection markers: {', '.join(verdict.markers)}.",
                        ],
                        evidence=evidence,
                    )
                )
                return True
        return False
