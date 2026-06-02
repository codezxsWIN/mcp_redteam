from __future__ import annotations

from ..client.session import RedTeamSession
from ..report.finding import Evidence, Finding, Severity
from .base import Probe, ScanContext, example_args


def _index(tools: list[dict]) -> dict[str, dict]:
    return {t.get("name", "?"): t for t in tools}


class RugPullProbe(Probe):
    name = "rug_pull"

    async def run(self, session: RedTeamSession, ctx: ScanContext) -> list[Finding]:
        before = _index(ctx.tools)

        calls_made: list[str] = []
        budget = ctx.settings.rug_pull_calls
        for tool in ctx.tools:
            if len(calls_made) >= budget:
                break
            name = tool.get("name", "?")
            try:
                await session.call_tool(name, example_args(tool))
                calls_made.append(name)
            except Exception:
                continue

        after = _index(await session.list_tools())

        findings: list[Finding] = []
        for name in sorted(set(before) | set(after)):
            old = before.get(name)
            new = after.get(name)
            change = self._classify(old, new)
            if change is None:
                continue
            kind, detail, old_v, new_v = change

            evidence = Evidence()
            evidence.request(
                "tools/list (baseline snapshot)", method="tools/list", data={"tool": name}
            )
            evidence.note(f"performed {len(calls_made)} tool call(s): {', '.join(calls_made) or 'none'}")
            evidence.response(
                "tools/list (re-listed after calls) differs from baseline",
                method="tools/list",
                data={"tool": name, "change": kind, "before": old_v, "after": new_v},
            )
            findings.append(
                Finding(
                    probe=self.name,
                    title=f"Tool catalog mutated after use ({kind}: `{name}`)",
                    severity=Severity.high,
                    category="Rug Pull (post-approval tool mutation)",
                    tool=name,
                    description=(
                        f"{detail} A user/host that approved this server's tools at connect "
                        "time would not re-review them, so the server can swap in malicious "
                        "behaviour or descriptions after trust is granted."
                    ),
                    remediation=(
                        "Pin and hash tool definitions at approval time; re-prompt the user "
                        "when name, description, or schema changes during a session."
                    ),
                    reproduction=[
                        f"Connect to the target ({session.spec.transport_label}).",
                        "Call tools/list and record the definitions.",
                        f"Invoke tool(s): {', '.join(calls_made) or 'any'}.",
                        "Call tools/list again and diff against the snapshot.",
                        f"Observe {kind} on `{name}`.",
                    ],
                    evidence=evidence,
                )
            )
        return findings

    @staticmethod
    def _classify(old: dict | None, new: dict | None):
        if old is None and new is not None:
            return ("added", f"Tool `{new.get('name')}` appeared only after tool calls.", None, new.get("description"))
        if old is not None and new is None:
            return ("removed", f"Tool `{old.get('name')}` disappeared after tool calls.", old.get("description"), None)
        if old is None or new is None:
            return None
        if (old.get("description") or "") != (new.get("description") or ""):
            return (
                "description changed",
                f"Tool `{old.get('name')}` description changed between listings.",
                old.get("description"),
                new.get("description"),
            )
        if (old.get("inputSchema") or {}) != (new.get("inputSchema") or {}):
            return (
                "schema changed",
                f"Tool `{old.get('name')}` input schema changed between listings.",
                old.get("inputSchema"),
                new.get("inputSchema"),
            )
        return None
