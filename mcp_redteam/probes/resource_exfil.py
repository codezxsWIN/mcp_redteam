from __future__ import annotations

import re

from ..client.session import RedTeamSession
from ..report.finding import Evidence, Finding, Severity
from .base import Probe, ScanContext

_VAR = re.compile(r"\{([+#./;?&]?)([^}]+)\}")
_SINGLE_VAR = re.compile(r"^[a-z][a-z0-9+.\-]*://\{[+#./;?&]?[^}]+\}/?$", re.IGNORECASE)
_SENSITIVE_SCHEMES = {"file", "fs", "resource", ""}


def _scheme(uri: str) -> str:
    return uri.split("://", 1)[0].lower() if "://" in uri else ""


def template_risk(uri_template: str) -> tuple[bool, list[str]]:
    matches = _VAR.findall(uri_template)
    if not matches:
        return False, []
    reasons: list[str] = []
    for op, var_name in matches:
        if op in ("+", "#", "/"):
            reasons.append(f"path-expansion variable {{{op}{var_name}}} permits '/'")
    scheme = _scheme(uri_template)
    if scheme in _SENSITIVE_SCHEMES:
        reasons.append(f"sensitive scheme '{scheme or 'relative'}'")
    if _SINGLE_VAR.match(uri_template):
        reasons.append("entire path is a single unconstrained variable")
    return (bool(reasons), sorted(set(reasons)))


class ResourceExfilProbe(Probe):
    name = "resource_exfil"

    async def run(self, session: RedTeamSession, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for template in ctx.resource_templates:
            uri_template = template.get("uriTemplate", "")
            broad, reasons = template_risk(uri_template)
            if not broad:
                continue
            findings.append(
                await self._finding_for_template(session, template, uri_template, reasons, ctx)
            )
        return findings

    async def _finding_for_template(self, session, template, uri_template, reasons, ctx) -> Finding:
        name = template.get("name") or uri_template
        evidence = Evidence()
        evidence.request("resources/templates/list", method="resources/templates/list")
        evidence.response(
            "server advertises an over-broad resource template",
            method="resources/templates/list",
            data={"uriTemplate": uri_template, "reasons": reasons},
        )

        probe_uri = self._sample_uri(uri_template, ctx)
        severity = Severity.medium
        if probe_uri:
            try:
                read = await session.read_resource(probe_uri)
                content = RedTeamSession.resource_text_of(read)
                evidence.request(
                    f"resources/read {probe_uri}", method="resources/read", data={"uri": probe_uri}
                )
                evidence.response(
                    "template resolved to readable content",
                    method="resources/read",
                    data={"uri": probe_uri, "content": content[:600]},
                )
                if content:
                    severity = Severity.high
            except Exception as exc:
                evidence.note(f"contained read attempt failed: {exc}")

        return Finding(
            probe=self.name,
            title=f"Over-broad resource template `{uri_template}`",
            severity=severity,
            category="Resource Exfiltration (over-broad URI template)",
            resource=uri_template,
            description=(
                f"Resource template `{uri_template}` is over-broad ({'; '.join(reasons)}). "
                "A host that exposes this server's resources to its LLM grants the server "
                "control over which URIs get read, enabling exfiltration of files or data "
                "beyond any intended boundary."
            ),
            remediation=(
                "Constrain resource templates to a fixed prefix and a restricted character "
                "set; never expose a single unconstrained path/scheme variable. Validate and "
                "canonicalise resolved URIs against an allow-list before reading."
            ),
            reproduction=[
                f"Connect to the target ({session.spec.transport_label}).",
                "Call resources/templates/list.",
                f"Inspect template `{uri_template}`.",
                "Note the unconstrained variable / sensitive scheme."
                + (f" Read `{probe_uri}` to confirm live access." if probe_uri else ""),
            ],
            evidence=evidence,
        )

    @staticmethod
    def _sample_uri(uri_template: str, ctx: ScanContext) -> str | None:
        scheme = _scheme(uri_template)
        candidate: str | None = None
        for res in ctx.resources:
            uri = res.get("uri", "")
            if _scheme(uri) == scheme and "://" in uri:
                candidate = uri.split("://", 1)[1]
                break
        if candidate is None:
            candidate = "README"
        return _VAR.sub(candidate, uri_template, count=1)
