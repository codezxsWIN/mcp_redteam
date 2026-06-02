from __future__ import annotations

from datetime import datetime, timezone

from .client.transport import TargetSpec, connect
from .config import Settings
from .probes import ScanContext, get_probes
from .report.finding import ScanReport, ServerInfo


async def scan_target(
    spec: TargetSpec,
    settings: Settings | None = None,
    probe_names: list[str] | None = None,
) -> ScanReport:
    settings = settings or Settings()
    async with connect(spec, timeout=settings.timeout) as session:
        tools = await session.list_tools()
        resources = await session.list_resources()
        templates = await session.list_resource_templates()

        ctx = ScanContext(
            tools=tools,
            resources=resources,
            resource_templates=templates,
            settings=settings,
        )
        report = ScanReport(
            target=spec.transport_label,
            server=ServerInfo(
                name=session.server_name,
                version=session.server_version,
                transport="streamable-http" if spec.kind == "http" else "stdio",
                target=spec.transport_label,
            ),
            tool_count=len(tools),
            resource_count=len(resources) + len(templates),
        )
        for probe in get_probes(probe_names):
            report.probes_run.append(probe.name)
            report.findings.extend(await probe.run(session, ctx))

        report.finished_at = datetime.now(timezone.utc)
        return report
