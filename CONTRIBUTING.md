# Contributing

Thanks for taking a look at `mcp-redteam`. This is early-stage security tooling,
so the best contributions are focused, reproducible, and careful about safety.

## Good first contributions

- Improve probe precision or reduce false positives.
- Add tests for a real MCP behavior with a minimal fixture.
- Improve JSON, Markdown, HTML, or dashboard reporting.
- Add documentation that helps users reproduce a finding safely.
- Extend transport or preset coverage without weakening existing tests.

## Development setup

```pwsh
uv sync
uv run pytest
```

Run a local scan against the intentionally vulnerable fixture:

```pwsh
uv run mcp-redteam scan stdio:python -m tests.fixtures.vulnerable_server
```

## Pull request checklist

- Keep the change focused on one behavior or workflow.
- Add or update tests for scanner behavior, report shape, or CLI output.
- Include reproduction steps for new probes or bug fixes.
- Avoid committing generated scan artifacts such as `findings.json`,
  `report.md`, or `report.html`.
- Do not add payloads that cause destructive behavior, credential theft, or
  unauthorized access.

## Safety expectations

Only test systems you own or have explicit permission to assess. The bundled
vulnerable fixtures and `hostile-*` demo repositories are intentionally unsafe
test material; keep them isolated from real secrets and production agents.