# Security Policy

`mcp-redteam` is security research tooling for authorized testing of Model
Context Protocol servers.

## Reporting vulnerabilities

If you find a vulnerability in this project, please open a private advisory or
contact the maintainers before publishing details. If private reporting is not
available yet on the GitHub repository, open an issue with a minimal description
and ask for a private channel before sharing exploit details.

Please include:

- Affected version or commit.
- Reproduction steps.
- Expected and actual behavior.
- Impact and any known mitigations.

## Responsible use

Do not scan third-party MCP servers without authorization. Do not submit reports
that include real secrets, tokens, private data, or third-party transcripts.

This repository includes intentionally vulnerable fixtures and hostile demo
repositories for scanner validation. Treat them as unsafe samples and keep them
isolated from trusted editor sessions, agents, and credentials.