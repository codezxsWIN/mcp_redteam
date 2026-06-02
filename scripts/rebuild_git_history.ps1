# Rebuild main with one sensible commit per project area.
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))

git checkout --orphan rebuild-main 2>$null
if ($LASTEXITCODE -ne 0) { git checkout -B rebuild-main }
git reset

function Commit-Group {
    param([string]$Message, [string[]]$Paths)
    if (-not $Paths) { return }
    git add -- $Paths
    $staged = git diff --cached --name-only
    if ($staged) {
        git commit -m $Message
    }
}

Commit-Group "chore: add MIT license and changelog" @("LICENSE", "CHANGELOG.md")
Commit-Group "chore: add Python project configuration" @(".gitignore", "pyproject.toml", "requirements.txt", "uv.lock")
Commit-Group "feat: add MCP client transport and session layer" @(
    "mcp_redteam/__init__.py", "mcp_redteam/config.py", "mcp_redteam/client"
)
Commit-Group "feat: add adversarial payload corpus and mutators" @("mcp_redteam/payloads")
Commit-Group "feat: add heuristic judge for probe findings" @("mcp_redteam/judge")
Commit-Group "feat: add runtime security probes for MCP servers" @("mcp_redteam/probes")
Commit-Group "feat: add finding models and report formatters" @("mcp_redteam/report")
Commit-Group "feat: add scanner orchestration and server presets" @("mcp_redteam/scanner.py", "mcp_redteam/presets.py")
Commit-Group "feat: add CLI entrypoint" @("mcp_redteam/cli.py")
Commit-Group "feat: add web dashboard for interactive scans" @("mcp_redteam/web")
Commit-Group "test: add vulnerable fixture and integration tests" @("tests")
Commit-Group "ci: add GitHub Actions workflow and issue templates" @(".github")
Commit-Group "docs: add README, security policy, and contributor guide" @(
    "README.md", "SECURITY.md", "CONTRIBUTING.md", "docs"
)
Commit-Group "docs: add dashboard screenshots and maintainer scripts" @(
    "dashboard-desktop.png", "dashboard-preview.png", "scripts"
)
Commit-Group "chore: add hostile MCP demo fixtures for authorized research" @(
    "hostile-beacon", "hostile-copilot", "hostile-demo"
)
Commit-Group "chore: add agentpwn payload generation utilities" @("agentpwn")
Commit-Group "chore: archive legacy scanner prototype" @("_old")

git branch -M main
Write-Host "`nNew history:"
git log --oneline
