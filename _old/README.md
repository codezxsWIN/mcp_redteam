# promptprobe

> An offensive security scanner for LLM-powered web applications.
> Point it at a chatbot, get a security report.

Think **"Nmap, but for AI features."**

## What it does

Given the URL of a chatbot or LLM-backed API, `promptprobe`:

1. Fires a curated library of **prompt injection** payloads at it.
2. Uses a **judge** (rule-based or local LLM) to decide which attacks succeeded.
3. Generates a **security report** with severity and reproducible PoCs.

Today it covers:

- System prompt extraction
- Direct prompt injection (rule override)
- Role-play / persona hijacking
- Indirect injection via injected context
- Encoding-based bypasses (base64, leet, unicode)
- Authority impersonation (`[SYSTEM]: ...`)
- Output-format jailbreaks

## Quick start (60 seconds)

```pwsh
# 1. Install Python deps
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Start the vulnerable demo chatbot (in a separate terminal)
python -m demo_app.vulnerable_chatbot

# 3. Run the scanner against it
python cli.py scan http://localhost:8000/chat
```

You should see a colored report listing which attacks succeeded.

## Modes

The demo chatbot and scanner both have two backends:

| Backend  | Setup                          | Use it when                |
|----------|--------------------------------|----------------------------|
| `mock`   | nothing — works out of the box | First run, CI, demos       |
| `ollama` | `ollama pull llama3.1:8b`      | Realistic results          |

Switch with the `BACKEND` env var:

```pwsh
$env:BACKEND="ollama"
python -m demo_app.vulnerable_chatbot
```

## Project layout

```
.
├── cli.py                       # entry point
├── demo_app/
│   └── vulnerable_chatbot.py    # leaky FastAPI chatbot for testing
├── scanner/
│   ├── payloads.py              # curated attack payloads
│   ├── judge.py                 # decides if an attack succeeded
│   ├── scanner.py               # fires payloads, collects results
│   └── report.py                # renders the report
└── requirements.txt
```

## Roadmap

- [ ] Phase 1 — MVP scanner with curated payloads (this repo)
- [ ] Phase 2 — Web crawler that auto-discovers LLM input surfaces
- [ ] Phase 3 — Indirect injection (uploaded files / fetched URLs)
- [ ] Phase 4 — Adaptive attacker (local LLM mutates payloads based on responses)
- [ ] Phase 5 — HTML report + OWASP LLM Top 10 mapping
- [ ] Phase 6 — MCP server auditor module

## Responsible use

Only test systems you own or have explicit permission to test. This tool is for
defensive security research. Don't be a jerk.

## License

MIT
