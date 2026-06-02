"""Capture README dashboard screenshots from a running local server."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


def main() -> None:
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_redteam.cli", "serve", "--port", str(PORT)],
        cwd=REPO,
        env=env,
    )
    try:
        time.sleep(2.5)
        from playwright.sync_api import sync_playwright

        desktop = REPO / "dashboard-desktop.png"
        preview = REPO / "dashboard-preview.png"

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.goto(BASE, wait_until="networkidle")
            page.wait_for_selector("#presetChips .chip")
            page.screenshot(path=str(desktop), full_page=True)

            page.click('#presetChips .chip[data-name="vulnerable"]')
            page.click("#run")
            page.wait_for_function(
                "() => (document.getElementById('status').textContent || '').includes('finding')",
                timeout=120_000,
            )
            page.wait_for_timeout(500)
            page.screenshot(path=str(preview), full_page=True)
            browser.close()

        print(f"wrote {desktop}")
        print(f"wrote {preview}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    main()
