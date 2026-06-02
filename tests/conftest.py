from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import closing

import pytest

from mcp_redteam.client.transport import TargetSpec


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError(f"server did not start on port {port}")


@pytest.fixture
def stdio_spec() -> TargetSpec:
    return TargetSpec(
        name="server",
        kind="stdio",
        command=sys.executable,
        args=["-m", "tests.fixtures.vulnerable_server"],
    )


@pytest.fixture
def http_spec():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "tests.fixtures.vulnerable_server", "http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port)
        yield TargetSpec(name="server", kind="http", url=f"http://127.0.0.1:{port}/mcp")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
