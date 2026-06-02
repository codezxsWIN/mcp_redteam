from __future__ import annotations

import sys

from .server import mcp


def main() -> None:
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport in ("http", "streamable-http"):
        if len(sys.argv) > 2:
            mcp.settings.port = int(sys.argv[2])
        mcp.settings.host = "127.0.0.1"
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
