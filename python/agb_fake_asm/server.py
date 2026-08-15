"""Unix-domain JSONL server for exercising the future ASM-CM boundary."""

from __future__ import annotations

import argparse
import json
import os
import socketserver
from pathlib import Path
from typing import Any

from .engine import FakeAsmEngine

MAX_MESSAGE_BYTES = 64 * 1024


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        if len(line) > MAX_MESSAGE_BYTES:
            self._reply({"error": "message exceeds 64 KiB"})
            return
        try:
            event: dict[str, Any] = json.loads(line)
            summary = self.server.engine.update(event)  # type: ignore[attr-defined]
            self._reply(summary)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self._reply({"error": str(error)})

    def _reply(self, value: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")


class FakeAsmServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: str) -> None:
        self.engine = FakeAsmEngine()
        super().__init__(socket_path, _Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unix-AGB fake ASM server")
    parser.add_argument("--socket", default="var/run/fake-asm.sock")
    args = parser.parse_args()
    socket_path = Path(args.socket)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()
    server = FakeAsmServer(os.fspath(socket_path))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

