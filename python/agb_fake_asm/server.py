"""Unix-domain JSONL server for exercising the future ASM-CM boundary."""

from __future__ import annotations

import argparse
import json
import os
import socketserver
from pathlib import Path
from typing import Any

from .engine import FakeAsmEngine
from .asm_cm_engine import AsmCmEngine
from .persistent_engine import PersistentStatefulProxy

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
        except (KeyError, TypeError, ValueError, RuntimeError, OSError, json.JSONDecodeError) as error:
            self._reply({"effect": "ABSTAIN", "reason": "STATE_ENGINE_ERROR", "error": str(error)})

    def _reply(self, value: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")


class StateEngineServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: str, engine: Any) -> None:
        self.engine = engine
        super().__init__(socket_path, _Handler)


class FakeAsmServer(StateEngineServer):
    def __init__(self, socket_path: str) -> None:
        super().__init__(socket_path, FakeAsmEngine())


def main() -> None:
    parser = argparse.ArgumentParser(description="Unix-AGB fake ASM server")
    parser.add_argument("--socket", default="var/run/fake-asm.sock")
    parser.add_argument("--engine", choices=("fake", "stateful-proxy", "asm-cm"), default="fake")
    parser.add_argument("--snapshot", type=Path, default=Path("var/stateful-proxy.json"))
    parser.add_argument("--configuration-fingerprint", default="config:gate2-v1")
    parser.add_argument("--asm-checkpoint", type=Path)
    parser.add_argument("--asm-source-root", type=Path)
    parser.add_argument("--asm-checkpoint-sha256")
    parser.add_argument("--device", default="cpu")
    parser.add_argument(
        "--asm-inference-policy",
        choices=("security-relevant", "all-events"),
        default="security-relevant",
    )
    args = parser.parse_args()
    socket_path = Path(args.socket)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()
    engine: Any = FakeAsmEngine()
    if args.engine == "stateful-proxy":
        engine = PersistentStatefulProxy(args.snapshot, args.configuration_fingerprint)
    elif args.engine == "asm-cm":
        if args.asm_checkpoint is None or args.asm_source_root is None:
            parser.error("--engine asm-cm requires --asm-checkpoint and --asm-source-root")
        engine = AsmCmEngine(
            args.asm_checkpoint,
            args.asm_source_root,
            device=args.device,
            expected_sha256=args.asm_checkpoint_sha256,
            snapshot=args.snapshot,
            inference_policy=args.asm_inference_policy,
        )
    server = StateEngineServer(os.fspath(socket_path), engine)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
