from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from agb_fake_asm import FakeAsmEngine
from agb_fake_asm.server import FakeAsmServer
from generate_synthetic_events import event


class FakeAsmEngineTests(unittest.TestCase):
    def test_elevated_chain_is_deterministic(self) -> None:
        engine = FakeAsmEngine()
        engine.update(event(1, "process.exec", []))
        engine.update(event(2, "network.connect", []))
        summary = engine.update(event(3, "file.open", ["credential"]))
        self.assertEqual(summary["risk_band"], "elevated")
        self.assertEqual(summary["state_revision"], 3)
        self.assertIn("exec_network_credential_chain", summary["signals"])
        self.assertEqual(
            summary["evidence_ids"],
            ["evt:synthetic:1", "evt:synthetic:2", "evt:synthetic:3"],
        )

    def test_pid_reuse_is_isolated_by_start_time(self) -> None:
        engine = FakeAsmEngine()
        first = event(1, "process.exec", [])
        second = event(2, "process.exec", [])
        second["subject"]["start_time_ns"] = 900_000_002  # type: ignore[index]
        second["namespace_id"] = "process:boot-synthetic:4242:900000002"
        engine.update(first)
        engine.update(second)
        self.assertEqual(engine.namespace_count, 2)

    def test_unix_socket_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = str(Path(directory) / "asm.sock")
            server = FakeAsmServer(socket_path)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(socket_path)
                    client.sendall(json.dumps(event(1, "process.exec", [])).encode() + b"\n")
                    response = json.loads(client.makefile("rb").readline())
                self.assertEqual(response["engine"], "fake")
                self.assertEqual(response["state_revision"], 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
