from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


class CacheCorruptionTests(unittest.TestCase):
    def test_invalid_snapshot_line_does_not_break_health(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="agb-corrupt-cache-") as directory:
            base = Path(directory)
            socket_path = base / "policy.sock"
            audit_path = base / "audit.jsonl"
            cache_path = base / "cache.jsonl"
            cache_path.write_text("not-json\n")
            process = subprocess.Popen([str(root / "target/debug/agb-policy-broker"), str(socket_path), str(audit_path), str(cache_path)])
            try:
                for _ in range(50):
                    if socket_path.exists():
                        break
                    time.sleep(0.02)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(socket_path))
                    client.sendall((json.dumps({"type": "health", "namespace_id": "health:corrupt", "resource": "health://broker", "policy_revision": "policy:health-probe", "requested_effect": "ALLOW"}) + "\n").encode())
                    response = json.loads(client.makefile("rb").readline())
                self.assertEqual(response["reason"], "health-ok")
            finally:
                process.terminate()
                process.wait(timeout=3)
                socket_path.unlink(missing_ok=True)

