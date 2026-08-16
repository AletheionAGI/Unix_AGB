from __future__ import annotations

import json
import socket
import subprocess
import time
import unittest
from pathlib import Path


class BrokerHealthProtocolTests(unittest.TestCase):
    def test_health_request_is_dedicated(self) -> None:
        root = Path(__file__).resolve().parents[1]
        socket_path = Path("/tmp/unix-agb-health-test.sock")
        audit_path = Path("/tmp/unix-agb-health-test.jsonl")
        socket_path.unlink(missing_ok=True)
        process = subprocess.Popen([str(root / "target/debug/agb-policy-broker"), str(socket_path), str(audit_path)])
        try:
            for _ in range(50):
                if socket_path.exists():
                    break
                time.sleep(0.02)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall((json.dumps({"type": "health", "namespace_id": "health:test", "resource": "health://broker", "policy_revision": "policy:health-probe", "requested_effect": "ALLOW"}) + "\n").encode())
                response = json.loads(client.makefile("rb").readline())
            self.assertEqual(response["reason"], "health-ok")
            self.assertFalse(response["applied"])
        finally:
            process.terminate()
            process.wait(timeout=3)
            socket_path.unlink(missing_ok=True)
