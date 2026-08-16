from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


class AdminAllowlistTests(unittest.TestCase):
    def test_peer_outside_uid_allowlist_is_rejected(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="agb-admin-allow-") as directory:
            base = Path(directory)
            sock = base / "admin.sock"
            process = subprocess.Popen([str(root / "target/debug/agb-admin-server"), str(sock), str(base / "cache"), str(base / "audit")], env={**os.environ, "AGB_ADMIN_TOKEN": "test-token", "AGB_ADMIN_UIDS": "4294967294"})
            try:
                for _ in range(50):
                    if sock.exists(): break
                    time.sleep(0.02)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(sock))
                    client.sendall((json.dumps({"token": "test-token", "operation": "list", "operator": "ignored"}) + "\n").encode())
                    response = json.loads(client.makefile("rb").readline())
                self.assertEqual(response["reason"], "peer-not-allowlisted")
            finally:
                process.terminate(); process.wait(timeout=3); sock.unlink(missing_ok=True)
