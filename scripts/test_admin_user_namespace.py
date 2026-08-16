#!/usr/bin/env python3
"""Run the admin server in a user namespace and inspect peer authorization."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="agb-userns-admin-") as directory:
        base = Path(directory)
        sock = base / "admin.sock"
        command = ["unshare", "-Ur", str(root / "target/debug/agb-admin-server"), str(sock), str(base / "cache"), str(base / "audit")]
        process = subprocess.Popen(command, env={**os.environ, "AGB_ADMIN_TOKEN": "test-token", "AGB_ADMIN_UIDS": str(os.getuid())})
        try:
            for _ in range(100):
                if sock.exists(): break
                if process.poll() is not None: raise RuntimeError("user-namespace admin server exited")
                time.sleep(0.02)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(sock))
                client.sendall((json.dumps({"token": "test-token", "operation": "list", "operator": "ignored"}) + "\n").encode())
                response = json.loads(client.makefile("rb").readline())
            report = {"host_uid": os.getuid(), "allowlist": os.getuid(), "response": response, "virtual_root_must_not_equal_host_uid": response.get("reason") == "peer-not-allowlisted"}
            print(json.dumps(report, indent=2))
            if not report["virtual_root_must_not_equal_host_uid"]:
                raise SystemExit("virtual UID was incorrectly accepted")
        finally:
            process.terminate(); process.wait(timeout=3); sock.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
