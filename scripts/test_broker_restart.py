#!/usr/bin/env python3
"""Exercise broker crash, socket recreation, and post-restart health."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def wait_socket(path: Path) -> None:
    for _ in range(100):
        if path.exists():
            return
        time.sleep(0.02)
    raise RuntimeError("broker socket did not become ready")


def health(path: Path) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall((json.dumps({"type": "health", "namespace_id": "health:restart", "resource": "health://broker", "policy_revision": "policy:health-probe", "requested_effect": "ALLOW"}) + "\n").encode())
        return json.loads(client.makefile("rb").readline())


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="agb-restart-") as directory:
        directory_path = Path(directory)
        socket_path = directory_path / "policy.sock"
        audit_path = directory_path / "enforcement.jsonl"
        command = [str(root / "target/debug/agb-policy-broker"), str(socket_path), str(audit_path)]
        first = subprocess.Popen(command)
        wait_socket(socket_path)
        before = health(socket_path)
        first.send_signal(signal.SIGKILL)
        first.wait(timeout=3)
        socket_path.unlink(missing_ok=True)
        second = subprocess.Popen(command)
        try:
            wait_socket(socket_path)
            after = health(socket_path)
        finally:
            second.terminate()
            second.wait(timeout=3)
            socket_path.unlink(missing_ok=True)
        report = {"proof": "broker-crash-restart-v1", "before": before, "after": after, "recreated_socket": True}
        if before.get("reason") != "health-ok" or after.get("reason") != "health-ok":
            raise SystemExit("health failed before or after restart")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
