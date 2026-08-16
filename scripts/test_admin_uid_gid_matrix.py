#!/usr/bin/env python3
"""Test UID/GID allowlist combinations for host and user-namespace peers."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import shutil
from pathlib import Path


def request(sock: Path) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(sock))
        client.sendall((json.dumps({"token": "matrix-token", "operation": "list", "operator": "ignored"}) + "\n").encode())
        return json.loads(client.makefile("rb").readline())


def run(command: list[str], sock: Path, env: dict[str, str]) -> dict[str, object]:
    process = subprocess.Popen(command, env=env)
    try:
        for _ in range(100):
            if sock.exists(): break
            if process.poll() is not None: raise RuntimeError("admin server exited")
            time.sleep(0.02)
        return request(sock)
    finally:
        process.terminate(); process.wait(timeout=3); sock.unlink(missing_ok=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="agb-uid-gid-matrix-") as directory:
        base = Path(directory)
        base.chmod(0o755)
        binary = base / "agb-admin-server"
        shutil.copy2(root / "target/debug/agb-admin-server", binary)
        binary.chmod(0o755)
        env = {**os.environ, "AGB_ADMIN_TOKEN": "matrix-token", "AGB_ADMIN_UIDS": str(os.getuid()), "AGB_ADMIN_GIDS": str(os.getgid())}
        host = run([str(binary), str(base / "host.sock"), str(base / "host.cache"), str(base / "host.audit")], base / "host.sock", env)
        mismatch_env = {**env, "AGB_ADMIN_GIDS": "4294967294"}
        mismatch = run([str(binary), str(base / "mismatch.sock"), str(base / "mismatch.cache"), str(base / "mismatch.audit")], base / "mismatch.sock", mismatch_env)
        userns = run(["unshare", "-Ur", str(binary), str(base / "userns.sock"), str(base / "userns.cache"), str(base / "userns.audit")], base / "userns.sock", env)
        report = {"host_uid": os.getuid(), "host_gid": os.getgid(), "host_allowed": host, "gid_mismatch": mismatch, "user_namespace": userns}
        print(json.dumps(report, indent=2))
        userns_ok = userns.get("reason") == ("admin-ok" if os.getuid() == 0 else "peer-not-allowlisted")
        if host.get("reason") != "admin-ok" or mismatch.get("reason") != "peer-not-allowlisted" or not userns_ok:
            raise SystemExit("UID/GID matrix did not produce expected decisions")


if __name__ == "__main__":
    main()
