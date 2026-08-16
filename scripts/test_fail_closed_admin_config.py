#!/usr/bin/env python3
"""Verify absent admin allowlists fail closed and are audited."""
import json, os, socket, subprocess, tempfile, time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for case, allowlist in (("absent", {}), ("malformed", {"AGB_ADMIN_UIDS": "not-a-uid"})):
 with tempfile.TemporaryDirectory(prefix="agb-fail-closed-") as directory:
    base = Path(directory); sock = base / "admin.sock"; audit = base / "audit.jsonl"
    env = {**os.environ, "AGB_ADMIN_TOKEN":"fail-closed-token", "AGB_ADMIN_FAIL_CLOSED_CONFIG":"1", **allowlist}
    env.pop("AGB_ADMIN_UIDS", None); env.pop("AGB_ADMIN_GIDS", None)
    process = subprocess.Popen([str(root / "target/debug/agb-admin-server"), str(sock), str(base / "cache"), str(audit)], env=env)
    try:
        for _ in range(100):
            if sock.exists(): break
            time.sleep(.02)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(sock)); client.sendall(b'{"token":"fail-closed-token","operation":"list","operator":"test"}\n')
            response=json.loads(client.makefile("rb").readline())
        records=[json.loads(line) for line in audit.read_text().splitlines()]
        if response.get("reason") != "peer-not-allowlisted" or len(records) != 1 or records[0].get("reason") != "peer-not-allowlisted":
            raise SystemExit("fail-closed configuration was not enforced and audited")
        print(json.dumps({"status":"passed","case":case,"response":response,"audit_events":records},indent=2))
    finally:
        process.terminate(); process.wait(timeout=3)
