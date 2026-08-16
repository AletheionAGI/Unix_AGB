#!/usr/bin/env python3
"""Verify absent admin allowlists fail closed and are audited."""
import json, os, socket, subprocess, tempfile, time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for case, allowlist, request_token, expected_reason in (("absent", {}, "fail-closed-token", "peer-not-allowlisted"), ("malformed", {"AGB_ADMIN_UIDS": "not-a-uid"}, "fail-closed-token", "peer-not-allowlisted"), ("invalid-token", {"AGB_ADMIN_UIDS": str(os.getuid())}, "wrong-token", "invalid-token-or-request"), ("missing-token", {"AGB_ADMIN_UIDS": str(os.getuid())}, "", "invalid-token-or-request")):
 with tempfile.TemporaryDirectory(prefix="agb-fail-closed-") as directory:
    base = Path(directory); sock = base / "admin.sock"; audit = base / "audit.jsonl"
    env = {**os.environ, "AGB_ADMIN_TOKEN":"fail-closed-token", "AGB_ADMIN_FAIL_CLOSED_CONFIG":"1", **allowlist}
    if "AGB_ADMIN_UIDS" not in allowlist: env.pop("AGB_ADMIN_UIDS", None)
    if "AGB_ADMIN_GIDS" not in allowlist: env.pop("AGB_ADMIN_GIDS", None)
    process = subprocess.Popen([str(root / "target/debug/agb-admin-server"), str(sock), str(base / "cache"), str(audit)], env=env)
    try:
        for _ in range(100):
            if sock.exists(): break
            time.sleep(.02)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(sock)); client.sendall((json.dumps({"token":request_token,"operation":"list","operator":"test"}) + "\n").encode())
            response=json.loads(client.makefile("rb").readline())
        if case == "absent":
            process.terminate(); process.wait(timeout=3); sock.unlink(missing_ok=True)
            process = subprocess.Popen([str(root / "target/debug/agb-admin-server"), str(sock), str(base / "cache"), str(audit)], env=env)
            for _ in range(100):
                if sock.exists(): break
                time.sleep(.02)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(sock)); client.sendall((json.dumps({"token":request_token,"operation":"list"}) + "\n").encode())
                restarted=json.loads(client.makefile("rb").readline())
            if restarted.get("reason") != expected_reason: raise SystemExit("fail-closed decision changed after restart")
        records=[json.loads(line) for line in audit.read_text().splitlines()]
        expected_count = 2 if case == "absent" else 1
        if response.get("reason") != expected_reason or len(records) != expected_count or any(record.get("reason") != expected_reason for record in records):
            raise SystemExit("fail-closed configuration was not enforced and audited")
        print(json.dumps({"status":"passed","case":case,"response":response,"audit_events":records},indent=2))
    finally:
        process.terminate(); process.wait(timeout=3)
