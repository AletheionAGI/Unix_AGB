#!/usr/bin/env python3
import json, os, socket, subprocess, tempfile, time
from pathlib import Path

root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="agb-rate-limit-") as d:
 base=Path(d); sock=base/"admin.sock"; audit=base/"audit.jsonl"
 env={**os.environ,"AGB_ADMIN_TOKEN":"rate-token","AGB_ADMIN_UIDS":str(os.getuid()),"AGB_ADMIN_RATE_WINDOW_SECS":"1"}
 p=subprocess.Popen([str(root/"target/debug/agb-admin-server"),str(sock),str(base/"cache"),str(audit)],env=env)
 try:
  for _ in range(100):
   if sock.exists(): break
   time.sleep(.02)
  responses=[]
  for _ in range(6):
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
    c.connect(str(sock)); c.sendall(b'{"token":"rate-token","operation":"list","operator":"test"}\n'); responses.append(json.loads(c.makefile("rb").readline()))
  time.sleep(1.1)
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
   c.connect(str(sock)); c.sendall(b'{"token":"rate-token","operation":"list","operator":"test"}\n'); responses.append(json.loads(c.makefile("rb").readline()))
  events=[json.loads(line) for line in audit.read_text().splitlines()]
  if [r["reason"] for r in responses] != ["admin-ok"]*5+["rate-limit", "admin-ok"] or events[-1]["reason"] != "admin-ok": raise SystemExit("rate limit behavior mismatch")
  print(json.dumps({"status":"passed","responses":responses,"audit_events":events},indent=2))
 finally: p.terminate(); p.wait(timeout=3)
