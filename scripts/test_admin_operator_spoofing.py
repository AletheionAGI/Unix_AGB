#!/usr/bin/env python3
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="agb-operator-spoof-") as d:
 base=Path(d); sock=base/"admin.sock"; audit=base/"audit.jsonl"; fake="pid:1:uid:0:gid:0"
 p=subprocess.Popen([str(root/"target/debug/agb-admin-server"),str(sock),str(base/"cache"),str(audit)],env={**os.environ,"AGB_ADMIN_TOKEN":"spoof-token","AGB_ADMIN_UIDS":str(os.getuid())})
 try:
  for _ in range(100):
   if sock.exists(): break
   time.sleep(.02)
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
   c.connect(str(sock)); c.sendall((json.dumps({"token":"spoof-token","operation":"list","operator":fake})+"\n").encode()); response=json.loads(c.makefile("rb").readline())
  event=json.loads(audit.read_text().strip())
  if fake in response["operator"] or fake in event["operator"] or f"uid:{os.getuid()}" not in event["operator"]: raise SystemExit("operator spoofing affected audit identity")
  print(json.dumps({"status":"passed","response":response,"audit_event":event},indent=2))
 finally: p.terminate(); p.wait(timeout=3)
