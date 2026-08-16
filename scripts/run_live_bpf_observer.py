#!/usr/bin/env python3
"""Run the BPF observer continuously and stream normalized events to stdout."""
import argparse, json, socket, subprocess, sys
from pathlib import Path

p=argparse.ArgumentParser(); p.add_argument("--duration",type=int,default=10); p.add_argument("--broker-socket"); args=p.parse_args()
root=Path(__file__).resolve().parents[1]
command=["timeout",str(args.duration),"bpftrace",str(root/"scripts/observe_live_bpf.bt")]
try:
 process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
except FileNotFoundError:
 print('{"status":"unavailable","reason":"bpftrace-not-installed"}'); sys.exit(0)
count=0
assert process.stdout
for line in process.stdout:
 result=subprocess.run(["python3",str(root/"scripts/bpf_to_events.py")],input=line,text=True,capture_output=True)
 if result.returncode == 0 and result.stdout.strip():
  event=result.stdout.strip(); output={"event":json.loads(event)}
  if args.broker_socket:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
    client.connect(args.broker_socket); client.sendall((event+"\n").encode()); output["broker_response"]=json.loads(client.makefile("rb").readline())
  print(json.dumps(output)); count+=1
process.wait()
print('{"observer":"bpftrace","events":%d,"status":"stopped"}' % count)
