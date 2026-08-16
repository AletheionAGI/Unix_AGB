#!/usr/bin/env python3
"""Run the BPF observer continuously and stream normalized events to stdout."""
import argparse, subprocess, sys
from pathlib import Path

p=argparse.ArgumentParser(); p.add_argument("--duration",type=int,default=10); args=p.parse_args()
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
 if result.returncode == 0 and result.stdout.strip(): print(result.stdout.strip()); count+=1
process.wait()
print('{"observer":"bpftrace","events":%d,"status":"stopped"}' % count)
