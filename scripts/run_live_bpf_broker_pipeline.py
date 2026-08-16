#!/usr/bin/env python3
import subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="agb-live-bpf-") as directory:
    base = Path(directory); sock = base / "broker.sock"
    broker = subprocess.Popen([str(root / "target/debug/agb-policy-broker"), str(sock), str(base / "audit.jsonl")])
    try:
        subprocess.run(["python3", str(root / "scripts/run_live_bpf_observer.py"), "--duration", "10", "--broker-socket", str(sock)], check=True)
    finally:
        broker.terminate(); broker.wait(timeout=3)
