#!/usr/bin/env python3
"""Supervise the Rust policy broker with bounded restart and health checks."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="var/agb-policy.sock")
    parser.add_argument("--audit", default="var/enforcement.jsonl")
    parser.add_argument("--max-restarts", type=int, default=3)
    parser.add_argument("--backoff", type=float, default=0.2)
    args = parser.parse_args()
    socket_path = Path(args.socket)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    restarts = 0
    process: subprocess.Popen[str] | None = None

    def stop(*_: object) -> None:
        if process is not None and process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while restarts <= args.max_restarts:
            socket_path.unlink(missing_ok=True)
            process = subprocess.Popen(
                ["target/debug/agb-policy-broker", str(socket_path), args.audit],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            healthy = False
            for _ in range(50):
                if socket_path.exists():
                    healthy = True
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            if not healthy:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=2)
                restarts += 1
                time.sleep(args.backoff)
                continue
            print(f"healthy socket={socket_path} restart_count={restarts}", flush=True)
            code = process.wait()
            if code == 0:
                return
            restarts += 1
            if restarts <= args.max_restarts:
                time.sleep(args.backoff)
        print("policy broker restart budget exhausted", file=sys.stderr)
        raise SystemExit(1)
    finally:
        stop()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
