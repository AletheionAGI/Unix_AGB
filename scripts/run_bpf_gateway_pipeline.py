#!/usr/bin/env python3
"""Run the bounded BPF-normalizer → AGB-gateway pipeline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from bpf_to_events import normalize


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="BPF text file; stdin when omitted")
    parser.add_argument("--store", default="var/bpf-pipeline/events.jsonl")
    parser.add_argument("--report", default="var/bpf-pipeline/REPORT.json")
    parser.add_argument("--max-line-bytes", type=int, default=65536)
    args = parser.parse_args()

    store = Path(args.store)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.unlink(missing_ok=True)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    gateway = subprocess.Popen(
        ["target/debug/agb-gateway", "--store", str(store)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    sequences: dict[str, int] = {}
    accepted = rejected = oversized = 0
    started = time.monotonic()
    source = open(args.input) if args.input else sys.stdin
    try:
        assert gateway.stdin is not None and gateway.stdout is not None
        for raw_line in source:
            if len(raw_line.encode()) > args.max_line_bytes:
                oversized += 1
                continue
            try:
                event = normalize(raw_line, sequences)
                if event is None:
                    rejected += 1
                    continue
                gateway.stdin.write(json.dumps(event, separators=(",", ":")) + "\n")
                gateway.stdin.flush()
                response = gateway.stdout.readline()
                if not response:
                    raise RuntimeError("gateway stopped before responding")
                json.loads(response)
                accepted += 1
            except (KeyError, OSError, ValueError, RuntimeError):
                rejected += 1
    finally:
        if args.input:
            source.close()
        if gateway.stdin:
            gateway.stdin.close()
        gateway.wait(timeout=5)
    elapsed = time.monotonic() - started
    report = {
        "pipeline": "bpf-normalizer-gateway-v1",
        "accepted": accepted,
        "rejected": rejected,
        "oversized": oversized,
        "elapsed_seconds": elapsed,
        "events_per_second": accepted / elapsed if elapsed else 0,
        "store": str(store),
        "backpressure": "synchronous stdin/stdout; no unbounded queue",
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
