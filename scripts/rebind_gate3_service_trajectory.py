#!/usr/bin/env python3
"""Bind one frozen controlled trajectory to an already-running service identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--family", default="protected-credential-egress-delayed")
    args = parser.parse_args()
    parts = args.namespace.split(":")
    if len(parts) != 4 or parts[0] != "process":
        parser.error("namespace must use process:BOOT_ID:PID:START_NS")
    boot_id, pid, start_ns = parts[1], int(parts[2]), int(parts[3])
    selected = None
    for line in args.source.read_text().splitlines():
        item = json.loads(line)
        if item.get("split") == "test" and item.get("label") == "malicious" and item.get("family") == args.family:
            selected = deepcopy(item)
            break
    if selected is None:
        raise RuntimeError("matching frozen malicious trajectory not found")
    stamp = time.monotonic_ns()
    for sequence, event in enumerate(selected["events"], 1):
        event["event_id"] = f"evt:agent-broker:{pid}:{sequence}:{stamp + sequence}"
        event["namespace_id"] = args.namespace
        event["sequence"] = sequence
        event["monotonic_ns"] = stamp + sequence
        event["occurred_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event["subject"] = {
            **event["subject"],
            "boot_id": boot_id,
            "pid": pid,
            "start_time_ns": start_ns,
        }
        event["provenance"] = {
            "source": "agent-broker",
            "raw": "controlled frozen trajectory rebound to live protected namespace",
            "template_event_sha256": hashlib.sha256(json.dumps(event["resource"], sort_keys=True).encode()).hexdigest(),
        }
    selected["trajectory_id"] = "candidate:gate4-live-" + hashlib.sha256(args.namespace.encode()).hexdigest()[:24]
    selected["collector_revision"] = "agent-broker:gate4-live-rebind-v1"
    selected["label_source"] = "controlled-replay:frozen-gate3-malicious-template"
    selected["coverage_config_sha256"] = hashlib.sha256(b"gate4-live-service-rebind-v1").hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(selected, separators=(",", ":")) + "\n")
    print(json.dumps({"namespace_id": args.namespace, "family": args.family, "events": len(selected["events"]), "output": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
