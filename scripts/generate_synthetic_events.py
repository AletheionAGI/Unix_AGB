#!/usr/bin/env python3
"""Generate deterministic Gate 0 events without observing a real host."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone


def event(sequence: int, operation: str, labels: list[str]) -> dict[str, object]:
    start_time = 900_000_001
    occurred_at = datetime(2026, 8, 15, 20, tzinfo=timezone.utc) + timedelta(
        milliseconds=sequence
    )
    return {
        "schema_version": "1.0",
        "event_id": f"evt:synthetic:{sequence}",
        "sequence": sequence,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "monotonic_ns": sequence * 1_000_000,
        "host_id": "host:synthetic",
        "namespace_id": f"process:boot-synthetic:4242:{start_time}",
        "subject": {
            "pid": 4242,
            "uid": 1000,
            "gid": 1000,
            "boot_id": "boot-synthetic",
            "start_time_ns": start_time,
            "exe": "/usr/bin/synthetic-agent",
        },
        "operation": operation,
        "resource": {"type": operation.split(".", 1)[0]},
        "result": "allowed",
        "policy_revision": "policy:gate0",
        "labels": labels,
        "provenance": {"source": "synthetic", "generator": "gate0-v1"},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()
    pattern = [
        ("process.exec", []),
        ("network.connect", []),
        ("file.open", ["credential"]),
    ]
    for sequence in range(1, args.count + 1):
        operation, labels = pattern[(sequence - 1) % len(pattern)]
        print(json.dumps(event(sequence, operation, labels), separators=(",", ":")))


if __name__ == "__main__":
    main()

