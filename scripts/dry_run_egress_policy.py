#!/usr/bin/env python3
"""Audit an exact-executable network policy without changing host networking."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from agb_fake_asm.egress_policy import ExecutableEgressPolicy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    policy = ExecutableEgressPolicy(args.executable)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    with args.events.open() as source, args.audit.open("w") as audit:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            decision = policy.evaluate(event)
            counts[decision["effect"]] += 1
            reasons[decision["reason"]] += 1
            audit.write(json.dumps({
                "event_id": event["event_id"],
                "executable": event.get("subject", {}).get("exe"),
                "operation": event.get("operation"),
                "resource": event.get("resource"),
                "effect": decision["effect"],
                "reason": decision["reason"],
                "enforcement_applied": False,
                "source_line": line_number,
            }, sort_keys=True) + "\n")
    print(json.dumps({
        "effects": dict(sorted(counts.items())),
        "reasons": dict(sorted(reasons.items())),
        "enforcement_applied": False,
        "audit": str(args.audit),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
