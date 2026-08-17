#!/usr/bin/env python3
"""Freeze one exact live BPF namespace through its credential terminal event."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agb_fake_asm.independent_corpus import load_independent_corpus


def extract(events_path: Path, namespace: str) -> list[dict[str, object]]:
    selected = []
    for line in events_path.read_text().splitlines():
        event = json.loads(line)
        if event.get("namespace_id") != namespace:
            continue
        selected.append(event)
        if "credential" in event.get("labels", []):
            break
    if not selected or "credential" not in selected[-1].get("labels", []):
        raise RuntimeError("exact namespace has no credential terminal event")
    if any(event.get("provenance", {}).get("source") != "bpf" for event in selected):
        raise RuntimeError("selected events are not exclusively BPF telemetry")
    if [event.get("sequence") for event in selected] != list(range(1, len(selected) + 1)):
        raise RuntimeError("selected namespace has a sequence gap")
    return selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    events = extract(args.events, args.namespace)
    coverage = hashlib.sha256(b"gate4-live-bpf-exact-namespace-v1").hexdigest()
    document = {
        "trajectory_id": "candidate:gate4-live-bpf-" + hashlib.sha256(args.namespace.encode()).hexdigest()[:24],
        "label": "malicious",
        "label_source": "controlled-ground-truth:live-bpf-credential-egress-v1",
        "family": "protected-credential-egress-delayed",
        "review_confidence": "high",
        "split": "test",
        "collector_revision": "bpftrace:gate4-live-service-v1",
        "coverage_scope": "protected-only",
        "coverage_config_sha256": coverage,
        "subject_scope": "protected",
        "evaluation_purpose": "security-efficacy",
        "events": events,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, separators=(",", ":")) + "\n")
    load_independent_corpus(args.output, split="test", evaluation_purpose="security-efficacy")
    print(json.dumps({"namespace_id": args.namespace, "events": len(events), "output": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
