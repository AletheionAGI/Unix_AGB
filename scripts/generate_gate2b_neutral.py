#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Any

from agb_gate2b.neutral import validate_corpus

ROOT = Path(__file__).resolve().parents[1]
RELATION_TOKEN = {"R0": 8, "R1": 9, "R2": 10, "R3": 11, "R4": 12, "R5": 13, "RN": 14}


def entity_token(value: str, _offset: int) -> int:
    if value.startswith("A") and value[1:].isdigit(): return 32 + int(value[1:])
    if value.startswith("T") and value[1:].isdigit(): return 40 + int(value[1:])
    if value.startswith("F") and value[1:].isdigit(): return 48 + int(value[1:])
    if value.startswith("D") and value[1:].isdigit(): return 56 + int(value[1:])
    if value.startswith("X") and value[1:].isdigit(): return 128 + int(value[1:]) % 128
    return 80 + hashlib.sha256(value.encode()).digest()[0] % 48


def encode(events: list[dict[str, str]]) -> list[int]:
    tokens: list[int] = []
    for event in events:
        tokens.extend([4, entity_token(event["subject"], 32), RELATION_TOKEN[event["relation"]], entity_token(event["object"], 64)])
    tokens.append(1)  # neutral terminal query
    return tokens


def trajectory(index: int, split: str, distance: int, malicious: bool, agent: str, tool: str, family: str, rng: random.Random) -> dict[str, Any]:
    session = f"S{index:05d}"
    events = [
        {"subject": f"O{index % 11}", "relation": "R0", "object": session},
        {"subject": session, "relation": "R1", "object": agent},
        {"subject": agent, "relation": "R2", "object": tool},
        {"subject": tool, "relation": "R3", "object": family},
        {"subject": family, "relation": "R4", "object": f"D{index % 13}"},
    ]
    noise_needed = distance
    for n in range(noise_needed):
        decoy = f"X{rng.randrange(128)}"
        relation = ("R3", "R4", "RN")[n % 3]
        events.append({"subject": decoy, "relation": relation, "object": f"X{rng.randrange(128)}"})
    if malicious:
        events.append({"subject": tool, "relation": "R5", "object": f"D{index % 13}"})
    else:
        # Same terminal R5; one causal link is deliberately inconsistent.
        events.append({"subject": tool, "relation": "R5", "object": f"D{(index + 1) % 13}"})
    return {
        "schema_version": "gate2b-neutral-v1", "trajectory_id": f"ntraj:{index:06d}",
        "split": split, "label": "malicious" if malicious else "benign", "distance": distance,
        "agent_id": agent, "session_id": session, "tool_id": tool, "family_id": family,
        "events": events, "tokens": encode(events),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20260816)
    parser.add_argument("--per-cell", type=int, default=16)
    parser.add_argument("--output", type=Path, default=ROOT / "var/benchmark/gate2b-neutral.jsonl")
    parser.add_argument("--test-output", type=Path, default=ROOT / "var/benchmark/gate2b-neutral-test.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "var/benchmark/gate2b-neutral-manifest.json")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    definitions = {
        "calibration": (["A0", "A1"], ["T0", "T1"], ["F0", "F1"]),
        "validation": (["A0"], ["T2"], ["F0", "F1"]),
        "test-composition": (["A1"], ["T2"], ["F0", "F1"]),
        "test-hidden-family": (["A0", "A1"], ["T0", "T1", "T2"], ["F2"]),
    }
    items = []
    index = 0
    for split, (agents, tools, families) in definitions.items():
        for distance in (4, 16, 64, 256, 1024):
            for malicious in (False, True):
                for repetition in range(args.per_cell):
                    index += 1
                    items.append(trajectory(index, split, distance, malicious, agents[repetition % len(agents)], tools[repetition % len(tools)], families[repetition % len(families)], rng))
    validation = validate_corpus(items, required_splits={"calibration", "validation", "test-composition", "test-hidden-family"})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    public = [item for item in items if item["split"] in {"calibration", "validation"}]
    sealed = [item for item in items if item["split"].startswith("test-")]
    encoded = "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in public)
    test_encoded = "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in sealed)
    args.output.write_text(encoded); args.test_output.write_text(test_encoded)
    manifest = {
        "protocol": "gate2b-neutral-v1", "seed": args.seed, "per_cell": args.per_cell,
        "public_corpus_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
        "sealed_test_sha256": hashlib.sha256(test_encoded.encode()).hexdigest(), **validation,
        "split_rule": "agent/tool compositions and family F2 are held out; structural signatures cannot cross splits",
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
