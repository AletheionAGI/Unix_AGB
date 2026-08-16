from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SPLITS = {"calibration", "validation", "test-composition", "test-hidden-family"}
RELATIONS = {"R0", "R1", "R2", "R3", "R4", "R5", "RN"}


def structural_signature(item: dict[str, Any]) -> str:
    material = {
        "agent": item["agent_id"],
        "tool": item["tool_id"],
        "family": item["family_id"],
        "relations": [event["relation"] for event in item["events"] if event["relation"] != "RN"],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def validate_corpus(items: list[dict[str, Any]], *, required_splits: set[str] | None = None) -> dict[str, Any]:
    if not items:
        raise ValueError("neutral corpus is empty")
    ids: set[str] = set()
    signatures: dict[str, str] = {}
    split_counts: dict[str, int] = {}
    for item in items:
        required = {
            "schema_version", "trajectory_id", "split", "label", "distance",
            "agent_id", "session_id", "tool_id", "family_id", "events", "tokens",
        }
        if set(item) != required or item["schema_version"] != "gate2b-neutral-v1":
            raise ValueError("invalid neutral trajectory fields or version")
        if item["trajectory_id"] in ids or item["split"] not in SPLITS:
            raise ValueError("duplicate trajectory or invalid split")
        ids.add(item["trajectory_id"])
        if item["label"] not in {"benign", "malicious"} or item["distance"] not in {4, 16, 64, 256, 1024}:
            raise ValueError("invalid label or causal distance")
        if not item["events"] or any(event["relation"] not in RELATIONS for event in item["events"]):
            raise ValueError("invalid neutral events")
        if not item["tokens"] or any(not isinstance(token, int) or not 0 <= token < 256 for token in item["tokens"]):
            raise ValueError("neutral tokens must be uint8-compatible")
        signature = structural_signature(item)
        prior = signatures.setdefault(signature, item["split"])
        if prior != item["split"]:
            raise ValueError("structural leakage across splits")
        split_counts[item["split"]] = split_counts.get(item["split"], 0) + 1
    missing = (required_splits or set()) - set(split_counts)
    if missing:
        raise ValueError(f"missing neutral splits: {sorted(missing)}")
    calibration_families = {item["family_id"] for item in items if item["split"] == "calibration"}
    hidden_families = {item["family_id"] for item in items if item["split"] == "test-hidden-family"}
    if calibration_families & hidden_families:
        raise ValueError("hidden family appears in calibration")
    return {"trajectories": len(items), "split_counts": split_counts, "leakage": False}


def load_corpus(path: Path, *, required_splits: set[str] | None = None) -> list[dict[str, Any]]:
    items = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    validate_corpus(items, required_splits=required_splits)
    return items
