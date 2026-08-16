"""Validation and freezing for externally collected security trajectories."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ALLOWED_SPLITS = {"calibration", "test"}
ALLOWED_LABELS = {"benign", "malicious"}
REAL_PROVENANCE = {"ptrace", "bpf", "audit", "agent-broker"}


class IndependentCorpusError(ValueError):
    pass


def load_independent_corpus(path: Path, *, split: str | None = None) -> list[dict[str, Any]]:
    if not path.is_file():
        raise IndependentCorpusError(f"input does not exist: {path}")
    trajectories: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    namespace_split: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise IndependentCorpusError(f"line {line_number}: invalid JSON: {error}") from error
        required = {
            "trajectory_id",
            "label",
            "label_source",
            "family",
            "split",
            "collector_revision",
            "events",
        }
        if set(item) != required:
            raise IndependentCorpusError(
                f"line {line_number}: fields must be exactly {sorted(required)}"
            )
        if item["label"] not in ALLOWED_LABELS or item["split"] not in ALLOWED_SPLITS:
            raise IndependentCorpusError(f"line {line_number}: invalid label or split")
        if not item["label_source"].strip() or not item["collector_revision"].strip():
            raise IndependentCorpusError(f"line {line_number}: label source and revision required")
        events = item["events"]
        if not isinstance(events, list) or not events:
            raise IndependentCorpusError(f"line {line_number}: events must be non-empty")
        namespace_ids = {event.get("namespace_id") for event in events}
        if len(namespace_ids) != 1 or None in namespace_ids:
            raise IndependentCorpusError(f"line {line_number}: one exact namespace is required")
        namespace_id = next(iter(namespace_ids))
        previous_sequence = 0
        for event in events:
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or event_id in event_ids:
                raise IndependentCorpusError(f"line {line_number}: duplicate or missing event_id")
            event_ids.add(event_id)
            if event.get("sequence") != previous_sequence + 1:
                raise IndependentCorpusError(f"line {line_number}: sequence gap")
            previous_sequence = event["sequence"]
            source = event.get("provenance", {}).get("source")
            if source not in REAL_PROVENANCE:
                raise IndependentCorpusError(
                    f"line {line_number}: provenance {source!r} is not independent telemetry"
                )
        prior_split = namespace_split.setdefault(namespace_id, item["split"])
        if prior_split != item["split"]:
            raise IndependentCorpusError(
                f"namespace leakage: {namespace_id} occurs in calibration and test"
            )
        if split is None or item["split"] == split:
            trajectories.append(
                {
                    "case_id": item["trajectory_id"],
                    "family": item["family"],
                    "malicious": item["label"] == "malicious",
                    "events": events,
                }
            )
    if not trajectories:
        raise IndependentCorpusError("corpus contains no trajectories for requested split")
    return trajectories


def freeze_manifest(path: Path) -> dict[str, Any]:
    all_items = load_independent_corpus(path)
    calibration = load_independent_corpus(path, split="calibration")
    test = load_independent_corpus(path, split="test")

    def counts(items: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "trajectories": len(items),
            "events": sum(len(item["events"]) for item in items),
            "benign": sum(not item["malicious"] for item in items),
            "malicious": sum(item["malicious"] for item in items),
        }

    return {
        "protocol": "unix-agb-independent-telemetry-v1",
        "dataset_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "all": counts(all_items),
        "calibration": counts(calibration),
        "test": counts(test),
        "families": sorted({item["family"] for item in all_items}),
        "promotion_eligible": all(
            (
                counts(test)["benign"] >= 20,
                counts(test)["malicious"] >= 20,
                len({item["family"] for item in test}) >= 3,
            )
        ),
    }
