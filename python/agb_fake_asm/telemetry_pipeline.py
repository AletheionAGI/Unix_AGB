"""Turn normalized, independent telemetry into reviewable trajectories."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .independent_corpus import (
    ALLOWED_COVERAGE_SCOPES,
    ALLOWED_LABELS,
    REAL_PROVENANCE,
    IndependentCorpusError,
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise IndependentCorpusError(f"input does not exist: {path}")
    items: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise IndependentCorpusError(f"line {line_number}: invalid JSON: {error}") from error
        if not isinstance(item, dict):
            raise IndependentCorpusError(f"line {line_number}: expected a JSON object")
        items.append(item)
    return items


def write_jsonl(path: Path, items: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in items))


def summarize_candidate(candidate: dict[str, Any], *, max_resources: int = 8) -> dict[str, Any]:
    events = candidate.get("events")
    if not isinstance(events, list) or not events:
        raise IndependentCorpusError("candidate events must be a non-empty list")
    namespace_ids = {event.get("namespace_id") for event in events}
    if len(namespace_ids) != 1 or None in namespace_ids:
        raise IndependentCorpusError("candidate must contain one exact namespace")
    operation_counts: dict[str, int] = defaultdict(int)
    resources: list[str] = []
    for event in events:
        operation_counts[str(event.get("operation", "unknown"))] += 1
        resource = event.get("resource", {})
        value = resource.get("path") if isinstance(resource, dict) else None
        if value is None and isinstance(resource, dict) and "fd" in resource:
            value = f"fd:{resource['fd']}"
        if value is not None and str(value) not in resources and len(resources) < max_resources:
            resources.append(str(value))
    first = events[0]
    last = events[-1]
    source_sequences = [
        int(event.get("provenance", {}).get("source_sequence", event["sequence"]))
        for event in events
    ]
    subject = first.get("subject", {})
    return {
        "trajectory_id": candidate["trajectory_id"],
        "status": candidate["status"],
        "split": candidate["split"],
        "collector_revision": candidate["collector_revision"],
        "coverage_scope": candidate["coverage_scope"],
        "coverage_config_sha256": candidate["coverage_config_sha256"],
        "subject_scope": candidate["subject_scope"],
        "evaluation_purpose": candidate["evaluation_purpose"],
        "namespace_id": first["namespace_id"],
        "subject": {key: subject.get(key) for key in ("pid", "uid", "gid", "exe")},
        "event_count": len(events),
        "source_sequence_first": min(source_sequences),
        "source_sequence_last": max(source_sequences),
        "occurred_at_first": first.get("occurred_at"),
        "occurred_at_last": last.get("occurred_at"),
        "operation_counts": dict(sorted(operation_counts.items())),
        "resource_samples": resources,
        "terminal": {
            "operation": last.get("operation"),
            "resource": last.get("resource"),
            "result": last.get("result"),
        },
    }


def build_candidates(
    events: list[dict[str, Any]],
    *,
    collector_revision: str,
    calibration_percent: int = 20,
    min_events: int = 1,
    max_events: int = 256,
    coverage_scope: str = "system-wide",
    protected_executables: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not collector_revision.strip():
        raise IndependentCorpusError("collector revision is required")
    if not 1 <= calibration_percent <= 99:
        raise IndependentCorpusError("calibration percent must be between 1 and 99")
    if min_events < 1:
        raise IndependentCorpusError("minimum events must be positive")
    if max_events < min_events:
        raise IndependentCorpusError("maximum events must be at least minimum events")
    if coverage_scope not in ALLOWED_COVERAGE_SCOPES:
        raise IndependentCorpusError("invalid coverage scope")
    protected_executables = protected_executables or set()
    coverage_config_sha256 = hashlib.sha256(
        json.dumps(
            {
                "coverage_scope": coverage_scope,
                "protected_executables": sorted(protected_executables),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_ids: set[str] = set()
    for index, event in enumerate(events, 1):
        namespace = event.get("namespace_id")
        event_id = event.get("event_id")
        source = event.get("provenance", {}).get("source")
        if not isinstance(namespace, str) or not namespace:
            raise IndependentCorpusError(f"event {index}: namespace_id is required")
        if not isinstance(event_id, str) or event_id in seen_ids:
            raise IndependentCorpusError(f"event {index}: duplicate or missing event_id")
        if source not in REAL_PROVENANCE:
            raise IndependentCorpusError(
                f"event {index}: provenance {source!r} is not independent telemetry"
            )
        seen_ids.add(event_id)
        grouped[namespace].append(event)

    candidates: list[dict[str, Any]] = []
    for namespace, observed in sorted(grouped.items()):
        observed.sort(key=lambda item: item.get("sequence", -1))
        if len(observed) < min_events:
            continue
        sequences = [event.get("sequence") for event in observed]
        if sequences != list(range(1, len(observed) + 1)):
            raise IndependentCorpusError(f"namespace {namespace}: sequence gap")
        namespace_bucket = int(hashlib.sha256(namespace.encode()).hexdigest()[:8], 16) % 100
        split = "calibration" if namespace_bucket < calibration_percent else "test"
        executable = str(observed[0].get("subject", {}).get("exe", ""))
        subject_scope = (
            "protected"
            if coverage_scope == "protected-only" or executable in protected_executables
            else "external"
        )
        evaluation_purpose = (
            "security-efficacy"
            if subject_scope == "protected"
            else "false-positive-monitoring"
        )
        for start in range(0, len(observed), max_events):
            source_window = observed[start : start + max_events]
            identity = hashlib.sha256(
                (namespace + "\0" + "\0".join(event["event_id"] for event in source_window)).encode()
            ).hexdigest()
            window = source_window
            for derived_sequence, event in enumerate(window, 1):
                provenance = dict(event.get("provenance", {}))
                provenance["source_sequence"] = event["sequence"]
                event["provenance"] = provenance
                event["sequence"] = derived_sequence
            candidates.append(
                {
                    "trajectory_id": f"candidate:{identity[:24]}",
                    "status": "pending-review",
                    "split": split,
                    "collector_revision": collector_revision,
                    "coverage_scope": coverage_scope,
                    "coverage_config_sha256": coverage_config_sha256,
                    "subject_scope": subject_scope,
                    "evaluation_purpose": evaluation_purpose,
                    "events": window,
                }
            )
    if not candidates:
        raise IndependentCorpusError("no trajectories met the collection criteria")
    return candidates


def apply_reviews(
    candidates: list[dict[str, Any]], reviews: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    candidate_fields = {
        "trajectory_id",
        "status",
        "split",
        "collector_revision",
        "coverage_scope",
        "coverage_config_sha256",
        "subject_scope",
        "evaluation_purpose",
        "events",
    }
    for index, candidate in enumerate(candidates, 1):
        if set(candidate) != candidate_fields:
            raise IndependentCorpusError(
                f"candidate {index}: fields must be exactly {sorted(candidate_fields)}"
            )
        if candidate["status"] != "pending-review":
            raise IndependentCorpusError(f"candidate {index}: invalid review status")
        if candidate["split"] not in {"calibration", "test"}:
            raise IndependentCorpusError(f"candidate {index}: invalid split")
        if not str(candidate["collector_revision"]).strip():
            raise IndependentCorpusError(f"candidate {index}: collector revision is required")

    review_fields = {"trajectory_id", "label", "label_source", "family"}
    by_id: dict[str, dict[str, Any]] = {}
    for index, review in enumerate(reviews, 1):
        if set(review) != review_fields:
            raise IndependentCorpusError(
                f"review {index}: fields must be exactly {sorted(review_fields)}"
            )
        trajectory_id = review["trajectory_id"]
        if trajectory_id in by_id:
            raise IndependentCorpusError(f"duplicate review: {trajectory_id}")
        if review["label"] not in ALLOWED_LABELS:
            raise IndependentCorpusError(f"review {index}: invalid label")
        if not str(review["label_source"]).strip() or not str(review["family"]).strip():
            raise IndependentCorpusError(f"review {index}: label_source and family are required")
        by_id[trajectory_id] = review

    candidate_ids = {item["trajectory_id"] for item in candidates}
    unknown = set(by_id) - candidate_ids
    missing = candidate_ids - set(by_id)
    if unknown:
        raise IndependentCorpusError(f"reviews reference unknown candidates: {sorted(unknown)}")
    if missing:
        raise IndependentCorpusError(f"candidates still pending review: {sorted(missing)}")

    return [
        {
            "trajectory_id": candidate["trajectory_id"],
            "label": by_id[candidate["trajectory_id"]]["label"],
            "label_source": by_id[candidate["trajectory_id"]]["label_source"],
            "family": by_id[candidate["trajectory_id"]]["family"],
            "split": candidate["split"],
            "collector_revision": candidate["collector_revision"],
            "coverage_scope": candidate["coverage_scope"],
            "coverage_config_sha256": candidate["coverage_config_sha256"],
            "subject_scope": candidate["subject_scope"],
            "evaluation_purpose": candidate["evaluation_purpose"],
            "events": candidate["events"],
        }
        for candidate in candidates
    ]
