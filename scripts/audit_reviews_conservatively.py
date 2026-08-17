#!/usr/bin/env python3
"""Re-audit human reviews without converting ambiguity into a binary label."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agb_fake_asm.telemetry_pipeline import read_jsonl, write_jsonl

WILDCARD_ADDRESSES = {"0.0.0.0", "::", "<unknown>"}


def ambiguity_reasons(candidate: dict[str, Any], review: dict[str, Any]) -> list[str]:
    reasons: set[str] = set()
    events = candidate.get("events", [])
    if review.get("label") == "malicious" and not str(review.get("label_source", "")).startswith(
        "controlled-lab:"
    ):
        reasons.add("natural telemetry alone does not prove malicious intent")
    if review.get("review_confidence", "high") == "low":
        reasons.add("review confidence is low")
    if len(events) >= 256:
        reasons.add("trajectory reached the window limit")
    for event in events:
        subject = event.get("subject", {})
        resource = event.get("resource", {})
        if subject.get("exe") in {None, "", "<unavailable>", "<unknown>"}:
            reasons.add("executable identity is unavailable")
        if event.get("result") == "requested":
            reasons.add("syscall outcome is not observed")
        if event.get("operation") == "network.connect":
            if resource.get("address") in WILDCARD_ADDRESSES or resource.get("port") in {0, None}:
                reasons.add("network destination is unresolved or wildcard")
        if resource.get("path") == "<unknown>":
            reasons.add("resource path is unknown")
    return sorted(reasons)


def audit_reviews(
    candidates: list[dict[str, Any]], reviews: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {item["trajectory_id"]: item for item in candidates}
    if len(by_id) != len(candidates):
        raise ValueError("duplicate candidate trajectory_id")
    output = []
    seen: set[str] = set()
    for review in reviews:
        trajectory_id = review.get("trajectory_id")
        if trajectory_id in seen:
            raise ValueError(f"duplicate review: {trajectory_id}")
        if trajectory_id not in by_id:
            raise ValueError(f"unknown trajectory_id: {trajectory_id}")
        seen.add(trajectory_id)
        revised = dict(review)
        reasons = ambiguity_reasons(by_id[trajectory_id], review)
        if reasons:
            revised["label"] = "inconclusive"
            revised["review_confidence"] = "low"
            revised["review_reason"] = "; ".join(reasons)
        output.append(revised)
    missing = set(by_id) - seen
    if missing:
        raise ValueError(f"candidates still pending review: {sorted(missing)}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        reviews = audit_reviews(read_jsonl(args.candidates), read_jsonl(args.reviews))
    except (KeyError, OSError, ValueError) as error:
        parser.error(str(error))
    write_jsonl(args.output, reviews)
    counts = {label: sum(item["label"] == label for item in reviews) for label in (
        "benign", "malicious", "inconclusive"
    )}
    print(json.dumps({**counts, "output": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
