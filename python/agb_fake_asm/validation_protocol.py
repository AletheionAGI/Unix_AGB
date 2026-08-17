"""Freeze a leakage-resistant Gate 3 natural/control validation bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .asm_cm_engine import sha256_file
from .independent_corpus import freeze_manifest, load_independent_corpus

PROTOCOL = "unix-agb-gate3-natural-controlled-validation-v1"
KNOWN_DATASET_SHA256 = {
    "deab550cd06f1590e094256f2184deaf1d95729b4922052357ef5bdeb5e8b548",
    "ae165d68603180df880de933ed8fb6a84137aac14cc1e8bdab65de259dd53740",
}
KNOWN_PROTECTED_FAMILIES = {
    "protected-credential-egress",
    "protected-persistence-origin",
    "protected-admin-origin",
}


class ValidationProtocolError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze_validation_bundle(
    natural_corpus: Path,
    controlled_corpus: Path,
    checkpoints: Iterable[tuple[str, Path, str]],
    *,
    minimum_natural_test: int = 30,
    minimum_controlled_per_class: int = 20,
    asm_source_revision: str | None = None,
) -> dict[str, Any]:
    """Validate and freeze inputs before any ensemble evaluation."""
    natural_manifest = freeze_manifest(natural_corpus)
    controlled_manifest = freeze_manifest(controlled_corpus)
    for manifest in (natural_manifest, controlled_manifest):
        if manifest["dataset_sha256"] in KNOWN_DATASET_SHA256:
            raise ValidationProtocolError("previously observed corpus cannot satisfy validation")

    natural_test = load_independent_corpus(
        natural_corpus, split="test", evaluation_purpose="false-positive-monitoring"
    )
    if len(natural_test) < minimum_natural_test:
        raise ValidationProtocolError("natural test corpus is below the preregistered minimum")
    if any(item["malicious"] or item["subject_scope"] != "external" for item in natural_test):
        raise ValidationProtocolError("natural false-positive corpus must be external and benign")

    controlled_test = load_independent_corpus(
        controlled_corpus, split="test", evaluation_purpose="security-efficacy"
    )
    benign = sum(not item["malicious"] for item in controlled_test)
    malicious = sum(item["malicious"] for item in controlled_test)
    if min(benign, malicious) < minimum_controlled_per_class:
        raise ValidationProtocolError("controlled test corpus is below the per-class minimum")
    controlled_families = {item["family"] for item in controlled_test}
    if len(controlled_families) < 3:
        raise ValidationProtocolError("controlled test corpus requires three families")
    overlap = controlled_families & KNOWN_PROTECTED_FAMILIES
    if overlap:
        raise ValidationProtocolError(f"controlled families were already observed: {sorted(overlap)}")

    frozen_checkpoints = []
    member_ids = set()
    for member, path, expected_sha256 in checkpoints:
        if member in member_ids:
            raise ValidationProtocolError(f"duplicate checkpoint member: {member}")
        member_ids.add(member)
        actual_sha256 = sha256_file(path)
        if actual_sha256 != expected_sha256:
            raise ValidationProtocolError(f"checkpoint fingerprint mismatch: {member}")
        frozen_checkpoints.append(
            {"member": member, "path": str(path.resolve()), "sha256": actual_sha256}
        )
    if len(frozen_checkpoints) != 3:
        raise ValidationProtocolError("exactly three checkpoints are required")

    return {
        "protocol": PROTOCOL,
        "natural_corpus": {
            "path": str(natural_corpus.resolve()),
            "sha256": _sha256(natural_corpus),
            "manifest": natural_manifest,
            "test_trajectories": len(natural_test),
        },
        "controlled_corpus": {
            "path": str(controlled_corpus.resolve()),
            "sha256": _sha256(controlled_corpus),
            "manifest": controlled_manifest,
            "test_benign": benign,
            "test_malicious": malicious,
            "test_families": sorted(controlled_families),
        },
        "checkpoints": sorted(frozen_checkpoints, key=lambda item: item["member"]),
        "asm_source_revision": asm_source_revision,
        "ensemble": {
            "deny_votes_required": 2,
            "disagreement_action": "abstain",
        },
        "criteria": {
            "natural_false_positive_rate_maximum": 0.01,
            "controlled_false_positive_rate_maximum": 0.01,
            "controlled_recall_minimum": 0.95,
            "decision_coverage_minimum": 1.0,
            "disagreement_rate_maximum": 0.05,
            "every_member_visible": True,
            "enforcement_applied": False,
        },
        "test_evaluated": False,
        "limitations": (
            "Natural benign telemetry measures false positives only. Controlled delayed "
            "compositions remain laboratory attacks, not natural unknown attacks."
        ),
    }


def write_frozen_bundle(path: Path, bundle: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
