#!/usr/bin/env python3
"""Evaluate a pre-frozen ensemble on fresh natural and controlled telemetry."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from agb_fake_asm import AsmCmEngine, DecisionEnsemble, EnsemblePolicy
from agb_fake_asm.independent_corpus import load_independent_corpus
from agb_fake_asm.validation_protocol import PROTOCOL
from benchmark_gate2 import evaluate


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metrics_pass(result: dict[str, Any], *, natural: bool, criteria: dict[str, Any]) -> list[bool]:
    checks = [result["decision_coverage"]["rate"] >= criteria["decision_coverage_minimum"]]
    checks.append(
        result["false_positive_rate"]
        <= criteria[
            "natural_false_positive_rate_maximum"
            if natural
            else "controlled_false_positive_rate_maximum"
        ]
    )
    if not natural:
        checks.append(result["recall"] >= criteria["controlled_recall_minimum"])
    return checks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--asm-source-revision", required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("validation output already exists and cannot be overwritten")
    freeze = json.loads(args.freeze.read_text())
    if freeze.get("protocol") != PROTOCOL or freeze.get("test_evaluated") is not False:
        parser.error("invalid or already evaluated validation freeze")
    actual_revision = subprocess.run(
        ["git", "-C", str(args.asm_source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_revision != args.asm_source_revision or actual_revision != freeze.get(
        "asm_source_revision"
    ):
        parser.error("ASM source revision differs from the frozen revision")
    natural_path = Path(freeze["natural_corpus"]["path"])
    controlled_path = Path(freeze["controlled_corpus"]["path"])
    if digest(natural_path) != freeze["natural_corpus"]["sha256"]:
        parser.error("natural corpus changed after freeze")
    if digest(controlled_path) != freeze["controlled_corpus"]["sha256"]:
        parser.error("controlled corpus changed after freeze")

    def engine_factory() -> DecisionEnsemble:
        members = []
        for entry in freeze["checkpoints"]:
            member = AsmCmEngine(
                Path(entry["path"]),
                args.asm_source_root,
                device=args.device,
                expected_sha256=entry["sha256"],
                inference_policy="security-relevant",
            )
            member.name = f"D:asm-cm:{entry['member']}"
            members.append(member)
        return DecisionEnsemble(
            members,
            policy=EnsemblePolicy(
                deny_votes_required=freeze["ensemble"]["deny_votes_required"],
                disagreement_action=freeze["ensemble"]["disagreement_action"],
            ),
        )

    natural = load_independent_corpus(
        natural_path, split="test", evaluation_purpose="false-positive-monitoring"
    )
    controlled = load_independent_corpus(
        controlled_path, split="test", evaluation_purpose="security-efficacy"
    )
    natural_result = evaluate(engine_factory, natural)
    controlled_result = evaluate(engine_factory, controlled)
    criteria = freeze["criteria"]
    natural_checks = metrics_pass(natural_result, natural=True, criteria=criteria)
    controlled_checks = metrics_pass(controlled_result, natural=False, criteria=criteria)
    disagreement_checks = [
        natural_result["engine_telemetry"]["disagreement_rate"]
        <= criteria["disagreement_rate_maximum"],
        controlled_result["engine_telemetry"]["disagreement_rate"]
        <= criteria["disagreement_rate_maximum"],
    ]
    report = {
        "benchmark": "unix-agb-gate3-natural-controlled-ensemble-validation-v1",
        "freeze_sha256": digest(args.freeze),
        "source_revision": args.asm_source_revision,
        "device": args.device,
        "checkpoints": freeze["checkpoints"],
        "natural_false_positive_monitoring": natural_result,
        "controlled_security_efficacy": controlled_result,
        "criteria": {
            "declared": criteria,
            "natural_checks": natural_checks,
            "controlled_checks": controlled_checks,
            "disagreement_checks": disagreement_checks,
            "supported": all(natural_checks + controlled_checks + disagreement_checks),
        },
        "enforcement_applied": False,
        "test_evaluated": True,
        "limitations": freeze["limitations"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
