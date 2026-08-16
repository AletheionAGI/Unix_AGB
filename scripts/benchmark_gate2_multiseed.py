#!/usr/bin/env python3
"""Run the adversarial Gate 2 corpus over three promoted ASM-CM checkpoints."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any

from agb_fake_asm import AsmCmEngine, EventLocalEngine, SequenceRuleEngine, SlidingWindowEngine
from agb_fake_asm.independent_corpus import freeze_manifest, load_independent_corpus
from benchmark_gate2 import adversarial_corpus, evaluate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "fixtures" / "benchmark" / "gate2-adversarial-v2.json"


def checkpoint_spec(value: str) -> tuple[int, Path, str]:
    try:
        seed_text, path_text, digest = value.split(":", 2)
        return int(seed_text), Path(path_text), digest
    except ValueError as error:
        raise argparse.ArgumentTypeError("checkpoint must be SEED:PATH:SHA256") from error


def accuracy(result: dict[str, Any]) -> float:
    counts = result["confusion"]
    total = counts["tp"] + counts["fp"] + counts["tn"] + counts["fn"]
    return (counts["tp"] + counts["tn"]) / total


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--independent-dataset", type=Path)
    parser.add_argument("--checkpoint", type=checkpoint_spec, action="append", required=True)
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--asm-source-revision", required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "var" / "benchmark" / "gate2-adversarial-v2-multiseed.json",
    )
    args = parser.parse_args()
    if len(args.checkpoint) != 3 or len({seed for seed, _, _ in args.checkpoint}) != 3:
        parser.error("exactly three distinct checkpoint seeds are required")
    independent_manifest = None
    if args.independent_dataset:
        manifest_bytes = args.independent_dataset.read_bytes()
        independent_manifest = freeze_manifest(args.independent_dataset)
        trajectories = load_independent_corpus(args.independent_dataset, split="test")
        limitations = (
            "Externally collected labels remain subject to collector and reviewer bias; "
            "Unix-AGB did not alter the frozen test split."
        )
    else:
        manifest_bytes = args.manifest.read_bytes()
        manifest = json.loads(manifest_bytes)
        trajectories = adversarial_corpus(manifest)
        limitations = manifest["limitations"]
    baselines = [
        evaluate(EventLocalEngine, trajectories),
        evaluate(SequenceRuleEngine, trajectories),
        evaluate(SlidingWindowEngine, trajectories),
    ]
    sequence = next(item for item in baselines if item["engine"].startswith("B:"))
    seeds: list[dict[str, Any]] = []
    for seed, checkpoint, digest in sorted(args.checkpoint):
        result = evaluate(
            lambda checkpoint=checkpoint, digest=digest: AsmCmEngine(
                checkpoint,
                args.asm_source_root,
                device=args.device,
                expected_sha256=digest,
            ),
            trajectories,
        )
        seeds.append(
            {
                "seed": seed,
                "checkpoint": str(checkpoint.resolve()),
                "checkpoint_sha256": digest,
                "result": result,
            }
        )
    accuracies = [accuracy(item["result"]) for item in seeds]
    sequence_accuracy = accuracy(sequence)
    strict_advantages = sum(value > sequence_accuracy for value in accuracies)
    all_noninferior = all(value >= sequence_accuracy for value in accuracies)
    report = {
        "benchmark": "unix-agb-gate2-adversarial-v2-multiseed",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "independent_dataset_manifest": independent_manifest,
        "source_revision": args.asm_source_revision,
        "device": args.device,
        "trajectory_count": len(trajectories),
        "event_count": sum(len(item["events"]) for item in trajectories),
        "baselines": baselines,
        "asm_cm_seeds": seeds,
        "aggregate": {
            "accuracy_mean": statistics.mean(accuracies),
            "accuracy_population_stddev": statistics.pstdev(accuracies),
            "sequence_accuracy": sequence_accuracy,
            "all_seeds_noninferior_to_sequence": all_noninferior,
            "strict_advantage_seed_count": strict_advantages,
        },
        "promotion": {
            "gate2_promoted": bool(
                independent_manifest
                and independent_manifest["promotion_eligible"]
                and all_noninferior
                and strict_advantages >= 2
            ),
            "criterion": "All seeds non-inferior and at least two seeds strictly exceed sequence accuracy.",
        },
        "limitations": limitations,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
