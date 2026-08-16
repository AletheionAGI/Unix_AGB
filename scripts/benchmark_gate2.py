#!/usr/bin/env python3
"""Compare frozen Gate 2 modes A-D without claiming learned ASM efficacy."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import tempfile
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agb_fake_asm import (
    AsmCmEngine,
    AsmCmUnavailable,
    EventLocalEngine,
    PersistentStatefulProxy,
    SequenceRuleEngine,
    SlidingWindowEngine,
    SnapshotError,
    StatefulProxyEngine,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "fixtures" / "benchmark" / "gate2-v1.json"


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return ordered[index]


def make_event(case_id: str, sequence: int, operation: str, label: str | None = None) -> dict[str, Any]:
    class_offset = 100_000 if "malicious" in case_id else 0
    start = 1_000_000_000 + class_offset + int(case_id.split("-")[-1])
    labels = [label] if label else []
    resource: dict[str, Any] = {"type": operation.split(".", 1)[0]}
    if label == "credential":
        resource["path"] = "/run/secrets/api-token"
    elif label == "local-config":
        resource["path"] = "/etc/agb/local.conf"
    occurred = datetime(2026, 8, 15, 20, tzinfo=timezone.utc) + timedelta(milliseconds=sequence)
    return {
        "schema_version": "1.0",
        "event_id": f"evt:{case_id}:{sequence}",
        "sequence": sequence,
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "monotonic_ns": sequence * 1_000_000,
        "host_id": "host:gate2-benchmark",
        "namespace_id": f"process:boot-gate2:{20_000 + start}:{start}",
        "subject": {
            "pid": 20_000 + start,
            "uid": 1000,
            "gid": 1000,
            "boot_id": "boot-gate2",
            "start_time_ns": start,
            "exe": "/usr/bin/gate2-workload",
        },
        "operation": operation,
        "resource": resource,
        "result": "allowed",
        "policy_revision": "policy:gate2-benchmark-v1",
        "labels": labels,
        "provenance": {"source": "synthetic", "corpus": "gate2"},
    }


def corpus(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest["corpus_version"] == "gate2-adversarial-v2":
        return adversarial_corpus(manifest)
    trajectories: list[dict[str, Any]] = []
    count = int(manifest["trajectories_per_class"])
    seeds = manifest["seeds"]
    for malicious in (False, True):
        for index in range(count):
            case_id = f"{'malicious' if malicious else 'benign'}-{index + 1}"
            rng = random.Random(int(seeds[index % len(seeds)]) + index)
            steps: list[tuple[str, str | None]] = [("process.exec", None)]
            if malicious:
                steps.append(("network.connect", None))
                steps.extend(("file.open", "noise") for _ in range(rng.randint(0, 5)))
            else:
                steps.append(("file.open", "local-config"))
            steps.append(("file.open", "credential"))
            trajectories.append(
                {
                    "case_id": case_id,
                    "malicious": malicious,
                    "events": [
                        make_event(case_id, sequence, operation, label)
                        for sequence, (operation, label) in enumerate(steps, 1)
                    ],
                }
            )
    return trajectories


def adversarial_corpus(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    trajectories: list[dict[str, Any]] = []
    seeds = [int(seed) for seed in manifest["seeds"]]
    low, high = (int(value) for value in manifest["distractor_range"])
    families = (
        (False, "clean"),
        (False, "trusted-network"),
        (False, "risk-then-reset"),
        (True, "risk-long-gap"),
        (True, "trusted-then-risk"),
        (True, "repeated-risk"),
    )
    for malicious, family in families:
        for index in range(10):
            ordinal = len(trajectories) + 1
            case_id = f"v2-{'malicious' if malicious else 'benign'}-{family}-{ordinal}"
            rng = random.Random(seeds[index % len(seeds)] + ordinal * 97)
            steps: list[tuple[str, str | None]] = [("process.exec", None)]
            if family == "trusted-network":
                steps.append(("network.connect", "trusted-network"))
            elif family == "risk-then-reset":
                steps.append(("network.connect", None))
                steps.extend(("file.open", "noise") for _ in range(4))
                steps.append(("identity.change", "trusted-reset"))
            elif family == "risk-long-gap":
                steps.append(("network.connect", None))
            elif family == "trusted-then-risk":
                steps.extend(
                    (("network.connect", "trusted-network"), ("network.connect", None))
                )
            elif family == "repeated-risk":
                steps.extend((("network.connect", None), ("network.connect", None)))
            steps.extend(("file.open", "noise") for _ in range(rng.randint(low, high)))
            steps.append(("file.open", "credential"))
            trajectories.append(
                {
                    "case_id": case_id,
                    "family": family,
                    "malicious": malicious,
                    "events": [
                        make_event(case_id, sequence, operation, label)
                        for sequence, (operation, label) in enumerate(steps, 1)
                    ],
                }
            )
    return trajectories


def evaluate(engine_factory: Any, trajectories: list[dict[str, Any]]) -> dict[str, Any]:
    engine = engine_factory()
    latencies: list[float] = []
    ingest_latencies: list[float] = []
    query_latencies: list[float] = []
    tp = fp = tn = fn = abstain = 0
    terminal_decisions: list[dict[str, Any]] = []
    family_counts: dict[str, dict[str, int]] = {}
    if hasattr(engine, "reset_peak_memory_stats"):
        engine.reset_peak_memory_stats()
    tracemalloc.start()
    for trajectory in trajectories:
        decision: dict[str, Any] = {}
        for event in trajectory["events"]:
            if hasattr(engine, "synchronize"):
                engine.synchronize()
            started = time.perf_counter_ns()
            decision = engine.update(event)
            if hasattr(engine, "synchronize"):
                engine.synchronize()
            elapsed_us = (time.perf_counter_ns() - started) / 1_000
            latencies.append(elapsed_us)
            is_query = event["operation"] == "file.open" and "credential" in event.get("labels", [])
            (query_latencies if is_query else ingest_latencies).append(elapsed_us)
        predicted = decision["effect"] == "DENY"
        terminal_decisions.append(decision)
        abstain += decision["effect"] == "ABSTAIN"
        actual = trajectory["malicious"]
        tp += actual and predicted
        fp += (not actual) and predicted
        tn += (not actual) and (not predicted)
        fn += actual and (not predicted)
        family = trajectory.get("family", "default")
        counts = family_counts.setdefault(family, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        counts["tp"] += int(actual and predicted)
        counts["fp"] += int((not actual) and predicted)
        counts["tn"] += int((not actual) and (not predicted))
        counts["fn"] += int(actual and (not predicted))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "engine": engine.name,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "abstain": abstain},
        "families": family_counts,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "latency_us": {
            "p50": statistics.median(latencies),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
        "ingest_latency_us": {
            "p50": statistics.median(ingest_latencies),
            "p95": percentile(ingest_latencies, 0.95),
            "p99": percentile(ingest_latencies, 0.99),
        },
        "query_latency_us": {
            "p50": statistics.median(query_latencies),
            "p95": percentile(query_latencies, 0.95),
            "p99": percentile(query_latencies, 0.99),
        },
        "python_peak_bytes": peak,
        "accelerator_memory": (
            engine.accelerator_memory() if hasattr(engine, "accelerator_memory") else None
        ),
        "terminal_decisions_sha256": hashlib.sha256(
            json.dumps(terminal_decisions, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def persistence_proofs(trajectories: list[dict[str, Any]]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="agb-gate2-proof-") as directory:
        path = Path(directory) / "state.json"
        fingerprint = "config:gate2-benchmark-v1"
        first, second = trajectories[20], trajectories[21]
        engine = PersistentStatefulProxy(path, fingerprint)
        for event in first["events"][:-1]:
            engine.update(event)
        restored = PersistentStatefulProxy(path, fingerprint)
        restart_decision = restored.update(first["events"][-1])
        isolation_decision = restored.update(second["events"][0])
        snapshot_bytes = path.stat().st_size
        corrupted = json.loads(path.read_text())
        corrupted["namespaces"][first["events"][0]["namespace_id"]]["revision"] = 999
        path.write_text(json.dumps(corrupted))
        corruption_failed_closed = False
        try:
            PersistentStatefulProxy(path, fingerprint)
        except SnapshotError:
            corruption_failed_closed = True

        gap_engine = StatefulProxyEngine()
        gap_engine.update(first["events"][0])
        gap_event = dict(first["events"][1])
        gap_event["sequence"] = 3
        gap_decision = gap_engine.update(gap_event)
        return {
            "engine": "D:stateful-proxy",
            "restart_preserved_decision": restart_decision["effect"] == "DENY",
            "corruption_failed_closed": corruption_failed_closed,
            "sequence_gap_abstained": gap_decision["effect"] == "ABSTAIN",
            "namespace_isolation": isolation_decision["state_revision"] == 1,
            "snapshot_bytes": snapshot_bytes,
            "snapshot_namespace_count": 2,
        }


def asm_cm_persistence_proofs(
    checkpoint: Path,
    source_root: Path,
    expected_sha256: str,
    device: str,
    trajectory: dict[str, Any],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="agb-asm-cm-proof-") as directory:
        snapshot = Path(directory) / "asm-cm-state.pt"
        engine = AsmCmEngine(
            checkpoint,
            source_root,
            expected_sha256=expected_sha256,
            device=device,
            snapshot=snapshot,
        )
        for event in trajectory["events"][:-1]:
            engine.update(event)
        restored = AsmCmEngine(
            checkpoint,
            source_root,
            expected_sha256=expected_sha256,
            device=device,
            snapshot=snapshot,
        )
        decision = restored.update(trajectory["events"][-1])
        snapshot_bytes = snapshot.stat().st_size
        corrupted = bytearray(snapshot.read_bytes())
        corrupted[len(corrupted) // 2] ^= 1
        snapshot.write_bytes(corrupted)
        rejected = False
        try:
            AsmCmEngine(
                checkpoint,
                source_root,
                expected_sha256=expected_sha256,
                device=device,
                snapshot=snapshot,
            )
        except AsmCmUnavailable:
            rejected = True
        return {
            "engine": "D:asm-cm",
            "restart_preserved_decision": decision["effect"] == "DENY",
            "corruption_failed_closed": rejected,
            "snapshot_bytes": snapshot_bytes,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=ROOT / "var" / "benchmark" / "gate2-v1-report.json")
    parser.add_argument("--mode-d", choices=("proxy", "asm-cm"), default="proxy")
    parser.add_argument("--asm-checkpoint", type=Path)
    parser.add_argument("--asm-source-root", type=Path)
    parser.add_argument("--asm-source-revision")
    parser.add_argument("--asm-checkpoint-sha256")
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    trajectories = corpus(manifest)
    mode_d: Any = StatefulProxyEngine
    asm_metadata: dict[str, Any] | None = None
    if args.mode_d == "asm-cm":
        if (
            args.asm_checkpoint is None
            or args.asm_source_root is None
            or args.asm_checkpoint_sha256 is None
            or args.asm_source_revision is None
        ):
            parser.error(
                "--mode-d asm-cm requires --asm-checkpoint, --asm-source-root, "
                "--asm-checkpoint-sha256, and --asm-source-revision"
            )
        mode_d = lambda: AsmCmEngine(
            args.asm_checkpoint,
            args.asm_source_root,
            device=args.device,
            expected_sha256=args.asm_checkpoint_sha256,
        )
        asm_metadata = {
            "checkpoint": str(args.asm_checkpoint.resolve()),
            "checkpoint_sha256": args.asm_checkpoint_sha256,
            "source_root": str(args.asm_source_root.resolve()),
            "source_revision": args.asm_source_revision,
            "device": args.device,
        }
    modes = [EventLocalEngine, SequenceRuleEngine, SlidingWindowEngine, mode_d]
    results = [evaluate(mode, trajectories) for mode in modes]
    proofs = persistence_proofs(trajectories)
    real_persistence = None
    if args.mode_d == "asm-cm":
        real_persistence = asm_cm_persistence_proofs(
            args.asm_checkpoint,
            args.asm_source_root,
            args.asm_checkpoint_sha256,
            args.device,
            trajectories[20],
        )
    sequence = next(result for result in results if result["engine"].startswith("B:"))
    stateful = next(result for result in results if result["engine"].startswith("D:"))
    report = {
        "benchmark": "unix-agb-gate2-v1",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "trajectory_count": len(trajectories),
        "event_count": sum(len(item["events"]) for item in trajectories),
        "modes": results,
        "persistence_proofs": proofs,
        "asm_cm_persistence_proofs": real_persistence,
        "asm_cm": asm_metadata,
        "promotion": {
            "stateful_beats_sequence_baseline": stateful["recall"] > sequence["recall"]
            or stateful["false_positive_rate"] < sequence["false_positive_rate"],
            "gate2_promoted": False,
            "reason": (
                "Real ASM-CM was measured on one promoted checkpoint and a synthetic security corpus; "
                "multi-seed security-specific validation is still required."
                if args.mode_d == "asm-cm"
                else "D is a deterministic proxy, not ASM-CM; learned-state efficacy is not measured."
            ),
        },
        "limitations": manifest["limitations"],
    }
    required_proofs = (
        "restart_preserved_decision",
        "corruption_failed_closed",
        "sequence_gap_abstained",
        "namespace_isolation",
    )
    if not all(proofs[key] for key in required_proofs):
        raise SystemExit("Gate 2 persistence proof failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
