#!/usr/bin/env python3
"""Measure BPF telemetry -> ASM-CM state -> Gate 3 audit/cache dry-run."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from agb_fake_asm import AsmCmEngine, DecisionEnsemble, EnsemblePolicy
from agb_fake_asm.independent_corpus import freeze_manifest, load_independent_corpus

ROOT = Path(__file__).resolve().parents[1]


def asm_decision_to_state(event: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Translate model output into the narrow, validated Gate 3 state contract."""
    effect = result.get("effect")
    if effect == "DENY":
        risk_band = "elevated"
    elif effect == "ALLOW":
        risk_band = "normal"
    else:
        risk_band = "unknown"
    signals = [str(result.get("reason", "ASM_CM_RESULT_UNSPECIFIED"))]
    if result.get("model_inference_performed"):
        signals.append("asm-cm-inference-performed")
    ensemble = result.get("ensemble")
    if ensemble:
        signals.append("asm-cm-ensemble")
        if ensemble.get("disagreement"):
            signals.append("asm-cm-member-disagreement")
    return {
        "schema_version": "1.0",
        "namespace_id": event["namespace_id"],
        "state_revision": int(result["state_revision"]),
        "risk_band": risk_band,
        "confidence": result.get("confidence"),
        "signals": signals,
        "evidence_ids": list(dict.fromkeys(result.get("evidence_ids", []))),
        # The versioned state contract identifies the model family here;
        # ensemble provenance remains explicit in signals and the report.
        "engine": "asm-cm",
        "checkpoint_fingerprint": result.get("checkpoint_fingerprint"),
        "updated_at": event["occurred_at"],
    }


def parse_ensemble_checkpoint(spec: str) -> tuple[str, Path, str]:
    """Parse MEMBER:PATH:SHA256 while allowing colons inside the path."""
    try:
        member, remainder = spec.split(":", 1)
        path, fingerprint = remainder.rsplit(":", 1)
    except ValueError as error:
        raise ValueError("ensemble checkpoint must be MEMBER:PATH:SHA256") from error
    if not member or not path or len(fingerprint) != 64:
        raise ValueError("ensemble checkpoint must include member, path and SHA-256")
    return member, Path(path), fingerprint


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": statistics.median(values) if values else 0.0,
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--checkpoint-sha256")
    parser.add_argument(
        "--ensemble-checkpoint",
        action="append",
        default=[],
        metavar="MEMBER:PATH:SHA256",
        help="repeat exactly three times to enable an ASM-CM ensemble",
    )
    parser.add_argument(
        "--ensemble-disagreement-action",
        choices=("abstain", "majority"),
        default="abstain",
        help="abstain is the conservative operational default",
    )
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--asm-source-revision", required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--split", choices=("calibration", "test"), default="test")
    parser.add_argument("--policy-revision", required=True)
    parser.add_argument("--minimum-confidence", type=float, default=0.8)
    parser.add_argument("--ttl-seconds", type=int, default=2)
    parser.add_argument("--policy-bin", type=Path, default=ROOT / "target/debug/agb-policy-dry-run")
    parser.add_argument("--audit", type=Path, default=ROOT / "var/gate3-asm-decisions.jsonl")
    parser.add_argument("--cache", type=Path, default=ROOT / "var/gate3-asm-cache.json")
    parser.add_argument("--output", type=Path, default=ROOT / "var/benchmark/gate3-asm-pipeline.json")
    args = parser.parse_args()
    cache_key = os.environ.get("AGB_GATE3_CACHE_KEY", "")
    if not cache_key:
        parser.error("AGB_GATE3_CACHE_KEY must be set")
    if args.ensemble_checkpoint:
        if args.checkpoint or args.checkpoint_sha256:
            parser.error("use either one checkpoint or ensemble checkpoints, not both")
        if len(args.ensemble_checkpoint) != 3:
            parser.error("exactly three --ensemble-checkpoint values are required")
    elif not args.checkpoint or not args.checkpoint_sha256:
        parser.error("--checkpoint and --checkpoint-sha256 are required")

    trajectories = load_independent_corpus(
        args.corpus, split=args.split, evaluation_purpose="security-efficacy"
    )
    events = [event for trajectory in trajectories for event in trajectory["events"]]
    revisions = {event["policy_revision"] for event in events}
    if revisions != {args.policy_revision}:
        raise RuntimeError(
            f"policy revision must match captured telemetry exactly: captured={sorted(revisions)}"
        )
    if not args.policy_bin.is_file():
        raise RuntimeError(f"Gate 3 policy binary not found: {args.policy_bin}")

    if args.ensemble_checkpoint:
        members = []
        member_ids = set()
        for spec in args.ensemble_checkpoint:
            member_id, checkpoint, fingerprint = parse_ensemble_checkpoint(spec)
            if member_id in member_ids:
                parser.error(f"duplicate ensemble member: {member_id}")
            member_ids.add(member_id)
            member = AsmCmEngine(
                checkpoint,
                args.asm_source_root,
                device=args.device,
                expected_sha256=fingerprint,
                inference_policy="security-relevant",
            )
            member.name = f"D:asm-cm:{member_id}"
            members.append(member)
        engine: Any = DecisionEnsemble(
            members,
            policy=EnsemblePolicy(
                deny_votes_required=2,
                disagreement_action=args.ensemble_disagreement_action,
            ),
        )
    else:
        engine = AsmCmEngine(
            args.checkpoint,
            args.asm_source_root,
            device=args.device,
            expected_sha256=args.checkpoint_sha256,
            inference_policy="security-relevant",
        )
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.cache.parent.mkdir(parents=True, exist_ok=True)
    args.audit.unlink(missing_ok=True)
    args.cache.unlink(missing_ok=True)
    environment = {
        **os.environ,
        "AGB_GATE3_POLICY_REVISION": args.policy_revision,
        "AGB_GATE3_CACHE_KEY": cache_key,
        "AGB_GATE3_MIN_CONFIDENCE": str(args.minimum_confidence),
        "AGB_GATE3_TTL_SECONDS": str(args.ttl_seconds),
    }
    process = subprocess.Popen(
        [str(args.policy_bin), str(args.audit), str(args.cache)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=environment,
    )
    assert process.stdin is not None and process.stdout is not None

    asm_us: list[float] = []
    gate3_us: list[float] = []
    end_to_end_us: list[float] = []
    effects: Counter[str] = Counter()
    terminal = {item["events"][-1]["event_id"]: item for item in trajectories}
    terminal_confusion: Counter[str] = Counter()
    inference_count = 0
    try:
        for event in events:
            started = time.perf_counter_ns()
            asm_started = time.perf_counter_ns()
            asm_result = engine.update(event)
            if isinstance(engine, DecisionEnsemble):
                for member in engine.engines:
                    member.synchronize()
            else:
                engine.synchronize()
            asm_finished = time.perf_counter_ns()
            state = asm_decision_to_state(event, asm_result)
            gate3_started = time.perf_counter_ns()
            process.stdin.write(json.dumps({"event": event, "state": state}) + "\n")
            process.stdin.flush()
            response_line = process.stdout.readline()
            if not response_line:
                stderr = process.stderr.read() if process.stderr else ""
                raise RuntimeError(f"Gate 3 policy process stopped early: {stderr}")
            response = json.loads(response_line)
            if response.get("enforcement_applied") is not False:
                raise RuntimeError("Gate 3 dry-run unexpectedly reported enforcement")
            finished = time.perf_counter_ns()
            effect = response["decision"]["effect"]
            effects[effect] += 1
            inference_count += int(bool(asm_result.get("model_inference_performed")))
            asm_us.append((asm_finished - asm_started) / 1_000)
            gate3_us.append((finished - gate3_started) / 1_000)
            end_to_end_us.append((finished - started) / 1_000)
            item = terminal.get(event["event_id"])
            if item:
                predicted_malicious = effect == "DENY"
                if effect == "ABSTAIN":
                    terminal_confusion["abstain"] += 1
                elif item["malicious"] and predicted_malicious:
                    terminal_confusion["tp"] += 1
                elif item["malicious"]:
                    terminal_confusion["fn"] += 1
                elif predicted_malicious:
                    terminal_confusion["fp"] += 1
                else:
                    terminal_confusion["tn"] += 1
    finally:
        process.stdin.close()
        return_code = process.wait()
    if return_code != 0:
        stderr = process.stderr.read() if process.stderr else ""
        raise RuntimeError(f"Gate 3 policy process failed ({return_code}): {stderr}")

    cache_snapshot = json.loads(args.cache.read_text())
    cache_entries = cache_snapshot.get("entries", [])
    if any(entry.get("effect") != "DENY" for entry in cache_entries):
        raise RuntimeError("Gate 3 cache contains a non-DENY decision")
    audit_records = sum(1 for line in args.audit.read_text().splitlines() if line.strip())
    if audit_records != len(events):
        raise RuntimeError(
            f"durable audit is incomplete: expected={len(events)} actual={audit_records}"
        )

    ensemble_enabled = isinstance(engine, DecisionEnsemble)
    ensemble_telemetry = engine.telemetry if ensemble_enabled else None
    report = {
        "benchmark": (
            "unix-agb-gate3-asm-cm-ensemble-pipeline-v1"
            if ensemble_enabled
            else "unix-agb-gate3-asm-cm-pipeline-v1"
        ),
        "pipeline": [
            "bpf-telemetry",
            "asm-cm",
            "security-state-summary",
            "gate3-policy",
            "durable-audit",
            "authenticated-deny-only-cache",
        ],
        "enforcement_applied": False,
        "corpus_manifest": freeze_manifest(args.corpus),
        "split": args.split,
        "trajectory_count": len(trajectories),
        "event_count": len(events),
        "asm_cm": {
            "checkpoint_sha256": getattr(engine, "checkpoint_sha256", None),
            "checkpoint_sha256s": [
                member.checkpoint_sha256 for member in engine.engines
            ] if ensemble_enabled else None,
            "source_revision": args.asm_source_revision,
            "device": args.device,
            "inference_policy": "security-relevant",
            "inference_event_count": inference_count,
            "inference_count": (
                ensemble_telemetry["total_member_inferences"]
                if ensemble_telemetry
                else inference_count
            ),
            "ensemble_telemetry": ensemble_telemetry,
        },
        "policy": {
            "revision": args.policy_revision,
            "minimum_confidence": args.minimum_confidence,
            "ttl_seconds": args.ttl_seconds,
            "compiled_effects": ["DENY"],
        },
        "decision_effects": dict(sorted(effects.items())),
        "persistence_proofs": {
            "audit_record_count": audit_records,
            "cache_entry_count": len(cache_entries),
            "cache_contains_only_deny": True,
            "every_response_enforcement_applied_false": True,
        },
        "terminal_confusion": {
            key: terminal_confusion[key] for key in ("tp", "fp", "tn", "fn", "abstain")
        },
        "latency_us": {
            "asm_cm": latency_summary(asm_us),
            "gate3_audit_cache": latency_summary(gate3_us),
            "end_to_end": latency_summary(end_to_end_us),
        },
        "artifacts": {
            "audit": str(args.audit.resolve()),
            "cache": str(args.cache.resolve()),
        },
        "limitations": (
            "Controlled BPF laboratory corpus and "
            + ("three promoted checkpoints" if ensemble_enabled else "one promoted checkpoint")
            + "; dry-run only. "
            "No enforcement backend was called."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
