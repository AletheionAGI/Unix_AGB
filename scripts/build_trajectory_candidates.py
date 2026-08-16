#!/usr/bin/env python3
"""Group normalized BPF events into unlabeled review candidates."""

import argparse
import json
from pathlib import Path

from agb_fake_asm.telemetry_pipeline import build_candidates, read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--collector-revision", required=True)
    parser.add_argument("--calibration-percent", type=int, default=20)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--max-events", type=int, default=256)
    parser.add_argument(
        "--coverage-scope",
        choices=("system-wide", "protected-only", "allowlist"),
        default="system-wide",
    )
    parser.add_argument(
        "--protected-executables",
        default="",
        help="comma-separated exact executable paths treated as protected",
    )
    parser.add_argument("--exclude-external", action="store_true")
    args = parser.parse_args()
    candidates = build_candidates(
        read_jsonl(args.input),
        collector_revision=args.collector_revision,
        calibration_percent=args.calibration_percent,
        min_events=args.min_events,
        max_events=args.max_events,
        coverage_scope=args.coverage_scope,
        protected_executables={item for item in args.protected_executables.split(",") if item},
        include_external=not args.exclude_external,
    )
    write_jsonl(args.output, candidates)
    print(json.dumps({"candidates": len(candidates), "output": str(args.output)}))


if __name__ == "__main__":
    main()
