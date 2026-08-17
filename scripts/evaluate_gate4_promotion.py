#!/usr/bin/env python3
"""Evaluate Gate 4 promotion evidence without treating missing data as success."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from agb_fake_asm.gate4_promotion import evaluate_matrix, load_jsonl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=Path("var/benchmark/gate4-promotion-evidence.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-promotion-summary.json"))
    parser.add_argument("--policy-revision", required=True)
    args = parser.parse_args()
    secret_text = os.environ.get("AGB_GATE4_PROMOTION_KEY")
    if not secret_text or len(secret_text.encode()) < 32:
        parser.error("AGB_GATE4_PROMOTION_KEY must contain at least 32 bytes")
    summary = evaluate_matrix(load_jsonl(args.evidence), secret_text.encode(), args.policy_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["supported"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
