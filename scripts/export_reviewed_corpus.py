#!/usr/bin/env python3
"""Join independent review decisions to frozen-split trajectory candidates."""

import argparse
import json
from pathlib import Path

from agb_fake_asm.telemetry_pipeline import apply_reviews, read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidates = read_jsonl(args.candidates)
    reviews = read_jsonl(args.reviews)
    corpus = apply_reviews(candidates, reviews)
    write_jsonl(args.output, corpus)
    print(json.dumps({
        "candidates": len(candidates),
        "trajectories": len(corpus),
        "excluded_inconclusive": len(candidates) - len(corpus),
        "output": str(args.output),
    }))


if __name__ == "__main__":
    main()
