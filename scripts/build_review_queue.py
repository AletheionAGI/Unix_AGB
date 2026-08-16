#!/usr/bin/env python3
"""Build a compact review queue and an intentionally incomplete label template."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agb_fake_asm.independent_corpus import IndependentCorpusError
from agb_fake_asm.telemetry_pipeline import summarize_candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--review-template", type=Path, required=True)
    parser.add_argument("--max-resource-samples", type=int, default=8)
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"candidate file does not exist: {args.input}")
    if args.max_resource_samples < 0:
        parser.error("--max-resource-samples must be non-negative")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.review_template.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    seen: set[str] = set()
    try:
        with (
            args.input.open() as source,
            args.output.open("w") as queue,
            args.review_template.open("w") as reviews,
        ):
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    candidate = json.loads(line)
                except json.JSONDecodeError as error:
                    raise IndependentCorpusError(
                        f"line {line_number}: invalid candidate JSON: {error}"
                    ) from error
                summary = summarize_candidate(
                    candidate, max_resources=args.max_resource_samples
                )
                trajectory_id = summary["trajectory_id"]
                if trajectory_id in seen:
                    raise IndependentCorpusError(f"duplicate candidate: {trajectory_id}")
                seen.add(trajectory_id)
                queue.write(json.dumps(summary, sort_keys=True) + "\n")
                reviews.write(
                    json.dumps(
                        {
                            "trajectory_id": trajectory_id,
                            "label": "REVIEW_REQUIRED",
                            "label_source": "REVIEW_REQUIRED",
                            "family": "REVIEW_REQUIRED",
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                count += 1
    except (IndependentCorpusError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({"review_items": count, "output": str(args.output)}))


if __name__ == "__main__":
    main()
