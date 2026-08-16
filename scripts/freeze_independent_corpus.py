#!/usr/bin/env python3
"""Validate an external telemetry JSONL and freeze its immutable manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agb_fake_asm.independent_corpus import IndependentCorpusError, freeze_manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = freeze_manifest(args.input)
    except (IndependentCorpusError, OSError) as error:
        parser.error(
            f"cannot freeze {args.input}: {error}. "
            "Collect events, build candidates, and export independent reviews first."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
