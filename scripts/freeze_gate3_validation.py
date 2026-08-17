#!/usr/bin/env python3
"""Freeze natural/control corpora and three checkpoints before evaluation."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from agb_fake_asm.validation_protocol import (
    ValidationProtocolError,
    freeze_validation_bundle,
    write_frozen_bundle,
)


def checkpoint_spec(value: str) -> tuple[str, Path, str]:
    try:
        member, remainder = value.split(":", 1)
        path, digest = remainder.rsplit(":", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("checkpoint must be MEMBER:PATH:SHA256") from error
    return member, Path(path), digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--natural-corpus", type=Path, required=True)
    parser.add_argument("--controlled-corpus", type=Path, required=True)
    parser.add_argument("--checkpoint", type=checkpoint_spec, action="append", required=True)
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--asm-source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("freeze output already exists; a preregistration cannot be overwritten")
    actual_revision = subprocess.run(
        ["git", "-C", str(args.asm_source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_revision != args.asm_source_revision:
        parser.error("ASM source revision does not match the declared freeze revision")
    try:
        bundle = freeze_validation_bundle(
            args.natural_corpus,
            args.controlled_corpus,
            args.checkpoint,
            asm_source_revision=actual_revision,
        )
    except (OSError, ValidationProtocolError, ValueError) as error:
        parser.error(str(error))
    write_frozen_bundle(args.output, bundle)
    print(json.dumps(bundle, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
