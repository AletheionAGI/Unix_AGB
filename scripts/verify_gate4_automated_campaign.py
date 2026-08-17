#!/usr/bin/env python3
"""Verify manifest, heartbeat chain and artifact hashes of a Gate 4 campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from run_gate4_automated_campaign import canonical, digest


def verify(manifest: Path, output_dir: Path) -> dict[str, object]:
    summary = json.loads((output_dir / "summary.json").read_text())
    errors = []
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != summary.get("manifest_sha256"):
        errors.append("MANIFEST_DIGEST_MISMATCH")
    previous = "0" * 64
    samples = 0
    for number, line in enumerate((output_dir / "heartbeats.jsonl").read_text().splitlines(), 1):
        row = json.loads(line); claimed = row.pop("sha256", None)
        if row.get("previous_sha256") != previous:
            errors.append(f"HEARTBEAT_PREVIOUS_MISMATCH:{number}")
        actual = hashlib.sha256(canonical(row)).hexdigest()
        if claimed != actual:
            errors.append(f"HEARTBEAT_DIGEST_MISMATCH:{number}")
        previous = actual; samples += 1
    if previous != summary.get("heartbeat_chain_head"):
        errors.append("HEARTBEAT_HEAD_MISMATCH")
    if samples != summary.get("heartbeat_samples"):
        errors.append("HEARTBEAT_COUNT_MISMATCH")
    for name, expected in summary.get("artifacts", {}).items():
        path = Path(name)
        if not path.is_file(): errors.append(f"ARTIFACT_MISSING:{name}")
        elif digest(path) != expected.get("sha256"): errors.append(f"ARTIFACT_DIGEST_MISMATCH:{name}")
    return {"protocol": "unix-agb-gate4-campaign-verification-v1", "valid": not errors,
            "errors": errors, "heartbeat_samples": samples, "heartbeat_chain_head": previous}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.manifest, args.output_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
