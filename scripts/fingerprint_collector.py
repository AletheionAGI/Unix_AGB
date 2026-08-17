#!/usr/bin/env python3
"""Fingerprint the exact source files that define independent telemetry collection."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sources = [
        "scripts/observe_live_bpf.bt",
        "scripts/run_live_bpf_observer.py",
        "scripts/bpf_to_events.py",
        "scripts/build_trajectory_candidates.py",
        "scripts/run_protected_corpus_lab.py",
        "scripts/fingerprint_collector.py",
        "python/agb_fake_asm/telemetry_pipeline.py",
        "src/bin/agb-lab-workload.rs",
    ]
    digest = hashlib.sha256()
    for relative in sources:
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update((root / relative).read_bytes())
        digest.update(b"\0")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"git:{commit}:collector-sha256:{digest.hexdigest()}")


if __name__ == "__main__":
    main()
