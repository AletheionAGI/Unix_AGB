#!/usr/bin/env python3
"""Measure fake-engine plumbing throughput; not security efficacy."""

from __future__ import annotations

import argparse
import time

from agb_fake_asm import FakeAsmEngine
from generate_synthetic_events import event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100_000)
    args = parser.parse_args()
    engine = FakeAsmEngine()
    operations = ["process.exec", "network.connect", "file.open"]
    started = time.perf_counter()
    for sequence in range(1, args.events + 1):
        operation = operations[(sequence - 1) % 3]
        labels = ["credential"] if operation == "file.open" else []
        engine.update(event(sequence, operation, labels))
    elapsed = time.perf_counter() - started
    print(f"events={args.events} elapsed_s={elapsed:.6f} events_per_s={args.events / elapsed:.2f}")
    print("scope=fake-engine-plumbing security_efficacy=not_measured")


if __name__ == "__main__":
    main()

