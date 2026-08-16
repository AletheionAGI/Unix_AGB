#!/usr/bin/env python3
"""Capture a labeled protected corpus using safe loopback-only lab workloads."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from agb_fake_asm.independent_corpus import freeze_manifest
from agb_fake_asm.telemetry_pipeline import (
    apply_reviews,
    build_candidates,
    read_jsonl,
    write_jsonl,
)


def listener(expected: int) -> tuple[socket.socket, int, threading.Thread, list[Exception]]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(1)
    failures: list[Exception] = []

    def accept_all() -> None:
        accepted = 0
        deadline = time.monotonic() + 30
        try:
            while accepted < expected and time.monotonic() < deadline:
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    continue
                with connection:
                    accepted += 1
            if accepted != expected:
                raise RuntimeError(f"expected {expected} loopback connections, got {accepted}")
        except Exception as error:  # propagated after thread join
            failures.append(error)

    thread = threading.Thread(target=accept_all, daemon=True)
    thread.start()
    return server, server.getsockname()[1], thread, failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bpftrace-command", default="sudo bpftrace")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--cases-per-class", type=int, default=30)
    parser.add_argument("--output-root", type=Path, default=Path("var/telemetry/protected-lab"))
    args = parser.parse_args()
    if args.duration < 8:
        parser.error("--duration must be at least 8 seconds")
    if args.cases_per_class < 1:
        parser.error("--cases-per-class must be positive")

    root = Path(__file__).resolve().parents[1]
    workload = (root / "target/debug/agb-lab-workload").resolve()
    if not workload.is_file():
        parser.error("build target/debug/agb-lab-workload first")
    output = (root / args.output_root).resolve()
    output.mkdir(parents=True, exist_ok=True)
    canary = output / "protected-canary.txt"
    config = output / "benign-config.txt"
    canary.write_text("unix-agb controlled canary; never transmitted\n")
    config.write_text("controlled benign configuration\n")
    events_path = output / "events.jsonl"
    candidates_path = output / "candidates.jsonl"
    reviews_path = output / "reviews.jsonl"
    corpus_path = output / "corpus.jsonl"
    manifest_path = output / "manifest.json"

    server, port, listener_thread, listener_failures = listener(args.cases_per_class)
    observer = subprocess.Popen(
        [
            sys.executable,
            str(root / "scripts/run_live_bpf_observer.py"),
            "--duration",
            str(args.duration),
            "--bpftrace-command",
            args.bpftrace_command,
            "--target-uid",
            str(-1),
            "--sensitive-path",
            str(canary),
            "--output-events",
            str(events_path),
        ],
        stdout=subprocess.DEVNULL,
    )
    ground_truth: dict[int, str] = {}
    try:
        time.sleep(2)
        for index in range(args.cases_per_class * 2):
            case = "benign" if index % 2 == 0 else "suspicious"
            process = subprocess.Popen(
                [
                    str(workload),
                    "--case",
                    case,
                    "--secret",
                    str(canary),
                    "--config",
                    str(config),
                    "--port",
                    str(port),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            assert process.stdin and process.stdout
            ready = json.loads(process.stdout.readline())
            if ready.get("pid") != process.pid or ready.get("case") != case:
                raise RuntimeError("workload identity handshake failed")
            ground_truth[process.pid] = case
            process.stdin.write("ALLOW\n")
            process.stdin.flush()
            remainder = process.communicate(timeout=5)[0]
            if process.returncode != 0 or '"open_result":"allowed"' not in remainder:
                raise RuntimeError(f"controlled workload failed: {case}: {remainder.strip()}")
        if observer.wait(timeout=args.duration + 10) != 0:
            raise RuntimeError("BPF observer rejected the protected capture")
        listener_thread.join(timeout=5)
        if listener_thread.is_alive() or listener_failures:
            raise RuntimeError(f"loopback listener failed: {listener_failures}")
    finally:
        server.close()
        if observer.poll() is None:
            observer.terminate()
            observer.wait(timeout=5)

    collector_revision = subprocess.check_output(
        [sys.executable, str(root / "scripts/fingerprint_collector.py")], text=True
    ).strip()
    candidates = build_candidates(
        read_jsonl(events_path),
        collector_revision=collector_revision,
        coverage_scope="allowlist",
        protected_executables={str(workload)},
        include_external=False,
    )
    observed_pids = {int(item["events"][0]["subject"]["pid"]) for item in candidates}
    if observed_pids != set(ground_truth):
        missing = sorted(set(ground_truth) - observed_pids)
        unexpected = sorted(observed_pids - set(ground_truth))
        raise RuntimeError(f"capture identity mismatch; missing={missing}, unexpected={unexpected}")

    reviews = []
    for candidate in candidates:
        pid = int(candidate["events"][0]["subject"]["pid"])
        case = ground_truth[pid]
        operations = [event["operation"] for event in candidate["events"]]
        sensitive = any("credential" in event.get("labels", []) for event in candidate["events"])
        if not sensitive or (case == "suspicious" and "network.connect" not in operations):
            raise RuntimeError(f"incomplete causal trajectory for PID {pid}")
        reviews.append(
            {
                "trajectory_id": candidate["trajectory_id"],
                "label": "malicious" if case == "suspicious" else "benign",
                "label_source": "controlled-lab:loopback-canary-v1",
                "family": "protected-loopback-canary",
                "review_confidence": "high",
            }
        )
    corpus = apply_reviews(candidates, reviews)
    write_jsonl(candidates_path, candidates)
    write_jsonl(reviews_path, reviews)
    write_jsonl(corpus_path, corpus)
    manifest = freeze_manifest(corpus_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "benign": sum(item["label"] == "benign" for item in corpus),
                "malicious": sum(item["label"] == "malicious" for item in corpus),
                "corpus": str(corpus_path),
                "manifest": str(manifest_path),
                "promotion_eligible": manifest["promotion_eligible"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
