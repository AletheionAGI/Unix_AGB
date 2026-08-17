#!/usr/bin/env python3
"""Bounded teardown when a broker dies after RECV but before lease publication."""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any

from benchmark_gate4_egress_broker import filtered_workload
from run_egress_seccomp_pilot import receive_listener
from run_gate4_listener_guardian import start_broker


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def terminate_group(pgid: int, grace_ms: int) -> dict[str, Any]:
    started_ns = time.monotonic_ns()
    os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic_ns() + grace_ms * 1_000_000
    while process_exists(pgid) and time.monotonic_ns() < deadline:
        time.sleep(0.001)
    escalated = process_exists(pgid)
    if escalated:
        os.killpg(pgid, signal.SIGKILL)
    return {"signal": "SIGKILL" if escalated else "SIGTERM", "escalated": escalated, "elapsed_us": (time.monotonic_ns() - started_ns) // 1_000}


def run_proof(*, attempts: int, threads: int, crash_after_received: int, recovery_deadline_ms: int) -> dict[str, Any]:
    unrelated_pid = os.fork()
    if unrelated_pid == 0:
        time.sleep(30)
        os._exit(0)
    guardian_workload, workload_channel = socket.socketpair(type=socket.SOCK_SEQPACKET)
    workload_pid = os.fork()
    if workload_pid == 0:
        guardian_workload.close()
        os.setpgid(0, 0)
        filtered_workload(workload_channel, threads, attempts)
    workload_channel.close()
    listener = receive_listener(guardian_workload)
    executable = Path(sys.executable).resolve()
    generation = 1
    broker_pid, broker_channel = start_broker(listener, workload_pid, executable, generation, None, crash_before_lease_after_received=crash_after_received, lease_reporting=True)
    guardian_workload.send(b"GO")
    decisions = 0
    leases = 0
    crash_detected_ns: int | None = None
    replacement_ready_us: int | None = None
    teardown: dict[str, Any] | None = None
    try:
        while teardown is None:
            if crash_detected_ns is not None and time.monotonic_ns() - crash_detected_ns >= recovery_deadline_ms * 1_000_000:
                teardown = terminate_group(workload_pid, grace_ms=20)
                teardown["deadline_ms"] = recovery_deadline_ms
                teardown["reason"] = "PRELEASE_NOTIFICATION_UNRECOVERABLE"
                break
            ready, _, _ = select.select([broker_channel], [], [], 0.001)
            if broker_channel not in ready:
                continue
            payload = broker_channel.recv(65536)
            if payload:
                report = json.loads(payload)
                decisions += report["type"] == "decision"
                leases += report["type"] == "lease"
                continue
            _, status = os.waitpid(broker_pid, 0)
            if os.waitstatus_to_exitcode(status) != 72:
                raise RuntimeError("unexpected pre-lease broker exit")
            crash_detected_ns = time.monotonic_ns()
            broker_channel.close()
            generation += 1
            replacement_started_ns = time.monotonic_ns()
            broker_pid, broker_channel = start_broker(listener, workload_pid, executable, generation, None, lease_reporting=True)
            replacement_ready_us = (time.monotonic_ns() - replacement_started_ns) // 1_000
    finally:
        try:
            os.kill(broker_pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(broker_pid, 0)
        except ChildProcessError:
            pass
        broker_channel.close()
        os.close(listener)
        guardian_workload.close()
        try:
            os.waitpid(workload_pid, 0)
        except ChildProcessError:
            pass
    unrelated_survived = process_exists(unrelated_pid)
    try:
        os.kill(unrelated_pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(unrelated_pid, 0)
    report = {
        "proof": "unix-agb-gate4-prelease-deadline-teardown-v1",
        "configuration": {"attempts": attempts, "threads": threads, "crash_after_received": crash_after_received, "recovery_deadline_ms": recovery_deadline_ms},
        "broker": {"generations": generation, "decisions_before_teardown": decisions, "leases_before_teardown": leases, "replacement_ready_us": replacement_ready_us},
        "teardown": teardown,
        "unrelated_process_survived": unrelated_survived,
        "system_wide_changes": False,
        "criteria": {
            "prelease_crash_detected": crash_detected_ns is not None,
            "replacement_attempted": generation == 2,
            "deadline_triggered_teardown": teardown is not None and teardown["reason"] == "PRELEASE_NOTIFICATION_UNRECOVERABLE",
            "protected_group_terminated": not process_exists(workload_pid),
            "unrelated_process_survived": unrelated_survived,
            "system_wide_changes": False,
        },
        "limitations": ["A process group is used as the reversible laboratory boundary; production requires a delegated cgroup.", "The protected workload is intentionally terminated because the pre-lease notification ID is unknown."],
    }
    if not all(value for key, value in report["criteria"].items() if key != "system_wide_changes"):
        raise RuntimeError(f"pre-lease teardown criteria failed: {report['criteria']}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=64)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--crash-after-received", type=int, default=8)
    parser.add_argument("--recovery-deadline-ms", type=int, default=50)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-prelease-teardown.json"))
    args = parser.parse_args()
    report = run_proof(attempts=args.attempts, threads=args.threads, crash_after_received=args.crash_after_received, recovery_deadline_ms=args.recovery_deadline_ms)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
